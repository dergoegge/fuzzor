use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use fuzzor::{
    corpora::VersionedOverwritingHerder,
    env::ResourcePool,
    project::{
        campaign::CampaignEvent,
        description::{InMemoryProjectFolder, ProjectDescription, ProjectFolder},
        harness::SharedHarnessMap,
        monitor::{ProjectMonitor, SolutionReportingMonitor},
        scheduler::CoverageBasedScheduler,
        state::StdProjectState,
        Project, ProjectEvent, ProjectOptions,
    },
};
use fuzzor_docker::{
    builder::DockerBuilder,
    env::{DockerEnvAllocator, DockerMachine},
};
use fuzzor_github::{
    reporter::GitHubRepoSolutionReporter,
    revisions::{GitHubRepository, GitHubRevisionTracker, GithubRevisionSource},
};
use fuzzor_infra::FuzzEngine;

use clap::Parser;
use octocrab::Octocrab;

#[derive(Parser, Debug, Clone)]
struct Options {
    #[arg(long = "project", help = "Project to fuzz", required = true)]
    project: String,

    #[arg(
        long = "cores-per-build",
        help = "Number of cores to use for builds",
        default_value_t = 8
    )]
    cores_per_build: u64,
    #[arg(
        long = "cores-per-campaign",
        help = "Number of cores to use for each campaign",
        default_value_t = 8
    )]
    cores_per_campaign: u64,
    #[arg(
        long = "campaign-duration",
        help = "Campaign duration in CPU hours",
        default_value_t = 8
    )]
    campaign_duration: u64,
    #[arg(
        long = "base-campaign-duration",
        help = "Campaign duration in CPU hours for the base project",
        default_value_t = 8
    )]
    base_campaign_duration: u64,
    #[arg(
        long = "cores-per-base-campaign",
        help = "Number of cores to use for each campaign of the base project",
        default_value_t = 8
    )]
    cores_per_base_campaign: u64,
}

struct PullRequestMonitor {
    pr_manager: Option<PullRequestManager>,
}

#[async_trait::async_trait]
impl ProjectMonitor for PullRequestMonitor {
    async fn monitor_campaign_event(&mut self, _project: String, _event: CampaignEvent) {}

    async fn monitor_project_event(&mut self, _project: String, event: ProjectEvent) {
        log::trace!("New project event: {:?}", &event);
        if self.pr_manager.is_none() {
            return;
        }

        if let ProjectEvent::NewBuild = event {
            let mut pr_manager = self.pr_manager.take().unwrap();
            tokio::spawn(async move {
                pr_manager.create_pr_projects().await;
            });
        }
    }
}

struct PullRequestManager {
    machines: ResourcePool<DockerMachine>,
    github: octocrab::Octocrab,
    allocator: DockerEnvAllocator,
    parent_folder: InMemoryProjectFolder,
    parent_harnesses: SharedHarnessMap,
    opts: Options,
    access_token: String,

    already_fuzzing: HashSet<u64>,
}

unsafe impl Send for PullRequestManager {}

impl PullRequestManager {
    fn new(
        machines: ResourcePool<DockerMachine>,
        allocator: DockerEnvAllocator,
        parent_folder: InMemoryProjectFolder,
        parent_harnesses: SharedHarnessMap,
        opts: Options,
        access_token: &str,
    ) -> Self {
        Self {
            machines,
            github: Octocrab::builder()
                .personal_token(access_token.to_string())
                .build()
                .unwrap(),
            allocator,
            parent_folder,
            opts,
            parent_harnesses,
            access_token: access_token.to_string(),
            already_fuzzing: HashSet::new(),
        }
    }

    async fn create_pr_project(
        &mut self,
        ignore_first_revision: bool,
        pr_num: u64,
        gh_tracker: GitHubRevisionTracker,
    ) {
        let parent_config = self.parent_folder.config();

        log::info!(
            "Creating project for {} PR #{} (author={})",
            &parent_config.name,
            pr_num,
            &gh_tracker.source().0.owner,
        );

        let mut folder = self.parent_folder.clone();
        folder.config_mut().owner = gh_tracker.source().0.owner.clone();
        folder.config_mut().repo = gh_tracker.source().0.repo.clone();
        if !folder.config_mut().has_engine(&FuzzEngine::LibFuzzer) {
            panic!("Project needs to support LibFuzzer for PR fuzzing!");
            // TODO don't panic, recover gracefully
        }
        // Only use LibFuzzer and "None" to reduce build times
        folder.config_mut().engines = Some(vec![FuzzEngine::LibFuzzer, FuzzEngine::None]);

        folder.config_mut().branch = Some(gh_tracker.lookup_branch().await);
        folder.config_mut().name = format!("{}-pr{}", folder.config_mut().name, pr_num);
        let config = folder.config();

        let scheduler = Box::new(CoverageBasedScheduler::new(
            folder.config(),
            Duration::from_secs(self.opts.campaign_duration * 60 * 60),
            self.parent_harnesses.clone(),
        ));

        let state_location = homedir::get_my_home()
            .unwrap()
            .unwrap()
            .join(".fuzzor")
            .join(folder.config().name);

        let corpus_herder = VersionedOverwritingHerder::new(
            state_location.join("corpora"),
            String::from("https://github.com/auto-fuzz/corpora.git"),
        )
        .await
        .unwrap();

        let state = StdProjectState::new(state_location, corpus_herder);

        let mut project = Project::new(
            folder,
            self.allocator.clone(),
            scheduler,
            state,
            ProjectOptions {
                ignore_first_revision,
                no_fuzzing: false,
            },
        );

        let solution_monitor = SolutionReportingMonitor::new(GitHubRepoSolutionReporter::new(
            "auto-fuzz",
            "reports",
            &self.access_token,
            config.ccs.clone(),
        ));
        project.register_monitor(Box::new(solution_monitor));

        let builder = DockerBuilder::new(self.machines.clone());

        tokio::spawn(async move {
            let (_quit_tx, quit_rx) = tokio::sync::mpsc::channel(16);
            project.run(gh_tracker, builder, quit_rx).await;
        });
    }

    async fn fetch_new_prs(&mut self) -> Vec<u64> {
        let mut prs = Vec::new();
        let parent_config = self.parent_folder.config();

        let mut page: u32 = 1;
        'page_loop: loop {
            if let Ok(result) = self
                .github
                .pulls(&parent_config.owner, &parent_config.repo)
                .list()
                .sort(octocrab::params::pulls::Sort::Created)
                .direction(octocrab::params::Direction::Descending) // from newest to oldest
                .state(octocrab::params::State::Open)
                .page(page)
                .send()
                .await
            {
                if result.items.is_empty() {
                    break;
                }

                log::trace!("Fetched pr page {} with {} prs", page, result.items.len());

                for pr in result.items.iter() {
                    if !self.already_fuzzing.insert(pr.number) {
                        break 'page_loop;
                    }

                    prs.push(pr.number);
                }

                page += 1;
            } else {
                log::warn!("Could not fetch page {}, bailing!", page);
                break;
            }
        }

        prs
    }

    async fn create_pr_projects(&mut self) {
        log::trace!("Entering pr fetch loop");

        loop {
            let first_pr_fetch = self.already_fuzzing.is_empty();
            let prs = self.fetch_new_prs().await;

            for pr_num in prs.iter() {
                let parent_config = self.parent_folder.config();

                let gh_tracker = GitHubRevisionTracker::new(
                    self.access_token.clone(),
                    GitHubRepository {
                        owner: parent_config.owner.clone(),
                        repo: parent_config.repo.clone(),
                    },
                    GithubRevisionSource::PullRequest(*pr_num),
                );

                // Skip fuzzing the first revision for already existing PRs (i.e.
                // first_pr_fetch = true). We will start fuzzing PRs that were already open on
                // their next push.
                self.create_pr_project(first_pr_fetch, *pr_num, gh_tracker)
                    .await;
            }

            let fetch_interval = tokio::time::Duration::from_secs(
                std::env::var("FUZZOR_PR_FETCH_INTERVAL").map_or(60 * 60, |val| {
                    // 1h default
                    val.parse()
                        .expect("FUZZOR_PR_FETCH_INTERVAL should be a value in seconds")
                }),
            );
            tokio::time::sleep(fetch_interval).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let access_token = std::env::var("FUZZOR_GH_TOKEN").unwrap();

    let opts = Options::parse();

    let total_num_cpus = num_cpus::get() as u64;
    if total_num_cpus % opts.cores_per_campaign != 0 {
        return Err("cores-per-campaign has to be a multiple of total number of cpus".to_string());
    }

    let folder = InMemoryProjectFolder::from_folder(
        ProjectFolder::new(PathBuf::from(format!("./projects/{}", opts.project))).unwrap(),
    );

    let mut machines = Vec::new();
    for i in 0..(total_num_cpus / opts.cores_per_campaign) {
        machines.push(DockerMachine {
            cores: (i..(i + opts.cores_per_campaign)).collect(),
            daemon_addr: "tcp://127.0.0.1:2375".to_string(),
        });
    }
    let machines = ResourcePool::new(machines.drain(..));

    let config = folder.config();

    let gh_tracker = GitHubRevisionTracker::new(
        access_token.clone(),
        GitHubRepository {
            owner: config.owner.clone(),
            repo: config.repo.clone(),
        },
        GithubRevisionSource::Branch(config.branch.clone().unwrap_or(String::from("master"))),
    );

    let builder = DockerBuilder::new(machines.clone());

    let docker_allocator = DockerEnvAllocator::new(machines.clone());
    // Prioritize fuzzing harnesses that reach recently modified files but fall back to round
    // robin campaign scheduling when necessary.
    let scheduler = Box::new(CoverageBasedScheduler::with_round_robin_fallback(
        folder.config(),
        Duration::from_secs(opts.base_campaign_duration * 60 * 60),
    ));

    // $HOME/.fuzzor/<project name>
    let state_location = homedir::get_my_home()
        .unwrap()
        .unwrap()
        .join(".fuzzor")
        .join(folder.config().name);

    let corpus_herder = VersionedOverwritingHerder::new(
        state_location.join("corpora"),
        String::from("https://github.com/auto-fuzz/corpora.git"),
    )
    .await?;

    let state = StdProjectState::new(state_location, corpus_herder);

    let folder_clone = folder.clone();
    let mut project = Project::new(
        folder_clone,
        docker_allocator.clone(),
        scheduler,
        state,
        ProjectOptions {
            ignore_first_revision: false,
            no_fuzzing: false,
        },
    );

    let pr_mngr = PullRequestMonitor {
        pr_manager: Some(PullRequestManager::new(
            machines,
            docker_allocator,
            folder.clone(),
            project.harnesses(),
            opts.clone(),
            &access_token,
        )),
    };

    let solution_monitor = SolutionReportingMonitor::new(GitHubRepoSolutionReporter::new(
        "auto-fuzz",
        "reports",
        &access_token,
        config.ccs.clone(),
    ));
    project.register_monitor(Box::new(solution_monitor));

    project.register_monitor(Box::new(pr_mngr));

    let (_quit_tx, quit_rx) = tokio::sync::mpsc::channel(16);
    project.run(gh_tracker, builder, quit_rx).await;

    Ok(())
}
