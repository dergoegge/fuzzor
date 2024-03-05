use std::collections::HashMap;
use std::path::PathBuf;

use fuzzor::corpora::VersionedOverwritingHerder;
use fuzzor::env::{docker::DockerEnvAllocator, Cores};
use fuzzor::project::{
    builder::DockerBuilder,
    campaign::CampaignEvent,
    description::{InMemoryProjectFolder, ProjectDescription, ProjectFolder},
    harness::SharedHarnessMap,
    monitor::{ProjectMonitor, SolutionReportingMonitor},
    revision_tracker::GitHubRevisionTracker,
    scheduler::{CoverageBasedScheduler, RoundRobinCampaignScheduler},
    state::StdProjectState,
    Project, ProjectEvent,
};
use fuzzor::solutions::reporter::GitHubRepoSolutionReporter;

use clap::Parser;
use octocrab::Octocrab;

// Needs to have read/write perms for issues and contents
const GH_ACCESS_TOKEN: &str =
    "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";

#[derive(Parser, Debug, Clone)]
struct Options {
    #[arg(long = "project", help = "Project to fuzz", required = true)]
    project: String,

    #[arg(
        long = "prs",
        help = "Specify the list of PRs to fuzz",
        value_delimiter = ',',
        required = true
    )]
    pull_requests: Vec<u64>,

    #[arg(
        long = "cores-per-build",
        help = "Number of cores to use for builds",
        default_value_t = 16
    )]
    cores_per_build: u64,
    #[arg(
        long = "cores-per-campaign",
        help = "Number of cores to use for each campaign",
        default_value_t = 16
    )]
    cores_per_campaign: u64,
    #[arg(
        long = "campaign-duration",
        help = "Campaign duration in CPU hours",
        default_value_t = 16
    )]
    campaign_duration: u64,
    #[arg(
        long = "base-campaign-duration",
        help = "Campaign duration in CPU hours for the base project",
        default_value_t = 16
    )]
    base_campaign_duration: u64,
}

struct GitHubReportingBuildFailureMonitor {
    github: octocrab::Octocrab,
    repo: String,
    owner: String,
    ccs: Vec<String>,

    failure_counters: HashMap<String, u64>,
}

unsafe impl Send for GitHubReportingBuildFailureMonitor {}

impl GitHubReportingBuildFailureMonitor {
    pub fn new(owner: &str, repo: &str, ccs: Vec<String>) -> Self {
        Self {
            github: Octocrab::builder()
                .personal_token(GH_ACCESS_TOKEN.to_string())
                .build()
                .unwrap(),
            repo: repo.to_string(),
            owner: owner.to_string(),
            ccs,
            failure_counters: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl ProjectMonitor for GitHubReportingBuildFailureMonitor {
    async fn monitor_campaign_event(&mut self, _project: String, _event: CampaignEvent) {}
    async fn monitor_project_event(&mut self, project: String, event: ProjectEvent) {
        match event {
            ProjectEvent::BuildFailure => {
                if let Some(counter) = self.failure_counters.get_mut(&project) {
                    *counter += 1;
                } else {
                    self.failure_counters.insert(project.clone(), 1);
                }

                if *self.failure_counters.get(&project).unwrap() == 3 {
                    // Report that last three builds failed
                    if let Err(err) = self
                        .github
                        .issues(&self.owner, &self.repo)
                        .create(format!("{}: Build failure", project))
                        .body("Last three builds failed.")
                        .labels(vec!["Build Failure".to_string()])
                        .assignees(self.ccs.clone())
                        .send()
                        .await
                    {
                        log::error!("Could not open issue for build failure: {:?}", err);
                    }
                }
            }
            ProjectEvent::NewBuild => {
                self.failure_counters.remove(&project);
            }
        }
    }
}

struct PullRequestManager {
    cores: Cores,
    allocator: DockerEnvAllocator,
    parent_folder: InMemoryProjectFolder,
    parent_harnesses: SharedHarnessMap,
    opts: Options,
    projects_created: bool,
}

unsafe impl Send for PullRequestManager {}

impl PullRequestManager {
    fn new(
        cores: Cores,
        allocator: DockerEnvAllocator,
        parent_folder: InMemoryProjectFolder,
        parent_harnesses: SharedHarnessMap,
        opts: Options,
    ) -> Self {
        Self {
            allocator,
            parent_folder,
            opts,
            projects_created: false,
            parent_harnesses,
            cores,
        }
    }

    async fn create_pr_projects(&mut self) {
        for pr_num in self.opts.pull_requests.iter() {
            let parent_config = self.parent_folder.config();

            if let Some(gh_tracker) = GitHubRevisionTracker::from_pull_request(
                parent_config.repo.clone(),
                parent_config.owner.clone(),
                *pr_num,
                GH_ACCESS_TOKEN.to_string(),
            )
            .await
            {
                log::info!(
                    "Creating project for {} PR #{} (author={} branch={})",
                    &parent_config.name,
                    pr_num,
                    &gh_tracker.owner,
                    &gh_tracker.branch
                );

                let mut folder = self.parent_folder.clone();
                folder.config_mut().owner = gh_tracker.owner.clone();
                folder.config_mut().repo = gh_tracker.repo.clone();
                folder.config_mut().branch = Some(gh_tracker.branch.clone());
                folder.config_mut().name = format!("{}-pr{}", folder.config_mut().name, pr_num);
                let config = folder.config();

                let scheduler = Box::new(CoverageBasedScheduler::new(
                    folder.config(),
                    self.opts.cores_per_campaign,
                    self.opts.campaign_duration,
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

                let mut project = Project::new(folder, self.allocator.clone(), scheduler, state);

                let solution_monitor =
                    SolutionReportingMonitor::new(GitHubRepoSolutionReporter::new(
                        "auto-fuzz",
                        "reports",
                        GH_ACCESS_TOKEN,
                        config.ccs.clone(),
                    ));
                project.register_monitor(Box::new(solution_monitor));

                let cores = self.cores.clone();
                let cores_per_build = self.opts.cores_per_build as usize;

                let builder = DockerBuilder::new(cores, cores_per_build, None);

                tokio::spawn(async move {
                    let (_quit_tx, quit_rx) = tokio::sync::mpsc::channel(16);
                    project.run(gh_tracker, builder, quit_rx).await;
                });
            }
        }

        self.projects_created = true;
    }
}

#[async_trait::async_trait]
impl ProjectMonitor for PullRequestManager {
    async fn monitor_campaign_event(&mut self, _project: String, _event: CampaignEvent) {}

    async fn monitor_project_event(&mut self, _project: String, event: ProjectEvent) {
        if self.projects_created {
            // We've already created all the pull request projects.
            return;
        }

        if let ProjectEvent::NewBuild = event {
            self.create_pr_projects().await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let opts = Options::parse();

    let cores = Cores::new(0..num_cpus::get() as u64);
    let folder = InMemoryProjectFolder::from_folder(
        ProjectFolder::new(PathBuf::from(format!("./projects/{}", opts.project))).unwrap(),
    );

    let config = folder.config();

    let gh_tracker = GitHubRevisionTracker::new(
        config.owner.clone(),
        config.repo.clone(),
        config.branch.clone().unwrap_or(String::from("master")),
        GH_ACCESS_TOKEN.to_string(),
    );

    let builder = DockerBuilder::new(cores.clone(), opts.cores_per_build as usize, None);

    let docker_allocator = DockerEnvAllocator::new(cores.clone());

    let scheduler = Box::new(RoundRobinCampaignScheduler::new(
        folder.config(),
        opts.cores_per_campaign,
        opts.base_campaign_duration,
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
    let mut project = Project::new(folder_clone, docker_allocator.clone(), scheduler, state);

    let pr_mngr = PullRequestManager::new(
        cores.clone(),
        docker_allocator,
        folder.clone(),
        project.harnesses(),
        opts.clone(),
    );

    let solution_monitor = SolutionReportingMonitor::new(GitHubRepoSolutionReporter::new(
        "auto-fuzz",
        "reports",
        GH_ACCESS_TOKEN,
        config.ccs.clone(),
    ));
    project.register_monitor(Box::new(solution_monitor));

    let build_monitor =
        GitHubReportingBuildFailureMonitor::new("auto-fuzz", "reports", config.ccs.clone());
    project.register_monitor(Box::new(build_monitor));

    project.register_monitor(Box::new(pr_mngr));

    let (_quit_tx, quit_rx) = tokio::sync::mpsc::channel(16);
    project.run(gh_tracker, builder, quit_rx).await;

    Ok(())
}
