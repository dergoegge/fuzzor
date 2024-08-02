use std::collections::HashMap;
use std::path::PathBuf;

use fuzzor::corpora::VersionedOverwritingHerder;
use fuzzor::env::{docker::DockerEnvAllocator, Cores};
use fuzzor::project::{
    builder::DockerBuilder,
    campaign::CampaignEvent,
    description::{InMemoryProjectFolder, ProjectDescription, ProjectFolder},
    monitor::{ProjectMonitor, SolutionReportingMonitor},
    revision_tracker::GitHubRevisionTracker,
    scheduler::{CampaignScheduler, CoverageBasedScheduler, OneShotScheduler},
    state::StdProjectState,
    Project, ProjectEvent, ProjectOptions,
};
use fuzzor::solutions::reporter::GitHubRepoSolutionReporter;

use clap::Parser;
use octocrab::Octocrab;

#[derive(Parser, Debug)]
struct Options {
    #[arg(long = "project", help = "Project to fuzz", required = true)]
    project: String,

    #[arg(long = "owner", help = "Overwrite the repo owner from the config")]
    owner: Option<String>,
    #[arg(long = "repo", help = "Overwrite the repo from the config")]
    repo: Option<String>,
    #[arg(long = "branch", help = "Overwrite the branch from the config")]
    branch: Option<String>,
    #[arg(long = "name", help = "Overwrite the name from the config")]
    name: Option<String>,

    #[arg(
        long = "harnesses",
        help = "Specify the list of harnesses to fuzz",
        value_delimiter = ','
    )]
    harnesses: Option<Vec<String>>,

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
}

struct GitHubReportingBuildFailureMonitor {
    github: octocrab::Octocrab,
    repo: String,
    owner: String,
    ccs: Vec<String>,

    failure_counters: HashMap<String, u64>,
}

impl GitHubReportingBuildFailureMonitor {
    pub fn new(owner: &str, repo: &str, access_token: &str, ccs: Vec<String>) -> Self {
        Self {
            github: Octocrab::builder()
                .personal_token(access_token.to_string())
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

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let opts = Options::parse();

    let access_token = std::env::var("FUZZOR_GH_TOKEN").unwrap();

    let cores = Cores::new(0..num_cpus::get() as u64);
    let mut folder = InMemoryProjectFolder::from_folder(
        ProjectFolder::new(PathBuf::from(format!("./projects/{}", opts.project))).unwrap(),
    );

    if let Some(owner) = opts.owner.clone() {
        folder.config_mut().owner = owner;
    }
    if let Some(repo) = opts.repo.clone() {
        folder.config_mut().repo = repo;
    }
    if let Some(branch) = opts.branch.clone() {
        folder.config_mut().branch = Some(branch);
    }
    if let Some(name) = opts.name.clone() {
        folder.config_mut().name = name;
    }

    let config = folder.config();

    let gh_tracker = GitHubRevisionTracker::new(
        config.owner.clone(),
        config.repo.clone(),
        config.branch.clone().unwrap_or(String::from("master")),
        access_token.clone(),
    );

    let builder = DockerBuilder::new(cores.clone(), opts.cores_per_build as usize, None);

    let docker_allocator = DockerEnvAllocator::new(cores.clone());

    let scheduler: Box<dyn CampaignScheduler + Send> = if let Some(harnesses) = opts.harnesses {
        Box::new(OneShotScheduler::new(
            folder.config(),
            opts.cores_per_campaign,
            opts.campaign_duration,
            harnesses,
        ))
    } else {
        // Prioritize fuzzing harnesses that reach recently modified files but fall back to round
        // robin campaign scheduling when necessary.
        Box::new(CoverageBasedScheduler::with_round_robin_fallback(
            folder.config(),
            opts.cores_per_campaign,
            opts.campaign_duration,
        ))
    };

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
    let mut project = Project::new(
        folder,
        docker_allocator,
        scheduler,
        state,
        ProjectOptions {
            ignore_first_revision: false,
            no_fuzzing: false,
        },
    );

    let solution_monitor = SolutionReportingMonitor::new(GitHubRepoSolutionReporter::new(
        "auto-fuzz",
        "reports",
        &access_token,
        config.ccs.clone(),
    ));
    project.register_monitor(Box::new(solution_monitor));

    let build_monitor = GitHubReportingBuildFailureMonitor::new(
        "auto-fuzz",
        "reports",
        &access_token,
        config.ccs.clone(),
    );
    project.register_monitor(Box::new(build_monitor));

    let (_quit_tx, quit_rx) = tokio::sync::mpsc::channel(16);
    project.run(gh_tracker, builder, quit_rx).await;

    Ok(())
}
