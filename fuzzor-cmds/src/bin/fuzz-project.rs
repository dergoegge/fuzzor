use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use fuzzor::{
    corpora::VersionedOverwritingHerder,
    env::ResourcePool,
    project::{
        campaign::CampaignEvent,
        description::{InMemoryProjectFolder, ProjectDescription, ProjectFolder},
        monitor::{ProjectMonitor, SolutionReportingMonitor},
        scheduler::{CampaignScheduler, CoverageBasedScheduler, OneShotScheduler},
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

use clap::Parser;
use octocrab::Octocrab;
use tokio::fs;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Infrastructure {
    builders: Vec<DockerMachine>,
    runners: Vec<DockerMachine>,
    registry: Option<String>,
}

#[derive(Parser, Debug)]
struct Options {
    #[arg(long = "project", help = "Project to fuzz", required = true)]
    project: String,

    #[arg(
        long = "infra-spec",
        help = "Infrastructure specification file",
        required = true
    )]
    infra_spec: PathBuf,

    #[arg(
        long = "report-repo",
        help = "GitHub repository for bug reports",
        required = true
    )]
    report_repo: String,
    #[arg(
        long = "report-repo-owner",
        help = "Owner of the GitHub repository for bug reports",
        required = true
    )]
    report_repo_owner: String,

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

    let config = fs::read_to_string(&opts.infra_spec).await.unwrap();
    let mut infra: Infrastructure = serde_yaml::from_str(&config)
        .map_err(|e| format!("Could not parse infra spec file {:?}", e))?;
    log::info!("{:?}", infra);

    let access_token = std::env::var("FUZZOR_GH_TOKEN").map_err(|_| {
        String::from(
            "You have to provide a GitHub auth token via the FUZZOR_GH_TOKEN env variable.",
        )
    })?;

    // Use directory specified by the `FUZZOR_PROJECTS_DIR` env variable or use `./projects/` as
    // default.
    let mut folder = InMemoryProjectFolder::from_folder(
        ProjectFolder::new(
            PathBuf::from(
                std::env::var("FUZZOR_PROJECTS_DIR").unwrap_or(String::from("./projects/")),
            )
            .join(opts.project),
        )
        .unwrap(),
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
        access_token.clone(),
        GitHubRepository {
            owner: config.owner.clone(),
            repo: config.repo.clone(),
        },
        GithubRevisionSource::Branch(config.branch.clone().unwrap_or(String::from("master"))),
    );

    let docker_machine_pool = ResourcePool::new(infra.runners.drain(..));

    let builder_pool = if infra.builders.is_empty() {
        // If no builders are configured, we use the runner pool (mostly useful when fuzzing on the
        // same machine).
        docker_machine_pool.clone()
    } else {
        ResourcePool::new(infra.builders.drain(..))
    };

    let docker_allocator = if let Some(registry) = infra.registry.clone() {
        DockerEnvAllocator::with_registry(docker_machine_pool, registry)
    } else {
        DockerEnvAllocator::new(docker_machine_pool)
    };

    let builder = if let Some(registry) = infra.registry.clone() {
        DockerBuilder::with_registry(builder_pool, registry)
    } else {
        DockerBuilder::new(builder_pool)
    };

    let scheduler: Box<dyn CampaignScheduler + Send> = if let Some(harnesses) = opts.harnesses {
        Box::new(OneShotScheduler::new(
            folder.config(),
            Duration::from_secs(opts.campaign_duration * 60 * 60),
            harnesses,
        ))
    } else {
        // Prioritize fuzzing harnesses that reach recently modified files but fall back to round
        // robin campaign scheduling when necessary.
        Box::new(CoverageBasedScheduler::with_round_robin_fallback(
            folder.config(),
            Duration::from_secs(opts.campaign_duration * 60 * 60),
        ))
    };

    // Use directory specified by the `FUZZOR_STATE_DIR` env variable or use `$HOME/.fuzzor` as
    // default.
    let state_location = std::env::var("FUZZOR_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or(homedir::get_my_home().unwrap().unwrap().join(".fuzzor"))
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
        &opts.report_repo_owner,
        &opts.report_repo,
        &access_token,
        config.ccs.clone(),
    ));
    project.register_monitor(Box::new(solution_monitor));

    let build_monitor = GitHubReportingBuildFailureMonitor::new(
        &opts.report_repo_owner,
        &opts.report_repo,
        &access_token,
        config.ccs.clone(),
    );
    project.register_monitor(Box::new(build_monitor));

    let (_quit_tx, quit_rx) = tokio::sync::mpsc::channel(16);
    project.run(gh_tracker, builder, quit_rx).await;

    Ok(())
}
