use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use crate::{
    builder::RemoteBuilder,
    campaign::RemoteCampaign,
    environment::RemoteEnvironmentAllocator,
    workers::{WorkerInfo, WorkerPurpose},
};
use async_nats::jetstream;
use futures::future::join_all;
use fuzzor::{
    corpora::VersionedOverwritingHerder,
    project::{
        description::{InMemoryProjectFolder, ProjectDescription, ProjectFolder},
        monitor::SolutionReportingMonitor,
        scheduler::CoverageBasedScheduler,
        state::StdProjectState,
        Project,
    },
};
use fuzzor_github::{
    reporter::GitHubRepoSolutionReporter,
    revisions::{GitHubRepository, GitHubRevision, GitHubRevisionTracker, GithubRevisionSource},
};
use fuzzor_prometheus::monitor::{PrometheusProjectMonitor, SharedMetrics};

use crate::nats_client::{FuzzorNatsClient, NatsError};

/// `FuzzorSubjects` represents the subjects used by the coordinator and the workers.
///
/// Current subjects are:
///   - `work.<purpose>.<arch>.<project>.<harness>`: Subject for requesting jobs to be processed by
///     workers.
///   - `work-channel.<id>.<role>`: Subject for communication between the coordinator and the workers.
///     The role can be `worker` or `coordinator`.
pub enum FuzzorSubjects {
    Fuzz {
        arch: Option<fuzzor_infra::CpuArchitecture>,
        project: String,
        harness: String,
    },
    Build {
        arch: Option<fuzzor_infra::CpuArchitecture>,
        project: String,
    },
    WorkChannel {
        id: String,
        receiver_is_worker: bool,
    },
}

impl std::fmt::Display for FuzzorSubjects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzorSubjects::Fuzz {
                arch,
                project,
                harness,
            } => write!(
                f,
                "work.{}.{}.{}.{}",
                WorkerPurpose::Fuzz,
                arch.map_or_else(|| String::from("any"), |a| a.to_string()),
                project,
                harness
            ),
            FuzzorSubjects::Build { arch, project } => write!(
                f,
                "work.{}.{}.{}",
                WorkerPurpose::Build,
                arch.map_or_else(|| String::from("any"), |a| a.to_string()),
                project
            ),
            FuzzorSubjects::WorkChannel {
                id,
                receiver_is_worker,
            } => write!(
                f,
                "work-channel.{}.{}",
                id,
                if *receiver_is_worker {
                    "worker"
                } else {
                    "coordinator"
                }
            ),
        }
    }
}

pub enum FuzzorObjectBuckets {
    Corpora,
    Coverage,
    BuildLogs,
}

impl std::fmt::Display for FuzzorObjectBuckets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzorObjectBuckets::Corpora => write!(f, "corpora"),
            FuzzorObjectBuckets::Coverage => write!(f, "coverage"),
            FuzzorObjectBuckets::BuildLogs => write!(f, "build-logs"),
        }
    }
}

/// `FuzzorConsumers` represents the consumers used by the coordinator and the workers.
pub enum FuzzorConsumers {
    Allocator {
        id: String,
    },
    // Consumer for fuzzing workers, unique per campaign
    Fuzzer {
        id: String,
    },
    // Counter part of the `Fuzzer` consumer on the coordinator side
    Campaign {
        id: String,
    },
    // Consumer for building workers, unique per build
    Builder {
        id: String,
    },
    // Counter part of the `Builder` consumer on the coordinator side
    RemoteBuilder {
        id: String,
    },
    // Consumer for workers, unique per worker purpose and architecture, i.e. workers may share a
    // consumer if they have the same purpose and architecture to achieve load balancing.
    Worker {
        purpose: WorkerPurpose,
        arch: Option<fuzzor_infra::CpuArchitecture>,
        project: Option<String>,
    },
}

impl std::fmt::Display for FuzzorConsumers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzorConsumers::Allocator { id } => write!(f, "allocator-{}", id),
            FuzzorConsumers::Fuzzer { id } => write!(f, "fuzzer-{}", id),
            FuzzorConsumers::Builder { id } => write!(f, "builder-{}", id),
            FuzzorConsumers::RemoteBuilder { id } => write!(f, "remote-builder-{}", id),
            FuzzorConsumers::Campaign { id } => write!(f, "campaign-{}", id),
            FuzzorConsumers::Worker {
                purpose,
                arch,
                project,
            } => write!(
                f,
                "worker-{}-{}-{}",
                purpose,
                arch.map_or_else(|| String::from("any"), |a| a.to_string()),
                project.clone().unwrap_or_else(|| String::from("any"))
            ),
        }
    }
}

/// `FuzzorMsg` represents an envelope for messages sent between the coordinator and the workers.
///
/// Any data that is useful or required to be present on every message is contained in the
/// envelope. Custom data is contained in the payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FuzzorMsg<P> {
    /// Information about the worker that sent the message, or `None` if the message is coming from
    /// the coordinator.
    pub worker_info: Option<WorkerInfo>,
    /// Correlation ID of the message (used for request/response patterns)
    pub correlation_id: Option<String>,
    /// Payload of the message
    pub payload: P,
}

#[derive(Debug, Clone)]
pub struct CoordinatorOpts {
    pub allowed_projects: Vec<String>,
    pub denied_projects: Vec<String>,
    pub report_repo: String,
    pub campaign_duration: u64,
}

pub struct Coordinator {
    client: FuzzorNatsClient,
    opts: CoordinatorOpts,
    metrics: Arc<SharedMetrics>,
}

#[derive(Debug)]
pub enum CoordinatorError {
    MissingGitHubToken,
    ProjectsDirNotFound,
    FailedToCreateEnvAllocator,
    FailedToCreateCorpusHerder,
    FailedToRunProject,
    FailedToCreateBuilder,
    FailedToCreateProjectCoordinator,
    InvalidProjectFilter,
    FailedToStartMetricsServer,
    NatsError(NatsError),
}

impl From<NatsError> for CoordinatorError {
    fn from(err: NatsError) -> Self {
        CoordinatorError::NatsError(err)
    }
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Coordinator {
    pub async fn new(
        nats_server: std::net::SocketAddr,
        opts: CoordinatorOpts,
    ) -> Result<Self, CoordinatorError> {
        if !opts.allowed_projects.is_empty() && !opts.denied_projects.is_empty() {
            return Err(CoordinatorError::InvalidProjectFilter);
        }

        let client = FuzzorNatsClient::new(nats_server).await?;

        let _ = client
            .get_or_create_stream(jetstream::stream::Config {
                name: "fuzzor".to_string(),
                duplicate_window: Duration::from_secs(60 * 60),
                subjects: vec!["work.>".to_string(), "work-channel.>".to_string()],
                max_message_size: 8 * 1024 * 1024, // 8MiB
                max_consumers: -1,
                ..Default::default()
            })
            .await?;

        let buckets = vec![
            FuzzorObjectBuckets::Corpora,
            FuzzorObjectBuckets::Coverage,
            FuzzorObjectBuckets::BuildLogs,
        ];

        for bucket in buckets {
            let _ = client
                .get_or_create_object_store(jetstream::object_store::Config {
                    bucket: bucket.to_string(),
                    ..Default::default()
                })
                .await?;
        }

        Ok(Self {
            client,
            opts,
            metrics: Arc::new(SharedMetrics::new()),
        })
    }

    pub async fn run(&mut self, metrics_bind: SocketAddr) -> Result<(), CoordinatorError> {
        fuzzor_prometheus::monitor::start_metrics_server(metrics_bind, self.metrics.clone())
            .await
            .map_err(|_| CoordinatorError::FailedToStartMetricsServer)?;

        let projects: Vec<String> = std::fs::read_dir(
            std::env::var("FUZZOR_PROJECTS_DIR").unwrap_or(String::from("./projects/")),
        )
        .map_err(|_| CoordinatorError::ProjectsDirNotFound)?
        .filter(|entry| entry.is_ok())
        .map(|entry| entry.unwrap())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();

        log::info!("Found {} projects: {:?}", projects.len(), projects);

        let projects = if !self.opts.allowed_projects.is_empty() {
            projects
                .into_iter()
                .filter(|project| self.opts.allowed_projects.contains(&project))
                .collect()
        } else {
            projects
        };

        let mut projects = if !self.opts.denied_projects.is_empty() {
            projects
                .into_iter()
                .filter(|project| !self.opts.denied_projects.contains(&project))
                .collect()
        } else {
            projects
        };

        log::info!("Running {} projects: {:?}", projects.len(), projects);

        let mut handles = vec![];
        for project in projects.drain(..) {
            let client = self.client.clone();
            let opts = self.opts.clone();
            let metrics = self.metrics.clone();
            let handle = tokio::spawn(async move {
                let coordinator = SingleProjectCoordinator::new(client, opts, project).await;
                match coordinator {
                    Ok(mut coordinator) => match coordinator.run(metrics).await {
                        Ok(_) => (),
                        Err(e) => {
                            log::error!("Failed to run project coordinator: {}", e);
                        }
                    },
                    Err(e) => {
                        log::error!("Failed to create project coordinator: {}", e);
                    }
                }
            });
            handles.push(handle);
        }

        join_all(handles).await;

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SingleProjectCoordinator {
    client: FuzzorNatsClient,
    opts: CoordinatorOpts,
    project: String,
}

impl SingleProjectCoordinator {
    pub async fn new(
        client: FuzzorNatsClient,
        opts: CoordinatorOpts,
        project: String,
    ) -> Result<Self, CoordinatorError> {
        Ok(Self {
            client,
            opts,
            project,
        })
    }

    pub async fn run(&mut self, metrics: Arc<SharedMetrics>) -> Result<(), CoordinatorError> {
        let access_token =
            std::env::var("FUZZOR_GH_TOKEN").map_err(|_| CoordinatorError::MissingGitHubToken)?;

        // Use directory specified by the `FUZZOR_PROJECTS_DIR` env variable or use `./projects/` as
        // default.
        let folder = InMemoryProjectFolder::from_folder(
            ProjectFolder::new(
                PathBuf::from(
                    std::env::var("FUZZOR_PROJECTS_DIR").unwrap_or(String::from("./projects/")),
                )
                .join(&self.project),
            )
            .map_err(|_| CoordinatorError::ProjectsDirNotFound)?,
        );

        let config = folder.config();

        let gh_tracker = GitHubRevisionTracker::new(
            access_token.clone(),
            GitHubRepository {
                owner: config.owner.clone(),
                repo: config.repo.clone(),
            },
            GithubRevisionSource::Branch(config.branch.clone().unwrap_or(String::from("master"))),
        );

        let allocator = RemoteEnvironmentAllocator::new(self.client.addr().clone())
            .await
            .map_err(|_| CoordinatorError::FailedToCreateEnvAllocator)?;

        let builder = RemoteBuilder::new(self.client.addr().clone())
            .await
            .map_err(|_| CoordinatorError::FailedToCreateBuilder)?;

        let scheduler = Box::new(CoverageBasedScheduler::with_round_robin_fallback(
            folder.config(),
            Duration::from_secs(
                folder
                    .config()
                    .cpu_hours_per_campaign
                    .unwrap_or(self.opts.campaign_duration)
                    * 60
                    * 60,
            ),
        ));

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
        .await
        .map_err(|_| CoordinatorError::FailedToCreateCorpusHerder)?;

        let state = StdProjectState::new(state_location, corpus_herder);

        let config = folder.config();
        let mut project = Project::<_, _, _, _, _, RemoteCampaign, GitHubRevision>::new(
            folder,
            allocator.clone(),
            scheduler,
            state,
            fuzzor::project::ProjectOptions {
                ignore_first_revision: false,
                no_fuzzing: false,
            },
        );

        let (owner, repo) = {
            let split: Vec<&str> = config
                .report_repo
                .as_ref()
                .unwrap_or(&self.opts.report_repo)
                .split("/")
                .collect();
            assert!(split.len() == 2);
            (split[0], split[1])
        };

        let solution_monitor = SolutionReportingMonitor::new(GitHubRepoSolutionReporter::new(
            owner,
            repo,
            &access_token,
            config.ccs.clone(),
        ));
        project.register_monitor(Box::new(solution_monitor));

        let prometheus_monitor = PrometheusProjectMonitor::new(metrics);
        project.register_monitor(Box::new(prometheus_monitor));

        let (_quit_tx, quit_rx) = tokio::sync::mpsc::channel::<()>(16);

        project
            .run(gh_tracker, builder, quit_rx)
            .await
            .ok_or(CoordinatorError::FailedToRunProject)?;

        Ok(())
    }
}
