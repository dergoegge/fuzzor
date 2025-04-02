pub mod builder;
pub mod fuzzer;

use async_nats::{self, jetstream::consumer};
use builder::{Builder, BuilderRevision};
use fuzzer::Fuzzer;
use fuzzor::{project::description::InMemoryProjectFolder, revisions::Revision};
use std::time::Duration;

use crate::{
    builder::BuildControlMsg,
    coordinator::{FuzzorConsumers, FuzzorMsg, FuzzorSubjects},
};
use crate::{environment::RemoteEnvironmentAllocatorMsg, nats_client::FuzzorNatsClient};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum WorkerPurpose {
    /// Build workers build container images to be used by fuzz workers
    Build,
    /// Fuzz workers run fuzzing campaigns and produce soutions, stats, corpora and coverage
    /// reports
    Fuzz,
}

impl std::fmt::Display for WorkerPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerPurpose::Build => write!(f, "building"),
            WorkerPurpose::Fuzz => write!(f, "fuzzing"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ListFilter<T> {
    None,
    Allow(Vec<T>),
    Deny(Vec<T>),
}

impl<T: std::fmt::Display> std::fmt::Display for ListFilter<T>
where
    T: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListFilter::None => write!(f, "none"),
            ListFilter::Allow(list) => {
                write!(
                    f,
                    "allow: {}",
                    list.iter()
                        .map(|item| item.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            ListFilter::Deny(list) => {
                write!(
                    f,
                    "deny: {}",
                    list.iter()
                        .map(|item| item.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkerInfo {
    pub id: String,
    pub purpose: WorkerPurpose,
    pub cpu_type: fuzzor_infra::CpuType,
    pub architecture: fuzzor_infra::CpuArchitecture,
    pub cores: u64,

    /// List of projects that the worker will or won't deal with
    pub project_filter: ListFilter<String>,
    /// List of harnesses that the worker will or won't deal with
    pub harness_filter: ListFilter<String>,
}

impl std::fmt::Display for WorkerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} worker (\"{}\") for {} with {} cores (project filter: {}, harness filter: {})",
            self.architecture,
            self.cpu_type,
            self.id,
            self.purpose,
            self.cores,
            self.project_filter,
            self.harness_filter
        )
    }
}

fn worker_info_from_env(opts: &WorkerOptions) -> WorkerInfo {
    let worker_id = opts
        .name
        .clone()
        .unwrap_or_else(|| hostname::get().unwrap().to_string_lossy().to_string());

    let architecture = if cfg!(target_arch = "x86_64") {
        fuzzor_infra::CpuArchitecture::X86_64
    } else if cfg!(target_arch = "aarch64") {
        fuzzor_infra::CpuArchitecture::Arm64
    } else {
        panic!("Unsupported architecture");
    };

    // Get CPU core count
    let cores = num_cpus::get() as u64;

    let project_filter = if opts.allowed_projects.is_empty() {
        ListFilter::None
    } else {
        ListFilter::Allow(opts.allowed_projects.clone())
    };
    let harness_filter = ListFilter::None;

    WorkerInfo {
        id: worker_id,
        purpose: opts.purpose.clone(),
        cpu_type: opts.cpu_type.clone(),
        architecture,
        cores,
        project_filter,
        harness_filter,
    }
}

#[derive(Clone)]
pub struct WorkerOptions {
    pub purpose: WorkerPurpose,
    pub cpu_type: fuzzor_infra::CpuType,
    pub name: Option<String>,
    pub registry: Option<String>,
    pub allowed_projects: Vec<String>,
}

pub struct NatsWorker {
    pub info: WorkerInfo,
    pub opts: WorkerOptions,
    pub nats_client: Option<FuzzorNatsClient>,
}

impl NatsWorker {
    pub fn new(opts: WorkerOptions) -> Self {
        let info = worker_info_from_env(&opts);

        Self {
            info,
            opts,
            nats_client: None,
        }
    }

    pub async fn run(&mut self, nats_server: &std::net::SocketAddr) {
        let client = match FuzzorNatsClient::new(nats_server.clone()).await {
            Ok(c) => c,
            Err(err) => {
                log::error!(
                    "Worker '{:?}' could not connect to nats server: {}",
                    self.opts.name,
                    err.to_string()
                );
                return;
            }
        };
        self.nats_client = Some(client);
        let client = self.nats_client.as_ref().unwrap();

        let stream_name = "fuzzor";
        let stream = match client.wait_for_stream(stream_name).await {
            Ok(stream) => stream,
            Err(e) => {
                log::error!(
                    "Worker '{}' failed to get JetStream stream '{}': {}",
                    self.info.id,
                    stream_name,
                    e
                );
                return;
            }
        };

        let mut consumer_configs = match &self.info.project_filter {
            ListFilter::Deny(_) => todo!("Project deny filters are not implemented!"),
            ListFilter::Allow(prjs) => prjs
                .iter()
                .map(|prj| consumer::pull::Config {
                    durable_name: Some(
                        FuzzorConsumers::Worker {
                            purpose: self.info.purpose.clone(),
                            arch: Some(self.info.architecture.clone()),
                            project: Some(prj.clone()),
                        }
                        .to_string(),
                    ),
                    filter_subjects: vec![match &self.info.purpose {
                        WorkerPurpose::Fuzz => FuzzorSubjects::Fuzz {
                            arch: Some(self.info.architecture.clone()),
                            project: prj.clone(),
                            harness: "*".to_string(),
                        }
                        .to_string(),
                        WorkerPurpose::Build => FuzzorSubjects::Build {
                            arch: Some(self.info.architecture.clone()),
                            project: prj.clone(),
                        }
                        .to_string(),
                    }
                    .to_string()],
                    ..Default::default()
                })
                .collect(),
            ListFilter::None => {
                vec![consumer::pull::Config {
                    durable_name: Some(
                        FuzzorConsumers::Worker {
                            purpose: self.info.purpose.clone(),
                            arch: Some(self.info.architecture.clone()),
                            project: None,
                        }
                        .to_string(),
                    ),
                    filter_subjects: vec![match &self.info.purpose {
                        WorkerPurpose::Fuzz => FuzzorSubjects::Fuzz {
                            arch: Some(self.info.architecture.clone()),
                            project: "*".to_string(),
                            harness: "*".to_string(),
                        }
                        .to_string(),
                        WorkerPurpose::Build => FuzzorSubjects::Build {
                            arch: Some(self.info.architecture.clone()),
                            project: "*".to_string(),
                        }
                        .to_string(),
                    }
                    .to_string()],
                    ..Default::default()
                }]
            }
        };

        let mut consumers = Vec::new();
        for cfg in consumer_configs.drain(..) {
            let name = cfg.durable_name.as_ref().unwrap().clone();
            consumers.push(match stream.create_consumer(cfg).await {
                Ok(consumer) => {
                    log::info!(
                        "Worker '{}' created JetStream consumer '{}' on stream '{}'",
                        self.info.id,
                        name,
                        stream_name
                    );
                    consumer
                }
                Err(e) => {
                    log::error!(
                        "Worker '{}' failed to create JetStream consumer '{}' on stream '{}': {}",
                        self.info.id,
                        name,
                        stream_name,
                        e
                    );
                    return;
                }
            });
        }

        loop {
            let consumers: Vec<_> = consumers.iter().collect();
            match &self.info.purpose {
                WorkerPurpose::Fuzz => {
                    match client
                        .fetch_next_fuzzor_msg(&consumers, Duration::from_secs(60 * 10))
                        .await
                    {
                        Ok(Some((msg, _))) => {
                            self.process_fuzz_announcement(&msg).await;
                        }
                        Ok(None) => continue,
                        Err(err) => {
                            log::error!("Failed to fetch next fuzz message: {}", err.to_string());
                            continue;
                        }
                    }
                }
                WorkerPurpose::Build => {
                    match client
                        .fetch_next_fuzzor_msg(&consumers, Duration::from_secs(60 * 10))
                        .await
                    {
                        Ok(Some((msg, _))) => {
                            self.process_build_announcement(&msg).await;
                        }
                        Ok(None) => continue,
                        Err(err) => {
                            log::error!("Failed to fetch next build message: {}", err.to_string());
                            continue;
                        }
                    }
                }
            }
        }
    }

    async fn process_fuzz_announcement(
        &self,
        fuzzor_msg: &FuzzorMsg<RemoteEnvironmentAllocatorMsg>,
    ) {
        match &fuzzor_msg.payload {
            RemoteEnvironmentAllocatorMsg::Allocate { id, params } => {
                log::trace!("Received Allocate message for campaign {}", id);

                let client = self.nats_client.as_ref().unwrap();

                let (maybe_fuzzer, response) = match Fuzzer::new(
                    self.info.clone(),
                    client.addr().clone(),
                    id.clone(),
                    params.clone(),
                    self.opts.registry.clone(),
                )
                .await
                {
                    Ok(fuzzer) => (Some(fuzzer), RemoteEnvironmentAllocatorMsg::AllocateAck),
                    Err(err) => {
                        log::error!("Could not create fuzzer: {}", err);
                        (None, RemoteEnvironmentAllocatorMsg::AllocateNack)
                    }
                };

                let _ = client
                    .publish_fuzzor_msg_and_wait(
                        FuzzorSubjects::WorkChannel {
                            id: id.clone(),
                            receiver_is_worker: false,
                        }
                        .to_string(),
                        response,
                        None,
                        Some(self.info.clone()),
                    )
                    .await;

                if let Some(mut fuzzer) = maybe_fuzzer {
                    if let Err(err) = fuzzer.run().await {
                        log::error!("Failed to run fuzzer: {}", err);
                    }
                }
            }
            msg => {
                log::error!("Received unknown allocator message: {:?}", msg);
            }
        }
    }

    async fn process_build_announcement(&self, fuzzor_msg: &FuzzorMsg<BuildControlMsg>) {
        match &fuzzor_msg.payload {
            BuildControlMsg::Build {
                id,
                project_config,
                tarball,
                revision_commit,
            } => {
                log::trace!("Received Build message for build {}", id);
                let client = self.nats_client.as_ref().unwrap();
                let (maybe_builder, response) = match Builder::new(
                    self.info.clone(),
                    self.opts.clone(),
                    client.addr().clone(),
                    id.clone(),
                )
                .await
                {
                    Ok(builder) => (Some(builder), BuildControlMsg::BuildAck),
                    Err(err) => {
                        log::error!("Could not create builder: {}", err);
                        (
                            None,
                            BuildControlMsg::BuildFailed {
                                build_log_location: None,
                                error_msg: Some(err.to_string()),
                            },
                        )
                    }
                };

                let _ = client
                    .publish_fuzzor_msg_and_wait(
                        FuzzorSubjects::WorkChannel {
                            id: id.clone(),
                            receiver_is_worker: false,
                        }
                        .to_string(),
                        response,
                        None,
                        Some(self.info.clone()),
                    )
                    .await;

                let desc = InMemoryProjectFolder::new(project_config.clone(), tarball.clone());
                let rev = BuilderRevision::new(revision_commit.clone(), None, Vec::new());

                if let Some(mut builder) = maybe_builder {
                    if let Err(err) = builder.run(desc, rev).await {
                        log::error!("Failed to run builder: {}", err);
                    }
                }
            }
            _ => {
                log::error!("Received unknown build message: {:?}", fuzzor_msg);
            }
        }
    }
}
