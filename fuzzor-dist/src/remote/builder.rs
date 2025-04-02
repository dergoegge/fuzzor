use std::{collections::HashSet, net::SocketAddr, path::PathBuf, time::Duration};

use async_nats::jetstream::consumer::{self, DeliverPolicy};
use fuzzor::{
    project::{
        builder::{ProjectBuild, ProjectBuildFailure, ProjectBuilder},
        description::ProjectDescription,
    },
    revisions::Revision,
};
use fuzzor_infra::ProjectConfig;
use rand::{rng, Rng, RngCore};

use crate::{
    coordinator::{FuzzorConsumers, FuzzorMsg, FuzzorSubjects},
    nats_client::FuzzorNatsClient,
};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BuildControlMsg {
    Build {
        id: String,
        project_config: ProjectConfig,
        tarball: Vec<u8>,
        revision_commit: String,
    },
    BuildAck,
    BuildFinished {
        revision_commit: String,
        revision_prev_commit: Option<String>,
        revision_changed_files: Vec<String>,
        harnesses: Vec<String>,
        image_location: String,
    },
    BuildFailed {
        build_log_location: Option<String>,
        error_msg: Option<String>,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

pub struct RemoteBuilder {
    pub nats_client: FuzzorNatsClient,

    pong_outstanding: bool,
}

impl RemoteBuilder {
    pub async fn new(nats_server: SocketAddr) -> Result<Self, String> {
        let nats_client = FuzzorNatsClient::new(nats_server)
            .await
            .map_err(|e| format!("Remote builder failed to connect to NATS: {}", e))?;

        Ok(Self {
            nats_client,
            pong_outstanding: false,
        })
    }

    async fn inner_build<PD: ProjectDescription, R: Revision>(
        &mut self,
        folder: PD,
        revision: R,
    ) -> Result<Result<ProjectBuild<R>, ProjectBuildFailure>, String> {
        let config = folder.config();

        let mut id = [0u8; 16];
        rng().fill_bytes(&mut id);
        let build_id = format!("build-{}-{}", config.name, hex::encode(&id));

        let consumer_config = consumer::pull::Config {
            durable_name: Some(
                FuzzorConsumers::RemoteBuilder {
                    id: build_id.clone(),
                }
                .to_string(),
            ),
            filter_subjects: vec![FuzzorSubjects::WorkChannel {
                id: build_id.clone(),
                receiver_is_worker: false,
            }
            .to_string()],
            deliver_policy: DeliverPolicy::New,
            ..Default::default()
        };

        let stream = self
            .nats_client
            .get_stream("fuzzor")
            .await
            .map_err(|e| format!("Failed to create stream: {}", e))?;

        let consumer = stream
            .create_consumer(consumer_config)
            .await
            .map_err(|e| format!("Failed to create consumer: {}", e))?;

        log::info!("Publishing work request for build '{}'", build_id);

        self.nats_client
            .publish_fuzzor_msg_and_wait(
                FuzzorSubjects::Build {
                    arch: config.architecture.clone(),
                    project: config.name.clone(),
                }
                .to_string(),
                BuildControlMsg::Build {
                    id: build_id.clone(),
                    project_config: config.clone(),
                    tarball: folder.tarball(),
                    revision_commit: revision.commit_hash().to_string(),
                },
                None,
                None,
            )
            .await
            .map_err(|e| {
                format!(
                    "Failed to publish work request for build '{}': {}",
                    build_id, e
                )
            })?;

        log::info!(
            "Received ack for build request '{}' (request is now persisted in NATS)",
            build_id
        );

        // Wait for build ack
        let mut build_ack_received = false;
        for _ in 0..10 {
            match self
                .nats_client
                .fetch_next_fuzzor_msg(&[&consumer], Duration::from_secs(24 * 60 * 60))
                .await
            {
                Ok(Some((
                    FuzzorMsg {
                        payload: BuildControlMsg::BuildAck,
                        ..
                    },
                    _,
                ))) => {
                    log::info!("Received build ack for build '{}'", build_id);
                    build_ack_received = true;
                    break;
                }

                Ok(None) => {
                    log::warn!("Timeout waiting for build ack for build '{}'", build_id);
                    continue;
                }
                Ok(_) => {
                    log::warn!("Received unexpected message for build '{}'", build_id);
                    continue;
                }
                Err(e) => {
                    log::warn!("Failed to fetch message: {}", e);
                    continue;
                }
            }
        }

        if !build_ack_received {
            return Err(format!(
                "Timeout waiting for build ack for build '{}'",
                build_id
            ));
        }

        let mut ping_interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            let consumers = &[&consumer];
            tokio::select! {
                _ = ping_interval.tick() => {
                    if self.pong_outstanding {
                        return Err("Build aborted: worker did not respond to ping".to_string());
                    } else {
                        let _ = self.ping_worker(&build_id).await;
                    }
                }
                maybe_msg = self.nats_client.fetch_next_fuzzor_msg(consumers, Duration::from_secs(24 * 60 * 60)) => {
                    if let Ok(Some((msg, _))) = maybe_msg {
                        if let Some(build_result) = self.handle_worker_msg(msg).await {
                            return Ok(build_result);
                        }
                    }
                }
            }
        }
    }

    async fn handle_worker_msg<R: Revision>(
        &mut self,
        msg: FuzzorMsg<BuildControlMsg>,
    ) -> Option<Result<ProjectBuild<R>, ProjectBuildFailure>> {
        match msg {
            FuzzorMsg {
                payload:
                    BuildControlMsg::BuildFinished {
                        mut harnesses,
                        revision_commit,
                        revision_prev_commit,
                        revision_changed_files,
                        ..
                    },
                ..
            } => {
                return Some(Ok(ProjectBuild::new(
                    HashSet::from_iter(harnesses.drain(..)),
                    R::new(
                        revision_commit,
                        revision_prev_commit,
                        revision_changed_files,
                    ),
                )));
            }
            FuzzorMsg {
                payload:
                    BuildControlMsg::BuildFailed {
                        build_log_location,
                        error_msg,
                    },
                ..
            } => match (build_log_location, error_msg) {
                (Some(log), _) => {
                    return Some(Err(ProjectBuildFailure::Build {
                        log: PathBuf::from(log),
                    }));
                }
                (None, Some(msg)) => {
                    return Some(Err(ProjectBuildFailure::Other { msg }));
                }
                (None, None) => {
                    return Some(Err(ProjectBuildFailure::Other {
                        msg: "No build log location or error message provided".to_string(),
                    }));
                }
            },
            FuzzorMsg {
                payload: BuildControlMsg::Pong { nonce },
                worker_info: Some(worker_info),
                ..
            } => {
                log::debug!(
                    "Received pong from worker '{}' nonce='{}'",
                    worker_info.id,
                    nonce
                );

                self.pong_outstanding = false;
            }
            _ => {}
        }

        None
    }

    async fn ping_worker(&mut self, build_id: &str) -> Result<(), String> {
        let nonce = rand::rng().random();
        self.nats_client
            .publish_fuzzor_msg_and_wait(
                FuzzorSubjects::WorkChannel {
                    id: build_id.to_string(),
                    receiver_is_worker: true,
                }
                .to_string(),
                BuildControlMsg::Ping { nonce },
                None,
                None,
            )
            .await
            .map_err(|e| format!("Failed to publish message: {}", e))?;
        self.pong_outstanding = true;

        Ok(())
    }
}

#[async_trait::async_trait]
impl<R, PD> ProjectBuilder<R, PD> for RemoteBuilder
where
    R: Revision + Send + Clone + 'static,
    PD: ProjectDescription + Clone + Send + 'static,
{
    async fn build(
        &mut self,
        folder: PD,
        revision: R,
    ) -> Result<ProjectBuild<R>, ProjectBuildFailure> {
        loop {
            match self.inner_build(folder.clone(), revision.clone()).await {
                Ok(result) => return result,
                Err(e) => {
                    self.pong_outstanding = false;
                    log::warn!("Failed to build revision: {}", e);
                    continue;
                }
            }
        }
    }
}
