use async_nats::jetstream::{self, consumer::PullConsumer};
use futures::StreamExt;
use fuzzor::{
    env::ResourcePool,
    project::{
        builder::{ProjectBuild, ProjectBuildFailure, ProjectBuilder},
        description::ProjectDescription,
    },
    revisions::Revision,
};
use fuzzor_docker::{builder::DockerBuilder, env::DockerMachine};
use std::{net::SocketAddr, time::Duration};

use crate::{
    builder::BuildControlMsg,
    coordinator::{FuzzorConsumers, FuzzorMsg, FuzzorSubjects},
};

use super::{WorkerInfo, WorkerOptions};

#[derive(Clone, Debug)]
pub struct BuilderRevision {
    commit_hash: String,
    modified_files: Vec<String>,
}

impl Revision for BuilderRevision {
    fn commit_hash(&self) -> &str {
        &self.commit_hash
    }
    fn modified_files(&self) -> &[String] {
        &self.modified_files
    }
    fn previous_commit_hash(&self) -> Option<&str> {
        None
    }

    fn new(
        commit_hash: String,
        _previous_commit_hash: Option<String>,
        modified_files: Vec<String>,
    ) -> Self {
        Self {
            commit_hash,
            modified_files,
        }
    }
}

pub struct Builder {
    build_id: String,
    worker_info: WorkerInfo,
    opts: WorkerOptions,
    nats_client: async_nats::Client,
}

impl Builder {
    pub async fn new(
        worker_info: WorkerInfo,
        opts: WorkerOptions,
        nats_server: SocketAddr,
        build_id: String,
    ) -> Result<Self, String> {
        let nats_url = format!("nats://{}", nats_server);
        let nats_client = async_nats::connect(&nats_url)
            .await
            .map_err(|e| format!("Failed to connect to NATS: {}", e))?;
        Ok(Self {
            build_id,
            worker_info,
            opts,
            nats_client,
        })
    }

    fn get_channel_subject_for_publishing(&self) -> String {
        FuzzorSubjects::WorkChannel {
            id: self.build_id.clone(),
            receiver_is_worker: false,
        }
        .to_string()
    }

    fn get_channel_subject_for_subscribing(&self) -> String {
        FuzzorSubjects::WorkChannel {
            id: self.build_id.clone(),
            receiver_is_worker: true,
        }
        .to_string()
    }

    pub async fn run<
        P: ProjectDescription + Send + Clone + 'static,
        R: Revision + Send + Clone + 'static,
    >(
        &mut self,
        desc: P,
        revision: R,
    ) -> Result<(), String> {
        log::info!("Starting builder for build '{}'", self.build_id);

        let js = jetstream::new(self.nats_client.clone());

        let stream = js
            .get_stream("fuzzor")
            .await
            .map_err(|e| format!("Failed to get stream: {}", e))?;

        let consumer = stream
            .create_consumer(jetstream::consumer::pull::Config {
                durable_name: Some(FuzzorConsumers::Builder { id: self.build_id.clone() }.to_string()),
                filter_subject: self.get_channel_subject_for_subscribing(),
                ..Default::default()
            })
            .await
            .map_err(|e| format!("Failed to create consumer: {}", e))?;

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let build_desc = desc.clone();
        let rev = revision.clone();
        let registry = self.opts.registry.clone();
        tokio::spawn(async move {
            let local_machine = DockerMachine {
                cores: (0..num_cpus::get() as u64).collect(),
                // TODO this should be configurable or just use the unix socket
                daemon_addr: "tcp://127.0.0.1:2375".to_string(),
            };

            let mut builder = match registry {
                Some(registry) => {
                    DockerBuilder::with_registry(ResourcePool::new(vec![local_machine]), registry)
                }
                None => DockerBuilder::new(ResourcePool::new(vec![local_machine])),
            };

            let build = builder.build(build_desc, rev).await;
            let _ = tx.send(build).await;
        });

        loop {
            let config = desc.clone().config();
            tokio::select! {
                _ = self.process_control_messages(&consumer) => {}
                build = rx.recv() => {
                    match build {
                        Some(Ok(build)) => {
                            let _ = self.handle_successful_build(config.name, build).await;
                            break;
                        }
                        Some(Err(e)) => {
                            let _ = self.handle_failed_build(e).await;
                            break;
                        }
                        None => {
                            log::error!("Builder received no build result");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_successful_build<R: Revision>(
        &mut self,
        project_name: String,
        build: ProjectBuild<R>,
    ) -> Result<(), String> {
        self.send_worker_msg(FuzzorMsg {
            worker_info: Some(self.worker_info.clone()),
            correlation_id: None,
            payload: BuildControlMsg::BuildFinished {
                revision_commit: build.revision().commit_hash().to_string(),
                revision_prev_commit: build
                    .revision()
                    .previous_commit_hash()
                    .map(|h| h.to_string()),
                revision_changed_files: build.revision().modified_files().to_vec(),
                harnesses: build.harnesses().iter().cloned().collect(),
                image_location: format!(
                    "fuzzor-{}-{}",
                    project_name,
                    build.revision().commit_hash()
                ),
            },
        })
        .await?;

        Ok(())
    }

    async fn handle_failed_build(&mut self, failure: ProjectBuildFailure) -> Result<(), String> {
        match failure {
            ProjectBuildFailure::Build { log } => {
                let js = jetstream::new(self.nats_client.clone());
                let build_logs_bucket = js
                    .get_object_store("build-logs")
                    .await
                    .map_err(|e| format!("Failed to get build logs object store: {}", e))?;

                let mut error_msg = None;
                let mut build_log_location = Some(format!("{}-error.log", self.build_id));
                if let Ok(mut file) = tokio::fs::File::open(&log).await {
                    match build_logs_bucket
                        .put(build_log_location.as_ref().unwrap().as_str(), &mut file)
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            build_log_location = None;
                            error_msg = Some(format!("Failed to put build log: {}", e));
                        }
                    }
                } else {
                    build_log_location = None;
                    error_msg = Some(format!("Failed to open build log"));
                }

                let _ = self
                    .send_worker_msg(FuzzorMsg {
                        worker_info: Some(self.worker_info.clone()),
                        correlation_id: None,
                        payload: BuildControlMsg::BuildFailed {
                            build_log_location,
                            error_msg,
                        },
                    })
                    .await?;

                Ok(())
            }
            ProjectBuildFailure::Other { msg } => {
                let _ = self
                    .send_worker_msg(FuzzorMsg {
                        worker_info: Some(self.worker_info.clone()),
                        correlation_id: None,
                        payload: BuildControlMsg::BuildFailed {
                            build_log_location: None,
                            error_msg: Some(msg),
                        },
                    })
                    .await?;

                Ok(())
            }
        }
    }

    async fn process_control_messages(&mut self, consumer: &PullConsumer) -> Result<(), String> {
        let mut messages = consumer
            .fetch()
            .max_messages(1)
            .expires(Duration::from_secs(60 * 60))
            .messages()
            .await
            .map_err(|e| format!("Failed to fetch messages: {}", e))?;

        while let Some(message) = messages.next().await {
            let msg = message.map_err(|e| format!("Failed to get message: {}", e))?;
            let _ = msg.ack().await;

            let control_msg: FuzzorMsg<BuildControlMsg> = serde_json::from_slice(&msg.payload)
                .map_err(|e| format!("Failed to deserialize message: {}", e))?;

            match control_msg.payload {
                BuildControlMsg::Ping { nonce } => {
                    log::debug!("Received ping from coordinator nonce='{}'", nonce);

                    let _ = self
                        .send_worker_msg(FuzzorMsg {
                            worker_info: Some(self.worker_info.clone()),
                            correlation_id: None,
                            payload: BuildControlMsg::Pong { nonce },
                        })
                        .await;
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn send_worker_msg(&mut self, msg: FuzzorMsg<BuildControlMsg>) -> Result<(), String> {
        let js = jetstream::new(self.nats_client.clone());

        let msg_bytes =
            serde_json::to_vec(&msg).map_err(|e| format!("Failed to serialize message: {}", e))?;

        js.publish(self.get_channel_subject_for_publishing(), msg_bytes.into())
            .await
            .map_err(|e| format!("Failed to send message: {}", e))?
            .await
            .map_err(|e| format!("Failed to wait for ack: {}", e))?;

        Ok(())
    }
}
