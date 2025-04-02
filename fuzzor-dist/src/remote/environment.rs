use async_nats::jetstream::{self};
use fuzzor::{
    env::{Environment, EnvironmentAllocator, EnvironmentParams},
    solutions::Solution,
};
use fuzzor_infra::FuzzerStats;
use rand::{rng, RngCore};
use std::{net::SocketAddr, time::Duration};

use crate::coordinator::{FuzzorConsumers, FuzzorMsg, FuzzorSubjects};
use crate::nats_client::FuzzorNatsClient;
/// `RemoteEnvironment` is an environment that is running on a remote machine. It is allocated by
/// the `RemoteEnvironmentAllocator` and its only purpose is to pass information to the owning
/// `RemoteCampaign`, i.e. the nats server address and the environment id.
pub struct RemoteEnvironment {
    pub nats_server: SocketAddr,
    pub id: String,
}

impl RemoteEnvironment {
    pub fn new(nats_server: SocketAddr, id: String) -> Self {
        Self { nats_server, id }
    }
}

#[async_trait::async_trait]
impl Environment for RemoteEnvironment {
    async fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn get_stats(&self) -> Result<FuzzerStats, String> {
        Err("Not implemented".to_string())
    }

    async fn get_solutions(&self) -> Result<Vec<Solution>, String> {
        Err("Not implemented".to_string())
    }

    async fn reproduce_solutions(
        &self,
        _solutions: Vec<Solution>,
    ) -> Result<Vec<Solution>, String> {
        Err("Not implemented".to_string())
    }

    async fn get_corpus(&self, _minimize: bool) -> Result<Vec<u8>, String> {
        Err("Not implemented".to_string())
    }

    async fn get_covered_files(&self) -> Result<Vec<String>, String> {
        Err("Not implemented".to_string())
    }

    async fn get_coverage_report(&self) -> Result<Vec<u8>, String> {
        Err("Not implemented".to_string())
    }

    async fn upload_initial_corpus(&self, _corpus: Vec<u8>) -> Result<(), String> {
        Ok(())
    }

    async fn start(&mut self) -> Result<(), String> {
        Ok(())
    }

    async fn shutdown(&mut self) -> bool {
        false
    }

    async fn ping(&self) -> Result<bool, String> {
        Err("Not implemented".to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RemoteEnvironmentAllocatorMsg {
    Allocate {
        id: String,
        params: EnvironmentParams,
    },
    AllocateAck,
    AllocateNack,
    Free,
}

#[derive(Clone)]
pub struct RemoteEnvironmentAllocator {
    pub nats_client: FuzzorNatsClient,
}

impl RemoteEnvironmentAllocator {
    pub async fn new(nats_server: SocketAddr) -> Result<Self, String> {
        let nats_client = match FuzzorNatsClient::new(nats_server).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to connect to NATS: {}", e);
                return Err(e.to_string());
            }
        };

        Ok(Self { nats_client })
    }
}

#[async_trait::async_trait]
impl EnvironmentAllocator<RemoteEnvironment> for RemoteEnvironmentAllocator {
    async fn alloc(&mut self, opts: EnvironmentParams) -> Result<RemoteEnvironment, String> {
        let mut id = [0u8; 16];
        rng().fill_bytes(&mut id);
        let env_id = format!(
            "env-{}-{}-{}",
            opts.project_config.name,
            opts.harness_name,
            hex::encode(&id)
        );

        log::debug!("Attempting to allocate environment {}", env_id);

        self.nats_client
            .publish_fuzzor_msg_and_wait(
                FuzzorSubjects::Fuzz {
                    arch: opts.project_config.architecture.clone(),
                    project: opts.project_config.name.clone(),
                    harness: opts.harness_name.clone(),
                }
                .to_string(),
                RemoteEnvironmentAllocatorMsg::Allocate {
                    id: env_id.clone(),
                    params: opts,
                },
                None,
                None,
            )
            .await
            .map_err(|e| e.to_string())?;

        let stream = self
            .nats_client
            .get_stream("fuzzor")
            .await
            .map_err(|e| e.to_string())?;

        let consumer_name = FuzzorConsumers::Allocator { id: env_id.clone() }.to_string();
        let consumer = stream
            .create_consumer(jetstream::consumer::pull::Config {
                durable_name: Some(consumer_name),
                filter_subject: FuzzorSubjects::WorkChannel {
                    id: env_id.clone(),
                    receiver_is_worker: false,
                }
                .to_string(),
                ..Default::default()
            })
            .await
            .map_err(|_| "Could not create campaign consumer during env allocation".to_string())?;

        match self
            .nats_client
            .fetch_next_fuzzor_msg(&[&consumer], Duration::from_secs(48 * 60 * 60))
            .await
        {
            Ok(Some((msg, _))) => match msg {
                FuzzorMsg {
                    payload: RemoteEnvironmentAllocatorMsg::AllocateAck,
                    ..
                } => Ok(RemoteEnvironment {
                    nats_server: self.nats_client.addr().clone(),
                    id: env_id,
                }),
                FuzzorMsg {
                    payload: RemoteEnvironmentAllocatorMsg::AllocateNack,
                    ..
                } => return Err("worker send nack, something is probably cooked".to_string()),
                _ => {
                    return Err("unknown message received while waiting for AllocateAck".to_string())
                }
            },
            Ok(None) => {
                return Err(
                    "No worker available within 48 hours, consider adding more workers".to_string(),
                )
            } // timeout
            Err(err) => {
                return Err(err.to_string());
            }
        }
    }

    async fn free(&mut self, _env: RemoteEnvironment) -> bool {
        true
    }
}
