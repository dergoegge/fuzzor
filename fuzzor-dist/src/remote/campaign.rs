use fuzzor::project::{
    campaign::{Campaign, CampaignEvent},
    harness::Harness,
};
use fuzzor_infra::{ProjectConfig, Sanitizer};

use crate::{
    coordinator::{FuzzorConsumers, FuzzorMsg, FuzzorSubjects},
    environment::RemoteEnvironment,
    nats_client::FuzzorNatsClient,
};

use std::{sync::Arc, time::Duration};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};

use async_nats::jetstream::consumer::{self, DeliverPolicy};

use tokio::io::AsyncReadExt;

/// Messages send and received by the coordinator (i.e. `RemoteCampaign`) and the workers (i.e. `Fuzzer`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CampaignControlMsg {
    /// Initialize the campaign
    Init,
    /// Acknowledge the initialization
    InitAck,

    /// Gracefully quit the campaign
    Quit,
    /// Immediately quit the campaign
    Kill,

    /// Campaign events
    Event {
        event: CampaignEvent,
    },

    /// Coordinator uses a ping/pong mechanism to check if the worker is still reachable.
    /// Worker will respond to a ping with a pong (including the nonce from the ping).
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

pub struct RemoteCampaign {
    env: RemoteEnvironment,
    event_sender: Sender<CampaignEvent>,
    nats_client: Option<FuzzorNatsClient>,
    project_config: ProjectConfig,
    harness: Arc<Mutex<Harness>>,
}

impl RemoteCampaign {
    async fn connect_to_nats(&mut self) {
        if self.nats_client.is_some() {
            return;
        }

        let client = match FuzzorNatsClient::new(self.env.nats_server).await {
            Ok(c) => c,
            Err(e) => {
                log::error!(
                    "Campaign '{}' failed to connect to NATS: {}",
                    self.env.id,
                    e
                );
                return;
            }
        };

        self.nats_client = Some(client);
    }

    fn get_channel_subject_for_publishing(&self) -> String {
        FuzzorSubjects::WorkChannel {
            id: self.env.id.clone(),
            receiver_is_worker: true,
        }
        .to_string()
    }

    fn get_channel_subject_for_subscribing(&self) -> String {
        FuzzorSubjects::WorkChannel {
            id: self.env.id.clone(),
            receiver_is_worker: false,
        }
        .to_string()
    }

    async fn send_event(&self, event: CampaignEvent) {
        log::trace!("Sending event: {:?}", &event);

        if let Err(err) = self.event_sender.send(event).await {
            log::error!("Failed to fire event: {:?}", err);
        }
    }

    async fn handle_quit(&mut self, harness: String) {
        log::info!(
            "Campaign '{}' received quit event for harness '{}'",
            self.env.id,
            harness
        );

        let js = self.nats_client.as_ref().unwrap().jetstream_context();

        if self.project_config.has_sanitizer(&Sanitizer::Coverage) {
            let coverage_store = match js.get_object_store("coverage").await {
                Ok(store) => store,
                Err(e) => {
                    log::error!("Failed to get object store '{}': {}", "coverage", e);
                    return;
                }
            };

            let mut object = match coverage_store
                .get(format!("{}-{}/covered_files.txt", self.project_config.name, harness).as_str())
                .await
            {
                Ok(object) => object,
                Err(e) => {
                    log::error!(
                        "Failed to get covered files for harness '{}': {}",
                        harness,
                        e
                    );
                    return;
                }
            };

            let mut file_contents = Vec::new();
            if let Err(e) = object.read_to_end(&mut file_contents).await {
                log::error!(
                    "Failed to read covered files data for harness '{}': {}",
                    harness,
                    e
                );
                return;
            }

            match String::from_utf8(file_contents) {
                Ok(covered_files) => {
                    let mut harness = self.harness.lock().await;
                    harness
                        .state_mut()
                        .set_covered_files(
                            covered_files.split("\n").map(|s| s.to_string()).collect(),
                        )
                        .await;
                }
                Err(e) => {
                    log::error!(
                        "Covered files data for harness '{}' is not valid UTF-8: {}",
                        harness,
                        e
                    );
                }
            }
        }

        let corpus_store = match js.get_object_store("corpora").await {
            Ok(store) => store,
            Err(e) => {
                log::error!("Failed to get object store '{}': {}", "corpora", e);
                return;
            }
        };

        let mut object = match corpus_store
            .get(format!("{}-{}/corpus.tar", self.project_config.name, harness).as_str())
            .await
        {
            Ok(object) => object,
            Err(e) => {
                log::warn!("Failed to get corpus for harness '{}': {}", harness, e);
                return;
            }
        };

        let mut corpus_tar = Vec::new();
        if let Err(e) = object.read_to_end(&mut corpus_tar).await {
            log::warn!("Failed to read corpus for harness '{}': {}", harness, e);
            self.send_event(CampaignEvent::Quit(harness, None)).await;
        } else {
            self.send_event(CampaignEvent::Quit(harness, Some(corpus_tar)))
                .await;
        }
    }
}

#[async_trait::async_trait]
impl Campaign<RemoteEnvironment> for RemoteCampaign {
    async fn new(
        project_config: ProjectConfig,
        harness: Arc<Mutex<Harness>>,
        env: RemoteEnvironment,
        event_sender: Sender<CampaignEvent>,
    ) -> Self {
        log::info!(
            "New campaign project='{}' harness='{}' (id='{}')",
            project_config.name,
            harness.lock().await.name(),
            env.id
        );
        let mut campaign = Self {
            env,
            event_sender,
            nats_client: None,
            project_config,
            harness,
        };

        campaign.connect_to_nats().await;

        campaign
    }

    async fn run(&mut self, mut quit_rx: Receiver<bool>) {
        if self.nats_client.is_none() {
            self.send_event(CampaignEvent::Quit(self.env.id.clone(), None))
                .await;
            return;
        }

        let client = self.nats_client.as_ref().unwrap();
        let js = client.jetstream_context();

        let stream = match js.get_stream("fuzzor").await {
            Ok(stream) => stream,
            Err(e) => {
                log::error!("Failed to get stream '{}': {}", "fuzzor", e);
                return;
            }
        };

        // Initialize campaign event consumer
        let consumer_config = consumer::pull::Config {
            durable_name: Some(
                FuzzorConsumers::Campaign {
                    id: self.env.id.clone(),
                }
                .to_string(),
            ),
            filter_subjects: vec![self.get_channel_subject_for_subscribing()],
            ack_policy: consumer::AckPolicy::Explicit,
            ack_wait: std::time::Duration::from_secs(60 * 5),
            // We are using the same channel as the environment allocator (since we use the env id
            // as campaign id), so we use the `DeliverPolicy::New` to avoid receiving the old
            // allocator msg in the subject here.
            deliver_policy: DeliverPolicy::New,
            ..Default::default()
        };

        let consumer = match stream.create_consumer(consumer_config).await {
            Ok(consumer) => consumer,
            Err(e) => {
                log::error!("Failed to create consumer '{}': {}", self.env.id, e);
                return;
            }
        };

        if let Err(err) = client
            .publish_fuzzor_msg_and_wait(
                self.get_channel_subject_for_publishing(),
                CampaignControlMsg::Init,
                None,
                None,
            )
            .await
        {
            log::error!(
                "Failed to send init message for campaign '{}': {}",
                self.env.id,
                err
            );
            self.send_event(CampaignEvent::Quit(self.env.id.clone(), None))
                .await;
        }

        log::debug!(
            "Campaign '{}' started event consumer on stream '{}'",
            self.env.id,
            "fuzzor",
        );

        let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

        'outer: loop {
            let consumers = &[&consumer];
            tokio::select! {
                _ = ping_interval.tick() => {
                    let _ = client.publish_fuzzor_msg_and_wait(
                        self.get_channel_subject_for_publishing(),
                        CampaignControlMsg::Ping { nonce: 0u64 },
                        None,
                        None,
                    );
                }
                _ = quit_rx.recv() => {
                    break;
                }
                msg = client.fetch_next_fuzzor_msg(consumers, Duration::from_secs(60 * 10)) => {
                   match msg {
                       Ok(Some((msg, _))) => {
                           match msg {
                               FuzzorMsg { payload: CampaignControlMsg::Event { event }, .. } => {
                                   log::debug!("Received event for campaign='{}': {:?}", self.env.id, event);
                                   match event {
                                       CampaignEvent::Quit(harness, _) => {
                                           self.handle_quit(harness.clone()).await;
                                           break 'outer;
                                       }
                                       _ => {
                                           self.send_event(event).await
                                       }
                                   }
                               }
                               _ => {}
                           }
                       }
                       Ok(None) => {} // timeout
                       _ => {}
                   }
                }
            }
        }

        log::info!("Campaign '{}' ended", self.env.id);
    }

    async fn end(self) -> RemoteEnvironment {
        self.env
    }
}
