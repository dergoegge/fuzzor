use fuzzor::{
    env::{Environment, EnvironmentAllocator, EnvironmentParams, ResourcePool},
    project::{
        campaign::{Campaign, CampaignEvent, LocalCampaign},
        harness::{Harness, HarnessState},
    },
    solutions::{inmemory::InMemorySolutionTracker, SolutionTracker},
};
use fuzzor_docker::env::{DockerEnv, DockerEnvAllocator, DockerMachine};
use fuzzor_infra::FuzzerStats;
use std::{collections::HashSet, io::Cursor, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, sync::Mutex};

use crate::{
    campaign::CampaignControlMsg,
    coordinator::{FuzzorConsumers, FuzzorMsg, FuzzorSubjects},
};
use async_nats::jetstream;
use futures::StreamExt;

use super::WorkerInfo;

pub struct NatsHarnessState {
    solution_tracker: Arc<Mutex<InMemorySolutionTracker>>,
    js_ctx: jetstream::Context,
    id: String,
}

impl NatsHarnessState {
    pub fn new(id: String, js_ctx: jetstream::Context) -> Self {
        Self {
            solution_tracker: Arc::new(Mutex::new(InMemorySolutionTracker::default())),
            js_ctx,
            id,
        }
    }
}

// Take all files from a tarball and return a new tarball that contains all the files in the root
fn flatten_tar_ball(tar_data: Vec<u8>) -> Result<Vec<u8>, String> {
    let reader = Cursor::new(tar_data);
    let mut archive = tar::Archive::new(reader);
    let mut new_tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut new_tar_data);

        for entry_result in archive.entries().map_err(|e| e.to_string())? {
            let mut entry = entry_result.map_err(|e| e.to_string())?;
            if !entry.header().entry_type().is_file() {
                continue; // Skip non-file entries (directories, links, etc.)
            }

            let path = entry.path().map_err(|e| e.to_string())?.to_path_buf();
            if let Some(file_name) = path.file_name() {
                // Append file with only its name to the new tarball
                let mut header = tar::Header::new_gnu();
                header.set_size(entry.size() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, file_name, &mut entry)
                    .map_err(|e| e.to_string())?;
            } else {
                log::warn!("Skipping entry with invalid path: {:?}", path);
            }
        }
        builder.finish().map_err(|e| e.to_string())?;
    } // Builder is dropped here, flushing the data

    Ok(new_tar_data)
}

#[async_trait::async_trait]
impl HarnessState for NatsHarnessState {
    async fn solutions(&self) -> Arc<Mutex<dyn SolutionTracker + Send>> {
        self.solution_tracker.clone()
    }

    async fn set_covered_files(&mut self, covered_files: Vec<String>) {
        let store = match self.js_ctx.get_object_store("coverage").await {
            Ok(store) => store,
            Err(e) => {
                log::error!("Failed to get coverage object store: {}", e);
                return;
            }
        };

        let mut cursor = Cursor::new(covered_files.join("\n"));
        if let Err(e) = store
            .put(
                format!("{}/covered_files.txt", self.id).as_str(),
                &mut cursor,
            )
            .await
        {
            log::error!("Failed to store covered files: {}", e);
        }
    }

    async fn store_coverage_report(&self, tar: Vec<u8>) {
        let store = match self.js_ctx.get_object_store("coverage").await {
            Ok(store) => store,
            Err(e) => {
                log::error!("Failed to get coverage object store: {}", e);
                return;
            }
        };

        let mut cursor = Cursor::new(tar);
        if let Err(e) = store
            .put(
                format!("{}/coverage_report.tar", self.id).as_str(),
                &mut cursor,
            )
            .await
        {
            log::error!("Failed to store coverage report: {}", e);
        }
    }

    async fn record_stats(&mut self, _stats: FuzzerStats) {}

    // Unused
    async fn covered_files(&self) -> HashSet<String> {
        HashSet::new()
    }
    async fn covers_file(&self, _file: String) -> bool {
        false
    }
}

pub struct Fuzzer {
    pub worker_info: WorkerInfo,
    pub campaign_id: String,
    pub params: EnvironmentParams,

    pub env_allocator: DockerEnvAllocator,
    pub env: Option<DockerEnv>,

    pub nats_server: SocketAddr,
}

impl Fuzzer {
    pub async fn new(
        worker_info: WorkerInfo,
        nats_server: SocketAddr,
        campaign_id: String,
        params: EnvironmentParams,
        registry: Option<String>,
    ) -> Result<Self, String> {
        let local_machine = DockerMachine {
            cores: (0..num_cpus::get() as u64).collect(),
            daemon_addr: "tcp://127.0.0.1:2375".to_string(), // TODO this should be configurable or
                                                             // just use the unix socket
        };
        let mut env_allocator = match registry {
            Some(registry) => {
                DockerEnvAllocator::with_registry(ResourcePool::new(vec![local_machine]), registry)
            }
            None => DockerEnvAllocator::new(ResourcePool::new(vec![local_machine])),
        };

        let env = env_allocator.alloc(params.clone()).await?;

        Ok(Self {
            worker_info,
            campaign_id,
            params,
            env_allocator,
            env: Some(env),
            nats_server,
        })
    }

    pub async fn run(&mut self) -> Result<(), String> {
        let nats_url = format!("nats://{}", self.nats_server);
        let client = match async_nats::connect(&nats_url).await {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to connect to NATS: {}", e)),
        };

        let js = jetstream::new(client);

        let stream = match js.get_stream("fuzzor").await {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to get stream: {}", e)),
        };

        let consumer = match stream
            .create_consumer(jetstream::consumer::pull::Config {
                durable_name: Some(
                    FuzzorConsumers::Fuzzer {
                        id: self.campaign_id.clone(),
                    }
                    .to_string(),
                ),
                filter_subjects: vec![self.get_channel_subject_for_subscribing()],
                ..Default::default()
            })
            .await
        {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to create consumer: {}", e)),
        };

        let init_msg = self.get_next_control_msg(&consumer).await?;
        match init_msg {
            FuzzorMsg {
                payload: CampaignControlMsg::Init,
                ..
            } => {}
            _ => return Err(format!("Unexpected message: {:?}", init_msg)),
        }

        let harness_id = format!(
            "{}-{}",
            self.params.project_config.name, self.params.harness_name,
        );
        let harness = Arc::new(Mutex::new(Harness::new(
            self.params.harness_name.clone(),
            Box::new(NatsHarnessState::new(harness_id, js.clone())),
        )));

        let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(100);
        let (quit_sender, quit_receiver) = tokio::sync::mpsc::channel(1);

        let env = self.env.take().unwrap();

        match js.get_object_store("corpora").await {
            Ok(bucket) => match bucket
                .get(format!(
                    "{}-{}/corpus.tar",
                    self.params.project_config.name, self.params.harness_name
                ))
                .await
            {
                Ok(mut corpus_obj) => {
                    let mut corpus_tarball = Vec::new();
                    let _ = corpus_obj.read_to_end(&mut corpus_tarball).await;
                    let _ = env.upload_initial_corpus(corpus_tarball).await;
                }
                Err(err) => {
                    log::warn!("Failed to download corpus from bucket: {}", err.to_string());
                }
            },
            Err(_) => {
                log::warn!("Corpora storage bucket not found");
            }
        }

        let config = self.params.project_config.clone();
        let mut campaign_handle = tokio::spawn(async move {
            let mut campaign = LocalCampaign::new(config, harness, env, event_sender).await;
            campaign.run(quit_receiver).await;

            campaign
        });

        loop {
            tokio::select! {
                event = event_receiver.recv() => {
                    if let Some(event) = event {
                        self.handle_event(event, &js).await;
                    } else {
                        log::warn!("Failed to receive event from campaign");
                    }
                }
                control_msg = self.get_next_control_msg(&consumer) => {
                    match control_msg {
                        Ok(FuzzorMsg { payload: CampaignControlMsg::Quit, .. }) => {
                            let _ = quit_sender.send(false).await;
                        }
                        Ok(FuzzorMsg { payload: CampaignControlMsg::Kill, .. }) => {
                            let _ = quit_sender.send(true).await;
                        }
                        Ok(FuzzorMsg { payload: CampaignControlMsg::Ping { nonce }, correlation_id, .. }) => {
                            self.send_pong(&js, nonce, correlation_id).await;
                        }
                        _ => {}
                    }
                }
                campaign_handle = &mut campaign_handle => {
                    let Ok(campaign) = campaign_handle else {
                        return Err("Failed to join campaign handle".to_string());
                    };

                    let env = campaign.end().await;

                    let _ = self.env_allocator.free(env).await;
                    break;
                }
            }
        }

        // Drain the event receiver (avoid race condition above)
        while let Some(event) = event_receiver.recv().await {
            self.handle_event(event, &js).await;
        }

        Ok(())
    }

    async fn send_pong(&self, js: &jetstream::Context, nonce: u64, correlation_id: Option<String>) {
        let pong_msg = FuzzorMsg {
            payload: CampaignControlMsg::Pong { nonce },
            correlation_id,
            worker_info: Some(self.worker_info.clone()),
        };

        let serde_result = serde_json::to_vec(&pong_msg);
        match serde_result {
            Ok(bytes) => {
                let _ = js
                    .publish(self.get_channel_subject_for_publishing(), bytes.into())
                    .await;
            }
            Err(e) => log::warn!("Failed to serialize pong message: {}", e),
        }
    }

    fn get_channel_subject_for_publishing(&self) -> String {
        FuzzorSubjects::WorkChannel {
            id: self.campaign_id.clone(),
            receiver_is_worker: false,
        }
        .to_string()
    }

    fn get_channel_subject_for_subscribing(&self) -> String {
        FuzzorSubjects::WorkChannel {
            id: self.campaign_id.clone(),
            receiver_is_worker: true,
        }
        .to_string()
    }

    async fn handle_quit(&self, harness: String, corpus: Option<Vec<u8>>, js: &jetstream::Context) {
        let store = match js.get_object_store("corpora").await {
            Ok(store) => store,
            Err(e) => {
                log::error!("Failed to get corpus object store: {}", e);
                return;
            }
        };
        let corpus = corpus.map(|c| match flatten_tar_ball(c.clone()) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to flatten corpus: {}", e);
                c // return unflattened corpus instead of failing
            }
        });

        if let Some(corpus) = corpus {
            let mut cursor = Cursor::new(corpus);
            if let Err(e) = store
                .put(
                    format!("{}-{}/corpus.tar", self.params.project_config.name, harness).as_str(),
                    &mut cursor,
                )
                .await
            {
                log::error!("Failed to store corpus: {}", e);
            }
        }
    }

    async fn handle_event(&self, event: CampaignEvent, js: &jetstream::Context) {
        let event = match event {
            // Remove the corpus result from quit events, we're not sending those through the MQ
            CampaignEvent::Quit(harness, corpus) => {
                self.handle_quit(harness.clone(), corpus, js).await;
                CampaignEvent::Quit(harness, None)
            }
            e => e,
        };

        let serde_result = serde_json::to_vec(&FuzzorMsg {
            worker_info: Some(self.worker_info.clone()),
            correlation_id: None,
            payload: CampaignControlMsg::Event { event },
        });

        match serde_result {
            Ok(bytes) => {
                if let Ok(ack) = js
                    .publish(self.get_channel_subject_for_publishing(), bytes.into())
                    .await
                {
                    let _ = ack.await;
                }
            }
            Err(e) => log::warn!("Failed to serialize event: {}", e),
        }
    }

    async fn get_next_control_msg(
        &self,
        consumer: &jetstream::consumer::Consumer<jetstream::consumer::pull::Config>,
    ) -> Result<FuzzorMsg<CampaignControlMsg>, String> {
        let mut msg = consumer
            .fetch()
            .max_messages(1)
            .expires(Duration::from_secs(60))
            .messages()
            .await
            .map_err(|e| format!("Failed to fetch messages: {}", e))?;
        let js_msg = msg
            .next()
            .await
            .ok_or("Failed to get next message from batch".to_string())?
            .map_err(|_| "Failed to get next message from batch".to_string())?; // wtf is this type

        let msg = serde_json::from_slice::<FuzzorMsg<CampaignControlMsg>>(&js_msg.payload)
            .map_err(|e| format!("Failed to deserialize message: {}", e))?;

        let _ = js_msg.ack().await;

        Ok(msg)
    }
}
