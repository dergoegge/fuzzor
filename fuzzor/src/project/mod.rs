pub mod builder;
pub mod campaign;
pub mod description;
pub mod harness;
pub mod monitor;
pub mod scheduler;
pub mod state;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::{
    corpora::CorpusHerder,
    env::{Environment, EnvironmentAllocator},
    revisions::{Revision, RevisionTracker},
};
use builder::{ProjectBuild, ProjectBuilder};
use campaign::{Campaign, CampaignEvent, CampaignJoinHandle};
use description::ProjectDescription;
use harness::{Harness, PersistentHarnessState, SharedHarnessMap};
use monitor::ProjectMonitor;
use scheduler::{CampaignScheduler, CampaignSchedulerInput};
use state::State;

use fuzzor_infra::ProjectConfig;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;

#[derive(Debug)]
pub enum ProjectEvent {
    NewBuild,
    BuildFailure,
}

pub struct ProjectOptions {
    /// Ignore the first revision returned by the revision tracker and only start fuzzing on the
    /// next revision that becomes available.
    pub ignore_first_revision: bool,
    /// Only build the environment but don't schedule any fuzzing campaigns.
    pub no_fuzzing: bool,
}

pub struct Project<E, D, EA, CH, S>
where
    E: Environment,
    CH: CorpusHerder<Vec<u8>> + Send,
    S: State<CH, PersistentHarnessState>,
{
    description: D,
    config: ProjectConfig,

    harnesses: SharedHarnessMap,
    retired_harnesses: SharedHarnessMap,

    state: S,

    scheduler: Arc<Mutex<Box<dyn CampaignScheduler + Send>>>,
    env_allocator: EA,
    wake_up_scheduler: Option<Sender<()>>,

    campaigns: HashMap<String, (CampaignJoinHandle<E>, Sender<bool>)>,

    monitors: Vec<Box<dyn ProjectMonitor + Send>>,

    options: ProjectOptions,

    phantom: std::marker::PhantomData<CH>,
}

impl<E, D, EA, CH, S> Project<E, D, EA, CH, S>
where
    E: Environment + Send + 'static,
    D: ProjectDescription + Clone + Send + 'static,
    EA: EnvironmentAllocator<E> + Clone + Send + 'static,
    CH: CorpusHerder<Vec<u8>> + Send + 'static,
    S: State<CH, PersistentHarnessState>,
{
    pub fn new(
        description: D,
        env_allocator: EA,
        scheduler: Box<dyn CampaignScheduler + Send>,
        state: S,
        options: ProjectOptions,
    ) -> Self {
        Self {
            config: description.config(),
            description,
            harnesses: Arc::new(Mutex::new(HashMap::new())),
            retired_harnesses: Arc::new(Mutex::new(HashMap::new())),
            state,
            wake_up_scheduler: None,
            campaigns: HashMap::new(),
            scheduler: Arc::new(Mutex::new(scheduler)),
            env_allocator,
            monitors: Vec::new(),
            options,
            phantom: std::marker::PhantomData::default(),
        }
    }

    pub fn config(&self) -> &ProjectConfig {
        &self.config
    }

    pub fn harnesses(&self) -> SharedHarnessMap {
        self.harnesses.clone()
    }

    pub fn register_monitor(&mut self, monitor: Box<dyn ProjectMonitor + Send>) {
        self.monitors.push(monitor);
    }

    async fn handle_build_result<R: Revision>(&mut self, result: Result<ProjectBuild<R>, String>) {
        match result {
            Ok(build) => self.handle_new_build(build).await,
            Err(_) => {
                for monitor in self.monitors.iter_mut() {
                    monitor
                        .monitor_project_event(self.config.name.clone(), ProjectEvent::BuildFailure)
                        .await;
                }
            }
        }
    }

    // Update active and retired harnesses when a new build is available.
    async fn handle_new_build<R: Revision>(&mut self, build: ProjectBuild<R>) {
        let mut harnesses = self.harnesses.lock().await;
        let harness_names = harnesses.keys().cloned().collect::<HashSet<String>>();

        let new = build.harnesses() - &harness_names;
        let removed = &harness_names - build.harnesses();

        if !new.is_empty() {
            log::info!(
                "New harnesses found in latest build for project '{}': {:?}",
                self.config.name,
                new,
            );
        }

        if !removed.is_empty() {
            log::info!(
                "Harnesses removed in latest build for project '{}': {:?}",
                self.config.name,
                removed,
            );
        }

        let mut retired_harnesses = self.retired_harnesses.lock().await;

        // Add new harnesses to the shared harness map
        for harness_name in new.iter() {
            let state = self.state.create_harness_state(harness_name.clone()).await;

            // Bring back an old harness from retirement or create a new harness.
            let harness = retired_harnesses
                .remove(harness_name)
                .unwrap_or(Arc::new(Mutex::new(Harness::new(
                    harness_name.to_string(),
                    Box::new(state),
                ))));

            harnesses.insert(harness_name.to_string(), harness);

            log::trace!("Added {} to {}'s harnesses", harness_name, self.config.name);
        }

        // Retire removed harnesses by moving them into a separate map.
        for harness_name in removed.iter() {
            if let Some(harness) = harnesses.remove(harness_name) {
                retired_harnesses.insert(harness_name.clone(), harness);
            }
        }

        // Sync the campaign schedule with the new harness map changes.
        drop(harnesses);
        self.scheduler
            .lock()
            .await
            .sync_schedule(CampaignSchedulerInput {
                harnesses: self.harnesses.clone(),
                modified_files: build.revision().modified_files().to_vec(),
            })
            .await;
        // Wake up the scheduler task to see if there is a campaign to schedule.
        let _ = self.wake_up_scheduler.as_ref().unwrap().try_send(());

        for monitor in self.monitors.iter_mut() {
            monitor
                .monitor_project_event(self.config.name.clone(), ProjectEvent::NewBuild)
                .await;
        }
    }

    async fn handle_new_campaign(&mut self, campaign: ScheduledCampaign<E>) {
        if self.campaigns.contains_key(&campaign.0) {
            // This can happen if e.g. the coverage based scheduler with a round-robin fallback
            // schedules the same harness twice, once based on coverage and once based on the r-r.
            //
            // TODO spinning up the duplicate campaign and then immediately killing it wastes
            // resources, fix this in the scheduler instead.
            log::warn!(
                "Campaign ('{}') was scheduled twice, stopping the duplicate now!",
                campaign.0,
            );

            let _ = campaign.2.send(true).await;
            self.finish_campaign(campaign.0, campaign.1, None).await;
        } else {
            self.campaigns.insert(campaign.0, (campaign.1, campaign.2));
        }
    }

    async fn finish_campaign(
        &mut self,
        harness: String,
        campaign_handle: CampaignJoinHandle<E>,
        corpus: Option<Vec<u8>>,
    ) {
        if let Ok(Campaign { env, .. }) = campaign_handle.await {
            self.env_allocator.free(env).await;
        } else {
            log::error!(
                "Failed to wait for campaign to join (project='{}', harness='{}')",
                self.config.name,
                harness
            );
        }

        if let Some(corpus) = corpus {
            let corpus_herder = self.state.corpus_herder().await;

            // Hand the corpus of to the corpus herder.
            if let Err(err) = corpus_herder
                .lock()
                .await
                .merge(harness.clone(), corpus)
                .await
            {
                log::warn!(
                    "Could not merge new corpus for project '{}': {}",
                    self.config.name,
                    err
                );
            };
        }

        // Mark the campaign as finished with the scheduler.
        let _ = self.scheduler.lock().await.finish(&harness);
        // Wake up the scheduler task to see if there is a new campaign to schedule.
        // Note: We use try_send to avoid blocking on a full channel.
        let _ = self.wake_up_scheduler.as_ref().unwrap().try_send(());
    }

    async fn handle_campaign_event(&mut self, event: CampaignEvent) {
        log::trace!(
            "New campaign event for project '{}': {:?}",
            self.config.name,
            event
        );

        match event.clone() {
            CampaignEvent::Stats(harness, stats) => {
                log::trace!(
                    "{:?} (harness='{}', project='{}')",
                    stats,
                    harness,
                    self.config.name,
                );
            }
            CampaignEvent::Quit(harness, corpus) => {
                if let Some((handle, _)) = self.campaigns.remove(&harness) {
                    self.finish_campaign(harness, handle, corpus).await;
                } else {
                    log::error!(
                        "Received quit event but the campaign was not found (harness={}, project={})",
                        harness,
                        self.config.name
                    );
                }
            }
            _ => {}
        }

        for monitor in self.monitors.iter_mut() {
            monitor
                .monitor_campaign_event(self.config.name.clone(), event.clone())
                .await;
        }
    }

    pub async fn run<R, RT, B, Q>(
        &mut self,
        revision_tracker: RT,
        builder: B,
        mut quit: Receiver<Q>,
    ) -> Option<Q>
    where
        R: Revision + Clone + Send + 'static,
        RT: RevisionTracker<R> + Send + 'static,
        B: ProjectBuilder<R, D> + Send + 'static,
    {
        let (build_tx, mut build_rx) = tokio::sync::mpsc::channel(16);

        // Start the builder task, which monitors for new software revision of the project and
        // creates a build for fuzzing it.
        let description = self.description.clone();
        let ignore_first_revision = self.options.ignore_first_revision;
        tokio::spawn(async move {
            let mut build_task = BuildTask::new(
                revision_tracker,
                builder,
                description,
                build_tx,
                ignore_first_revision,
            );
            build_task.run().await;
        });

        // Start the campaign scheduler task, which takes harnesses from the schedule, allocates an
        // environment for them and starts fuzzing campaigns.
        let scheduler = self.scheduler.clone();
        let env_allocator = self.env_allocator.clone();
        let harnesses = self.harnesses.clone();
        let corpus_herder = self.state.corpus_herder().await;
        let config = self.description.config();
        // Channel used to receive ScheduledCampaigns from the scheduling task.
        let (campaign_tx, mut campaign_rx) = tokio::sync::mpsc::channel(16);
        // Channel used to receive campaign events from active campaigns.
        let (campaign_event_tx, mut campaign_event_rx) = tokio::sync::mpsc::channel(128);
        // Channel used to wake up the scheduler task.
        let (wake_up_tx, wake_up_rx) = tokio::sync::mpsc::channel(16);
        self.wake_up_scheduler = Some(wake_up_tx);
        let scheduler_task = if !self.options.no_fuzzing {
            tokio::spawn(async move {
                let mut campaign_scheduler_task: CampaignScheduleTask<E, EA, CH> =
                    CampaignScheduleTask {
                        project_config: config,
                        schedule: scheduler,
                        campaign_sender: campaign_tx,
                        env_allocator,
                        corpus_herder,
                        wake_up_receiver: wake_up_rx,
                        campaign_event_sender: campaign_event_tx,
                        harnesses,
                    };

                campaign_scheduler_task.run().await;
            })
        } else {
            // Dummy tokio task that does nothing.
            tokio::spawn(async {})
        };

        // This is the main project loop. It handles new builds, new campaigns and campaign events.
        let result;
        loop {
            tokio::select! {
                Some(build) = build_rx.recv() => self.handle_build_result(build).await,
                Some(campaign) = campaign_rx.recv() => self.handle_new_campaign(campaign).await,
                Some(event) = campaign_event_rx.recv() => self.handle_campaign_event(event).await,
                q = quit.recv() => {
                    result = q;
                    break;
                },
            }
        }

        log::info!("Quiting project '{}'", self.config.name);

        // Quit the campaign scheduler task.
        self.wake_up_scheduler = None;
        let _ = scheduler_task.await;

        // Quit all active campaigns.
        for (_, (campaign_handle, quit)) in self.campaigns.drain() {
            let _ = quit.send(false).await;
            let _ = campaign_handle.await;
        }

        return result;
    }
}

struct BuildTask<R, RT, B, D> {
    current_revision: Option<R>,
    revision_tracker: RT,
    builder: B,
    description: D,

    build_sender: Sender<Result<ProjectBuild<R>, String>>,
    ignore_first_revision: bool,
}

impl<R, RT, B, D> BuildTask<R, RT, B, D>
where
    R: Revision + Clone,
    RT: RevisionTracker<R>,
    B: ProjectBuilder<R, D>,
    D: ProjectDescription + Clone,
{
    fn new(
        revision_tracker: RT,
        builder: B,
        description: D,
        build_sender: Sender<Result<ProjectBuild<R>, String>>,
        ignore_first_revision: bool,
    ) -> Self {
        Self {
            current_revision: None,
            revision_tracker,
            builder,
            description,
            build_sender,
            ignore_first_revision,
        }
    }

    async fn run(&mut self) {
        let config = self.description.config();

        loop {
            // Wait for new revision of the project
            self.current_revision = Some(
                self.revision_tracker
                    .track(self.current_revision.clone())
                    .await,
            );

            if self.ignore_first_revision {
                log::info!("Ignoring first revision for project '{}'", config.name);
                self.ignore_first_revision = false;
                continue;
            }

            // Re-build the fuzzing image
            let build = self
                .builder
                .build(
                    self.description.clone(),
                    self.current_revision.as_ref().unwrap().clone(),
                )
                .await;

            if let Err(_) = self.build_sender.send(build).await {
                // Notify project about new build
                log::info!("Build task quit for project '{}'", config.name);
                break;
            }
        }
    }
}

type ScheduledCampaign<E> = (String, CampaignJoinHandle<E>, Sender<bool>);

struct CampaignScheduleTask<E, EA, CH>
where
    E: Environment,
{
    project_config: ProjectConfig,
    schedule: Arc<Mutex<Box<dyn CampaignScheduler + Send>>>,
    campaign_sender: Sender<ScheduledCampaign<E>>,
    campaign_event_sender: Sender<CampaignEvent>,
    wake_up_receiver: Receiver<()>,
    env_allocator: EA,
    harnesses: SharedHarnessMap,
    corpus_herder: Arc<Mutex<CH>>,
}

impl<E, EA, CH> CampaignScheduleTask<E, EA, CH>
where
    E: Environment + Send + 'static,
    EA: EnvironmentAllocator<E>,
    CH: CorpusHerder<Vec<u8>> + Send + 'static,
{
    async fn run(&mut self) {
        log::info!(
            "Starting campaign scheduler task for project '{}'",
            self.project_config.name
        );

        let mut eager_scheduling = false;
        loop {
            if eager_scheduling {
                log::trace!(
                    "Attempting to eagerly scheduling the next campaign for project '{}'",
                    self.project_config.name
                );
            }

            if !eager_scheduling && self.wake_up_receiver.recv().await.is_none() {
                break;
            }
            eager_scheduling = false;

            log::trace!(
                "Campaign scheduler task woken up for project '{}'",
                self.project_config.name
            );

            let env_params = match self.schedule.lock().await.next().await {
                Ok(env_params) => env_params,
                Err(err) => {
                    log::warn!(
                        "Campaign scheduling failed for project '{}': {:?}",
                        self.project_config.name,
                        err
                    );
                    continue;
                }
            };

            let harnesses = self.harnesses.lock().await;
            let Some(harness) = harnesses.get(&env_params.harness_name).map(|h| h.clone()) else {
                log::warn!(
                    "Scheduled harness '{}' does not exist in the harness map (project={})",
                    &env_params.harness_name,
                    self.project_config.name
                );

                if let Err(err) = self.schedule.lock().await.finish(&env_params.harness_name) {
                    log::warn!("Failed to finish scheduled campaign: {}", err);
                }

                continue;
            };
            drop(harnesses);

            //if harness
            //    .get_last_revision_with_solutions()
            //    .await
            //    .map_or(false, |rev| rev == "")
            //{}

            log::trace!(
                "Scheduled harness '{}' for project '{}'",
                env_params.harness_name,
                self.project_config.name,
            );

            let harness_name = env_params.harness_name.clone();

            let env = match self.env_allocator.alloc(env_params).await {
                Ok(env) => env,
                Err(_err) => {
                    if let Err(err) = self.schedule.lock().await.finish(&harness_name) {
                        log::warn!("Failed to finish scheduled campaign: {}", err);
                    }
                    continue;
                }
            };

            if let Ok(corpus) = self
                .corpus_herder
                .lock()
                .await
                .fetch(harness_name.clone())
                .await
            {
                if let Err(err) = env.upload_initial_corpus(corpus).await {
                    log::warn!(
                        "Could not upload initial '{}' corpus for project '{}': {}",
                        harness_name,
                        self.project_config.name,
                        err
                    );
                }
            }

            let event_sender = self.campaign_event_sender.clone();
            // Create quit channel for the new campaign.
            let (quit_tx, quit_rx) = tokio::sync::mpsc::channel(16);
            // Run the campaign in a separate task.
            let project_name = self.project_config.name.clone();
            let campaign_task = tokio::spawn(async move {
                let mut campaign = Campaign::new(project_name, harness, env, event_sender).await;
                campaign.run(quit_rx).await;
                campaign
            });

            // Send the campaign task and quit signal channel back to the project.
            if let Err(_) = self
                .campaign_sender
                .send((harness_name, campaign_task, quit_tx))
                .await
            {
                log::error!(
                    "Campaign could not be send back to project '{}'",
                    self.project_config.name
                );
            }

            eager_scheduling = true;
        }
    }
}
