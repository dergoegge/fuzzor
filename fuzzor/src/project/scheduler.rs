use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use super::harness::*;
use super::ProjectConfig;
use crate::env::*;

use rand::{seq::SliceRandom, thread_rng};

#[derive(Clone)]
pub struct CampaignSchedulerInput {
    pub harnesses: SharedHarnessMap,
    pub modified_files: Vec<String>,
}

/// CampaignScheduler defines how fuzzing campaigns are scheduled.
#[async_trait::async_trait]
pub trait CampaignScheduler {
    /// Get the next harness from the schedule
    async fn next(&mut self) -> Result<EnvironmentParams, &'static str>;
    /// Mark the campaign for harness as finished
    fn finish(&mut self, harness: &str) -> Result<(), &'static str>;
    /// Sync the shared harness list with the campaign schedule
    async fn sync_schedule(&mut self, input: CampaignSchedulerInput);
}

/// RoundRobinCampaignScheduler defines a round-robin campaign scheduling strategy.
///
/// It schedules each harness with equal resources in circular order.
pub struct RoundRobinCampaignScheduler {
    // Harnesses currently scheduled for fuzzing
    current_schedule: Vec<String>,
    // Index of the next harness to be returned from `current_schedule`
    next_harness: usize,
    // Fuzz duration for each campaign
    duration: Duration,
    // Config of the project that this schedule belongs to
    project_config: ProjectConfig,
    // Set of harness names that are active
    unfinished: HashSet<String>,
}

unsafe impl Send for RoundRobinCampaignScheduler {}

impl RoundRobinCampaignScheduler {
    pub fn new(project_config: ProjectConfig, duration: Duration) -> Self {
        Self {
            current_schedule: Vec::new(),
            next_harness: 0,
            duration,
            unfinished: HashSet::new(),
            project_config,
        }
    }
}

#[async_trait::async_trait]
impl CampaignScheduler for RoundRobinCampaignScheduler {
    async fn next(&mut self) -> Result<EnvironmentParams, &'static str> {
        if self.current_schedule.is_empty() {
            return Err("Nothing in the current schedule");
        }

        let harness_name = self.current_schedule[self.next_harness].clone();

        if !self.unfinished.insert(harness_name.clone()) {
            return Err("Attempted to reschedule unfinished campaign");
        }

        self.next_harness = (self.next_harness + 1) % self.current_schedule.len();
        Ok(EnvironmentParams {
            docker_image: format!("fuzzor-{}:latest", self.project_config.name),
            arch: None,
            harness_name,
            duration: self.duration,
            project_config: self.project_config.clone(),
        })
    }

    async fn sync_schedule(&mut self, input: CampaignSchedulerInput) {
        // Sync the shared harness map with the internal schedule. This is necessary since the
        // shared map might have changed: projects might add or remove harnesses.
        let harnesses = input.harnesses.lock().await;

        self.current_schedule = Vec::from_iter(harnesses.keys().cloned());
        self.current_schedule.shuffle(&mut thread_rng());

        self.next_harness = 0;

        log::trace!("Synced schedule {}", self.current_schedule.len());
    }

    fn finish(&mut self, harness_name: &str) -> Result<(), &'static str> {
        if self.unfinished.remove(harness_name) {
            Ok(())
        } else {
            Err("Harness was not previously scheduled")
        }
    }
}

/// CoverageBasedScheduler defines a campaign scheduler that schedules new harnesses as well as
/// harnesses that reach the modified files in a software patch.
///
/// This scheduler requires knowledge of the base projects' harnesses in order to figure out which
/// of them achieve coverage in the modified files.
pub struct CoverageBasedScheduler {
    // Harnesses of the base project
    base_harnesses: Option<SharedHarnessMap>,
    // Current campaign schedule, the next harness is poped from the front.
    schedule: VecDeque<String>,
    // Fuzz duration for each campaign
    duration: Duration,
    // Config of the project that this schedule belongs to
    project_config: ProjectConfig,

    rr_scheduler: Option<RoundRobinCampaignScheduler>,
}

impl CoverageBasedScheduler {
    pub fn new(
        project_config: ProjectConfig,
        duration: Duration,
        base_harnesses: SharedHarnessMap,
    ) -> Self {
        Self {
            base_harnesses: Some(base_harnesses),
            schedule: VecDeque::new(),
            duration,
            project_config,
            rr_scheduler: None,
        }
    }

    /// Create a CoverageBasedScheduler that will fall back to round robin scheduling once finished
    /// with fuzzing the harnesses that reached the modified files.
    pub fn with_round_robin_fallback(project_config: ProjectConfig, duration: Duration) -> Self {
        Self {
            base_harnesses: None,
            schedule: VecDeque::new(),
            duration,
            rr_scheduler: Some(RoundRobinCampaignScheduler::new(
                project_config.clone(),
                duration,
            )),

            project_config,
        }
    }
}

#[async_trait::async_trait]
impl CampaignScheduler for CoverageBasedScheduler {
    async fn next(&mut self) -> Result<EnvironmentParams, &'static str> {
        match self.schedule.pop_front() {
            Some(harness_name) => Ok(EnvironmentParams {
                docker_image: format!("fuzzor-{}:latest", self.project_config.name),
                arch: None,
                harness_name,
                duration: self.duration,
                project_config: self.project_config.clone(),
            }),
            None => {
                if let Some(rr) = self.rr_scheduler.as_mut() {
                    rr.next().await
                } else {
                    Err("Nothing in current schedule")
                }
            }
        }
    }

    async fn sync_schedule(&mut self, input: CampaignSchedulerInput) {
        if let Some(rr) = self.rr_scheduler.as_mut() {
            rr.sync_schedule(input.clone()).await;
        }

        if let Some(base_harnesses) = &self.base_harnesses {
            let base_harnesses = base_harnesses.lock().await;
            // Set of all harness names of the base project
            let base_harness_names: HashSet<&String> = base_harnesses.keys().collect();

            let harnesses = input.harnesses.lock().await;
            // Set of all harness names of the project owning this scheduler
            let harness_names = harnesses.keys().collect();

            // Set of harnesses new harnesses added by the owning project
            let new_harnesses = &harness_names - &base_harness_names;

            let mut scheduled_harnesses = HashSet::new();

            // Schedule newly added harnesses
            self.schedule.clear();
            for harness_name in new_harnesses.iter() {
                scheduled_harnesses.insert(*harness_name);
                self.schedule.push_back(harness_name.to_string());
            }

            // Schedule harnesses that reach the modified files
            for file in input.modified_files.iter() {
                for (harness_name, harness) in base_harnesses.iter() {
                    if scheduled_harnesses.contains(harness_name)
                        || !harness
                            .lock()
                            .await
                            .state()
                            .covers_file(file.to_string())
                            .await
                    {
                        continue;
                    }

                    scheduled_harnesses.insert(harness_name);

                    // Only add to the schedule if the harness exists (it might have been removed)
                    if harnesses.contains_key(harness_name.as_str()) {
                        self.schedule.push_back(harness_name.clone());
                    }
                }
            }
        } else {
            let mut current_schedule: HashSet<String> =
                HashSet::from_iter(self.schedule.iter().cloned());

            let harnesses = input.harnesses.lock().await;

            // Schedule harnesses that reach the modified files
            let mut newly_scheduled = Vec::new();
            for file in input.modified_files.iter() {
                for (harness_name, harness) in harnesses.iter() {
                    let harness = harness.lock().await;

                    // Add harness to the coverage based schedule if it doesn't cover any files yet
                    // (i.e. it is a new harness) or if it covers the modified file.
                    if harness.state().covered_files().await.len() > 0
                        && !harness.state().covers_file(file.to_string()).await
                    {
                        continue;
                    }

                    if !current_schedule.contains(harness_name) {
                        newly_scheduled.push(harness_name.as_str());
                        self.schedule.push_front(harness_name.clone());
                        current_schedule.insert(harness_name.clone());
                    }
                }
            }

            log::info!(
                "Scheduled {} harnesses to reach {} modified files (project='{}', files='{:?}', scheduled='{:?}')",
                newly_scheduled.len(),
                input.modified_files.len(),
                self.project_config.name,
                input.modified_files,
                newly_scheduled,
            );
        }
    }

    fn finish(&mut self, harness: &str) -> Result<(), &'static str> {
        if let Some(rr) = self.rr_scheduler.as_mut() {
            let _ = rr.finish(harness);
        }

        Ok(())
    }
}

/// OneShotScheduler defines a campaign scheduler that schedules a fixed set of harnesses once.
pub struct OneShotScheduler {
    harnesses: Vec<String>,
    schedule: VecDeque<String>,

    duration: Duration,
    project_config: ProjectConfig,
}

impl OneShotScheduler {
    pub fn new(project_config: ProjectConfig, duration: Duration, harnesses: Vec<String>) -> Self {
        Self {
            harnesses,
            schedule: VecDeque::new(),
            duration,
            project_config,
        }
    }
}

#[async_trait::async_trait]
impl CampaignScheduler for OneShotScheduler {
    async fn next(&mut self) -> Result<EnvironmentParams, &'static str> {
        match self.schedule.pop_front() {
            Some(harness_name) => Ok(EnvironmentParams {
                docker_image: format!("fuzzor-{}:latest", self.project_config.name),
                arch: None,
                harness_name,
                duration: self.duration,
                project_config: self.project_config.clone(),
            }),
            None => Err("Nothing in the current schedule"),
        }
    }

    async fn sync_schedule(&mut self, input: CampaignSchedulerInput) {
        let harnesses = input.harnesses.lock().await;

        self.schedule.clear();
        for harness_name in self.harnesses.iter() {
            if harnesses.contains_key(harness_name) {
                self.schedule.push_back(harness_name.clone());
            }
        }
    }

    fn finish(&mut self, _harness: &str) -> Result<(), &'static str> {
        Ok(())
    }
}
