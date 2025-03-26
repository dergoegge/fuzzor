use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::{env::*, project::harness::*, solutions::*};

use fuzzor_infra::{FuzzerStats, ProjectConfig};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};
use tokio::task::JoinHandle;

/// Possible states of a campaign
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CampaignState {
    /// Campaign has been scheduled but has not started fuzzing yet
    Scheduled,
    /// Campaign is currently fuzzing
    Fuzzing,
    /// Campaign has completed
    Ended,
}

#[derive(Debug, Clone)]
pub enum CampaignEvent {
    Initialized(String),
    /// NewState fires when a campaign changes state
    NewState(String, CampaignState, CampaignState),
    /// NewSolution fires when a campaign discovers a *new* solution for the given harness
    NewSolution(String, Solution),
    /// ResolvedSolution fires when a solution no longer reproduces
    ResolvedSolution(String, Solution),
    /// Stats fires when new fuzzing stats are available
    Stats(String, FuzzerStats),
    /// Quit fires when a campaign task quits
    Quit(String, Option<Vec<u8>>),
}

pub struct Campaign<E> {
    // Fuzzing environment for this campaign
    pub env: E,
    // Harness being fuzzed by this campaign
    harness: Arc<Mutex<Harness>>,
    harness_name: String,
    // State of the campaign
    state: CampaignState,
    // Sender for sending campaign events to the managing project
    event_sender: Sender<CampaignEvent>,
    // Last stats reported by the environment
    last_reported_stats: Option<FuzzerStats>,
    // Name of the project managing this campaign
    project_config: ProjectConfig,
}

impl<E> Campaign<E>
where
    E: Environment,
{
    pub async fn new(
        project_config: ProjectConfig,
        harness: Arc<Mutex<Harness>>,
        env: E,
        event_sender: Sender<CampaignEvent>,
    ) -> Self {
        let harness_name = harness.lock().await.name().to_string();

        log::info!(
            "New campaign: project='{}' harness='{}' env='{}'",
            &project_config.name,
            &harness_name,
            &env.get_id().await[..8],
        );

        Self {
            harness,
            harness_name,
            env,
            state: CampaignState::Scheduled,
            event_sender,
            last_reported_stats: None,
            project_config,
        }
    }

    async fn new_state(&mut self, new_state: CampaignState) {
        match (self.state, new_state) {
            (CampaignState::Scheduled, CampaignState::Fuzzing) => {}
            (_, CampaignState::Ended) => {}

            (old, new) => log::error!("Invalid campaign state transition: {:?} -> {:?}", old, new),
        }

        log::trace!("New campaign state: {:?} -> {:?}", self.state, new_state);

        let prev_state = self.state;
        self.state = new_state;

        self.send_event(CampaignEvent::NewState(
            self.harness_name.clone(),
            prev_state,
            self.state,
        ))
        .await;
    }

    async fn send_event(&mut self, event: CampaignEvent) {
        log::trace!("Sending event: {:?}", &event);

        if let Err(err) = self.event_sender.send(event).await {
            log::error!("Failed to fire event: {:?}", err);
        }
    }

    async fn process_solutions(&mut self, mut solutions: Vec<Solution>) {
        let quit = !solutions.is_empty();

        let mut non_new_solutions = HashMap::new();
        for solution in solutions.drain(..) {
            let solution_id = solution.id().to_string();

            let solutions = self.harness.lock().await.state().solutions().await;

            let new_solution = solutions.lock().await.submit(solution.clone()).await;

            if new_solution {
                log::info!(
                    "Stored new solution harness={} id={}",
                    self.harness_name,
                    &solution_id,
                );

                // Only notify for solutions that are not a duplicate of a previously found solution.
                self.send_event(CampaignEvent::NewSolution(
                    self.harness_name.clone(),
                    solution,
                ))
                .await;
            } else if let Ok(count) = non_new_solutions.try_insert(solution_id, 1) {
                *count += 1;
            }
        }

        for (id, count) in non_new_solutions.iter() {
            log::info!(
                "Did not store {} duplicate solutions with id={} for harness={}",
                count,
                id,
                &self.harness_name,
            );
        }

        if quit {
            // We end the campaign if there are any solutions . Solutions tend to block fuzzers
            // from making progress in any case, so there is little value in continuing (we
            // would just be wasting resources).
            self.new_state(CampaignState::Ended).await;
        }
    }

    async fn process_stats(&mut self, stats: FuzzerStats) {
        if self.state == CampaignState::Scheduled && stats.execs_per_sec > 0.0 {
            self.new_state(CampaignState::Fuzzing).await;
        }

        let total_solutions = stats.saved_crashes + stats.saved_hangs;
        let found_solutions = total_solutions > 0;

        {
            let mut harness = self.harness.lock().await;
            harness.state_mut().record_stats(stats.clone()).await;
        }

        if self
            .last_reported_stats
            .as_ref()
            .map_or(true, |last_reported_stats| {
                // Report new stats if we found any solutions or if the corpus grew.
                found_solutions || stats.corpus_count > last_reported_stats.corpus_count
            })
        {
            self.send_event(CampaignEvent::Stats(
                self.harness_name.clone(),
                stats.clone(),
            ))
            .await;
            self.last_reported_stats = Some(stats.clone());
        }

        if !found_solutions {
            // Shortcurcuit since there are no solutions to download
            return;
        }

        match self.env.get_solutions().await {
            Ok(solutions) => {
                let reproduced_hangs = solutions
                    .iter()
                    .filter(|s| matches!(s.metadata(), SolutionMetadata::Timeout(_)))
                    .count() as u64;
                if reproduced_hangs < stats.saved_hangs {
                    log::warn!(
                        "{} hangs did not reproduce (harness={}, project={})",
                        stats.saved_hangs - reproduced_hangs,
                        self.harness_name,
                        self.project_config.name
                    );
                }

                let reproduced_crashes = solutions
                    .iter()
                    .filter(|s| matches!(s.metadata(), SolutionMetadata::Crash(_)))
                    .count() as u64;
                let mut end = false;
                if stats.saved_crashes > 0 && reproduced_crashes == 0 {
                    log::error!(
                        "{} crashes did not reproduce (harness={}, project={})",
                        stats.saved_crashes - reproduced_crashes,
                        self.harness_name,
                        self.project_config.name
                    );

                    end = true;
                }

                self.process_solutions(solutions).await;

                if end {
                    self.new_state(CampaignState::Ended).await;
                }
            }
            Err(err) => log::warn!("{}", err),
        }
    }

    pub async fn run(&mut self, mut quit_rx: Receiver<bool>) {
        self.send_event(CampaignEvent::Initialized(self.harness_name.clone()))
            .await;

        let _ = self.env.start().await;

        let mut quit = false;
        let mut kill = false; // kill: end the campaign without sending a quit event

        let existing_solutions = {
            let harness = self.harness.lock().await;
            let state = harness.state();
            state.solutions().await.lock().await.get_all().await
        };
        let solution_set: HashSet<String> =
            HashSet::from_iter(existing_solutions.iter().map(|s| s.id().to_string()));

        match self.env.reproduce_solutions(existing_solutions).await {
            Ok(solutions) => {
                let reproduced_solution_set: HashSet<String> =
                    HashSet::from_iter(solutions.iter().map(|s| s.id().to_string()));

                for solution_id in solution_set.iter() {
                    if reproduced_solution_set.contains(solution_id.as_str()) {
                        log::info!(
                            "Existing solution ({}) still reproduces (project='{}', harness='{}')",
                            solution_id,
                            self.project_config.name,
                            self.harness_name,
                        );

                        quit = true; // Quit campaigns that have unresolved solutions
                    } else {
                        log::info!(
                            "Existing solution ({}) no longer reproduces (project='{}', harness='{}')",
                            solution_id,
                            self.project_config.name,
                            self.harness_name,
                        );

                        let solution = {
                            let harness = self.harness.lock().await;
                            let state = harness.state();
                            let tracker = state.solutions().await;

                            let solution = tracker
                                .lock()
                                .await
                                .mark_as_resolved(solution_id)
                                .await
                                .expect("Solution has to exist in the tracker at this point");
                            solution
                        };

                        self.send_event(CampaignEvent::ResolvedSolution(
                            self.harness_name.clone(),
                            solution,
                        ))
                        .await;
                    }
                }
            }
            Err(err) => log::warn!("Could not reproduce initial solutions: {}", err),
        };

        let default_inspect_timeout = 60;
        let mut inspect_interval = tokio::time::interval(tokio::time::Duration::from_secs(
            std::env::var("FUZZOR_CAMPAIGN_INTERVAL").map_or(default_inspect_timeout, |val| {
                val.parse()
                    .expect("FUZZOR_CAMPAIGN_INTERVAL should be a value in seconds")
            }),
        ));

        while !quit {
            tokio::select! {
                _ = inspect_interval.tick() => match self.env.get_stats().await {
                    Ok(stats) => self.process_stats(stats).await,
                    Err(err) => log::trace!("{}", err),
                },
                maybe_kill = quit_rx.recv() => {
                    quit = true;
                    kill = maybe_kill.unwrap_or(false);
                }
            };

            if kill {
                break;
            }

            if let Ok(false) = self.env.ping().await {
                // End the campaign once fuzzing has stopped. It likely stopped because we've
                // reached the maximum duration we wanted to fuzz for.
                self.new_state(CampaignState::Ended).await;
            }

            if self.state == CampaignState::Ended {
                // Campaign ended, shutdown the environment and quit.
                quit = true;
            }
        }

        let campaign_ended = self.state == CampaignState::Ended;
        let corpus = if campaign_ended && !kill {
            let corpus = match self.env.get_corpus(true).await {
                Ok(c) => Some(c),
                Err(err) => {
                    log::warn!(
                        "Failed to minimize and download corpus for '{}': {}",
                        self.harness_name,
                        err
                    );
                    None
                }
            };

            match self.env.get_covered_files().await {
                Ok(covered_files) => {
                    let mut harness = self.harness.lock().await;

                    log::trace!(
                        "Covered files for harness '{}': {:?}",
                        harness.name(),
                        covered_files
                    );

                    harness.state_mut().set_covered_files(covered_files).await;
                }
                Err(err) => log::warn!("Could not fetch covered files from env: {:?}", err),
            }

            match self.env.get_coverage_report().await {
                Ok(report) => {
                    let mut harness = self.harness.lock().await;
                    harness.state_mut().store_coverage_report(report).await;
                }
                Err(err) => log::warn!("Could not fetch coverage report from env: {:?}", err),
            }

            corpus
        } else {
            None
        };

        if !kill {
            self.send_event(CampaignEvent::Quit(self.harness_name.clone(), corpus))
                .await;
        }

        log::info!(
            "Campaign ended: project='{}' harness='{}' env='{}'",
            self.project_config.name,
            self.harness_name,
            &self.env.get_id().await[..8]
        );
    }
}

pub type CampaignJoinHandle<E> = JoinHandle<Campaign<E>>;
