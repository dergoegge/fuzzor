use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use crate::solutions::{inmemory::InMemorySolutionStore, SolutionStore};

use fuzzor_infra::FuzzerStats;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter},
    sync::Mutex,
};

#[async_trait::async_trait]
pub trait HarnessState {
    /// Get the solution store for the harness
    async fn solutions(&self) -> Arc<Mutex<dyn SolutionStore + Send>>;
    /// Store the file names that the harness can reach through fuzzing
    async fn set_covered_files(&mut self, covered_files: Vec<String>);
    /// Get the file names that the harness can reach through fuzzing
    async fn covered_files(&self) -> HashSet<String>;
    /// Check if a file is reachable by the harness through fuzzing
    async fn covers_file(&self, file: String) -> bool;
    /// Store a coverage report
    async fn store_coverage_report(&self, tar: Vec<u8>);
    /// Record stats
    async fn record_stats(&mut self, stats: FuzzerStats);
}

pub struct Harness {
    name: String,
    state: Box<dyn HarnessState + Send>,
}

impl Harness {
    pub fn new(name: String, state: Box<dyn HarnessState + Send>) -> Self {
        Self { name, state }
    }

    pub fn state_mut(&mut self) -> &mut dyn HarnessState {
        self.state.as_mut()
    }
    pub fn state(&self) -> &dyn HarnessState {
        self.state.as_ref()
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// HarnessMap represents a map of harnesses.
pub type HarnessMap = HashMap<String, Arc<Mutex<Harness>>>;
/// SharedHarnessMap represents a map of shared harnesses that can be safely shared between
/// threads.
pub type SharedHarnessMap = Arc<Mutex<HarnessMap>>;

pub struct PersistentHarnessState {
    covered_files: HashSet<String>,
    solutions: Arc<Mutex<dyn SolutionStore + Send>>,
    path: PathBuf,
    stats_file: File,
}

impl PersistentHarnessState {
    pub async fn new(path: PathBuf) -> Self {
        let mut covered_files = HashSet::new();

        let _ = tokio::fs::create_dir_all(&path).await;

        if let Ok(file) = File::open(path.join("covered_files.txt")).await {
            let reader = BufReader::new(file);

            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                covered_files.insert(line.to_string());
            }
        }

        let stats_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path.join("stats.txt"))
            .await
            .unwrap();

        Self {
            solutions: Arc::new(Mutex::new(InMemorySolutionStore::default())),
            covered_files,
            path,
            stats_file,
        }
    }
}

#[async_trait::async_trait]
impl HarnessState for PersistentHarnessState {
    async fn solutions(&self) -> Arc<Mutex<dyn SolutionStore + Send>> {
        self.solutions.clone()
    }

    async fn set_covered_files(&mut self, mut covered_files: Vec<String>) {
        let _ = tokio::fs::create_dir_all(&self.path).await;

        if let Ok(file) = File::create(self.path.join("covered_files.txt")).await {
            let mut writer = BufWriter::new(file);

            for covered_file in covered_files.iter() {
                let line = format!("{}\n", covered_file);
                writer.write_all(line.as_bytes()).await.unwrap();
            }

            writer.flush().await.unwrap();
        } else {
            log::error!("Could not save covered files: {:?}", self.path);
        }

        self.covered_files = HashSet::from_iter(covered_files.drain(..));
    }
    async fn covered_files(&self) -> HashSet<String> {
        self.covered_files.clone()
    }
    async fn covers_file(&self, file: String) -> bool {
        for covered_file in self.covered_files.iter() {
            if covered_file.ends_with(&file) {
                return true;
            }
        }

        return false;
    }

    async fn store_coverage_report(&self, tar: Vec<u8>) {
        let report_dir = self.path.join("coverage_report");
        if let Err(err) = tokio::fs::remove_dir_all(&report_dir).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                log::warn!(
                    "Could not remove old coverage report directory \"{:?}\": {:?}",
                    &report_dir,
                    err
                );
            }
        }

        let mut archive = tar::Archive::new(tar.as_slice());
        if let Err(err) = archive.unpack(&self.path) {
            log::warn!("Could not unpack coverage report: {:?}", err);
        }
    }

    async fn record_stats(&mut self, stats: FuzzerStats) {
        if let Err(err) = self
            .stats_file
            .write_all(
                format!(
                    "{:?},{},{}\n",
                    stats.stability, stats.execs_per_sec, stats.corpus_count
                )
                .as_bytes(),
            )
            .await
        {
            log::error!("Could not write to stats file: {:?}", err);
        }

        let _ = self.stats_file.flush().await;
    }
}
