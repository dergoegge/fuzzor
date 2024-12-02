use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use fuzzor_infra::FuzzerStats;
use rand::distributions::{Alphanumeric, DistString};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::Mutex,
};

use super::Fuzzer;

pub struct HonggFuzzer {
    binary: PathBuf,
    corpus: PathBuf,
    solutions: PathBuf,
    num_threads: u64,

    last_stats: Arc<Mutex<FuzzerStats>>,
    tail_stats_proc: Option<tokio::process::Child>,
}

impl HonggFuzzer {
    pub fn new(binary: PathBuf, workspace: PathBuf, num_threads: u64) -> Self {
        Self {
            binary,
            corpus: workspace.join("corpus"),
            solutions: workspace.join("solutions"),
            num_threads,

            last_stats: Arc::new(Mutex::new(FuzzerStats::default())),
            tail_stats_proc: None,
        }
    }
}

#[async_trait]
impl Fuzzer for HonggFuzzer {
    fn get_name(&self) -> &str {
        "honggfuzz"
    }

    fn get_instance_name(&self) -> String {
        self.get_name().to_string()
    }

    async fn get_stats(&self) -> FuzzerStats {
        let stats = self.last_stats.lock().await.clone();
        stats.clone()
    }

    fn get_push_corpus(&self) -> Option<PathBuf> {
        Some(self.corpus.clone())
    }
    fn get_pull_corpus(&self) -> Option<PathBuf> {
        None
    }

    fn get_solutions(&self) -> Vec<PathBuf> {
        vec![self.solutions.clone()]
    }

    fn start(&mut self) -> tokio::process::Child {
        let _ = std::fs::create_dir_all(&self.corpus);
        let _ = std::fs::create_dir_all(&self.solutions);

        let stats_file = std::env::temp_dir().join(format!(
            "honggfuzz-{}.stats",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 16)
        ));

        // TODO there must be a more elegant way to get the stats
        let mut tail_stats_proc = tokio::process::Command::new("tail")
            .args(vec!["--follow", "--retry", stats_file.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("Could not start honggfuzz stats tail");

        spawn_honggfuzz_stats_parser(
            BufReader::new(tail_stats_proc.stdout.take().unwrap()),
            self.last_stats.clone(),
        );

        self.tail_stats_proc = Some(tail_stats_proc);

        let num_threads_str = self.num_threads.to_string();
        let args = vec![
            "--timeout",
            "10",
            "--verbose",
            "--quiet",
            "--statsfile",
            stats_file.to_str().unwrap(),
            "--input",
            self.corpus.to_str().unwrap(),
            "--crashdir",
            self.solutions.to_str().unwrap(),
            "--threads",
            num_threads_str.as_str(),
            "--",
            self.binary.to_str().unwrap(),
        ];

        let host_env: HashMap<String, String> = std::env::vars().collect();
        tokio::process::Command::new("honggfuzz")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .envs(host_env)
            .kill_on_drop(true)
            .spawn()
            .expect("Could not start honggfuzz instance")
    }
}

fn spawn_honggfuzz_stats_parser(
    stdout: BufReader<tokio::process::ChildStdout>,
    last_stats: Arc<Mutex<FuzzerStats>>,
) {
    let mut lines = stdout.lines();

    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            // # unix_time, last_cov_update, total_exec, exec_per_sec, crashes, unique_crashes, hangs, edge_cov, block_cov
            if line.starts_with("#") {
                continue;
            }

            log::trace!("honggfuzz: {}", line);

            let current_stats: Vec<u64> = line
                .split(",")
                .map(|num_str| num_str.trim().parse::<u64>().unwrap())
                .collect();

            let mut stats = last_stats.lock().await;
            stats.execs_per_sec = current_stats[3] as f64;
            stats.saved_crashes = current_stats[5];
            // stats.saved_hangs = current_stats[6]; // hongfuzz does not save timeouts to disk :(
            // TODO corpus count
        }
    });
}
