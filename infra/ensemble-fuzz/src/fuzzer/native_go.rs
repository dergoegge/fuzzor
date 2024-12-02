use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use fuzzor_infra::FuzzerStats;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::Mutex,
};

use super::Fuzzer;

pub struct NativeGoFuzzer {
    binary: PathBuf,
    solutions: PathBuf,
    go_fuzz_cache_dir: PathBuf,

    last_stats: Arc<Mutex<FuzzerStats>>,
}

impl NativeGoFuzzer {
    pub fn new(binary: PathBuf, workspace: PathBuf) -> Self {
        let go_fuzz_cache_dir = workspace.join("fuzzcache");
        let solutions = workspace.join("solutions");

        Self {
            binary,
            go_fuzz_cache_dir,
            solutions,
            last_stats: Arc::new(Mutex::new(FuzzerStats::default())),
        }
    }

    fn get_harness_name(&self) -> &str {
        // e.g. some/path/fuzz_pkg_FuzzFoo -> FuzzFoo
        let binary_str = self.binary.file_name().unwrap().to_str().unwrap();
        binary_str.split("_").last().unwrap()
    }
}

#[async_trait]
impl Fuzzer for NativeGoFuzzer {
    fn get_name(&self) -> &str {
        "native-go"
    }

    fn get_instance_name(&self) -> String {
        self.get_name().to_string()
    }

    async fn get_stats(&self) -> FuzzerStats {
        let stats = self.last_stats.lock().await.clone();
        stats.clone()
    }

    fn get_push_corpus(&self) -> Option<PathBuf> {
        Some(self.go_fuzz_cache_dir.join(self.get_harness_name()))
    }
    fn get_pull_corpus(&self) -> Option<PathBuf> {
        None
    }

    fn get_solutions(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    fn start(&mut self) -> tokio::process::Child {
        let _ = std::fs::create_dir_all(&self.solutions);
        let _ = std::fs::create_dir_all(&self.go_fuzz_cache_dir);

        let args = vec![
            self.binary.to_str().unwrap(),
            self.go_fuzz_cache_dir.to_str().unwrap(),
        ];

        let mut command = tokio::process::Command::new("bash");
        command.args(&args);
        command.stdout(Stdio::null());
        command.stderr(Stdio::piped());

        let host_env: HashMap<String, String> = std::env::vars().collect();
        command.envs(host_env);
        command.kill_on_drop(true);

        let mut child = command.spawn().expect("Could not start native-go instance");

        let stderr = child.stderr.take().unwrap();

        spawn_native_go_log_parser(
            BufReader::new(stderr),
            self.last_stats.clone(),
            self.solutions.clone(),
        );

        child
    }
}

fn spawn_native_go_log_parser(
    stderr_reader: BufReader<tokio::process::ChildStderr>,
    last_stats: Arc<Mutex<FuzzerStats>>,
    _crash_dir: PathBuf,
) {
    let mut lines = stderr_reader.lines();

    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            // Match lines as the following:
            // fuzz: elapsed: 3s, execs: 29639 (9879/sec), new interesting: 9 (total: 9)
            // fuzz: elapsed: 6s, execs: 67935 (12761/sec), new interesting: 9 (total: 9)
            // fuzz: elapsed: 9s, execs: 106516 (12850/sec), new interesting: 9 (total: 9)
            // fuzz: elapsed: 12s, execs: 145407 (12975/sec), new interesting: 9 (total: 9)
            // fuzz: elapsed: 15s, execs: 184024 (12864/sec), new interesting: 9 (total: 9)

            let stats_regex =
                    regex::Regex::new(r"fuzz: elapsed: [0-9]*s, execs: [0-9]* \((?<execs_per_sec>[0-9]*)/sec\), new interesting: [0-9]* \(total: (?<corpus>[0-9]*)\).*")
                        .unwrap();
            log::trace!("native-go: {}", line);
            let Some(caps) = stats_regex.captures(&line) else {
                continue;
            };

            let mut stats = last_stats.lock().await;
            stats.execs_per_sec = caps["execs_per_sec"].parse().unwrap_or(0.0);
            stats.corpus_count = caps["corpus"].parse().unwrap_or(0);
        }

        if PathBuf::from("testdata/").exists() {
            let mut stats = last_stats.lock().await;
            stats.saved_crashes += 1;
        }
    });
}
