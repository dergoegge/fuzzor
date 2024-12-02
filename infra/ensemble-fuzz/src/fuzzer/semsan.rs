use std::io::Write;
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

pub struct SemSanFuzzer {
    pub primary_binary: PathBuf,
    pub secondary_binary: PathBuf,
    pub seeds: PathBuf,
    pub solutions: PathBuf,
    pub pull_corpus: PathBuf,
    pub comparator: String,

    last_stats: Arc<Mutex<Option<FuzzerStats>>>,
}

impl SemSanFuzzer {
    pub fn new(
        primary_binary: PathBuf,
        secondary_binary: PathBuf,
        seeds: PathBuf,
        solutions: PathBuf,
        pull_corpus: PathBuf,
        comparator: String,
    ) -> Self {
        Self {
            primary_binary,
            secondary_binary,
            seeds,
            solutions,
            pull_corpus,
            comparator,

            last_stats: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Fuzzer for SemSanFuzzer {
    fn get_name(&self) -> &str {
        "semsan"
    }
    fn get_instance_name(&self) -> String {
        self.get_name().to_string()
    }
    async fn get_stats(&self) -> FuzzerStats {
        let stats = self.last_stats.lock().await.clone();
        stats.unwrap_or(FuzzerStats::default())
    }

    fn get_push_corpus(&self) -> Option<PathBuf> {
        None
    }

    fn get_pull_corpus(&self) -> Option<PathBuf> {
        Some(self.pull_corpus.clone())
    }

    fn get_solutions(&self) -> Vec<PathBuf> {
        vec![self.solutions.clone()]
    }

    fn start(&mut self) -> tokio::process::Child {
        let _ = std::fs::create_dir_all(&self.solutions);
        let _ = std::fs::create_dir_all(&self.seeds);
        let _ = std::fs::create_dir_all(&self.pull_corpus);

        if std::fs::read_dir(&self.seeds).unwrap().count() == 0 {
            let mut dummy_input = std::fs::File::create(self.seeds.join("dummy_input")).unwrap();
            dummy_input.write_all(b"AAA").unwrap();
        }

        // TODO make this async
        let file_info = std::process::Command::new("file")
            .arg(&self.secondary_binary)
            .output()
            .unwrap()
            .stdout;

        let info: Vec<&str> = unsafe {
            std::str::from_utf8_unchecked(&file_info)
                .split(",")
                .collect()
        };
        assert!(info.len() > 2);

        #[cfg(target_arch = "x86_64")]
        let x86_64_bin = "semsan";
        #[cfg(not(target_arch = "x86_64"))]
        let x86_64_bin = "semsan-x86_64"; // emulate x86_64
        #[cfg(target_arch = "aarch64")]
        let aarch64_bin = "semsan";
        #[cfg(not(target_arch = "aarch64"))]
        let aarch64_bin = "semsan-aarch64"; // emulate aarch64

        // TODO detect host
        let semsan_binary = match info[1] {
            " ARM" => "semsan-arm",
            " x86-64" => x86_64_bin,
            " ARM aarch64" => aarch64_bin,
            _ => "semsan",
        };

        let mut command = tokio::process::Command::new(semsan_binary);

        if let Ok(comparator) = std::env::var("SEMSAN_CUSTOM_COMPARATOR") {
            command.env("LD_PRELOAD", comparator);
            command.args(&["--comparator", "custom"]);
        } else {
            command.args(&["--comparator", &self.comparator]);
        }
        command.args(&["--timeout", "5000"]);
        command.arg("--ignore-exit-kind");
        command.args(&[&self.primary_binary, &self.secondary_binary]);
        command.args(&[
            "fuzz",
            "--seeds",
            self.seeds.to_str().unwrap(),
            "--solutions",
            self.solutions.to_str().unwrap(),
            "--foreign-corpus",
            self.pull_corpus.to_str().unwrap(),
            "--ignore-solutions",
        ]);

        command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        let mut child = command.spawn().expect("Could not start SemSan instance");

        let stdout = child.stdout.take().unwrap();

        spawn_semsan_log_parser(BufReader::new(stdout), self.last_stats.clone());

        child
    }
}

fn spawn_semsan_log_parser(
    stdout_reader: BufReader<tokio::process::ChildStdout>,
    last_stats: Arc<Mutex<Option<FuzzerStats>>>,
) {
    let mut lines = stdout_reader.lines();

    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            // [UserStats #0] run time: 0h-0m-0s, clients: 1, corpus: 18, objectives: 0, executions: 536, exec/sec: 0.000, combined-coverage: 8/65599 (0%), stability: 4/7 (57%)
            // [UserStats #0] run time: 0h-0m-0s, clients: 1, corpus: 19, objectives: 0, executions: 602, exec/sec: 0.000, combined-coverage: 8/65599 (0%), stability: 4/7 (57%)
            // [UserStats #0] run time: 0h-0m-0s, clients: 1, corpus: 20, objectives: 0, executions: 604, exec/sec: 0.000, combined-coverage: 8/65599 (0%), stability: 4/7 (57%)

            let new_regex =
                    regex::Regex::new(r".* run time: .*, clients: .*, corpus: (?<corpus>[0-9]*), objectives: (?<solutions>.*), executions: .*, exec/sec: (?<execs_per_sec>.*), combined-coverage: .*, stability: [0-9]*/[0-9]* \((?<stability>[0-9]*)%")
                        .unwrap();

            let Some(caps) = new_regex.captures(&line) else {
                continue;
            };

            let mut stats = last_stats.lock().await;
            *stats = Some(FuzzerStats {
                execs_per_sec: caps["execs_per_sec"].parse().unwrap_or(0.0),
                corpus_count: caps["corpus"].parse().unwrap_or(0),
                stability: None, // Some(caps["stability"].parse().unwrap_or(0)),
                saved_hangs: 0,  // Not stored by SemSan
                saved_crashes: caps["solutions"].parse().unwrap_or(0),
            });
        }
    });
}
