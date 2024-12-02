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

/// LibFuzzer is an implementation of [`Fuzzer`] for the libFuzzer engine.
pub struct LibFuzzer {
    pub seeds: PathBuf,
    pub workspace: PathBuf,
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub instance_tag: String,

    last_stats: Arc<Mutex<Option<FuzzerStats>>>,
}

impl LibFuzzer {
    pub fn new(
        seeds: PathBuf,
        workspace: PathBuf,
        binary: PathBuf,
        args: Vec<String>,
        env: HashMap<String, String>,
        instance_tag: String,
    ) -> Self {
        let fuzzer = Self {
            seeds,
            workspace,
            binary,
            args,
            env,
            instance_tag,
            last_stats: Arc::new(Mutex::new(None)),
        };

        if !fuzzer.seeds.exists() {
            std::fs::create_dir(&fuzzer.seeds).unwrap();
        }

        for solution_dir in fuzzer.get_solutions() {
            if !solution_dir.exists() {
                std::fs::create_dir(&solution_dir).unwrap();
            }
        }

        fuzzer
    }
}

#[async_trait]
impl Fuzzer for LibFuzzer {
    fn get_name(&self) -> &str {
        "libfuzzer"
    }

    fn get_instance_name(&self) -> String {
        format!("{}-{}", self.get_name(), &self.instance_tag)
    }

    async fn get_stats(&self) -> FuzzerStats {
        let stats = self.last_stats.lock().await.clone();
        stats.unwrap_or(FuzzerStats::default())
    }

    fn get_push_corpus(&self) -> Option<PathBuf> {
        Some(self.seeds.clone())
    }

    fn get_pull_corpus(&self) -> Option<PathBuf> {
        Some(self.seeds.clone())
    }

    fn get_solutions(&self) -> Vec<PathBuf> {
        vec![self.workspace.join("solutions")]
    }

    fn start(&mut self) -> tokio::process::Child {
        let mut args = Vec::new();
        args.extend(self.args.iter().map(std::ops::Deref::deref));

        args.push("-timeout=5");

        let solutions_dirs = self.get_solutions();
        let artifact_arg = format!("-artifact_prefix={}/", solutions_dirs[0].to_str().unwrap());
        args.push(artifact_arg.as_str());
        args.push(self.seeds.to_str().unwrap());

        let mut command = tokio::process::Command::new(self.binary.to_str().unwrap());
        command.args(&args);
        command.envs(&self.env);
        command.stdout(Stdio::null());
        command.stderr(Stdio::piped());

        let host_env: HashMap<String, String> = std::env::vars().collect();
        command.envs(host_env);
        command.kill_on_drop(true);

        let mut child = command.spawn().expect("Could not start libFuzzer instance");

        let stderr = child.stderr.take().unwrap();

        spawn_libfuzzer_log_parser(
            self.get_instance_name(),
            BufReader::new(stderr),
            self.last_stats.clone(),
            solutions_dirs[0].clone(),
        );

        child
    }
}

fn spawn_libfuzzer_log_parser(
    instance_name: String,
    stderr_reader: BufReader<tokio::process::ChildStderr>,
    last_stats: Arc<Mutex<Option<FuzzerStats>>>,
    crash_dir: PathBuf,
) {
    let mut lines = stderr_reader.lines();

    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            // Match lines as the following:
            // "#505851: cov: 5744 ft: 5240 corp: 1284 exec/s: 20917 oom/timeout/crash: 0/0/0 time: 36s job: 7 dft_time: 0"
            // "#37221: cov: 5298 ft: 5298 corp: 1302 exec/s: 18610 oom/timeout/crash: 0/0/0 time: 2s job: 1 dft_time: 0"
            // "#70933: cov: 5298 ft: 5298 corp: 1302 exec/s: 11237 oom/timeout/crash: 0/0/0 time: 6s job: 2 dft_time: 0"
            // "#79983: cov: 136 ft: 193 corp: 41 exec/s 16059 oom/timeout/crash: 0/0/0 time: 5s job: 2 dft_time: 0" (example from cargo-fuzz)

            // The ":" after "exec/s" is not there for cargo-fuzz, so we treat it as optional
            let new_regex =
                    regex::Regex::new(r"#[0-9]*: cov: [0-9]* ft: [0-9]* corp: (?<corpus>[0-9]*) exec/s[:]? (?<execs_per_sec>[0-9]*) oom/timeout/crash: [0-9]*/(?<hangs>[0-9]*)/(?<crashes>[0-9]*).*")
                        .unwrap();
            log::trace!("({}) {}", new_regex.is_match(&line), line);

            let Some(caps) = new_regex.captures(&line) else {
                continue;
            };

            let mut saved_crashes = caps["crashes"].parse().unwrap_or(0);
            if saved_crashes > 0 {
                let crashes = std::fs::read_dir(&crash_dir)
                    .unwrap()
                    .collect::<Result<Vec<_>, std::io::Error>>()
                    .unwrap();

                if crashes.is_empty() {
                    // LibFuzzer reported a crash but didn't store it on disk for some reason.
                    // Noticed with Go targets compiled for LibFuzzer with go-118-fuzz-build.
                    saved_crashes = 0;
                } else {
                    log::trace!("Solutions {}: {:?}", instance_name, &crashes);
                }
            }

            let mut stats = last_stats.lock().await;
            *stats = Some(FuzzerStats {
                execs_per_sec: caps["execs_per_sec"].parse().unwrap_or(0.0),
                corpus_count: caps["corpus"].parse().unwrap_or(0),
                // Stability not available from libFuzzer output :(
                stability: None,
                saved_hangs: caps["hangs"].parse().unwrap_or(0),
                saved_crashes,
            });
        }
    });
}
