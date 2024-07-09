use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use crate::options::EnsembleOptions;

use async_trait::async_trait;
use fuzzor_infra::FuzzerStats;
use rand::Rng;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::Mutex,
};

/// [`Fuzzer`] provides an abstraction for fuzz engines, useful for ensembling various fuzz engines
/// to work in parallel.
#[async_trait]
pub trait Fuzzer {
    /// Name of the underlying fuzz engine.
    fn get_name(&self) -> &str;
    /// Name of the fuzz instance
    fn get_instance_name(&self) -> String;

    /// Get [`FuzzerStats`] for the instance
    async fn get_stats(&self) -> FuzzerStats;

    /// Whether or not the fuzzer's corpus should be synced with the global corpus.
    ///
    /// Note: Disabling syncing mostly only makes sense for fuzz engines that do not support
    /// pulling in new inputs found by other fuzzers at runtime.
    fn should_sync_corpus(&self) -> bool {
        true
    }

    /// Path to the corpus that the fuzzer pushes new inputs to.
    fn get_push_corpus(&self) -> PathBuf;
    /// Path to a corpus that the fuzzer pulls new inputs from.
    fn get_pull_corpus(&self) -> PathBuf;
    /// Path to a folder containing solutions found by the fuzzer.
    fn get_solutions(&self) -> Vec<PathBuf>;

    /// Start the fuzzer instance.
    fn start(&mut self) -> tokio::process::Child;
}

pub type SharedFuzzer = Arc<Mutex<dyn Fuzzer + Send>>;

pub struct SemSanFuzzer {
    pub primary_binary: PathBuf,
    pub secondary_binary: PathBuf,
    pub seeds: PathBuf,
    pub solutions: PathBuf,
    pub pull_corpus: PathBuf,
    pub comparator: String,
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
        FuzzerStats {
            saved_crashes: std::fs::read_dir(&self.solutions).unwrap().count() as u64,
            // TODO parse other stats from stdout
            ..Default::default()
        }
    }

    fn get_push_corpus(&self) -> PathBuf {
        // TODO SemSan does not actually push new inputs here, maybe the push corpus should be
        // optional?
        self.seeds.clone()
    }

    fn get_pull_corpus(&self) -> PathBuf {
        self.pull_corpus.clone()
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

        let mut command = tokio::process::Command::new("semsan");
        command.args(&["--comparator", &self.comparator, "--timeout", "5000"]);
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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }
}

/// AflppFuzzer is an implementation of [`Fuzzer`] for the afl++ fuzz engine.
pub struct AflppFuzzer {
    pub seeds: Option<PathBuf>,
    // Workdir for afl++ instances (should be the same for all instances)
    pub workspace: PathBuf,
    pub binary: PathBuf,
    pub id: u64,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,

    out_dir: PathBuf,
    pull_corpus: PathBuf,
}

impl AflppFuzzer {
    pub fn new(
        seeds: Option<PathBuf>,
        workspace: PathBuf,
        binary: PathBuf,
        id: u64,
        args: Vec<String>,
        env: HashMap<String, String>,
    ) -> Self {
        Self {
            seeds,
            workspace,
            binary,
            id,
            args,
            env,
            out_dir: PathBuf::new(),
            pull_corpus: PathBuf::new(),
        }
    }
}

#[async_trait]
impl Fuzzer for AflppFuzzer {
    fn get_name(&self) -> &str {
        "afl++"
    }

    fn get_instance_name(&self) -> String {
        format!("{}-{}", self.get_name(), self.id)
    }

    async fn get_stats(&self) -> FuzzerStats {
        let mut stats = FuzzerStats::default();

        if let Ok(stat_file) =
            std::fs::read_to_string(self.out_dir.join(self.id.to_string()).join("fuzzer_stats"))
        {
            let mut afl_fuzzer_stats = HashMap::new();
            stat_file
                .lines()
                .map(|line| line.split(":").collect::<Vec<_>>())
                .for_each(|split| {
                    afl_fuzzer_stats.insert(split[0].trim(), split[1].trim());
                });

            stats.execs_per_sec = afl_fuzzer_stats
                .get("execs_per_sec")
                .unwrap()
                .parse()
                .unwrap_or(0.0);
            stats.corpus_count = afl_fuzzer_stats
                .get("corpus_count")
                .unwrap()
                .parse()
                .unwrap_or(0);
            stats.saved_crashes = afl_fuzzer_stats
                .get("saved_crashes")
                .unwrap()
                .parse()
                .unwrap_or(0);
            stats.saved_hangs = afl_fuzzer_stats
                .get("saved_hangs")
                .unwrap()
                .parse()
                .unwrap_or(0);

            if self.id == 0 {
                // Stability seems to be inaccurate for sanitized binaries, only
                // collect from the main instance for now.
                stats.stability = Some(
                    afl_fuzzer_stats
                        .get("stability")
                        .unwrap()
                        .strip_suffix("%")
                        .unwrap()
                        .parse()
                        .unwrap_or(0.0),
                );
            }
        }

        stats
    }

    fn should_sync_corpus(&self) -> bool {
        // Only the main instance (-M) of afl++ needs to be synced
        self.id == 0
    }

    fn get_push_corpus(&self) -> PathBuf {
        self.out_dir.join(self.id.to_string()).join("queue")
    }

    fn get_pull_corpus(&self) -> PathBuf {
        self.pull_corpus.clone()
    }

    fn get_solutions(&self) -> Vec<PathBuf> {
        vec![
            self.out_dir.join(self.id.to_string()).join("crashes"),
            self.out_dir.join(self.id.to_string()).join("hangs"),
        ]
    }

    fn start(&mut self) -> tokio::process::Child {
        self.out_dir = self.workspace.join("out");
        self.pull_corpus = self.workspace.join("pull_corpus");
        let _ = std::fs::create_dir(&self.pull_corpus);

        let mut args = Vec::new();

        args.push("-t");
        args.push("5000");

        // Specify initial seeds or setup to resume
        args.push("-i");
        if let Some(seeds) = self.seeds.as_ref() {
            if std::fs::read_dir(seeds).unwrap().count() == 0 {
                let mut dummy_input = std::fs::File::create(seeds.join("dummy_input")).unwrap();
                dummy_input.write_all(b"AAA").unwrap();
            }
            args.push(seeds.to_str().unwrap());
        } else {
            args.push("-");
        }

        // Specify afl++'s output dir
        args.push("-o");
        args.push(self.out_dir.to_str().unwrap());

        // Specify instance type (main/secondary) and name
        let id_str = self.id.to_string();
        if self.id == 0 {
            args.push("-M");
            args.push(&id_str);
            args.push("-F");
            args.push(self.pull_corpus.to_str().unwrap());
        } else {
            args.push("-S");
            args.push(&id_str);
        }

        // Append extra args
        args.extend(self.args.iter().map(std::ops::Deref::deref));

        // Specify the binary under test
        args.push("--");
        args.push(self.binary.to_str().unwrap());

        let mut command = tokio::process::Command::new("afl-fuzz");
        command.args(&args);

        self.env
            .insert(String::from("AFL_NO_UI"), String::from("1"));
        command.envs(&self.env);
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());

        let host_env: HashMap<String, String> = std::env::vars().collect();
        command.envs(host_env);
        command.kill_on_drop(true);

        command.spawn().expect("Could not start afl++ instance")
    }
}

fn apply_aflpp_setting<F: FnMut(usize, &str, Option<&str>)>(
    cores: usize,
    name: &str,
    value: Option<&str>,
    percentage: f64,
    used: &mut HashMap<String, HashSet<usize>>,
    append: &mut F,
) {
    let cores_with_arg = cores as f64 * percentage;
    for _ in 0..cores_with_arg as u64 {
        if !used.contains_key(name) {
            used.insert(name.to_string(), HashSet::new());
        }
        let used_args = used.get_mut(name).unwrap();

        let cores_without = &HashSet::from_iter((0..cores).into_iter()) - used_args;
        if !cores_without.is_empty() {
            let core = cores_without
                .iter()
                .nth(rand::thread_rng().gen_range(0..cores_without.len()))
                .unwrap()
                .clone();

            used_args.insert(core);

            append(core, name, value);
        }
    }
}

/// Generate recommended afl-fuzz settings for a given number of instances
/// (https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores).
///
/// Returns a list of afl-fuzz arguments and a list of afl specific environment variables.
pub fn recommended_aflpp_settings(
    cores: usize,
    options: &EnsembleOptions,
) -> (Vec<Vec<String>>, Vec<HashMap<String, String>>) {
    let mut envs: Vec<HashMap<String, String>> = Vec::new();
    envs.resize_with(cores, || HashMap::new());
    let mut append_env = |core: usize, var: &str, value: Option<&str>| {
        envs[core].insert(var.to_string(), value.unwrap_or("1").to_string());
    };

    let mut args: Vec<Vec<String>> = Vec::new();
    args.resize_with(cores, || Vec::new());
    let mut append_arg = |core: usize, arg: &str, value: Option<&str>| {
        args[core].extend(arg.split(" ").map(String::from));
        if let Some(value) = value {
            args[core].extend(value.split(" ").map(String::from));
        }
    };

    let mut used_env_vars = HashMap::new();
    apply_aflpp_setting(
        cores,
        "AFL_DISABLE_TRIM",
        None,
        0.65,
        &mut used_env_vars,
        &mut append_env,
    );
    apply_aflpp_setting(
        cores,
        "AFL_KEEP_TIMEOUTS",
        None,
        0.5,
        &mut used_env_vars,
        &mut append_env,
    );
    apply_aflpp_setting(
        cores,
        "AFL_EXPAND_HAVOC_NOW",
        None,
        0.4,
        &mut used_env_vars,
        &mut append_env,
    );

    if std::env::var("ENSEMBLE_FUZZ_LIMIT_INPUT_LEN").is_ok() {
        apply_aflpp_setting(
            cores,
            "AFL_INPUT_LEN_MAX",
            Some("128"),
            0.1,
            &mut used_env_vars,
            &mut append_env,
        );
        apply_aflpp_setting(
            cores,
            "AFL_INPUT_LEN_MAX",
            Some("8192"),
            0.1,
            &mut used_env_vars,
            &mut append_env,
        );
    }

    let mut used_args = HashMap::new();
    apply_aflpp_setting(cores, "-L", Some("0"), 0.1, &mut used_args, &mut append_arg);
    apply_aflpp_setting(cores, "-Z", None, 0.1, &mut used_args, &mut append_arg);
    apply_aflpp_setting(
        cores,
        "-P",
        Some("explore"),
        0.4,
        &mut used_args,
        &mut append_arg,
    );
    apply_aflpp_setting(
        cores,
        "-P",
        Some("exploit"),
        0.2,
        &mut used_args,
        &mut append_arg,
    );
    apply_aflpp_setting(
        cores,
        "-a",
        Some("binary"),
        0.3,
        &mut used_args,
        &mut append_arg,
    );
    apply_aflpp_setting(
        cores,
        "-a",
        Some("ascii"),
        0.3,
        &mut used_args,
        &mut append_arg,
    );

    let pow_scheds = &["fast", "explore", "coe", "lin", "quad", "exploit", "rare"];
    for i in 0..cores {
        append_arg(i, "-p", Some(pow_scheds[i % pow_scheds.len()]));
    }

    if let Some(cmplog_bin) = options
        .aflpp_cmplog_binary
        .as_ref()
        .map(|c| c.to_str())
        .unwrap_or(None)
    {
        apply_aflpp_setting(
            cores,
            format!("-c {}", cmplog_bin).as_str(),
            Some("-l 2"),
            0.1,
            &mut used_args,
            &mut append_arg,
        );
        apply_aflpp_setting(
            cores,
            format!("-c {}", cmplog_bin).as_str(),
            Some("-l 3"),
            0.1,
            &mut used_args,
            &mut append_arg,
        );
        apply_aflpp_setting(
            cores,
            format!("-c {}", cmplog_bin).as_str(),
            Some("-l 2AT"),
            0.1,
            &mut used_args,
            &mut append_arg,
        );
    }

    (args, envs)
}

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

    fn get_push_corpus(&self) -> PathBuf {
        self.seeds.clone()
    }

    fn get_pull_corpus(&self) -> PathBuf {
        self.seeds.clone()
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
        let mut stderr_reader = BufReader::new(stderr).lines();

        let last_stats = self.last_stats.clone();
        let instance_name = self.get_instance_name();
        tokio::spawn(async move {
            while let Ok(Some(line)) = stderr_reader.next_line().await {
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

                let caps_crashes = caps["crashes"].parse().unwrap_or(0);
                let num_crashes = if caps_crashes > 0 {
                    let crashes = std::fs::read_dir(&solutions_dirs[0])
                        .unwrap()
                        .collect::<Result<Vec<_>, std::io::Error>>()
                        .unwrap();

                    if crashes.is_empty() {
                        // LibFuzzer reported a crash but didn't store it on disk for some reason.
                        // Noticed with Go targets compiled for LibFuzzer with go-118-fuzz-build.
                        0u64
                    } else {
                        log::trace!("Solutions {}: {:?}", instance_name, &crashes);
                        caps_crashes
                    }
                } else {
                    caps_crashes
                };

                let mut stats = last_stats.lock().await;
                *stats = Some(FuzzerStats {
                    execs_per_sec: caps["execs_per_sec"].parse().unwrap_or(0.0),
                    corpus_count: caps["corpus"].parse().unwrap_or(0),
                    // Stability not available from libFuzzer output :(
                    stability: None,
                    saved_hangs: caps["hangs"].parse().unwrap_or(0),
                    saved_crashes: num_crashes,
                });
            }
        });

        child
    }
}

/// Aggregate [`FuzzerStats`] across multiple fuzzer instances.
///
/// Most metrics are simply summed up (e.g. execs/s, number of crashes). However, for stability the
/// minimum is returned and corpus_count refelects the number of files in the global corpus.
pub async fn aggregate_stats(fuzzers: &mut [SharedFuzzer], global_corpus: PathBuf) -> FuzzerStats {
    let mut stats = FuzzerStats::default();
    let mut stability = None;
    for fuzzer in fuzzers.iter() {
        let fuzzer = fuzzer.lock().await;
        let other_stats = fuzzer.get_stats().await;

        log::trace!("{} stats: {:?}", fuzzer.get_instance_name(), &other_stats);

        stats.execs_per_sec += other_stats.execs_per_sec;
        stability = match (stability, other_stats.stability) {
            (Some(stab1), Some(stab2)) => Some(f64::min(stab1, stab2)),
            (Some(stab1), None) => Some(stab1),
            (None, Some(stab2)) => Some(stab2),
            (None, None) => None,
        };

        stats.saved_crashes += other_stats.saved_crashes;
        stats.saved_hangs += other_stats.saved_hangs;
    }

    stats.stability = stability;

    stats.corpus_count = std::fs::read_dir(global_corpus)
        .unwrap()
        .collect::<Result<Vec<_>, std::io::Error>>()
        .unwrap()
        .len() as u64;

    stats
}
