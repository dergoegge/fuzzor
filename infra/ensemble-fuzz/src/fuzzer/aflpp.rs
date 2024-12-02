use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

use crate::options::EnsembleOptions;

use async_trait::async_trait;
use fuzzor_infra::FuzzerStats;
use rand::Rng;

use super::Fuzzer;

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

    fn get_push_corpus(&self) -> Option<PathBuf> {
        if self.id == 0 {
            Some(self.out_dir.join(self.id.to_string()).join("queue"))
        } else {
            None
        }
    }

    fn get_pull_corpus(&self) -> Option<PathBuf> {
        if self.id == 0 {
            Some(self.pull_corpus.clone())
        } else {
            None
        }
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
