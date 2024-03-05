use std::path::PathBuf;

use clap::Parser;
use fuzzor_infra::{get_harness_binary, FuzzEngine, ProjectConfig, Sanitizer};
use tokio::fs;

#[derive(Parser, Debug)]
struct Options {
    #[arg(help = "Path to project config", required = true)]
    pub config: PathBuf,
    #[arg(help = "Name of the harness to fuzz", required = true)]
    pub harness: String,
    #[arg(
        long = "duration",
        help = "Campaign duration in CPU hours",
        required = true
    )]
    pub duration: f64,
    #[arg(
        long = "workspace",
        help = "Location for fuzzer data (i.e. corpus, solutions, etc.)",
        required = true
    )]
    pub workspace: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let opts = Options::parse();

    let config = fs::read_to_string(&opts.config).await?;
    let config: ProjectConfig = serde_yaml::from_str(&config).unwrap();

    let add_fuzzer =
        |engine: &FuzzEngine, sanitizer: &Sanitizer, command: &mut tokio::process::Command| {
            assert!(config.has_sanitizer(sanitizer));
            assert!(config.has_engine(engine));

            let sanitizer_str = match sanitizer {
                Sanitizer::None => None,
                Sanitizer::Coverage => None,
                Sanitizer::Address => Some("asan"),
                Sanitizer::Undefined => Some("ubsan"),
                Sanitizer::CmpLog => Some("cmplog"),
                Sanitizer::ValueProfile => None,
            };

            let engine_str = match engine {
                FuzzEngine::None => panic!("Can't add FuzzEngine::None to ensemble-fuzz flags"),
                FuzzEngine::LibFuzzer => "libfuzzer",
                FuzzEngine::AflPlusPlus => "aflpp",
            };

            command.arg(
                sanitizer_str.map_or(format!("--{}-binary", engine_str), |sanitizer_str| {
                    format!("--{}-{}-binary", engine_str, sanitizer_str)
                }),
            );

            command.arg(get_harness_binary(engine, sanitizer, &opts.harness, &config).unwrap());
        };

    let mut command = tokio::process::Command::new("ensemble-fuzz");
    let mut supported_fuzzers = Vec::new();

    if config.has_engine(&FuzzEngine::AflPlusPlus) {
        supported_fuzzers.push((FuzzEngine::AflPlusPlus, Sanitizer::None));

        for sanitizer in &[Sanitizer::CmpLog, Sanitizer::Undefined, Sanitizer::Address] {
            supported_fuzzers.push((FuzzEngine::AflPlusPlus, sanitizer.clone()));
        }

        // Occupy left over cores with afl++ instances
        command.arg("--aflpp-occupy");
    }

    if config.has_engine(&FuzzEngine::LibFuzzer) {
        let mut libfuzzer_cores = 0;
        supported_fuzzers.push((FuzzEngine::LibFuzzer, Sanitizer::None));
        libfuzzer_cores += 1;
        if config.has_sanitizer(&Sanitizer::ValueProfile) {
            command.arg("--libfuzzer-value-profile");
            libfuzzer_cores += 1;
        }

        if !config.has_engine(&FuzzEngine::AflPlusPlus) {
            // We only add libFuzzer sanitizer instances if we haven't already afl++ instances.
            for sanitizer in &[Sanitizer::Undefined, Sanitizer::Address] {
                if config.has_sanitizer(sanitizer) {
                    supported_fuzzers.push((FuzzEngine::LibFuzzer, sanitizer.clone()));
                    libfuzzer_cores += 1;
                }
            }
        }

        if !config.has_engine(&FuzzEngine::AflPlusPlus) {
            // Allocate additional cores to libfuzzer if afl++ is not enabled
            command.arg("--libfuzzer-add-cores");
            if num_cpus::get() > libfuzzer_cores {
                command.arg((num_cpus::get() - libfuzzer_cores).to_string());
            }
        }
    }

    for (engine, sanitizer) in supported_fuzzers.iter() {
        add_fuzzer(engine, sanitizer, &mut command);
    }

    let seconds_to_fuzz = (opts.duration / num_cpus::get() as f64) * 60.0 * 60.0;
    command.arg("--max-duration");
    command.arg((seconds_to_fuzz as u64).to_string());

    command.arg("--workspace");
    command.arg(&opts.workspace);

    let status = command.kill_on_drop(true).status().await?;
    std::process::exit(status.code().unwrap());
}
