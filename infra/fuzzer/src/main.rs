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
                Sanitizer::SemSan(_) => Some("secondary"),
            };

            let engine_str = match engine {
                FuzzEngine::None => panic!("Can't add FuzzEngine::None to ensemble-fuzz flags"),
                FuzzEngine::LibFuzzer => "libfuzzer",
                FuzzEngine::AflPlusPlus => "aflpp",
                FuzzEngine::HonggFuzz => "honggfuzz",
                FuzzEngine::SemSan => "semsan",
                FuzzEngine::NativeGo => "native-go",
            };

            command.arg(
                sanitizer_str.map_or(format!("--{}-binary", engine_str), |sanitizer_str| {
                    format!("--{}-{}-binary", engine_str, sanitizer_str)
                }),
            );

            command.arg(get_harness_binary(engine, sanitizer, &opts.harness, &config).unwrap());
        };

    let mut command = tokio::process::Command::new("ensemble-fuzz");
    // afl++ requires symbolize=0
    command.env("ASAN_OPTIONS", "detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:abort_on_error=1:symbolize=0");
    let mut supported_fuzzers = Vec::new();

    let mut cores_assigned = 0;

    if config.has_engine(&FuzzEngine::NativeGo) && num_cpus::get() > cores_assigned {
        cores_assigned = num_cpus::get();
        supported_fuzzers.push((FuzzEngine::NativeGo, Sanitizer::None));
    }

    if config.has_engine(&FuzzEngine::SemSan) && num_cpus::get() > cores_assigned {
        if let Some(sanitizers) = &config.sanitizers {
            supported_fuzzers.push((FuzzEngine::SemSan, Sanitizer::None));
            for sanitizer in sanitizers.iter() {
                if matches!(sanitizer, &Sanitizer::SemSan(_))
                    && config.has_sanitizer(sanitizer)
                    && num_cpus::get() > cores_assigned
                {
                    supported_fuzzers.push((FuzzEngine::SemSan, sanitizer.clone()));
                    cores_assigned += 1;
                }
            }
        }
    }

    if config.has_engine(&FuzzEngine::LibFuzzer) && num_cpus::get() > cores_assigned {
        supported_fuzzers.push((FuzzEngine::LibFuzzer, Sanitizer::None));
        cores_assigned += 1;
        if config.has_sanitizer(&Sanitizer::ValueProfile) && num_cpus::get() > cores_assigned {
            command.arg("--libfuzzer-value-profile");
            cores_assigned += 1;
        }

        if !config.has_engine(&FuzzEngine::AflPlusPlus) {
            // We only add libFuzzer sanitizer instances if we haven't already afl++ instances.
            for sanitizer in &[Sanitizer::Address, Sanitizer::Undefined] {
                if config.has_sanitizer(sanitizer) && num_cpus::get() > cores_assigned {
                    supported_fuzzers.push((FuzzEngine::LibFuzzer, sanitizer.clone()));
                    cores_assigned += 1;
                }
            }
        }

        if !config.has_engine(&FuzzEngine::AflPlusPlus) {
            // Allocate additional cores to libfuzzer if afl++ is not enabled
            if num_cpus::get() > cores_assigned {
                command.arg("--libfuzzer-add-cores");
                command.arg((num_cpus::get() - cores_assigned).to_string());
            }
        }
    }

    if config.has_engine(&FuzzEngine::HonggFuzz) && num_cpus::get() > cores_assigned {
        supported_fuzzers.push((FuzzEngine::HonggFuzz, Sanitizer::None));
        cores_assigned += 1;

        // TODO honggfuzz sanitizers

        if !config.has_engine(&FuzzEngine::AflPlusPlus)
            && !config.has_engine(&FuzzEngine::LibFuzzer)
        {
            // Allocate additional cores to honggfuzz if afl++ and libfuzzer are not enabled
            if num_cpus::get() > cores_assigned {
                command.arg("--honggfuzz-add-cores");
                command.arg((num_cpus::get() - cores_assigned).to_string());
            }
        }
    }

    if config.has_engine(&FuzzEngine::AflPlusPlus) && num_cpus::get() > cores_assigned {
        supported_fuzzers.push((FuzzEngine::AflPlusPlus, Sanitizer::None));
        cores_assigned += 1;

        for sanitizer in &[Sanitizer::CmpLog, Sanitizer::Address, Sanitizer::Undefined] {
            if config.has_sanitizer(sanitizer) && num_cpus::get() > cores_assigned {
                supported_fuzzers.push((FuzzEngine::AflPlusPlus, sanitizer.clone()));
                cores_assigned += 1;
            }
        }

        // Occupy left over cores with afl++ instances
        command.arg("--aflpp-occupy");
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
