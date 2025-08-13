use std::path::PathBuf;

use clap::Parser;
use fuzzor_infra::{get_harness_binary, FuzzEngine, HarnessConfig, ProjectConfig, Sanitizer};
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

struct FuzzerConfiguration {
    config: ProjectConfig,
    harness_config: HarnessConfig,
    total_cores: usize,
    supported_fuzzers: Vec<(FuzzEngine, Sanitizer)>,
    cores_assigned: usize,
    extra_args: Vec<String>,
}

impl FuzzerConfiguration {
    fn new(config: ProjectConfig, harness_config: HarnessConfig) -> Self {
        Self {
            config,
            harness_config,
            total_cores: num_cpus::get(),
            supported_fuzzers: Vec::new(),
            cores_assigned: 0,
            extra_args: Vec::new(),
        }
    }

    fn has_available_cores(&self) -> bool {
        self.total_cores > self.cores_assigned
    }

    fn try_add_fuzzer(&mut self, engine: FuzzEngine, sanitizer: Sanitizer) -> bool {
        if self.has_available_cores()
            && self.config.has_engine(&engine)
            && self.config.has_sanitizer(&sanitizer)
        {
            self.supported_fuzzers.push((engine, sanitizer));
            self.cores_assigned += 1;
            true
        } else {
            false
        }
    }

    fn configure_native_go(&mut self) {
        if self.try_add_fuzzer(FuzzEngine::NativeGo, Sanitizer::None) {
            self.cores_assigned = self.total_cores; // NativeGo takes all remaining cores
        }
    }

    fn configure_semsan(&mut self) {
        // First collect the sanitizers we want to add
        let semsan_sanitizers: Vec<_> = self
            .config
            .sanitizers
            .as_ref()
            .map(|sanitizers| {
                sanitizers
                    .iter()
                    .filter(|s| matches!(s, Sanitizer::SemSan(_)))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // Then add them one by one
        if self.try_add_fuzzer(FuzzEngine::SemSan, Sanitizer::None) {
            for sanitizer in semsan_sanitizers {
                self.try_add_fuzzer(FuzzEngine::SemSan, sanitizer);
            }
        }
    }

    fn configure_libfuzzer(&mut self) {
        if !self.try_add_fuzzer(FuzzEngine::LibFuzzer, Sanitizer::None) {
            return;
        }

        if self.config.has_sanitizer(&Sanitizer::ValueProfile) && self.has_available_cores() {
            self.extra_args
                .push("--libfuzzer-value-profile".to_string());
            self.cores_assigned += 1;
        }

        if !self.config.has_engine(&FuzzEngine::AflPlusPlus) {
            // Add sanitizer instances only if AFL++ is not present
            for sanitizer in &[Sanitizer::Address, Sanitizer::Undefined, Sanitizer::Memory] {
                self.try_add_fuzzer(FuzzEngine::LibFuzzer, sanitizer.clone());
            }

            // Allocate remaining cores to LibFuzzer if available
            if self.has_available_cores() {
                self.extra_args.push("--libfuzzer-add-cores".to_string());
                self.extra_args
                    .push((self.total_cores - self.cores_assigned).to_string());
            }
        }
    }

    fn configure_aflplusplus(&mut self) {
        if self.try_add_fuzzer(FuzzEngine::AflPlusPlusNyx, Sanitizer::Address) {
            self.extra_args.push("--aflpp-nyx".to_string());
            self.extra_args.push("--aflpp-occupy".to_string());
            return;
        }

        if !self.try_add_fuzzer(FuzzEngine::AflPlusPlus, Sanitizer::None) {
            return;
        }

        for sanitizer in &[
            Sanitizer::CmpLog,
            Sanitizer::Address,
            Sanitizer::Undefined,
            Sanitizer::Memory,
        ] {
            self.try_add_fuzzer(FuzzEngine::AflPlusPlus, sanitizer.clone());
        }

        self.extra_args.push("--aflpp-occupy".to_string());
    }

    fn build_command(&self, opts: &Options) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("ensemble-fuzz");

        // Set ASAN options
        command.env("ASAN_OPTIONS", 
            "strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:abort_on_error=1:symbolize=0");

        // Add all configured fuzzers
        for (engine, sanitizer) in &self.supported_fuzzers {
            add_fuzzer(engine, sanitizer, &mut command, &opts.harness, &self.config);
        }

        // Add all extra arguments
        command.args(&self.extra_args);

        if let Some(dictionary) = &self.harness_config.dictionary {
            command.arg("--dictionary").arg(dictionary);
        }

        // Configure duration and workspace
        let seconds_to_fuzz = (opts.duration / self.total_cores as f64) * 60.0 * 60.0;
        command
            .arg("--max-duration")
            .arg((seconds_to_fuzz as u64).to_string())
            .arg("--workspace")
            .arg(&opts.workspace);

        command
    }
}

// Helper function moved outside the struct
fn add_fuzzer(
    engine: &FuzzEngine,
    sanitizer: &Sanitizer,
    command: &mut tokio::process::Command,
    harness: &str,
    config: &ProjectConfig,
) {
    let sanitizer_str = match sanitizer {
        Sanitizer::None | Sanitizer::Coverage | Sanitizer::ValueProfile => None,
        // `--aflpp-binary` is set to the sharedir of the nyx address sanitizer
        // build.
        Sanitizer::Address if config.has_engine(&FuzzEngine::AflPlusPlusNyx) => None,
        Sanitizer::Address => Some("asan"),
        Sanitizer::Undefined => Some("ubsan"),
        Sanitizer::Memory => Some("msan"),
        Sanitizer::CmpLog => Some("cmplog"),
        Sanitizer::SemSan(_) => Some("secondary"),
    };

    let engine_str = match engine {
        FuzzEngine::None => panic!("Can't add FuzzEngine::None to ensemble-fuzz flags"),
        FuzzEngine::LibFuzzer => "libfuzzer",
        FuzzEngine::AflPlusPlus | FuzzEngine::AflPlusPlusNyx => "aflpp",
        FuzzEngine::HonggFuzz => "honggfuzz",
        FuzzEngine::SemSan => "semsan",
        FuzzEngine::NativeGo => "native-go",
    };

    let flag = sanitizer_str.map_or(format!("--{}-binary", engine_str), |s| {
        format!("--{}-{}-binary", engine_str, s)
    });

    command
        .arg(flag)
        .arg(get_harness_binary(engine, sanitizer, harness, config).unwrap());
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let opts = Options::parse();
    let config: ProjectConfig =
        serde_yaml::from_str(&fs::read_to_string(&opts.config).await?).unwrap();
    let harness_config = serde_yaml::from_str(
        &fs::read_to_string(&PathBuf::from(format!("/{}.options.yaml", opts.harness)))
            .await
            .unwrap_or("".to_string()),
    )
    .unwrap_or(HarnessConfig::default());

    let mut fuzzer_config = FuzzerConfiguration::new(config, harness_config);

    // Configure fuzzers
    fuzzer_config.configure_native_go();
    fuzzer_config.configure_semsan();
    fuzzer_config.configure_libfuzzer();
    fuzzer_config.configure_aflplusplus();

    // Build and execute command
    let mut command = fuzzer_config.build_command(&opts);
    let status = command.kill_on_drop(true).status().await?;
    std::process::exit(status.code().unwrap());
}
