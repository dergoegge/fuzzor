use std::path::PathBuf;

use clap::Parser;
use fuzzor_infra::{get_harness_binary, FuzzEngine, ProjectConfig, Sanitizer};
use tokio::{fs, process::Command};

#[derive(Parser, Debug)]
struct Options {
    #[arg(help = "Path to project config file", required = true)]
    pub config: PathBuf,
    #[arg(help = "Input corpus to be minimized", required = true)]
    pub input_corpus: PathBuf,
    #[arg(help = "Path to output corpus", required = true)]
    pub output_corpus: PathBuf,
    #[arg(help = "Harness name", required = true)]
    pub harness: String,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let opts = Options::parse();

    let config = fs::read_to_string(&opts.config).await?;
    let config: ProjectConfig = serde_yaml::from_str(&config).unwrap();

    let afl_success =
        if config.has_engine(&FuzzEngine::AflPlusPlus) && config.has_sanitizer(&Sanitizer::None) {
            let status = Command::new("afl-cmin")
                .args(vec![
                    "-i",
                    opts.input_corpus.as_os_str().to_str().unwrap(),
                    "-o",
                    opts.output_corpus.as_os_str().to_str().unwrap(),
                    "--",
                    get_harness_binary(
                        &FuzzEngine::AflPlusPlus,
                        &Sanitizer::None,
                        &opts.harness,
                        &config,
                    )
                    .unwrap()
                    .to_str()
                    .unwrap(),
                ])
                .kill_on_drop(true)
                .status()
                .await?;

            status.success()
        } else {
            false
        };

    let libfuzzer_success =
        if config.has_engine(&FuzzEngine::LibFuzzer) && config.has_sanitizer(&Sanitizer::None) {
            let status = Command::new(
                get_harness_binary(
                    &FuzzEngine::LibFuzzer,
                    &Sanitizer::None,
                    &opts.harness,
                    &config,
                )
                .unwrap(),
            )
            .args(vec![
                "-rss_limit_mb=8000",
                "-set_cover_merge=1",
                "-shuffle=0",
                "-prefer_small=1",
                "-use_value_profile=0",
                opts.output_corpus.as_os_str().to_str().unwrap(),
                opts.input_corpus.as_os_str().to_str().unwrap(),
            ])
            .kill_on_drop(true)
            .status()
            .await?;

            status.success()
        } else {
            false
        };

    // Native go fuzzing does not support minimization (like really???)
    let native_go_success =
        if config.has_engine(&FuzzEngine::NativeGo) && config.has_sanitizer(&Sanitizer::None) {
            let status = Command::new("cp")
                .args(vec![
                    "-r",
                    opts.input_corpus.as_os_str().to_str().unwrap(),
                    opts.output_corpus.as_os_str().to_str().unwrap(),
                ])
                .kill_on_drop(true)
                .status()
                .await?;

            status.success()
        } else {
            false
        };

    if !afl_success && !libfuzzer_success && !native_go_success {
        std::process::exit(1);
    }

    Ok(())
}
