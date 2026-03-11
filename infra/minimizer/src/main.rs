use std::path::PathBuf;

use clap::Parser;
use fuzzor_infra::{
    get_afl_tool_path, get_harness_binary, AflTool, FuzzEngine, ProjectConfig, Sanitizer,
};
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

async fn minimize_with_afl_nyx(
    input: &PathBuf,
    output: &PathBuf,
    harness: &str,
    config: &ProjectConfig,
) -> Result<bool, std::io::Error> {
    if !config.has_engine(&FuzzEngine::AflPlusPlusNyx) || !config.has_sanitizer(&Sanitizer::Address)
    {
        return Ok(false);
    }

    let binary = get_harness_binary(
        &FuzzEngine::AflPlusPlusNyx,
        &Sanitizer::Address,
        harness,
        config,
    )
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Nyx share dir not found"))?;

    Command::new(get_afl_tool_path(AflTool::AflCMin))
        .args([
            "-A",
            "-X",
            "-i",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--",
            binary.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .status()
        .await
        .map(|status| status.success())
}

async fn minimize_with_afl(
    input: &PathBuf,
    output: &PathBuf,
    harness: &str,
    config: &ProjectConfig,
) -> Result<bool, std::io::Error> {
    if !config.has_engine(&FuzzEngine::AflPlusPlus) || !config.has_sanitizer(&Sanitizer::None) {
        return Ok(false);
    }

    let binary = get_harness_binary(&FuzzEngine::AflPlusPlus, &Sanitizer::None, harness, config)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Harness binary not found")
        })?;

    Command::new(get_afl_tool_path(AflTool::AflCMin))
        .args([
            "-A",
            "-i",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--",
            binary.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .status()
        .await
        .map(|status| status.success())
}

async fn minimize_with_libfuzzer(
    input: &PathBuf,
    output: &PathBuf,
    harness: &str,
    config: &ProjectConfig,
) -> Result<bool, std::io::Error> {
    if !config.has_engine(&FuzzEngine::LibFuzzer) || !config.has_sanitizer(&Sanitizer::None) {
        return Ok(false);
    }

    let binary = get_harness_binary(&FuzzEngine::LibFuzzer, &Sanitizer::None, harness, config)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Harness binary not found")
        })?;

    Command::new(binary)
        .args([
            "-rss_limit_mb=8000",
            "-set_cover_merge=1",
            "-shuffle=0",
            "-prefer_small=1",
            "-use_value_profile=1",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .status()
        .await
        .map(|status| status.success())
}

async fn minimize_with_honggfuzz(
    input: &PathBuf,
    output: &PathBuf,
    harness: &str,
    config: &ProjectConfig,
) -> Result<bool, std::io::Error> {
    if !config.has_engine(&FuzzEngine::HonggFuzz)
        || !config.has_sanitizer(&Sanitizer::None)
        || std::env::var("FUZZOR_HONGGFUZZ_NO_MINIMIZE").is_ok()
    {
        return Ok(false);
    }

    let binary = get_harness_binary(&FuzzEngine::HonggFuzz, &Sanitizer::None, harness, config)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Harness binary not found")
        })?;

    Command::new("honggfuzz")
        .args([
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--minimize",
            "--",
            binary.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .status()
        .await
        .map(|status| status.success())
}

async fn copy_for_native_go(
    input: &PathBuf,
    output: &PathBuf,
    config: &ProjectConfig,
) -> Result<bool, std::io::Error> {
    if !config.has_engine(&FuzzEngine::NativeGo) || !config.has_sanitizer(&Sanitizer::None) {
        return Ok(false);
    }

    Command::new("cp")
        .args(["-r", input.to_str().unwrap(), output.to_str().unwrap()])
        .kill_on_drop(true)
        .status()
        .await
        .map(|status| status.success())
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let opts = Options::parse();
    let config: ProjectConfig =
        serde_yaml::from_str(&fs::read_to_string(&opts.config).await?).unwrap();

    // Run all available minimizers
    let afl_success = minimize_with_afl(
        &opts.input_corpus,
        &opts.output_corpus,
        &opts.harness,
        &config,
    )
    .await?;
    let afl_nyx_success = minimize_with_afl_nyx(
        &opts.input_corpus,
        &opts.output_corpus,
        &opts.harness,
        &config,
    )
    .await?;
    let libfuzzer_success = minimize_with_libfuzzer(
        &opts.input_corpus,
        &opts.output_corpus,
        &opts.harness,
        &config,
    )
    .await?;
    let honggfuzz_success = minimize_with_honggfuzz(
        &opts.input_corpus,
        &opts.output_corpus,
        &opts.harness,
        &config,
    )
    .await?;
    let native_go_success =
        copy_for_native_go(&opts.input_corpus, &opts.output_corpus, &config).await?;

    if !afl_success
        && !afl_nyx_success
        && !libfuzzer_success
        && !honggfuzz_success
        && !native_go_success
    {
        std::process::exit(1);
    }

    Ok(())
}
