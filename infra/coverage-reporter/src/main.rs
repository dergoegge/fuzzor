use std::path::PathBuf;

use clap::Parser;

use fuzzor_infra::{get_harness_binary, FuzzEngine, Language, ProjectConfig, Sanitizer};

#[derive(Parser, Debug)]
struct Options {
    #[arg(help = "Path to project config", required = true)]
    pub config: PathBuf,
    #[arg(help = "Corpus to report coverage for", required = true)]
    pub corpus: String,
    #[arg(help = "Name of the harness to report coverage for", required = true)]
    pub harness: String,
}

#[tokio::main]
async fn main() {
    let opts = Options::parse();

    let config = tokio::fs::read_to_string(&opts.config).await.unwrap();
    let config: ProjectConfig = serde_yaml::from_str(&config).unwrap();

    let coverage_bin = get_harness_binary(
        &FuzzEngine::None,
        &Sanitizer::Coverage,
        &opts.harness,
        &config,
    )
    .unwrap();

    // Run every input in the corpus once through the harness binary instrumented for coverage
    // reporting.
    tokio::process::Command::new(&coverage_bin)
        .arg("-runs=1") // Coverage binary is compiled with LibFuzzer
        .arg(&opts.corpus)
        .kill_on_drop(true)
        .status()
        .await
        .unwrap();

    tokio::process::Command::new("llvm-profdata")
        .arg("merge")
        .arg("-sparse")
        .arg("default.profraw")
        .arg("-o")
        .arg("default.profdata")
        .kill_on_drop(true)
        .status()
        .await
        .unwrap();

    // Export a coverage summary
    let coverage_summary_file = std::fs::File::create("./coverage-summary.json").unwrap();
    tokio::process::Command::new("llvm-cov")
        .arg("export")
        .arg(coverage_bin.to_str().unwrap())
        .arg("-summary-only")
        .arg("-instr-profile=default.profdata")
        .kill_on_drop(true)
        .stdout(coverage_summary_file)
        .status()
        .await
        .unwrap();

    let demangler = match config.language {
        Language::Rust => Some("rustfilt"),
        Language::Cpp => Some("c++filt"),
        _ => None,
    };

    // Create html coverage report
    let mut html_cmd = tokio::process::Command::new("llvm-cov");
    html_cmd
        .arg("show")
        .arg(coverage_bin.to_str().unwrap())
        .arg("-instr-profile=default.profdata")
        .arg("-format=html")
        .arg("-show-directory-coverage")
        .arg("-show-branches=count")
        .arg("-output-dir=/workdir/coverage_report");

    if let Some(demangler) = demangler {
        html_cmd.arg(format!("-Xdemangler={}", demangler));
    }

    html_cmd.kill_on_drop(true).status().await.unwrap();
}
