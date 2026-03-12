use clap::Parser;
use std::{io, path::PathBuf};
use tokio::process::Command;

use fuzzor_infra::{get_harness_binary, FuzzEngine, Language, ProjectConfig, Sanitizer};

const PROFRAW_FILE: &str = "default.profraw";
const PROFDATA_FILE: &str = "default.profdata";
const COVERAGE_SUMMARY_FILE: &str = "coverage-summary.json";
const COVERED_FUNCTIONS_FILE: &str = "/workdir/covered-functions.txt";
const COVERAGE_REPORT_DIR: &str = "/workdir/coverage_report";

#[derive(Parser, Debug)]
struct Options {
    #[arg(help = "Path to project config", required = true)]
    pub config: PathBuf,
    #[arg(help = "Corpus to report coverage for", required = true)]
    pub corpus: String,
    #[arg(help = "Name of the harness to report coverage for", required = true)]
    pub harness: String,
}

struct CoverageReporter {
    binary_path: PathBuf,
    demangler: Option<String>,
}

impl CoverageReporter {
    fn new(binary_path: PathBuf, language: &Language) -> Self {
        let demangler = match language {
            Language::Rust => Some("rustfilt".to_string()),
            Language::Cpp => Some("c++filt".to_string()),
            _ => None,
        };
        Self {
            binary_path,
            demangler,
        }
    }

    async fn run_coverage_binary(&self, corpus_path: &str) -> io::Result<()> {
        let status = Command::new(&self.binary_path)
            .arg("-runs=1")
            .arg(corpus_path)
            .kill_on_drop(true)
            .status()
            .await?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Coverage binary execution failed",
            ));
        }
        Ok(())
    }

    async fn merge_profdata(&self) -> io::Result<()> {
        let status = Command::new("llvm-profdata")
            .args(["merge", "-sparse", PROFRAW_FILE, "-o", PROFDATA_FILE])
            .kill_on_drop(true)
            .status()
            .await?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to merge profdata",
            ));
        }
        Ok(())
    }

    async fn export_coverage_summary(&self) -> io::Result<()> {
        let coverage_summary_file = std::fs::File::create(COVERAGE_SUMMARY_FILE)?;

        let status = Command::new("llvm-cov")
            .args([
                "export",
                self.binary_path.to_str().unwrap(),
                "-summary-only",
                &format!("-instr-profile={}", PROFDATA_FILE),
            ])
            .kill_on_drop(true)
            .stdout(coverage_summary_file)
            .status()
            .await?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to export coverage summary",
            ));
        }
        Ok(())
    }

    async fn export_covered_functions(&self) -> io::Result<()> {
        let mut cmd = Command::new("llvm-cov");
        cmd.args([
            "export",
            self.binary_path.to_str().unwrap(),
            &format!("-instr-profile={}", PROFDATA_FILE),
        ]);

        if let Some(demangler) = &self.demangler {
            cmd.arg(format!("-Xdemangler={}", demangler));
        }

        let output = cmd.kill_on_drop(true).output().await?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to export full coverage data",
            ));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut function_names = Vec::new();
        if let Some(functions) = json["data"][0]["functions"].as_array() {
            for func in functions {
                if func["count"].as_i64().unwrap_or(0) > 0 {
                    if let Some(name) = func["name"].as_str() {
                        function_names.push(name.to_string());
                    }
                }
            }
        }

        function_names.sort();
        function_names.dedup();

        let contents = function_names.join("\n");
        tokio::fs::write(COVERED_FUNCTIONS_FILE, contents).await?;

        Ok(())
    }

    async fn generate_html_report(&self) -> io::Result<()> {
        let mut cmd = Command::new("llvm-cov");
        cmd.args([
            "show",
            self.binary_path.to_str().unwrap(),
            &format!("-instr-profile={}", PROFDATA_FILE),
            "-format=html",
            "-show-directory-coverage",
            "-show-branches=count",
            &format!("-output-dir={}", COVERAGE_REPORT_DIR),
        ]);

        if let Some(demangler) = &self.demangler {
            cmd.arg(format!("-Xdemangler={}", demangler));
        }

        let status = cmd.kill_on_drop(true).status().await?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to generate HTML report",
            ));
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let opts = Options::parse();

    let config = tokio::fs::read_to_string(&opts.config).await?;
    let config: ProjectConfig =
        serde_yaml::from_str(&config).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let coverage_bin = get_harness_binary(
        &FuzzEngine::None,
        &Sanitizer::Coverage,
        &opts.harness,
        &config,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get harness binary"))?;

    let reporter = CoverageReporter::new(coverage_bin, &config.language);

    reporter.run_coverage_binary(&opts.corpus).await?;
    reporter.merge_profdata().await?;
    reporter.export_coverage_summary().await?;
    reporter.export_covered_functions().await?;
    reporter.generate_html_report().await?;

    Ok(())
}
