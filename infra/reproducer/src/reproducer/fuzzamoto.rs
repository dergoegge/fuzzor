use super::{create_cloned_files, Reproducer};
use fuzzor_infra::ReproducedSolution;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum FuzzamotoReproducerError {
    FailedToCreateWorkdir,
    HarnessOrScenarioBinaryNotFound,
    FailedToReadTestCase,
    FailedToSpawnScenarioCommand,
    FailedToWriteToScenarioStdin,
    FailedToWaitOnScenarioCommand,
    FailedToCreateOutputFile,
    FailedToReadOutputFile,
    SolutionNotReproducible,
}

impl Error for FuzzamotoReproducerError {}

impl fmt::Display for FuzzamotoReproducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzamotoReproducerError::FailedToCreateWorkdir => {
                write!(f, "Failed to create workdir")
            }
            FuzzamotoReproducerError::HarnessOrScenarioBinaryNotFound => {
                write!(f, "Harness or scenario binary not found")
            }
            FuzzamotoReproducerError::FailedToReadTestCase => write!(f, "Failed to read test case"),
            FuzzamotoReproducerError::FailedToSpawnScenarioCommand => {
                write!(f, "Failed to spawn scenario command")
            }
            FuzzamotoReproducerError::FailedToWriteToScenarioStdin => {
                write!(f, "Failed to write to scenario stdin")
            }
            FuzzamotoReproducerError::FailedToWaitOnScenarioCommand => {
                write!(f, "Failed to wait on scenario command")
            }
            FuzzamotoReproducerError::FailedToCreateOutputFile => {
                write!(f, "Failed to create stdout/stderr output file")
            }
            FuzzamotoReproducerError::FailedToReadOutputFile => {
                write!(f, "Failed to read stdout/stderr output file")
            }
            FuzzamotoReproducerError::SolutionNotReproducible => {
                write!(f, "Solution not reproducible")
            }
        }
    }
}

pub struct FuzzamotoReproducer {
    harness_directory: PathBuf,
    test_case: PathBuf,
}

impl FuzzamotoReproducer {
    pub fn new(harness_directory: PathBuf, test_case: PathBuf) -> Self {
        Self {
            harness_directory,
            test_case,
        }
    }
}

#[async_trait::async_trait]
impl Reproducer<FuzzamotoReproducerError> for FuzzamotoReproducer {
    async fn reproduce(&self) -> Result<ReproducedSolution, FuzzamotoReproducerError> {
        let workdir =
            tempfile::tempdir().map_err(|_| FuzzamotoReproducerError::FailedToCreateWorkdir)?;

        // Check for bitcoind and scenario binary in harness directory
        let bitcoind = self.harness_directory.join("bitcoind");
        let scenario = self.harness_directory.join("scenario");

        if !bitcoind.exists() || !scenario.exists() {
            return Err(FuzzamotoReproducerError::HarnessOrScenarioBinaryNotFound);
        }

        // Read test case into memory
        let test_case_bytes = tokio::fs::read(&self.test_case)
            .await
            .map_err(|_| FuzzamotoReproducerError::FailedToReadTestCase)?;

        let output_path = workdir.path().join("output.txt");
        let (stdout, stderr) = create_cloned_files(&output_path)
            .map_err(|_| FuzzamotoReproducerError::FailedToCreateOutputFile)?;

        let asan_options = std::env::var("ASAN_OPTIONS").unwrap_or_default();
        let asan_options = format!(
            "{}:symbolize=1:abort_on_error=1:handle_abort=1",
            asan_options
        );

        let mut child = tokio::process::Command::new(&scenario)
            .arg(&bitcoind)
            .stdin(std::process::Stdio::piped())
            .stdout(stdout)
            .stderr(stderr)
            .env("RUST_LOG", "debug")
            .env("ASAN_OPTIONS", asan_options)
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| FuzzamotoReproducerError::FailedToSpawnScenarioCommand)?;

        // Get stdin handle and write test case contents
        if let Some(mut stdin) = child.stdin.take() {
            tokio::io::AsyncWriteExt::write_all(&mut stdin, &test_case_bytes)
                .await
                .map_err(|_| FuzzamotoReproducerError::FailedToWriteToScenarioStdin)?;
            // Drop stdin handle to close the pipe
            drop(stdin);
        }

        let status = child
            .wait()
            .await
            .map_err(|_| FuzzamotoReproducerError::FailedToWaitOnScenarioCommand)?;

        if status.success() {
            return Err(FuzzamotoReproducerError::SolutionNotReproducible);
        }

        let trace = tokio::fs::read(&output_path)
            .await
            .map_err(|_| FuzzamotoReproducerError::FailedToReadOutputFile)?;

        Ok(ReproducedSolution {
            code: 71,
            input: test_case_bytes,
            trace,
        })
    }
}
