use std::error::Error;

use std::fmt::{self, Display};
use std::path::PathBuf;

use super::{create_cloned_files, Reproducer};
use fuzzor_infra::{ReproducedSolution, Sanitizer, SolutionCause};

#[derive(Debug)]
pub enum LibFuzzerReproducerError {
    FailedToCreateOutputFile,
    FailedToRunHarness,
    FailedToReadOutputFile,
    FailedToReadTestCase,
    FailedToCreateWorkdir,

    FailedToCreatePerfOutputFile,
    FailedToRunPerfRecord,
    FailedToCreatePerfScriptFile,
    FailedToRunPerfScript,
    FailedToRunStackcollapse,
    FailedToRunFlameGraph,
    FlameGraphRepoNotConfigured,
    FailedToCreateFoldedFile,
    FailedToCreateFlameGraphFile,
    FailedToReadFlameGraphFile,

    SolutionNotReproducible,
}

impl Error for LibFuzzerReproducerError {}

impl Display for LibFuzzerReproducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct LibFuzzerReproducer {
    harness_binary: PathBuf,
    sanitizer: Sanitizer,
    test_case: PathBuf,
}

impl LibFuzzerReproducer {
    pub fn new(harness_binary: PathBuf, sanitizer: Sanitizer, test_case: PathBuf) -> Self {
        Self {
            harness_binary,
            sanitizer,
            test_case,
        }
    }

    async fn produce_flame_graph(&self) -> Result<Vec<u8>, LibFuzzerReproducerError> {
        let workdir = tempfile::tempdir()
            .map_err(|_| LibFuzzerReproducerError::FailedToCreatePerfOutputFile)?;
        let perf_output_file_path = workdir.path().join("perf_output");

        std::fs::File::create(&perf_output_file_path)
            .map_err(|_| LibFuzzerReproducerError::FailedToCreatePerfOutputFile)?;

        tokio::process::Command::new("perf")
            .args(&["record", "-g", "--output"])
            .arg(&perf_output_file_path)
            .arg("--")
            .arg(&self.harness_binary)
            .arg("-runs=5")
            .arg(&self.test_case)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|_| LibFuzzerReproducerError::FailedToRunPerfRecord)?;

        let perf_script_file_path = workdir.path().join("perf_script");
        let perf_script_file = std::fs::File::create(&perf_script_file_path)
            .map_err(|_| LibFuzzerReproducerError::FailedToCreatePerfScriptFile)?;

        tokio::process::Command::new("perf")
            .args(&["script", "--input"])
            .arg(&perf_output_file_path)
            .stdout(perf_script_file)
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|_| LibFuzzerReproducerError::FailedToRunPerfScript)?;

        let flame_graph_repo = PathBuf::from(
            std::env::var("FLAMEGRAPH_REPO")
                .map_err(|_| LibFuzzerReproducerError::FlameGraphRepoNotConfigured)?,
        );

        let folded_file_path = workdir.path().join("folded");
        let folded_file = std::fs::File::create(&folded_file_path)
            .map_err(|_| LibFuzzerReproducerError::FailedToCreateFoldedFile)?;

        tokio::process::Command::new(flame_graph_repo.join("stackcollapse-perf.pl"))
            .arg(&perf_script_file_path)
            .stdout(folded_file)
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|_| LibFuzzerReproducerError::FailedToRunStackcollapse)?;

        let flame_graph_file_path = workdir.path().join("flame_graph");
        let flame_graph_file = std::fs::File::create(&flame_graph_file_path)
            .map_err(|_| LibFuzzerReproducerError::FailedToCreateFlameGraphFile)?;

        tokio::process::Command::new(flame_graph_repo.join("flamegraph.pl"))
            .arg(&folded_file_path)
            .stdout(flame_graph_file)
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|_| LibFuzzerReproducerError::FailedToRunFlameGraph)?;

        let flame_graph_bytes = tokio::fs::read(&flame_graph_file_path)
            .await
            .map_err(|_| LibFuzzerReproducerError::FailedToReadFlameGraphFile)?;

        Ok(flame_graph_bytes)
    }
}

#[async_trait::async_trait]
impl Reproducer<LibFuzzerReproducerError> for LibFuzzerReproducer {
    async fn reproduce(&self) -> Result<ReproducedSolution, LibFuzzerReproducerError> {
        log::info!(
            "Reproducing with libfuzzer (sanitizer={:?}) {:?}",
            self.sanitizer,
            self.test_case
        );

        let workdir =
            tempfile::tempdir().map_err(|_| LibFuzzerReproducerError::FailedToCreateWorkdir)?;

        // File that merges the harness' stdout and stderr
        let output_file = workdir.path().join("output.txt");
        let Ok((stderr, stdout)) = create_cloned_files(&output_file) else {
            return Err(LibFuzzerReproducerError::FailedToCreateOutputFile);
        };

        // Read the test case into memory
        let input_bytes = tokio::fs::read(&self.test_case)
            .await
            .map_err(|_| LibFuzzerReproducerError::FailedToReadTestCase)?;

        let status = tokio::process::Command::new(&self.harness_binary)
            .args(vec![
                "-error_exitcode=77",
                "-timeout_exitcode=78",
                "-timeout=1",
            ])
            .arg(&self.test_case)
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|_| LibFuzzerReproducerError::FailedToRunHarness)?;

        if !status.success() {
            let code = status.code().unwrap_or(66); // 66: probably a signal kill

            // Create a flamegraph for timeouts and read the stack trace from stdout/stderr for crashes.
            let trace = match code {
                78 => self.produce_flame_graph().await?,
                _ => tokio::fs::read(&output_file)
                    .await
                    .map_err(|_| LibFuzzerReproducerError::FailedToReadOutputFile)?,
            };

            return Ok(ReproducedSolution {
                cause: match (code, &self.sanitizer) {
                    (78, _) => SolutionCause::Timeout,
                    (66, _) => SolutionCause::SignalCrash,
                    (_, Sanitizer::Address) => SolutionCause::AsanCrash,
                    (_, Sanitizer::Undefined) => SolutionCause::UbsanCrash,
                    (_, Sanitizer::Memory) => SolutionCause::MsanCrash,
                    (_, _) => SolutionCause::Crash,
                },
                input: input_bytes,
                trace,
            });
        }

        Err(LibFuzzerReproducerError::SolutionNotReproducible)
    }
}
