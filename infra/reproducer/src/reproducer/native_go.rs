use std::error::Error;

use std::fmt::{self, Display};
use std::path::PathBuf;

use super::{create_cloned_files, Reproducer};
use fuzzor_infra::{ReproducedSolution, SolutionCause};

#[derive(Debug)]
pub enum NativeGoReproducerError {
    FailedToCreateWorkdir,
    FailedToCreateOutputFile,
    FailedToRunHarness,
    FailedToReadTestCase,
    FailedToReadOutputFile,
    SolutionNotReproducible,
}

impl Error for NativeGoReproducerError {}

impl Display for NativeGoReproducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NativeGoReproducerError::FailedToCreateWorkdir => write!(f, "Failed to create workdir"),
            NativeGoReproducerError::FailedToCreateOutputFile => {
                write!(f, "Failed to create output file")
            }
            NativeGoReproducerError::FailedToRunHarness => write!(f, "Failed to run harness"),
            NativeGoReproducerError::FailedToReadTestCase => write!(f, "Failed to read testcase"),
            NativeGoReproducerError::FailedToReadOutputFile => {
                write!(f, "Failed to read output file")
            }
            NativeGoReproducerError::SolutionNotReproducible => {
                write!(f, "Solution not reproducible")
            }
        }
    }
}

pub struct NativeGoReproducer {
    harness_binary: PathBuf,
}

impl NativeGoReproducer {
    pub fn new(harness_binary: PathBuf) -> Self {
        Self { harness_binary }
    }
}

#[async_trait::async_trait]
impl Reproducer<NativeGoReproducerError> for NativeGoReproducer {
    async fn reproduce(&self) -> Result<ReproducedSolution, NativeGoReproducerError> {
        let workdir =
            tempfile::tempdir().map_err(|_| NativeGoReproducerError::FailedToCreateWorkdir)?;

        let output_file = workdir.path().join("output.txt");
        let Ok((stderr, stdout)) = create_cloned_files(&output_file) else {
            return Err(NativeGoReproducerError::FailedToCreateOutputFile);
        };

        let status = tokio::process::Command::new("bash")
            .arg(&self.harness_binary)
            .arg("/tmp")
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|_| NativeGoReproducerError::FailedToRunHarness)?;

        if status.success() {
            return Err(NativeGoReproducerError::SolutionNotReproducible);
        }

        let trace = tokio::fs::read(&output_file)
            .await
            .map_err(|_| NativeGoReproducerError::FailedToReadOutputFile)?;
        let trace_string = String::from_utf8(trace.clone())
            .map_err(|_| NativeGoReproducerError::FailedToReadOutputFile)?;

        let test_case_regex =
            regex::Regex::new(r"(?m)failure while testing seed corpus entry: (?<test_case>.*)")
                .expect("Failed to create regex");
        let Some(caps) = test_case_regex.captures(&trace_string) else {
            log::error!("Testcase file not found in trace");
            return Err(NativeGoReproducerError::SolutionNotReproducible);
        };

        let test_case = PathBuf::from("testdata/fuzz").join(&caps["test_case"]);

        let input_bytes = tokio::fs::read(&test_case)
            .await
            .map_err(|_| NativeGoReproducerError::FailedToReadTestCase)?;

        return Ok(ReproducedSolution {
            cause: SolutionCause::Crash,
            input: input_bytes,
            trace,
        });
    }
}
