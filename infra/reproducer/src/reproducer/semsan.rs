use std::error::Error;

use std::fmt::{self, Display};
use std::path::PathBuf;

use super::Reproducer;
use fuzzor_infra::{ReproducedSolution, SolutionCause};

#[derive(Debug)]
pub enum SemSanReproducerError {
    FailedToCreateWorkdir,
    FailedToCreateSeedsDir,
    FailedToCreateSolutionsDir,
    FailedToCopyTestCase,
    FailedToRunSemSan,
    FailedToParseFileInfo,
    FailedToCreateStderrFile,
    FailedToReadStderrFile,
    FailedToReadTestCase,
    SolutionNotReproducible,
}

impl Error for SemSanReproducerError {}

impl Display for SemSanReproducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct SemSanReproducer {
    primary_harness_binary: PathBuf,
    secondary_harness_binary: PathBuf,
    test_case: PathBuf,
}

impl SemSanReproducer {
    pub fn new(
        primary_harness_binary: PathBuf,
        secondary_harness_binary: PathBuf,
        test_case: PathBuf,
    ) -> Self {
        Self {
            primary_harness_binary,
            secondary_harness_binary,
            test_case,
        }
    }
}

#[async_trait::async_trait]
impl Reproducer<SemSanReproducerError> for SemSanReproducer {
    async fn reproduce(&self) -> Result<ReproducedSolution, SemSanReproducerError> {
        let workdir =
            tempfile::tempdir().map_err(|_| SemSanReproducerError::FailedToCreateWorkdir)?;

        let seeds_dir = workdir.path().join("seeds");
        let solutions_dir = workdir.path().join("solutions");

        tokio::fs::create_dir_all(&seeds_dir)
            .await
            .map_err(|_| SemSanReproducerError::FailedToCreateSeedsDir)?;
        tokio::fs::create_dir_all(&solutions_dir)
            .await
            .map_err(|_| SemSanReproducerError::FailedToCreateSolutionsDir)?;

        tokio::fs::copy(
            &self.test_case,
            seeds_dir.join(self.test_case.file_name().unwrap()),
        )
        .await
        .map_err(|_| SemSanReproducerError::FailedToCopyTestCase)?;

        let test_case_bytes = tokio::fs::read(&self.test_case)
            .await
            .map_err(|_| SemSanReproducerError::FailedToReadTestCase)?;

        let (x86_bin, aarch64_bin) = match std::env::consts::ARCH {
            "x86_64" => ("semsan", "semsan-aarch64"),
            "aarch64" => ("semsan-x86_64", "semsan"),
            _ => ("semsan-x86_64", "semsan-aarch64"),
        };

        let file_info = tokio::process::Command::new("file")
            .arg(&self.secondary_harness_binary)
            .output()
            .await
            .map_err(|_| SemSanReproducerError::FailedToParseFileInfo)?;

        let file_info: Vec<&str> = unsafe {
            std::str::from_utf8_unchecked(&file_info.stdout)
                .split(",")
                .collect()
        };

        let semsan_binary = match file_info[1] {
            " ARM" => "semsan-arm",
            " x86-64" => x86_bin,
            " ARM aarch64" => aarch64_bin,
            _ => "semsan",
        };

        let mut semsan_cmd = tokio::process::Command::new(semsan_binary);

        if let Ok(comparator) = std::env::var("SEMSAN_CUSTOM_COMPARATOR") {
            semsan_cmd
                .env("LD_PRELOAD", comparator)
                .args(&["--comparator", "custom"]);
        }

        semsan_cmd
            .args(&["--timeout", "5000", "--solution-exit-code", "71"])
            .args(&[&self.primary_harness_binary, &self.secondary_harness_binary])
            .arg(&seeds_dir)
            .arg("--solutions")
            .arg(&solutions_dir)
            .arg("--run-seeds-once");

        let stderr_path = workdir.path().join("stderr.txt");
        let stderr = std::fs::File::create(&stderr_path)
            .map_err(|_| SemSanReproducerError::FailedToCreateStderrFile)?;

        let status = semsan_cmd
            .stdout(std::process::Stdio::null())
            .stderr(stderr)
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|_| SemSanReproducerError::FailedToRunSemSan)?;

        if let Some(71) = status.code() {
            let trace = tokio::fs::read(&stderr_path)
                .await
                .map_err(|_| SemSanReproducerError::FailedToReadStderrFile)?;

            return Ok(ReproducedSolution {
                cause: SolutionCause::Differential,
                input: test_case_bytes,
                trace,
            });
        }

        Err(SemSanReproducerError::SolutionNotReproducible)
    }
}
