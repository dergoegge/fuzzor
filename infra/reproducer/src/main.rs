use std::path::PathBuf;
use std::process::Stdio;

use clap::Parser;
use futures::StreamExt;
use rand::distributions::{Alphanumeric, DistString};
use tokio::fs;

use fuzzor_infra::{get_harness_binary, FuzzEngine, ProjectConfig, ReproducedSolution, Sanitizer};

async fn create_flame_graph_for_input(
    binary: PathBuf,
    test_case: PathBuf,
) -> Result<Vec<u8>, std::io::Error> {
    let perf_output_file_path =
        std::env::temp_dir().join(Alphanumeric.sample_string(&mut rand::thread_rng(), 16));

    tokio::process::Command::new("perf")
        .args(vec![
            "record",
            "-g",
            "--output",
            perf_output_file_path.to_str().unwrap(),
            "--",
            binary.to_str().unwrap(),
            "-runs=5",
            test_case.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await?;

    let perf_script_file_path =
        std::env::temp_dir().join(Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
    let perf_script_file = std::fs::File::create(&perf_script_file_path)?;

    tokio::process::Command::new("perf")
        .args(vec![
            "script",
            "--input",
            perf_output_file_path.to_str().unwrap(),
        ])
        .stdout(perf_script_file)
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await?;

    let flame_graph_repo = PathBuf::from(std::env::var("FLAMEGRAPH_REPO").unwrap());

    let folded_file_path =
        std::env::temp_dir().join(Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
    let folded_file = std::fs::File::create(&folded_file_path)?;

    tokio::process::Command::new(flame_graph_repo.join("stackcollapse-perf.pl"))
        .args(vec![perf_script_file_path.to_str().unwrap()])
        .stdout(folded_file)
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await?;

    let flame_graph_file_path =
        std::env::temp_dir().join(Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
    let flame_graph_file = std::fs::File::create(&flame_graph_file_path)?;
    tokio::process::Command::new(flame_graph_repo.join("flamegraph.pl"))
        .args(vec![folded_file_path.to_str().unwrap()])
        .stdout(flame_graph_file)
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await?;

    // Remove all files except the flamegraph
    tokio::fs::remove_file(perf_output_file_path).await?;
    tokio::fs::remove_file(perf_script_file_path).await?;
    tokio::fs::remove_file(folded_file_path).await?;

    let flame_graph_bytes = tokio::fs::read(&flame_graph_file_path).await?;
    tokio::fs::remove_file(flame_graph_file_path).await?;

    Ok(flame_graph_bytes)
}

async fn reproduce(
    binary: PathBuf,
    test_case: PathBuf,
    output_dir: PathBuf,
) -> Result<Option<PathBuf>, std::io::Error> {
    let tmp_file =
        std::env::temp_dir().join(Alphanumeric.sample_string(&mut rand::thread_rng(), 16));

    let stderr = std::fs::File::create(&tmp_file)?;
    let stdout = stderr.try_clone()?;

    let test_case_str = test_case.clone().to_str().unwrap().to_string();

    let status = tokio::process::Command::new(&binary)
        .args(vec![
            "-error_exitcode=77",
            "-timeout_exitcode=78",
            "-timeout=1",
            &test_case_str,
        ])
        .stdout(stderr)
        .stderr(stdout)
        .kill_on_drop(true)
        .status()
        .await?;

    if let Some(code) = status.code() {
        let file_name = test_case.file_name().unwrap().to_str().unwrap();
        let reproduced_solution = std::fs::File::create(output_dir.join(file_name))?;

        // Create a flamegraph for timeouts and read the stack trace from stdout/stderr for crashes.
        let trace = match code {
            78 => create_flame_graph_for_input(binary, test_case.clone()).await?,
            75..=77 => tokio::fs::read(&tmp_file).await?,
            _ => {
                tokio::fs::remove_file(&tmp_file).await?;
                return Ok(None);
            }
        };

        serde_yaml::to_writer(
            reproduced_solution,
            &ReproducedSolution {
                code,
                input: tokio::fs::read(&test_case).await?,
                trace,
            },
        )
        .unwrap();

        tokio::fs::remove_file(&tmp_file).await?;
        return Ok(Some(test_case));
    }

    tokio::fs::remove_file(tmp_file).await?;
    Ok(None)
}

#[derive(Parser, Debug, Clone)]
pub struct Options {
    #[arg(
        long = "output-dir",
        help = "Path to output directory where reproduced solutions are written to",
        required = true
    )]
    pub output_dir: PathBuf,
    #[arg(help = "Path to the project config", required = true)]
    pub config: PathBuf,
    #[arg(
        help = "Files or directories containing the solutions to reproduce",
        required = true
    )]
    pub solutions: Vec<PathBuf>,
    #[arg(
        help = "Name of the harness to reproduce solutions for",
        required = true
    )]
    pub harness: String,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    let opts = Options::parse();

    let config = fs::read_to_string(&opts.config).await?;
    let config: ProjectConfig = serde_yaml::from_str(&config).unwrap();

    let _ = tokio::fs::create_dir_all(&opts.output_dir).await;

    let mut repro_futures = futures::stream::FuturesUnordered::new();

    let sanitizers = vec![Sanitizer::None, Sanitizer::Undefined, Sanitizer::Address];
    let libfuzzer_bins: Vec<PathBuf> = sanitizers
        .iter()
        .filter(|sanitizer| config.has_sanitizer(sanitizer))
        .map(|sanitizer| {
            get_harness_binary(&FuzzEngine::LibFuzzer, sanitizer, &opts.harness, &config).unwrap()
        })
        .collect();

    for dir_or_file in opts.solutions.iter() {
        if dir_or_file.is_file() {
            log::info!("Reproducing test case: {:?}", dir_or_file);

            for bin in libfuzzer_bins.iter() {
                repro_futures.push(reproduce(
                    bin.clone(),
                    dir_or_file.clone(),
                    opts.output_dir.clone(),
                ));
            }
            continue;
        }

        if dir_or_file.is_dir() {
            log::info!("Reproducing all test cases from dir: {:?}", dir_or_file);

            let mut dir_entries = fs::read_dir(dir_or_file).await?;
            while let Some(entry) = dir_entries.next_entry().await? {
                if !entry.path().is_file() {
                    continue;
                }

                for bin in libfuzzer_bins.iter() {
                    repro_futures.push(reproduce(
                        bin.clone(),
                        entry.path(),
                        opts.output_dir.clone(),
                    ));
                }
            }
        }
    }

    while let Some(res) = repro_futures.next().await {
        match res {
            Ok(Some(trace_file)) => {
                log::info!("Reproduced solution, strack trace file: {:?}", trace_file)
            }
            e => log::warn!("Test case did not reproduce: {:?}", e),
        }
    }

    Ok(())
}
