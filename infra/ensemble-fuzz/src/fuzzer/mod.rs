pub mod aflpp;
pub mod honggfuzz;
pub mod libfuzzer;
pub mod native_go;
pub mod semsan;

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use fuzzor_infra::FuzzerStats;
use tokio::sync::Mutex;

/// [`Fuzzer`] provides an abstraction for fuzz engines, useful for ensembling various fuzz engines
/// to work in parallel.
#[async_trait]
pub trait Fuzzer {
    /// Name of the underlying fuzz engine.
    fn get_name(&self) -> &str;
    /// Name of the fuzz instance
    fn get_instance_name(&self) -> String;

    /// Get [`FuzzerStats`] for the instance
    async fn get_stats(&self) -> FuzzerStats;

    /// Path to the corpus that the fuzzer pushes new inputs to.
    fn get_push_corpus(&self) -> Option<PathBuf>;
    /// Path to a corpus that the fuzzer pulls new inputs from.
    fn get_pull_corpus(&self) -> Option<PathBuf>;
    /// Path to a folder containing solutions found by the fuzzer.
    fn get_solutions(&self) -> Vec<PathBuf>;

    /// Start the fuzzer instance.
    fn start(&mut self) -> tokio::process::Child;
}

pub type SharedFuzzer = Arc<Mutex<dyn Fuzzer + Send>>;

/// Aggregate [`FuzzerStats`] across multiple fuzzer instances.
///
/// Most metrics are simply summed up (e.g. execs/s, number of crashes). However, for stability the
/// minimum is returned and corpus_count refelects the number of files in the global corpus.
pub async fn aggregate_stats(fuzzers: &mut [SharedFuzzer], global_corpus: PathBuf) -> FuzzerStats {
    let mut stats = FuzzerStats::default();
    let mut stability = None;
    for fuzzer in fuzzers.iter() {
        let fuzzer = fuzzer.lock().await;
        let other_stats = fuzzer.get_stats().await;

        log::trace!("{} stats: {:?}", fuzzer.get_instance_name(), &other_stats);

        stats.execs_per_sec += other_stats.execs_per_sec;
        stability = match (stability, other_stats.stability) {
            (Some(stab1), Some(stab2)) => Some(f64::min(stab1, stab2)),
            (Some(stab1), None) => Some(stab1),
            (None, Some(stab2)) => Some(stab2),
            (None, None) => None,
        };

        stats.saved_crashes += other_stats.saved_crashes;
        stats.saved_hangs += other_stats.saved_hangs;
    }

    stats.stability = stability;

    stats.corpus_count = std::fs::read_dir(global_corpus)
        .unwrap()
        .collect::<Result<Vec<_>, std::io::Error>>()
        .unwrap()
        .len() as u64;

    stats
}
