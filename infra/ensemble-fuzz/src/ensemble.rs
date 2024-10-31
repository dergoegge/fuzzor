use std::io::Write;
use std::path::PathBuf;

use tokio::{sync::mpsc::Sender, task::JoinHandle};

use crate::fuzzer::{aggregate_stats, SharedFuzzer};

async fn sync_folders(from: PathBuf, to: PathBuf) {
    tokio::process::Command::new("rsync")
        .args([
            "--recursive",
            "--archive",
            "--checksum",
            "--checksum-choice=sha1",
            "--compress",
            "--ignore-existing",
            format!("{}/", from.to_str().unwrap()).as_str(),
            to.to_str().unwrap(),
        ])
        .output()
        .await
        .expect("rsync should sync the folders");

    log::trace!("synced {:?} -> {:?}", from, to);
}

async fn ensemble_fuzzers(
    fuzzers: &[SharedFuzzer],
    global_corpus: PathBuf,
    global_solutions: PathBuf,
) {
    for fuzzer in fuzzers.iter() {
        let fuzzer = fuzzer.lock().await;
        if let Some(push_corpus) = fuzzer.get_push_corpus() {
            sync_folders(push_corpus, global_corpus.clone()).await;
        }
    }
    for fuzzer in fuzzers.iter() {
        let fuzzer = fuzzer.lock().await;
        if let Some(pull_corpus) = fuzzer.get_pull_corpus() {
            sync_folders(global_corpus.clone(), pull_corpus).await;
        }
    }

    for fuzzer in fuzzers.iter() {
        let fuzzer = fuzzer.lock().await;
        for solution_dir in fuzzer.get_solutions() {
            sync_folders(solution_dir, global_solutions.clone()).await;
        }
    }
}

/// Start the ensemble task.
///
/// This task regularly (every [`sync_interval`] seconds) syncs each fuzzer's corpus with the
/// global corpus. It also logs aggregated stats and writes them to disk as "stats.yaml" (every
/// [`stats_interval`] seconds).
pub async fn start_ensemble_task(
    mut fuzzers: Vec<SharedFuzzer>,
    sync_interval: u64,
    stats_interval: u64,
    workspace: PathBuf,
) -> (JoinHandle<()>, Sender<()>) {
    let global_corpus = workspace.join("corpus");
    let global_solutions = workspace.join("solutions");

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    let task_handle = tokio::spawn(async move {
        // Sync the global fuzzer corpus every `sync_interval` seconds.
        use tokio::time::{interval, Duration};
        let mut stats_interval = interval(Duration::from_secs(stats_interval));
        let mut interval = interval(Duration::from_secs(sync_interval));

        let mut quit = false;
        while !quit {
            let mut only_stats = false;
            tokio::select! {
                _ = interval.tick() => {},
                _ = stats_interval.tick() => only_stats = true,
                _ = rx.recv() => quit = true,
            };

            // Get aggregated stats over all fuzzer instances. We do this before ensembling the
            // fuzzers, so that the stats are mostly in sync (i.e. there might be more solutions in
            // the global dir than the stats indicate but not less) with the global corpus and
            // solution directory.
            let global_stats = aggregate_stats(fuzzers.as_mut_slice(), global_corpus.clone()).await;
            log::info!("{:?}", global_stats);

            if !only_stats || global_stats.has_solutions() {
                // Ensemble all fuzzer instances (i.e. sync the global corpus and solutions directory).
                ensemble_fuzzers(
                    fuzzers.as_slice(),
                    global_corpus.clone(),
                    global_solutions.clone(),
                )
                .await;
            }

            if let Ok(yaml) = serde_yaml::to_string(&global_stats) {
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(workspace.join("stats.yaml"))
                    .unwrap();

                file.write_all(yaml.as_bytes()).unwrap();
                file.flush().unwrap();
            }
        }
    });

    (task_handle, tx)
}
