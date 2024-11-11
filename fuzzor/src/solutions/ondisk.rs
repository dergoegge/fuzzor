use std::path::PathBuf;

use crate::solutions::{inmemory::InMemorySolutionTracker, Solution, SolutionTracker};

use tokio::{fs, io::AsyncWriteExt};

pub struct OnDiskSolutionTracker {
    cache: InMemorySolutionTracker, // in memory cache
    path: PathBuf,
}

impl OnDiskSolutionTracker {
    pub async fn new(path: PathBuf) -> Option<Self> {
        let _ = fs::create_dir_all(&path).await;

        let mut cache = InMemorySolutionTracker::default();

        // Load all solutions from disk into the in-memory cache
        match fs::read_dir(&path).await {
            Ok(mut paths) => {
                while let Some(entry) = paths.next_entry().await.unwrap() {
                    let path = entry.path();
                    if path.is_file() {
                        add_to_cache_if_yaml(&mut cache, &path).await;
                    }
                }
            }
            Err(err) => {
                log::error!("Could not list solution tracker directory: {}", err);
                return None;
            }
        };

        Some(Self { cache, path })
    }
}

async fn add_to_cache_if_yaml(cache: &mut InMemorySolutionTracker, path: &PathBuf) {
    assert!(path.is_file());

    if let Ok(solution) = fs::read_to_string(path).await {
        if let Ok(solution) = serde_yaml::from_str(&solution) {
            let _ = cache.submit(solution).await;
        }
    }
}

fn solution_file_name(solution: &Solution) -> String {
    format!("solution-{}", solution.id())
}

#[async_trait::async_trait]
impl SolutionTracker for OnDiskSolutionTracker {
    async fn mark_as_resolved(&mut self, id: &str) -> Option<Solution> {
        let cache_result = self.cache.mark_as_resolved(id).await;

        if let Some(solution) = cache_result.as_ref() {
            if let Err(err) = fs::remove_file(solution_file_name(solution)).await {
                log::error!("Could not remove solution file from disk: {}", err);
            }
        }

        cache_result
    }

    async fn submit(&mut self, solution: Solution) -> bool {
        let cache_result = self.cache.submit(solution.clone()).await;

        if let Ok(yaml) = serde_yaml::to_string(&solution) {
            let mut file = fs::File::create(self.path.join(solution_file_name(&solution)))
                .await
                .unwrap();

            if let Err(err) = file.write_all(yaml.as_bytes()).await {
                log::error!("Failed to write solution to disk: {}", err);
            }

            if let Err(err) = file.flush().await {
                log::error!("Failed to flush solution to disk: {}", err);
            }
        }

        cache_result
    }

    async fn get_open(&self, id: &str) -> Option<&Solution> {
        self.cache.get_open(id).await
    }

    async fn get_all(&self) -> Vec<Solution> {
        self.cache.get_all().await
    }
}
