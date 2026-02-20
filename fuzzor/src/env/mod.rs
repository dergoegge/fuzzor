use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use crate::solutions::Solution;

use async_trait::async_trait;
use fuzzor_infra::{CpuArchitecture, FuzzerStats, ProjectConfig};
use tokio::sync::{Mutex, Semaphore};

/// Environment defines a generic environment for fuzzing campaigns.
#[async_trait]
pub trait Environment {
    /// Get environment identifier
    async fn get_id(&self) -> String;
    /// Get fuzzer stats, aggregated over all fuzz instances that are running as part of the active
    /// campaign.
    async fn get_stats(&self) -> Result<FuzzerStats, String>;
    /// Get all fuzz solutions (crashes, timeouts, etc.) found so far
    async fn get_solutions(&self) -> Result<Vec<Solution>, String>;
    /// Attempt to reproduce the given solutions
    async fn reproduce_solutions(&self, solutions: Vec<Solution>) -> Result<Vec<Solution>, String>;
    /// Get a tarball of the corpus
    async fn get_corpus(&self, minimize: bool) -> Result<Vec<u8>, String>;
    /// Get the names of the source files that were covered through fuzzing
    async fn get_covered_files(&self) -> Result<Vec<String>, String>;
    /// Get the coverage report
    async fn get_coverage_report(&self) -> Result<Vec<u8>, String>;
    /// Get the raw coverage summary (coverage-summary.json)
    async fn get_coverage_summary(&self) -> Result<Vec<u8>, String>;
    /// Upload an initial corpus to the environment
    async fn upload_initial_corpus(&self, corpus: Vec<u8>) -> Result<(), String>;
    /// Start fuzzing in the environment
    async fn start(&mut self) -> Result<(), String>;
    /// Shutdown the environment
    async fn shutdown(&mut self) -> bool;
    /// Check if the environment is reachable
    async fn ping(&self) -> Result<bool, String>;
}

#[derive(Clone)]
pub struct EnvironmentParams {
    /// Docker image to use for the environment
    pub docker_image: String,
    /// Requested architecture for the environment
    pub arch: Option<CpuArchitecture>,
    /// Name of the harness to be fuzzed
    pub harness_name: String,
    /// Fuzz duration in seconds
    pub duration: Duration,
    /// Config of the owning project
    pub project_config: ProjectConfig,
}

/// EnvironmentAllocator allocation of environments for fuzzing campaigns.
///
/// Note: it only manages the allocation of resources (e.g. available CPU cores or architectures).
#[async_trait]
pub trait EnvironmentAllocator<E>
where
    E: Environment,
{
    /// Allocate a new environment from the allocator.
    async fn alloc(&mut self, opts: EnvironmentParams) -> Result<E, String>;

    /// Free an environment by giving it back to the allocator.
    ///
    /// A freed environment might be re-allocated in a future [alloc] call.
    async fn free(&mut self, env: E) -> bool;
}

#[derive(Clone)]
pub struct ResourcePool<T> {
    queue: Arc<Mutex<VecDeque<T>>>,
    queue_semaphore: Arc<Semaphore>,
}

impl<T> ResourcePool<T> {
    pub fn new(resources: impl IntoIterator<Item = T>) -> Self {
        let queue = VecDeque::from_iter(resources);
        Self {
            queue_semaphore: Arc::new(Semaphore::new(queue.len())),
            queue: Arc::new(Mutex::new(queue)),
        }
    }

    pub async fn take_one(&self) -> T {
        loop {
            if let Ok(permit) = self.queue_semaphore.acquire().await {
                let mut queue = self.queue.lock().await;
                if let Some(resource) = queue.pop_front() {
                    permit.forget();
                    return resource;
                }
            }
        }
    }

    pub async fn take_many(&self, num: u32) -> Vec<T> {
        loop {
            if let Ok(permit) = self.queue_semaphore.acquire_many(num).await {
                let mut queue = self.queue.lock().await;
                if queue.len() < num as usize {
                    continue;
                }

                permit.forget();
                return queue.drain(0..num as usize).collect::<Vec<_>>();
            }
        }
    }

    pub async fn add_one(&self, resource: T) {
        let mut queue = self.queue.lock().await;
        queue.push_back(resource);

        self.queue_semaphore.add_permits(1);
    }

    pub async fn add_many(&self, resources: Vec<T>) {
        let size = resources.len();
        let mut queue = self.queue.lock().await;
        queue.extend(resources);

        self.queue_semaphore.add_permits(size);
    }
}

/// ResourcePool for CPU cores
pub type Cores = ResourcePool<u64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pool_resource_test() {
        let mut resources: Vec<u64> = vec![0, 1, 2, 3, 4, 5];
        let resource = Arc::new(ResourcePool::new(resources.drain(..)));
        assert_eq!(resource.take_one().await, 0);
        assert_eq!(resource.take_one().await, 1);
        assert_eq!(resource.take_many(4).await, vec![2, 3, 4, 5]);
        resource.add_many(vec![0, 1, 2, 3, 4, 5]).await;
        assert_eq!(resource.take_many(6).await, vec![0, 1, 2, 3, 4, 5]);

        let resource_clone = resource.clone();
        let wait_for_res_task = tokio::spawn(async move { resource_clone.take_many(6).await });

        resource.add_many(vec![0, 1, 2, 3, 4, 5]).await;

        assert_eq!(wait_for_res_task.await.unwrap(), vec![0, 1, 2, 3, 4, 5]);
    }
}
