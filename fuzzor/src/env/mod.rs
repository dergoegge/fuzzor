pub mod docker;

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;

use crate::solutions::Solution;

use fuzzor_infra::{CpuArchitecture, FuzzerStats, ProjectConfig};
use tokio::sync::{Mutex, Semaphore};

/// Environment defines a generic environment for fuzzing campaigns.
pub trait Environment {
    /// Get environment identifier
    fn get_id(&self) -> impl Future<Output = String> + Send;
    /// Get aggreagated fuzzer stats
    fn get_stats(&self) -> impl Future<Output = Result<FuzzerStats, String>> + Send;
    /// Get all fuzz solutions (crashes, timeouts, etc.) found so far
    fn get_solutions(&self) -> impl Future<Output = Result<Vec<Solution>, String>> + Send;
    /// Get a tarball of the corpus
    fn get_corpus(&self, minimize: bool) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
    /// Get the names of the source files that were covered through fuzzing
    fn get_covered_files(&self) -> impl Future<Output = Result<Vec<String>, String>> + Send;
    /// Get the coverage report
    fn get_coverage_report(&self) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
    /// Upload an initial corpus to the environment
    fn upload_initial_corpus(
        &self,
        corpus: Vec<u8>,
    ) -> impl Future<Output = Result<(), String>> + Send;
    /// Start fuzzing in the environment
    fn start(&mut self) -> impl Future<Output = Result<(), String>> + Send;
    /// Shutdown the environment
    fn shutdown(&mut self) -> impl Future<Output = bool> + Send;
    /// Check if the environment is reachable
    fn ping(&self) -> impl Future<Output = Result<bool, String>> + Send;
}

/// EnvironmentAllocationError represents possible environment allocation errors
#[derive(Debug)]
pub enum EnvironmentAllocationError {
    /// Requsted architecture was not available to the allocator
    ArchNotAvailable,
}

unsafe impl Send for EnvironmentAllocationError {}

#[derive(Clone)]
pub struct EnvironmentParams {
    /// Docker image to use for the environment
    pub docker_image: String,
    /// Requested architecture for the environment
    pub arch: Option<CpuArchitecture>,
    /// Requested number of CPU cores for the environment
    pub cores: u64,
    /// Name of the harness to be fuzzed
    pub harness_name: String,
    /// Fuzz duration in seconds
    pub duration: u64,
    /// Config of the owning project
    pub project_config: ProjectConfig,
}

/// EnvironmentAllocator allocation of environments for fuzzing campaigns.
///
/// Note: it only manages the allocation of resources (e.g. available CPU cores or architectures).
pub trait EnvironmentAllocator<E>
where
    E: Environment,
{
    /// Allocate a new environment from the allocator.
    fn alloc(
        &mut self,
        opts: EnvironmentParams,
    ) -> impl Future<Output = Result<E, EnvironmentAllocationError>> + Send;
    /// Free an environment by giving it back to the allocator.
    ///
    /// A freed environment might be re-allocated in a future [alloc] call.
    fn free(&mut self, env: E) -> impl Future<Output = bool> + Send;
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
