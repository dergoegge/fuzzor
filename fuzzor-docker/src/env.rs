use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

use fuzzor::{
    env::{
        Cores, Environment, EnvironmentAllocationError, EnvironmentAllocator, EnvironmentParams,
    },
    solutions::Solution,
};

use futures_util::stream::StreamExt;
use fuzzor_infra::{FuzzerStats, ReproducedSolution};

pub const ENSEMBLE_DIR: &str = "/workdir/workspace";
pub const LIBFUZZER_STACK_TRACE_SUFFIX: &str = ".libfuzzer.crash";

pub struct DockerEnv {
    docker: bollard::Docker,
    container_id: String,
    cores: Vec<u64>,

    params: EnvironmentParams,
}

impl DockerEnv {
    pub async fn new(cores: Vec<u64>, params: EnvironmentParams) -> Self {
        let docker = bollard::Docker::connect_with_socket_defaults().unwrap();

        let cpuset_cpus = cores
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // Setup a tmpfs with limited size to avoid blowing up the host's disk space.
        let mut tmpfs = HashMap::new();
        tmpfs.insert("/tmp".to_string(), "size=8G".to_string());

        let fuzz_cmd = format!(
            "fuzzer --duration {} --workspace ./workspace ./config.yaml {}",
            params.duration.to_string(),
            &params.harness_name
        );

        let minimizer_cmd = format!(
            "minimizer ./config.yaml ./workspace/corpus ./workspace/min_corpus {}",
            params.harness_name
        );

        let coverage_cmd = format!(
            "coverage-reporter ./config.yaml ./workspace/min_corpus {}",
            params.harness_name
        );

        let full_cmd = format!("{} && {} && {}", fuzz_cmd, minimizer_cmd, coverage_cmd);

        let mut config = bollard::container::Config {
            image: Some(params.docker_image.clone()),
            tty: Some(true),
            working_dir: Some(String::from("/workdir")),
            cmd: Some(vec!["/bin/bash".to_string(), "-c".to_string(), full_cmd]),
            host_config: Some(bollard::secret::HostConfig {
                privileged: Some(true), // TODO needed for perf, use seccomp options instead
                cpuset_cpus: Some(cpuset_cpus),
                tmpfs: Some(tmpfs),
                ..Default::default()
            }),
            ..Default::default()
        };

        if let Some(env) = params.project_config.fuzz_env_var.as_ref() {
            config.env = Some(vec![format!("{}={}", env, params.harness_name)]);
        }

        let container_id = docker
            .create_container::<String, String>(
                Some(bollard::container::CreateContainerOptions {
                    //name: format!("fuzzor-{}", harness),
                    ..Default::default()
                }),
                config,
            )
            .await
            .unwrap()
            .id;

        log::trace!(
            "Created docker env: harness='{}' project='{}' container-id='{}'",
            &params.harness_name,
            &params.project_config.name,
            &container_id[..8]
        );

        Self {
            docker,
            container_id,
            cores,
            params,
        }
    }

    async fn download_tar(&self, path: String) -> Result<Vec<u8>, String> {
        let mut download = self.docker.download_from_container(
            &self.container_id,
            Some(bollard::container::DownloadFromContainerOptions { path }),
        );

        let mut tar_bytes = Vec::new();
        while let Some(chunk) = download.next().await {
            let bytes = chunk.map_err(|e| format!("Could not download tar chunk: {}", e))?;
            tar_bytes.extend(bytes.to_vec());
        }

        Ok(tar_bytes)
    }

    async fn reproduce_solutions(&self) -> Result<(), String> {
        let env = self
            .params
            .project_config
            .fuzz_env_var
            .as_ref()
            .map_or(None, |env| {
                Some(vec![format!("{}={}", env, self.params.harness_name)])
            });

        let exec = self
            .docker
            .create_exec(
                &self.container_id,
                bollard::exec::CreateExecOptions {
                    env,
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(vec![
                        "reproducer".to_string(),
                        "--output-dir".to_string(),
                        "/workdir/reproduced_solutions".to_string(),
                        "/workdir/config.yaml".to_string(),
                        "workspace/solutions".to_string(),
                        self.params.harness_name.clone(),
                    ]),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| format!("Could not create reproduction exec: {}", e))?
            .id;

        if let bollard::exec::StartExecResults::Attached { output, .. } = self
            .docker
            .start_exec(
                &exec,
                Some(bollard::exec::StartExecOptions {
                    detach: false,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| format!("Could not start repro exec: {}", e))?
        {
            output.count().await;
        }

        Ok(())
    }
}

impl Environment for DockerEnv {
    async fn get_id(&self) -> String {
        self.container_id.clone()
    }

    async fn get_stats(&self) -> Result<FuzzerStats, String> {
        let stats_tar = self
            .download_tar(format!("{}/stats.yaml", ENSEMBLE_DIR))
            .await?;

        let mut tarball = tar::Archive::new(stats_tar.as_slice());

        // Expect the first entry in the tarball to be the stats file.
        if let Some(entry) = tarball
            .entries()
            .map_err(|e| format!("Could not get entries from fuzzer stats tarball: {}", e))?
            .next()
        {
            let mut stats_str = String::new();
            entry
                .map_err(|e| format!("Entry was not Ok: {}", e))?
                .read_to_string(&mut stats_str)
                .map_err(|e| format!("Could not read stats to string: {}", e))?;

            if let Ok(stats) = serde_yaml::from_str(&stats_str) {
                return Ok(stats);
            }
        }

        Err(String::from("No entries in downloaded tar"))
    }

    async fn get_solutions(&self) -> Result<Vec<Solution>, String> {
        self.reproduce_solutions().await?;

        let solution_tar_bytes = self
            .download_tar(String::from("/workdir/reproduced_solutions"))
            .await?;

        let mut solutions = Vec::new();
        let mut archive = tar::Archive::new(solution_tar_bytes.as_slice());
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            if entry.header().entry_type().is_dir() {
                continue;
            }

            if let Ok(solution) = serde_yaml::from_reader(entry) {
                let solution: ReproducedSolution = solution;
                let trace = String::from_utf8(solution.trace).unwrap();

                match solution.code {
                    78 => solutions.push(Solution::from_timeout(solution.input, trace)),
                    71 => {
                        solutions.push(Solution::from_differential_solution(solution.input, trace))
                    }
                    _ => solutions.push(Solution::from_crash(solution.input, trace)),
                }
            }
        }

        log::trace!(
            "Downloaded {} solutions from docker env ({})",
            solutions.len(),
            &self.container_id[0..16]
        );

        Ok(solutions)
    }

    async fn get_corpus(&self, minimize: bool) -> Result<Vec<u8>, String> {
        if minimize {
            return self
                .download_tar(format!("{}/min_corpus/", ENSEMBLE_DIR))
                .await;
        }

        self.download_tar(format!("{}/corpus/", ENSEMBLE_DIR)).await
    }

    async fn get_covered_files(&self) -> Result<Vec<String>, String> {
        let coverage_summary_tar = self
            .download_tar(String::from("/workdir/coverage-summary.json"))
            .await?;

        let mut tarball = tar::Archive::new(coverage_summary_tar.as_slice());

        // Expect the first entry in the tarball to be the summary file.
        if let Some(entry) = tarball
            .entries()
            .map_err(|e| format!("Could not get entries from coverage summary tarball: {}", e))?
            .next()
        {
            let mut stats_str = String::new();
            entry
                .map_err(|e| format!("Entry was not Ok: {}", e))?
                .read_to_string(&mut stats_str)
                .map_err(|e| format!("Could not read stats to string: {}", e))?;

            let values = serde_json::from_str::<serde_json::Value>(&stats_str)
                .map_err(|e| format!("Could not deser json: {}", e))?;

            let mut file_names = Vec::new();
            for file_obj in values["data"][0]["files"].as_array().unwrap().iter() {
                if file_obj["summary"]["lines"]["covered"].as_i64().unwrap() > 0 {
                    let path = PathBuf::from(file_obj["filename"].as_str().unwrap());
                    // Pop off the first three components
                    let mut components = path.components();
                    components.next(); // root folder
                    components.next(); // workdir folder
                    components.next(); // project folder

                    file_names.push(components.as_path().to_str().unwrap().to_string());
                }
            }

            return Ok(file_names);
        }

        Err(String::from("No entries in downloaded tar"))
    }

    async fn get_coverage_report(&self) -> Result<Vec<u8>, String> {
        self.download_tar(String::from("/workdir/coverage_report"))
            .await
    }

    async fn upload_initial_corpus(&self, corpus: Vec<u8>) -> Result<(), String> {
        let options = Some(bollard::container::UploadToContainerOptions {
            path: "/workdir/workspace/corpus",
            ..Default::default()
        });

        self.docker
            .upload_to_container(&self.container_id, options, corpus.into())
            .await
            .map_err(|e| format!("Could not upload initial corpus: {:?}", e))?;

        Ok(())
    }

    async fn shutdown(&mut self) -> bool {
        let default_kill_timeout = 5;
        let kill_timeout =
            std::env::var("FUZZOR_KILL_TIMEOUT").map_or(default_kill_timeout, |val| {
                val.parse()
                    .expect("FUZZOR_KILL_TIMEOUT should be a value in seconds")
            });

        if let Err(err) = self
            .docker
            .stop_container(
                &self.container_id,
                Some(bollard::container::StopContainerOptions { t: kill_timeout }),
            )
            .await
        {
            log::error!("Failed to stop docker container: {}", err);
            return false;
        }

        if std::env::var("FUZZOR_DONT_REMOVE_CONTAINERS").is_err() {
            if let Err(err) = self
                .docker
                .remove_container(
                    &self.container_id,
                    Some(bollard::container::RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
            {
                log::error!("Failed to remove docker container: {}", err);
            }
        }

        true
    }

    async fn start(&mut self) -> Result<(), String> {
        self.docker
            .start_container::<String>(&self.container_id, None)
            .await
            .map_err(|e| format!("Could not start env: {:?}", e))?;

        log::trace!("Started docker env, container id={}", &self.container_id);
        Ok(())
    }

    async fn ping(&self) -> Result<bool, String> {
        self.docker
            .ping()
            .await
            .map_err(|e| format!("daemon ping error: {}", e))?;

        let inspection = self
            .docker
            .inspect_container(&self.container_id, None)
            .await
            .map_err(|e| format!("ping error: {}", e))?;

        Ok(inspection.state.unwrap().status.unwrap()
            == bollard::models::ContainerStateStatusEnum::RUNNING)
    }
}

#[derive(Clone)]
pub struct DockerEnvAllocator {
    cores: Cores,
}

impl DockerEnvAllocator {
    pub fn new(cores: Cores) -> Self {
        Self { cores }
    }
}

impl EnvironmentAllocator<DockerEnv> for DockerEnvAllocator {
    async fn alloc(
        &mut self,
        opts: EnvironmentParams,
    ) -> Result<DockerEnv, EnvironmentAllocationError> {
        // Wait until cores become available
        let cores = self.cores.take_many(opts.cores as u32).await;

        Ok(DockerEnv::new(cores, opts).await)
    }

    async fn free(&mut self, mut env: DockerEnv) -> bool {
        env.shutdown().await;
        self.cores
            .add_many(env.cores.drain(..).collect::<Vec<_>>())
            .await;
        true
    }
}
