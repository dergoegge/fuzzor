use std::collections::HashMap;
use std::io::Read;
use std::str::FromStr;

use fuzzor::{
    env::{Environment, EnvironmentAllocator, EnvironmentParams, ResourcePool},
    solutions::Solution,
};

use async_trait::async_trait;
use futures_util::stream::StreamExt;
use fuzzor_infra::{FuzzerStats, ReproducedSolution, SolutionCause};
use serde::{Deserialize, Serialize};

pub const ENSEMBLE_DIR: &str = "/workdir/workspace";
pub const LIBFUZZER_STACK_TRACE_SUFFIX: &str = ".libfuzzer.crash";

/// Connect to Docker daemon, handling both Unix sockets and HTTP URLs
pub fn connect_to_docker(daemon_addr: &str) -> Result<bollard::Docker, String> {
    let client_version = bollard::ClientVersion {
        minor_version: 1,
        major_version: 44,
    };

    if daemon_addr.starts_with("unix://") {
        let socket_path = daemon_addr.strip_prefix("unix://").unwrap();
        bollard::Docker::connect_with_socket(socket_path, 120, &client_version)
            .map_err(|e| format!("Could not connect to docker daemon via socket: {}", e))
    } else {
        bollard::Docker::connect_with_http(daemon_addr, 120, &client_version)
            .map_err(|e| format!("Could not connect to docker daemon via http: {}", e))
    }
}

pub struct DockerEnv {
    docker: bollard::Docker,
    container_id: String,
    machine: DockerMachine,

    params: EnvironmentParams,
}

impl DockerEnv {
    pub async fn new(
        machine: DockerMachine,
        registry: Option<String>,
        params: EnvironmentParams,
    ) -> Self {
        let docker = connect_to_docker(&machine.daemon_addr).unwrap();

        let cpuset_cpus = machine
            .cores
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // Setup a tmpfs with limited size to avoid blowing up the host's disk space.
        let mut tmpfs = HashMap::new();
        tmpfs.insert("/tmp".to_string(), "size=8G".to_string());

        let fuzz_cmd = format!(
            "fuzzer --duration {} --workspace ./workspace ./config.yaml {}",
            (params.duration.as_secs() / 60 / 60),
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

        if let Some(registry) = registry {
            // Pull the image from the registry set by the user and tag it for local use.

            let from_image = format!("{}/{}", &registry, &params.docker_image);
            log::info!("Pulling image='{}' on machine {:?}", from_image, machine);
            let options = Some(bollard::image::CreateImageOptions {
                from_image: from_image.as_str(),
                tag: "latest",
                ..Default::default()
            });

            let mut pull_stream = docker.create_image(options, None, None);

            while let Some(output) = pull_stream.next().await {
                match output {
                    Ok(output) => log::trace!("pull image stream: {:?}", output),
                    Err(e) => log::error!("pull image error: {:?}", e),
                }
            }

            let tag_options = bollard::image::TagImageOptions {
                repo: params.docker_image.as_str(),
                tag: "latest",
            };

            docker
                .tag_image(&from_image, Some(tag_options))
                .await
                .unwrap();
        }

        let mut resource_limits = Vec::new();
        if std::env::var("FUZZOR_DOCKER_NO_STACK_LIMIT").is_err() {
            // Limit the stack size in the env unless FUZZOR_DOCKER_NO_STACK_LIMIT is set.
            resource_limits.push(bollard::models::ResourcesUlimits {
                name: Some("stack".to_string()),
                soft: Some(512 * 1024),
                hard: Some(512 * 1024),
            });
        }

        let mut network_mode = Some("none".to_string());
        if std::env::var("FUZZOR_DOCKER_ENABLE_NETWORK").is_ok() {
            // By default, disable network access in the container.
            network_mode = None;
        }

        let mut config = bollard::container::Config {
            image: Some(params.docker_image.clone()),
            tty: Some(true),
            working_dir: Some(String::from("/workdir")),
            cmd: Some(vec!["/bin/bash".to_string(), "-c".to_string(), full_cmd]),
            host_config: Some(bollard::secret::HostConfig {
                privileged: Some(true), // for performance
                cpuset_cpus: Some(cpuset_cpus),
                tmpfs: Some(tmpfs),
                ulimits: Some(resource_limits),
                network_mode,
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
            machine,
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

    async fn reproduce_solutions(&self, input_solutions: String) -> Result<(), String> {
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
                        input_solutions,
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

    async fn upload_initial_solutions(&self, solutions: Vec<Solution>) -> Result<(), String> {
        if solutions.is_empty() {
            return Ok(());
        }

        let options = Some(bollard::container::UploadToContainerOptions {
            path: "/workdir/workspace/initial_solutions",
            ..Default::default()
        });

        let mut tar = tar::Builder::new(Vec::new());
        for solution in solutions.iter() {
            let mut header = tar::Header::new_gnu();
            header.set_size(solution.input_bytes().len() as u64);
            header.set_cksum();

            tar.append_data(
                &mut header,
                &format!("./{}", solution.id()),
                solution.input_bytes(),
            )
            .unwrap();
        }

        self.docker
            .upload_to_container(
                &self.container_id,
                options,
                tar.into_inner()
                    .map_err(|e| format!("Could not create archive: {}", e))?
                    .into(),
            )
            .await
            .map_err(|e| format!("Could not upload initial corpus: {:?}", e))?;

        Ok(())
    }

    async fn download_reproduced_solutions(&self) -> Result<Vec<Solution>, String> {
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

            match serde_yaml::from_reader::<_, ReproducedSolution>(entry) {
                Ok(solution) => {
                    let trace = String::from_utf8(solution.trace).unwrap();

                    match solution.cause {
                        SolutionCause::Timeout => {
                            solutions.push(Solution::from_timeout(solution.input, trace))
                        }
                        SolutionCause::Differential => solutions
                            .push(Solution::from_differential_solution(solution.input, trace)),
                        _ => solutions.push(Solution::from_crash(solution.input, trace)),
                    }
                }
                Err(e) => {
                    log::error!("Could not deserialize reproduced solution: {}", e);
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
}

#[async_trait]
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
        self.reproduce_solutions("/workdir/workspace/solutions".to_string())
            .await?;

        self.download_reproduced_solutions().await
    }

    async fn reproduce_solutions(&self, solutions: Vec<Solution>) -> Result<Vec<Solution>, String> {
        self.upload_initial_solutions(solutions).await?;

        self.reproduce_solutions("/workdir/workspace/initial_solutions".to_string())
            .await?;

        self.download_reproduced_solutions().await
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
                    // Collect files that have line coverage
                    file_names.push(file_obj["filename"].as_str().unwrap().to_string());
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

    async fn get_coverage_summary(&self) -> Result<Vec<u8>, String> {
        let tar_bytes = self
            .download_tar(String::from("/workdir/coverage-summary.json"))
            .await?;

        let mut tarball = tar::Archive::new(tar_bytes.as_slice());

        if let Some(entry) = tarball
            .entries()
            .map_err(|e| format!("Could not get entries from coverage summary tarball: {}", e))?
            .next()
        {
            let mut summary = Vec::new();
            entry
                .map_err(|e| format!("Entry was not Ok: {}", e))?
                .read_to_end(&mut summary)
                .map_err(|e| format!("Could not read coverage summary: {}", e))?;

            return Ok(summary);
        }

        Err(String::from("No entries in downloaded tar"))
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

fn deserialize_cores<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_cores(&s).map_err(serde::de::Error::custom)
}

fn parse_cores(s: &str) -> Result<Vec<u64>, String> {
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err("Invalid range format".to_string());
        }
        let start = u64::from_str(parts[0]).map_err(|e| e.to_string())?;
        let end = u64::from_str(parts[1]).map_err(|e| e.to_string())?;
        Ok((start..=end).collect())
    } else {
        s.split(',')
            .map(|num| u64::from_str(num.trim()).map_err(|e| e.to_string()))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerMachine {
    #[serde(deserialize_with = "deserialize_cores")]
    pub cores: Vec<u64>,
    pub daemon_addr: String,
}

#[derive(Clone)]
pub struct DockerEnvAllocator {
    machines: ResourcePool<DockerMachine>,
    registry: Option<String>,
}

impl DockerEnvAllocator {
    pub fn new(machines: ResourcePool<DockerMachine>) -> Self {
        Self {
            machines,
            registry: None,
        }
    }

    pub fn with_registry(machines: ResourcePool<DockerMachine>, registry: String) -> Self {
        Self {
            machines,
            registry: Some(registry),
        }
    }
}

#[async_trait]
impl EnvironmentAllocator<DockerEnv> for DockerEnvAllocator {
    async fn alloc(&mut self, opts: EnvironmentParams) -> Result<DockerEnv, String> {
        let machine = self.machines.take_one().await;

        Ok(DockerEnv::new(machine, self.registry.clone(), opts).await)
    }

    async fn free(&mut self, mut env: DockerEnv) -> bool {
        env.shutdown().await;
        self.machines.add_one(env.machine).await;
        true
    }
}
