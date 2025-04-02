use std::collections::{HashMap, HashSet};
use std::io::Write;

use fuzzor::project::builder::ProjectBuildFailure;
use fuzzor::{
    env::ResourcePool,
    project::{
        builder::{ProjectBuild, ProjectBuilder},
        description::ProjectDescription,
    },
    revisions::Revision,
};
use fuzzor_infra::{FuzzEngine, ProjectConfig, Sanitizer};

use futures_util::StreamExt;

use crate::env::DockerMachine;
use tempfile::NamedTempFile;

pub struct DockerBuilder {
    machines: ResourcePool<DockerMachine>,
    registry: Option<String>,
}

impl DockerBuilder {
    /// Create a new DockerBuilder
    pub fn new(machines: ResourcePool<DockerMachine>) -> Self {
        Self {
            machines,
            registry: None,
        }
    }

    /// Create a new DockerBuilder that pushes images to a registry
    pub fn with_registry(machines: ResourcePool<DockerMachine>, registry: String) -> Self {
        Self {
            machines,
            registry: Some(registry),
        }
    }
}

/// Get the harness list from the project image.
///
/// This is achieved by creating a container and listing all entries in the harness directory.
async fn get_harness_set(
    docker: &bollard::Docker,
    project_config: &ProjectConfig,
    image_id: &str,
) -> Result<HashSet<String>, String> {
    let config = bollard::container::Config {
        image: Some(image_id),
        tty: Some(true),
        ..Default::default()
    };
    let id = docker
        .create_container::<&str, &str>(None, config)
        .await
        .map_err(|e| format!("Could not create container: {}", e))?
        .id;

    log::trace!("Created container id={}", &id);

    docker
        .start_container::<String>(&id, None)
        .await
        .map_err(|e| format!("Could not create exec in container: {}", e))?;

    let engines_and_sanitizers = [
        (FuzzEngine::LibFuzzer, Sanitizer::None),
        (FuzzEngine::AflPlusPlus, Sanitizer::None),
        (FuzzEngine::AflPlusPlusNyx, Sanitizer::Address),
        (FuzzEngine::NativeGo, Sanitizer::None),
    ];

    let harness_dir = engines_and_sanitizers
        .iter()
        .find_map(|(engine, sanitizer)| {
            fuzzor_infra::get_harness_dir(engine, sanitizer, project_config)
        })
        .ok_or_else(|| String::from("Could not find harness directory"))?;

    let exec = docker
        .create_exec(
            &id,
            bollard::exec::CreateExecOptions {
                attach_stdout: Some(true),
                cmd: Some(vec!["ls", &format!("/workdir/out/{}", harness_dir)]),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| format!("Could not create exec in container: {}", e))?
        .id;

    let harnesses = if let bollard::exec::StartExecResults::Attached { mut output, .. } = docker
        .start_exec(&exec, None)
        .await
        .map_err(|e| format!("Could not start exec in container: {}", e))?
    {
        let mut harnesses: HashSet<String> = HashSet::new();
        while let Some(Ok(msg)) = output.next().await {
            harnesses.extend(msg.to_string().lines().map(String::from));
        }

        harnesses
    } else {
        HashSet::new()
    };

    docker
        .remove_container(
            &id,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| format!("Could not remove container: {}", e))?;

    Ok(harnesses)
}

impl DockerBuilder {
    async fn build_image<PD: ProjectDescription>(
        &self,
        docker: &bollard::Docker,
        cores: &[u64],
        descr: PD,
        revision: &str,
    ) -> Result<(String, String), ProjectBuildFailure> {
        let project_config = descr.config();
        let mut buildargs = HashMap::new();

        buildargs.insert(String::from("OWNER"), project_config.owner);
        buildargs.insert(String::from("REPO"), project_config.repo);
        if let Some(branch) = project_config.branch {
            buildargs.insert(String::from("BRANCH"), branch);
        }
        buildargs.insert(String::from("REVISION"), revision.to_string());

        // Create the image name as "fuzzor-<prj name>" (default tag will be "latest", set by
        // bollard)
        let image_name = format!("fuzzor-{}", project_config.name);

        // Convert the cpu core vector to a string representation for docker.
        //
        // Example: vec![1, 2, 3] becomes "1,2,3".
        let cpusetcpus = cores
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let image_options = bollard::image::BuildImageOptions {
            t: image_name.clone(),
            dockerfile: "Dockerfile".to_string(),
            version: bollard::image::BuilderVersion::BuilderBuildKit,
            session: Some(image_name.clone()),
            buildargs,
            cpusetcpus,
            // do not use "q: true", it supresses the buildinfo with the image id below
            nocache: std::env::var("FUZZOR_DOCKER_NOCACHE").is_ok(),
            ..Default::default()
        };

        // Create a named temporary file to store logs
        let mut temp_log_file = NamedTempFile::new().map_err(|e| ProjectBuildFailure::Other {
            msg: format!("Failed to create temp log file: {}", e),
        })?;
        log::debug!(
            "Created temporary build log file at: {:?}",
            temp_log_file.path()
        );

        {
            let file = temp_log_file.as_file_mut();

            let mut build_stream =
                docker.build_image(image_options, None, Some(descr.tarball().into()));

            while let Some(result) = build_stream.next().await {
                match result {
                    Ok(bollard::models::BuildInfo {
                        aux: Some(bollard::models::BuildInfoAux::Default(image_id)),
                        ..
                    }) => {
                        // Build succeeded, flush any remaining buffered logs
                        if let Err(e) = file.flush() {
                            log::warn!("Failed to flush temp log file on success: {}", e);
                        }
                        // Temp file will be automatically deleted when `temp_log_file` goes out of scope
                        return Ok((image_id.id.unwrap_or_default(), image_name));
                    }
                    Ok(bollard::models::BuildInfo {
                        stream: Some(msg), ..
                    }) => {
                        let log_line = msg.trim_end();
                        log::trace!("Stream log: {}", log_line);
                        // Write bytes to file, add newline
                        if let Err(e) = writeln!(file, "{}", log_line) {
                            log::error!("Failed to write stream log to temp file: {}", e);
                        }
                    }
                    Ok(bollard::models::BuildInfo {
                        aux: Some(bollard::models::BuildInfoAux::BuildKit(status_response)),
                        ..
                    }) => {
                        for log_entry in status_response.logs {
                            log::trace!(
                                "BuildKit log chunk: {}",
                                String::from_utf8_lossy(&log_entry.msg).trim_end()
                            );
                            // Write raw bytes directly to the file
                            if let Err(e) = file.write_all(&log_entry.msg) {
                                log::error!(
                                    "Failed to write BuildKit log chunk to temp file: {}",
                                    e
                                );
                            }
                        }
                    }
                    Ok(entry) => log::trace!("Unhandled image build entry: {:?}", entry),
                    Err(err) => {
                        let error_msg =
                            format!("Could not build image '{}': {:?}", &image_name, err);
                        log::error!("{}", &error_msg);
                        // Ensure logs are written before persisting
                        if let Err(e) = file.flush() {
                            log::warn!("Failed to flush temp log file on error: {}", e);
                        }
                        // Persist the temp file and return its path
                        let path = temp_log_file.path().to_path_buf();
                        match temp_log_file.keep() {
                            Ok((_file, path)) => {
                                return Err(ProjectBuildFailure::Build { log: path })
                            }
                            Err(e) => {
                                log::error!(
                                    "Failed to persist temp log file '{}': {}",
                                    path.display(),
                                    e.error
                                );
                                return Err(ProjectBuildFailure::Build { log: path });
                            }
                        }
                    }
                }
            }
        }

        // Ensure logs are written before persisting
        if let Err(e) = temp_log_file.flush() {
            log::warn!(
                "Failed to flush temp log file on unexpected stream end: {}",
                e
            );
        }
        // Persist the temp file and return its path
        let path = temp_log_file.path().to_path_buf();
        match temp_log_file.keep() {
            Ok((_file, path)) => Err(ProjectBuildFailure::Build { log: path }),
            Err(e) => {
                log::error!(
                    "Failed to persist temp log file '{}': {}",
                    path.display(),
                    e.error
                );
                Err(ProjectBuildFailure::Build { log: path })
            }
        }
    }
}

#[async_trait::async_trait]
impl<R, PD> ProjectBuilder<R, PD> for DockerBuilder
where
    R: Revision + Send + 'static,
    PD: ProjectDescription + Clone + Send + 'static,
{
    async fn build(
        &mut self,
        folder: PD,
        revision: R,
    ) -> Result<ProjectBuild<R>, ProjectBuildFailure> {
        let machine = self.machines.take_one().await;

        let docker = bollard::Docker::connect_with_http(
            &machine.daemon_addr,
            120,
            &bollard::ClientVersion {
                minor_version: 1,
                major_version: 44,
            },
        )
        .map_err(|e| ProjectBuildFailure::Other {
            msg: format!("Could not connect to docker daemon: {}", e),
        })?;
        // TODO If we return here due to an error, we won't add the machine back to the pool

        let config = folder.config();

        log::info!("Building image for project '{}'", config.name);
        let build_result = self
            .build_image(
                &docker,
                &machine.cores,
                folder.clone(),
                revision.commit_hash(),
            )
            .await;

        self.machines.add_one(machine).await;

        // This has to happen after freeing the machine.
        let (image_id, local_image_name) = match build_result {
            Ok(result) => result,
            Err(failure) => {
                return Err(failure);
            }
        };

        if let Some(registry) = &self.registry {
            let remote_image_name = format!("{}/{}", registry, local_image_name);
            if let Err(err) = docker
                .tag_image(
                    &local_image_name,
                    Some(bollard::image::TagImageOptions {
                        repo: remote_image_name.as_str(),
                        tag: revision.commit_hash(),
                    }),
                )
                .await
            {
                log::error!("Failed to tag image: {}", err.to_string());
                return Err(ProjectBuildFailure::Other {
                    msg: "Failed to tag image".to_string(),
                });
            }

            log::info!(
                "Pushing image '{}:{}' to registry",
                &remote_image_name,
                revision.commit_hash()
            );

            // Push the image to the configured registry
            let push_options = Some(bollard::image::PushImageOptions {
                tag: revision.commit_hash(),
            });
            let mut push_stream = docker.push_image(&remote_image_name, push_options, None);

            while let Some(msg) = push_stream.next().await {
                match msg {
                    Err(err) => {
                        log::error!(
                            "Could not push image '{}' to registry: {:?}",
                            &remote_image_name,
                            err
                        );
                        return Err(ProjectBuildFailure::Other {
                            msg: String::from("Could not push image"),
                        });
                    }
                    Ok(entry) => log::trace!("image push stream: {:?}", entry),
                }
            }

            // Images (unused, untagged) are pruned below to conserve disk space. Remove (locally) the image
            // that was just pushed, so it'll be pruned when a newer revision is pushed.
            let _ = docker
                .remove_image(
                    &format!("{}:{}", remote_image_name, revision.commit_hash()),
                    None,
                    None,
                )
                .await;
        }

        log::info!(
            "Successfully build and pushed local image '{}' with id={}",
            &local_image_name,
            &image_id
        );

        let mut harnesses = get_harness_set(&docker, &config, &image_id)
            .await
            .map_err(|e| ProjectBuildFailure::Other { msg: e })?;

        if config.fuzz_env_var.is_some() {
            harnesses.remove("fuzz");
        }

        log::trace!(
            "Harnesses found in image '{}': {:?}",
            &local_image_name,
            &harnesses
        );

        // Prune unused and untagged images
        let mut filters = HashMap::new();
        filters.insert("dangling", vec!["1"]);
        match docker
            .prune_images(Some(bollard::image::PruneImagesOptions { filters }))
            .await
        {
            Ok(prune_result) => {
                log::info!(
                    "Pruned {} images and reclaimed {} GiB of disk space!",
                    prune_result.images_deleted.map_or(0, |imgs| imgs.len()),
                    prune_result.space_reclaimed.unwrap_or(0) / (1024 * 1024 * 1024),
                );
            }
            Err(e) => {
                log::warn!("Could not prune dangling images: {:?}", e);
            }
        };

        Ok(ProjectBuild::new(harnesses, revision))
    }
}
