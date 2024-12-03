use std::collections::{HashMap, HashSet};

use fuzzor::{
    env::ResourcePool,
    project::{
        builder::{ProjectBuild, ProjectBuilder},
        description::ProjectDescription,
    },
    revisions::Revision,
};

use futures_util::StreamExt;

use crate::env::DockerMachine;

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

    let exec = docker
        .create_exec(
            &id,
            bollard::exec::CreateExecOptions {
                attach_stdout: Some(true),
                cmd: Some(vec!["ls", "/workdir/out/libfuzzer"]),
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
    ) -> Result<(String, String), String> {
        let project_config = descr.config();
        let mut buildargs = HashMap::new();

        buildargs.insert(String::from("OWNER"), project_config.owner);
        buildargs.insert(String::from("REPO"), project_config.repo);
        if let Some(branch) = project_config.branch {
            buildargs.insert(String::from("BRANCH"), branch);
        }
        buildargs.insert(String::from("REVISION"), revision.to_string());

        // Create the image tag as "<registry>/<name>:latest" if a registry is configured or
        // "<name>:latest" if not.
        let tag = self.registry.clone().map_or(
            format!("fuzzor-{}:latest", project_config.name),
            |registry| format!("{}/fuzzor-{}:latest", registry, project_config.name),
        );

        // Convert the cpu core vector to a string representation for docker.
        //
        // Example: vec![1, 2, 3] becomes "1,2,3".
        let cpusetcpus = cores
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let image_options = bollard::image::BuildImageOptions {
            t: tag.clone(),
            dockerfile: "Dockerfile".to_string(),
            version: bollard::image::BuilderVersion::BuilderBuildKit,
            session: Some(tag.clone()),
            buildargs,
            cpusetcpus,
            // do not use "q: true", it supresses the buildinfo with the image id below
            nocache: std::env::var("FUZZOR_DOCKER_NOCACHE").is_ok(),
            ..Default::default()
        };

        let mut build_stream =
            docker.build_image(image_options, None, Some(descr.tarball().into()));

        while let Some(result) = build_stream.next().await {
            match result {
                Ok(bollard::models::BuildInfo {
                    aux: Some(bollard::models::BuildInfoAux::Default(image_id)),
                    ..
                }) => return Ok((image_id.id.unwrap(), tag)),
                Ok(bollard::models::BuildInfo {
                    stream: Some(msg), ..
                }) => log::trace!("{}", msg.trim_end()),
                Ok(entry) => log::trace!("image build entry: {:?}", entry),
                Err(err) => {
                    log::error!("Could not build image '{}': {:?}", &tag, err);
                    return Err(String::from("Could not build image"));
                }
            }
        }

        Err(String::from("No items in build stream"))
    }
}

impl<R, PD> ProjectBuilder<R, PD> for DockerBuilder
where
    R: Revision + Send,
    PD: ProjectDescription + Clone + Send + 'static,
{
    async fn build(&mut self, folder: PD, revision: R) -> Result<ProjectBuild<R>, String> {
        let machine = self.machines.take_one().await;

        let docker = bollard::Docker::connect_with_http(
            &machine.daemon_addr,
            120,
            &bollard::ClientVersion {
                minor_version: 1,
                major_version: 44,
            },
        )
        .map_err(|e| format!("Could not connect to docker daemon: {}", e))?;
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
        let (image_id, tag) = build_result?;

        if self.registry.is_some() {
            log::info!("Pushing image '{}' to registry", &tag);
            // Push the image to the configured registry
            let push_options = Some(bollard::image::PushImageOptions { tag: "latest" });
            let mut push_stream = docker.push_image(&tag, push_options, None);

            while let Some(msg) = push_stream.next().await {
                match msg {
                    Err(err) => {
                        log::error!("Could not push image '{}' to registry: {:?}", &tag, err);
                        return Err(String::from("Could not push image"));
                    }
                    Ok(entry) => log::trace!("image push stream: {:?}", entry),
                }
            }
        }

        log::info!(
            "Successfully build and pushed image '{}' with id={}",
            &tag,
            &image_id
        );

        let mut harnesses = get_harness_set(&docker, &image_id).await?;

        if config.fuzz_env_var.is_some() {
            harnesses.remove("fuzz");
        }

        log::trace!("Harnesses found in image '{}': {:?}", &tag, &harnesses);

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
