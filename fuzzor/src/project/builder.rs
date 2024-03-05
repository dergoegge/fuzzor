use futures_util::StreamExt;
use std::collections::{HashMap, HashSet};
use std::future::Future;

use super::description::*;
use super::revision_tracker::Revision;
use crate::env::Cores;

pub trait ProjectBuilder<R, D>
where
    R: Revision,
    D: ProjectDescription,
{
    fn build(
        &mut self,
        description: D,
        revision: R,
    ) -> impl Future<Output = Result<ProjectBuild<R>, String>> + Send;
}

#[derive(Debug)]
pub struct ProjectBuild<R> {
    harnesses: HashSet<String>,
    revision: R,
}

impl<R: Revision> ProjectBuild<R> {
    pub fn harnesses(&self) -> &HashSet<String> {
        &self.harnesses
    }

    pub fn revision(&self) -> &R {
        &self.revision
    }
}

pub struct DockerBuilder {
    cores: Cores,
    num_builder_cores: usize,
    registry: Option<String>,
}

impl DockerBuilder {
    /// Create a new DockerBuilder.
    ///
    /// If provided, images created are pushed to the provided registry.
    pub fn new(cores: Cores, num_builder_cores: usize, registry: Option<String>) -> Self {
        Self {
            cores,
            num_builder_cores,
            registry,
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
        let docker = bollard::Docker::connect_with_socket_defaults()
            .map_err(|e| format!("Could not connect to docker daemon: {}", e))?;

        let config = folder.config();

        let cores = self.cores.take_many(self.num_builder_cores as u32).await;
        log::info!("Building image for project '{}'", config.name);
        let build_result = self
            .build_image(&docker, &cores, folder.clone(), revision.commit_hash())
            .await;
        self.cores.add_many(cores).await;

        // This has to happen after freeing the cores.
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

        Ok(ProjectBuild {
            harnesses,
            revision,
        })
    }
}
