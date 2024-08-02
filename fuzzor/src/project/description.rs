use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use fuzzor_infra::ProjectConfig;

pub trait ProjectDescription {
    /// Retrieve a tarball of all required data (sources, config, etc.) for a project
    fn tarball(&self) -> Vec<u8>;
    /// Get the project config
    fn config(&self) -> ProjectConfig;
}

const CONFIG_FILE: &str = "config.yaml";
const DOCKER_FILE: &str = "Dockerfile";

/// On-disk implementation of ProjectDescription for docker builds represented as a folder.
#[derive(Clone)]
pub struct ProjectFolder {
    path: PathBuf,
}

impl ProjectFolder {
    /// Create a new ProjectFolder given a path.
    ///
    /// Folder must contain at least two files: "Dockerfile" and "config.yaml".
    pub fn new(path: PathBuf) -> Result<Self, &'static str> {
        if !path.is_dir() {
            return Err("Project path has to be a directory");
        }

        let expected_files = Vec::from([CONFIG_FILE, DOCKER_FILE]);
        for file in expected_files {
            if !path.join(file).is_file() {
                log::error!("File not found: {}", file);
                return Err("One or more expected files are missing from the project directory");
            }
        }

        Ok(Self { path })
    }
}

impl ProjectDescription for ProjectFolder {
    fn tarball(&self) -> Vec<u8> {
        // Tar everything in the folder
        let mut tar = tar::Builder::new(Vec::new());
        tar.append_dir_all(".", &self.path).unwrap();
        tar.into_inner().unwrap()
    }

    fn config(&self) -> ProjectConfig {
        // Read the config file and parse it into a ProjectConfig
        let config_path = self.path.join(CONFIG_FILE);
        let config = fs::read_to_string(config_path).expect("Config file has to exist");
        serde_yaml::from_str(&config).expect("Config file should be properly formatted")
    }
}

#[derive(Clone)]
pub struct InMemoryProjectFolder {
    config: ProjectConfig,
    tarball: Vec<u8>,
}

impl InMemoryProjectFolder {
    pub fn from_folder(folder: ProjectFolder) -> Self {
        Self {
            config: folder.config(),
            tarball: folder.tarball(),
        }
    }

    pub fn config_mut(&mut self) -> &mut ProjectConfig {
        &mut self.config
    }
}

impl ProjectDescription for InMemoryProjectFolder {
    fn tarball(&self) -> Vec<u8> {
        // Replace the config.yaml in `self.tarball` with `self.config`, so that any changes made
        // to it are reflected in image builds.

        let mut tar_builder = tar::Builder::new(Vec::new());

        // Add the config.yaml file
        let mut config_yaml = Vec::new();
        serde_yaml::to_writer(&mut config_yaml, &self.config).unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_size(config_yaml.len() as u64);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "config.yaml", &config_yaml[..])
            .unwrap();

        // Add other files from the original tarball
        let mut ar = tar::Archive::new(&self.tarball[..]);
        for entry in ar.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap() != Path::new("config.yaml") {
                let mut file_contents = Vec::new();
                entry.read_to_end(&mut file_contents).unwrap();
                let mut header = entry.header().clone();
                header.set_cksum();
                tar_builder
                    .append_data(
                        &mut header,
                        entry.path().unwrap().as_ref(),
                        &file_contents[..],
                    )
                    .unwrap();
            }
        }

        tar_builder.into_inner().unwrap()
    }

    fn config(&self) -> ProjectConfig {
        self.config.clone()
    }
}
