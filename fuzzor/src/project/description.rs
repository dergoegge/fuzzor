use std::fs;
use std::path::PathBuf;


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
        self.tarball.clone()
    }

    fn config(&self) -> ProjectConfig {
        self.config.clone()
    }
}
