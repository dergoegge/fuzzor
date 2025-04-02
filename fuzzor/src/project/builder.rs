use std::collections::HashSet;

use super::description::ProjectDescription;
use crate::revisions::Revision;

#[derive(Debug, Clone)]
pub enum ProjectBuildFailure {
    Build { log: std::path::PathBuf },
    Other { msg: String },
}

#[async_trait::async_trait]
pub trait ProjectBuilder<R, D>
where
    R: Revision,
    D: ProjectDescription,
{
    async fn build(
        &mut self,
        description: D,
        revision: R,
    ) -> Result<ProjectBuild<R>, ProjectBuildFailure>;
}

#[derive(Debug)]
pub struct ProjectBuild<R> {
    harnesses: HashSet<String>,
    revision: R,
}

impl<R: Revision> ProjectBuild<R> {
    pub fn new(harnesses: HashSet<String>, revision: R) -> Self {
        Self {
            harnesses,
            revision,
        }
    }

    pub fn harnesses(&self) -> &HashSet<String> {
        &self.harnesses
    }

    pub fn revision(&self) -> &R {
        &self.revision
    }
}
