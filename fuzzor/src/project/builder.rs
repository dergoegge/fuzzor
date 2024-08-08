use std::collections::HashSet;
use std::future::Future;

use super::description::ProjectDescription;
use crate::revisions::Revision;

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
