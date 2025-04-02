use fuzzor::revisions::{Revision, RevisionTracker};

use async_trait;
use octocrab::{
    models::repos::{Object, Ref},
    params::repos::Reference::Branch,
};
use tokio::time;

#[derive(Clone)]
pub struct GitHubRevision {
    // Commit hash for the previous git revision
    previous_head: Option<String>,
    // Commit hash for the git revision
    head: String,
    // List of files changed in the revision
    files: Vec<String>,
}

impl Revision for GitHubRevision {
    fn previous_commit_hash(&self) -> Option<&str> {
        self.previous_head.as_deref().clone()
    }
    fn commit_hash(&self) -> &str {
        &self.head
    }
    fn modified_files(&self) -> &[String] {
        &self.files
    }

    fn new(
        commit_hash: String,
        previous_commit_hash: Option<String>,
        modified_files: Vec<String>,
    ) -> Self {
        Self {
            head: commit_hash,
            previous_head: previous_commit_hash,
            files: modified_files,
        }
    }
}

pub enum GithubRevisionSource {
    Branch(String),
    PullRequest(u64),
}

pub struct GitHubRepository {
    pub owner: String,
    pub repo: String,
}

/// GitHubRevisionTracker tracks software revisions hosted in GitHub repositories.
pub struct GitHubRevisionTracker {
    source: (GitHubRepository, GithubRevisionSource),
    github: octocrab::Octocrab,

    interval: time::Interval,

    resolve_source_cache: Option<(String, String, String)>,
}

impl GitHubRevisionTracker {
    pub fn new(access_token: String, repo: GitHubRepository, source: GithubRevisionSource) -> Self {
        let default_interval_seconds = time::Duration::from_secs(60 * 60 * 12); // 12h
        let interval = std::env::var("FUZZOR_GH_TRACK_INTERVAL")
            .map(|v| {
                v.parse()
                    .expect("FUZZOR_GH_TRACK_INTERVAL should be a value in seconds")
            })
            .map_or(default_interval_seconds, time::Duration::from_secs);

        GitHubRevisionTracker {
            source: (repo, source),
            github: octocrab::Octocrab::builder()
                .user_access_token(access_token)
                .build()
                .unwrap(),
            interval: time::interval(interval),
            resolve_source_cache: None,
        }
    }

    pub fn source(&self) -> &(GitHubRepository, GithubRevisionSource) {
        &self.source
    }

    pub async fn lookup_branch(&mut self) -> String {
        self.resolve_source().await.2
    }

    async fn resolve_source(&mut self) -> (String, String, String) {
        if self.resolve_source_cache.is_none() {
            // Do the actual lookup (GitHub API call) and populate the cache only on the first
            // call.
            self.resolve_source_cache = Some(self.inner_resolve_source().await);
        }

        self.resolve_source_cache
            .clone()
            .expect("Cache must be populated here")
    }
    async fn inner_resolve_source(&self) -> (String, String, String) {
        return match &self.source.1 {
            GithubRevisionSource::Branch(name) => (
                self.source.0.owner.clone(),
                self.source.0.repo.clone(),
                name.clone(),
            ),

            // If we are tracking a pull request, we'll need to fetch info about the pull request
            // origin (i.e. owner, repo and branch).
            GithubRevisionSource::PullRequest(number) => {
                if let Ok(pr) = self
                    .github
                    .pulls(&self.source.0.owner, &self.source.0.repo)
                    .get(*number)
                    .await
                {
                    let repo = pr.head.repo.as_ref().unwrap(); // TODO don't unwrap here

                    (
                        repo.owner.as_ref().unwrap().login.clone(),
                        repo.name.clone(),
                        pr.head.ref_field.clone(),
                    );
                };

                (String::new(), String::new(), String::new()) // TODO wtf is this
            }
        };
    }

    async fn get_pull_request_files(&self, repo: &GitHubRepository, number: u64) -> Vec<String> {
        if let Ok(result) = self
            .github
            .pulls(&repo.owner, &repo.repo)
            .list_files(number)
            .await
        {
            return result
                .items
                .iter()
                .map(|d| d.filename.clone())
                .collect::<Vec<String>>();
        } else {
            log::warn!(
                "No files in PR diff (repo={}/{}, pr={})",
                &repo.owner,
                &repo.repo,
                number
            );

            return Vec::new();
        };
    }

    async fn get_branch_files(
        &self,
        repo: &GitHubRepository,
        branch: &str,
        base: &str,
        head: &str,
    ) -> Vec<String> {
        let commit_comparison = self
            .github
            .commits(&repo.owner, &repo.repo)
            .compare(base, head)
            .per_page(100)
            .send()
            .await;

        match commit_comparison {
            Ok(comparison) => {
                if let Some(files) = comparison.files {
                    return files.iter().map(|diff| diff.filename.clone()).collect();
                }

                log::info!(
                    "No files in comparison for new revision (repo={}/{}, branch={})",
                    &repo.owner,
                    &repo.repo,
                    branch,
                );

                Vec::new()
            }

            Err(err) => {
                log::error!(
                    "Could not fetch changed files for new revision (repo={}/{}, branch={}): {}",
                    &repo.owner,
                    &repo.repo,
                    branch,
                    err
                );

                Vec::new()
            }
        }
    }

    async fn get_modified_files(&self, base: &str, head: &str) -> Vec<String> {
        match &self.source.1 {
            GithubRevisionSource::Branch(name) => {
                self.get_branch_files(&self.source.0, &name, base, head)
                    .await
            }
            GithubRevisionSource::PullRequest(number) => {
                self.get_pull_request_files(&self.source.0, *number).await
            }
        }
    }

    async fn inner_track(
        &mut self,
        owner: &str,
        repo: &str,
        branch: &str,
        current: &Option<GitHubRevision>,
    ) -> Option<GitHubRevision> {
        match self
            .github
            .repos(owner, repo)
            .get_ref(&Branch(branch.to_string()))
            .await
        {
            Ok(Ref {
                object: Object::Commit { sha, .. },
                ..
            }) => {
                if current.as_ref().map_or(true, |rev| rev.head != sha) {
                    log::info!(
                        "New GitHub revision for repo={}/{} branch={} rev={}",
                        &owner,
                        &repo,
                        &branch,
                        &sha[..8]
                    );

                    let previous_head = current
                        .as_ref()
                        .map_or(None, |rev| Some(rev.commit_hash().to_string()));

                    let mut modified_files = Vec::new();
                    if let Some(previous_head) = &previous_head {
                        modified_files = self.get_modified_files(previous_head, &sha).await;
                    }

                    return Some(GitHubRevision {
                        head: sha,
                        previous_head,
                        files: modified_files,
                    });
                }
            }
            Ok(_) => {}
            Err(err) => {
                if let octocrab::Error::GitHub { source, .. } = err {
                    log::warn!("Could not query GitHub api: {}", source)
                }
            }
        }

        None
    }
}

#[async_trait::async_trait]
impl RevisionTracker<GitHubRevision> for GitHubRevisionTracker {
    async fn track(&mut self, current: Option<GitHubRevision>) -> GitHubRevision {
        let (owner, repo, branch) = self.resolve_source().await;

        // Poll the GithubApi every now and then until a new revision is detected and returned.
        loop {
            self.interval.tick().await;

            if let Some(revision) = self.inner_track(&owner, &repo, &branch, &current).await {
                return revision;
            }
        }
    }
}
