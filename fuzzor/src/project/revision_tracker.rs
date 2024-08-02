use octocrab::models::repos::{Object, Ref};
use std::future::Future;
use tokio::time;

/// Revision represents a revision of a project's source code
pub trait Revision {
    /// Commit hash of the head for the previous revision. [`None`] if there was no previous
    /// revision.
    fn previous_commit_hash(&self) -> Option<&str>;
    /// Commit hash of the head for this revision
    fn commit_hash(&self) -> &str;
    /// List of files that were changed between this revision and the previous one.
    fn modified_files(&self) -> &[String];
}

/// ProjectRevisionTracker tracks software revisions for a given project.
pub trait ProjectRevisionTracker<R: Revision> {
    /// Resolves into a revision identifier whenever a newer revision becomes available.
    fn track(&mut self, current: Option<R>) -> impl Future<Output = R> + Send;
}

pub struct GitHubPullRequest {
    pub number: u64,
    pub base_owner: String,
    pub base_repo: String,
}

/// GitHubRevisionTracker tracks one branch for a repository hosted on GitHub.
pub struct GitHubRevisionTracker {
    pub owner: String,
    pub repo: String,
    pub branch: String,

    pub pr: Option<GitHubPullRequest>,

    pub track_interval: Option<u64>,

    github: octocrab::Octocrab,
}

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
}

impl GitHubRevisionTracker {
    pub fn new(owner: String, repo: String, branch: String, access_token: String) -> Self {
        let github = octocrab::Octocrab::builder()
            .personal_token(access_token)
            .build()
            .unwrap();

        GitHubRevisionTracker {
            owner,
            repo,
            branch,
            pr: None,
            track_interval: None,

            github,
        }
    }

    pub async fn from_pull_request(
        base_owner: String,
        base_repo: String,
        pr_num: u64,
        access_token: String,
        track_interval: Option<u64>,
    ) -> Option<Self> {
        let github = octocrab::Octocrab::builder()
            .personal_token(access_token)
            .build()
            .unwrap();

        if let Ok(pr) = github.pulls(&base_owner, &base_repo).get(pr_num).await {
            let (owner, repo) = if let Some(repo) = pr.head.repo.as_ref() {
                (
                    repo.owner.as_ref().unwrap().login.clone(),
                    repo.name.clone(),
                )
            } else {
                return None;
            };
            let branch = pr.head.ref_field;

            return Some(Self {
                owner,
                repo,
                branch,
                pr: Some(GitHubPullRequest {
                    number: pr_num,
                    base_owner,
                    base_repo,
                }),
                track_interval,
                github,
            });
        }

        None
    }

    async fn get_modified_files(&self, base: &str, head: &str) -> Vec<String> {
        if let Some(pr) = &self.pr {
            // Fetch pull request diff
            return if let Ok(result) = self
                .github
                .pulls(&pr.base_owner, &pr.base_repo)
                .list_files(pr.number)
                .await
            {
                result
                    .items
                    .iter()
                    .map(|d| d.filename.clone())
                    .collect::<Vec<String>>()
            } else {
                log::warn!(
                    "No files PR diff (repo={}/{}, branch={}, pr={})",
                    &self.owner,
                    &self.repo,
                    &self.branch,
                    pr.number
                );
                Vec::new()
            };
        }

        // Fetch diff to previous revision head
        let commit_comparison = self
            .github
            .commits(&self.owner, &self.repo)
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
                    &self.owner,
                    &self.repo,
                    &self.branch,
                );
                Vec::new()
            }
            Err(err) => {
                log::error!(
                    "Could not fetch changed files for new revision (repo={}/{}, branch={}): {}",
                    &self.owner,
                    &self.repo,
                    &self.branch,
                    err
                );
                Vec::new()
            }
        }
    }
}

impl ProjectRevisionTracker<GitHubRevision> for GitHubRevisionTracker {
    async fn track(&mut self, current: Option<GitHubRevision>) -> GitHubRevision {
        loop {
            // Query the GitHub API for recent repo events.
            match self
                .github
                .repos(&self.owner, &self.repo)
                .get_ref(&octocrab::params::repos::Reference::Branch(
                    self.branch.clone(),
                ))
                .await
            {
                Ok(Ref {
                    object: Object::Commit { sha, .. },
                    ..
                }) => {
                    if current.as_ref().map_or(true, |rev| rev.head != sha) {
                        log::info!(
                            "New GitHub revision for repo={}/{} branch={} rev={}",
                            self.owner,
                            self.repo,
                            self.branch,
                            &sha[..8]
                        );

                        let previous_head =
                            current.map_or(None, |rev| Some(rev.commit_hash().to_string()));

                        let mut modified_files = Vec::new();
                        if let Some(previous_head) = &previous_head {
                            modified_files = self.get_modified_files(previous_head, &sha).await;
                        }

                        return GitHubRevision {
                            head: sha,
                            previous_head,
                            files: modified_files,
                        };
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    if let octocrab::Error::GitHub { source, .. } = err {
                        log::warn!("Could not query GitHub api: {}", source)
                    }
                }
            }

            // Wait a little while before querying GitHub again.
            let default_interval_seconds = 60 * 5;
            let interval =
                std::env::var("FUZZOR_GH_TRACK_INTERVAL").map_or(default_interval_seconds, |val| {
                    val.parse()
                        .expect("FUZZOR_GH_TRACK_INTERVAL should be a value in seconds")
                });
            time::sleep(time::Duration::from_secs(
                self.track_interval.unwrap_or(interval),
            ))
            .await;
        }
    }
}
