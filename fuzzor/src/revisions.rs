use async_trait;

/// Revision represents a revision of a project's source code
pub trait Revision {
    /// Commit hash of the head for the previous revision. [`None`] if there was no previous
    /// revision.
    fn previous_commit_hash(&self) -> Option<&str>;
    /// Commit hash of the head for this revision
    fn commit_hash(&self) -> &str;
    /// List of files that were changed between this revision and the previous one.
    fn modified_files(&self) -> &[String];

    fn new(
        commit_hash: String,
        previous_commit_hash: Option<String>,
        modified_files: Vec<String>,
    ) -> Self;
}

#[async_trait::async_trait]
pub trait RevisionTracker<R: Revision> {
    /// Resolves into a revision identifier whenever a newer revision becomes available
    async fn track(&mut self, current: Option<R>) -> R;
}
