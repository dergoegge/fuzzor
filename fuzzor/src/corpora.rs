use std::path::PathBuf;

use async_trait::async_trait;

/// CorpusHerder acts a single source for corpora.
#[async_trait]
pub trait CorpusHerder<C: Send> {
    /// Merge new inputs into its existing corpus.
    async fn merge(&mut self, harness: String, corpus: C) -> Result<(), String>;
    /// Get the latest corpus for a given harness.
    async fn fetch(&self, harness: String) -> Result<C, String>;
}

/// VersionedOverwritingHerder stores corpora for projects on disk in form of a git repository.
///
/// This herder never actually merges new inputs, but rather overwrites the existing corpus with
/// the corpus supplied to [merge].
pub struct VersionedOverwritingHerder {
    // Path to the directory in which the corpora for each project are stored.
    //
    // Each project gets its own subdirectory for its corpora.
    corpora_dir: PathBuf,

    // Git repository at [corpora_dir] used for version control of the corpora.
    repo: git2::Repository,
}

unsafe impl Send for VersionedOverwritingHerder {}
unsafe impl Sync for VersionedOverwritingHerder {}

impl VersionedOverwritingHerder {
    pub async fn new(corpora_dir: PathBuf, remote: String) -> Result<Self, String> {
        if !corpora_dir.is_dir() {
            tokio::fs::create_dir_all(&corpora_dir)
                .await
                .map_err(|e| format!("Could not create corpora directory: {}", e))?;
        }

        let repo = match git2::Repository::open(&corpora_dir) {
            Ok(repo) => repo,
            Err(_err) => git2::Repository::init(&corpora_dir)
                .map_err(|e| format!("Could not open repo: {}", e))?,
        };

        if repo.find_remote("origin").is_err() {
            repo.remote("origin", &remote)
                .map_err(|e| format!("Could not add remote to repo: {}", e))?;
        }

        Ok(Self { corpora_dir, repo })
    }

    fn commit_corpora_changes(&mut self, harness: &str) -> Result<(), String> {
        let mut index = self
            .repo
            .index()
            .map_err(|e| format!("Could not get git index: {}", e))?;

        index
            .add_all(["."].iter(), git2::IndexAddOption::DEFAULT, None)
            .map_err(|e| format!("Could not update git index: {}", e))?;
        index
            .write()
            .map_err(|e| format!("Could not write git index: {}", e))?;

        let author = git2::Signature::now("fuzzor", "niklas@brink.dev").unwrap();
        let tree = self.repo.find_tree(index.write_tree().unwrap()).unwrap();

        let mut parents = Vec::new();
        if let Ok(head) = self.repo.head() {
            parents.push(head.peel_to_commit().unwrap());
        }
        self.repo
            .commit(
                Some("HEAD"),
                &author,
                &author,
                &format!("[merge] update {} corpus", harness),
                &tree,
                &parents.iter().collect::<Vec<_>>(),
            )
            .unwrap();

        Ok(())
    }

    fn get_corpus_dir(&self, harness: &str) -> PathBuf {
        self.corpora_dir.join(harness)
    }
}

#[async_trait]
impl CorpusHerder<Vec<u8>> for VersionedOverwritingHerder {
    async fn merge(&mut self, harness: String, corpus: Vec<u8>) -> Result<(), String> {
        let corpus_dir = self.get_corpus_dir(&harness);

        // Delete the current corpus folder
        if let Err(err) = tokio::fs::remove_dir_all(&corpus_dir).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                log::warn!(
                    "Could not remove old corpus directory \"{:?}\": {:?}",
                    &corpus_dir,
                    err
                );
            }
        }

        let _ = tokio::fs::create_dir_all(&corpus_dir).await;

        // Unpack the new corpus from the tarball
        let mut archive = tar::Archive::new(corpus.as_slice());
        for entry in archive.entries().unwrap() {
            let mut file = entry.unwrap();

            if file.header().entry_type().is_dir() {
                continue;
            }

            let input_path =
                corpus_dir.join(file.path().unwrap().file_name().unwrap().to_str().unwrap());
            if let Ok(_) = file.unpack(&input_path) {
                log::trace!("Unpacked fuzz input to: {:?}", &input_path);
            }
        }

        // Commit the changes to the git repo
        self.commit_corpora_changes(&harness)?;

        Ok(())
    }

    async fn fetch(&self, harness: String) -> Result<Vec<u8>, String> {
        let corpus_dir = self.get_corpus_dir(&harness);

        let mut tar = tar::Builder::new(Vec::new());
        tar.append_dir_all(".", corpus_dir)
            .map_err(|e| format!("Could add corpora to archive: {}", e))?;

        let tarball_bytes = tar
            .into_inner()
            .map_err(|e| format!("Could not create archive: {}", e))?;
        Ok(tarball_bytes)
    }
}
