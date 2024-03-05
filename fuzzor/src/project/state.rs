use std::path::PathBuf;
use std::sync::Arc;

use super::harness::{HarnessState, PersistentHarnessState};
use crate::corpora::CorpusHerder;

use tokio::sync::Mutex;

#[async_trait::async_trait]
pub trait State<CH, HS>
where
    CH: CorpusHerder<Vec<u8>>,
    HS: HarnessState,
{
    async fn corpus_herder(&self) -> Arc<Mutex<CH>>;
    async fn create_harness_state(&self, harness: String) -> HS;

    async fn set_last_build_rev(&mut self, rev: String);
    async fn last_build_rev(&self) -> Option<String>;
}

pub struct StdProjectState<CH> {
    corpus_herder: Arc<Mutex<CH>>,
    path: PathBuf,
    last_build_rev: Option<String>,
}

impl<CH> StdProjectState<CH>
where
    CH: CorpusHerder<Vec<u8>>,
{
    pub fn new(path: PathBuf, corpus_herder: CH) -> Self {
        Self {
            corpus_herder: Arc::new(Mutex::new(corpus_herder)),
            path,
            last_build_rev: None,
        }
    }
}

#[async_trait::async_trait]
impl<CH> State<CH, PersistentHarnessState> for StdProjectState<CH>
where
    CH: CorpusHerder<Vec<u8>> + Send,
{
    async fn corpus_herder(&self) -> Arc<Mutex<CH>> {
        self.corpus_herder.clone()
    }
    async fn create_harness_state(&self, harness: String) -> PersistentHarnessState {
        PersistentHarnessState::new(self.path.join("harnesses").join(&harness)).await
    }

    async fn set_last_build_rev(&mut self, rev: String) {
        self.last_build_rev = Some(rev);
    }
    async fn last_build_rev(&self) -> Option<String> {
        self.last_build_rev.clone()
    }
}
