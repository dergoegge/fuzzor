use super::{Solution, SolutionMetadata};

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

#[async_trait]
pub trait SolutionReporter {
    async fn report_new_solution(
        &mut self,
        project: String,
        harness: String,
        solution: Solution,
    ) -> Result<(), String>;
}

/// Reports solutions to StdErr
#[derive(Clone)]
pub struct StdErrSolutionReporter;

#[async_trait]
impl SolutionReporter for StdErrSolutionReporter {
    async fn report_new_solution(
        &mut self,
        project: String,
        harness: String,
        solution: Solution,
    ) -> Result<(), String> {
        match solution.metadata() {
            SolutionMetadata::Crash(stack_trace) => eprintln!(
                "New crash id='{}' (project='{}' harness='{}')\n Base64: {} \n ===== stack trace ===== \n {} \n",
                solution.id(),
                project,
                harness,
                solution.input_base64(),
                stack_trace
            ),
            SolutionMetadata::Differential(stack_trace) => eprintln!(
                "New differential solution (project='{}' harness='{}')\n Base64: {} \n ===== stack trace ===== \n {}",
                project,
                harness,
                solution.input_base64(),
                stack_trace
            ),
            SolutionMetadata::Timeout(_) => eprintln!(
                "New timeout (project='{}' harness='{}')\n Base64: {}", project,
                harness,
                solution.input_base64()
            ),
        };

        Ok(())
    }
}

/// Reports solutions through another wrapped `SolutionReporter` and quits the owning project.
#[derive(Clone)]
pub struct QuittingSolutionReporter<R> {
    inner: R,
    quit_project_sender: Sender<()>,
}

unsafe impl<R> Send for QuittingSolutionReporter<R> {}

impl<R: SolutionReporter> QuittingSolutionReporter<R> {
    pub fn new(inner: R, quit_project_sender: Sender<()>) -> Self {
        Self {
            inner,
            quit_project_sender,
        }
    }
}

#[async_trait]
impl<R: SolutionReporter> SolutionReporter for QuittingSolutionReporter<R> {
    async fn report_new_solution(
        &mut self,
        project: String,
        harness: String,
        solution: Solution,
    ) -> Result<(), String> {
        let _ = self
            .inner
            .report_new_solution(project, harness, solution)
            .await;

        let _ = self.quit_project_sender.try_send(());

        Ok(())
    }
}
