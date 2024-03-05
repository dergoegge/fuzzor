use super::campaign::CampaignEvent;
use super::ProjectEvent;
use crate::solutions::reporter::SolutionReporter;

#[async_trait::async_trait]
pub trait ProjectMonitor {
    async fn monitor_campaign_event(&mut self, project: String, event: CampaignEvent);
    async fn monitor_project_event(&mut self, project: String, event: ProjectEvent);
}

/// A [`ProjectMonitor`] that monitors for new solutions and relays them to the underlying
/// [`SolutionReporter`].
pub struct SolutionReportingMonitor<R> {
    reporter: R,
}

impl<R> SolutionReportingMonitor<R>
where
    R: SolutionReporter,
{
    pub fn new(reporter: R) -> Self {
        Self { reporter }
    }
}

#[async_trait::async_trait]
impl<R> ProjectMonitor for SolutionReportingMonitor<R>
where
    R: SolutionReporter + Clone + Send + 'static,
{
    async fn monitor_campaign_event(&mut self, project: String, event: CampaignEvent) {
        match event.clone() {
            CampaignEvent::NewSolution(harness, solution) => {
                if let Err(err) = self
                    .reporter
                    .report_new_solution(project.clone(), harness, solution)
                    .await
                {
                    log::error!(
                        "Could not report new solution for project '{}': {}",
                        project,
                        err
                    );
                }
            }
            _ => {}
        }
    }

    async fn monitor_project_event(&mut self, _project: String, _event: ProjectEvent) {}
}
