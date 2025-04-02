use std::net::SocketAddr;
use std::sync::{atomic::AtomicU64, Arc};

use fuzzor::project::{
    campaign::{CampaignEvent, CampaignState},
    monitor::ProjectMonitor,
    ProjectEvent,
};
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ProjectLabel {
    project: String,
    outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct HarnessLabel {
    project: String,
    harness: String,
}

pub struct SharedMetrics {
    registry: Registry,
    project_build_results: Family<ProjectLabel, Counter>,
    campaigns_completed: Family<HarnessLabel, Counter>,
    solutions_found: Family<HarnessLabel, Counter>,
    execs_per_sec: Family<HarnessLabel, Gauge<f64, AtomicU64>>,
    corpus_count: Family<HarnessLabel, Gauge>,
    saved_crashes: Family<HarnessLabel, Gauge>,
    saved_hangs: Family<HarnessLabel, Gauge>,
    fuzzer_stability: Family<HarnessLabel, Gauge<f64, AtomicU64>>,
    campaign_state_scheduled: Family<HarnessLabel, Gauge>,
    campaign_state_fuzzing: Family<HarnessLabel, Gauge>,
    campaign_state_ended: Family<HarnessLabel, Gauge>,
}

impl SharedMetrics {
    pub fn new() -> Self {
        let mut registry = <Registry>::default();

        let project_build_results = Family::<ProjectLabel, Counter>::default();
        registry.register(
            "project_build_results_total",
            "Result of project builds (success/failure)",
            project_build_results.clone(),
        );

        let campaigns_completed = Family::<HarnessLabel, Counter>::default();
        registry.register(
            "campaigns_completed_total",
            "Number of campaigns completed",
            campaigns_completed.clone(),
        );

        let solutions_found = Family::<HarnessLabel, Counter>::default();
        registry.register(
            "solutions_found_total",
            "Number of unique solutions found",
            solutions_found.clone(),
        );

        let execs_per_sec = Family::<HarnessLabel, Gauge<f64, AtomicU64>>::default();
        registry.register(
            "fuzzer_execs_per_sec",
            "Executions per second",
            execs_per_sec.clone(),
        );

        let corpus_count = Family::<HarnessLabel, Gauge>::default();
        registry.register(
            "fuzzer_corpus_count",
            "Number of items in the fuzzer corpus",
            corpus_count.clone(),
        );

        let saved_crashes = Family::<HarnessLabel, Gauge>::default();
        registry.register(
            "fuzzer_saved_crashes",
            "Number of crashes found by the fuzzer",
            saved_crashes.clone(),
        );

        let saved_hangs = Family::<HarnessLabel, Gauge>::default();
        registry.register(
            "fuzzer_saved_hangs",
            "Number of hangs found by the fuzzer",
            saved_hangs.clone(),
        );

        let fuzzer_stability = Family::<HarnessLabel, Gauge<f64, AtomicU64>>::default();
        registry.register(
            "fuzzer_stability",
            "Fuzzer stability percentage",
            fuzzer_stability.clone(),
        );

        let campaign_state_scheduled = Family::<HarnessLabel, Gauge>::default();
        registry.register(
            "campaign_state_scheduled",
            "Whether a campaign is in the scheduled state (0=false, 1=true)",
            campaign_state_scheduled.clone(),
        );

        let campaign_state_fuzzing = Family::<HarnessLabel, Gauge>::default();
        registry.register(
            "campaign_state_fuzzing",
            "Whether a campaign is in the fuzzing state (0=false, 1=true)",
            campaign_state_fuzzing.clone(),
        );

        let campaign_state_ended = Family::<HarnessLabel, Gauge>::default();
        registry.register(
            "campaign_state_ended",
            "Whether a campaign is in the ended state (0=false, 1=true)",
            campaign_state_ended.clone(),
        );

        Self {
            registry,
            project_build_results,
            campaigns_completed,
            solutions_found,
            execs_per_sec,
            corpus_count,
            saved_crashes,
            saved_hangs,
            fuzzer_stability,
            campaign_state_scheduled,
            campaign_state_fuzzing,
            campaign_state_ended,
        }
    }
}

pub struct PrometheusProjectMonitor {
    metrics: Arc<SharedMetrics>,
}

impl PrometheusProjectMonitor {
    pub fn new(metrics: Arc<SharedMetrics>) -> Self {
        Self { metrics }
    }
}

pub async fn start_metrics_server(
    addr: SocketAddr,
    metrics: Arc<SharedMetrics>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    log::info!("Prometheus metrics server listening on http://{}", addr);

    let server_metrics = metrics.clone();

    tokio::spawn(async move {
        loop {
            let connection_metrics = server_metrics.clone();
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to accept connection: {}", e);
                    continue;
                }
            };
            let io = TokioIo::new(stream);

            let service = service_fn(move |req| {
                let request_metrics = connection_metrics.clone();
                async move { handle_request(req, request_metrics).await }
            });

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                    log::trace!("Failed to serve connection: {}", err);
                }
            });
        }
    });

    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    metrics: Arc<SharedMetrics>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.uri().path() == "/metrics" {
        let mut buffer = String::new();
        match encode(&mut buffer, &metrics.registry) {
            Ok(_) => Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    CONTENT_TYPE,
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                )
                .body(Full::new(Bytes::from(buffer)))
                .unwrap()),
            Err(e) => {
                log::error!("Failed to encode metrics: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("Failed to encode metrics")))
                    .unwrap())
            }
        }
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap())
    }
}

#[async_trait::async_trait]
impl ProjectMonitor for PrometheusProjectMonitor {
    async fn monitor_campaign_event(&mut self, project: String, event: CampaignEvent) {
        match event {
            CampaignEvent::Initialized(harness) => {
                let labels = HarnessLabel { project, harness };
                // Ensure gauges are initialized to 0 when a campaign starts
                self.metrics
                    .campaign_state_scheduled
                    .get_or_create(&labels)
                    .set(1);
                self.metrics
                    .campaign_state_fuzzing
                    .get_or_create(&labels)
                    .set(0);
                self.metrics
                    .campaign_state_ended
                    .get_or_create(&labels)
                    .set(0);
            }
            CampaignEvent::NewState(harness, _old_state, new_state) => {
                let labels = HarnessLabel { project, harness };

                let (scheduled, fuzzing, ended) = match new_state {
                    CampaignState::Scheduled => (1, 0, 0),
                    CampaignState::Fuzzing => (0, 1, 0),
                    CampaignState::Ended => (0, 0, 1),
                };

                self.metrics
                    .campaign_state_scheduled
                    .get_or_create(&labels)
                    .set(scheduled);
                self.metrics
                    .campaign_state_fuzzing
                    .get_or_create(&labels)
                    .set(fuzzing);
                self.metrics
                    .campaign_state_ended
                    .get_or_create(&labels)
                    .set(ended);
            }
            CampaignEvent::NewSolution(harness, _solution) => {
                let labels = HarnessLabel { project, harness };
                self.metrics.solutions_found.get_or_create(&labels).inc();
            }
            CampaignEvent::ResolvedSolution(_, _) => { /* TODO */ }
            CampaignEvent::Stats(harness, stats) => {
                let labels = HarnessLabel { project, harness };
                self.metrics
                    .execs_per_sec
                    .get_or_create(&labels)
                    .set(stats.execs_per_sec);
                self.metrics
                    .corpus_count
                    .get_or_create(&labels)
                    .set(stats.corpus_count as i64);
                self.metrics
                    .saved_crashes
                    .get_or_create(&labels)
                    .set(stats.saved_crashes as i64);
                self.metrics
                    .saved_hangs
                    .get_or_create(&labels)
                    .set(stats.saved_hangs as i64);
                if let Some(stability) = stats.stability {
                    self.metrics
                        .fuzzer_stability
                        .get_or_create(&labels)
                        .set(stability);
                }
            }
            CampaignEvent::Quit(harness, _) => {
                let labels = HarnessLabel { project, harness };
                self.metrics
                    .campaigns_completed
                    .get_or_create(&labels)
                    .inc();
            }
        }
    }
    async fn monitor_project_event(&mut self, project: String, event: ProjectEvent) {
        let outcome = match event {
            ProjectEvent::NewBuild => "success",
            ProjectEvent::BuildFailure => "failure",
        };

        self.metrics
            .project_build_results
            .get_or_create(&ProjectLabel {
                project,
                outcome: outcome.to_string(),
            })
            .inc();
    }
}

impl Default for SharedMetrics {
    fn default() -> Self {
        Self::new()
    }
}
