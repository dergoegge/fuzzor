use clap::{Parser, Subcommand};
use fuzzor::solutions::inmemory::InMemorySolutionTracker;
use fuzzor::solutions::SolutionTracker;
use fuzzor_dist::coordinator::{Coordinator, CoordinatorOpts};
use fuzzor_dist::workers::{NatsWorker, WorkerOptions, WorkerPurpose};
use fuzzor_infra::FuzzerStats;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the coordinator server
    Coordinate {
        /// NATS server address (format: IP:PORT)
        #[arg(long, default_value = "127.0.0.1:4222")]
        nats_server: SocketAddr,

        /// Prometheus metrics exporter bind address (format: IP:PORT)
        #[arg(long, default_value = "127.0.0.1:9998")]
        metrics_bind: SocketAddr,

        /// List of allowed projects
        #[arg(long, value_delimiter = ',')]
        allowed_projects: Vec<String>,

        /// List of denied projects
        #[arg(long, value_delimiter = ',')]
        denied_projects: Vec<String>,

        /// GitHub repository for bug reports (format: '<owner>/<repo>')
        #[arg(long, required = true)]
        report_repo: String,

        /// Campaign duration in CPU hours (does not override value in project's config)
        #[arg(
            long = "campaign-duration",
            help = "Campaign duration in CPU hours",
            default_value_t = 16
        )]
        campaign_duration: u64,
    },
    /// Run a worker
    Work {
        /// NATS server address (format: IP:PORT)
        #[arg(long, default_value = "127.0.0.1:4222")]
        nats_server: SocketAddr,

        /// CPU type of the worker
        #[arg(
            long = "cpu-type",
            help = "Choose cpu type (bare-metal, virtual, emulated)",
            default_value_t = String::from("bare-metal")
        )]
        cpu_type: String,

        /// Name of the worker
        #[arg(long, help = "Name of the worker")]
        name: Option<String>,

        /// Container registry to push/pull container images from
        #[arg(long)]
        registry: Option<String>,

        /// List of projects to work on
        #[arg(long, value_delimiter = ',')]
        allowed_projects: Vec<String>,

        #[command(subcommand)]
        command: WorkCommands,
    },
}

#[derive(Subcommand)]
enum WorkCommands {
    Fuzz,
    Build,
}

// NopHarnessState is a no-op harness state that does nothing. Its only used for the RemoteCampaign
// which does not make use of the harness state.
pub struct NopHarnessState;
#[async_trait::async_trait]
impl fuzzor::project::harness::HarnessState for NopHarnessState {
    async fn solutions(&self) -> Arc<Mutex<dyn SolutionTracker + Send>> {
        Arc::new(Mutex::new(InMemorySolutionTracker::default()))
    }
    async fn set_covered_files(&mut self, _covered_files: Vec<String>) {}
    async fn covered_files(&self) -> HashSet<String> {
        HashSet::new()
    }
    async fn covers_file(&self, _file: String) -> bool {
        false
    }
    async fn store_coverage_report(&self, _tar: Vec<u8>) {}
    async fn record_stats(&mut self, _stats: FuzzerStats) {}
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Coordinate {
            nats_server,
            metrics_bind,
            allowed_projects,
            denied_projects,
            report_repo,
            campaign_duration,
        } => {
            let mut coordinator = Coordinator::new(
                nats_server.clone(),
                CoordinatorOpts {
                    allowed_projects,
                    denied_projects,
                    report_repo,
                    campaign_duration,
                },
            )
            .await
            .unwrap();

            coordinator.run(metrics_bind).await.unwrap();
        }
        Commands::Work {
            nats_server,
            cpu_type,
            name,
            registry,
            allowed_projects,
            command,
        } => {
            let purpose = match command {
                WorkCommands::Fuzz => WorkerPurpose::Fuzz,
                WorkCommands::Build => WorkerPurpose::Build,
            };

            let cpu_type = match cpu_type.as_str() {
                "bare-metal" => fuzzor_infra::CpuType::BareMetal,
                "emulated" => fuzzor_infra::CpuType::Emulated,
                "virtual" => fuzzor_infra::CpuType::Virtual,
                _ => {
                    log::error!("Invalid cpu type");
                    return;
                }
            };

            let mut worker = NatsWorker::new(WorkerOptions {
                purpose,
                cpu_type,
                name,
                registry,
                allowed_projects,
            });

            let _ = worker.run(&nats_server).await;
        }
    }
}
