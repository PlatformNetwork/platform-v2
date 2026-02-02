//! Platform - Unified Binary
//!
//! Single binary that can run as either:
//! - Server mode: `platform server [options]`
//! - Validator mode: `platform validator [options]`
//!
//! This enables using a single Docker image for both roles.
//!
//! Usage:
//!   platform server --port 8080
//!   platform validator --secret-key <KEY> --platform-server <URL>

mod server;
mod validator;

use clap::{Parser, Subcommand};
use tracing::info;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const BANNER: &str = r#"
  ██████╗ ██╗      █████╗ ████████╗███████╗ ██████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗████╗ ████║
  ██████╔╝██║     ███████║   ██║   █████╗  ██║   ██║██████╔╝██╔████╔██║
  ██╔═══╝ ██║     ██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║
  ██║     ███████╗██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║
  ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
"#;

#[derive(Parser)]
#[command(name = "platform")]
#[command(author = "Platform Network")]
#[command(version)]
#[command(about = "Platform Network - Unified Server/Validator Binary")]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as platform server (subnet owner only)
    /// Central API server for challenge orchestration and weight calculation
    #[command(visible_alias = "s")]
    Server(server::ServerArgs),

    /// Run as validator node
    /// Evaluates challenges and submits weights to Bittensor
    #[command(visible_alias = "v")]
    Validator(validator::ValidatorArgs),

    /// Show version and build info
    Version,
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("platform=debug".parse().unwrap())
                .add_directive("platform_server=debug".parse().unwrap())
                .add_directive("validator_node=debug".parse().unwrap())
                .add_directive("info".parse().unwrap()),
        )
        .init();
}

fn init_sentry() -> Option<sentry::ClientInitGuard> {
    const DEFAULT_DSN: &str = "https://56a006330cecdc120766a602a5091eb9@o4510579978272768.ingest.us.sentry.io/4510579979911168";

    let dsn = std::env::var("SENTRY_DSN").unwrap_or_else(|_| DEFAULT_DSN.to_string());
    if dsn.is_empty() {
        return None;
    }

    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string());

    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: Some(environment.into()),
            send_default_pii: false,
            sample_rate: 1.0,
            traces_sample_rate: 0.1,
            attach_stacktrace: true,
            ..Default::default()
        },
    ));

    Some(guard)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _sentry_guard = init_sentry();
    init_logging();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server(args) => {
            println!("{}", BANNER);
            info!("Platform Network v{} - Server Mode", VERSION);
            info!("=========================================");
            server::run(args).await
        }
        Commands::Validator(args) => {
            println!("{}", BANNER);
            info!("Platform Network v{} - Validator Mode", VERSION);
            info!("=========================================");
            validator::run(args).await
        }
        Commands::Version => {
            println!("Platform Network v{}", VERSION);
            println!("  Build: {}", env!("CARGO_PKG_NAME"));
            println!("  Commit: {}", option_env!("GIT_HASH").unwrap_or("unknown"));
            Ok(())
        }
    }
}
