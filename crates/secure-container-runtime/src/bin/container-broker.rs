//! Container Broker Daemon
//!
//! This is the ONLY process that should have access to the Docker socket.
//! It listens on a Unix socket and manages containers securely.
//!
//! Usage:
//!   container-broker [--socket /var/run/platform/container-broker.sock] [--config config.toml]

use secure_container_runtime::{ContainerBroker, SecurityPolicy};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

const DEFAULT_SOCKET: &str = "/var/run/platform/container-broker.sock";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    info!("Container Broker starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    let socket_path = parse_socket_arg(&args).unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    // Create socket directory if needed
    if let Some(parent) = PathBuf::from(&socket_path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            info!("Created socket directory: {:?}", parent);
        }
    }

    // Load policy (could be from config file in production)
    let policy = if std::env::var("BROKER_DEV_MODE").is_ok() {
        info!("Using development security policy");
        SecurityPolicy::development()
    } else {
        info!("Using strict security policy");
        SecurityPolicy::strict()
    };

    // Create broker
    let broker = ContainerBroker::with_policy(policy).await?;

    info!("Security policies:");
    info!("  - Only whitelisted images allowed");
    info!("  - Non-privileged containers only");
    info!("  - Docker socket mounting blocked");
    info!("  - Resource limits enforced");
    info!("  - Audit logging enabled");

    // Run broker
    info!("Listening on: {}", socket_path);
    broker.run(&socket_path).await?;

    Ok(())
}

fn parse_socket_arg(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "--socket" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    std::env::var("BROKER_SOCKET").ok()
}
