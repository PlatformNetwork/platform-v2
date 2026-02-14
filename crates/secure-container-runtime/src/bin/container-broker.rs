//! Container Broker Daemon — Validator Deployment Infrastructure
//!
//! This is the ONLY process that should have access to the Docker socket.  It
//! listens on a Unix socket AND/OR WebSocket and manages deployment containers
//! securely.  Challenge execution is handled by the WASM sandbox and does not
//! use Docker.
//!
//! Usage:
//!   container-broker [OPTIONS]
//!
//! Options:
//!   --socket PATH    Unix socket path (default: /var/run/platform/container-broker.sock)
//!   --ws-port PORT   WebSocket port (default: 8090, 0 to disable)
//!   --ws-only        Disable Unix socket, use WebSocket only
//!
//! Environment:
//!   BROKER_SOCKET      Unix socket path
//!   BROKER_WS_PORT     WebSocket port
//!   BROKER_HTTP_PORT   HTTP health check port (default: 8091, 0 to disable)
//!   BROKER_JWT_SECRET  JWT secret for WebSocket auth (required for WS in production)
//!   BROKER_DEV_MODE    Enable development mode (relaxed policy)

use secure_container_runtime::{run_ws_server, ContainerBroker, SecurityPolicy, WsConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

const DEFAULT_SOCKET: &str = "/var/run/platform/container-broker.sock";
const DEFAULT_WS_PORT: u16 = 8090;
const DEFAULT_HTTP_PORT: u16 = 8091;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging - use RUST_LOG env var or default to debug for broker
    let log_level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Level::DEBUG);

    FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(true) // Show module path for debugging
        .with_thread_ids(false)
        .init();

    info!("Container Broker starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    let socket_path = parse_arg(&args, "--socket")
        .or_else(|| std::env::var("BROKER_SOCKET").ok())
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    let ws_port: u16 = parse_arg(&args, "--ws-port")
        .or_else(|| std::env::var("BROKER_WS_PORT").ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WS_PORT);

    let ws_only = args.contains(&"--ws-only".to_string());

    let http_port: u16 = parse_arg(&args, "--http-port")
        .or_else(|| std::env::var("BROKER_HTTP_PORT").ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_HTTP_PORT);

    // Load policy
    let policy = if std::env::var("BROKER_DEV_MODE").is_ok() {
        info!("Using development security policy");
        SecurityPolicy::development()
    } else {
        info!("Using strict security policy");
        SecurityPolicy::strict()
    };

    // Create broker
    let broker = Arc::new(ContainerBroker::with_policy(policy).await?);

    info!("Security policies:");
    info!("  - Only whitelisted images allowed");
    info!("  - Non-privileged containers only");
    info!("  - Docker socket mounting blocked");
    info!("  - Resource limits enforced");
    info!("  - Audit logging enabled");

    // Start HTTP health server if enabled
    if http_port > 0 {
        info!("HTTP health server: http://0.0.0.0:{}/health", http_port);
        tokio::spawn(async move {
            if let Err(e) = run_health_server(http_port).await {
                warn!("HTTP health server error: {}", e);
            }
        });
    }

    // Start WebSocket server if enabled
    let ws_handle = if ws_port > 0 {
        let is_dev_mode = std::env::var("BROKER_DEV_MODE").is_ok();
        let ws_config = WsConfig {
            bind_addr: format!("0.0.0.0:{}", ws_port),
            jwt_secret: std::env::var("BROKER_JWT_SECRET").ok(),
            // SECURITY: Only allow unauthenticated in dev mode
            allow_unauthenticated: is_dev_mode,
            allowed_challenges: vec![],
            max_connections_per_challenge: 10,
        };

        if ws_config.jwt_secret.is_none() && !is_dev_mode {
            warn!("SECURITY WARNING: WebSocket requires JWT auth but BROKER_JWT_SECRET not set. Connections will be rejected unless BROKER_DEV_MODE is enabled.");
        }

        info!("WebSocket server: ws://0.0.0.0:{}", ws_port);
        if is_dev_mode {
            warn!("WebSocket running in DEV MODE - unauthenticated connections allowed");
        }
        let broker_clone = broker.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = run_ws_server(broker_clone, ws_config).await {
                tracing::error!(error = %e, "WebSocket server error");
            }
        }))
    } else {
        info!("WebSocket server: disabled");
        None
    };

    // Start Unix socket server if not ws-only
    if !ws_only {
        // Create socket directory if needed
        if let Some(parent) = PathBuf::from(&socket_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                info!("Created socket directory: {:?}", parent);
            }
        }

        info!("Unix socket: {}", socket_path);
        broker.run(&socket_path).await?;
    } else {
        info!("Unix socket: disabled (ws-only mode)");
        // Wait for WebSocket server
        if let Some(handle) = ws_handle {
            handle.await?;
        }
    }

    Ok(())
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

/// Simple HTTP server for health checks
/// Responds to any request on /health with "OK"
async fn run_health_server(port: u16) -> anyhow::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    loop {
        match listener.accept().await {
            Ok((mut socket, _)) => {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    // Read request (we don't really care about the content)
                    let _ = socket.read(&mut buf).await;

                    // Check if it's a health check request
                    let request = String::from_utf8_lossy(&buf);
                    let response = if request.contains("/health") || request.contains("GET /") {
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found"
                    };

                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
            Err(e) => {
                warn!("HTTP accept error: {}", e);
            }
        }
    }
}
