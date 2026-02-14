//! Secure Container Runtime — Validator Deployment Infrastructure
//!
//! This crate provides a secure Docker container broker used **exclusively** for
//! validator deployment infrastructure.  It is **not** used for challenge
//! execution — all challenge workloads run inside the deterministic WASM
//! sandbox provided by `wasm-runtime`.
//!
//! ## Scope
//!
//! | Concern                | Handled here? | Where instead?         |
//! |------------------------|:-------------:|------------------------|
//! | Validator node deploy  | ✅            | —                      |
//! | Service containers     | ✅            | —                      |
//! | Challenge execution    | ❌            | `wasm-runtime` crate   |
//! | Challenge sandboxing   | ❌            | `wasm-runtime` crate   |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │ Validator        │    │ Container       │    │ Docker Daemon   │
//! │ Deployment       │───▶│ Broker          │───▶│ (only broker    │
//! │ (no socket)      │    │ (Unix Socket)   │    │  has access)    │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! The broker is the **only** process with Docker socket access.  Validator
//! components communicate with it over a Unix socket or authenticated
//! WebSocket.  Security policies enforce image whitelisting, resource limits,
//! network isolation, and mount restrictions.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use secure_container_runtime::{
//!     SecureContainerClient, ContainerConfigBuilder, NetworkMode
//! };
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = SecureContainerClient::new("/var/run/platform/broker.sock");
//!
//!     let config = ContainerConfigBuilder::new(
//!         "ghcr.io/platformnetwork/validator-service:latest",
//!         "validator-deploy",
//!         "owner-123",
//!     )
//!     .memory_gb(2.0)
//!     .cpu(1.0)
//!     .expose(8080)
//!     .network_mode(NetworkMode::Isolated)
//!     .build();
//!
//!     let (container_id, name) = client.create_container(config).await?;
//!     client.start_container(&container_id).await?;
//!
//!     client.cleanup_challenge("validator-deploy").await?;
//!
//!     Ok(())
//! }
//! ```

pub mod broker;
pub mod client;
pub mod policy;
pub mod protocol;
pub mod types;
pub mod ws_client;
pub mod ws_transport;

pub use broker::ContainerBroker;
pub use client::{
    ChallengeStats, CleanupResult, ContainerConfigBuilder, ContainerStartResult, OneshotResult,
    SecureContainerClient,
};
pub use policy::SecurityPolicy;
pub use protocol::{Request, Response};
pub use types::*;
pub use ws_client::WsContainerClient;
pub use ws_transport::{generate_token, run_ws_server, WsClaims, WsConfig};
