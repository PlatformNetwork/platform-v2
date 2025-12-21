//! Secure Container Runtime
//!
//! This crate provides a secure broker for container management that:
//! - Isolates Docker socket access to a single broker process
//! - Enforces security policies (whitelisted images, non-privileged)
//! - Tags all containers with challenge/owner metadata
//! - Provides audit logging for all container operations
//! - Exposes a Unix socket API for unprivileged clients
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │ Challenge/      │    │ Container       │    │ Docker Daemon   │
//! │ Validator       │───▶│ Broker          │───▶│ (only broker    │
//! │ (no socket)     │    │ (Unix Socket)   │    │  has access)    │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
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
//!     // Connect to broker
//!     let client = SecureContainerClient::new("/var/run/platform/broker.sock");
//!     
//!     // Create container config
//!     let config = ContainerConfigBuilder::new(
//!         "ghcr.io/platformnetwork/term-challenge:latest",
//!         "my-challenge",
//!         "owner-123",
//!     )
//!     .memory_gb(2.0)
//!     .cpu(1.0)
//!     .expose(8080)
//!     .network_mode(NetworkMode::Isolated)
//!     .build();
//!     
//!     // Create and start container
//!     let (container_id, name) = client.create_container(config).await?;
//!     client.start_container(&container_id).await?;
//!     
//!     // Cleanup all containers for a challenge
//!     client.cleanup_challenge("my-challenge").await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod broker;
pub mod client;
pub mod policy;
pub mod protocol;
pub mod types;

pub use broker::ContainerBroker;
pub use client::{
    ChallengeStats, CleanupResult, ContainerConfigBuilder, ContainerStartResult, OneshotResult,
    SecureContainerClient,
};
pub use policy::SecurityPolicy;
pub use protocol::{Request, Response};
pub use types::*;
