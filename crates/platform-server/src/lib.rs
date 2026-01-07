//! Platform Server - Central API for Platform Network
//!
//! This is the SINGLE SOURCE OF TRUTH for the Platform subnet.
//!
//! Architecture:
//! - Control Plane API: Challenge registry, validator registry, configuration
//! - Data API: Gateway to all databases with Claim/Lease primitives
//! - Rule Engine: Server-side enforcement of challenge rules
//! - WebSocket: Real-time events to validators
//!
//! Key invariants:
//! - All databases live here (one global + one per challenge)
//! - Validators are execute-only, they query this server
//! - Challenges write results via Data API, never direct DB access
//! - Weights are computed from DB snapshots (deterministic)

pub mod api;
pub mod data_api;
pub mod db;
pub mod models;
pub mod observability;
pub mod orchestration;
pub mod state;
pub mod websocket;

pub use db::DbPool;
pub use observability::init_sentry;
pub use state::AppState;
