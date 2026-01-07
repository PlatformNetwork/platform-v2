//! WebSocket module for real-time events
//!
//! This module provides two WebSocket endpoints:
//! - `/ws` - For validators to receive events from the platform
//! - `/ws/challenge` - For challenges to send targeted notifications to validators

pub mod challenge_handler;
pub mod events;
pub mod handler;

pub use challenge_handler::*;
pub use handler::*;
