#![allow(dead_code, unused_variables, unused_imports)]
//! Mini-Chain Challenge SDK
//!
//! SDK for developing challenges on the Mini-Chain P2P network.
//! Each challenge is independent with its own database and can define
//! custom evaluation logic, weight calculations, and custom HTTP routes.
//!
//! # Architecture
//!
//! The SDK provides:
//! - **Types**: Base data structures (EncryptedSubmission, ValidatorEvaluation, etc.)
//! - **Traits**: Interfaces for challenges to implement (Challenge, P2PHandler)
//! - **Helpers**: Crypto utilities (encrypt/decrypt, key generation)
//!
//! Each challenge implements its own:
//! - Submission management logic
//! - Weight calculation algorithm
//! - Custom routes and handlers
//!
//! # Custom Routes
//!
//! ```rust,ignore
//! impl Challenge for MyChallenge {
//!     fn routes(&self) -> Vec<ChallengeRoute> {
//!         RouteBuilder::new()
//!             .get("/leaderboard", "Get leaderboard")
//!             .post("/submit", "Submit agent")
//!             .build()
//!     }
//! }
//! ```
//!
//! # Secure Submissions (Types)
//!
//! The SDK provides types for commit-reveal scheme:
//!
//! ```rust,ignore
//! use platform_challenge_sdk::{
//!     EncryptedSubmission, SubmissionAck, DecryptionKeyReveal,
//!     encrypt_data, decrypt_data, generate_key, hash_key
//! };
//!
//! // Miner side: encrypt and submit
//! let key = generate_key();
//! let content_hash = EncryptedSubmission::compute_content_hash(&code);
//! let encrypted = encrypt_data(&code, &key, &nonce)?;
//!
//! // Challenge implements its own SubmissionManager using these types
//! ```
//!
//! # Weight Calculation (Types)
//!
//! The SDK provides types, each challenge implements its own calculation:
//!
//! ```rust,ignore
//! use platform_challenge_sdk::{
//!     ValidatorEvaluation, WeightCalculationResult, WeightConfig
//! };
//!
//! // Challenge implements: fn calculate_weights(evals) -> WeightCalculationResult
//! ```

pub mod challenge;
pub mod context;
pub mod data;
pub mod database;
pub mod distributed_storage;
pub mod error;
pub mod p2p;
pub mod p2p_chain_storage;
pub mod routes;
pub mod storage_client;
pub mod storage_schema;
pub mod submission_types;
pub mod test_challenge;
pub mod types;
pub mod weight_types;
pub mod weights;

pub use challenge::*;
pub use context::*;
pub use data::*;
pub use database::*;
pub use distributed_storage::*;
pub use error::*;
pub use p2p::*;
pub use p2p_chain_storage::*;
pub use routes::*;
// Note: storage_client and storage_schema have conflicting types with distributed_storage
// Use explicit imports: platform_challenge_sdk::storage_schema::*
pub use submission_types::*;
pub use test_challenge::SimpleTestChallenge;
pub use types::*;
pub use weight_types::*;
pub use weights::*;

/// Re-export commonly used items
pub mod prelude {
    pub use super::challenge::Challenge;
    pub use super::context::ChallengeContext;
    pub use super::p2p::*;
    pub use super::routes::*;
    pub use super::submission_types::*;
    pub use super::types::*;
    pub use super::weight_types::*;
    pub use super::weights::*;
    pub use async_trait::async_trait;
    pub use serde_json::Value;
}
