//! Platform Challenge Loader
//!
//! Dynamic WASM challenge loading system for the Platform network.
//!
//! This crate provides functionality for:
//! - Loading and compiling WASM challenge modules
//! - Managing challenge versions with hot-reload support
//! - Discovering challenges from filesystem and P2P network
//! - Maintaining a registry of loaded challenges
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    ChallengeLoader                          │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │   Loader    │  │  Registry   │  │  Version    │         │
//! │  │   (main)    │  │             │  │  Manager    │         │
//! │  └─────────────┘  └─────────────┘  └─────────────┘         │
//! ├─────────────────────────────────────────────────────────────┤
//! │                      Discovery                              │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │ Filesystem  │  │    P2P      │  │  Composite  │         │
//! │  │  Discovery  │  │  Discovery  │  │  Discovery  │         │
//! │  └─────────────┘  └─────────────┘  └─────────────┘         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use platform_challenge_loader::{ChallengeLoader, LoaderConfig};
//! use platform_core::ChallengeConfig;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Create loader with default configuration
//!     let loader = ChallengeLoader::default_loader()?;
//!
//!     // Load a challenge from WASM bytes
//!     let wasm_bytes = std::fs::read("challenge.wasm")?;
//!     let id = platform_core::ChallengeId::new();
//!     
//!     loader.load_challenge(
//!         id,
//!         "my-challenge".to_string(),
//!         wasm_bytes,
//!         ChallengeConfig::default(),
//!     ).await?;
//!
//!     // Get the challenge module for evaluation
//!     if let Some(module) = loader.get_module(&id) {
//!         let score = module.evaluate(b"agent_data")?;
//!         println!("Score: {}", score);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Discovery
//!
//! The loader can automatically discover challenges from various sources:
//!
//! ```rust,ignore
//! use platform_challenge_loader::{ChallengeLoader, LoaderConfig};
//! use std::path::PathBuf;
//!
//! // Configure with filesystem discovery
//! let config = LoaderConfig::development(PathBuf::from("./challenges"));
//! let loader = ChallengeLoader::new(config)?;
//!
//! // Start discovery - will find and load challenges from the directory
//! loader.start_discovery().await?;
//!
//! // ... later ...
//! loader.stop_discovery().await?;
//! ```
//!
//! # Hot Reload
//!
//! Challenges can be hot-reloaded with new code while preserving version history:
//!
//! ```rust,ignore
//! // Hot-reload with new WASM bytes
//! let new_wasm = std::fs::read("challenge_v2.wasm")?;
//! let new_version = loader.hot_reload(&id, new_wasm).await?;
//!
//! // Rollback to a previous version if needed
//! loader.rollback(&id, 1).await?;
//! ```

pub mod discovery;
pub mod error;
pub mod loader;
pub mod registry;
pub mod versioning;

// Re-export main types at crate root
pub use discovery::{
    ChallengeDiscovery, ChallengeSource, ChallengeUpdate, CompositeDiscovery, DiscoveredChallenge,
    FilesystemDiscovery, FilesystemDiscoveryConfig, P2PDiscovery,
};
pub use error::{LoaderError, LoaderResult};
pub use loader::{ChallengeLoader, LoaderConfig, SandboxConfig};
pub use registry::{ChallengeInfo, ChallengeModule, ChallengeRegistry, LoadedChallenge};
pub use versioning::{ChallengeVersion, VersionManager};

/// Prelude module for convenient imports
pub mod prelude {
    pub use super::discovery::{
        ChallengeDiscovery, ChallengeSource, ChallengeUpdate, DiscoveredChallenge,
    };
    pub use super::error::{LoaderError, LoaderResult};
    pub use super::loader::{ChallengeLoader, LoaderConfig, SandboxConfig};
    pub use super::registry::{ChallengeInfo, ChallengeModule, ChallengeRegistry};
    pub use super::versioning::{ChallengeVersion, VersionManager};

    // Re-export commonly used types from platform-core
    pub use platform_core::{ChallengeConfig, ChallengeId};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_imports() {
        // Verify prelude contains expected types
        use crate::prelude::*;

        // These should all compile
        let _: fn() -> LoaderResult<()> = || Ok(());
        let _config = LoaderConfig::default();
        let _sandbox = SandboxConfig::default();
    }

    #[tokio::test]
    async fn test_loader_lifecycle() {
        use crate::prelude::*;

        // Create loader
        let loader = ChallengeLoader::default_loader().expect("create loader");

        // Load a challenge
        let id = ChallengeId::new();
        let wasm = vec![0u8; 100]; // Minimal WASM

        loader
            .load_challenge(
                id,
                "test".to_string(),
                wasm,
                ChallengeConfig::default(),
            )
            .await
            .expect("load");

        // Verify loaded
        assert_eq!(loader.challenge_count(), 1);
        assert!(loader.get_challenge(&id).is_some());

        // Unload
        loader.unload_challenge(&id).await.expect("unload");
        assert_eq!(loader.challenge_count(), 0);
    }

    #[test]
    fn test_error_types() {
        let err = LoaderError::ChallengeNotFound("test".to_string());
        assert!(err.to_string().contains("test"));

        let err2 = LoaderError::RegistryFull { max: 100 };
        assert!(err2.to_string().contains("100"));
    }

    #[test]
    fn test_challenge_source_variants() {
        use std::path::PathBuf;

        let fs = ChallengeSource::Filesystem(PathBuf::from("/test"));
        assert!(format!("{}", fs).contains("filesystem"));

        let p2p = ChallengeSource::P2P {
            peer_id: "peer".to_string(),
        };
        assert!(format!("{}", p2p).contains("p2p"));

        let registry = ChallengeSource::Registry {
            url: "https://example.com".to_string(),
        };
        assert!(format!("{}", registry).contains("registry"));

        let manual = ChallengeSource::Manual;
        assert_eq!(format!("{}", manual), "manual");
    }

    #[test]
    fn test_version_manager() {
        let vm = VersionManager::new();
        let id = platform_core::ChallengeId::new();

        // Initially no versions
        assert!(vm.latest_version(&id).is_none());

        // Register a version
        let version = ChallengeVersion::new(
            1,
            "hash123".to_string(),
            vec![0u8; 50],
        );
        let v = vm.register_version(id, version).expect("register");
        assert_eq!(v, 1);

        // Now has latest version
        assert_eq!(vm.latest_version(&id), Some(1));
    }
}
