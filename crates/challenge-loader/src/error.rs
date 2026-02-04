//! Error types for the challenge loader
//!
//! This module defines all error types that can occur during challenge loading,
//! registration, discovery, and hot-reload operations.

use thiserror::Error;

/// Result type alias for loader operations
pub type LoaderResult<T> = Result<T, LoaderError>;

/// Errors that can occur in the challenge loader
#[derive(Error, Debug)]
pub enum LoaderError {
    /// Challenge with the specified ID was not found
    #[error("Challenge not found: {0}")]
    ChallengeNotFound(String),

    /// Attempted to load a challenge that is already loaded
    #[error("Challenge already loaded: {0}")]
    AlreadyLoaded(String),

    /// The challenge data or configuration is invalid
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),

    /// Version conflict during update or registration
    #[error("Version conflict: {0}")]
    VersionConflict(String),

    /// Error during WASM module compilation or execution
    #[error("WASM error: {0}")]
    WasmError(String),

    /// File system I/O error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Discovery operation failed
    #[error("Discovery error: {0}")]
    DiscoveryError(String),

    /// Hash verification failed
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Hot-reload operation failed
    #[error("Hot-reload failed: {0}")]
    HotReloadFailed(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Registry is at maximum capacity
    #[error("Registry full: maximum {max} challenges allowed")]
    RegistryFull { max: usize },

    /// Channel communication error
    #[error("Channel error: {0}")]
    ChannelError(String),

    /// Internal unexpected error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for LoaderError {
    fn from(err: serde_json::Error) -> Self {
        LoaderError::SerializationError(err.to_string())
    }
}

impl From<tokio::sync::mpsc::error::SendError<super::discovery::ChallengeUpdate>> for LoaderError {
    fn from(err: tokio::sync::mpsc::error::SendError<super::discovery::ChallengeUpdate>) -> Self {
        LoaderError::ChannelError(format!("Failed to send challenge update: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_challenge_not_found() {
        let err = LoaderError::ChallengeNotFound("test-id".to_string());
        assert_eq!(err.to_string(), "Challenge not found: test-id");
    }

    #[test]
    fn test_error_display_already_loaded() {
        let err = LoaderError::AlreadyLoaded("my-challenge".to_string());
        assert_eq!(err.to_string(), "Challenge already loaded: my-challenge");
    }

    #[test]
    fn test_error_display_invalid_challenge() {
        let err = LoaderError::InvalidChallenge("missing WASM header".to_string());
        assert_eq!(err.to_string(), "Invalid challenge: missing WASM header");
    }

    #[test]
    fn test_error_display_version_conflict() {
        let err = LoaderError::VersionConflict("v1.0.0 vs v1.0.1".to_string());
        assert_eq!(err.to_string(), "Version conflict: v1.0.0 vs v1.0.1");
    }

    #[test]
    fn test_error_display_wasm_error() {
        let err = LoaderError::WasmError("compilation failed".to_string());
        assert_eq!(err.to_string(), "WASM error: compilation failed");
    }

    #[test]
    fn test_error_display_hash_mismatch() {
        let err = LoaderError::HashMismatch {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Hash mismatch: expected abc123, got def456"
        );
    }

    #[test]
    fn test_error_display_registry_full() {
        let err = LoaderError::RegistryFull { max: 100 };
        assert_eq!(
            err.to_string(),
            "Registry full: maximum 100 challenges allowed"
        );
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let loader_err: LoaderError = io_err.into();
        match loader_err {
            LoaderError::IoError(e) => {
                assert!(e.to_string().contains("file not found"));
            }
            other => panic!("Expected IoError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_result: Result<serde_json::Value, _> = serde_json::from_str("{invalid}");
        let json_err = json_result.unwrap_err();
        let loader_err: LoaderError = json_err.into();
        match loader_err {
            LoaderError::SerializationError(msg) => {
                assert!(!msg.is_empty());
            }
            other => panic!("Expected SerializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_all_error_variants_debug() {
        let errors: Vec<LoaderError> = vec![
            LoaderError::ChallengeNotFound("id".to_string()),
            LoaderError::AlreadyLoaded("id".to_string()),
            LoaderError::InvalidChallenge("reason".to_string()),
            LoaderError::VersionConflict("conflict".to_string()),
            LoaderError::WasmError("wasm".to_string()),
            LoaderError::SerializationError("serde".to_string()),
            LoaderError::DiscoveryError("discovery".to_string()),
            LoaderError::HashMismatch {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
            LoaderError::HotReloadFailed("reload".to_string()),
            LoaderError::ConfigError("config".to_string()),
            LoaderError::RegistryFull { max: 10 },
            LoaderError::ChannelError("channel".to_string()),
            LoaderError::Internal("internal".to_string()),
        ];

        for err in errors {
            let debug_str = format!("{:?}", err);
            assert!(!debug_str.is_empty());
        }
    }
}
