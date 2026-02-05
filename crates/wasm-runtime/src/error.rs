//! Error types for the WASM runtime
//!
//! This module defines all error types used throughout the WASM runtime crate.
//! These errors cover compilation, instantiation, execution, and resource limits.

use thiserror::Error;

/// Result type alias for WASM operations
pub type Result<T> = std::result::Result<T, WasmError>;

/// WASM runtime error types
///
/// Covers all error conditions that can occur during WASM module
/// compilation, instantiation, and execution.
#[derive(Error, Debug)]
pub enum WasmError {
    /// Failed to compile WASM bytecode into a module
    #[error("Failed to compile WASM module: {0}")]
    CompileError(String),

    /// Failed to create a WASM module instance
    #[error("Failed to instantiate WASM module: {0}")]
    InstantiationError(String),

    /// Error during WASM execution (traps, panics, etc.)
    #[error("WASM execution error: {0}")]
    ExecutionError(String),

    /// Resource limits exceeded (memory, CPU, fuel)
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Module validation failed (missing exports, invalid format)
    #[error("Invalid module: {0}")]
    InvalidModule(String),

    /// Memory access error (out of bounds, null pointer)
    #[error("Memory access error: {0}")]
    MemoryError(String),

    /// Host function call failed
    #[error("Host function error: {0}")]
    HostFunctionError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<wasmtime::Error> for WasmError {
    fn from(err: wasmtime::Error) -> Self {
        let msg = err.to_string();
        // Categorize wasmtime errors based on message content
        if msg.contains("out of fuel") {
            WasmError::ResourceLimitExceeded(format!("CPU fuel exhausted: {}", msg))
        } else if msg.contains("memory") {
            WasmError::MemoryError(msg)
        } else if msg.contains("trap") {
            WasmError::ExecutionError(msg)
        } else {
            WasmError::ExecutionError(msg)
        }
    }
}

impl From<serde_json::Error> for WasmError {
    fn from(err: serde_json::Error) -> Self {
        WasmError::SerializationError(err.to_string())
    }
}

impl From<std::io::Error> for WasmError {
    fn from(err: std::io::Error) -> Self {
        WasmError::ExecutionError(format!("IO error: {}", err))
    }
}

impl From<std::string::FromUtf8Error> for WasmError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        WasmError::MemoryError(format!("Invalid UTF-8 string: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WasmError::CompileError("invalid bytecode".to_string());
        assert_eq!(
            err.to_string(),
            "Failed to compile WASM module: invalid bytecode"
        );

        let err = WasmError::ResourceLimitExceeded("memory limit 512MB".to_string());
        assert_eq!(
            err.to_string(),
            "Resource limit exceeded: memory limit 512MB"
        );

        let err = WasmError::InvalidModule("missing 'main' export".to_string());
        assert_eq!(err.to_string(), "Invalid module: missing 'main' export");
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad json").unwrap_err();
        let wasm_err: WasmError = json_err.into();
        assert!(matches!(wasm_err, WasmError::SerializationError(_)));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let wasm_err: WasmError = io_err.into();
        assert!(matches!(wasm_err, WasmError::ExecutionError(_)));
        assert!(wasm_err.to_string().contains("file not found"));
    }
}
