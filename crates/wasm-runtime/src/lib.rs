//! Platform WASM Runtime
//!
//! This crate provides a sandboxed WASM runtime for executing challenge modules.
//! It uses wasmtime as the underlying WASM engine with configurable resource limits.
//!
//! # Features
//!
//! - **Sandboxed Execution**: Resource limits for memory, CPU, and fuel
//! - **Host Functions**: Logging, timestamps, and deterministic random number generation
//! - **Challenge Module Trait**: Abstract interface for challenge evaluation
//! - **WASM Challenge Modules**: Load and execute WASM-based challenges
//! - **Module Caching**: Compiled modules are cached for faster subsequent loads
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use platform_wasm_runtime::{WasmRuntime, SandboxConfig, ChallengeModule};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a runtime with default configuration
//!     let runtime = WasmRuntime::new()?;
//!
//!     // Load a challenge module from WASM bytecode
//!     let bytecode = std::fs::read("challenge.wasm")?;
//!     let module = runtime.load_challenge_module("my-challenge", 1, &bytecode).await?;
//!
//!     // Validate a submission
//!     let is_valid = module.validate(b"submission data").await?;
//!
//!     // Calculate a score
//!     let score = module.calculate_score(b"result data").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Custom Configuration
//!
//! ```rust,ignore
//! use platform_wasm_runtime::{WasmRuntimeBuilder, SandboxConfig};
//!
//! let runtime = WasmRuntimeBuilder::new()
//!     .max_memory_mb(256)
//!     .max_fuel(500_000_000)
//!     .max_cached_modules(50)
//!     .build()?;
//! ```
//!
//! # WASM Module Requirements
//!
//! WASM modules must export the following functions:
//!
//! - `allocate(size: i32) -> i32` - Allocate memory and return pointer
//! - `deallocate(ptr: i32, size: i32)` - Free allocated memory
//! - `validate(ptr: i32, len: i32) -> i32` - Validate submission (1=valid, 0=invalid)
//! - `calculate_score(ptr: i32, len: i32) -> i64` - Calculate score (fixed-point * 1_000_000)
//!
//! # Host Functions
//!
//! The following host functions are available to WASM modules:
//!
//! - `host_log(ptr: i32, len: i32)` - Log a message
//! - `host_get_timestamp() -> i64` - Get Unix timestamp in seconds
//! - `host_get_timestamp_millis() -> i64` - Get Unix timestamp in milliseconds
//! - `host_random_bytes(ptr: i32, len: i32) -> i32` - Get deterministic random bytes
//! - `host_abort(msg_ptr, msg_len, file_ptr, file_len, line, col)` - Abort with error
//! - `host_debug_i32(value: i32)` - Debug print i32
//! - `host_debug_i64(value: i64)` - Debug print i64
//! - `host_debug_f64(value: f64)` - Debug print f64

#![allow(dead_code)]

pub mod error;
pub mod host_functions;
pub mod module;
pub mod runtime;
pub mod sandbox;

// Re-export main types
pub use error::{Result, WasmError};
pub use host_functions::{
    create_host_state, read_bytes_from_memory, read_string_from_memory, write_bytes_to_memory,
    HostState, SharedHostState,
};
pub use module::{ChallengeModule, WasmChallengeModule, WasmChallengeModuleBuilder};
pub use runtime::{ExecutionResult, WasmRuntime, WasmRuntimeBuilder};
pub use sandbox::{ConfigValidationError, ResourceUsage, SandboxConfig};

/// Prelude for common imports
pub mod prelude {
    pub use crate::error::{Result, WasmError};
    pub use crate::module::ChallengeModule;
    pub use crate::runtime::{ExecutionResult, WasmRuntime, WasmRuntimeBuilder};
    pub use crate::sandbox::{ResourceUsage, SandboxConfig};
    pub use async_trait::async_trait;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        // Verify main types are exported
        let _ = SandboxConfig::default();
        let _ = ResourceUsage::new();
    }

    #[tokio::test]
    async fn test_runtime_default() {
        let runtime = WasmRuntime::new().expect("failed to create runtime");
        assert_eq!(runtime.cached_module_count().await, 0);
    }
}
