//! Sandboxing and resource limits for WASM execution
//!
//! This module provides configuration for sandboxing WASM modules,
//! including memory limits, CPU time limits, and capability restrictions.

use serde::{Deserialize, Serialize};

/// Configuration for WASM sandbox environment
///
/// Controls resource limits and capabilities for WASM module execution.
/// Default values are designed for safe challenge evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Maximum memory in megabytes that the WASM module can allocate
    pub max_memory_mb: u64,

    /// Maximum CPU time in seconds for execution
    pub max_cpu_secs: u64,

    /// Maximum fuel (instruction count) for execution
    /// Wasmtime's fuel system limits CPU usage at instruction granularity
    pub max_fuel: u64,

    /// Whether network access is allowed
    /// Note: WASM modules don't have direct network access, but this flag
    /// controls whether host functions that perform network operations are available
    pub allow_network: bool,

    /// Whether filesystem access is allowed
    /// Note: Controls availability of host functions that access the filesystem
    pub allow_filesystem: bool,

    /// Maximum stack size in bytes
    pub max_stack_size: usize,

    /// Maximum number of tables
    pub max_tables: u32,

    /// Maximum elements per table
    pub max_table_elements: u32,

    /// Maximum number of memories
    pub max_memories: u32,

    /// Maximum number of globals
    pub max_globals: u32,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            max_cpu_secs: 60,
            max_fuel: 1_000_000_000, // 1 billion instructions
            allow_network: false,
            allow_filesystem: false,
            max_stack_size: 1024 * 1024, // 1 MB stack
            max_tables: 10,
            max_table_elements: 10_000,
            max_memories: 1,
            max_globals: 1_000,
        }
    }
}

impl SandboxConfig {
    /// Create a new sandbox configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a restrictive configuration for untrusted code
    ///
    /// Uses lower limits suitable for running untrusted submissions
    pub fn restrictive() -> Self {
        Self {
            max_memory_mb: 128,
            max_cpu_secs: 30,
            max_fuel: 100_000_000, // 100 million instructions
            allow_network: false,
            allow_filesystem: false,
            max_stack_size: 512 * 1024, // 512 KB stack
            max_tables: 5,
            max_table_elements: 1_000,
            max_memories: 1,
            max_globals: 100,
        }
    }

    /// Create a permissive configuration for trusted code
    ///
    /// Uses higher limits for trusted challenge modules
    pub fn permissive() -> Self {
        Self {
            max_memory_mb: 2048,
            max_cpu_secs: 300,
            max_fuel: 10_000_000_000, // 10 billion instructions
            allow_network: false,
            allow_filesystem: false,
            max_stack_size: 4 * 1024 * 1024, // 4 MB stack
            max_tables: 100,
            max_table_elements: 100_000,
            max_memories: 10,
            max_globals: 10_000,
        }
    }

    /// Set maximum memory in megabytes
    pub fn with_max_memory_mb(mut self, mb: u64) -> Self {
        self.max_memory_mb = mb;
        self
    }

    /// Set maximum CPU time in seconds
    pub fn with_max_cpu_secs(mut self, secs: u64) -> Self {
        self.max_cpu_secs = secs;
        self
    }

    /// Set maximum fuel (instruction count)
    pub fn with_max_fuel(mut self, fuel: u64) -> Self {
        self.max_fuel = fuel;
        self
    }

    /// Enable or disable network access
    pub fn with_network(mut self, allow: bool) -> Self {
        self.allow_network = allow;
        self
    }

    /// Enable or disable filesystem access
    pub fn with_filesystem(mut self, allow: bool) -> Self {
        self.allow_filesystem = allow;
        self
    }

    /// Set maximum stack size in bytes
    pub fn with_stack_size(mut self, bytes: usize) -> Self {
        self.max_stack_size = bytes;
        self
    }

    /// Calculate memory limit in bytes
    pub fn memory_limit_bytes(&self) -> u64 {
        self.max_memory_mb * 1024 * 1024
    }

    /// Validate configuration values
    ///
    /// Returns an error if any configuration value is invalid or dangerous
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.max_memory_mb == 0 {
            return Err(ConfigValidationError::InvalidValue(
                "max_memory_mb must be greater than 0".to_string(),
            ));
        }

        if self.max_memory_mb > 16_384 {
            // 16 GB max
            return Err(ConfigValidationError::ValueTooLarge(
                "max_memory_mb cannot exceed 16384 MB".to_string(),
            ));
        }

        if self.max_fuel == 0 {
            return Err(ConfigValidationError::InvalidValue(
                "max_fuel must be greater than 0".to_string(),
            ));
        }

        if self.max_stack_size == 0 {
            return Err(ConfigValidationError::InvalidValue(
                "max_stack_size must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

/// Errors that can occur during configuration validation
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigValidationError {
    /// A configuration value is invalid
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),

    /// A configuration value exceeds safe limits
    #[error("Configuration value too large: {0}")]
    ValueTooLarge(String),
}

/// Resource usage statistics from WASM execution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Fuel consumed during execution
    pub fuel_consumed: u64,

    /// Peak memory usage in bytes
    pub peak_memory_bytes: u64,

    /// Execution wall-clock time in milliseconds
    pub execution_time_ms: u64,

    /// Number of host function calls made
    pub host_calls: u64,
}

impl ResourceUsage {
    /// Create a new empty resource usage record
    pub fn new() -> Self {
        Self::default()
    }

    /// Record fuel consumption
    pub fn record_fuel(&mut self, fuel: u64) {
        self.fuel_consumed = fuel;
    }

    /// Record peak memory usage
    pub fn record_memory(&mut self, bytes: u64) {
        if bytes > self.peak_memory_bytes {
            self.peak_memory_bytes = bytes;
        }
    }

    /// Record execution time
    pub fn record_time(&mut self, ms: u64) {
        self.execution_time_ms = ms;
    }

    /// Increment host call counter
    pub fn record_host_call(&mut self) {
        self.host_calls += 1;
    }

    /// Check if resource usage exceeds the given configuration
    pub fn exceeds_limits(&self, config: &SandboxConfig) -> Option<String> {
        if self.fuel_consumed > config.max_fuel {
            return Some(format!(
                "Fuel limit exceeded: {} > {}",
                self.fuel_consumed, config.max_fuel
            ));
        }

        let memory_limit = config.memory_limit_bytes();
        if self.peak_memory_bytes > memory_limit {
            return Some(format!(
                "Memory limit exceeded: {} bytes > {} bytes",
                self.peak_memory_bytes, memory_limit
            ));
        }

        let time_limit_ms = config.max_cpu_secs * 1000;
        if self.execution_time_ms > time_limit_ms {
            return Some(format!(
                "Time limit exceeded: {} ms > {} ms",
                self.execution_time_ms, time_limit_ms
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.max_cpu_secs, 60);
        assert_eq!(config.max_fuel, 1_000_000_000);
        assert!(!config.allow_network);
        assert!(!config.allow_filesystem);
    }

    #[test]
    fn test_restrictive_config() {
        let config = SandboxConfig::restrictive();
        assert_eq!(config.max_memory_mb, 128);
        assert_eq!(config.max_cpu_secs, 30);
        assert!(config.max_fuel < SandboxConfig::default().max_fuel);
    }

    #[test]
    fn test_permissive_config() {
        let config = SandboxConfig::permissive();
        assert_eq!(config.max_memory_mb, 2048);
        assert!(config.max_fuel > SandboxConfig::default().max_fuel);
    }

    #[test]
    fn test_builder_pattern() {
        let config = SandboxConfig::new()
            .with_max_memory_mb(256)
            .with_max_cpu_secs(120)
            .with_max_fuel(500_000_000)
            .with_network(true);

        assert_eq!(config.max_memory_mb, 256);
        assert_eq!(config.max_cpu_secs, 120);
        assert_eq!(config.max_fuel, 500_000_000);
        assert!(config.allow_network);
    }

    #[test]
    fn test_memory_limit_bytes() {
        let config = SandboxConfig::new().with_max_memory_mb(256);
        assert_eq!(config.memory_limit_bytes(), 256 * 1024 * 1024);
    }

    #[test]
    fn test_validation() {
        // Valid config
        assert!(SandboxConfig::default().validate().is_ok());

        // Invalid: zero memory
        let mut config = SandboxConfig::default();
        config.max_memory_mb = 0;
        assert!(config.validate().is_err());

        // Invalid: too much memory
        config.max_memory_mb = 20_000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_resource_usage() {
        let config = SandboxConfig::new()
            .with_max_memory_mb(128)
            .with_max_fuel(1_000_000);

        let mut usage = ResourceUsage::new();
        usage.record_fuel(500_000);
        usage.record_memory(64 * 1024 * 1024);
        usage.record_time(1000);

        // Within limits
        assert!(usage.exceeds_limits(&config).is_none());

        // Exceed fuel limit
        usage.record_fuel(2_000_000);
        assert!(usage.exceeds_limits(&config).is_some());
    }
}
