//! WASM runtime for executing challenge modules
//!
//! This module provides the main `WasmRuntime` struct that manages
//! WASM module compilation, instantiation, and execution.

use crate::error::{Result, WasmError};
use crate::host_functions::{create_host_state, register_host_functions, write_bytes_to_memory};
use crate::module::WasmChallengeModule;
use crate::sandbox::{ResourceUsage, SandboxConfig};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info};
use wasmtime::{Engine, Linker, Module, Store, TypedFunc};

/// WASM runtime for executing challenge modules
///
/// The runtime manages a pool of compiled modules and provides
/// methods for executing WASM functions with resource limits.
pub struct WasmRuntime {
    /// Wasmtime engine
    engine: Engine,

    /// Default sandbox configuration
    default_config: SandboxConfig,

    /// Cache of compiled modules by hash
    module_cache: Arc<RwLock<HashMap<String, Module>>>,

    /// Maximum number of cached modules
    max_cached_modules: usize,

    /// Default RNG seed
    default_rng_seed: u64,
}

impl WasmRuntime {
    /// Create a new WASM runtime with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(SandboxConfig::default())
    }

    /// Create a new WASM runtime with custom configuration
    pub fn with_config(config: SandboxConfig) -> Result<Self> {
        config
            .validate()
            .map_err(|e| WasmError::ConfigError(e.to_string()))?;

        let engine = Self::create_engine(&config)?;

        info!("Created WASM runtime with config: {:?}", config);

        Ok(Self {
            engine,
            default_config: config,
            module_cache: Arc::new(RwLock::new(HashMap::new())),
            max_cached_modules: 100,
            default_rng_seed: 0,
        })
    }

    /// Create a wasmtime engine with the given configuration
    fn create_engine(config: &SandboxConfig) -> Result<Engine> {
        let mut engine_config = wasmtime::Config::new();

        // Enable fuel consumption for CPU limiting
        engine_config.consume_fuel(true);

        // Set stack size limit
        engine_config.max_wasm_stack(config.max_stack_size);

        // Enable parallel compilation for faster module loading
        engine_config.parallel_compilation(true);

        Engine::new(&engine_config)
            .map_err(|e| WasmError::ConfigError(format!("failed to create engine: {}", e)))
    }

    /// Get the default sandbox configuration
    pub fn default_config(&self) -> &SandboxConfig {
        &self.default_config
    }

    /// Set the maximum number of cached modules
    pub fn set_max_cached_modules(&mut self, max: usize) {
        self.max_cached_modules = max;
    }

    /// Set the default RNG seed
    pub fn set_default_rng_seed(&mut self, seed: u64) {
        self.default_rng_seed = seed;
    }

    /// Calculate the hash of WASM bytecode
    pub fn hash_bytecode(bytecode: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytecode);
        hex::encode(hasher.finalize())
    }

    /// Compile a WASM module from bytecode
    ///
    /// If the module is already cached, returns the cached version.
    pub async fn compile(&self, bytecode: &[u8]) -> Result<Module> {
        let hash = Self::hash_bytecode(bytecode);

        // Check cache first
        {
            let cache = self.module_cache.read().await;
            if let Some(module) = cache.get(&hash) {
                debug!("Using cached module: {}", hash);
                return Ok(module.clone());
            }
        }

        // Compile the module
        debug!("Compiling WASM module ({} bytes)", bytecode.len());
        let start = Instant::now();

        let module = Module::new(&self.engine, bytecode)
            .map_err(|e| WasmError::CompileError(e.to_string()))?;

        let elapsed = start.elapsed();
        info!(
            "Compiled WASM module in {:?}: {} bytes, hash={}",
            elapsed,
            bytecode.len(),
            hash
        );

        // Cache the module
        {
            let mut cache = self.module_cache.write().await;

            // Evict old modules if cache is full
            if cache.len() >= self.max_cached_modules {
                // Simple eviction: remove a random entry
                if let Some(key) = cache.keys().next().cloned() {
                    cache.remove(&key);
                    debug!("Evicted module from cache: {}", key);
                }
            }

            cache.insert(hash.clone(), module.clone());
        }

        Ok(module)
    }

    /// Load a challenge module from bytecode
    pub async fn load_challenge_module(
        &self,
        name: impl Into<String>,
        version: u32,
        bytecode: &[u8],
    ) -> Result<WasmChallengeModule> {
        WasmChallengeModule::new(name, version, bytecode, self.default_config.clone())
    }

    /// Load a challenge module with custom configuration
    pub async fn load_challenge_module_with_config(
        &self,
        name: impl Into<String>,
        version: u32,
        bytecode: &[u8],
        config: SandboxConfig,
    ) -> Result<WasmChallengeModule> {
        WasmChallengeModule::new(name, version, bytecode, config)
    }

    /// Execute a WASM function that takes bytes and returns bytes
    ///
    /// This is a general-purpose execution method for WASM modules.
    /// The module must export:
    /// - `allocate(size: i32) -> i32` - allocate memory
    /// - `deallocate(ptr: i32, size: i32)` - free memory
    /// - `{function_name}(ptr: i32, len: i32) -> i32` - the function to call
    ///
    /// The function returns a pointer to a result structure in WASM memory.
    pub async fn execute(
        &self,
        bytecode: &[u8],
        function_name: &str,
        input: &[u8],
        config: Option<SandboxConfig>,
    ) -> Result<ExecutionResult> {
        let config = config.unwrap_or_else(|| self.default_config.clone());
        let start_time = Instant::now();

        // Compile or get cached module
        let module = self.compile(bytecode).await?;

        // Create store with fuel limit
        let state = create_host_state(self.default_rng_seed);
        let mut store = Store::new(&self.engine, state);
        store
            .set_fuel(config.max_fuel)
            .expect("failed to set fuel - fuel consumption should be enabled");

        // Create linker and register host functions
        let mut linker = Linker::new(&self.engine);
        register_host_functions(&mut linker, &self.engine)?;

        // Instantiate the module
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| WasmError::InstantiationError(e.to_string()))?;

        // Get memory
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| WasmError::InvalidModule("module has no 'memory' export".to_string()))?;

        // Allocate memory for input
        let alloc: TypedFunc<i32, i32> =
            instance
                .get_typed_func(&mut store, "allocate")
                .map_err(|e| {
                    WasmError::InvalidModule(format!("module has no 'allocate' function: {}", e))
                })?;

        let input_ptr = alloc
            .call(&mut store, input.len() as i32)
            .map_err(|e| WasmError::ExecutionError(format!("allocate failed: {}", e)))?;

        // Write input to WASM memory
        write_bytes_to_memory(&memory, &mut store, input_ptr, input)?;

        // Get the function to call
        let func: TypedFunc<(i32, i32), i32> = instance
            .get_typed_func(&mut store, function_name)
            .map_err(|e| {
            WasmError::InvalidModule(format!("module has no '{}' function: {}", function_name, e))
        })?;

        // Call the function
        let result_ptr = func
            .call(&mut store, (input_ptr, input.len() as i32))
            .map_err(|e| WasmError::ExecutionError(format!("{} failed: {}", function_name, e)))?;

        // Read result length from first 4 bytes at result_ptr
        let mut len_bytes = [0u8; 4];
        memory
            .read(&store, result_ptr as usize, &mut len_bytes)
            .map_err(|e| WasmError::MemoryError(format!("failed to read result length: {}", e)))?;
        let result_len = i32::from_le_bytes(len_bytes);

        // Read result data
        let output = if result_len > 0 {
            let mut data = vec![0u8; result_len as usize];
            memory
                .read(&store, (result_ptr + 4) as usize, &mut data)
                .map_err(|e| {
                    WasmError::MemoryError(format!("failed to read result data: {}", e))
                })?;
            data
        } else {
            Vec::new()
        };

        // Calculate resource usage
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = config.max_fuel.saturating_sub(fuel_remaining);
        let execution_time = start_time.elapsed();

        // Get logs from host state
        let logs = {
            let state = store.data();
            let guard = state
                .lock()
                .map_err(|e| WasmError::ExecutionError(format!("failed to lock state: {}", e)))?;
            guard.logs().to_vec()
        };

        let mut usage = ResourceUsage::new();
        usage.record_fuel(fuel_consumed);
        usage.record_time(execution_time.as_millis() as u64);

        debug!(
            "Executed {} in {:?}, fuel consumed: {}, output: {} bytes",
            function_name,
            execution_time,
            fuel_consumed,
            output.len()
        );

        Ok(ExecutionResult {
            output,
            resource_usage: usage,
            logs,
            execution_time_ms: execution_time.as_millis() as u64,
        })
    }

    /// Clear the module cache
    pub async fn clear_cache(&self) {
        let mut cache = self.module_cache.write().await;
        let count = cache.len();
        cache.clear();
        info!("Cleared {} modules from cache", count);
    }

    /// Get the number of cached modules
    pub async fn cached_module_count(&self) -> usize {
        self.module_cache.read().await.len()
    }

    /// Check if a module is cached
    pub async fn is_cached(&self, bytecode: &[u8]) -> bool {
        let hash = Self::hash_bytecode(bytecode);
        self.module_cache.read().await.contains_key(&hash)
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new().expect("failed to create default WASM runtime")
    }
}

/// Result of a WASM function execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Output bytes from the function
    pub output: Vec<u8>,

    /// Resource usage statistics
    pub resource_usage: ResourceUsage,

    /// Log messages from the WASM module
    pub logs: Vec<String>,

    /// Execution time in milliseconds
    pub execution_time_ms: u64,
}

impl ExecutionResult {
    /// Check if execution was successful (output is not empty)
    pub fn is_success(&self) -> bool {
        !self.output.is_empty()
    }

    /// Parse output as a specific type
    pub fn parse_output<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.output)
            .map_err(|e| WasmError::SerializationError(format!("failed to parse output: {}", e)))
    }
}

/// Builder for WasmRuntime
pub struct WasmRuntimeBuilder {
    config: SandboxConfig,
    max_cached_modules: usize,
    default_rng_seed: u64,
}

impl WasmRuntimeBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::default(),
            max_cached_modules: 100,
            default_rng_seed: 0,
        }
    }

    /// Set the sandbox configuration
    pub fn config(mut self, config: SandboxConfig) -> Self {
        self.config = config;
        self
    }

    /// Set maximum memory in MB
    pub fn max_memory_mb(mut self, mb: u64) -> Self {
        self.config.max_memory_mb = mb;
        self
    }

    /// Set maximum CPU time in seconds
    pub fn max_cpu_secs(mut self, secs: u64) -> Self {
        self.config.max_cpu_secs = secs;
        self
    }

    /// Set maximum fuel (instruction count)
    pub fn max_fuel(mut self, fuel: u64) -> Self {
        self.config.max_fuel = fuel;
        self
    }

    /// Set maximum cached modules
    pub fn max_cached_modules(mut self, max: usize) -> Self {
        self.max_cached_modules = max;
        self
    }

    /// Set default RNG seed
    pub fn default_rng_seed(mut self, seed: u64) -> Self {
        self.default_rng_seed = seed;
        self
    }

    /// Build the WasmRuntime
    pub fn build(self) -> Result<WasmRuntime> {
        let mut runtime = WasmRuntime::with_config(self.config)?;
        runtime.set_max_cached_modules(self.max_cached_modules);
        runtime.set_default_rng_seed(self.default_rng_seed);
        Ok(runtime)
    }
}

impl Default for WasmRuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_runtime_creation() {
        let runtime = WasmRuntime::new().expect("failed to create runtime");
        assert_eq!(runtime.default_config().max_memory_mb, 512);
    }

    #[tokio::test]
    async fn test_runtime_with_config() {
        let config = SandboxConfig::restrictive();
        let runtime = WasmRuntime::with_config(config).expect("failed to create runtime");
        assert_eq!(runtime.default_config().max_memory_mb, 128);
    }

    #[tokio::test]
    async fn test_runtime_builder() {
        let runtime = WasmRuntimeBuilder::new()
            .max_memory_mb(256)
            .max_fuel(500_000_000)
            .max_cached_modules(50)
            .default_rng_seed(12345)
            .build()
            .expect("failed to build runtime");

        assert_eq!(runtime.default_config().max_memory_mb, 256);
        assert_eq!(runtime.default_config().max_fuel, 500_000_000);
    }

    #[test]
    fn test_hash_bytecode() {
        let bytecode = b"test bytecode";
        let hash1 = WasmRuntime::hash_bytecode(bytecode);
        let hash2 = WasmRuntime::hash_bytecode(bytecode);
        assert_eq!(hash1, hash2);

        let different_bytecode = b"different bytecode";
        let hash3 = WasmRuntime::hash_bytecode(different_bytecode);
        assert_ne!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let runtime = WasmRuntime::new().expect("failed to create runtime");

        assert_eq!(runtime.cached_module_count().await, 0);
        assert!(!runtime.is_cached(b"test").await);

        // Note: Can't test actual caching without valid WASM bytecode
    }

    #[test]
    fn test_execution_result() {
        let result = ExecutionResult {
            output: b"{\"value\": 42}".to_vec(),
            resource_usage: ResourceUsage::new(),
            logs: vec!["test log".to_string()],
            execution_time_ms: 100,
        };

        assert!(result.is_success());
        assert_eq!(result.logs.len(), 1);

        #[derive(serde::Deserialize)]
        struct TestOutput {
            value: i32,
        }

        let parsed: TestOutput = result.parse_output().expect("failed to parse");
        assert_eq!(parsed.value, 42);
    }
}
