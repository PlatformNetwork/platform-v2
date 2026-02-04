//! Challenge module abstraction
//!
//! This module defines the `ChallengeModule` trait for challenge evaluation
//! and provides the `WasmChallengeModule` implementation for WASM-based challenges.

use crate::error::{Result, WasmError};
use crate::host_functions::{
    create_host_state, register_host_functions, write_bytes_to_memory, SharedHostState,
};
use crate::sandbox::{ResourceUsage, SandboxConfig};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

use tracing::{debug, error, info, trace, warn};
use wasmtime::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

/// Trait for challenge modules
///
/// Challenge modules can validate agent submissions and calculate scores.
/// Implementations can be WASM-based or native.
#[async_trait]
pub trait ChallengeModule: Send + Sync {
    /// Get the challenge name
    fn name(&self) -> &str;

    /// Get the challenge version (numeric for easy comparison)
    fn version(&self) -> u32;

    /// Validate an agent submission
    ///
    /// Returns true if the submission format is valid, false otherwise.
    /// This does not evaluate the quality of the submission, only its format.
    async fn validate(&self, agent_data: &[u8]) -> Result<bool>;

    /// Calculate score for an evaluation result
    ///
    /// Takes the raw evaluation result data and returns a normalized score (0.0 to 1.0).
    async fn calculate_score(&self, result_data: &[u8]) -> Result<f64>;

    /// Get task configuration as JSON
    ///
    /// Returns challenge-specific configuration that miners need to know.
    fn get_config(&self) -> Result<serde_json::Value>;
}

/// WASM-based challenge module
///
/// Loads and executes WASM bytecode for challenge evaluation.
pub struct WasmChallengeModule {
    /// Challenge name
    name: String,

    /// Challenge version
    version: u32,

    /// Compiled WASM module
    module: Module,

    /// Wasmtime engine
    engine: Engine,

    /// Sandbox configuration
    config: SandboxConfig,

    /// Hash of the WASM bytecode (for verification)
    bytecode_hash: String,

    /// Challenge configuration (cached)
    challenge_config: serde_json::Value,

    /// RNG seed for deterministic execution
    rng_seed: u64,
}

impl WasmChallengeModule {
    /// Create a new WASM challenge module from bytecode
    ///
    /// # Arguments
    /// * `name` - Challenge name
    /// * `version` - Challenge version
    /// * `bytecode` - WASM module bytecode
    /// * `config` - Sandbox configuration
    ///
    /// # Returns
    /// A new WasmChallengeModule or an error
    pub fn new(
        name: impl Into<String>,
        version: u32,
        bytecode: &[u8],
        config: SandboxConfig,
    ) -> Result<Self> {
        let name = name.into();
        info!(
            "Loading WASM challenge module: {} v{}",
            name, version
        );

        // Validate config
        config
            .validate()
            .map_err(|e| WasmError::ConfigError(e.to_string()))?;

        // Calculate bytecode hash
        let mut hasher = Sha256::new();
        hasher.update(bytecode);
        let bytecode_hash = hex::encode(hasher.finalize());

        debug!("WASM bytecode hash: {}", bytecode_hash);

        // Create engine with resource limits
        let engine = Self::create_engine(&config)?;

        // Compile the module
        let module = Module::new(&engine, bytecode)
            .map_err(|e| WasmError::CompileError(e.to_string()))?;

        info!(
            "Successfully compiled WASM module: {} ({} bytes)",
            name,
            bytecode.len()
        );

        Ok(Self {
            name,
            version,
            module,
            engine,
            config,
            bytecode_hash,
            challenge_config: serde_json::json!({}),
            rng_seed: 0,
        })
    }

    /// Create a new WASM challenge module with custom configuration
    pub fn with_config(
        name: impl Into<String>,
        version: u32,
        bytecode: &[u8],
        sandbox_config: SandboxConfig,
        challenge_config: serde_json::Value,
        rng_seed: u64,
    ) -> Result<Self> {
        let mut module = Self::new(name, version, bytecode, sandbox_config)?;
        module.challenge_config = challenge_config;
        module.rng_seed = rng_seed;
        Ok(module)
    }

    /// Create a wasmtime engine with the sandbox configuration
    fn create_engine(config: &SandboxConfig) -> Result<Engine> {
        let mut engine_config = wasmtime::Config::new();

        // Enable fuel consumption for CPU limiting
        engine_config.consume_fuel(true);

        // Set memory limits
        engine_config.max_wasm_stack(config.max_stack_size);

        // Create engine
        Engine::new(&engine_config)
            .map_err(|e| WasmError::ConfigError(format!("failed to create engine: {}", e)))
    }

    /// Create a store with the shared host state
    fn create_store(&self) -> Store<SharedHostState> {
        let state = create_host_state(self.rng_seed);
        let mut store = Store::new(&self.engine, state);

        // Set fuel limit
        store
            .set_fuel(self.config.max_fuel)
            .expect("failed to set fuel - fuel consumption should be enabled");

        store
    }

    /// Create an instance of the WASM module
    fn create_instance(&self, store: &mut Store<SharedHostState>) -> Result<Instance> {
        let mut linker = Linker::new(&self.engine);

        // Register host functions
        register_host_functions(&mut linker, &self.engine)?;

        // Instantiate the module
        let instance = linker
            .instantiate(&mut *store, &self.module)
            .map_err(|e| WasmError::InstantiationError(e.to_string()))?;

        Ok(instance)
    }

    /// Get the memory export from an instance
    fn get_memory(&self, store: &mut Store<SharedHostState>, instance: &Instance) -> Result<Memory> {
        instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| WasmError::InvalidModule("module has no 'memory' export".to_string()))
    }

    /// Allocate memory in the WASM module
    ///
    /// Calls the module's `allocate` function to get a pointer to allocated memory.
    fn allocate(
        &self,
        store: &mut Store<SharedHostState>,
        instance: &Instance,
        size: i32,
    ) -> Result<i32> {
        let alloc: TypedFunc<i32, i32> = instance
            .get_typed_func(&mut *store, "allocate")
            .map_err(|e| {
                WasmError::InvalidModule(format!("module has no 'allocate' function: {}", e))
            })?;

        alloc
            .call(&mut *store, size)
            .map_err(|e| WasmError::ExecutionError(format!("allocate failed: {}", e)))
    }

    /// Deallocate memory in the WASM module
    ///
    /// Calls the module's `deallocate` function to free allocated memory.
    fn deallocate(
        &self,
        store: &mut Store<SharedHostState>,
        instance: &Instance,
        ptr: i32,
        size: i32,
    ) -> Result<()> {
        let dealloc: TypedFunc<(i32, i32), ()> = instance
            .get_typed_func(&mut *store, "deallocate")
            .map_err(|e| {
                WasmError::InvalidModule(format!("module has no 'deallocate' function: {}", e))
            })?;

        dealloc
            .call(&mut *store, (ptr, size))
            .map_err(|e| WasmError::ExecutionError(format!("deallocate failed: {}", e)))
    }

    /// Call a validation function in the WASM module
    ///
    /// The WASM module should export: `validate(ptr: i32, len: i32) -> i32`
    /// Returns 1 for valid, 0 for invalid, negative for error
    fn call_validate(
        &self,
        store: &mut Store<SharedHostState>,
        instance: &Instance,
        data: &[u8],
    ) -> Result<i32> {
        let memory = self.get_memory(store, instance)?;

        // Allocate memory for input data
        let ptr = self.allocate(store, instance, data.len() as i32)?;

        // Write data to WASM memory
        write_bytes_to_memory(&memory, &mut *store, ptr, data)?;

        // Get the validate function
        let validate: TypedFunc<(i32, i32), i32> = instance
            .get_typed_func(&mut *store, "validate")
            .map_err(|e| {
                WasmError::InvalidModule(format!("module has no 'validate' function: {}", e))
            })?;

        // Call validate
        let result = validate
            .call(&mut *store, (ptr, data.len() as i32))
            .map_err(|e| WasmError::ExecutionError(format!("validate failed: {}", e)))?;

        // Deallocate input memory
        if let Err(e) = self.deallocate(store, instance, ptr, data.len() as i32) {
            warn!("Failed to deallocate memory after validate: {}", e);
        }

        Ok(result)
    }

    /// Call a scoring function in the WASM module
    ///
    /// The WASM module should export: `calculate_score(ptr: i32, len: i32) -> i64`
    /// Returns the score as a fixed-point number (score * 1_000_000)
    fn call_calculate_score(
        &self,
        store: &mut Store<SharedHostState>,
        instance: &Instance,
        data: &[u8],
    ) -> Result<i64> {
        let memory = self.get_memory(store, instance)?;

        // Allocate memory for input data
        let ptr = self.allocate(store, instance, data.len() as i32)?;

        // Write data to WASM memory
        write_bytes_to_memory(&memory, &mut *store, ptr, data)?;

        // Get the calculate_score function
        let calculate_score: TypedFunc<(i32, i32), i64> = instance
            .get_typed_func(&mut *store, "calculate_score")
            .map_err(|e| {
                WasmError::InvalidModule(format!("module has no 'calculate_score' function: {}", e))
            })?;

        // Call calculate_score
        let result = calculate_score
            .call(&mut *store, (ptr, data.len() as i32))
            .map_err(|e| WasmError::ExecutionError(format!("calculate_score failed: {}", e)))?;

        // Deallocate input memory
        if let Err(e) = self.deallocate(store, instance, ptr, data.len() as i32) {
            warn!("Failed to deallocate memory after calculate_score: {}", e);
        }

        Ok(result)
    }

    /// Get the resource usage from the store
    fn get_resource_usage(&self, store: &Store<SharedHostState>) -> ResourceUsage {
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = self.config.max_fuel.saturating_sub(fuel_remaining);

        let mut usage = ResourceUsage::new();
        usage.record_fuel(fuel_consumed);
        usage
    }

    /// Get the bytecode hash
    pub fn bytecode_hash(&self) -> &str {
        &self.bytecode_hash
    }

    /// Get the sandbox configuration
    pub fn sandbox_config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Set the RNG seed for deterministic execution
    pub fn set_rng_seed(&mut self, seed: u64) {
        self.rng_seed = seed;
    }

    /// Set the challenge configuration
    pub fn set_challenge_config(&mut self, config: serde_json::Value) {
        self.challenge_config = config;
    }
}

#[async_trait]
impl ChallengeModule for WasmChallengeModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> u32 {
        self.version
    }

    async fn validate(&self, agent_data: &[u8]) -> Result<bool> {
        trace!(
            "Validating agent data ({} bytes) for challenge {}",
            agent_data.len(),
            self.name
        );

        let mut store = self.create_store();
        let instance = self.create_instance(&mut store)?;

        let result = self.call_validate(&mut store, &instance, agent_data)?;
        let usage = self.get_resource_usage(&store);

        debug!(
            "Validation complete: result={}, fuel_consumed={}",
            result, usage.fuel_consumed
        );

        // Result: 1 = valid, 0 = invalid, negative = error
        match result {
            1 => Ok(true),
            0 => Ok(false),
            code => {
                error!("Validation returned error code: {}", code);
                Err(WasmError::ExecutionError(format!(
                    "validation returned error code: {}",
                    code
                )))
            }
        }
    }

    async fn calculate_score(&self, result_data: &[u8]) -> Result<f64> {
        trace!(
            "Calculating score for result data ({} bytes) for challenge {}",
            result_data.len(),
            self.name
        );

        let mut store = self.create_store();
        let instance = self.create_instance(&mut store)?;

        let score_fixed = self.call_calculate_score(&mut store, &instance, result_data)?;
        let usage = self.get_resource_usage(&store);

        // Convert fixed-point to float (score * 1_000_000 -> score)
        let score = (score_fixed as f64) / 1_000_000.0;

        // Clamp to valid range
        let score = score.clamp(0.0, 1.0);

        debug!(
            "Score calculation complete: score={:.6}, fuel_consumed={}",
            score, usage.fuel_consumed
        );

        Ok(score)
    }

    fn get_config(&self) -> Result<serde_json::Value> {
        Ok(self.challenge_config.clone())
    }
}

/// Builder for creating WasmChallengeModule instances
pub struct WasmChallengeModuleBuilder {
    name: String,
    version: u32,
    bytecode: Vec<u8>,
    sandbox_config: SandboxConfig,
    challenge_config: serde_json::Value,
    rng_seed: u64,
}

impl WasmChallengeModuleBuilder {
    /// Create a new builder with required parameters
    pub fn new(name: impl Into<String>, version: u32, bytecode: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            version,
            bytecode,
            sandbox_config: SandboxConfig::default(),
            challenge_config: serde_json::json!({}),
            rng_seed: 0,
        }
    }

    /// Set the sandbox configuration
    pub fn sandbox_config(mut self, config: SandboxConfig) -> Self {
        self.sandbox_config = config;
        self
    }

    /// Set the challenge configuration
    pub fn challenge_config(mut self, config: serde_json::Value) -> Self {
        self.challenge_config = config;
        self
    }

    /// Set the RNG seed
    pub fn rng_seed(mut self, seed: u64) -> Self {
        self.rng_seed = seed;
        self
    }

    /// Build the WasmChallengeModule
    pub fn build(self) -> Result<WasmChallengeModule> {
        WasmChallengeModule::with_config(
            self.name,
            self.version,
            &self.bytecode,
            self.sandbox_config,
            self.challenge_config,
            self.rng_seed,
        )
    }
}

/// A simple mock challenge module for testing
#[cfg(test)]
pub struct MockChallengeModule {
    name: String,
    version: u32,
    validate_result: bool,
    score: f64,
    config: serde_json::Value,
}

#[cfg(test)]
impl MockChallengeModule {
    pub fn new(name: &str, version: u32) -> Self {
        Self {
            name: name.to_string(),
            version,
            validate_result: true,
            score: 0.5,
            config: serde_json::json!({}),
        }
    }

    pub fn with_validate_result(mut self, result: bool) -> Self {
        self.validate_result = result;
        self
    }

    pub fn with_score(mut self, score: f64) -> Self {
        self.score = score;
        self
    }
}

#[cfg(test)]
#[async_trait]
impl ChallengeModule for MockChallengeModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> u32 {
        self.version
    }

    async fn validate(&self, _agent_data: &[u8]) -> Result<bool> {
        Ok(self.validate_result)
    }

    async fn calculate_score(&self, _result_data: &[u8]) -> Result<f64> {
        Ok(self.score)
    }

    fn get_config(&self) -> Result<serde_json::Value> {
        Ok(self.config.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_challenge_module() {
        let module = MockChallengeModule::new("test-challenge", 1)
            .with_validate_result(true)
            .with_score(0.75);

        assert_eq!(module.name(), "test-challenge");
        assert_eq!(module.version(), 1);

        let valid = module.validate(b"test data").await.expect("validate failed");
        assert!(valid);

        let score = module
            .calculate_score(b"result data")
            .await
            .expect("calculate_score failed");
        assert!((score - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_wasm_challenge_module_builder() {
        // Use empty bytecode - will fail compilation but tests the builder pattern
        let builder = WasmChallengeModuleBuilder::new("test", 1, vec![])
            .sandbox_config(SandboxConfig::restrictive())
            .challenge_config(serde_json::json!({"key": "value"}))
            .rng_seed(12345);

        // Building will fail because bytecode is invalid, but builder works
        let result = builder.build();
        assert!(result.is_err());
    }
}
