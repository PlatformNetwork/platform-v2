use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};
use wasm_runtime_interface::{
    InstanceConfig, NetworkHostFunctions, NetworkPolicy, RuntimeConfig, StorageHostConfig,
    StorageHostState, WasmModule, WasmRuntime, WasmRuntimeError,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationInput {
    pub agent_data: Vec<u8>,
    pub challenge_id: String,
    pub params: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationOutput {
    pub score: i64,
    pub valid: bool,
    pub message: String,
}

impl EvaluationOutput {
    #[allow(dead_code)]
    pub fn success(score: i64, message: &str) -> Self {
        Self {
            score,
            valid: true,
            message: String::from(message),
        }
    }

    #[allow(dead_code)]
    pub fn failure(message: &str) -> Self {
        Self {
            score: 0,
            valid: false,
            message: String::from(message),
        }
    }
}

pub struct WasmExecutorConfig {
    pub module_dir: PathBuf,
    pub max_memory_bytes: u64,
    pub enable_fuel: bool,
    pub fuel_limit: Option<u64>,
    pub storage_host_config: StorageHostConfig,
}

impl Default for WasmExecutorConfig {
    fn default() -> Self {
        Self {
            module_dir: PathBuf::from("./wasm_modules"),
            max_memory_bytes: 512 * 1024 * 1024,
            enable_fuel: false,
            fuel_limit: None,
            storage_host_config: StorageHostConfig::default(),
        }
    }
}

pub struct ExecutionMetrics {
    pub execution_time_ms: u128,
    pub memory_used_bytes: u64,
    pub network_requests_made: u32,
    pub fuel_consumed: Option<u64>,
}

pub struct WasmChallengeExecutor {
    runtime: WasmRuntime,
    config: WasmExecutorConfig,
    module_cache: RwLock<HashMap<String, Arc<WasmModule>>>,
}

impl WasmChallengeExecutor {
    pub fn new(config: WasmExecutorConfig) -> Result<Self> {
        let runtime_config = RuntimeConfig {
            max_memory_bytes: config.max_memory_bytes,
            max_instances: 32,
            allow_fuel: config.enable_fuel,
            fuel_limit: config.fuel_limit,
        };

        let runtime = WasmRuntime::new(runtime_config)
            .map_err(|e| anyhow::anyhow!("Failed to create WASM runtime: {}", e))?;

        info!(
            module_dir = %config.module_dir.display(),
            max_memory_bytes = config.max_memory_bytes,
            fuel_enabled = config.enable_fuel,
            "WASM challenge executor initialized"
        );

        Ok(Self {
            runtime,
            config,
            module_cache: RwLock::new(HashMap::new()),
        })
    }

    pub fn execute_evaluation(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        agent_data: &[u8],
        challenge_id: &str,
        params: &[u8],
    ) -> Result<(EvaluationOutput, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let input = EvaluationInput {
            agent_data: agent_data.to_vec(),
            challenge_id: challenge_id.to_string(),
            params: params.to_vec(),
        };

        let serialized =
            bincode::serialize(&input).context("Failed to serialize EvaluationInput")?;

        let network_host_fns = Arc::new(NetworkHostFunctions::all());

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: challenge_id.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, Some(network_host_fns))
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let _storage_state = StorageHostState::new(
            challenge_id.to_string(),
            self.config.storage_host_config.clone(),
        );

        let initial_fuel = instance.fuel_remaining();

        let alloc_result = instance.call_i32_i32_return_i32("alloc", serialized.len() as i32, 0);
        let ptr = match alloc_result {
            Ok(p) => p,
            Err(_) => {
                let mem_size = instance.memory().data_size(instance.store());
                let offset = mem_size.saturating_sub(serialized.len() + 1024);
                if offset == 0 {
                    return Err(anyhow::anyhow!(
                        "WASM module has insufficient memory for input data"
                    ));
                }
                offset as i32
            }
        };

        instance
            .write_memory(ptr as usize, &serialized)
            .map_err(|e| anyhow::anyhow!("Failed to write input data to WASM memory: {}", e))?;

        let result = instance
            .call_i32_i32_return_i64("evaluate", ptr, serialized.len() as i32)
            .map_err(|e| match &e {
                WasmRuntimeError::FuelExhausted => {
                    anyhow::anyhow!("WASM execution exceeded fuel limit")
                }
                WasmRuntimeError::Execution(msg) if msg.contains("timeout") => {
                    anyhow::anyhow!("WASM execution timed out")
                }
                _ => anyhow::anyhow!("WASM evaluate call failed: {}", e),
            })?;

        let out_len = (result >> 32) as i32;
        let out_ptr = result as i32;

        if out_ptr == 0 && out_len == 0 {
            return Err(anyhow::anyhow!(
                "WASM evaluate returned null pointer, deserialization failed inside module"
            ));
        }

        let output_bytes = instance
            .read_memory(out_ptr as usize, out_len as usize)
            .map_err(|e| {
                anyhow::anyhow!("Failed to read evaluation output from WASM memory: {}", e)
            })?;

        let output: EvaluationOutput = bincode::deserialize(&output_bytes)
            .context("Failed to deserialize EvaluationOutput from WASM module")?;

        let fuel_consumed = match (initial_fuel, instance.fuel_remaining()) {
            (Some(initial), Some(remaining)) => Some(initial.saturating_sub(remaining)),
            _ => None,
        };

        let metrics = ExecutionMetrics {
            execution_time_ms: start.elapsed().as_millis(),
            memory_used_bytes: instance.memory().data_size(instance.store()) as u64,
            network_requests_made: instance.network_requests_made(),
            fuel_consumed,
        };

        info!(
            module = module_path,
            challenge_id,
            score = output.score,
            valid = output.valid,
            message = %output.message,
            execution_time_ms = metrics.execution_time_ms,
            memory_bytes = metrics.memory_used_bytes,
            network_requests = metrics.network_requests_made,
            fuel_consumed = ?metrics.fuel_consumed,
            "WASM evaluation completed"
        );

        Ok((output, metrics))
    }

    #[allow(dead_code)]
    pub fn execute_validation(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        agent_data: &[u8],
        challenge_id: &str,
        params: &[u8],
    ) -> Result<(bool, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let input = EvaluationInput {
            agent_data: agent_data.to_vec(),
            challenge_id: challenge_id.to_string(),
            params: params.to_vec(),
        };

        let serialized =
            bincode::serialize(&input).context("Failed to serialize EvaluationInput")?;

        let network_host_fns = Arc::new(NetworkHostFunctions::all());

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: challenge_id.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, Some(network_host_fns))
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let _storage_state = StorageHostState::new(
            challenge_id.to_string(),
            self.config.storage_host_config.clone(),
        );

        let initial_fuel = instance.fuel_remaining();

        let alloc_result = instance.call_i32_i32_return_i32("alloc", serialized.len() as i32, 0);
        let ptr = match alloc_result {
            Ok(p) => p,
            Err(_) => {
                let mem_size = instance.memory().data_size(instance.store());
                let offset = mem_size.saturating_sub(serialized.len() + 1024);
                if offset == 0 {
                    return Err(anyhow::anyhow!(
                        "WASM module has insufficient memory for input data"
                    ));
                }
                offset as i32
            }
        };

        instance
            .write_memory(ptr as usize, &serialized)
            .map_err(|e| anyhow::anyhow!("Failed to write input data to WASM memory: {}", e))?;

        let result = instance
            .call_i32_i32_return_i32("validate", ptr, serialized.len() as i32)
            .map_err(|e| match &e {
                WasmRuntimeError::FuelExhausted => {
                    anyhow::anyhow!("WASM execution exceeded fuel limit")
                }
                WasmRuntimeError::Execution(msg) if msg.contains("timeout") => {
                    anyhow::anyhow!("WASM execution timed out")
                }
                _ => anyhow::anyhow!("WASM validate call failed: {}", e),
            })?;

        let valid = result != 0;

        let fuel_consumed = match (initial_fuel, instance.fuel_remaining()) {
            (Some(initial), Some(remaining)) => Some(initial.saturating_sub(remaining)),
            _ => None,
        };

        let metrics = ExecutionMetrics {
            execution_time_ms: start.elapsed().as_millis(),
            memory_used_bytes: instance.memory().data_size(instance.store()) as u64,
            network_requests_made: instance.network_requests_made(),
            fuel_consumed,
        };

        info!(
            module = module_path,
            challenge_id,
            valid,
            execution_time_ms = metrics.execution_time_ms,
            memory_bytes = metrics.memory_used_bytes,
            network_requests = metrics.network_requests_made,
            fuel_consumed = ?metrics.fuel_consumed,
            "WASM validation completed"
        );

        Ok((valid, metrics))
    }

    fn load_module(&self, module_path: &str) -> Result<Arc<WasmModule>> {
        {
            let cache = self.module_cache.read();
            if let Some(module) = cache.get(module_path) {
                debug!(module = module_path, "WASM module loaded from cache");
                return Ok(Arc::clone(module));
            }
        }

        let full_path = self.config.module_dir.join(module_path);
        let wasm_bytes = std::fs::read(&full_path)
            .with_context(|| format!("Failed to read WASM module from {}", full_path.display()))?;

        info!(
            module = module_path,
            size_bytes = wasm_bytes.len(),
            "Compiling WASM module"
        );

        let module = self
            .runtime
            .compile_module(&wasm_bytes)
            .map_err(|e| anyhow::anyhow!("WASM compilation failed: {}", e))?;

        let module = Arc::new(module);

        {
            let mut cache = self.module_cache.write();
            cache.insert(module_path.to_string(), Arc::clone(&module));
        }

        info!(module = module_path, "WASM module compiled and cached");
        Ok(module)
    }

    #[allow(dead_code)]
    pub fn invalidate_cache(&self, module_path: &str) {
        let mut cache = self.module_cache.write();
        if cache.remove(module_path).is_some() {
            info!(module = module_path, "WASM module cache entry invalidated");
        }
    }

    #[allow(dead_code)]
    pub fn clear_cache(&self) {
        let mut cache = self.module_cache.write();
        let count = cache.len();
        cache.clear();
        info!(cleared = count, "WASM module cache cleared");
    }

    #[allow(dead_code)]
    pub fn cached_module_count(&self) -> usize {
        self.module_cache.read().len()
    }

    pub fn resolve_module_path(&self, module_path: &str) -> PathBuf {
        self.config.module_dir.join(module_path)
    }

    pub fn module_exists(&self, module_path: &str) -> bool {
        self.resolve_module_path(module_path).exists()
    }
}
