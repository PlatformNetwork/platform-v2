use crate::{NetworkAuditLogger, NetworkPolicy, NetworkState};
use std::sync::Arc;
use thiserror::Error;
use tracing::info;
use wasmtime::{
    Config, Engine, Error as WasmtimeError, Func, Instance, Linker, Memory, Module,
    ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, Val,
};

pub const DEFAULT_WASM_MEMORY_NAME: &str = "memory";

#[derive(Debug, Error)]
pub enum WasmRuntimeError {
    #[error("module compile failed: {0}")]
    Compile(String),
    #[error("module instantiation failed: {0}")]
    Instantiate(String),
    #[error("host function registration failed: {0}")]
    HostFunction(String),
    #[error("missing export: {0}")]
    MissingExport(String),
    #[error("memory error: {0}")]
    Memory(String),
    #[error("execution error: {0}")]
    Execution(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("fuel exhausted")]
    FuelExhausted,
    #[error("policy violation: {0}")]
    PolicyViolation(String),
}

impl From<WasmtimeError> for WasmRuntimeError {
    fn from(err: WasmtimeError) -> Self {
        let msg = err.to_string();
        if msg.contains("fuel") {
            Self::FuelExhausted
        } else {
            Self::Execution(msg)
        }
    }
}

impl From<std::io::Error> for WasmRuntimeError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

pub trait HostFunctionRegistrar: Send + Sync {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError>;
}

#[derive(Clone)]
pub struct RuntimeConfig {
    pub max_memory_bytes: u64,
    pub max_instances: u32,
    pub allow_fuel: bool,
    pub fuel_limit: Option<u64>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 512 * 1024 * 1024,
            max_instances: 32,
            allow_fuel: false,
            fuel_limit: None,
        }
    }
}

#[derive(Clone)]
pub struct InstanceConfig {
    /// Network policy enforced by host functions.
    pub network_policy: NetworkPolicy,
    /// Optional audit logger for network calls.
    pub audit_logger: Option<Arc<dyn NetworkAuditLogger>>,
    /// Wasm memory export name.
    pub memory_export: String,
    /// Identifier used in audit logs.
    pub challenge_id: String,
    /// Validator identifier used in audit logs.
    pub validator_id: String,
    /// Restartable configuration identifier.
    pub restart_id: String,
    /// Configuration version for hot-restarts.
    pub config_version: u64,
}

impl Default for InstanceConfig {
    fn default() -> Self {
        Self {
            network_policy: NetworkPolicy::default(),
            audit_logger: None,
            memory_export: DEFAULT_WASM_MEMORY_NAME.to_string(),
            challenge_id: "unknown".to_string(),
            validator_id: "unknown".to_string(),
            restart_id: String::new(),
            config_version: 0,
        }
    }
}

pub struct RuntimeState {
    /// Network policy available to host functions.
    pub network_policy: NetworkPolicy,
    /// Mutable network state enforcing policy.
    pub network_state: NetworkState,
    /// Wasm memory export name.
    pub memory_export: String,
    /// Identifier used in audit logs.
    pub challenge_id: String,
    /// Validator identifier used in audit logs.
    pub validator_id: String,
    /// Restartable configuration identifier.
    pub restart_id: String,
    /// Configuration version for hot-restarts.
    pub config_version: u64,
    limits: StoreLimits,
}

impl RuntimeState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_policy: NetworkPolicy,
        network_state: NetworkState,
        memory_export: String,
        challenge_id: String,
        validator_id: String,
        restart_id: String,
        config_version: u64,
        limits: StoreLimits,
    ) -> Self {
        Self {
            network_policy,
            network_state,
            memory_export,
            challenge_id,
            validator_id,
            restart_id,
            config_version,
            limits,
        }
    }

    pub fn reset_network_counters(&mut self) {
        self.network_state.reset_counters();
    }
}

impl ResourceLimiter for RuntimeState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, WasmtimeError> {
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, WasmtimeError> {
        self.limits.table_growing(current, desired, maximum)
    }
}

pub struct WasmRuntime {
    engine: Engine,
    config: RuntimeConfig,
}

impl WasmRuntime {
    pub fn new(config: RuntimeConfig) -> Result<Self, WasmRuntimeError> {
        let mut engine_config = Config::new();
        if config.allow_fuel {
            engine_config.consume_fuel(true);
        }
        let engine = Engine::new(&engine_config)
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))?;
        Ok(Self { engine, config })
    }

    pub fn from_engine(engine: Engine, config: RuntimeConfig) -> Self {
        Self { engine, config }
    }

    pub fn compile_module(&self, wasm: &[u8]) -> Result<WasmModule, WasmRuntimeError> {
        let module = Module::from_binary(&self.engine, wasm)
            .map_err(|err: WasmtimeError| WasmRuntimeError::Compile(err.to_string()))?;
        Ok(WasmModule { module })
    }

    pub fn instantiate(
        &self,
        module: &WasmModule,
        instance_config: InstanceConfig,
        registrar: Option<Arc<dyn HostFunctionRegistrar>>,
    ) -> Result<ChallengeInstance, WasmRuntimeError> {
        let mut limits = StoreLimitsBuilder::new();
        limits = limits.memory_size(self.config.max_memory_bytes as usize);
        limits = limits.instances(self.config.max_instances as usize);
        let network_state = NetworkState::new(
            instance_config.network_policy.clone(),
            instance_config.audit_logger.clone(),
            instance_config.challenge_id.clone(),
            instance_config.validator_id.clone(),
        )
        .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        let runtime_state = RuntimeState::new(
            instance_config.network_policy.clone(),
            network_state,
            instance_config.memory_export.clone(),
            instance_config.challenge_id.clone(),
            instance_config.validator_id.clone(),
            instance_config.restart_id.clone(),
            instance_config.config_version,
            limits.build(),
        );
        let mut store = Store::new(&self.engine, runtime_state);

        if self.config.allow_fuel {
            if let Some(limit) = self.config.fuel_limit {
                store
                    .set_fuel(limit)
                    .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))?;
            }
        }

        store.limiter(|state| &mut state.limits);

        let mut linker = Linker::new(&self.engine);
        if let Some(registrar) = registrar {
            registrar.register(&mut linker)?;
        }

        let instance = linker
            .instantiate(&mut store, &module.module)
            .map_err(|err: WasmtimeError| WasmRuntimeError::Instantiate(err.to_string()))?;

        let memory = instance
            .get_memory(&mut store, &instance_config.memory_export)
            .ok_or_else(|| {
                WasmRuntimeError::MissingExport(instance_config.memory_export.clone())
            })?;

        info!(
            challenge_id = %instance_config.challenge_id,
            validator_id = %instance_config.validator_id,
            max_memory = self.config.max_memory_bytes,
            fuel_enabled = self.config.allow_fuel,
            fuel_limit = ?self.config.fuel_limit,
            "wasm challenge instance created"
        );

        Ok(ChallengeInstance {
            store,
            instance,
            memory,
        })
    }
}

pub struct WasmModule {
    module: Module,
}

impl WasmModule {
    pub fn module(&self) -> &Module {
        &self.module
    }
}

pub struct ChallengeInstance {
    store: Store<RuntimeState>,
    instance: Instance,
    memory: Memory,
}

impl ChallengeInstance {
    pub fn store(&self) -> &Store<RuntimeState> {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Store<RuntimeState> {
        &mut self.store
    }

    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    pub fn get_func(&mut self, name: &str) -> Result<Func, WasmRuntimeError> {
        self.instance
            .get_func(&mut self.store, name)
            .ok_or_else(|| WasmRuntimeError::MissingExport(name.to_string()))
    }

    pub fn call(&mut self, name: &str, params: &[Val]) -> Result<Vec<Val>, WasmRuntimeError> {
        let func = self.get_func(name)?;
        let ty = func.ty(&self.store);
        let mut results = vec![Val::I32(0); ty.results().len()];
        func.call(&mut self.store, params, &mut results)?;
        Ok(results)
    }

    pub fn read_memory(
        &mut self,
        offset: usize,
        length: usize,
    ) -> Result<Vec<u8>, WasmRuntimeError> {
        let data = self.memory.data(&self.store);
        let end = offset.saturating_add(length);
        if end > data.len() {
            return Err(WasmRuntimeError::Memory("read out of bounds".to_string()));
        }
        Ok(data[offset..end].to_vec())
    }

    pub fn write_memory(&mut self, offset: usize, bytes: &[u8]) -> Result<(), WasmRuntimeError> {
        let data = self.memory.data_mut(&mut self.store);
        let end = offset.saturating_add(bytes.len());
        if end > data.len() {
            return Err(WasmRuntimeError::Memory("write out of bounds".to_string()));
        }
        data[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    pub fn call_i32_i32_return_i64(
        &mut self,
        name: &str,
        arg0: i32,
        arg1: i32,
    ) -> Result<i64, WasmRuntimeError> {
        let func = self
            .instance
            .get_typed_func::<(i32, i32), i64>(&mut self.store, name)
            .map_err(|_| WasmRuntimeError::MissingExport(name.to_string()))?;
        func.call(&mut self.store, (arg0, arg1))
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))
    }

    pub fn call_i32_i32_return_i32(
        &mut self,
        name: &str,
        arg0: i32,
        arg1: i32,
    ) -> Result<i32, WasmRuntimeError> {
        let func = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, name)
            .map_err(|_| WasmRuntimeError::MissingExport(name.to_string()))?;
        func.call(&mut self.store, (arg0, arg1))
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))
    }

    pub fn call_return_i32(&mut self, name: &str) -> Result<i32, WasmRuntimeError> {
        let func = self
            .instance
            .get_typed_func::<(), i32>(&mut self.store, name)
            .map_err(|_| WasmRuntimeError::MissingExport(name.to_string()))?;
        func.call(&mut self.store, ())
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))
    }

    pub fn call_return_i64(&mut self, name: &str) -> Result<i64, WasmRuntimeError> {
        let func = self
            .instance
            .get_typed_func::<(), i64>(&mut self.store, name)
            .map_err(|_| WasmRuntimeError::MissingExport(name.to_string()))?;
        func.call(&mut self.store, ())
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))
    }

    pub fn fuel_remaining(&self) -> Option<u64> {
        self.store.get_fuel().ok()
    }

    pub fn network_requests_made(&self) -> u32 {
        self.store.data().network_state.requests_made()
    }

    pub fn network_dns_lookups(&self) -> u32 {
        self.store.data().network_state.dns_lookups()
    }

    pub fn reset_network_state(&mut self) {
        self.store.data_mut().reset_network_counters();
    }

    pub fn challenge_id(&self) -> &str {
        &self.store.data().challenge_id
    }

    pub fn validator_id(&self) -> &str {
        &self.store.data().validator_id
    }

    pub fn with_state<F, T>(&mut self, func: F) -> Result<T, WasmRuntimeError>
    where
        F: FnOnce(&mut RuntimeState) -> Result<T, WasmRuntimeError>,
    {
        func(self.store.data_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkPolicy;
    use wasmtime::StoreLimitsBuilder;

    #[test]
    fn test_wasm_runtime_error_compile_display() {
        let err = WasmRuntimeError::Compile("bad wasm".to_string());
        assert_eq!(err.to_string(), "module compile failed: bad wasm");
    }

    #[test]
    fn test_wasm_runtime_error_instantiate_display() {
        let err = WasmRuntimeError::Instantiate("link error".to_string());
        assert_eq!(err.to_string(), "module instantiation failed: link error");
    }

    #[test]
    fn test_wasm_runtime_error_host_function_display() {
        let err = WasmRuntimeError::HostFunction("dup func".to_string());
        assert_eq!(
            err.to_string(),
            "host function registration failed: dup func"
        );
    }

    #[test]
    fn test_wasm_runtime_error_missing_export_display() {
        let err = WasmRuntimeError::MissingExport("main".to_string());
        assert_eq!(err.to_string(), "missing export: main");
    }

    #[test]
    fn test_wasm_runtime_error_memory_display() {
        let err = WasmRuntimeError::Memory("out of bounds".to_string());
        assert_eq!(err.to_string(), "memory error: out of bounds");
    }

    #[test]
    fn test_wasm_runtime_error_execution_display() {
        let err = WasmRuntimeError::Execution("trap".to_string());
        assert_eq!(err.to_string(), "execution error: trap");
    }

    #[test]
    fn test_wasm_runtime_error_io_display() {
        let err = WasmRuntimeError::Io("file not found".to_string());
        assert_eq!(err.to_string(), "io error: file not found");
    }

    #[test]
    fn test_wasm_runtime_error_fuel_exhausted_display() {
        let err = WasmRuntimeError::FuelExhausted;
        assert_eq!(err.to_string(), "fuel exhausted");
    }

    #[test]
    fn test_wasm_runtime_error_policy_violation_display() {
        let err = WasmRuntimeError::PolicyViolation("blocked host".to_string());
        assert_eq!(err.to_string(), "policy violation: blocked host");
    }

    #[test]
    fn test_wasm_runtime_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing file");
        let err: WasmRuntimeError = io_err.into();
        assert!(matches!(err, WasmRuntimeError::Io(_)));
        assert!(err.to_string().contains("missing file"));
    }

    #[test]
    fn test_runtime_config_default() {
        let config = RuntimeConfig::default();
        assert_eq!(config.max_memory_bytes, 512 * 1024 * 1024);
        assert_eq!(config.max_instances, 32);
        assert!(!config.allow_fuel);
        assert!(config.fuel_limit.is_none());
    }

    #[test]
    fn test_instance_config_default() {
        let config = InstanceConfig::default();
        assert!(config.audit_logger.is_none());
        assert_eq!(config.memory_export, DEFAULT_WASM_MEMORY_NAME);
        assert_eq!(config.challenge_id, "unknown");
        assert_eq!(config.validator_id, "unknown");
        assert!(config.restart_id.is_empty());
        assert_eq!(config.config_version, 0);
    }

    #[test]
    fn test_runtime_state_new() {
        let policy = NetworkPolicy::development();
        let network_state = NetworkState::new(
            policy.clone(),
            None,
            "chal-1".to_string(),
            "val-1".to_string(),
        )
        .unwrap();
        let limits = StoreLimitsBuilder::new().build();

        let state = RuntimeState::new(
            policy,
            network_state,
            "memory".to_string(),
            "chal-1".to_string(),
            "val-1".to_string(),
            "restart-1".to_string(),
            42,
            limits,
        );

        assert_eq!(state.challenge_id, "chal-1");
        assert_eq!(state.validator_id, "val-1");
        assert_eq!(state.restart_id, "restart-1");
        assert_eq!(state.config_version, 42);
        assert_eq!(state.memory_export, "memory");
    }

    #[test]
    fn test_runtime_state_reset_network_counters() {
        let policy = NetworkPolicy::development();
        let network_state = NetworkState::new(
            policy.clone(),
            None,
            "chal-1".to_string(),
            "val-1".to_string(),
        )
        .unwrap();

        let limits = StoreLimitsBuilder::new().build();
        let mut state = RuntimeState::new(
            policy,
            network_state,
            "memory".to_string(),
            "chal-1".to_string(),
            "val-1".to_string(),
            "".to_string(),
            0,
            limits,
        );

        assert_eq!(state.network_state.requests_made(), 0);
        assert_eq!(state.network_state.dns_lookups(), 0);

        state.reset_network_counters();

        assert_eq!(state.network_state.requests_made(), 0);
        assert_eq!(state.network_state.dns_lookups(), 0);
    }

    #[test]
    fn test_wasm_runtime_new_default_config() {
        let config = RuntimeConfig::default();
        let runtime = WasmRuntime::new(config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_wasm_runtime_new_with_fuel() {
        let config = RuntimeConfig {
            allow_fuel: true,
            fuel_limit: None,
            ..RuntimeConfig::default()
        };
        let runtime = WasmRuntime::new(config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_wasm_runtime_new_with_fuel_limit() {
        let config = RuntimeConfig {
            allow_fuel: true,
            fuel_limit: Some(1_000_000),
            ..RuntimeConfig::default()
        };
        let runtime = WasmRuntime::new(config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_wasm_runtime_from_engine() {
        let engine = Engine::default();
        let config = RuntimeConfig::default();
        let runtime = WasmRuntime::from_engine(engine, config.clone());
        assert_eq!(runtime.config.max_memory_bytes, config.max_memory_bytes);
        assert_eq!(runtime.config.max_instances, config.max_instances);
    }
}
