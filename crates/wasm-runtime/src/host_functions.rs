//! Host functions for WASM modules
//!
//! This module provides host functions that WASM modules can call to interact
//! with the host environment. These functions are designed to be safe and
//! deterministic for challenge evaluation.

use crate::error::{Result, WasmError};
use crate::sandbox::ResourceUsage;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};
use tracing::{debug, trace};
use wasmtime::{Caller, Engine, Linker, Memory};

/// Type alias for wasmtime result in host functions
type WasmtimeResult<T> = std::result::Result<T, wasmtime::Error>;

/// State shared between host functions and the runtime
///
/// This struct holds mutable state that host functions can access,
/// including logging buffers, RNG, and resource tracking.
#[derive(Debug)]
pub struct HostState {
    /// Log messages from the WASM module
    logs: Vec<String>,

    /// Seeded RNG for deterministic random number generation
    rng: ChaCha20Rng,

    /// Resource usage tracking
    resource_usage: ResourceUsage,

    /// Memory reference (set during instantiation)
    memory: Option<Memory>,

    /// Seed used for RNG initialization
    seed: u64,

    /// Maximum log entries allowed
    max_log_entries: usize,

    /// Maximum log message length
    max_log_length: usize,
}

impl HostState {
    /// Create a new host state with the given RNG seed
    pub fn new(seed: u64) -> Self {
        Self {
            logs: Vec::new(),
            rng: ChaCha20Rng::seed_from_u64(seed),
            resource_usage: ResourceUsage::new(),
            memory: None,
            seed,
            max_log_entries: 1000,
            max_log_length: 4096,
        }
    }

    /// Set the WASM memory reference
    pub fn set_memory(&mut self, memory: Memory) {
        self.memory = Some(memory);
    }

    /// Get the memory reference
    pub fn memory(&self) -> Option<&Memory> {
        self.memory.as_ref()
    }

    /// Add a log message from the WASM module
    pub fn add_log(&mut self, message: String) {
        if self.logs.len() < self.max_log_entries {
            let truncated = if message.len() > self.max_log_length {
                format!("{}...[truncated]", &message[..self.max_log_length])
            } else {
                message
            };
            self.logs.push(truncated);
        }
    }

    /// Get all log messages
    pub fn logs(&self) -> &[String] {
        &self.logs
    }

    /// Clear log messages
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    /// Get random bytes from the seeded RNG
    pub fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        self.rng.fill(&mut bytes[..]);
        bytes
    }

    /// Get resource usage statistics
    pub fn resource_usage(&self) -> &ResourceUsage {
        &self.resource_usage
    }

    /// Get mutable resource usage statistics
    pub fn resource_usage_mut(&mut self) -> &mut ResourceUsage {
        &mut self.resource_usage
    }

    /// Reset the RNG to its initial state
    pub fn reset_rng(&mut self) {
        self.rng = ChaCha20Rng::seed_from_u64(self.seed);
    }

    /// Reset all state for a new execution
    pub fn reset(&mut self) {
        self.logs.clear();
        self.reset_rng();
        self.resource_usage = ResourceUsage::new();
    }
}

/// Thread-safe wrapper for host state
pub type SharedHostState = Arc<Mutex<HostState>>;

/// Create a new shared host state
pub fn create_host_state(seed: u64) -> SharedHostState {
    Arc::new(Mutex::new(HostState::new(seed)))
}

/// Register host functions with the wasmtime linker
///
/// This function adds all available host functions to the linker so they
/// can be called by WASM modules.
pub fn register_host_functions(
    linker: &mut Linker<SharedHostState>,
    _engine: &Engine,
) -> Result<()> {
    // host_log(ptr: i32, len: i32)
    // Logs a message from the WASM module
    linker
        .func_wrap(
            "env",
            "host_log",
            |mut caller: Caller<'_, SharedHostState>, ptr: i32, len: i32| -> WasmtimeResult<()> {
                let state = caller.data().clone();
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("failed to find memory export"))?;

                let mut buffer = vec![0u8; len as usize];
                memory.read(&caller, ptr as usize, &mut buffer)?;

                let message = String::from_utf8_lossy(&buffer).to_string();

                let mut state_guard = state
                    .lock()
                    .map_err(|e| wasmtime::Error::msg(format!("failed to lock state: {}", e)))?;
                state_guard.resource_usage_mut().record_host_call();
                state_guard.add_log(message.clone());

                debug!(target: "wasm", "WASM log: {}", message);

                Ok(())
            },
        )
        .map_err(|e| WasmError::HostFunctionError(format!("failed to register host_log: {}", e)))?;

    // host_get_timestamp() -> i64
    // Returns the current Unix timestamp in seconds
    linker
        .func_wrap(
            "env",
            "host_get_timestamp",
            |caller: Caller<'_, SharedHostState>| -> i64 {
                let state = caller.data().clone();
                if let Ok(mut guard) = state.lock() {
                    guard.resource_usage_mut().record_host_call();
                }

                let timestamp = chrono::Utc::now().timestamp();
                trace!(target: "wasm", "WASM timestamp request: {}", timestamp);
                timestamp
            },
        )
        .map_err(|e| {
            WasmError::HostFunctionError(format!("failed to register host_get_timestamp: {}", e))
        })?;

    // host_get_timestamp_millis() -> i64
    // Returns the current Unix timestamp in milliseconds
    linker
        .func_wrap(
            "env",
            "host_get_timestamp_millis",
            |caller: Caller<'_, SharedHostState>| -> i64 {
                let state = caller.data().clone();
                if let Ok(mut guard) = state.lock() {
                    guard.resource_usage_mut().record_host_call();
                }

                let timestamp = chrono::Utc::now().timestamp_millis();
                trace!(target: "wasm", "WASM timestamp_millis request: {}", timestamp);
                timestamp
            },
        )
        .map_err(|e| {
            WasmError::HostFunctionError(format!(
                "failed to register host_get_timestamp_millis: {}",
                e
            ))
        })?;

    // host_random_bytes(ptr: i32, len: i32) -> i32
    // Fills the buffer at ptr with len random bytes (deterministic from seed)
    // Returns 0 on success, -1 on error
    linker
        .func_wrap(
            "env",
            "host_random_bytes",
            |mut caller: Caller<'_, SharedHostState>, ptr: i32, len: i32| -> i32 {
                let state = caller.data().clone();

                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return -1,
                };

                let mut state_guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => return -1,
                };

                state_guard.resource_usage_mut().record_host_call();

                let bytes = state_guard.random_bytes(len as usize);

                match memory.write(&mut caller, ptr as usize, &bytes) {
                    Ok(()) => {
                        trace!(target: "wasm", "WASM random_bytes: {} bytes", len);
                        0
                    }
                    Err(_) => -1,
                }
            },
        )
        .map_err(|e| {
            WasmError::HostFunctionError(format!("failed to register host_random_bytes: {}", e))
        })?;

    // host_abort(msg_ptr: i32, msg_len: i32, file_ptr: i32, file_len: i32, line: i32, col: i32)
    // Abort execution with an error message (used by AssemblyScript and other languages)
    linker
        .func_wrap(
            "env",
            "host_abort",
            |mut caller: Caller<'_, SharedHostState>,
             msg_ptr: i32,
             msg_len: i32,
             file_ptr: i32,
             file_len: i32,
             line: i32,
             col: i32|
             -> WasmtimeResult<()> {
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| wasmtime::Error::msg("failed to find memory export"))?;

                let mut msg_buffer = vec![0u8; msg_len as usize];
                memory.read(&caller, msg_ptr as usize, &mut msg_buffer)?;
                let msg = String::from_utf8_lossy(&msg_buffer);

                let mut file_buffer = vec![0u8; file_len as usize];
                memory.read(&caller, file_ptr as usize, &mut file_buffer)?;
                let file = String::from_utf8_lossy(&file_buffer);

                tracing::error!(
                    target: "wasm",
                    "WASM abort: {} at {}:{}:{}",
                    msg,
                    file,
                    line,
                    col
                );

                Err(wasmtime::Error::msg(format!(
                    "WASM abort: {} at {}:{}:{}",
                    msg, file, line, col
                )))
            },
        )
        .map_err(|e| {
            WasmError::HostFunctionError(format!("failed to register host_abort: {}", e))
        })?;

    // host_debug_i32(value: i32)
    // Debug helper to print an i32 value
    linker
        .func_wrap(
            "env",
            "host_debug_i32",
            |caller: Caller<'_, SharedHostState>, value: i32| {
                let state = caller.data().clone();
                if let Ok(mut guard) = state.lock() {
                    guard.resource_usage_mut().record_host_call();
                    guard.add_log(format!("debug_i32: {}", value));
                }
                debug!(target: "wasm", "WASM debug_i32: {}", value);
            },
        )
        .map_err(|e| {
            WasmError::HostFunctionError(format!("failed to register host_debug_i32: {}", e))
        })?;

    // host_debug_i64(value: i64)
    // Debug helper to print an i64 value
    linker
        .func_wrap(
            "env",
            "host_debug_i64",
            |caller: Caller<'_, SharedHostState>, value: i64| {
                let state = caller.data().clone();
                if let Ok(mut guard) = state.lock() {
                    guard.resource_usage_mut().record_host_call();
                    guard.add_log(format!("debug_i64: {}", value));
                }
                debug!(target: "wasm", "WASM debug_i64: {}", value);
            },
        )
        .map_err(|e| {
            WasmError::HostFunctionError(format!("failed to register host_debug_i64: {}", e))
        })?;

    // host_debug_f64(value: f64)
    // Debug helper to print an f64 value
    linker
        .func_wrap(
            "env",
            "host_debug_f64",
            |caller: Caller<'_, SharedHostState>, value: f64| {
                let state = caller.data().clone();
                if let Ok(mut guard) = state.lock() {
                    guard.resource_usage_mut().record_host_call();
                    guard.add_log(format!("debug_f64: {}", value));
                }
                debug!(target: "wasm", "WASM debug_f64: {}", value);
            },
        )
        .map_err(|e| {
            WasmError::HostFunctionError(format!("failed to register host_debug_f64: {}", e))
        })?;

    Ok(())
}

/// Read a string from WASM memory
///
/// # Arguments
/// * `memory` - The WASM memory instance
/// * `store` - The wasmtime store context
/// * `ptr` - Pointer to the string in WASM memory
/// * `len` - Length of the string in bytes
///
/// # Returns
/// The string read from memory, or an error
pub fn read_string_from_memory<T>(
    memory: &Memory,
    store: impl wasmtime::AsContext<Data = T>,
    ptr: i32,
    len: i32,
) -> Result<String> {
    if ptr < 0 || len < 0 {
        return Err(WasmError::MemoryError(format!(
            "invalid pointer ({}) or length ({})",
            ptr, len
        )));
    }

    let mut buffer = vec![0u8; len as usize];
    memory
        .read(&store, ptr as usize, &mut buffer)
        .map_err(|e| WasmError::MemoryError(format!("failed to read from memory: {}", e)))?;

    String::from_utf8(buffer).map_err(|e| WasmError::MemoryError(format!("invalid UTF-8: {}", e)))
}

/// Read bytes from WASM memory
///
/// # Arguments
/// * `memory` - The WASM memory instance
/// * `store` - The wasmtime store context
/// * `ptr` - Pointer to the data in WASM memory
/// * `len` - Length of the data in bytes
///
/// # Returns
/// The bytes read from memory, or an error
pub fn read_bytes_from_memory<T>(
    memory: &Memory,
    store: impl wasmtime::AsContext<Data = T>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>> {
    if ptr < 0 || len < 0 {
        return Err(WasmError::MemoryError(format!(
            "invalid pointer ({}) or length ({})",
            ptr, len
        )));
    }

    let mut buffer = vec![0u8; len as usize];
    memory
        .read(&store, ptr as usize, &mut buffer)
        .map_err(|e| WasmError::MemoryError(format!("failed to read from memory: {}", e)))?;

    Ok(buffer)
}

/// Write bytes to WASM memory
///
/// # Arguments
/// * `memory` - The WASM memory instance
/// * `store` - The wasmtime store context (must be mutable)
/// * `ptr` - Pointer to write to in WASM memory
/// * `data` - The data to write
///
/// # Returns
/// Ok(()) on success, or an error
pub fn write_bytes_to_memory<T>(
    memory: &Memory,
    mut store: impl wasmtime::AsContextMut<Data = T>,
    ptr: i32,
    data: &[u8],
) -> Result<()> {
    if ptr < 0 {
        return Err(WasmError::MemoryError(format!("invalid pointer: {}", ptr)));
    }

    memory
        .write(&mut store, ptr as usize, data)
        .map_err(|e| WasmError::MemoryError(format!("failed to write to memory: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_state_creation() {
        let state = HostState::new(12345);
        assert!(state.logs().is_empty());
        assert_eq!(state.seed, 12345);
    }

    #[test]
    fn test_host_state_logging() {
        let mut state = HostState::new(12345);

        state.add_log("First message".to_string());
        state.add_log("Second message".to_string());

        assert_eq!(state.logs().len(), 2);
        assert_eq!(state.logs()[0], "First message");
        assert_eq!(state.logs()[1], "Second message");

        state.clear_logs();
        assert!(state.logs().is_empty());
    }

    #[test]
    fn test_host_state_log_truncation() {
        let mut state = HostState::new(12345);
        state.max_log_length = 10;

        state.add_log("This is a very long message that should be truncated".to_string());

        assert!(state.logs()[0].len() <= 30); // 10 + "...[truncated]"
        assert!(state.logs()[0].contains("[truncated]"));
    }

    #[test]
    fn test_host_state_random_bytes() {
        let mut state1 = HostState::new(42);
        let mut state2 = HostState::new(42);

        let bytes1 = state1.random_bytes(32);
        let bytes2 = state2.random_bytes(32);

        // Same seed should produce same random bytes
        assert_eq!(bytes1, bytes2);

        // Different calls should produce different bytes
        let bytes3 = state1.random_bytes(32);
        assert_ne!(bytes1, bytes3);
    }

    #[test]
    fn test_host_state_reset() {
        let mut state = HostState::new(42);

        state.add_log("test".to_string());
        let _ = state.random_bytes(32);

        state.reset();

        assert!(state.logs().is_empty());

        // RNG should be reset to initial state
        let mut state2 = HostState::new(42);
        assert_eq!(state.random_bytes(32), state2.random_bytes(32));
    }

    #[test]
    fn test_create_shared_host_state() {
        let shared = create_host_state(12345);

        {
            let mut guard = shared.lock().expect("failed to lock state");
            guard.add_log("test message".to_string());
        }

        {
            let guard = shared.lock().expect("failed to lock state");
            assert_eq!(guard.logs().len(), 1);
        }
    }
}
