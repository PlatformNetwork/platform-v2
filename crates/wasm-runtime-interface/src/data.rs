//! Data Host Functions for WASM Challenges
//!
//! This module provides host functions that allow WASM code to load
//! challenge-specific data from the host. All operations are gated by `DataPolicy`.
//!
//! # Host Functions
//!
//! - `data_get(key_ptr, key_len, buf_ptr, buf_len) -> i32` - Read challenge data by key
//! - `data_list(prefix_ptr, prefix_len, buf_ptr, buf_len) -> i32` - List data keys under a prefix

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::warn;
use wasmtime::{Caller, Linker, Memory};

pub const HOST_DATA_NAMESPACE: &str = "platform_data";
pub const HOST_DATA_GET: &str = "data_get";
pub const HOST_DATA_LIST: &str = "data_list";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DataHostStatus {
    Success = 0,
    Disabled = 1,
    NotFound = -1,
    KeyTooLarge = -2,
    BufferTooSmall = -3,
    PathNotAllowed = -4,
    IoError = -5,
    InternalError = -100,
}

impl DataHostStatus {
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::Disabled,
            -1 => Self::NotFound,
            -2 => Self::KeyTooLarge,
            -3 => Self::BufferTooSmall,
            -4 => Self::PathNotAllowed,
            -5 => Self::IoError,
            _ => Self::InternalError,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPolicy {
    pub enabled: bool,
    pub max_key_size: usize,
    pub max_value_size: usize,
    pub max_reads_per_execution: u32,
}

impl Default for DataPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_key_size: 1024,
            max_value_size: 10 * 1024 * 1024,
            max_reads_per_execution: 64,
        }
    }
}

impl DataPolicy {
    pub fn development() -> Self {
        Self {
            enabled: true,
            max_key_size: 4096,
            max_value_size: 50 * 1024 * 1024,
            max_reads_per_execution: 256,
        }
    }
}

pub trait DataBackend: Send + Sync {
    fn get(&self, challenge_id: &str, key: &str) -> Result<Option<Vec<u8>>, DataError>;
    fn list(&self, challenge_id: &str, prefix: &str) -> Result<Vec<String>, DataError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("io error: {0}")]
    Io(String),
    #[error("key too large: {0}")]
    KeyTooLarge(usize),
    #[error("path not allowed: {0}")]
    PathNotAllowed(String),
}

pub struct NoopDataBackend;

impl DataBackend for NoopDataBackend {
    fn get(&self, _challenge_id: &str, _key: &str) -> Result<Option<Vec<u8>>, DataError> {
        Ok(None)
    }

    fn list(&self, _challenge_id: &str, _prefix: &str) -> Result<Vec<String>, DataError> {
        Ok(Vec::new())
    }
}

pub struct FilesystemDataBackend {
    base_dir: PathBuf,
}

impl FilesystemDataBackend {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn validate_challenge_id(challenge_id: &str) -> Result<(), DataError> {
        if challenge_id.is_empty() {
            return Err(DataError::PathNotAllowed(
                "challenge_id must not be empty".to_string(),
            ));
        }
        if challenge_id.bytes().any(|b| b == 0) {
            return Err(DataError::PathNotAllowed(
                "challenge_id contains null byte".to_string(),
            ));
        }
        if challenge_id.contains('/')
            || challenge_id.contains('\\')
            || challenge_id.contains(std::path::MAIN_SEPARATOR)
            || challenge_id == ".."
            || challenge_id == "."
        {
            return Err(DataError::PathNotAllowed(
                "challenge_id contains path separator or traversal".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_segment(segment: &str, label: &str) -> Result<(), DataError> {
        if segment.is_empty() {
            return Err(DataError::PathNotAllowed(format!(
                "{label} must not be empty"
            )));
        }
        if segment.bytes().any(|b| b == 0) {
            return Err(DataError::PathNotAllowed(format!(
                "{label} contains null byte"
            )));
        }
        if segment.contains("..") || segment.contains('\\') || segment.starts_with('/') {
            return Err(DataError::PathNotAllowed(format!(
                "{label} contains path traversal or separator"
            )));
        }
        Ok(())
    }

    fn safe_resolve(&self, challenge_id: &str, subpath: &str) -> Result<PathBuf, DataError> {
        Self::validate_challenge_id(challenge_id)?;
        Self::validate_segment(subpath, "subpath")?;

        let challenge_dir = self.base_dir.join(challenge_id);
        let path = challenge_dir.join(subpath);

        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(DataError::PathNotAllowed(subpath.to_string()));
        }

        if !path.starts_with(&challenge_dir) {
            return Err(DataError::PathNotAllowed(subpath.to_string()));
        }

        if path.exists() {
            let canonical_path = path
                .canonicalize()
                .map_err(|e| DataError::Io(e.to_string()))?;
            let canonical_base = if challenge_dir.exists() {
                challenge_dir
                    .canonicalize()
                    .map_err(|e| DataError::Io(e.to_string()))?
            } else {
                return Err(DataError::PathNotAllowed(
                    "challenge directory does not exist".to_string(),
                ));
            };
            if !canonical_path.starts_with(&canonical_base) {
                return Err(DataError::PathNotAllowed(subpath.to_string()));
            }
        }

        Ok(path)
    }
}

impl DataBackend for FilesystemDataBackend {
    fn get(&self, challenge_id: &str, key: &str) -> Result<Option<Vec<u8>>, DataError> {
        let path = self.safe_resolve(challenge_id, key)?;
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(DataError::Io(e.to_string())),
        }
    }

    fn list(&self, challenge_id: &str, prefix: &str) -> Result<Vec<String>, DataError> {
        let dir = self.safe_resolve(challenge_id, prefix)?;
        let entries = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(DataError::Io(e.to_string())),
        };
        let mut names = Vec::new();
        for entry in entries {
            match entry {
                Ok(e) => {
                    if let Some(name) = e.file_name().to_str() {
                        names.push(name.to_string());
                    }
                }
                Err(e) => {
                    warn!(error = %e, "data backend: failed to read directory entry");
                    continue;
                }
            }
        }
        Ok(names)
    }
}

pub struct DataState {
    pub policy: DataPolicy,
    pub backend: std::sync::Arc<dyn DataBackend>,
    pub challenge_id: String,
    pub reads: u32,
}

impl DataState {
    pub fn new(
        policy: DataPolicy,
        backend: std::sync::Arc<dyn DataBackend>,
        challenge_id: String,
    ) -> Self {
        Self {
            policy,
            backend,
            challenge_id,
            reads: 0,
        }
    }

    pub fn reset_counters(&mut self) {
        self.reads = 0;
    }
}

#[derive(Clone, Debug)]
pub struct DataHostFunctions;

impl DataHostFunctions {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DataHostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl HostFunctionRegistrar for DataHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        linker
            .func_wrap(
                HOST_DATA_NAMESPACE,
                HOST_DATA_GET,
                |mut caller: Caller<RuntimeState>,
                 key_ptr: i32,
                 key_len: i32,
                 buf_ptr: i32,
                 buf_len: i32|
                 -> i32 {
                    handle_data_get(&mut caller, key_ptr, key_len, buf_ptr, buf_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_DATA_NAMESPACE,
                HOST_DATA_LIST,
                |mut caller: Caller<RuntimeState>,
                 prefix_ptr: i32,
                 prefix_len: i32,
                 buf_ptr: i32,
                 buf_len: i32|
                 -> i32 {
                    handle_data_list(&mut caller, prefix_ptr, prefix_len, buf_ptr, buf_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        Ok(())
    }
}

fn handle_data_get(
    caller: &mut Caller<RuntimeState>,
    key_ptr: i32,
    key_len: i32,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    if !caller.data().data_state.policy.enabled {
        return DataHostStatus::Disabled.to_i32();
    }

    let key_bytes = match read_wasm_memory(caller, key_ptr, key_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "data_get: failed to read key from wasm memory");
            return DataHostStatus::InternalError.to_i32();
        }
    };

    let key_str = match std::str::from_utf8(&key_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return DataHostStatus::InternalError.to_i32(),
    };

    if key_bytes.len() > caller.data().data_state.policy.max_key_size {
        return DataHostStatus::KeyTooLarge.to_i32();
    }

    if caller.data().data_state.reads >= caller.data().data_state.policy.max_reads_per_execution {
        return DataHostStatus::InternalError.to_i32();
    }

    let challenge_id = caller.data().data_state.challenge_id.clone();
    let backend = std::sync::Arc::clone(&caller.data().data_state.backend);

    let value = match backend.get(&challenge_id, &key_str) {
        Ok(Some(v)) => v,
        Ok(None) => return DataHostStatus::NotFound.to_i32(),
        Err(err) => {
            warn!(error = %err, "data_get: backend read failed");
            return DataHostStatus::IoError.to_i32();
        }
    };

    if value.len() > caller.data().data_state.policy.max_value_size {
        warn!(
            value_len = value.len(),
            max = caller.data().data_state.policy.max_value_size,
            "data_get: value exceeds max_value_size"
        );
        return DataHostStatus::InternalError.to_i32();
    }

    caller.data_mut().data_state.reads += 1;

    if buf_len < 0 || value.len() > buf_len as usize {
        return DataHostStatus::BufferTooSmall.to_i32();
    }

    if let Err(err) = write_wasm_memory(caller, buf_ptr, &value) {
        warn!(error = %err, "data_get: failed to write value to wasm memory");
        return DataHostStatus::InternalError.to_i32();
    }

    value.len() as i32
}

fn handle_data_list(
    caller: &mut Caller<RuntimeState>,
    prefix_ptr: i32,
    prefix_len: i32,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    if !caller.data().data_state.policy.enabled {
        return DataHostStatus::Disabled.to_i32();
    }

    let prefix_bytes = match read_wasm_memory(caller, prefix_ptr, prefix_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "data_list: failed to read prefix from wasm memory");
            return DataHostStatus::InternalError.to_i32();
        }
    };

    let prefix_str = match std::str::from_utf8(&prefix_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return DataHostStatus::InternalError.to_i32(),
    };

    if prefix_str.len() > caller.data().data_state.policy.max_key_size {
        return DataHostStatus::KeyTooLarge.to_i32();
    }

    if caller.data().data_state.reads >= caller.data().data_state.policy.max_reads_per_execution {
        return DataHostStatus::InternalError.to_i32();
    }

    let challenge_id = caller.data().data_state.challenge_id.clone();
    let backend = std::sync::Arc::clone(&caller.data().data_state.backend);

    let entries = match backend.list(&challenge_id, &prefix_str) {
        Ok(e) => e,
        Err(err) => {
            warn!(error = %err, "data_list: backend list failed");
            return DataHostStatus::IoError.to_i32();
        }
    };

    caller.data_mut().data_state.reads += 1;

    let result = entries.join("\n");
    let result_bytes = result.as_bytes();

    if buf_len < 0 || result_bytes.len() > buf_len as usize {
        return DataHostStatus::BufferTooSmall.to_i32();
    }

    if let Err(err) = write_wasm_memory(caller, buf_ptr, result_bytes) {
        warn!(error = %err, "data_list: failed to write to wasm memory");
        return DataHostStatus::InternalError.to_i32();
    }

    result_bytes.len() as i32
}

fn read_wasm_memory(
    caller: &mut Caller<RuntimeState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, String> {
    if ptr < 0 || len < 0 {
        return Err("negative pointer/length".to_string());
    }
    let ptr = ptr as usize;
    let len = len as usize;
    let memory = get_memory(caller).ok_or_else(|| "memory export not found".to_string())?;
    let data = memory.data(caller);
    let end = ptr
        .checked_add(len)
        .ok_or_else(|| "pointer overflow".to_string())?;
    if end > data.len() {
        return Err("memory read out of bounds".to_string());
    }
    Ok(data[ptr..end].to_vec())
}

fn write_wasm_memory(
    caller: &mut Caller<RuntimeState>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), String> {
    if ptr < 0 {
        return Err("negative pointer".to_string());
    }
    let ptr = ptr as usize;
    let memory = get_memory(caller).ok_or_else(|| "memory export not found".to_string())?;
    let end = ptr
        .checked_add(bytes.len())
        .ok_or_else(|| "pointer overflow".to_string())?;
    let data = memory.data_mut(caller);
    if end > data.len() {
        return Err("memory write out of bounds".to_string());
    }
    data[ptr..end].copy_from_slice(bytes);
    Ok(())
}

fn get_memory(caller: &mut Caller<RuntimeState>) -> Option<Memory> {
    let memory_export = caller.data().memory_export.clone();
    caller
        .get_export(&memory_export)
        .and_then(|export| export.into_memory())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_host_status_conversion() {
        assert_eq!(DataHostStatus::Success.to_i32(), 0);
        assert_eq!(DataHostStatus::Disabled.to_i32(), 1);
        assert_eq!(DataHostStatus::NotFound.to_i32(), -1);
        assert_eq!(DataHostStatus::InternalError.to_i32(), -100);

        assert_eq!(DataHostStatus::from_i32(0), DataHostStatus::Success);
        assert_eq!(DataHostStatus::from_i32(1), DataHostStatus::Disabled);
        assert_eq!(
            DataHostStatus::from_i32(-999),
            DataHostStatus::InternalError
        );
    }

    #[test]
    fn test_data_policy_default() {
        let policy = DataPolicy::default();
        assert!(!policy.enabled);
        assert_eq!(policy.max_key_size, 1024);
    }

    #[test]
    fn test_data_policy_development() {
        let policy = DataPolicy::development();
        assert!(policy.enabled);
        assert_eq!(policy.max_key_size, 4096);
    }

    #[test]
    fn test_filesystem_backend_rejects_traversal_in_key() {
        let tmp = std::env::temp_dir().join("platform_data_test");
        let _ = std::fs::create_dir_all(tmp.join("challenge-1"));
        let backend = FilesystemDataBackend::new(tmp.clone());
        let result = backend.get("challenge-1", "../../../etc/passwd");
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_filesystem_backend_rejects_traversal_in_challenge_id() {
        let tmp = std::env::temp_dir().join("platform_data_test2");
        let _ = std::fs::create_dir_all(&tmp);
        let backend = FilesystemDataBackend::new(tmp.clone());
        let result = backend.get("../etc", "passwd");
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_filesystem_backend_rejects_null_in_key() {
        let tmp = std::env::temp_dir().join("platform_data_test3");
        let _ = std::fs::create_dir_all(tmp.join("challenge-1"));
        let backend = FilesystemDataBackend::new(tmp.clone());
        let result = backend.get("challenge-1", "key\0evil");
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_filesystem_backend_rejects_empty_challenge_id() {
        let tmp = std::env::temp_dir().join("platform_data_test4");
        let _ = std::fs::create_dir_all(&tmp);
        let backend = FilesystemDataBackend::new(tmp.clone());
        let result = backend.get("", "key");
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_filesystem_backend_rejects_dot_dot_challenge_id() {
        let tmp = std::env::temp_dir().join("platform_data_test5");
        let _ = std::fs::create_dir_all(&tmp);
        let backend = FilesystemDataBackend::new(tmp.clone());
        let result = backend.get("..", "key");
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_noop_data_backend() {
        let backend = NoopDataBackend;
        assert!(backend.get("challenge-1", "key1").unwrap().is_none());
        assert!(backend.list("challenge-1", "").unwrap().is_empty());
    }

    #[test]
    fn test_data_state_creation() {
        let state = DataState::new(
            DataPolicy::default(),
            std::sync::Arc::new(NoopDataBackend),
            "test".to_string(),
        );
        assert_eq!(state.reads, 0);
    }

    #[test]
    fn test_data_state_reset() {
        let mut state = DataState::new(
            DataPolicy::default(),
            std::sync::Arc::new(NoopDataBackend),
            "test".to_string(),
        );
        state.reads = 10;
        state.reset_counters();
        assert_eq!(state.reads, 0);
    }
}
