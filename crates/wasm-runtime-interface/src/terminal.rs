//! Terminal Host Functions for WASM Challenges
//!
//! This module provides host functions that allow WASM code to execute
//! terminal commands, read/write files, list directories, get time, and
//! obtain deterministic random seeds — all within a sandboxed environment.
//!
//! # Host Functions (import module: `platform_terminal`)
//!
//! - `terminal_exec(req_ptr, req_len, resp_ptr, resp_len) -> i32`
//! - `terminal_read_file(path_ptr, path_len, buf_ptr, buf_len) -> i32`
//! - `terminal_write_file(path_ptr, path_len, data_ptr, data_len) -> i32`
//! - `terminal_list_dir(path_ptr, path_len, buf_ptr, buf_len) -> i32`
//! - `terminal_get_time() -> i64`
//! - `terminal_random_seed(buf_ptr, buf_len) -> i32`

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tracing::{info, warn};
use wait_timeout::ChildExt;
use wasmtime::{Caller, Linker, Memory};

pub const HOST_TERMINAL_NAMESPACE: &str = "platform_terminal";
pub const HOST_TERMINAL_EXEC: &str = "terminal_exec";
pub const HOST_TERMINAL_READ_FILE: &str = "terminal_read_file";
pub const HOST_TERMINAL_WRITE_FILE: &str = "terminal_write_file";
pub const HOST_TERMINAL_LIST_DIR: &str = "terminal_list_dir";
pub const HOST_TERMINAL_GET_TIME: &str = "terminal_get_time";
pub const HOST_TERMINAL_RANDOM_SEED: &str = "terminal_random_seed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalPolicy {
    pub allowed_commands: Vec<String>,
    pub sandbox_root: PathBuf,
    pub max_exec_time_ms: u64,
    pub max_output_bytes: usize,
    pub max_file_size: usize,
    pub allow_network_in_commands: bool,
}

impl Default for TerminalPolicy {
    fn default() -> Self {
        Self {
            allowed_commands: Vec::new(),
            sandbox_root: PathBuf::from("/tmp/wasm-sandbox"),
            max_exec_time_ms: 10_000,
            max_output_bytes: 1024 * 1024,
            max_file_size: 10 * 1024 * 1024,
            allow_network_in_commands: false,
        }
    }
}

impl TerminalPolicy {
    pub fn development() -> Self {
        Self {
            allowed_commands: vec![
                "ls".to_string(),
                "cat".to_string(),
                "echo".to_string(),
                "grep".to_string(),
                "wc".to_string(),
                "head".to_string(),
                "tail".to_string(),
                "sort".to_string(),
                "uniq".to_string(),
                "find".to_string(),
                "python3".to_string(),
                "node".to_string(),
            ],
            sandbox_root: PathBuf::from("/tmp/wasm-sandbox"),
            max_exec_time_ms: 30_000,
            max_output_bytes: 4 * 1024 * 1024,
            max_file_size: 50 * 1024 * 1024,
            allow_network_in_commands: false,
        }
    }

    pub fn is_command_allowed(&self, cmd: &str) -> bool {
        if self.allowed_commands.is_empty() {
            return false;
        }
        let base = Path::new(cmd)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(cmd);
        self.allowed_commands.iter().any(|allowed| allowed == base)
    }

    pub fn validate_sandbox_path(&self, path: &Path) -> Result<PathBuf, TerminalError> {
        let canonical_root = std::fs::canonicalize(&self.sandbox_root).map_err(|e| {
            TerminalError::SandboxViolation(format!("sandbox root does not exist: {}", e))
        })?;

        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else {
            canonical_root.join(path)
        };

        for component in joined.components() {
            if matches!(component, Component::ParentDir) {
                return Err(TerminalError::SandboxViolation(
                    "path traversal (..) not allowed".to_string(),
                ));
            }
        }

        let resolved = if joined.exists() {
            std::fs::canonicalize(&joined).map_err(|e| {
                TerminalError::SandboxViolation(format!("cannot resolve path: {}", e))
            })?
        } else {
            let parent = joined
                .parent()
                .ok_or_else(|| TerminalError::SandboxViolation("path has no parent".to_string()))?;
            let parent_canonical = std::fs::canonicalize(parent).map_err(|e| {
                TerminalError::SandboxViolation(format!("parent directory does not exist: {}", e))
            })?;
            let file_name = joined.file_name().ok_or_else(|| {
                TerminalError::SandboxViolation("path has no file name".to_string())
            })?;
            parent_canonical.join(file_name)
        };

        if !resolved.starts_with(&canonical_root) {
            return Err(TerminalError::SandboxViolation(format!(
                "path escapes sandbox: {} is not under {}",
                resolved.display(),
                canonical_root.display()
            )));
        }

        Ok(resolved)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub working_dir: Option<String>,
    pub stdin_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum TerminalError {
    #[error("command not allowed: {0}")]
    CommandNotAllowed(String),
    #[error("sandbox violation: {0}")]
    SandboxViolation(String),
    #[error("execution timeout")]
    Timeout,
    #[error("output too large: {0}")]
    OutputTooLarge(String),
    #[error("file too large: {0}")]
    FileTooLarge(String),
    #[error("io error: {0}")]
    IoError(String),
    #[error("execution error: {0}")]
    ExecutionError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalAuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub challenge_id: String,
    pub validator_id: String,
    pub action: TerminalAuditAction,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalAuditAction {
    CommandExec {
        command: String,
        args: Vec<String>,
        exit_code: Option<i32>,
    },
    ReadFile {
        path: String,
        bytes: u64,
    },
    WriteFile {
        path: String,
        bytes: u64,
    },
    ListDir {
        path: String,
        entry_count: usize,
    },
    GetTime,
    RandomSeed {
        bytes: usize,
    },
    PolicyDenied {
        reason: String,
    },
}

pub trait TerminalAuditLogger: Send + Sync {
    fn record(&self, entry: TerminalAuditEntry);
}

pub struct TerminalState {
    pub policy: TerminalPolicy,
    pub challenge_id: String,
    pub validator_id: String,
    pub audit_logger: Option<std::sync::Arc<dyn TerminalAuditLogger>>,
    pub commands_executed: u32,
    pub logical_clock_ms: i64,
}

impl TerminalState {
    pub fn new(
        policy: TerminalPolicy,
        challenge_id: String,
        validator_id: String,
        audit_logger: Option<std::sync::Arc<dyn TerminalAuditLogger>>,
    ) -> Self {
        Self {
            policy,
            challenge_id,
            validator_id,
            audit_logger,
            commands_executed: 0,
            logical_clock_ms: 0,
        }
    }

    pub fn reset_counters(&mut self) {
        self.commands_executed = 0;
        self.logical_clock_ms = 0;
    }

    pub fn exec_command(
        &mut self,
        request: CommandRequest,
    ) -> Result<CommandResult, TerminalError> {
        if !self.policy.is_command_allowed(&request.command) {
            self.audit_denial(&format!("command not allowed: {}", request.command));
            return Err(TerminalError::CommandNotAllowed(request.command));
        }

        let working_dir = if let Some(ref wd) = request.working_dir {
            self.policy.validate_sandbox_path(Path::new(wd))?
        } else {
            self.policy.sandbox_root.clone()
        };

        let mut cmd = Command::new(&request.command);
        cmd.args(&request.args);
        cmd.current_dir(&working_dir);
        cmd.env_clear();

        for (key, value) in &request.env {
            let key_upper = key.to_uppercase();
            if key_upper == "PATH" || key_upper == "LD_PRELOAD" || key_upper == "LD_LIBRARY_PATH" {
                continue;
            }
            cmd.env(key, value);
        }

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        if request.stdin_data.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }

        let mut child = cmd.spawn().map_err(|e| {
            TerminalError::ExecutionError(format!("failed to spawn command: {}", e))
        })?;

        if let Some(stdin_data) = &request.stdin_data {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(stdin_data);
            }
            child.stdin.take();
        }

        let timeout = Duration::from_millis(self.policy.max_exec_time_ms);
        let status = match child.wait_timeout(timeout) {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                self.audit(TerminalAuditAction::CommandExec {
                    command: request.command.clone(),
                    args: request.args.clone(),
                    exit_code: None,
                });
                return Err(TerminalError::Timeout);
            }
            Err(e) => {
                let _ = child.kill();
                return Err(TerminalError::ExecutionError(format!("wait failed: {}", e)));
            }
        };

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        if let Some(mut out) = child.stdout.take() {
            use std::io::Read;
            let mut buf = vec![0u8; self.policy.max_output_bytes + 1];
            let n = out.read(&mut buf).unwrap_or(0);
            if n > self.policy.max_output_bytes {
                return Err(TerminalError::OutputTooLarge(format!(
                    "stdout exceeds {} bytes",
                    self.policy.max_output_bytes
                )));
            }
            stdout = buf[..n].to_vec();
        }

        if let Some(mut err_stream) = child.stderr.take() {
            use std::io::Read;
            let mut buf = vec![0u8; self.policy.max_output_bytes + 1];
            let n = err_stream.read(&mut buf).unwrap_or(0);
            if n > self.policy.max_output_bytes {
                return Err(TerminalError::OutputTooLarge(format!(
                    "stderr exceeds {} bytes",
                    self.policy.max_output_bytes
                )));
            }
            stderr = buf[..n].to_vec();
        }

        let exit_code = status.code().unwrap_or(-1);
        self.commands_executed = self.commands_executed.saturating_add(1);

        self.audit(TerminalAuditAction::CommandExec {
            command: request.command,
            args: request.args,
            exit_code: Some(exit_code),
        });

        Ok(CommandResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, TerminalError> {
        let resolved = self.policy.validate_sandbox_path(Path::new(path))?;
        let data = std::fs::read(&resolved)
            .map_err(|e| TerminalError::IoError(format!("read failed: {}", e)))?;

        if data.len() > self.policy.max_file_size {
            return Err(TerminalError::FileTooLarge(format!(
                "file is {} bytes, max {}",
                data.len(),
                self.policy.max_file_size
            )));
        }

        self.audit(TerminalAuditAction::ReadFile {
            path: path.to_string(),
            bytes: data.len() as u64,
        });

        Ok(data)
    }

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), TerminalError> {
        if data.len() > self.policy.max_file_size {
            return Err(TerminalError::FileTooLarge(format!(
                "data is {} bytes, max {}",
                data.len(),
                self.policy.max_file_size
            )));
        }

        let resolved = self.policy.validate_sandbox_path(Path::new(path))?;
        std::fs::write(&resolved, data)
            .map_err(|e| TerminalError::IoError(format!("write failed: {}", e)))?;

        self.audit(TerminalAuditAction::WriteFile {
            path: path.to_string(),
            bytes: data.len() as u64,
        });

        Ok(())
    }

    pub fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, TerminalError> {
        let resolved = self.policy.validate_sandbox_path(Path::new(path))?;
        let entries = std::fs::read_dir(&resolved)
            .map_err(|e| TerminalError::IoError(format!("read_dir failed: {}", e)))?;

        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| TerminalError::IoError(format!("entry error: {}", e)))?;
            let metadata = entry
                .metadata()
                .map_err(|e| TerminalError::IoError(format!("metadata error: {}", e)))?;
            let name = entry.file_name().to_string_lossy().to_string();
            result.push(DirEntry {
                name,
                is_dir: metadata.is_dir(),
                size: metadata.len(),
            });
        }

        result.sort_by(|a, b| a.name.cmp(&b.name));

        self.audit(TerminalAuditAction::ListDir {
            path: path.to_string(),
            entry_count: result.len(),
        });

        Ok(result)
    }

    pub fn get_time(&mut self) -> i64 {
        self.logical_clock_ms += 1;
        self.audit(TerminalAuditAction::GetTime);
        self.logical_clock_ms
    }

    pub fn random_seed(&mut self, len: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.challenge_id.as_bytes());
        hasher.update(self.validator_id.as_bytes());
        hasher.update(self.commands_executed.to_le_bytes());
        hasher.update(self.logical_clock_ms.to_le_bytes());
        let base_hash = hasher.finalize();

        let mut output = Vec::with_capacity(len);
        let mut counter: u64 = 0;
        while output.len() < len {
            let mut h = Sha256::new();
            h.update(&base_hash);
            h.update(counter.to_le_bytes());
            let block = h.finalize();
            let remaining = len - output.len();
            let take = remaining.min(block.len());
            output.extend_from_slice(&block[..take]);
            counter += 1;
        }

        self.audit(TerminalAuditAction::RandomSeed { bytes: len });

        output
    }

    fn audit(&self, action: TerminalAuditAction) {
        if let Some(logger) = &self.audit_logger {
            logger.record(TerminalAuditEntry {
                timestamp: chrono::Utc::now(),
                challenge_id: self.challenge_id.clone(),
                validator_id: self.validator_id.clone(),
                action,
                metadata: HashMap::new(),
            });
        }
    }

    fn audit_denial(&self, reason: &str) {
        self.audit(TerminalAuditAction::PolicyDenied {
            reason: reason.to_string(),
        });
        warn!(
            challenge_id = %self.challenge_id,
            validator_id = %self.validator_id,
            reason = %reason,
            "terminal policy denied"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalHostFunction {
    TerminalExec,
    TerminalReadFile,
    TerminalWriteFile,
    TerminalListDir,
    TerminalGetTime,
    TerminalRandomSeed,
}

#[derive(Clone, Debug)]
pub struct TerminalHostFunctions {
    enabled: Vec<TerminalHostFunction>,
}

impl TerminalHostFunctions {
    pub fn new(enabled: Vec<TerminalHostFunction>) -> Self {
        Self { enabled }
    }

    pub fn all() -> Self {
        Self {
            enabled: vec![
                TerminalHostFunction::TerminalExec,
                TerminalHostFunction::TerminalReadFile,
                TerminalHostFunction::TerminalWriteFile,
                TerminalHostFunction::TerminalListDir,
                TerminalHostFunction::TerminalGetTime,
                TerminalHostFunction::TerminalRandomSeed,
            ],
        }
    }
}

impl Default for TerminalHostFunctions {
    fn default() -> Self {
        Self::all()
    }
}

impl HostFunctionRegistrar for TerminalHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        if self.enabled.contains(&TerminalHostFunction::TerminalExec) {
            linker
                .func_wrap(
                    HOST_TERMINAL_NAMESPACE,
                    HOST_TERMINAL_EXEC,
                    |mut caller: Caller<RuntimeState>,
                     req_ptr: i32,
                     req_len: i32,
                     resp_ptr: i32,
                     resp_len: i32|
                     -> i32 {
                        handle_terminal_exec(&mut caller, req_ptr, req_len, resp_ptr, resp_len)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        if self
            .enabled
            .contains(&TerminalHostFunction::TerminalReadFile)
        {
            linker
                .func_wrap(
                    HOST_TERMINAL_NAMESPACE,
                    HOST_TERMINAL_READ_FILE,
                    |mut caller: Caller<RuntimeState>,
                     path_ptr: i32,
                     path_len: i32,
                     buf_ptr: i32,
                     buf_len: i32|
                     -> i32 {
                        handle_terminal_read_file(&mut caller, path_ptr, path_len, buf_ptr, buf_len)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        if self
            .enabled
            .contains(&TerminalHostFunction::TerminalWriteFile)
        {
            linker
                .func_wrap(
                    HOST_TERMINAL_NAMESPACE,
                    HOST_TERMINAL_WRITE_FILE,
                    |mut caller: Caller<RuntimeState>,
                     path_ptr: i32,
                     path_len: i32,
                     data_ptr: i32,
                     data_len: i32|
                     -> i32 {
                        handle_terminal_write_file(
                            &mut caller,
                            path_ptr,
                            path_len,
                            data_ptr,
                            data_len,
                        )
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        if self
            .enabled
            .contains(&TerminalHostFunction::TerminalListDir)
        {
            linker
                .func_wrap(
                    HOST_TERMINAL_NAMESPACE,
                    HOST_TERMINAL_LIST_DIR,
                    |mut caller: Caller<RuntimeState>,
                     path_ptr: i32,
                     path_len: i32,
                     buf_ptr: i32,
                     buf_len: i32|
                     -> i32 {
                        handle_terminal_list_dir(&mut caller, path_ptr, path_len, buf_ptr, buf_len)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        if self
            .enabled
            .contains(&TerminalHostFunction::TerminalGetTime)
        {
            linker
                .func_wrap(
                    HOST_TERMINAL_NAMESPACE,
                    HOST_TERMINAL_GET_TIME,
                    |mut caller: Caller<RuntimeState>| -> i64 {
                        handle_terminal_get_time(&mut caller)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        if self
            .enabled
            .contains(&TerminalHostFunction::TerminalRandomSeed)
        {
            linker
                .func_wrap(
                    HOST_TERMINAL_NAMESPACE,
                    HOST_TERMINAL_RANDOM_SEED,
                    |mut caller: Caller<RuntimeState>, buf_ptr: i32, buf_len: i32| -> i32 {
                        handle_terminal_random_seed(&mut caller, buf_ptr, buf_len)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        Ok(())
    }
}

fn handle_terminal_exec(
    caller: &mut Caller<RuntimeState>,
    req_ptr: i32,
    req_len: i32,
    resp_ptr: i32,
    resp_len: i32,
) -> i32 {
    let request_bytes = match read_memory(caller, req_ptr, req_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                validator_id = %caller.data().validator_id,
                error = %err,
                "terminal_exec: memory read failed"
            );
            return write_terminal_result::<CommandResult>(
                caller,
                resp_ptr,
                resp_len,
                Err(TerminalError::ExecutionError(err)),
            );
        }
    };

    let request = match bincode::deserialize::<CommandRequest>(&request_bytes) {
        Ok(req) => req,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                validator_id = %caller.data().validator_id,
                error = %err,
                "terminal_exec: decode failed"
            );
            return write_terminal_result::<CommandResult>(
                caller,
                resp_ptr,
                resp_len,
                Err(TerminalError::ExecutionError(format!(
                    "invalid command request: {}",
                    err
                ))),
            );
        }
    };

    info!(
        challenge_id = %caller.data().challenge_id,
        validator_id = %caller.data().validator_id,
        command = %request.command,
        args = ?request.args,
        "terminal_exec: executing command"
    );

    let result = caller.data_mut().terminal_state.exec_command(request);

    if let Err(ref err) = result {
        warn!(
            challenge_id = %caller.data().challenge_id,
            validator_id = %caller.data().validator_id,
            error = %err,
            "terminal_exec: command failed"
        );
    }

    write_terminal_result(caller, resp_ptr, resp_len, result)
}

fn handle_terminal_read_file(
    caller: &mut Caller<RuntimeState>,
    path_ptr: i32,
    path_len: i32,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    let path_bytes = match read_memory(caller, path_ptr, path_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                validator_id = %caller.data().validator_id,
                error = %err,
                "terminal_read_file: memory read failed"
            );
            return -1;
        }
    };

    let path = match std::str::from_utf8(&path_bytes) {
        Ok(s) => s.to_string(),
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_read_file: invalid utf8 path"
            );
            return -1;
        }
    };

    let result = caller.data_mut().terminal_state.read_file(&path);

    match result {
        Ok(data) => write_bytes(caller, buf_ptr, buf_len, &data),
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_read_file: failed"
            );
            let err_bytes = match bincode::serialize(&Err::<Vec<u8>, TerminalError>(err)) {
                Ok(b) => b,
                Err(_) => return -1,
            };
            write_bytes(caller, buf_ptr, buf_len, &err_bytes)
        }
    }
}

fn handle_terminal_write_file(
    caller: &mut Caller<RuntimeState>,
    path_ptr: i32,
    path_len: i32,
    data_ptr: i32,
    data_len: i32,
) -> i32 {
    let path_bytes = match read_memory(caller, path_ptr, path_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_write_file: path memory read failed"
            );
            return -1;
        }
    };

    let path = match std::str::from_utf8(&path_bytes) {
        Ok(s) => s.to_string(),
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_write_file: invalid utf8 path"
            );
            return -1;
        }
    };

    let data = match read_memory(caller, data_ptr, data_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_write_file: data memory read failed"
            );
            return -1;
        }
    };

    match caller.data_mut().terminal_state.write_file(&path, &data) {
        Ok(()) => 0,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_write_file: failed"
            );
            -1
        }
    }
}

fn handle_terminal_list_dir(
    caller: &mut Caller<RuntimeState>,
    path_ptr: i32,
    path_len: i32,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    let path_bytes = match read_memory(caller, path_ptr, path_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_list_dir: memory read failed"
            );
            return -1;
        }
    };

    let path = match std::str::from_utf8(&path_bytes) {
        Ok(s) => s.to_string(),
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_list_dir: invalid utf8 path"
            );
            return -1;
        }
    };

    let result = caller.data_mut().terminal_state.list_dir(&path);

    match result {
        Ok(entries) => {
            let serialized = match bincode::serialize(&entries) {
                Ok(bytes) => bytes,
                Err(err) => {
                    warn!(error = %err, "terminal_list_dir: serialize failed");
                    return -1;
                }
            };
            write_bytes(caller, buf_ptr, buf_len, &serialized)
        }
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "terminal_list_dir: failed"
            );
            -1
        }
    }
}

fn handle_terminal_get_time(caller: &mut Caller<RuntimeState>) -> i64 {
    caller.data_mut().terminal_state.get_time()
}

fn handle_terminal_random_seed(
    caller: &mut Caller<RuntimeState>,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    if buf_len < 0 {
        return -1;
    }
    let len = buf_len as usize;
    let seed_bytes = caller.data_mut().terminal_state.random_seed(len);
    write_bytes(caller, buf_ptr, buf_len, &seed_bytes)
}

fn read_memory(caller: &mut Caller<RuntimeState>, ptr: i32, len: i32) -> Result<Vec<u8>, String> {
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

fn write_terminal_result<T: serde::Serialize>(
    caller: &mut Caller<RuntimeState>,
    resp_ptr: i32,
    resp_len: i32,
    result: Result<T, TerminalError>,
) -> i32 {
    let response_bytes = match bincode::serialize(&result) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "failed to serialize terminal response");
            return -1;
        }
    };
    write_bytes(caller, resp_ptr, resp_len, &response_bytes)
}

fn write_bytes(
    caller: &mut Caller<RuntimeState>,
    resp_ptr: i32,
    resp_len: i32,
    bytes: &[u8],
) -> i32 {
    if resp_ptr < 0 || resp_len < 0 {
        return -1;
    }
    if bytes.len() > i32::MAX as usize {
        return -1;
    }
    let resp_len = resp_len as usize;
    if bytes.len() > resp_len {
        return -(bytes.len() as i32);
    }

    let memory = match get_memory(caller) {
        Some(memory) => memory,
        None => return -1,
    };

    let ptr = resp_ptr as usize;
    let end = match ptr.checked_add(bytes.len()) {
        Some(end) => end,
        None => return -1,
    };
    let data = memory.data_mut(caller);
    if end > data.len() {
        return -1;
    }
    data[ptr..end].copy_from_slice(bytes);
    bytes.len() as i32
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
    fn test_terminal_policy_default() {
        let policy = TerminalPolicy::default();
        assert!(policy.allowed_commands.is_empty());
        assert_eq!(policy.max_exec_time_ms, 10_000);
        assert!(!policy.allow_network_in_commands);
    }

    #[test]
    fn test_terminal_policy_development() {
        let policy = TerminalPolicy::development();
        assert!(!policy.allowed_commands.is_empty());
        assert!(policy.allowed_commands.contains(&"ls".to_string()));
        assert!(policy.allowed_commands.contains(&"python3".to_string()));
    }

    #[test]
    fn test_command_allowed() {
        let policy = TerminalPolicy {
            allowed_commands: vec!["ls".to_string(), "cat".to_string()],
            ..Default::default()
        };
        assert!(policy.is_command_allowed("ls"));
        assert!(policy.is_command_allowed("cat"));
        assert!(!policy.is_command_allowed("rm"));
        assert!(!policy.is_command_allowed("bash"));
    }

    #[test]
    fn test_command_allowed_with_path() {
        let policy = TerminalPolicy {
            allowed_commands: vec!["ls".to_string()],
            ..Default::default()
        };
        assert!(policy.is_command_allowed("/usr/bin/ls"));
        assert!(!policy.is_command_allowed("/usr/bin/rm"));
    }

    #[test]
    fn test_empty_allowed_commands_blocks_all() {
        let policy = TerminalPolicy::default();
        assert!(!policy.is_command_allowed("ls"));
        assert!(!policy.is_command_allowed("anything"));
    }

    #[test]
    fn test_sandbox_path_traversal_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let policy = TerminalPolicy {
            sandbox_root: dir.path().to_path_buf(),
            ..Default::default()
        };
        let result = policy.validate_sandbox_path(Path::new("../etc/passwd"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TerminalError::SandboxViolation(_)
        ));
    }

    #[test]
    fn test_sandbox_path_valid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.txt"), "hello").unwrap();
        let policy = TerminalPolicy {
            sandbox_root: dir.path().to_path_buf(),
            ..Default::default()
        };
        let result = policy.validate_sandbox_path(Path::new("test.txt"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_terminal_state_exec_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = TerminalState::new(
            TerminalPolicy {
                allowed_commands: vec!["ls".to_string()],
                sandbox_root: dir.path().to_path_buf(),
                ..Default::default()
            },
            "test-challenge".to_string(),
            "test-validator".to_string(),
            None,
        );

        let result = state.exec_command(CommandRequest {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/".to_string()],
            env: HashMap::new(),
            working_dir: None,
            stdin_data: None,
        });

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TerminalError::CommandNotAllowed(_)
        ));
    }

    #[test]
    fn test_terminal_state_exec_allowed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "world").unwrap();
        let mut state = TerminalState::new(
            TerminalPolicy {
                allowed_commands: vec!["echo".to_string()],
                sandbox_root: dir.path().to_path_buf(),
                ..Default::default()
            },
            "test-challenge".to_string(),
            "test-validator".to_string(),
            None,
        );

        let result = state.exec_command(CommandRequest {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            env: HashMap::new(),
            working_dir: None,
            stdin_data: None,
        });

        assert!(result.is_ok());
        let cmd_result = result.unwrap();
        assert_eq!(cmd_result.exit_code, 0);
        assert!(String::from_utf8_lossy(&cmd_result.stdout).contains("hello"));
    }

    #[test]
    fn test_terminal_state_read_write_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = TerminalState::new(
            TerminalPolicy {
                sandbox_root: dir.path().to_path_buf(),
                ..Default::default()
            },
            "test".to_string(),
            "test".to_string(),
            None,
        );

        state.write_file("test.txt", b"hello world").unwrap();
        let data = state.read_file("test.txt").unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn test_terminal_state_list_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "a").unwrap();
        std::fs::write(dir.path().join("b.txt"), "bb").unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let mut state = TerminalState::new(
            TerminalPolicy {
                sandbox_root: dir.path().to_path_buf(),
                ..Default::default()
            },
            "test".to_string(),
            "test".to_string(),
            None,
        );

        let entries = state.list_dir(".").unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().any(|e| e.name == "a.txt" && !e.is_dir));
        assert!(entries.iter().any(|e| e.name == "subdir" && e.is_dir));
    }

    #[test]
    fn test_terminal_state_get_time() {
        let mut state = TerminalState::new(
            TerminalPolicy::default(),
            "test".to_string(),
            "test".to_string(),
            None,
        );

        let t1 = state.get_time();
        let t2 = state.get_time();
        assert_eq!(t1, 1);
        assert_eq!(t2, 2);
        assert!(t2 > t1);
    }

    #[test]
    fn test_terminal_state_random_seed_deterministic() {
        let mut state1 = TerminalState::new(
            TerminalPolicy::default(),
            "challenge-1".to_string(),
            "validator-1".to_string(),
            None,
        );
        let mut state2 = TerminalState::new(
            TerminalPolicy::default(),
            "challenge-1".to_string(),
            "validator-1".to_string(),
            None,
        );

        let seed1 = state1.random_seed(32);
        let seed2 = state2.random_seed(32);
        assert_eq!(seed1, seed2);
        assert_eq!(seed1.len(), 32);
    }

    #[test]
    fn test_terminal_state_random_seed_different_contexts() {
        let mut state1 = TerminalState::new(
            TerminalPolicy::default(),
            "challenge-1".to_string(),
            "validator-1".to_string(),
            None,
        );
        let mut state2 = TerminalState::new(
            TerminalPolicy::default(),
            "challenge-2".to_string(),
            "validator-1".to_string(),
            None,
        );

        let seed1 = state1.random_seed(32);
        let seed2 = state2.random_seed(32);
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_file_too_large_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = TerminalState::new(
            TerminalPolicy {
                sandbox_root: dir.path().to_path_buf(),
                max_file_size: 10,
                ..Default::default()
            },
            "test".to_string(),
            "test".to_string(),
            None,
        );

        let result = state.write_file("big.txt", &vec![0u8; 100]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TerminalError::FileTooLarge(_)
        ));
    }

    #[test]
    fn test_terminal_host_functions_all() {
        let funcs = TerminalHostFunctions::all();
        assert_eq!(funcs.enabled.len(), 6);
    }
}
