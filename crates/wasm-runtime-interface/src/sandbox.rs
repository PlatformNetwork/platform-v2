use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};
use wait_timeout::ChildExt;
use wasmtime::{Caller, Linker, Memory};

pub const HOST_SANDBOX_NAMESPACE: &str = "platform_sandbox";
pub const HOST_SANDBOX_EXEC: &str = "sandbox_exec";
pub const HOST_GET_TIMESTAMP: &str = "get_timestamp";
pub const HOST_LOG_MESSAGE: &str = "log_message";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecRequest {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub stdin: Option<Vec<u8>>,
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecResponse {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum SandboxError {
    #[error("sandbox disabled")]
    SandboxDisabled,
    #[error("command not allowed: {0}")]
    CommandNotAllowed(String),
    #[error("execution timeout: {0}ms")]
    Timeout(u64),
    #[error("output too large: {0} bytes")]
    OutputTooLarge(usize),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("policy violation: {0}")]
    PolicyViolation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub allowed_commands: Vec<String>,
    pub blocked_commands: Vec<String>,
    pub max_execution_time_ms: u64,
    pub max_output_bytes: usize,
    pub allow_network: bool,
    pub working_directory: PathBuf,
    pub environment_whitelist: Vec<String>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            allowed_commands: Vec::new(),
            blocked_commands: Vec::new(),
            max_execution_time_ms: 30_000,
            max_output_bytes: 1024 * 1024,
            allow_network: false,
            working_directory: PathBuf::from("/tmp"),
            environment_whitelist: Vec::new(),
        }
    }
}

impl SandboxPolicy {
    pub fn permissive() -> Self {
        Self {
            allowed_commands: Vec::new(),
            blocked_commands: Vec::new(),
            max_execution_time_ms: 60_000,
            max_output_bytes: 10 * 1024 * 1024,
            allow_network: false,
            working_directory: PathBuf::from("/tmp"),
            environment_whitelist: vec![
                "PATH".to_string(),
                "HOME".to_string(),
                "USER".to_string(),
                "LANG".to_string(),
                "TERM".to_string(),
            ],
        }
    }

    pub fn is_command_allowed(&self, command: &str) -> Result<(), SandboxError> {
        let basename = std::path::Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command);

        for blocked in &self.blocked_commands {
            if command == blocked || basename == blocked {
                return Err(SandboxError::CommandNotAllowed(command.to_string()));
            }
        }

        if !self.allowed_commands.is_empty() {
            let allowed = self
                .allowed_commands
                .iter()
                .any(|a| command == a || basename == a);
            if !allowed {
                return Err(SandboxError::CommandNotAllowed(command.to_string()));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampMode {
    RealTime,
    Deterministic(i64),
}

#[allow(clippy::derivable_impls)]
impl Default for TimestampMode {
    fn default() -> Self {
        Self::RealTime
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl LogLevel {
    pub fn from_i32(level: i32) -> Self {
        match level {
            0 => Self::Trace,
            1 => Self::Debug,
            2 => Self::Info,
            3 => Self::Warn,
            4 => Self::Error,
            _ => Self::Info,
        }
    }
}

pub struct SandboxState {
    pub policy: SandboxPolicy,
    pub timestamp_mode: TimestampMode,
    pub executions_count: u32,
    pub challenge_id: String,
    pub validator_id: String,
}

impl SandboxState {
    pub fn new(
        policy: SandboxPolicy,
        timestamp_mode: TimestampMode,
        challenge_id: String,
        validator_id: String,
    ) -> Self {
        Self {
            policy,
            timestamp_mode,
            executions_count: 0,
            challenge_id,
            validator_id,
        }
    }

    pub fn reset_counters(&mut self) {
        self.executions_count = 0;
    }

    pub fn handle_exec(
        &mut self,
        request: SandboxExecRequest,
    ) -> Result<SandboxExecResponse, SandboxError> {
        self.policy.is_command_allowed(&request.command)?;

        let working_dir = request
            .working_directory
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.policy.working_directory.clone());

        let mut cmd = Command::new(&request.command);
        cmd.args(&request.args);
        cmd.current_dir(&working_dir);
        cmd.env_clear();

        for (key, value) in &request.env {
            if self.policy.environment_whitelist.is_empty()
                || self.policy.environment_whitelist.contains(key)
            {
                cmd.env(key, value);
            }
        }

        if request.stdin.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let start = Instant::now();
        let timeout = Duration::from_millis(self.policy.max_execution_time_ms);

        let mut child = cmd
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(e.to_string()))?;

        if let Some(stdin_data) = &request.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(stdin_data);
            }
        }

        let exit_status = match child.wait_timeout(timeout) {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::Timeout(self.policy.max_execution_time_ms));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(SandboxError::ExecutionFailed(e.to_string()));
            }
        };

        let duration = start.elapsed();

        let mut stdout = Vec::new();
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_end(&mut stdout);
        }

        let mut stderr = Vec::new();
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_end(&mut stderr);
        }

        if stdout.len() > self.policy.max_output_bytes {
            stdout.truncate(self.policy.max_output_bytes);
        }
        if stderr.len() > self.policy.max_output_bytes {
            stderr.truncate(self.policy.max_output_bytes);
        }

        self.executions_count = self.executions_count.saturating_add(1);

        let exit_code = exit_status.code().unwrap_or(-1);

        info!(
            challenge_id = %self.challenge_id,
            validator_id = %self.validator_id,
            command = %request.command,
            exit_code = exit_code,
            duration_ms = duration.as_millis() as u64,
            stdout_bytes = stdout.len(),
            stderr_bytes = stderr.len(),
            "sandbox exec completed"
        );

        Ok(SandboxExecResponse {
            exit_code,
            stdout,
            stderr,
            duration_ms: duration.as_millis() as u64,
        })
    }

    pub fn get_timestamp(&self) -> i64 {
        match self.timestamp_mode {
            TimestampMode::RealTime => chrono::Utc::now().timestamp_millis(),
            TimestampMode::Deterministic(ts) => ts,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SandboxHostFunctions;

impl SandboxHostFunctions {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SandboxHostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl HostFunctionRegistrar for SandboxHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        linker
            .func_wrap(
                HOST_SANDBOX_NAMESPACE,
                HOST_SANDBOX_EXEC,
                |mut caller: Caller<RuntimeState>,
                 req_ptr: i32,
                 req_len: i32,
                 resp_ptr: i32,
                 resp_len: i32|
                 -> i32 {
                    handle_sandbox_exec(&mut caller, req_ptr, req_len, resp_ptr, resp_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_SANDBOX_NAMESPACE,
                HOST_GET_TIMESTAMP,
                |caller: Caller<RuntimeState>| -> i64 {
                    caller.data().sandbox_state.get_timestamp()
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_SANDBOX_NAMESPACE,
                HOST_LOG_MESSAGE,
                |mut caller: Caller<RuntimeState>, level: i32, msg_ptr: i32, msg_len: i32| {
                    handle_log_message(&mut caller, level, msg_ptr, msg_len);
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        Ok(())
    }
}

fn handle_sandbox_exec(
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
                function = "sandbox_exec",
                error = %err,
                "host memory read failed"
            );
            return write_result::<SandboxExecResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(SandboxError::ExecutionFailed(err)),
            );
        }
    };

    let request = match bincode::deserialize::<SandboxExecRequest>(&request_bytes) {
        Ok(req) => req,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                validator_id = %caller.data().validator_id,
                function = "sandbox_exec",
                error = %err,
                "host request decode failed"
            );
            return write_result::<SandboxExecResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(SandboxError::ExecutionFailed(format!(
                    "invalid sandbox exec payload: {err}"
                ))),
            );
        }
    };

    let result = caller.data_mut().sandbox_state.handle_exec(request);
    if let Err(ref err) = result {
        warn!(
            challenge_id = %caller.data().challenge_id,
            validator_id = %caller.data().validator_id,
            function = "sandbox_exec",
            error = %err,
            "sandbox exec denied"
        );
    }
    write_result(caller, resp_ptr, resp_len, result)
}

fn handle_log_message(caller: &mut Caller<RuntimeState>, level: i32, msg_ptr: i32, msg_len: i32) {
    let msg_bytes = match read_memory(caller, msg_ptr, msg_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                validator_id = %caller.data().validator_id,
                function = "log_message",
                error = %err,
                "host memory read failed for log message"
            );
            return;
        }
    };

    let message = String::from_utf8_lossy(&msg_bytes);
    let challenge_id = caller.data().challenge_id.clone();
    let validator_id = caller.data().validator_id.clone();
    let log_level = LogLevel::from_i32(level);

    match log_level {
        LogLevel::Trace => {
            tracing::trace!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                source = "wasm",
                "{}",
                message
            );
        }
        LogLevel::Debug => {
            debug!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                source = "wasm",
                "{}",
                message
            );
        }
        LogLevel::Info => {
            info!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                source = "wasm",
                "{}",
                message
            );
        }
        LogLevel::Warn => {
            warn!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                source = "wasm",
                "{}",
                message
            );
        }
        LogLevel::Error => {
            error!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                source = "wasm",
                "{}",
                message
            );
        }
    }
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

fn write_result<T: serde::Serialize>(
    caller: &mut Caller<RuntimeState>,
    resp_ptr: i32,
    resp_len: i32,
    result: Result<T, SandboxError>,
) -> i32 {
    let response_bytes = match bincode::serialize(&result) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "failed to serialize sandbox response");
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
    fn test_sandbox_policy_default() {
        let policy = SandboxPolicy::default();
        assert!(policy.allowed_commands.is_empty());
        assert!(policy.blocked_commands.is_empty());
        assert_eq!(policy.max_execution_time_ms, 30_000);
        assert_eq!(policy.max_output_bytes, 1024 * 1024);
        assert!(!policy.allow_network);
        assert_eq!(policy.working_directory, PathBuf::from("/tmp"));
    }

    #[test]
    fn test_sandbox_policy_permissive() {
        let policy = SandboxPolicy::permissive();
        assert_eq!(policy.max_execution_time_ms, 60_000);
        assert_eq!(policy.max_output_bytes, 10 * 1024 * 1024);
        assert!(!policy.environment_whitelist.is_empty());
    }

    #[test]
    fn test_command_allowed_empty_allowlist() {
        let policy = SandboxPolicy::default();
        assert!(policy.is_command_allowed("ls").is_ok());
        assert!(policy.is_command_allowed("cat").is_ok());
    }

    #[test]
    fn test_command_allowed_with_allowlist() {
        let mut policy = SandboxPolicy::default();
        policy.allowed_commands = vec!["ls".to_string(), "cat".to_string()];
        assert!(policy.is_command_allowed("ls").is_ok());
        assert!(policy.is_command_allowed("cat").is_ok());
        assert!(policy.is_command_allowed("rm").is_err());
    }

    #[test]
    fn test_command_blocked() {
        let mut policy = SandboxPolicy::default();
        policy.blocked_commands = vec!["rm".to_string(), "dd".to_string()];
        assert!(policy.is_command_allowed("ls").is_ok());
        assert!(policy.is_command_allowed("rm").is_err());
        assert!(policy.is_command_allowed("dd").is_err());
    }

    #[test]
    fn test_command_blocked_by_basename() {
        let mut policy = SandboxPolicy::default();
        policy.blocked_commands = vec!["rm".to_string()];
        assert!(policy.is_command_allowed("/bin/rm").is_err());
    }

    #[test]
    fn test_command_allowed_by_basename() {
        let mut policy = SandboxPolicy::default();
        policy.allowed_commands = vec!["ls".to_string()];
        assert!(policy.is_command_allowed("/bin/ls").is_ok());
        assert!(policy.is_command_allowed("/usr/bin/cat").is_err());
    }

    #[test]
    fn test_blocked_takes_precedence() {
        let mut policy = SandboxPolicy::default();
        policy.allowed_commands = vec!["rm".to_string()];
        policy.blocked_commands = vec!["rm".to_string()];
        assert!(policy.is_command_allowed("rm").is_err());
    }

    #[test]
    fn test_log_level_from_i32() {
        assert_eq!(LogLevel::from_i32(0), LogLevel::Trace);
        assert_eq!(LogLevel::from_i32(1), LogLevel::Debug);
        assert_eq!(LogLevel::from_i32(2), LogLevel::Info);
        assert_eq!(LogLevel::from_i32(3), LogLevel::Warn);
        assert_eq!(LogLevel::from_i32(4), LogLevel::Error);
        assert_eq!(LogLevel::from_i32(99), LogLevel::Info);
    }

    #[test]
    fn test_timestamp_mode_real_time() {
        let state = SandboxState::new(
            SandboxPolicy::default(),
            TimestampMode::RealTime,
            "test".into(),
            "test".into(),
        );
        let ts = state.get_timestamp();
        assert!(ts > 0);
    }

    #[test]
    fn test_timestamp_mode_deterministic() {
        let fixed_ts = 1700000000000i64;
        let state = SandboxState::new(
            SandboxPolicy::default(),
            TimestampMode::Deterministic(fixed_ts),
            "test".into(),
            "test".into(),
        );
        assert_eq!(state.get_timestamp(), fixed_ts);
    }

    #[test]
    fn test_sandbox_exec_simple_command() {
        let mut state = SandboxState::new(
            SandboxPolicy::default(),
            TimestampMode::RealTime,
            "test".into(),
            "test".into(),
        );

        let request = SandboxExecRequest {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            env: HashMap::new(),
            stdin: None,
            working_directory: None,
        };

        let result = state.handle_exec(request);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&response.stdout).trim(), "hello");
        assert_eq!(state.executions_count, 1);
    }

    #[test]
    fn test_sandbox_exec_blocked_command() {
        let mut policy = SandboxPolicy::default();
        policy.blocked_commands = vec!["rm".to_string()];
        let mut state = SandboxState::new(
            policy,
            TimestampMode::RealTime,
            "test".into(),
            "test".into(),
        );

        let request = SandboxExecRequest {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/".to_string()],
            env: HashMap::new(),
            stdin: None,
            working_directory: None,
        };

        let result = state.handle_exec(request);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SandboxError::CommandNotAllowed(_)
        ));
    }

    #[test]
    fn test_sandbox_exec_output_truncation() {
        let mut policy = SandboxPolicy::default();
        policy.max_output_bytes = 5;
        let mut state = SandboxState::new(
            policy,
            TimestampMode::RealTime,
            "test".into(),
            "test".into(),
        );

        let request = SandboxExecRequest {
            command: "echo".to_string(),
            args: vec!["hello world this is a long message".to_string()],
            env: HashMap::new(),
            stdin: None,
            working_directory: None,
        };

        let result = state.handle_exec(request);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.stdout.len() <= 5);
    }

    #[test]
    fn test_sandbox_state_reset_counters() {
        let mut state = SandboxState::new(
            SandboxPolicy::default(),
            TimestampMode::RealTime,
            "test".into(),
            "test".into(),
        );
        state.executions_count = 5;
        state.reset_counters();
        assert_eq!(state.executions_count, 0);
    }
}
