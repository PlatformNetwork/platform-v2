//! Docker Runner for Agent Execution
//!
//! Executes agents in isolated Docker containers with:
//! - Network isolation (only allowed hosts)
//! - Resource limits (CPU, memory, time)
//! - LLM API proxy injection
//! - Output capture
//!
//! SECURITY: Only whitelisted base images are allowed for agent execution.

use crate::host_functions::{
    ExecuteAgentRequest, ExecuteAgentResult, LLMCallRecord, TestResult, VerifyTaskRequest,
    VerifyTaskResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Allowed base images for agent execution
/// SECURITY: Only these images are allowed to run agents
pub const ALLOWED_BASE_IMAGES: &[&str] = &[
    "python:3.11-slim",
    "python:3.12-slim",
    "python:3.11",
    "python:3.12",
    "node:20-slim",
    "node:22-slim",
    "rust:1.75-slim",
    "rust:1.76-slim",
    "ghcr.io/platformnetwork/agent-runner:", // Custom runner images
];

/// Docker runner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerRunnerConfig {
    /// Base image for agent execution (must be whitelisted)
    pub base_image: String,
    /// Docker socket path
    pub docker_socket: String,
    /// Working directory base path
    pub work_dir_base: PathBuf,
    /// Network name for isolated network
    pub network_name: String,
    /// LLM proxy URL (injected into containers)
    pub llm_proxy_url: String,
    /// Default memory limit (MB)
    pub default_memory_mb: u64,
    /// Default CPU limit (cores)
    pub default_cpu_cores: f32,
    /// Default timeout (seconds)
    pub default_timeout_secs: u64,
    /// Enable seccomp profile
    pub enable_seccomp: bool,
    /// Read-only root filesystem
    pub read_only_root: bool,
    /// Drop all capabilities
    pub drop_capabilities: bool,
}

impl Default for DockerRunnerConfig {
    fn default() -> Self {
        Self {
            base_image: "python:3.11-slim".to_string(),
            docker_socket: "/var/run/docker.sock".to_string(),
            work_dir_base: PathBuf::from("/tmp/challenge-runner"),
            network_name: "challenge-isolated".to_string(),
            llm_proxy_url: "http://host.docker.internal:8081".to_string(),
            default_memory_mb: 4096,
            default_cpu_cores: 2.0,
            default_timeout_secs: 300,
            enable_seccomp: true,
            read_only_root: true,
            drop_capabilities: true,
        }
    }
}

/// Docker runner
pub struct DockerRunner {
    config: DockerRunnerConfig,
    /// Track running containers
    running_containers: Arc<RwLock<HashMap<String, RunningContainer>>>,
    /// LLM call records (populated by proxy)
    llm_records: Arc<RwLock<Vec<LLMCallRecord>>>,
}

/// Running container info
#[derive(Debug, Clone)]
struct RunningContainer {
    container_id: String,
    execution_id: String,
    started_at: Instant,
    agent_hash: String,
    task_id: String,
}

impl DockerRunner {
    /// Check if a base image is allowed
    /// SECURITY: Prevents running agents with unauthorized images
    fn is_base_image_allowed(image: &str) -> bool {
        let image_lower = image.to_lowercase();
        ALLOWED_BASE_IMAGES.iter().any(|allowed| {
            let allowed_lower = allowed.to_lowercase();
            // Exact match or prefix match (for versioned images like ghcr.io/platformnetwork/agent-runner:v1)
            image_lower == allowed_lower || image_lower.starts_with(&allowed_lower)
        })
    }

    pub fn new(config: DockerRunnerConfig) -> Result<Self, String> {
        // SECURITY: Validate base image on creation
        if !Self::is_base_image_allowed(&config.base_image) {
            return Err(format!(
                "Base image '{}' is not whitelisted. Allowed images: {:?}",
                config.base_image, ALLOWED_BASE_IMAGES
            ));
        }

        Ok(Self {
            config,
            running_containers: Arc::new(RwLock::new(HashMap::new())),
            llm_records: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create with default config (always uses whitelisted image)
    pub fn with_defaults() -> Self {
        Self {
            config: DockerRunnerConfig::default(),
            running_containers: Arc::new(RwLock::new(HashMap::new())),
            llm_records: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize the runner (create network, etc)
    pub async fn init(&self) -> Result<(), String> {
        // Create work directory
        tokio::fs::create_dir_all(&self.config.work_dir_base)
            .await
            .map_err(|e| format!("Failed to create work dir: {}", e))?;

        // Create isolated network if it doesn't exist
        self.create_network_if_needed().await?;

        info!("Docker runner initialized");
        Ok(())
    }

    /// Create isolated network
    async fn create_network_if_needed(&self) -> Result<(), String> {
        let output = Command::new("docker")
            .args(["network", "ls", "--format", "{{.Name}}"])
            .output()
            .await
            .map_err(|e| format!("Failed to list networks: {}", e))?;

        let networks = String::from_utf8_lossy(&output.stdout);
        if networks.lines().any(|n| n == self.config.network_name) {
            debug!("Network {} already exists", self.config.network_name);
            return Ok(());
        }

        let output = Command::new("docker")
            .args([
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal", // No external access by default
                &self.config.network_name,
            ])
            .output()
            .await
            .map_err(|e| format!("Failed to create network: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Failed to create network: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        info!("Created isolated network: {}", self.config.network_name);
        Ok(())
    }

    /// Execute an agent
    pub async fn execute_agent(
        &self,
        request: ExecuteAgentRequest,
    ) -> Result<ExecuteAgentResult, String> {
        let execution_id = Uuid::new_v4().to_string();
        let start_time = Instant::now();

        info!(
            "Starting agent execution {} for agent {} task {}",
            execution_id, request.agent_hash, request.task_id
        );

        // Create working directory
        let work_dir = self.config.work_dir_base.join(&execution_id);
        tokio::fs::create_dir_all(&work_dir)
            .await
            .map_err(|e| format!("Failed to create work dir: {}", e))?;

        // Write files to working directory
        for (path, content) in &request.files {
            let file_path = work_dir.join(path);
            if let Some(parent) = file_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| format!("Failed to create dir: {}", e))?;
            }
            tokio::fs::write(&file_path, content)
                .await
                .map_err(|e| format!("Failed to write file {}: {}", path, e))?;
        }

        // Write agent code
        let agent_code_path = work_dir.join("agent.py");
        // Agent code should be in request.files["agent.py"]

        // Write instruction to task.txt
        tokio::fs::write(work_dir.join("task.txt"), &request.instruction)
            .await
            .map_err(|e| format!("Failed to write task: {}", e))?;

        // Build docker run command
        let mut cmd = Command::new("docker");
        cmd.arg("run");

        // Remove container after exit
        cmd.arg("--rm");

        // Container name
        let container_name = format!("challenge-{}", execution_id);
        cmd.args(["--name", &container_name]);

        // Resource limits
        let memory_mb = if request.memory_limit_mb > 0 {
            request.memory_limit_mb
        } else {
            self.config.default_memory_mb
        };
        cmd.args(["--memory", &format!("{}m", memory_mb)]);
        cmd.args(["--memory-swap", &format!("{}m", memory_mb)]); // No swap

        let cpu = if request.cpu_limit > 0.0 {
            request.cpu_limit
        } else {
            self.config.default_cpu_cores
        };
        cmd.args(["--cpus", &format!("{}", cpu)]);

        // Network
        if request.allow_network {
            // Use host network with proxy
            cmd.args(["--network", "bridge"]);
            // Inject proxy URL
            cmd.args([
                "-e",
                &format!("LLM_PROXY_URL={}", self.config.llm_proxy_url),
            ]);
            cmd.args([
                "-e",
                &format!("OPENAI_BASE_URL={}/openai", self.config.llm_proxy_url),
            ]);
            cmd.args([
                "-e",
                &format!("ANTHROPIC_BASE_URL={}/anthropic", self.config.llm_proxy_url),
            ]);
        } else {
            cmd.args(["--network", "none"]);
        }

        // Security options
        if self.config.read_only_root {
            cmd.arg("--read-only");
            cmd.args(["--tmpfs", "/tmp:rw,noexec,nosuid,size=512m"]);
        }

        if self.config.drop_capabilities {
            cmd.args(["--cap-drop", "ALL"]);
        }

        // No privileged operations
        cmd.args(["--security-opt", "no-new-privileges"]);

        // User (non-root)
        cmd.args(["--user", "1000:1000"]);

        // Environment variables
        for (key, value) in &request.env_vars {
            cmd.args(["-e", &format!("{}={}", key, value)]);
        }

        // Execution ID for tracking
        cmd.args(["-e", &format!("EXECUTION_ID={}", execution_id)]);
        cmd.args(["-e", &format!("AGENT_HASH={}", request.agent_hash)]);
        cmd.args(["-e", &format!("TASK_ID={}", request.task_id)]);

        // Mount working directory
        cmd.args(["-v", &format!("{}:/workspace:rw", work_dir.display())]);
        cmd.args(["-w", "/workspace"]);

        // Image and command
        cmd.arg(&self.config.base_image);
        cmd.args(["python", "agent.py"]);

        // Set up timeout
        let timeout_secs = if request.timeout_secs > 0 {
            request.timeout_secs
        } else {
            self.config.default_timeout_secs
        };

        // Track running container
        {
            let mut running = self.running_containers.write().await;
            running.insert(
                execution_id.clone(),
                RunningContainer {
                    container_id: container_name.clone(),
                    execution_id: execution_id.clone(),
                    started_at: start_time,
                    agent_hash: request.agent_hash.clone(),
                    task_id: request.task_id.clone(),
                },
            );
        }

        // Execute with timeout
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let result = tokio::time::timeout(Duration::from_secs(timeout_secs), cmd.output()).await;

        // Remove from running
        {
            let mut running = self.running_containers.write().await;
            running.remove(&execution_id);
        }

        let (exit_code, stdout, stderr, timed_out) = match result {
            Ok(Ok(output)) => (
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).to_string(),
                String::from_utf8_lossy(&output.stderr).to_string(),
                false,
            ),
            Ok(Err(e)) => {
                error!("Docker execution error: {}", e);
                (-1, String::new(), format!("Execution error: {}", e), false)
            }
            Err(_) => {
                // Timeout - kill container
                warn!(
                    "Execution {} timed out after {}s",
                    execution_id, timeout_secs
                );
                let _ = Command::new("docker")
                    .args(["kill", &container_name])
                    .output()
                    .await;
                (-1, String::new(), "Execution timed out".to_string(), true)
            }
        };

        // Read output files
        let mut output_files = HashMap::new();
        let output_dir = work_dir.join("output");
        if output_dir.exists() {
            if let Ok(mut entries) = tokio::fs::read_dir(&output_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Ok(content) = tokio::fs::read(entry.path()).await {
                        let name = entry.file_name().to_string_lossy().to_string();
                        output_files.insert(name, content);
                    }
                }
            }
        }

        // Get LLM records (would be populated by proxy callback)
        let llm_calls = self.llm_records.read().await.clone();
        let total_cost: f64 = llm_calls.iter().map(|c| c.cost_usd).sum();

        // Cleanup work directory
        let _ = tokio::fs::remove_dir_all(&work_dir).await;

        let execution_time = start_time.elapsed().as_millis() as u64;

        info!(
            "Execution {} completed: exit_code={}, time={}ms, cost=${:.4}",
            execution_id, exit_code, execution_time, total_cost
        );

        Ok(ExecuteAgentResult {
            execution_id,
            exit_code,
            stdout,
            stderr,
            execution_time_ms: execution_time,
            memory_used_mb: 0, // Memory tracking via container stats
            output_files,
            llm_calls,
            total_cost_usd: total_cost,
            timed_out,
            resource_limited: false,
        })
    }

    /// Verify task completion
    pub async fn verify_task(
        &self,
        request: VerifyTaskRequest,
    ) -> Result<VerifyTaskResult, String> {
        let execution_id = Uuid::new_v4().to_string();
        info!(
            "Verifying task {} (execution {})",
            request.task_id, execution_id
        );

        // Create working directory
        let work_dir = self
            .config
            .work_dir_base
            .join(&format!("verify-{}", execution_id));
        tokio::fs::create_dir_all(&work_dir)
            .await
            .map_err(|e| format!("Failed to create work dir: {}", e))?;

        // Write files
        for (path, content) in &request.working_dir {
            let file_path = work_dir.join(path);
            if let Some(parent) = file_path.parent() {
                tokio::fs::create_dir_all(parent).await.ok();
            }
            tokio::fs::write(&file_path, content).await.ok();
        }

        // Write test script
        let test_script_path = work_dir.join("test.sh");
        tokio::fs::write(&test_script_path, &request.test_script)
            .await
            .map_err(|e| format!("Failed to write test script: {}", e))?;

        // Make test script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&test_script_path)
                .await
                .map_err(|e| format!("Failed to get metadata: {}", e))?
                .permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&test_script_path, perms)
                .await
                .map_err(|e| format!("Failed to set permissions: {}", e))?;
        }

        // Run test script
        let mut cmd = Command::new("docker");
        cmd.args([
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=256m",
            "--cap-drop",
            "ALL",
            "--user",
            "1000:1000",
            "-v",
            &format!("{}:/workspace:ro", work_dir.display()),
            "-w",
            "/workspace",
            &self.config.base_image,
            "bash",
            "test.sh",
        ]);

        let result = tokio::time::timeout(
            Duration::from_secs(request.timeout_secs.max(60)),
            cmd.output(),
        )
        .await;

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&work_dir).await;

        let (output, passed) = match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let passed = output.status.success();
                (stdout, passed)
            }
            Ok(Err(e)) => (format!("Test execution error: {}", e), false),
            Err(_) => ("Test timed out".to_string(), false),
        };

        // Parse test results (basic parsing)
        let (tests_passed, tests_failed, test_details) = self.parse_test_output(&output);

        let score = if tests_passed + tests_failed > 0 {
            tests_passed as f64 / (tests_passed + tests_failed) as f64
        } else if passed {
            1.0
        } else {
            0.0
        };

        Ok(VerifyTaskResult {
            passed,
            score,
            output,
            tests_passed,
            tests_failed,
            test_details,
        })
    }

    /// Parse test output for pass/fail counts
    fn parse_test_output(&self, output: &str) -> (u32, u32, Vec<TestResult>) {
        let mut passed = 0u32;
        let mut failed = 0u32;
        let mut details = Vec::new();

        for line in output.lines() {
            let line_lower = line.to_lowercase();

            // Common test result patterns
            if line_lower.contains("pass") || line_lower.contains("ok") || line_lower.contains("✓")
            {
                passed += 1;
                details.push(TestResult {
                    name: line.trim().to_string(),
                    passed: true,
                    message: None,
                    expected: None,
                    actual: None,
                });
            } else if line_lower.contains("fail")
                || line_lower.contains("error")
                || line_lower.contains("✗")
            {
                failed += 1;
                details.push(TestResult {
                    name: line.trim().to_string(),
                    passed: false,
                    message: Some(line.to_string()),
                    expected: None,
                    actual: None,
                });
            }
        }

        (passed, failed, details)
    }

    /// Record an LLM call (called by proxy)
    pub async fn record_llm_call(&self, record: LLMCallRecord) {
        self.llm_records.write().await.push(record);
    }

    /// Clear LLM records
    pub async fn clear_llm_records(&self) {
        self.llm_records.write().await.clear();
    }

    /// Kill a running execution
    pub async fn kill_execution(&self, execution_id: &str) -> Result<(), String> {
        let container_name = {
            let running = self.running_containers.read().await;
            running.get(execution_id).map(|c| c.container_id.clone())
        };

        if let Some(name) = container_name {
            Command::new("docker")
                .args(["kill", &name])
                .output()
                .await
                .map_err(|e| format!("Failed to kill container: {}", e))?;

            let mut running = self.running_containers.write().await;
            running.remove(execution_id);

            info!("Killed execution {}", execution_id);
        }

        Ok(())
    }

    /// Get running executions
    pub async fn get_running(&self) -> Vec<String> {
        self.running_containers
            .read()
            .await
            .keys()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = DockerRunnerConfig::default();
        assert_eq!(config.default_memory_mb, 4096);
        assert_eq!(config.default_timeout_secs, 300);
    }
}
