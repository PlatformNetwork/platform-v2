use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandRequest {
    pub command: String,
    pub args: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub execution_time_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileReadRequest {
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileReadResponse {
    pub data: Vec<u8>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileWriteRequest {
    pub path: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileWriteResponse {
    pub success: bool,
    pub bytes_written: u64,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileListRequest {
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileListResponse {
    pub entries: Vec<FileEntry>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub task_id: String,
    pub description: String,
    pub expected_output_hash: Option<Vec<u8>>,
    pub environment_config: Vec<u8>,
    pub scoring_params: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TermEvaluationMetrics {
    pub execution_time_ms: u64,
    pub correctness_score: f64,
    pub partial_credit: f64,
    pub cost: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TermEvaluationInput {
    pub agent_data: Vec<u8>,
    pub challenge_id: String,
    pub params: Vec<u8>,
    pub task_definition: Option<Vec<u8>>,
    pub environment_config: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TermEvaluationOutput {
    pub score: i64,
    pub valid: bool,
    pub message: String,
    pub metrics: Option<Vec<u8>>,
}

impl TermEvaluationOutput {
    pub fn success(score: i64, message: &str) -> Self {
        Self {
            score,
            valid: true,
            message: String::from(message),
            metrics: None,
        }
    }

    pub fn failure(message: &str) -> Self {
        Self {
            score: 0,
            valid: false,
            message: String::from(message),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: Vec<u8>) -> Self {
        self.metrics = Some(metrics);
        self
    }
}
