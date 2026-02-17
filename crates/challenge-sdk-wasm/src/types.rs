use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationInput {
    pub agent_data: Vec<u8>,
    pub challenge_id: String,
    pub params: Vec<u8>,
    pub submission_id: Option<String>,
    pub participant_id: Option<String>,
    pub epoch: Option<u64>,
    pub metadata: Vec<u8>,
    pub task_definitions: Vec<u8>,
    pub task_definition: Option<Vec<u8>>,
    pub environment_config: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationOutput {
    pub score: i64,
    pub valid: bool,
    pub message: String,
    pub metrics: Option<Vec<u8>>,
}

impl EvaluationOutput {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    pub passed: bool,
    pub name: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetailedScore {
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
    pub task_results: Vec<TaskResult>,
}
