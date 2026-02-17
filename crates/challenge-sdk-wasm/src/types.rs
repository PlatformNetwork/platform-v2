use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvaluationInput {
    pub agent_data: Vec<u8>,
    pub challenge_id: String,
    pub params: Vec<u8>,
    pub submission: SubmissionMetadata,
    pub tasks: Vec<EvalTaskDefinition>,
    pub task_definition: Option<Vec<u8>>,
    pub environment_config: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SubmissionMetadata {
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub miner_uid: u16,
    pub epoch: u64,
    pub submitted_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct EvalTaskDefinition {
    pub task_id: String,
    pub name: String,
    pub difficulty: String,
    pub tags: Vec<String>,
    pub timeout_secs: f64,
    pub test_timeout_secs: f64,
}

impl Default for EvalTaskDefinition {
    fn default() -> Self {
        Self {
            task_id: String::new(),
            name: String::new(),
            difficulty: String::from("medium"),
            tags: Vec::new(),
            timeout_secs: 180.0,
            test_timeout_secs: 30.0,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskResult {
    pub task_id: String,
    pub passed: bool,
    pub score: f64,
    pub reward: f64,
    pub execution_time_ms: u64,
    pub steps: u32,
    pub error: Option<String>,
}

impl TaskResult {
    pub fn success(task_id: &str, score: f64) -> Self {
        Self {
            task_id: String::from(task_id),
            passed: true,
            score,
            reward: score,
            execution_time_ms: 0,
            steps: 0,
            error: None,
        }
    }

    pub fn failure(task_id: &str, error: &str) -> Self {
        Self {
            task_id: String::from(task_id),
            passed: false,
            score: 0.0,
            reward: 0.0,
            execution_time_ms: 0,
            steps: 0,
            error: Some(String::from(error)),
        }
    }

    pub fn with_timing(mut self, execution_time_ms: u64, steps: u32) -> Self {
        self.execution_time_ms = execution_time_ms;
        self.steps = steps;
        self
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Metric {
    pub name: String,
    pub value: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvaluationOutput {
    pub score: i64,
    pub valid: bool,
    pub message: String,
    pub tasks_passed: u32,
    pub tasks_total: u32,
    pub metrics: Vec<Metric>,
    pub task_results: Vec<TaskResult>,
    pub execution_time_ms: u64,
    pub raw_metrics: Option<Vec<u8>>,
}

impl EvaluationOutput {
    pub fn success(score: i64, message: &str) -> Self {
        Self {
            score,
            valid: true,
            message: String::from(message),
            ..Self::default()
        }
    }

    pub fn failure(message: &str) -> Self {
        Self {
            score: 0,
            valid: false,
            message: String::from(message),
            ..Self::default()
        }
    }

    pub fn with_tasks(score: i64, tasks_passed: u32, tasks_total: u32, message: &str) -> Self {
        Self {
            score,
            valid: tasks_passed > 0,
            message: String::from(message),
            tasks_passed,
            tasks_total,
            ..Self::default()
        }
    }

    pub fn with_raw_metrics(mut self, metrics: Vec<u8>) -> Self {
        self.raw_metrics = Some(metrics);
        self
    }

    pub fn add_metric(&mut self, name: &str, value: f64) {
        self.metrics.push(Metric {
            name: String::from(name),
            value,
        });
    }

    pub fn add_task_result(&mut self, result: TaskResult) {
        if result.passed {
            self.tasks_passed += 1;
        }
        self.tasks_total += 1;
        self.task_results.push(result);
    }

    pub fn pass_rate(&self) -> f64 {
        if self.tasks_total > 0 {
            self.tasks_passed as f64 / self.tasks_total as f64
        } else {
            0.0
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ChallengeParams {
    pub difficulty: String,
    pub timeout_secs: f64,
    pub max_steps: u32,
    pub task_ids: Vec<String>,
    pub tags: Vec<String>,
}

impl Default for ChallengeParams {
    fn default() -> Self {
        Self {
            difficulty: String::from("medium"),
            timeout_secs: 180.0,
            max_steps: 200,
            task_ids: Vec::new(),
            tags: Vec::new(),
        }
    }
}
