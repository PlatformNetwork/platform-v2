use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Difficulty {
    Easy,
    #[default]
    Medium,
    Hard,
}

impl Difficulty {
    pub fn weight(self) -> f64 {
        match self {
            Difficulty::Easy => 1.0,
            Difficulty::Medium => 2.0,
            Difficulty::Hard => 3.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub id: String,
    pub name: String,
    pub difficulty: Difficulty,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: f64,
}

fn default_timeout() -> f64 {
    180.0
}

impl Default for TaskDefinition {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            difficulty: Difficulty::default(),
            tags: Vec::new(),
            timeout_secs: default_timeout(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub passed: bool,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub execution_time_ms: u64,
    #[serde(default)]
    pub error: Option<String>,
}

impl TaskResult {
    pub fn success(task_id: String, execution_time_ms: u64) -> Self {
        Self {
            task_id,
            passed: true,
            score: 1.0,
            execution_time_ms,
            error: None,
        }
    }

    pub fn failure(task_id: String, execution_time_ms: u64, error: String) -> Self {
        Self {
            task_id,
            passed: false,
            score: 0.0,
            execution_time_ms,
            error: Some(error),
        }
    }
}
