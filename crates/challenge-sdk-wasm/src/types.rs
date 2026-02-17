use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationInput {
    pub agent_data: Vec<u8>,
    pub challenge_id: String,
    pub params: Vec<u8>,
    #[serde(default)]
    pub submission_id: Option<String>,
    #[serde(default)]
    pub participant_id: Option<String>,
    #[serde(default)]
    pub epoch: Option<u64>,
    #[serde(default)]
    pub metadata: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationOutput {
    pub score: i64,
    pub valid: bool,
    pub message: String,
    #[serde(default)]
    pub score_f64: Option<f64>,
    #[serde(default)]
    pub results: Option<Vec<u8>>,
    #[serde(default)]
    pub execution_time_ms: Option<u64>,
}

impl EvaluationOutput {
    pub fn success(score: i64, message: &str) -> Self {
        Self {
            score,
            valid: true,
            message: String::from(message),
            score_f64: None,
            results: None,
            execution_time_ms: None,
        }
    }

    pub fn failure(message: &str) -> Self {
        Self {
            score: 0,
            valid: false,
            message: String::from(message),
            score_f64: None,
            results: None,
            execution_time_ms: None,
        }
    }
}
