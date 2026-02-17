use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationInput {
    pub agent_data: Vec<u8>,
    pub challenge_id: String,
    pub params: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationOutput {
    pub score: i64,
    pub valid: bool,
    pub message: String,
}

impl EvaluationOutput {
    pub fn success(score: i64, message: &str) -> Self {
        Self {
            score,
            valid: true,
            message: String::from(message),
        }
    }

    pub fn failure(message: &str) -> Self {
        Self {
            score: 0,
            valid: false,
            message: String::from(message),
        }
    }
}
