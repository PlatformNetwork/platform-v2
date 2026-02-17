#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use platform_challenge_sdk_wasm::{Challenge, EvaluationInput, EvaluationOutput};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct TaskEntry {
    pub name: String,
    pub passed: bool,
}

#[derive(Serialize, Deserialize)]
struct AgentResults {
    pub tasks: Vec<TaskEntry>,
}

pub struct TermChallenge;

impl TermChallenge {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for TermChallenge {
    fn default() -> Self {
        Self::new()
    }
}

impl Challenge for TermChallenge {
    fn name(&self) -> &'static str {
        "term-challenge"
    }

    fn version(&self) -> &'static str {
        "2.0.0"
    }

    fn evaluate(&self, input: EvaluationInput) -> EvaluationOutput {
        let results: AgentResults = match bincode::deserialize(&input.agent_data) {
            Ok(r) => r,
            Err(_) => {
                return EvaluationOutput::failure("failed to deserialize agent data");
            }
        };

        if results.tasks.is_empty() {
            return EvaluationOutput::failure("no tasks provided");
        }

        let total = results.tasks.len() as f64;
        let passed = results.tasks.iter().filter(|t| t.passed).count() as f64;
        let pass_rate = (passed / total).clamp(0.0, 1.0);
        let score = (pass_rate * 100.0) as i64;

        let message = format!(
            "{}/{} tasks passed ({:.0}%)",
            passed as u64,
            total as u64,
            pass_rate * 100.0
        );

        EvaluationOutput::success(score, &message)
    }

    fn validate(&self, input: EvaluationInput) -> bool {
        !input.agent_data.is_empty() && !input.challenge_id.is_empty()
    }
}

platform_challenge_sdk_wasm::register_challenge!(TermChallenge);
