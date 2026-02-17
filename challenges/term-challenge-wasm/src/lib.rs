#![no_std]

extern crate alloc;

mod evaluation;
mod scoring;
mod tasks;

use platform_challenge_sdk_wasm::types::{EvaluationInput, EvaluationOutput};
use platform_challenge_sdk_wasm::Challenge;

pub struct TermChallenge;

impl Default for TermChallenge {
    fn default() -> Self {
        Self
    }
}

impl TermChallenge {
    pub const fn new() -> Self {
        Self
    }
}

impl Challenge for TermChallenge {
    fn name(&self) -> &'static str {
        "term-challenge"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn evaluate(&self, input: EvaluationInput) -> EvaluationOutput {
        evaluation::run_evaluation(input)
    }

    fn validate(&self, input: EvaluationInput) -> bool {
        evaluation::validate_input(&input)
    }
}

platform_challenge_sdk_wasm::register_challenge!(TermChallenge, TermChallenge::new());
