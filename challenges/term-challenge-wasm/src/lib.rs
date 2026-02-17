#![no_std]
#![allow(dead_code)]

extern crate alloc;

mod evaluation;
mod scoring;
mod tasks;

use platform_challenge_sdk_wasm::{Challenge, EvaluationInput, EvaluationOutput};

pub struct TermChallenge;

impl Challenge for TermChallenge {
    fn name(&self) -> &'static str {
        "term-challenge"
    }

    fn version(&self) -> &'static str {
        "0.2.3"
    }

    fn evaluate(&self, input: EvaluationInput) -> EvaluationOutput {
        evaluation::evaluate(&input.agent_data, &input.params)
    }

    fn validate(&self, input: EvaluationInput) -> bool {
        evaluation::validate(&input.agent_data, &input.params)
    }
}

platform_challenge_sdk_wasm::register_challenge!(TermChallenge, TermChallenge);
