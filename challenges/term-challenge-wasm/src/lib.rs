#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use platform_challenge_sdk_wasm::{Challenge, EvaluationInput, EvaluationOutput};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct TaskResultEntry {
    task_id: String,
    passed: bool,
    score: f64,
    execution_time_ms: u64,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct AgentData {
    agent_hash: String,
    miner_hotkey: String,
    miner_uid: u16,
    task_results: Vec<TaskResultEntry>,
    total_execution_time_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct ChallengeParams {
    total_tasks: u32,
    max_execution_time_ms: u64,
    epoch: u64,
}

impl Default for ChallengeParams {
    fn default() -> Self {
        Self {
            total_tasks: 20,
            max_execution_time_ms: 600_000,
            epoch: 0,
        }
    }
}

pub struct TermChallenge;

impl TermChallenge {
    const fn new() -> Self {
        Self
    }
}

impl Default for TermChallenge {
    fn default() -> Self {
        Self::new()
    }
}

impl TermChallenge {
    fn compute_score(agent_data: &AgentData, params: &ChallengeParams) -> (i64, String) {
        if agent_data.task_results.is_empty() {
            return (0, String::from("no task results"));
        }

        let tasks_evaluated = agent_data.task_results.len() as u32;
        let tasks_passed = agent_data.task_results.iter().filter(|t| t.passed).count() as u32;

        let denominator = if params.total_tasks > 0 && params.total_tasks >= tasks_evaluated {
            params.total_tasks
        } else {
            tasks_evaluated
        };

        let score_f64 = if denominator > 0 {
            (tasks_passed as f64) / (denominator as f64)
        } else {
            0.0
        };

        let score_i64 = (score_f64 * 10000.0) as i64;

        let mut msg = String::from("passed ");
        push_u32(&mut msg, tasks_passed);
        msg.push('/');
        push_u32(&mut msg, denominator);
        msg.push_str(" tasks");

        (score_i64, msg)
    }

    fn validate_agent_data(agent_data: &AgentData, params: &ChallengeParams) -> bool {
        if agent_data.agent_hash.is_empty() {
            return false;
        }

        if agent_data.miner_hotkey.is_empty() {
            return false;
        }

        if agent_data.task_results.is_empty() {
            return false;
        }

        if params.max_execution_time_ms > 0
            && agent_data.total_execution_time_ms > params.max_execution_time_ms
        {
            return false;
        }

        for entry in &agent_data.task_results {
            if entry.task_id.is_empty() {
                return false;
            }
            if entry.passed && entry.score < 0.999 {
                return false;
            }
            if !entry.passed && entry.score > 0.001 {
                return false;
            }
        }

        true
    }
}

impl Challenge for TermChallenge {
    fn name(&self) -> &'static str {
        "term-challenge"
    }

    fn version(&self) -> &'static str {
        "0.2.3"
    }

    fn evaluate(&self, input: EvaluationInput) -> EvaluationOutput {
        let agent_data: AgentData = match bincode::deserialize(&input.agent_data) {
            Ok(v) => v,
            Err(_) => return EvaluationOutput::failure("failed to deserialize agent_data"),
        };

        let params: ChallengeParams = if input.params.is_empty() {
            ChallengeParams::default()
        } else {
            match bincode::deserialize(&input.params) {
                Ok(v) => v,
                Err(_) => return EvaluationOutput::failure("failed to deserialize params"),
            }
        };

        if !Self::validate_agent_data(&agent_data, &params) {
            return EvaluationOutput::failure("agent_data validation failed");
        }

        let (score, message) = Self::compute_score(&agent_data, &params);

        EvaluationOutput {
            score,
            valid: true,
            message,
        }
    }

    fn validate(&self, input: EvaluationInput) -> bool {
        let agent_data: AgentData = match bincode::deserialize(&input.agent_data) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let params: ChallengeParams = if input.params.is_empty() {
            ChallengeParams::default()
        } else {
            match bincode::deserialize(&input.params) {
                Ok(v) => v,
                Err(_) => return false,
            }
        };

        Self::validate_agent_data(&agent_data, &params)
    }
}

fn push_u32(s: &mut String, mut n: u32) {
    if n == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        s.push(buf[i] as char);
    }
}

platform_challenge_sdk_wasm::register_challenge!(TermChallenge);
