use alloc::string::String;
use alloc::vec::Vec;
use platform_challenge_sdk_wasm::EvaluationOutput;
use serde::{Deserialize, Serialize};

use crate::scoring::ScoreCalculator;
use crate::tasks::{TaskDefinition, TaskResult};

const MAX_AGENT_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalParams {
    pub tasks: Vec<TaskDefinition>,
    pub results: Vec<TaskResult>,
}

pub fn evaluate(agent_data: &[u8], params: &[u8]) -> EvaluationOutput {
    if agent_data.is_empty() {
        return EvaluationOutput::failure("no agent data provided");
    }

    if agent_data.len() > MAX_AGENT_SIZE {
        return EvaluationOutput::failure("agent data exceeds 1MB size limit");
    }

    let eval_params: EvalParams = match bincode::deserialize(params) {
        Ok(p) => p,
        Err(_) => return EvaluationOutput::failure("failed to deserialize evaluation params"),
    };

    if eval_params.tasks.is_empty() {
        return EvaluationOutput::failure("no tasks provided");
    }

    if eval_params.results.is_empty() {
        return EvaluationOutput::failure("no task results provided");
    }

    let calculator = ScoreCalculator;
    let aggregate = calculator.calculate_aggregate(&eval_params.tasks, &eval_params.results);
    let score = calculator.to_score_i64(&aggregate);

    let mut msg = String::new();
    msg.push_str("passed=");
    push_usize(&mut msg, aggregate.tasks_passed);
    msg.push_str(" failed=");
    push_usize(&mut msg, aggregate.tasks_failed);
    msg.push_str(" rate=");
    push_f64_pct(&mut msg, aggregate.pass_rate);

    EvaluationOutput::success(score, &msg)
}

pub fn validate(agent_data: &[u8], params: &[u8]) -> bool {
    if agent_data.is_empty() || agent_data.len() > MAX_AGENT_SIZE {
        return false;
    }

    let eval_params: EvalParams = match bincode::deserialize(params) {
        Ok(p) => p,
        Err(_) => return false,
    };

    !eval_params.tasks.is_empty()
}

fn push_usize(s: &mut String, v: usize) {
    let mut buf = [0u8; 20];
    let n = fmt_usize(v, &mut buf);
    if let Ok(part) = core::str::from_utf8(&buf[20 - n..]) {
        s.push_str(part);
    }
}

fn fmt_usize(mut v: usize, buf: &mut [u8; 20]) -> usize {
    if v == 0 {
        buf[19] = b'0';
        return 1;
    }
    let mut i = 20;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    20 - i
}

fn push_f64_pct(s: &mut String, v: f64) {
    let pct = (v * 10000.0) as u64;
    let whole = pct / 100;
    let frac = pct % 100;
    push_usize(s, whole as usize);
    s.push('.');
    if frac < 10 {
        s.push('0');
    }
    push_usize(s, frac as usize);
    s.push('%');
}
