use alloc::string::String;
use alloc::vec::Vec;
use platform_challenge_sdk_wasm::host_functions::host_terminal_exec;
use platform_challenge_sdk_wasm::types::{EvaluationInput, EvaluationOutput};
use platform_challenge_sdk_wasm::TaskDefinition;

use crate::scoring::calculate_score;
use crate::tasks::{build_test_command, default_tasks, Difficulty, TermTask};

pub fn run_evaluation(input: EvaluationInput) -> EvaluationOutput {
    let tasks: Vec<TermTask> = if input.params.is_empty() {
        default_tasks()
    } else {
        match bincode::deserialize(&input.params) {
            Ok(task_defs) => tasks_from_definitions(task_defs),
            Err(_) => default_tasks(),
        }
    };

    if tasks.is_empty() {
        return EvaluationOutput::failure("No tasks to evaluate");
    }

    let mut results: Vec<(Difficulty, bool)> = Vec::with_capacity(tasks.len());
    let mut passed_count: usize = 0;
    let mut failed_count: usize = 0;

    for task in &tasks {
        let task_passed = execute_task(task);
        if task_passed {
            passed_count += 1;
        } else {
            failed_count += 1;
        }
        results.push((task.difficulty, task_passed));
    }

    let (score, all_passed) = calculate_score(&results);

    let mut msg = String::from("Evaluation complete: ");
    msg.push_str(&format_usize(passed_count));
    msg.push_str(" passed, ");
    msg.push_str(&format_usize(failed_count));
    msg.push_str(" failed");

    EvaluationOutput {
        score,
        valid: all_passed,
        message: msg,
        metrics: None,
    }
}

fn execute_task(task: &TermTask) -> bool {
    let cmd = build_test_command(task);
    let serialized = match bincode::serialize(&cmd) {
        Ok(v) => v,
        Err(_) => return false,
    };

    match host_terminal_exec(&serialized) {
        Ok(response_bytes) => {
            if let Ok(result) =
                bincode::deserialize::<platform_challenge_sdk_wasm::CommandResult>(&response_bytes)
            {
                result.exit_code == 0
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn tasks_from_definitions(defs: Vec<TaskDefinition>) -> Vec<TermTask> {
    let mut tasks = Vec::with_capacity(defs.len());
    for def in defs {
        let test_script = match core::str::from_utf8(&def.scoring_params) {
            Ok(s) => String::from(s),
            Err(_) => continue,
        };
        tasks.push(TermTask {
            id: def.task_id.clone(),
            name: def.description.clone(),
            difficulty: Difficulty::Medium,
            test_script,
            timeout_ms: 120_000,
        });
    }
    tasks
}

pub fn validate_input(input: &EvaluationInput) -> bool {
    if input.params.is_empty() {
        return true;
    }
    bincode::deserialize::<Vec<TaskDefinition>>(&input.params).is_ok()
}

fn format_usize(n: usize) -> String {
    use alloc::format;
    format!("{}", n)
}
