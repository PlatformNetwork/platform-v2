use serde::{Deserialize, Serialize};

use crate::tasks::{TaskDefinition, TaskResult};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DifficultyStats {
    pub total: usize,
    pub passed: usize,
    pub total_score: f64,
}

impl DifficultyStats {
    pub fn pass_rate(&self) -> f64 {
        if self.total > 0 {
            self.passed as f64 / self.total as f64
        } else {
            0.0
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateScore {
    pub total_score: f64,
    pub normalized_score: f64,
    pub max_possible: f64,
    pub tasks_passed: usize,
    pub tasks_failed: usize,
    pub pass_rate: f64,
    pub total_execution_time_ms: Option<u64>,
}

impl AggregateScore {
    pub fn total_tasks(&self) -> usize {
        self.tasks_passed + self.tasks_failed
    }

    pub fn percentage(&self) -> f64 {
        self.normalized_score * 100.0
    }
}

pub struct ScoreCalculator;

impl ScoreCalculator {
    pub fn score_task(&self, result: &TaskResult) -> f64 {
        if result.passed {
            1.0
        } else {
            0.0
        }
    }

    pub fn calculate_aggregate(
        &self,
        tasks: &[TaskDefinition],
        results: &[TaskResult],
    ) -> AggregateScore {
        let mut passed: usize = 0;
        let mut failed: usize = 0;
        let mut total_execution_time_ms: u64 = 0;

        for result in results.iter().take(tasks.len()) {
            if result.passed {
                passed += 1;
            } else {
                failed += 1;
            }
            total_execution_time_ms =
                total_execution_time_ms.saturating_add(result.execution_time_ms);
        }

        let total = passed + failed;
        let pass_rate = if total > 0 {
            passed as f64 / total as f64
        } else {
            0.0
        };

        AggregateScore {
            total_score: passed as f64,
            normalized_score: pass_rate,
            max_possible: total as f64,
            tasks_passed: passed,
            tasks_failed: failed,
            pass_rate,
            total_execution_time_ms: Some(total_execution_time_ms),
        }
    }

    pub fn to_weight(&self, score: &AggregateScore) -> f64 {
        score.pass_rate.clamp(0.0, 1.0)
    }

    pub fn to_score_i64(&self, score: &AggregateScore) -> i64 {
        (score.normalized_score.clamp(0.0, 1.0) * 10000.0) as i64
    }
}
