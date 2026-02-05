//! Terminal Benchmark Challenge types and scoring
//!
//! These types are extracted from term-challenge and made WASM-compatible
//! for use in the dynamic challenge loading system.

use crate::{ChallengeId, Hotkey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// TASK TYPES
// ============================================================================

/// Task difficulty level
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Difficulty {
    Easy,
    #[default]
    Medium,
    Hard,
}

impl Difficulty {
    /// Get weight multiplier for this difficulty
    pub fn weight(&self) -> f64 {
        match self {
            Difficulty::Easy => 1.0,
            Difficulty::Medium => 2.0,
            Difficulty::Hard => 3.0,
        }
    }
}

/// Task configuration for terminal benchmark
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TermTaskConfig {
    /// Task ID
    pub id: String,
    /// Task name
    pub name: String,
    /// Task instruction/description
    pub instruction: String,
    /// Difficulty level
    pub difficulty: Difficulty,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Timeout for agent execution (seconds)
    pub timeout_secs: f64,
    /// Timeout for test execution (seconds)
    pub test_timeout_secs: f64,
    /// Docker image to use
    pub docker_image: String,
    /// Memory limit (e.g., "2g")
    pub memory_limit: String,
    /// CPU limit
    pub cpu_limit: f64,
}

impl Default for TermTaskConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            instruction: String::new(),
            difficulty: Difficulty::Medium,
            tags: Vec::new(),
            timeout_secs: 180.0,
            test_timeout_secs: 30.0,
            docker_image: "ghcr.io/platformnetwork/term-challenge:latest".to_string(),
            memory_limit: "2g".to_string(),
            cpu_limit: 1.0,
        }
    }
}

// ============================================================================
// EVALUATION TYPES
// ============================================================================

/// Result of evaluating a single task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TermTaskResult {
    /// Task ID
    pub task_id: String,
    /// Agent hash
    pub agent_hash: String,
    /// Whether the task passed
    pub passed: bool,
    /// Score (0.0 - 1.0)
    pub score: f64,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Test output
    pub test_output: String,
    /// Agent output/logs
    pub agent_output: String,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: i64,
}

impl TermTaskResult {
    /// Create a success result
    pub fn success(
        task_id: String,
        agent_hash: String,
        execution_time_ms: u64,
        test_output: String,
        agent_output: String,
    ) -> Self {
        Self {
            task_id,
            agent_hash,
            passed: true,
            score: 1.0,
            execution_time_ms,
            test_output,
            agent_output,
            error: None,
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Create a failure result
    pub fn failure(
        task_id: String,
        agent_hash: String,
        execution_time_ms: u64,
        test_output: String,
        agent_output: String,
        error: String,
    ) -> Self {
        Self {
            task_id,
            agent_hash,
            passed: false,
            score: 0.0,
            execution_time_ms,
            test_output,
            agent_output,
            error: Some(error),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Create a timeout result
    pub fn timeout(task_id: String, agent_hash: String, timeout_ms: u64) -> Self {
        Self {
            task_id,
            agent_hash,
            passed: false,
            score: 0.0,
            execution_time_ms: timeout_ms,
            test_output: String::new(),
            agent_output: String::new(),
            error: Some("Task timed out".to_string()),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }
}

/// Aggregate score for an agent across multiple tasks
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TermAggregateScore {
    /// Total raw score
    pub total_score: f64,
    /// Normalized score (0.0 - 1.0)
    pub normalized_score: f64,
    /// Maximum possible score
    pub max_possible: f64,
    /// Number of tasks passed
    pub tasks_passed: usize,
    /// Number of tasks failed
    pub tasks_failed: usize,
    /// Pass rate (0.0 - 1.0)
    pub pass_rate: f64,
    /// Breakdown by difficulty
    pub by_difficulty: HashMap<Difficulty, DifficultyStats>,
    /// Total execution time in milliseconds
    pub total_execution_time_ms: u64,
}

/// Statistics for a difficulty level
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

// ============================================================================
// SCORING
// ============================================================================

/// Terminal benchmark score calculator
#[derive(Clone, Debug, Default)]
pub struct TermScoreCalculator;

impl TermScoreCalculator {
    /// Create a new score calculator
    pub fn new() -> Self {
        Self
    }

    /// Calculate score for a single task result
    /// Returns 1.0 if passed, 0.0 if failed
    pub fn score_task(&self, result: &TermTaskResult) -> f64 {
        if result.passed {
            1.0
        } else {
            0.0
        }
    }

    /// Calculate aggregate score for multiple task results
    pub fn calculate_aggregate(
        &self,
        configs: &[TermTaskConfig],
        results: &[TermTaskResult],
    ) -> TermAggregateScore {
        let mut passed = 0;
        let mut failed = 0;
        let mut by_difficulty: HashMap<Difficulty, DifficultyStats> = HashMap::new();
        let mut total_execution_time_ms = 0u64;

        for (config, result) in configs.iter().zip(results.iter()) {
            if result.passed {
                passed += 1;
            } else {
                failed += 1;
            }

            total_execution_time_ms =
                total_execution_time_ms.saturating_add(result.execution_time_ms);

            let stats = by_difficulty.entry(config.difficulty).or_default();
            stats.total += 1;
            if result.passed {
                stats.passed += 1;
                stats.total_score += 1.0;
            }
        }

        let total = passed + failed;
        let pass_rate = if total > 0 {
            passed as f64 / total as f64
        } else {
            0.0
        };

        TermAggregateScore {
            total_score: passed as f64,
            normalized_score: pass_rate,
            max_possible: total as f64,
            tasks_passed: passed,
            tasks_failed: failed,
            pass_rate,
            by_difficulty,
            total_execution_time_ms,
        }
    }

    /// Convert aggregate score to weight (0.0 - 1.0)
    pub fn to_weight(&self, score: &TermAggregateScore) -> f64 {
        score.pass_rate.clamp(0.0, 1.0)
    }
}

// ============================================================================
// WASM INTERFACE
// ============================================================================

/// WASM-compatible evaluation request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmEvalRequest {
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Agent hash
    pub agent_hash: String,
    /// Agent source code
    pub agent_source: String,
    /// Miner hotkey
    pub miner_hotkey: Hotkey,
    /// Task configurations (JSON)
    pub task_configs: Vec<TermTaskConfig>,
}

/// WASM-compatible evaluation response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmEvalResponse {
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Agent hash
    pub agent_hash: String,
    /// Individual task results
    pub task_results: Vec<TermTaskResult>,
    /// Aggregate score
    pub aggregate_score: TermAggregateScore,
    /// Final weight (0.0 - 1.0)
    pub weight: f64,
    /// Execution timestamp
    pub timestamp: i64,
}

/// Interface that WASM challenge modules must implement
pub trait WasmChallengeInterface {
    /// Get challenge name
    fn name(&self) -> String;

    /// Get challenge version
    fn version(&self) -> u32;

    /// Validate agent submission format
    fn validate_agent(&self, agent_source: &str) -> Result<bool, String>;

    /// Get task configurations
    fn get_task_configs(&self) -> Vec<TermTaskConfig>;

    /// Calculate final score from task results
    fn calculate_score(&self, results: &[TermTaskResult]) -> TermAggregateScore;

    /// Convert score to weight
    fn score_to_weight(&self, score: &TermAggregateScore) -> f64;
}

/// Default implementation of terminal benchmark challenge
pub struct TerminalBenchChallenge {
    pub id: ChallengeId,
    pub name: String,
    pub version: u32,
    pub tasks: Vec<TermTaskConfig>,
    pub calculator: TermScoreCalculator,
}

impl TerminalBenchChallenge {
    /// Create a new terminal benchmark challenge
    pub fn new(name: String, version: u32, tasks: Vec<TermTaskConfig>) -> Self {
        Self {
            id: ChallengeId::from_string(&name),
            name,
            version,
            tasks,
            calculator: TermScoreCalculator::new(),
        }
    }

    /// Create with default configuration
    pub fn default_challenge() -> Self {
        Self {
            id: ChallengeId::from_string("terminal-bench"),
            name: "terminal-bench".to_string(),
            version: 1,
            tasks: Vec::new(),
            calculator: TermScoreCalculator::new(),
        }
    }
}

impl WasmChallengeInterface for TerminalBenchChallenge {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn validate_agent(&self, agent_source: &str) -> Result<bool, String> {
        // Basic validation - check for required structure
        if agent_source.is_empty() {
            return Err("Empty agent source".to_string());
        }

        // Check for minimum length
        if agent_source.len() < 10 {
            return Err("Agent source too short".to_string());
        }

        // Could add more validation here (syntax check, required functions, etc.)
        Ok(true)
    }

    fn get_task_configs(&self) -> Vec<TermTaskConfig> {
        self.tasks.clone()
    }

    fn calculate_score(&self, results: &[TermTaskResult]) -> TermAggregateScore {
        self.calculator.calculate_aggregate(&self.tasks, results)
    }

    fn score_to_weight(&self, score: &TermAggregateScore) -> f64 {
        self.calculator.to_weight(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_weight() {
        assert_eq!(Difficulty::Easy.weight(), 1.0);
        assert_eq!(Difficulty::Medium.weight(), 2.0);
        assert_eq!(Difficulty::Hard.weight(), 3.0);
    }

    #[test]
    fn test_task_result_success() {
        let result = TermTaskResult::success(
            "task1".to_string(),
            "agent123".to_string(),
            5000,
            "passed".to_string(),
            "output".to_string(),
        );
        assert!(result.passed);
        assert_eq!(result.score, 1.0);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_task_result_failure() {
        let result = TermTaskResult::failure(
            "task2".to_string(),
            "agent456".to_string(),
            3000,
            "failed".to_string(),
            "output".to_string(),
            "assertion error".to_string(),
        );
        assert!(!result.passed);
        assert_eq!(result.score, 0.0);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_task_result_timeout() {
        let result = TermTaskResult::timeout("task3".to_string(), "agent789".to_string(), 10000);
        assert!(!result.passed);
        assert_eq!(result.error, Some("Task timed out".to_string()));
    }

    #[test]
    fn test_score_calculator() {
        let calculator = TermScoreCalculator::new();

        let configs = vec![
            TermTaskConfig {
                difficulty: Difficulty::Easy,
                ..Default::default()
            },
            TermTaskConfig {
                difficulty: Difficulty::Medium,
                ..Default::default()
            },
        ];

        let results = vec![
            TermTaskResult::success(
                "t1".to_string(),
                "a".to_string(),
                1000,
                "".to_string(),
                "".to_string(),
            ),
            TermTaskResult::failure(
                "t2".to_string(),
                "a".to_string(),
                2000,
                "".to_string(),
                "".to_string(),
                "fail".to_string(),
            ),
        ];

        let aggregate = calculator.calculate_aggregate(&configs, &results);

        assert_eq!(aggregate.tasks_passed, 1);
        assert_eq!(aggregate.tasks_failed, 1);
        assert_eq!(aggregate.pass_rate, 0.5);
    }

    #[test]
    fn test_terminal_bench_challenge() {
        let challenge = TerminalBenchChallenge::default_challenge();

        assert_eq!(challenge.name(), "terminal-bench");
        assert_eq!(challenge.version(), 1);
    }

    #[test]
    fn test_validate_agent() {
        let challenge = TerminalBenchChallenge::default_challenge();

        assert!(challenge.validate_agent("").is_err());
        assert!(challenge.validate_agent("short").is_err());
        assert!(challenge.validate_agent("valid agent code here").is_ok());
    }

    #[test]
    fn test_difficulty_stats() {
        let mut stats = DifficultyStats::default();
        assert_eq!(stats.pass_rate(), 0.0);

        stats.total = 10;
        stats.passed = 7;
        assert_eq!(stats.pass_rate(), 0.7);
    }

    #[test]
    fn test_aggregate_score_empty() {
        let calculator = TermScoreCalculator::new();
        let aggregate = calculator.calculate_aggregate(&[], &[]);

        assert_eq!(aggregate.tasks_passed, 0);
        assert_eq!(aggregate.pass_rate, 0.0);
    }
}
