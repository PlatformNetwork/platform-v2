use crate::tasks::Difficulty;

const SCORE_SCALE: i64 = 10_000;

pub fn calculate_score(results: &[(Difficulty, bool)]) -> (i64, bool) {
    if results.is_empty() {
        return (0, false);
    }

    let mut passed: usize = 0;
    let total = results.len();

    for &(_, task_passed) in results {
        if task_passed {
            passed += 1;
        }
    }

    let pass_rate = passed as f64 / total as f64;
    let score = (pass_rate * SCORE_SCALE as f64) as i64;
    let all_passed = passed == total;

    (score, all_passed)
}
