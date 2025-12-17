//! Weight calculation and aggregation utilities
//!
//! Provides functions for:
//! - Normalizing weights to sum to 1.0
//! - Smoothing weights to prevent gaming
//! - Aggregating weights from multiple validators
//! - Commit-reveal scheme for weight submission
//!
//! ## Commit-Reveal Hash Format
//!
//! For subtensor compatibility, use `create_subtensor_commitment` which matches
//! subtensor's exact hash format:
//! ```ignore
//! BlakeTwo256::hash_of(&(account, netuid_index, uids, values, salt, version_key))
//! ```

use crate::{ChallengeError, Result, WeightAssignment};
use parity_scale_codec::Encode;
use sha2::{Digest, Sha256};
use sp_core::blake2_256;

/// Normalize weights to sum to 1.0
pub fn normalize_weights(mut weights: Vec<WeightAssignment>) -> Vec<WeightAssignment> {
    let total: f64 = weights.iter().map(|w| w.weight).sum();

    if total > 0.0 {
        for w in &mut weights {
            w.weight /= total;
        }
    }

    weights
}

/// Apply smoothing to weights
///
/// Smoothing prevents extreme weight distributions by blending
/// with equal distribution.
///
/// Formula: smoothed = (1 - factor) * original + factor * equal
///
/// factor = 0.0: No smoothing (original weights)
/// factor = 1.0: Full smoothing (equal weights)
pub fn smooth_weights(mut weights: Vec<WeightAssignment>, factor: f64) -> Vec<WeightAssignment> {
    let factor = factor.clamp(0.0, 1.0);

    if weights.is_empty() || factor == 0.0 {
        return weights;
    }

    let n = weights.len() as f64;
    let equal_weight = 1.0 / n;

    for w in &mut weights {
        w.weight = (1.0 - factor) * w.weight + factor * equal_weight;
    }

    weights
}

/// Calculate weights from evaluation scores
///
/// Converts raw scores to normalized weights using softmax-like function.
pub fn scores_to_weights(scores: &[(String, f64)], temperature: f64) -> Vec<WeightAssignment> {
    if scores.is_empty() {
        return vec![];
    }

    let temp = temperature.max(0.01); // Prevent division by zero

    // Apply temperature scaling
    let scaled: Vec<f64> = scores.iter().map(|(_, s)| (s / temp).exp()).collect();

    let sum: f64 = scaled.iter().sum();

    scores
        .iter()
        .zip(scaled.iter())
        .map(|((hash, _), scaled_score)| WeightAssignment::new(hash.clone(), scaled_score / sum))
        .collect()
}

/// Aggregate weights from multiple validators
///
/// Uses median aggregation to be robust against malicious validators.
pub fn aggregate_weights(
    submissions: Vec<Vec<WeightAssignment>>,
    min_validators: usize,
) -> Result<Vec<WeightAssignment>> {
    if submissions.len() < min_validators {
        return Err(ChallengeError::InsufficientValidators {
            required: min_validators,
            got: submissions.len(),
        });
    }

    // Collect all agent hashes
    let mut all_agents: std::collections::HashSet<String> = std::collections::HashSet::new();
    for sub in &submissions {
        for w in sub {
            all_agents.insert(w.agent_hash.clone());
        }
    }

    // For each agent, collect weights from all validators
    let mut aggregated = Vec::new();

    for agent_hash in all_agents {
        let mut weights_for_agent: Vec<f64> = Vec::new();

        for submission in &submissions {
            if let Some(w) = submission.iter().find(|w| w.agent_hash == agent_hash) {
                weights_for_agent.push(w.weight);
            } else {
                // Validator didn't submit weight for this agent, use 0
                weights_for_agent.push(0.0);
            }
        }

        // Calculate median
        let median = calculate_median(&mut weights_for_agent);

        // Calculate confidence based on agreement
        let confidence = calculate_confidence(&weights_for_agent, median);

        aggregated.push(WeightAssignment {
            agent_hash,
            weight: median,
            confidence,
            reason: Some(format!("Aggregated from {} validators", submissions.len())),
        });
    }

    // Normalize
    Ok(normalize_weights(aggregated))
}

/// Calculate median of values
fn calculate_median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mid = values.len() / 2;

    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

/// Calculate confidence based on agreement among validators
fn calculate_confidence(values: &[f64], median: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    // Calculate standard deviation
    let mean: f64 = values.iter().sum::<f64>() / values.len() as f64;
    let variance: f64 =
        values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;
    let std_dev = variance.sqrt();

    // Higher std_dev = lower confidence
    // Using exponential decay: confidence = exp(-std_dev / scale)
    let scale = 0.1; // Adjust for sensitivity
    (-(std_dev / scale)).exp()
}

/// Create a commitment hash for weights (for commit-reveal scheme)
///
/// NOTE: This is a local hash for validator consensus. For actual subtensor
/// submission, use `create_subtensor_commitment` which matches subtensor's format.
pub fn create_commitment(weights: &[WeightAssignment], secret: &[u8]) -> String {
    let mut hasher = Sha256::new();

    // Hash weights in deterministic order
    let mut sorted_weights = weights.to_vec();
    sorted_weights.sort_by(|a, b| a.agent_hash.cmp(&b.agent_hash));

    for w in &sorted_weights {
        hasher.update(w.agent_hash.as_bytes());
        hasher.update(w.weight.to_le_bytes());
    }

    // Add secret for privacy
    hasher.update(secret);

    hex::encode(hasher.finalize())
}

/// Create a commitment hash matching subtensor's exact format.
///
/// Subtensor computes:
/// ```ignore
/// BlakeTwo256::hash_of(&(who, netuid_index, uids, values, salt, version_key))
/// ```
///
/// This is a SCALE-encoded tuple hashed with Blake2b-256.
///
/// # Arguments
/// * `account` - The hotkey's public key (32 bytes)
/// * `netuid` - The subnet ID (u16)
/// * `mechanism_id` - Optional mechanism ID for sub-subnet (default 0 = main)
/// * `uids` - Vector of neuron UIDs (u16)
/// * `values` - Vector of weight values (u16, 0-65535 scale)
/// * `salt` - Random salt (Vec<u16>)
/// * `version_key` - Network version key (u64)
///
/// # Returns
/// Hex-encoded 32-byte Blake2b-256 hash matching subtensor's format
pub fn create_subtensor_commitment(
    account: &[u8; 32],
    netuid: u16,
    mechanism_id: Option<u8>,
    uids: &[u16],
    values: &[u16],
    salt: &[u16],
    version_key: u64,
) -> String {
    let hash = compute_subtensor_hash(
        account,
        netuid,
        mechanism_id,
        uids,
        values,
        salt,
        version_key,
    );
    hex::encode(hash)
}

/// Compute the raw 32-byte hash for subtensor commit-reveal.
pub fn compute_subtensor_hash(
    account: &[u8; 32],
    netuid: u16,
    mechanism_id: Option<u8>,
    uids: &[u16],
    values: &[u16],
    salt: &[u16],
    version_key: u64,
) -> [u8; 32] {
    // Calculate netuid_index (NetUidStorageIndex)
    // In subtensor: netuid_index = get_mechanism_storage_index(netuid, mecid)
    // GLOBAL_MAX_SUBNET_COUNT = 4096
    // Formula: mecid * 4096 + netuid
    // IMPORTANT: NetUidStorageIndex is u16 in subtensor, not u32!
    let mecid = mechanism_id.unwrap_or(0) as u16;
    let netuid_index: u16 = mecid.saturating_mul(4096).saturating_add(netuid);

    // Create SCALE-encodable tuple matching subtensor's format
    // NetUidStorageIndex is a newtype over u16, so it SCALE encodes as u16
    let data = (
        account,         // [u8; 32] - AccountId
        netuid_index,    // u16 - NetUidStorageIndex (NOT u32!)
        uids.to_vec(),   // Vec<u16>
        values.to_vec(), // Vec<u16>
        salt.to_vec(),   // Vec<u16>
        version_key,     // u64
    );

    // SCALE encode and hash
    let encoded = data.encode();
    blake2_256(&encoded)
}

/// Verify a subtensor commitment matches the provided data.
pub fn verify_subtensor_commitment(
    commitment: &str,
    account: &[u8; 32],
    netuid: u16,
    mechanism_id: Option<u8>,
    uids: &[u16],
    values: &[u16],
    salt: &[u16],
    version_key: u64,
) -> bool {
    let computed = create_subtensor_commitment(
        account,
        netuid,
        mechanism_id,
        uids,
        values,
        salt,
        version_key,
    );
    computed == commitment
}

/// Generate random salt as Vec<u16> for commit-reveal.
/// Subtensor expects salt as Vec<u16>, not Vec<u8>.
pub fn generate_salt_u16(len: usize) -> Vec<u16> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Simple PRNG seeded with current time (for non-crypto randomness)
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(12345);

    let mut state = seed;
    (0..len)
        .map(|_| {
            // Simple xorshift for demonstration - use proper rand in production
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFFFF) as u16
        })
        .collect()
}

/// Convert u8 salt to u16 salt (for backwards compatibility)
pub fn salt_u8_to_u16(salt: &[u8]) -> Vec<u16> {
    salt.iter().map(|b| *b as u16).collect()
}

/// Verify a commitment matches the weights (local hash, not subtensor)
pub fn verify_commitment(weights: &[WeightAssignment], secret: &[u8], commitment: &str) -> bool {
    let computed = create_commitment(weights, secret);
    computed == commitment
}

/// Detect potentially malicious weight submissions
///
/// Returns a list of validators whose submissions are suspicious.
pub fn detect_malicious_weights(
    submissions: &[(platform_core::Hotkey, Vec<WeightAssignment>)],
    threshold: f64,
) -> Vec<platform_core::Hotkey> {
    if submissions.len() < 3 {
        return vec![]; // Need at least 3 to detect outliers
    }

    let mut suspicious = Vec::new();

    // For each agent, check if any validator's weight is too far from median
    let mut all_agents: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, weights) in submissions {
        for w in weights {
            all_agents.insert(w.agent_hash.clone());
        }
    }

    for agent_hash in &all_agents {
        let mut weights_by_validator: Vec<(platform_core::Hotkey, f64)> = Vec::new();

        for (validator, weights) in submissions {
            if let Some(w) = weights.iter().find(|w| &w.agent_hash == agent_hash) {
                weights_by_validator.push((validator.clone(), w.weight));
            }
        }

        if weights_by_validator.len() < 3 {
            continue;
        }

        // Calculate median
        let mut values: Vec<f64> = weights_by_validator.iter().map(|(_, w)| *w).collect();
        let median = calculate_median(&mut values);

        // Check each validator
        for (validator, weight) in &weights_by_validator {
            let deviation = (weight - median).abs();
            if deviation > threshold {
                if !suspicious.contains(validator) {
                    suspicious.push(validator.clone());
                }
            }
        }
    }

    suspicious
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_weights() {
        // Note: WeightAssignment::new clamps weights to 0-1
        // So we create with raw weights
        let weights = vec![
            WeightAssignment {
                agent_hash: "a".to_string(),
                weight: 2.0,
                confidence: 1.0,
                reason: None,
            },
            WeightAssignment {
                agent_hash: "b".to_string(),
                weight: 3.0,
                confidence: 1.0,
                reason: None,
            },
        ];

        let normalized = normalize_weights(weights);

        assert!((normalized[0].weight - 0.4).abs() < 0.001);
        assert!((normalized[1].weight - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_smooth_weights() {
        let weights = vec![
            WeightAssignment::new("a".to_string(), 0.9),
            WeightAssignment::new("b".to_string(), 0.1),
        ];

        // 30% smoothing
        let smoothed = smooth_weights(weights, 0.3);

        // Expected: 0.7 * 0.9 + 0.3 * 0.5 = 0.63 + 0.15 = 0.78
        assert!((smoothed[0].weight - 0.78).abs() < 0.001);
    }

    #[test]
    fn test_scores_to_weights() {
        let scores = vec![
            ("a".to_string(), 0.8),
            ("b".to_string(), 0.4),
            ("c".to_string(), 0.2),
        ];

        let weights = scores_to_weights(&scores, 1.0);

        // Higher score should have higher weight
        assert!(weights[0].weight > weights[1].weight);
        assert!(weights[1].weight > weights[2].weight);

        // Should sum to 1.0
        let total: f64 = weights.iter().map(|w| w.weight).sum();
        assert!((total - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_aggregate_weights() {
        let submissions = vec![
            vec![
                WeightAssignment::new("a".to_string(), 0.6),
                WeightAssignment::new("b".to_string(), 0.4),
            ],
            vec![
                WeightAssignment::new("a".to_string(), 0.65),
                WeightAssignment::new("b".to_string(), 0.35),
            ],
            vec![
                WeightAssignment::new("a".to_string(), 0.55),
                WeightAssignment::new("b".to_string(), 0.45),
            ],
        ];

        let aggregated = aggregate_weights(submissions, 2).unwrap();

        // Should have weights for both agents
        assert_eq!(aggregated.len(), 2);
    }

    #[test]
    fn test_commitment() {
        let weights = vec![
            WeightAssignment::new("a".to_string(), 0.6),
            WeightAssignment::new("b".to_string(), 0.4),
        ];

        let secret = b"my_secret";
        let commitment = create_commitment(&weights, secret);

        // Verify should succeed with same data
        assert!(verify_commitment(&weights, secret, &commitment));

        // Verify should fail with different secret
        assert!(!verify_commitment(&weights, b"wrong_secret", &commitment));
    }

    #[test]
    fn test_median() {
        assert_eq!(calculate_median(&mut vec![1.0, 3.0, 2.0]), 2.0);
        assert_eq!(calculate_median(&mut vec![1.0, 2.0, 3.0, 4.0]), 2.5);
    }
}
