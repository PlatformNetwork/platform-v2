//! Validator assignment for fair task distribution
//!
//! Implements a stake-weighted deterministic assignment algorithm that:
//! - Distributes tasks fairly across validators based on stake
//! - Ensures reproducibility (same inputs = same assignment)
//! - Prevents gaming by using cryptographic randomness

use crate::validator::{ValidatorRecord, ValidatorSet};
use platform_core::{ChallengeId, Hotkey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

/// Configuration for validator assignment
#[derive(Clone, Debug)]
pub struct AssignmentConfig {
    /// Minimum validators required for a task
    pub min_validators: usize,
    /// Maximum validators that can be assigned to a task
    pub max_validators: usize,
    /// Whether to use stake weighting
    pub stake_weighted: bool,
    /// Epoch seed for randomness (changes each epoch)
    pub epoch_seed: [u8; 32],
}

impl Default for AssignmentConfig {
    fn default() -> Self {
        Self {
            min_validators: 3,
            max_validators: 10,
            stake_weighted: true,
            epoch_seed: [0u8; 32],
        }
    }
}

/// Result of a validator assignment
#[derive(Clone, Debug)]
pub struct Assignment {
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Submission hash being validated
    pub submission_hash: [u8; 32],
    /// Assigned validators (in priority order)
    pub validators: Vec<AssignedValidator>,
    /// Primary validator (first in list)
    pub primary: Hotkey,
    /// Assignment timestamp
    pub assigned_at: i64,
    /// Epoch when assigned
    pub epoch: u64,
}

/// Information about an assigned validator
#[derive(Clone, Debug)]
pub struct AssignedValidator {
    /// Validator's hotkey
    pub hotkey: Hotkey,
    /// Validator's stake
    pub stake: u64,
    /// Priority order (0 = highest priority, i.e., primary)
    pub priority: u32,
    /// Whether this validator can store the validation result
    pub can_store_result: bool,
}

/// Assignment errors
#[derive(Debug, Error)]
pub enum AssignmentError {
    #[error("Not enough validators: need {needed}, have {available}")]
    NotEnoughValidators { needed: usize, available: usize },
    #[error("Invalid submission hash: expected 32 bytes")]
    InvalidSubmissionHash,
    #[error("Validator not found: {0}")]
    ValidatorNotFound(String),
    #[error("No validators available")]
    NoValidatorsAvailable,
}

/// Validator assignment engine
///
/// Provides deterministic assignment of validators to evaluation tasks
/// based on stake-weighted selection using cryptographic hashing.
pub struct ValidatorAssignment {
    validator_set: Arc<ValidatorSet>,
    config: AssignmentConfig,
}

impl ValidatorAssignment {
    /// Create new assignment engine
    pub fn new(validator_set: Arc<ValidatorSet>, config: AssignmentConfig) -> Self {
        Self {
            validator_set,
            config,
        }
    }

    /// Assign validators for a submission
    ///
    /// Uses VRF-like deterministic selection based on:
    /// - submission_hash: Hash of the agent submission
    /// - epoch_seed: Changes each epoch for rotation
    /// - challenge_id: Ensures different challenges get different assignments
    ///
    /// The algorithm:
    /// 1. Get all active validators
    /// 2. Compute priority score for each validator using cryptographic hash
    /// 3. If stake_weighted is enabled, multiply priority by stake
    /// 4. Sort by priority (descending)
    /// 5. Select top N validators up to max_validators
    pub fn assign(
        &self,
        challenge_id: ChallengeId,
        submission_hash: [u8; 32],
        epoch: u64,
    ) -> Result<Assignment, AssignmentError> {
        // Get all active validators
        let active_validators = self.validator_set.active_validators();

        if active_validators.is_empty() {
            return Err(AssignmentError::NoValidatorsAvailable);
        }

        if active_validators.len() < self.config.min_validators {
            return Err(AssignmentError::NotEnoughValidators {
                needed: self.config.min_validators,
                available: active_validators.len(),
            });
        }

        // Compute priority scores for all validators
        let mut scored_validators: Vec<(ValidatorRecord, u64)> = active_validators
            .into_iter()
            .map(|v| {
                let priority = self.compute_priority(
                    &v.hotkey,
                    &submission_hash,
                    &self.config.epoch_seed,
                    &challenge_id,
                );
                let weighted_priority = if self.config.stake_weighted {
                    // Multiply by stake to give higher-stake validators better odds
                    // Use saturating multiplication to prevent overflow
                    priority.saturating_mul(v.stake.saturating_add(1) / 1_000_000)
                } else {
                    priority
                };
                (v, weighted_priority)
            })
            .collect();

        // Sort by weighted priority (descending), with hotkey as tiebreaker for determinism
        scored_validators
            .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.hotkey.0.cmp(&b.0.hotkey.0)));

        // Take up to max_validators
        let num_to_assign = self.config.max_validators.min(scored_validators.len());
        let assigned: Vec<AssignedValidator> = scored_validators
            .into_iter()
            .take(num_to_assign)
            .enumerate()
            .map(|(idx, (record, _priority))| AssignedValidator {
                hotkey: record.hotkey,
                stake: record.stake,
                priority: idx as u32,
                // Only primary validator (priority 0) can store result by default
                can_store_result: idx == 0,
            })
            .collect();

        let primary = assigned
            .first()
            .map(|v| v.hotkey.clone())
            .ok_or(AssignmentError::NoValidatorsAvailable)?;

        Ok(Assignment {
            challenge_id,
            submission_hash,
            validators: assigned,
            primary,
            assigned_at: chrono::Utc::now().timestamp_millis(),
            epoch,
        })
    }

    /// Check if a validator is assigned to a submission
    ///
    /// Recomputes the assignment deterministically and checks if the validator
    /// is in the assigned set.
    pub fn is_assigned(
        &self,
        validator: &Hotkey,
        challenge_id: ChallengeId,
        submission_hash: &[u8; 32],
        epoch: u64,
    ) -> bool {
        match self.assign(challenge_id, *submission_hash, epoch) {
            Ok(assignment) => assignment.validators.iter().any(|v| &v.hotkey == validator),
            Err(_) => false,
        }
    }

    /// Check if a validator can store the result for a submission
    ///
    /// Only the primary validator (or backup if primary failed) can store.
    /// This ensures only one validator writes the canonical result.
    pub fn can_store_result(
        &self,
        validator: &Hotkey,
        challenge_id: ChallengeId,
        submission_hash: &[u8; 32],
        epoch: u64,
    ) -> bool {
        match self.assign(challenge_id, *submission_hash, epoch) {
            Ok(assignment) => assignment
                .validators
                .iter()
                .any(|v| &v.hotkey == validator && v.can_store_result),
            Err(_) => false,
        }
    }

    /// Get the assigned validator for a specific priority level
    ///
    /// Returns the validator at the given priority (0 = primary, 1 = first backup, etc.)
    pub fn get_validator_at_priority(
        &self,
        challenge_id: ChallengeId,
        submission_hash: &[u8; 32],
        epoch: u64,
        priority: u32,
    ) -> Result<AssignedValidator, AssignmentError> {
        let assignment = self.assign(challenge_id, *submission_hash, epoch)?;
        assignment
            .validators
            .into_iter()
            .find(|v| v.priority == priority)
            .ok_or_else(|| AssignmentError::ValidatorNotFound(format!("priority {}", priority)))
    }

    /// Compute priority score for validator selection
    ///
    /// Creates a deterministic priority value by hashing:
    /// - validator hotkey
    /// - submission hash
    /// - epoch seed
    /// - challenge id
    ///
    /// This ensures the same inputs always produce the same priority,
    /// making assignments reproducible and verifiable.
    fn compute_priority(
        &self,
        validator: &Hotkey,
        submission_hash: &[u8; 32],
        epoch_seed: &[u8; 32],
        challenge_id: &ChallengeId,
    ) -> u64 {
        let mut hasher = Sha256::new();

        // Include all inputs in the hash
        hasher.update(validator.as_bytes());
        hasher.update(submission_hash);
        hasher.update(epoch_seed);
        hasher.update(challenge_id.0.as_bytes());

        let hash = hasher.finalize();

        // Take first 8 bytes as u64 priority score
        let bytes: [u8; 8] = hash[..8]
            .try_into()
            .expect("SHA256 hash is always at least 8 bytes");
        u64::from_be_bytes(bytes)
    }

    /// Update config (e.g., new epoch seed)
    pub fn update_config(&mut self, config: AssignmentConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn config(&self) -> &AssignmentConfig {
        &self.config
    }

    /// Get the number of validators that would be assigned
    ///
    /// Useful for checking if there are enough validators before assignment.
    pub fn expected_assignment_count(&self) -> usize {
        let active_count = self.validator_set.active_count();
        self.config.max_validators.min(active_count)
    }

    /// Check if assignment is possible with current validator set
    pub fn can_assign(&self) -> bool {
        self.validator_set.active_count() >= self.config.min_validators
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::Keypair;

    fn create_test_keypair() -> Keypair {
        Keypair::generate()
    }

    fn create_validator_set_with_validators(count: usize) -> Arc<ValidatorSet> {
        let keypair = create_test_keypair();
        let set = ValidatorSet::new(keypair, 1000);

        for i in 0..count {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            bytes[1] = (i >> 8) as u8;
            // Give different stakes to test stake weighting
            let stake = 10_000 + (i as u64 * 5_000);
            let record = crate::validator::ValidatorRecord::new(Hotkey(bytes), stake);
            set.register_validator(record)
                .expect("should register validator");
        }

        Arc::new(set)
    }

    #[test]
    fn test_deterministic_assignment() {
        let validator_set = create_validator_set_with_validators(5);
        let config = AssignmentConfig::default();
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        // Perform same assignment twice
        let assignment1 = assignment_engine
            .assign(challenge_id, submission_hash, epoch)
            .expect("assignment should succeed");
        let assignment2 = assignment_engine
            .assign(challenge_id, submission_hash, epoch)
            .expect("assignment should succeed");

        // Verify assignments are identical
        assert_eq!(assignment1.primary, assignment2.primary);
        assert_eq!(assignment1.validators.len(), assignment2.validators.len());

        for (v1, v2) in assignment1
            .validators
            .iter()
            .zip(assignment2.validators.iter())
        {
            assert_eq!(v1.hotkey, v2.hotkey);
            assert_eq!(v1.priority, v2.priority);
            assert_eq!(v1.stake, v2.stake);
        }
    }

    #[test]
    fn test_stake_weighted_distribution() {
        // Create validators with very different stakes
        let keypair = create_test_keypair();
        let set = ValidatorSet::new(keypair, 1000);

        // High stake validator
        let mut high_stake_bytes = [1u8; 32];
        high_stake_bytes[0] = 1;
        let high_stake_record =
            crate::validator::ValidatorRecord::new(Hotkey(high_stake_bytes), 100_000_000);
        set.register_validator(high_stake_record)
            .expect("should register");

        // Low stake validator
        let mut low_stake_bytes = [2u8; 32];
        low_stake_bytes[0] = 2;
        let low_stake_record =
            crate::validator::ValidatorRecord::new(Hotkey(low_stake_bytes), 10_000);
        set.register_validator(low_stake_record)
            .expect("should register");

        // Medium stake validator
        let mut med_stake_bytes = [3u8; 32];
        med_stake_bytes[0] = 3;
        let med_stake_record =
            crate::validator::ValidatorRecord::new(Hotkey(med_stake_bytes), 1_000_000);
        set.register_validator(med_stake_record)
            .expect("should register");

        let validator_set = Arc::new(set);
        let config = AssignmentConfig {
            min_validators: 2,
            max_validators: 3,
            stake_weighted: true,
            epoch_seed: [0u8; 32],
        };
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        // Run multiple assignments and track who becomes primary
        let mut high_stake_primary_count = 0;
        let challenge_id = ChallengeId::new();

        for i in 0..100 {
            let mut submission_hash = [0u8; 32];
            submission_hash[0] = i as u8;
            submission_hash[1] = (i >> 8) as u8;

            let assignment = assignment_engine
                .assign(challenge_id, submission_hash, i as u64)
                .expect("should succeed");

            // Check if high stake validator is primary
            if assignment.primary == Hotkey(high_stake_bytes) {
                high_stake_primary_count += 1;
            }
        }

        // High stake validator should be primary more often than random (33%)
        // With 100x higher stake, they should dominate
        assert!(
            high_stake_primary_count > 50,
            "High stake validator should be primary more often, was primary {} times",
            high_stake_primary_count
        );
    }

    #[test]
    fn test_different_epochs_different_assignments() {
        // Create validators with equal stakes to ensure the hash-based randomness
        // is the primary factor in assignment ordering
        let keypair = create_test_keypair();
        let set = ValidatorSet::new(keypair, 1000);

        // Add 20 validators with equal stakes
        for i in 0..20 {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            bytes[1] = (i >> 8) as u8;
            // All validators have the same stake
            let stake = 10_000;
            let record = crate::validator::ValidatorRecord::new(Hotkey(bytes), stake);
            set.register_validator(record)
                .expect("should register validator");
        }
        let validator_set = Arc::new(set);

        // Use very different epoch seeds
        let mut seed1 = [0u8; 32];
        seed1[0] = 0xAA;
        seed1[31] = 0xBB;

        let mut seed2 = [0u8; 32];
        seed2[0] = 0xCC;
        seed2[31] = 0xDD;

        // Disable stake weighting to ensure hash determines order
        let config1 = AssignmentConfig {
            epoch_seed: seed1,
            max_validators: 15,
            stake_weighted: false,
            ..Default::default()
        };
        let config2 = AssignmentConfig {
            epoch_seed: seed2,
            max_validators: 15,
            stake_weighted: false,
            ..Default::default()
        };

        let assignment_engine1 = ValidatorAssignment::new(validator_set.clone(), config1);
        let assignment_engine2 = ValidatorAssignment::new(validator_set, config2);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        let assignment1 = assignment_engine1
            .assign(challenge_id, submission_hash, epoch)
            .expect("should succeed");
        let assignment2 = assignment_engine2
            .assign(challenge_id, submission_hash, epoch)
            .expect("should succeed");

        // Count how many positions are different
        let different_count = assignment1
            .validators
            .iter()
            .zip(assignment2.validators.iter())
            .filter(|(v1, v2)| v1.hotkey != v2.hotkey)
            .count();

        // With different epoch seeds, equal stakes, and 15 validators, at least some should be different
        // The probability of all 15 being the same is astronomically low (1/15!)
        assert!(
            different_count > 0,
            "Different epoch seeds should produce at least some different validator positions, got 0 differences"
        );
    }

    #[test]
    fn test_primary_validator_can_store() {
        let validator_set = create_validator_set_with_validators(5);
        let config = AssignmentConfig::default();
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        let assignment = assignment_engine
            .assign(challenge_id, submission_hash, epoch)
            .expect("should succeed");

        // Only primary (priority 0) should be able to store result
        let primary_validator = assignment
            .validators
            .iter()
            .find(|v| v.priority == 0)
            .expect("should have primary");

        assert!(
            primary_validator.can_store_result,
            "Primary validator should be able to store result"
        );

        // Other validators should not be able to store
        for validator in assignment.validators.iter().filter(|v| v.priority > 0) {
            assert!(
                !validator.can_store_result,
                "Non-primary validator should not be able to store result"
            );
        }

        // Verify via can_store_result method
        assert!(assignment_engine.can_store_result(
            &assignment.primary,
            challenge_id,
            &submission_hash,
            epoch
        ));
    }

    #[test]
    fn test_not_enough_validators_error() {
        let validator_set = create_validator_set_with_validators(2);
        let config = AssignmentConfig {
            min_validators: 5,
            max_validators: 10,
            stake_weighted: true,
            epoch_seed: [0u8; 32],
        };
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        let result = assignment_engine.assign(challenge_id, submission_hash, epoch);

        assert!(matches!(
            result,
            Err(AssignmentError::NotEnoughValidators {
                needed: 5,
                available: 2
            })
        ));
    }

    #[test]
    fn test_no_validators_error() {
        let keypair = create_test_keypair();
        let set = Arc::new(ValidatorSet::new(keypair, 1000));
        let config = AssignmentConfig::default();
        let assignment_engine = ValidatorAssignment::new(set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        let result = assignment_engine.assign(challenge_id, submission_hash, epoch);

        assert!(matches!(
            result,
            Err(AssignmentError::NoValidatorsAvailable)
        ));
    }

    #[test]
    fn test_is_assigned() {
        let validator_set = create_validator_set_with_validators(5);
        let config = AssignmentConfig::default();
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        let assignment = assignment_engine
            .assign(challenge_id, submission_hash, epoch)
            .expect("should succeed");

        // All assigned validators should return true
        for validator in &assignment.validators {
            assert!(assignment_engine.is_assigned(
                &validator.hotkey,
                challenge_id,
                &submission_hash,
                epoch
            ));
        }

        // Non-existent validator should return false
        let non_existent = Hotkey([255u8; 32]);
        assert!(!assignment_engine.is_assigned(
            &non_existent,
            challenge_id,
            &submission_hash,
            epoch
        ));
    }

    #[test]
    fn test_update_config() {
        let validator_set = create_validator_set_with_validators(5);
        let initial_config = AssignmentConfig::default();
        let mut assignment_engine = ValidatorAssignment::new(validator_set, initial_config);

        let new_config = AssignmentConfig {
            min_validators: 2,
            max_validators: 3,
            stake_weighted: false,
            epoch_seed: [99u8; 32],
        };

        assignment_engine.update_config(new_config.clone());

        assert_eq!(assignment_engine.config().min_validators, 2);
        assert_eq!(assignment_engine.config().max_validators, 3);
        assert!(!assignment_engine.config().stake_weighted);
        assert_eq!(assignment_engine.config().epoch_seed, [99u8; 32]);
    }

    #[test]
    fn test_max_validators_limit() {
        let validator_set = create_validator_set_with_validators(20);
        let config = AssignmentConfig {
            min_validators: 3,
            max_validators: 5,
            stake_weighted: true,
            epoch_seed: [0u8; 32],
        };
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        let assignment = assignment_engine
            .assign(challenge_id, submission_hash, epoch)
            .expect("should succeed");

        // Should only assign max_validators even though more are available
        assert_eq!(assignment.validators.len(), 5);
    }

    #[test]
    fn test_can_assign() {
        let validator_set = create_validator_set_with_validators(5);
        let config = AssignmentConfig {
            min_validators: 3,
            max_validators: 10,
            stake_weighted: true,
            epoch_seed: [0u8; 32],
        };
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        assert!(assignment_engine.can_assign());
    }

    #[test]
    fn test_cannot_assign_insufficient_validators() {
        let validator_set = create_validator_set_with_validators(2);
        let config = AssignmentConfig {
            min_validators: 5,
            max_validators: 10,
            stake_weighted: true,
            epoch_seed: [0u8; 32],
        };
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        assert!(!assignment_engine.can_assign());
    }

    #[test]
    fn test_expected_assignment_count() {
        let validator_set = create_validator_set_with_validators(8);
        let config = AssignmentConfig {
            min_validators: 3,
            max_validators: 5,
            stake_weighted: true,
            epoch_seed: [0u8; 32],
        };
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        // Should be min(max_validators, active_count) = min(5, 8) = 5
        assert_eq!(assignment_engine.expected_assignment_count(), 5);
    }

    #[test]
    fn test_get_validator_at_priority() {
        let validator_set = create_validator_set_with_validators(5);
        let config = AssignmentConfig::default();
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        // Get validator at priority 0 (primary)
        let primary = assignment_engine
            .get_validator_at_priority(challenge_id, &submission_hash, epoch, 0)
            .expect("should find primary");

        assert_eq!(primary.priority, 0);
        assert!(primary.can_store_result);

        // Get validator at priority 1 (first backup)
        let backup = assignment_engine
            .get_validator_at_priority(challenge_id, &submission_hash, epoch, 1)
            .expect("should find backup");

        assert_eq!(backup.priority, 1);
        assert!(!backup.can_store_result);
    }

    #[test]
    fn test_assignment_priority_ordering() {
        let validator_set = create_validator_set_with_validators(5);
        let config = AssignmentConfig::default();
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [42u8; 32];
        let epoch = 100;

        let assignment = assignment_engine
            .assign(challenge_id, submission_hash, epoch)
            .expect("should succeed");

        // Verify priorities are sequential starting from 0
        for (idx, validator) in assignment.validators.iter().enumerate() {
            assert_eq!(
                validator.priority, idx as u32,
                "Priority should match index"
            );
        }
    }

    #[test]
    fn test_assignment_config_default() {
        let config = AssignmentConfig::default();
        assert_eq!(config.min_validators, 3);
        assert_eq!(config.max_validators, 10);
        assert!(config.stake_weighted);
        assert_eq!(config.epoch_seed, [0u8; 32]);
    }

    #[test]
    fn test_assignment_contains_challenge_info() {
        let validator_set = create_validator_set_with_validators(5);
        let config = AssignmentConfig::default();
        let assignment_engine = ValidatorAssignment::new(validator_set, config);

        let challenge_id = ChallengeId::new();
        let submission_hash = [123u8; 32];
        let epoch = 42;

        let assignment = assignment_engine
            .assign(challenge_id, submission_hash, epoch)
            .expect("should succeed");

        assert_eq!(assignment.challenge_id, challenge_id);
        assert_eq!(assignment.submission_hash, submission_hash);
        assert_eq!(assignment.epoch, epoch);
        assert!(assignment.assigned_at > 0);
    }
}
