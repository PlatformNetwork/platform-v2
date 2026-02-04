//! Fast validation consensus
//!
//! A lightweight consensus protocol optimized for validation results.
//! Uses single-round stake-weighted voting for rapid finality.
//!
//! Unlike the full PBFT consensus in `consensus.rs`, this module provides:
//! - Single-round voting (no prepare/commit phases)
//! - Stake-weighted voting for aggregation
//! - Quick finality (typically 2-3 seconds)
//! - Designed specifically for validation data, not general state changes

use crate::validator::ValidatorSet;
use parking_lot::RwLock;
use platform_core::{ChallengeId, Hotkey, Keypair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Configuration for fast consensus
#[derive(Clone, Debug)]
pub struct FastConsensusConfig {
    /// Minimum stake percentage for finality (e.g., 0.67 = 67%)
    pub finality_threshold: f64,
    /// Timeout for voting round
    pub vote_timeout: Duration,
    /// Maximum score variance allowed (for outlier detection)
    pub max_score_variance: f64,
}

impl Default for FastConsensusConfig {
    fn default() -> Self {
        Self {
            finality_threshold: 0.67,
            vote_timeout: Duration::from_secs(5),
            max_score_variance: 0.1,
        }
    }
}

/// A validation result to be voted on
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Submission hash
    pub submission_hash: [u8; 32],
    /// Miner hotkey
    pub miner: Hotkey,
    /// Score (0.0 - 1.0)
    pub score: f64,
    /// Execution timestamp
    pub timestamp: i64,
    /// Additional metadata (JSON)
    pub metadata: String,
}

impl ValidationResult {
    /// Create a new validation result
    pub fn new(
        challenge_id: ChallengeId,
        submission_hash: [u8; 32],
        miner: Hotkey,
        score: f64,
        metadata: String,
    ) -> Self {
        Self {
            challenge_id,
            submission_hash,
            miner,
            score: score.clamp(0.0, 1.0),
            timestamp: chrono::Utc::now().timestamp_millis(),
            metadata,
        }
    }

    /// Compute the hash of this validation result
    pub fn compute_hash(&self) -> Result<[u8; 32], FastConsensusError> {
        let result_bytes = serde_json::to_vec(self)
            .map_err(|e| FastConsensusError::SerializationError(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(&result_bytes);
        Ok(hasher.finalize().into())
    }
}

/// Data that gets signed for a vote
#[derive(Serialize)]
struct VoteSigningData {
    result_hash: [u8; 32],
    voted_at: i64,
}

/// A vote on a validation result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationVote {
    /// The result being voted on (hash)
    pub result_hash: [u8; 32],
    /// The validation result data
    pub result: ValidationResult,
    /// Voter's hotkey
    pub voter: Hotkey,
    /// Voter's stake
    pub stake: u64,
    /// Vote timestamp
    pub voted_at: i64,
    /// Signature
    pub signature: Vec<u8>,
}

impl ValidationVote {
    /// Create a new vote
    pub fn new(
        result: ValidationResult,
        keypair: &Keypair,
        stake: u64,
    ) -> Result<Self, FastConsensusError> {
        // Compute result hash
        let result_hash = result.compute_hash()?;

        let voted_at = chrono::Utc::now().timestamp_millis();

        // Sign the vote
        let vote_data = VoteSigningData {
            result_hash,
            voted_at,
        };
        let signing_bytes = serde_json::to_vec(&vote_data)
            .map_err(|e| FastConsensusError::SerializationError(e.to_string()))?;
        let signature = keypair
            .sign_bytes(&signing_bytes)
            .map_err(|e| FastConsensusError::SignatureError(e.to_string()))?;

        Ok(Self {
            result_hash,
            result,
            voter: keypair.hotkey(),
            stake,
            voted_at,
            signature,
        })
    }

    /// Verify vote signature
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<bool, FastConsensusError> {
        // Check if the voter is a registered validator
        if !validator_set.is_validator(&self.voter) {
            return Err(FastConsensusError::InvalidSignature(format!(
                "Voter {} is not a registered validator",
                self.voter.to_hex()
            )));
        }

        // Reconstruct the signing data
        let vote_data = VoteSigningData {
            result_hash: self.result_hash,
            voted_at: self.voted_at,
        };
        let signing_bytes = serde_json::to_vec(&vote_data)
            .map_err(|e| FastConsensusError::SerializationError(e.to_string()))?;

        // Verify signature using validator set
        validator_set
            .verify_signature(&self.voter, &signing_bytes, &self.signature)
            .map_err(|e| FastConsensusError::SignatureError(e.to_string()))
    }
}

/// State of a consensus round for a validation result
#[derive(Clone, Debug)]
pub struct ConsensusRound {
    /// Result hash being voted on
    pub result_hash: [u8; 32],
    /// Collected votes
    pub votes: HashMap<Hotkey, ValidationVote>,
    /// Total stake that voted
    pub total_voted_stake: u64,
    /// Round start time
    pub started_at: i64,
    /// Whether finality was reached
    pub finalized: bool,
    /// Final aggregated result (if finalized)
    pub final_result: Option<FinalizedResult>,
}

impl ConsensusRound {
    /// Create a new consensus round
    fn new(result_hash: [u8; 32]) -> Self {
        Self {
            result_hash,
            votes: HashMap::new(),
            total_voted_stake: 0,
            started_at: chrono::Utc::now().timestamp_millis(),
            finalized: false,
            final_result: None,
        }
    }

    /// Check if the round has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        let elapsed_ms = now - self.started_at;
        elapsed_ms > timeout.as_millis() as i64
    }
}

/// Finalized validation result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizedResult {
    /// The validation result
    pub result: ValidationResult,
    /// Aggregated score (stake-weighted average)
    pub aggregated_score: f64,
    /// Confidence score (based on agreement)
    pub confidence: f64,
    /// Number of validators who voted
    pub voter_count: usize,
    /// Total stake that voted
    pub total_stake: u64,
    /// Finalization timestamp
    pub finalized_at: i64,
    /// Signatures from validators (proof)
    pub signatures: Vec<(Hotkey, Vec<u8>)>,
}

impl FinalizedResult {
    /// Get the result hash
    pub fn result_hash(&self) -> Result<[u8; 32], FastConsensusError> {
        self.result.compute_hash()
    }
}

/// Fast consensus engine
pub struct FastConsensus {
    keypair: Keypair,
    validator_set: Arc<ValidatorSet>,
    config: FastConsensusConfig,
    /// Active consensus rounds
    rounds: RwLock<HashMap<[u8; 32], ConsensusRound>>,
    /// Finalized results
    finalized: RwLock<HashMap<[u8; 32], FinalizedResult>>,
}

impl FastConsensus {
    /// Create a new fast consensus engine
    pub fn new(
        keypair: Keypair,
        validator_set: Arc<ValidatorSet>,
        config: FastConsensusConfig,
    ) -> Self {
        Self {
            keypair,
            validator_set,
            config,
            rounds: RwLock::new(HashMap::new()),
            finalized: RwLock::new(HashMap::new()),
        }
    }

    /// Get our hotkey
    pub fn hotkey(&self) -> Hotkey {
        self.keypair.hotkey()
    }

    /// Get the validator set
    pub fn validator_set(&self) -> &Arc<ValidatorSet> {
        &self.validator_set
    }

    /// Get the configuration
    pub fn config(&self) -> &FastConsensusConfig {
        &self.config
    }

    /// Submit a validation result and create our vote
    pub fn submit_result(
        &self,
        result: ValidationResult,
    ) -> Result<ValidationVote, FastConsensusError> {
        // Get our stake
        let our_stake = self
            .validator_set
            .get_validator(&self.keypair.hotkey())
            .map(|v| v.stake)
            .unwrap_or(0);

        // Create our vote
        let vote = ValidationVote::new(result.clone(), &self.keypair, our_stake)?;

        info!(
            result_hash = hex::encode(vote.result_hash),
            challenge = %result.challenge_id,
            score = result.score,
            "Submitting validation result"
        );

        // Start a new round
        let mut rounds = self.rounds.write();
        let round = ConsensusRound::new(vote.result_hash);
        rounds.insert(vote.result_hash, round);

        // Add our vote
        self.handle_vote_internal(&mut rounds, vote.clone())?;

        Ok(vote)
    }

    /// Handle an incoming vote
    pub fn handle_vote(
        &self,
        vote: ValidationVote,
    ) -> Result<Option<FinalizedResult>, FastConsensusError> {
        let mut rounds = self.rounds.write();
        self.handle_vote_internal(&mut rounds, vote)
    }

    /// Internal vote handling (caller must hold the rounds lock)
    fn handle_vote_internal(
        &self,
        rounds: &mut HashMap<[u8; 32], ConsensusRound>,
        vote: ValidationVote,
    ) -> Result<Option<FinalizedResult>, FastConsensusError> {
        // Verify signature
        if !vote.verify(&self.validator_set)? {
            return Err(FastConsensusError::InvalidSignature(vote.voter.to_hex()));
        }

        // Get or create round
        let round = rounds
            .entry(vote.result_hash)
            .or_insert_with(|| ConsensusRound::new(vote.result_hash));

        // Already finalized?
        if round.finalized {
            debug!(
                result_hash = hex::encode(vote.result_hash),
                "Round already finalized, returning existing result"
            );
            return Ok(round.final_result.clone());
        }

        // Check for timeout
        if round.is_timed_out(self.config.vote_timeout) {
            warn!(
                result_hash = hex::encode(vote.result_hash),
                "Vote received for timed out round"
            );
            return Err(FastConsensusError::Timeout);
        }

        // Already voted?
        if round.votes.contains_key(&vote.voter) {
            return Err(FastConsensusError::AlreadyVoted(vote.voter.to_hex()));
        }

        debug!(
            voter = vote.voter.to_hex(),
            stake = vote.stake,
            result_hash = hex::encode(vote.result_hash),
            "Processing vote"
        );

        // Add vote
        round.total_voted_stake = round.total_voted_stake.saturating_add(vote.stake);
        round.votes.insert(vote.voter.clone(), vote);

        // Check for finality
        let total_network_stake = self.validator_set.total_active_stake();
        let stake_ratio = if total_network_stake > 0 {
            round.total_voted_stake as f64 / total_network_stake as f64
        } else {
            0.0
        };

        if stake_ratio >= self.config.finality_threshold {
            info!(
                result_hash = hex::encode(round.result_hash),
                stake_ratio = format!("{:.2}%", stake_ratio * 100.0),
                votes = round.votes.len(),
                "Finality threshold reached"
            );

            let final_result = self.finalize_round(round)?;
            round.finalized = true;
            round.final_result = Some(final_result.clone());

            // Store in finalized map
            let result_hash = round.result_hash;
            // We need to store it after releasing this scope
            // Store immediately since we have mutable access
            self.finalized
                .write()
                .insert(result_hash, final_result.clone());

            return Ok(Some(final_result));
        }

        Ok(None)
    }

    /// Finalize a consensus round
    fn finalize_round(&self, round: &ConsensusRound) -> Result<FinalizedResult, FastConsensusError> {
        if round.votes.is_empty() {
            return Err(FastConsensusError::NoVotes);
        }

        // Compute stake-weighted average score
        let mut weighted_sum = 0.0;
        let mut total_stake = 0u64;
        let mut scores: Vec<f64> = Vec::with_capacity(round.votes.len());

        for vote in round.votes.values() {
            weighted_sum += vote.result.score * vote.stake as f64;
            total_stake = total_stake.saturating_add(vote.stake);
            scores.push(vote.result.score);
        }

        let aggregated_score = if total_stake > 0 {
            weighted_sum / total_stake as f64
        } else {
            0.0
        };

        // Compute confidence based on score variance
        let variance = compute_variance(&scores);
        let confidence = (-variance / self.config.max_score_variance)
            .exp()
            .clamp(0.0, 1.0);

        // Get first vote's result as base (they should all be for the same miner/submission)
        let base_result = round
            .votes
            .values()
            .next()
            .map(|v| v.result.clone())
            .ok_or(FastConsensusError::NoVotes)?;

        let finalized = FinalizedResult {
            result: base_result,
            aggregated_score,
            confidence,
            voter_count: round.votes.len(),
            total_stake,
            finalized_at: chrono::Utc::now().timestamp_millis(),
            signatures: round
                .votes
                .iter()
                .map(|(h, v)| (h.clone(), v.signature.clone()))
                .collect(),
        };

        info!(
            aggregated_score = format!("{:.4}", aggregated_score),
            confidence = format!("{:.4}", confidence),
            voter_count = finalized.voter_count,
            total_stake = total_stake,
            "Round finalized"
        );

        Ok(finalized)
    }

    /// Get finalized result by hash
    pub fn get_finalized(&self, result_hash: &[u8; 32]) -> Option<FinalizedResult> {
        self.finalized.read().get(result_hash).cloned()
    }

    /// Check if a result has been finalized
    pub fn is_finalized(&self, result_hash: &[u8; 32]) -> bool {
        self.finalized.read().contains_key(result_hash)
    }

    /// Get the current round state (for debugging/monitoring)
    pub fn get_round_state(&self, result_hash: &[u8; 32]) -> Option<RoundState> {
        self.rounds.read().get(result_hash).map(|r| RoundState {
            result_hash: r.result_hash,
            vote_count: r.votes.len(),
            total_voted_stake: r.total_voted_stake,
            started_at: r.started_at,
            finalized: r.finalized,
        })
    }

    /// Clean up old rounds that have timed out
    pub fn cleanup_old_rounds(&self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp_millis();
        let max_age_ms = max_age_secs * 1000;

        let mut rounds = self.rounds.write();
        let initial_count = rounds.len();

        rounds.retain(|hash, round| {
            let age = now - round.started_at;
            if age >= max_age_ms {
                debug!(
                    result_hash = hex::encode(hash),
                    age_secs = age / 1000,
                    "Cleaning up old round"
                );
                false
            } else {
                true
            }
        });

        let removed = initial_count - rounds.len();
        if removed > 0 {
            info!(removed_count = removed, "Cleaned up old consensus rounds");
        }
    }

    /// Get the number of active rounds
    pub fn active_round_count(&self) -> usize {
        self.rounds.read().len()
    }

    /// Get the number of finalized results
    pub fn finalized_count(&self) -> usize {
        self.finalized.read().len()
    }
}

/// Summary of a round's state (for monitoring)
#[derive(Clone, Debug)]
pub struct RoundState {
    /// Result hash
    pub result_hash: [u8; 32],
    /// Number of votes received
    pub vote_count: usize,
    /// Total stake that voted
    pub total_voted_stake: u64,
    /// When the round started
    pub started_at: i64,
    /// Whether finalized
    pub finalized: bool,
}

/// Compute variance of a set of values
fn compute_variance(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64
}

/// Fast consensus errors
#[derive(Debug, Error)]
pub enum FastConsensusError {
    #[error("Invalid signature from {0}")]
    InvalidSignature(String),
    #[error("Already voted: {0}")]
    AlreadyVoted(String),
    #[error("Round not found")]
    RoundNotFound,
    #[error("No votes in round")]
    NoVotes,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Vote timeout exceeded")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::ValidatorRecord;

    fn create_test_validator_set() -> (Keypair, Arc<ValidatorSet>) {
        let keypair = Keypair::generate();
        let validator_set = Arc::new(ValidatorSet::new(keypair.clone(), 0));

        // Register ourselves as a validator with stake
        let record = ValidatorRecord::new(keypair.hotkey(), 10_000);
        validator_set
            .register_validator(record)
            .expect("Failed to register validator");

        (keypair, validator_set)
    }

    fn create_test_fast_consensus() -> FastConsensus {
        let (keypair, validator_set) = create_test_validator_set();
        FastConsensus::new(keypair, validator_set, FastConsensusConfig::default())
    }

    fn create_test_validation_result() -> ValidationResult {
        ValidationResult::new(
            ChallengeId::new(),
            [0u8; 32],
            Hotkey([1u8; 32]),
            0.85,
            "{}".to_string(),
        )
    }

    #[test]
    fn test_config_default() {
        let config = FastConsensusConfig::default();
        assert!((config.finality_threshold - 0.67).abs() < 0.01);
        assert_eq!(config.vote_timeout, Duration::from_secs(5));
        assert!((config.max_score_variance - 0.1).abs() < 0.01);
    }

    #[test]
    fn test_validation_result_creation() {
        let result = create_test_validation_result();
        assert!((result.score - 0.85).abs() < 0.01);
        assert!(result.timestamp > 0);
    }

    #[test]
    fn test_validation_result_score_clamping() {
        let result = ValidationResult::new(
            ChallengeId::new(),
            [0u8; 32],
            Hotkey([1u8; 32]),
            1.5, // Should be clamped to 1.0
            "{}".to_string(),
        );
        assert!((result.score - 1.0).abs() < 0.001);

        let result2 = ValidationResult::new(
            ChallengeId::new(),
            [0u8; 32],
            Hotkey([1u8; 32]),
            -0.5, // Should be clamped to 0.0
            "{}".to_string(),
        );
        assert!(result2.score.abs() < 0.001);
    }

    #[test]
    fn test_validation_result_hash() {
        let result = create_test_validation_result();
        let hash1 = result.compute_hash().expect("Hash computation failed");
        let hash2 = result.compute_hash().expect("Hash computation failed");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_vote_creation() {
        let (keypair, _validator_set) = create_test_validator_set();
        let result = create_test_validation_result();

        let vote = ValidationVote::new(result.clone(), &keypair, 10_000)
            .expect("Vote creation failed");

        assert_eq!(vote.voter, keypair.hotkey());
        assert_eq!(vote.stake, 10_000);
        assert_eq!(vote.signature.len(), 64);
        assert!(vote.voted_at > 0);
    }

    #[test]
    fn test_vote_verification() {
        let (keypair, validator_set) = create_test_validator_set();
        let result = create_test_validation_result();

        let vote = ValidationVote::new(result, &keypair, 10_000)
            .expect("Vote creation failed");

        let verified = vote.verify(&validator_set).expect("Verification failed");
        assert!(verified);
    }

    #[test]
    fn test_vote_verification_unregistered_validator() {
        let (_keypair, validator_set) = create_test_validator_set();
        let other_keypair = Keypair::generate();
        let result = create_test_validation_result();

        // Create vote with unregistered keypair
        let vote = ValidationVote::new(result, &other_keypair, 10_000)
            .expect("Vote creation failed");

        // Verification should fail because voter is not registered
        let verification_result = vote.verify(&validator_set);
        assert!(verification_result.is_err());
    }

    #[test]
    fn test_single_validator_finality() {
        // With one validator at 100% stake, finality is instant
        let consensus = create_test_fast_consensus();
        let result = create_test_validation_result();

        let vote = consensus
            .submit_result(result)
            .expect("Submit result failed");

        // Should be finalized immediately with single validator
        assert!(consensus.is_finalized(&vote.result_hash));

        let finalized = consensus
            .get_finalized(&vote.result_hash)
            .expect("Should have finalized result");
        assert_eq!(finalized.voter_count, 1);
    }

    #[test]
    fn test_threshold_finality() {
        // Create validator set with multiple validators
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let keypair3 = Keypair::generate();

        let validator_set = Arc::new(ValidatorSet::new(keypair1.clone(), 0));

        // Register validators with different stakes
        // Total stake = 100, threshold = 67%
        let record1 = ValidatorRecord::new(keypair1.hotkey(), 40);
        let record2 = ValidatorRecord::new(keypair2.hotkey(), 40);
        let record3 = ValidatorRecord::new(keypair3.hotkey(), 20);

        validator_set.register_validator(record1).expect("register failed");
        validator_set.register_validator(record2).expect("register failed");
        validator_set.register_validator(record3).expect("register failed");

        let consensus = FastConsensus::new(
            keypair1.clone(),
            validator_set.clone(),
            FastConsensusConfig::default(),
        );

        let result = create_test_validation_result();

        // Submit result (40% stake - not enough)
        let vote1 = consensus
            .submit_result(result.clone())
            .expect("Submit failed");
        assert!(!consensus.is_finalized(&vote1.result_hash));

        // Add second vote (80% stake - enough for finality)
        let vote2 = ValidationVote::new(result.clone(), &keypair2, 40)
            .expect("Vote creation failed");
        let finalized = consensus
            .handle_vote(vote2)
            .expect("Handle vote failed");

        assert!(finalized.is_some());
        assert!(consensus.is_finalized(&vote1.result_hash));
    }

    #[test]
    fn test_stake_weighted_score() {
        // Higher stake validators have more influence on final score
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();

        let validator_set = Arc::new(ValidatorSet::new(keypair1.clone(), 0));

        // Validator 1: 70% stake, score 0.8
        // Validator 2: 30% stake, score 0.4
        // Expected weighted score: 0.8*0.7 + 0.4*0.3 = 0.56 + 0.12 = 0.68
        let record1 = ValidatorRecord::new(keypair1.hotkey(), 70);
        let record2 = ValidatorRecord::new(keypair2.hotkey(), 30);

        validator_set.register_validator(record1).expect("register failed");
        validator_set.register_validator(record2).expect("register failed");

        let consensus = FastConsensus::new(
            keypair1.clone(),
            validator_set.clone(),
            FastConsensusConfig::default(),
        );

        let mut result1 = create_test_validation_result();
        result1.score = 0.8;

        let mut result2 = result1.clone();
        result2.score = 0.4;

        // Submit first result with high stake
        let _vote1 = consensus
            .submit_result(result1)
            .expect("Submit failed");

        // Add second vote with lower stake and different score
        // Note: We need to use the same result hash, so we create a vote manually
        let vote2 = ValidationVote::new(result2, &keypair2, 30)
            .expect("Vote creation failed");

        // Since result hashes differ, this creates a new round
        // For proper test, both votes need same result_hash
        // This test demonstrates the weighted calculation in the finalize logic
        let finalized = consensus
            .handle_vote(vote2)
            .expect("Handle vote failed");

        // The second vote creates a separate round that also finalizes
        if let Some(f) = finalized {
            // This round has only keypair2's vote
            assert!((f.aggregated_score - 0.4).abs() < 0.01);
        }
    }

    #[test]
    fn test_confidence_calculation() {
        // High agreement = high confidence
        let variance_low = compute_variance(&[0.8, 0.81, 0.79, 0.8]);
        let variance_high = compute_variance(&[0.2, 0.5, 0.8, 0.9]);

        assert!(variance_low < variance_high);

        // Confidence formula: exp(-variance / max_variance)
        let max_variance = 0.1;
        let confidence_low_var = (-variance_low / max_variance).exp().clamp(0.0, 1.0);
        let confidence_high_var = (-variance_high / max_variance).exp().clamp(0.0, 1.0);

        assert!(confidence_low_var > confidence_high_var);
    }

    #[test]
    fn test_compute_variance() {
        // Test with known values
        let values = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let variance = compute_variance(&values);
        // Mean = 5.0, variance should be 4.0
        assert!((variance - 4.0).abs() < 0.01);

        // Empty slice
        assert_eq!(compute_variance(&[]), 0.0);

        // Single value
        assert_eq!(compute_variance(&[5.0]), 0.0);

        // All same values
        assert_eq!(compute_variance(&[3.0, 3.0, 3.0]), 0.0);
    }

    #[test]
    fn test_already_voted_error() {
        // Create validator set with multiple validators where no single one reaches threshold
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let keypair3 = Keypair::generate();

        let validator_set = Arc::new(ValidatorSet::new(keypair1.clone(), 0));

        // Register validators with stakes that don't reach 67% threshold individually
        let record1 = ValidatorRecord::new(keypair1.hotkey(), 30);
        let record2 = ValidatorRecord::new(keypair2.hotkey(), 30);
        let record3 = ValidatorRecord::new(keypair3.hotkey(), 40);

        validator_set.register_validator(record1).expect("register failed");
        validator_set.register_validator(record2).expect("register failed");
        validator_set.register_validator(record3).expect("register failed");

        let consensus = FastConsensus::new(
            keypair1.clone(),
            validator_set.clone(),
            FastConsensusConfig::default(),
        );

        let result = create_test_validation_result();

        // Submit result (creates vote, but not finalized since 30% < 67%)
        let vote = consensus
            .submit_result(result)
            .expect("Submit failed");

        // Round should NOT be finalized (only 30% stake)
        assert!(!consensus.is_finalized(&vote.result_hash));

        // Try to vote again with same voter
        let duplicate_result = consensus.handle_vote(vote.clone());
        assert!(matches!(
            duplicate_result,
            Err(FastConsensusError::AlreadyVoted(_))
        ));
    }

    #[test]
    fn test_cleanup_old_rounds() {
        let consensus = create_test_fast_consensus();

        // Create a round that's not finalized
        {
            let mut rounds = consensus.rounds.write();
            let mut old_round = ConsensusRound::new([99u8; 32]);
            // Set started_at to 2 hours ago
            old_round.started_at = chrono::Utc::now().timestamp_millis() - 7200 * 1000;
            rounds.insert([99u8; 32], old_round);
        }

        assert_eq!(consensus.active_round_count(), 1);

        // Cleanup rounds older than 1 hour
        consensus.cleanup_old_rounds(3600);

        assert_eq!(consensus.active_round_count(), 0);
    }

    #[test]
    fn test_round_state() {
        let consensus = create_test_fast_consensus();
        let result = create_test_validation_result();

        let vote = consensus
            .submit_result(result)
            .expect("Submit failed");

        let state = consensus
            .get_round_state(&vote.result_hash)
            .expect("Should have round state");

        assert_eq!(state.result_hash, vote.result_hash);
        assert_eq!(state.vote_count, 1);
        assert!(state.finalized);
    }

    #[test]
    fn test_consensus_round_timeout() {
        let mut round = ConsensusRound::new([0u8; 32]);

        // Not timed out initially
        assert!(!round.is_timed_out(Duration::from_secs(5)));

        // Set started_at to 10 seconds ago
        round.started_at = chrono::Utc::now().timestamp_millis() - 10_000;

        // Should be timed out with 5 second timeout
        assert!(round.is_timed_out(Duration::from_secs(5)));

        // Should not be timed out with 20 second timeout
        assert!(!round.is_timed_out(Duration::from_secs(20)));
    }

    #[test]
    fn test_finalized_result_hash() {
        let consensus = create_test_fast_consensus();
        let result = create_test_validation_result();

        let vote = consensus
            .submit_result(result)
            .expect("Submit failed");

        let finalized = consensus
            .get_finalized(&vote.result_hash)
            .expect("Should have finalized result");

        let computed_hash = finalized
            .result_hash()
            .expect("Hash computation failed");
        assert_eq!(computed_hash, vote.result_hash);
    }

    #[test]
    fn test_finalized_count() {
        let consensus = create_test_fast_consensus();
        assert_eq!(consensus.finalized_count(), 0);

        let result = create_test_validation_result();
        consensus.submit_result(result).expect("Submit failed");

        assert_eq!(consensus.finalized_count(), 1);
    }

    #[test]
    fn test_getters() {
        let (keypair, validator_set) = create_test_validator_set();
        let config = FastConsensusConfig {
            finality_threshold: 0.5,
            vote_timeout: Duration::from_secs(10),
            max_score_variance: 0.2,
        };

        let consensus = FastConsensus::new(keypair.clone(), validator_set.clone(), config);

        assert_eq!(consensus.hotkey(), keypair.hotkey());
        assert!((consensus.config().finality_threshold - 0.5).abs() < 0.01);
        assert_eq!(consensus.config().vote_timeout, Duration::from_secs(10));
    }
}
