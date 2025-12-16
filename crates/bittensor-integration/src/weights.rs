//! Weight submission to Bittensor
//!
//! This module handles submitting weights to the Bittensor network using the
//! commit-reveal pattern that matches subtensor's exact format.

use crate::SubtensorClient;
use anyhow::Result;
use bittensor_rs::chain::ExtrinsicWait;
use bittensor_rs::validator_weights::{
    commit_weights, prepare_commit_reveal, prepare_mechanism_commit_reveal, reveal_weights,
    set_weights,
};
use bittensor_rs::{
    commit_mechanism_weights, get_next_epoch_start_block, reveal_mechanism_weights,
    set_mechanism_weights,
};
use platform_challenge_sdk::WeightAssignment;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Weight submission manager
pub struct WeightSubmitter {
    client: SubtensorClient,
    /// Current commit hash (if using commit-reveal) - now uses v2 format
    pending_commit: Option<PendingCommitV2>,
    /// Pending mechanism commits for batch commit-reveal
    pending_mechanism_commits: HashMap<u8, PendingMechanismCommit>,
}

/// Pending mechanism commit data
#[derive(Clone, Debug)]
struct PendingMechanismCommit {
    mechanism_id: u8,
    hash: String,
    uids: Vec<u16>,
    weights: Vec<u16>,
    salt: Vec<u16>,
    version_key: u64,
}

/// Pending commit data using subtensor-compatible format (v2)
#[derive(Clone, Debug)]
struct PendingCommitV2 {
    hash: String,
    uids: Vec<u16>, // u16 to match subtensor
    weights: Vec<u16>,
    salt: Vec<u16>, // u16 salt as required by subtensor
    version_key: u64,
}

impl WeightSubmitter {
    /// Create a new weight submitter
    pub fn new(client: SubtensorClient) -> Self {
        Self {
            client,
            pending_commit: None,
            pending_mechanism_commits: HashMap::new(),
        }
    }

    /// Get mutable access to the client
    pub fn client_mut(&mut self) -> &mut SubtensorClient {
        &mut self.client
    }

    /// Submit weights to Bittensor
    ///
    /// If commit-reveal is enabled:
    ///   1. First call commits the hash
    ///   2. Second call reveals the weights (after tempo blocks)
    ///
    /// If not:
    ///   - Directly calls set_weights
    pub async fn submit_weights(&mut self, weights: &[WeightAssignment]) -> Result<String> {
        if self.client.use_commit_reveal() {
            self.submit_with_commit_reveal(weights).await
        } else {
            self.submit_direct(weights).await
        }
    }

    /// Direct weight submission (no commit-reveal)
    async fn submit_direct(&self, weights: &[WeightAssignment]) -> Result<String> {
        let (uids, weight_values) = self.prepare_weights(weights)?;

        if uids.is_empty() {
            return Err(anyhow::anyhow!("No valid UIDs found for weights"));
        }

        // Convert u16 weights to f32 for set_weights
        let weight_f32: Vec<f32> = weight_values.iter().map(|w| *w as f32 / 65535.0).collect();

        info!("Submitting {} weights directly", uids.len());

        let tx_hash = set_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            &uids,
            &weight_f32,
            Some(self.client.version_key()),
            ExtrinsicWait::Finalized,
        )
        .await?;

        info!("Weights submitted: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Submit with commit-reveal pattern (v2 - subtensor compatible)
    async fn submit_with_commit_reveal(&mut self, weights: &[WeightAssignment]) -> Result<String> {
        // If we have a pending commit, reveal it
        if let Some(pending) = self.pending_commit.take() {
            return self.reveal_pending_v2(pending).await;
        }

        // Otherwise, create new commit using v2 format
        let (uids, weight_values) = self.prepare_weights(weights)?;

        if uids.is_empty() {
            return Err(anyhow::anyhow!("No valid UIDs found for weights"));
        }

        // Convert to u16 for subtensor
        let uids_u16: Vec<u16> = uids.iter().map(|u| *u as u16).collect();

        // Get account public key for hash
        let account = self.client.signer()?.account_id().0;
        let version_key = self.client.version_key();

        // Generate commit using v2 format (subtensor compatible)
        let commit_data = prepare_commit_reveal(
            &account,
            self.client.netuid(),
            &uids_u16,
            &weight_values,
            version_key,
            8, // salt length
        );

        info!("Committing weights hash (v2): {}", commit_data.commit_hash);

        let tx_hash = commit_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            &commit_data.commit_hash,
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Store pending commit for reveal
        self.pending_commit = Some(PendingCommitV2 {
            hash: commit_data.commit_hash,
            uids: commit_data.uids,
            weights: commit_data.weights,
            salt: commit_data.salt,
            version_key: commit_data.version_key,
        });

        info!("Weights committed: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Reveal pending commit (v2 format)
    async fn reveal_pending_v2(&mut self, pending: PendingCommitV2) -> Result<String> {
        info!("Revealing weights for commit: {}", pending.hash);

        // Convert uids to u64 for reveal_weights API
        let uids_u64: Vec<u64> = pending.uids.iter().map(|u| *u as u64).collect();

        let tx_hash = reveal_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            &uids_u64,
            &pending.weights,
            // Convert salt u16 back to u8 for reveal_weights API (it converts internally)
            &pending.salt.iter().map(|s| *s as u8).collect::<Vec<u8>>(),
            pending.version_key,
            ExtrinsicWait::Finalized,
        )
        .await?;

        info!("Weights revealed: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Check if we have a pending commit to reveal
    pub fn has_pending_commit(&self) -> bool {
        self.pending_commit.is_some()
    }

    /// Prepare weights for submission
    /// Converts WeightAssignment to (UIDs, normalized u16 weights)
    fn prepare_weights(&self, weights: &[WeightAssignment]) -> Result<(Vec<u64>, Vec<u16>)> {
        // Get hotkeys from weights
        let hotkeys: Vec<String> = weights.iter().map(|w| w.agent_hash.clone()).collect();

        // Lookup UIDs for hotkeys from cached metagraph
        let uid_map = self.client.get_uids_for_hotkeys(&hotkeys);

        let mut uids = Vec::new();
        let mut weight_values = Vec::new();

        for weight in weights {
            if let Some((_, uid)) = uid_map.iter().find(|(h, _)| h == &weight.agent_hash) {
                uids.push(*uid as u64);
                // Convert 0-1 weight to u16 (0-65535)
                let w_u16 = (weight.weight.clamp(0.0, 1.0) * 65535.0) as u16;
                weight_values.push(w_u16);
            } else {
                warn!("No UID found for hotkey: {}", weight.agent_hash);
            }
        }

        debug!(
            "Prepared {} weights from {} assignments",
            uids.len(),
            weights.len()
        );
        Ok((uids, weight_values))
    }

    /// Force reveal without new commit (if we have pending)
    pub async fn force_reveal(&mut self) -> Result<Option<String>> {
        if let Some(pending) = self.pending_commit.take() {
            let tx = self.reveal_pending_v2(pending).await?;
            Ok(Some(tx))
        } else {
            Ok(None)
        }
    }

    /// Submit weights for multiple mechanisms in a single batch transaction
    /// This is used at epoch end to submit all mechanism weights at once.
    ///
    /// mechanism_weights: Vec<(mechanism_id, uids, weights)>
    pub async fn submit_mechanism_weights_batch(
        &mut self,
        mechanism_weights: &[(u8, Vec<u16>, Vec<u16>)],
    ) -> Result<String> {
        if mechanism_weights.is_empty() {
            return Err(anyhow::anyhow!("No mechanism weights to submit"));
        }

        if self.client.use_commit_reveal() {
            self.submit_mechanism_weights_batch_commit_reveal(mechanism_weights)
                .await
        } else {
            self.submit_mechanism_weights_batch_direct(mechanism_weights)
                .await
        }
    }

    /// Submit mechanism weights directly (without commit-reveal)
    async fn submit_mechanism_weights_batch_direct(
        &mut self,
        mechanism_weights: &[(u8, Vec<u16>, Vec<u16>)],
    ) -> Result<String> {
        use bittensor_rs::validator::utility::batch_set_mechanism_weights;

        let weights_for_batch: Vec<(u8, Vec<u16>, Vec<u16>)> =
            mechanism_weights.iter().cloned().collect();

        info!(
            "Batch submitting weights directly for {} mechanisms",
            weights_for_batch.len()
        );

        let tx_hash = batch_set_mechanism_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            weights_for_batch,
            self.client.version_key(),
            ExtrinsicWait::Finalized,
        )
        .await?;

        info!("Batch mechanism weights submitted: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Submit mechanism weights using commit-reveal pattern
    async fn submit_mechanism_weights_batch_commit_reveal(
        &mut self,
        mechanism_weights: &[(u8, Vec<u16>, Vec<u16>)],
    ) -> Result<String> {
        use bittensor_rs::commit_hash_to_hex;
        use bittensor_rs::generate_mechanism_commit_hash;
        use bittensor_rs::generate_salt;
        use bittensor_rs::validator::utility::{batch_all, BatchCall};

        let account = self.client.signer()?.account_id().0;
        let netuid = self.client.netuid();
        let version_key = self.client.version_key();

        // Generate commits for all mechanisms
        let mut batch_calls = Vec::new();
        let mut pending_commits = Vec::new();

        for (mechanism_id, uids, weights) in mechanism_weights {
            // Generate salt (8 bytes converted to u16)
            let salt = generate_salt(8);

            // Generate commit hash
            let commit_hash = generate_mechanism_commit_hash(
                &account,
                netuid,
                *mechanism_id,
                uids,
                weights,
                &salt,
                version_key,
            );

            let commit_hash_hex = commit_hash_to_hex(&commit_hash);
            info!(
                "Generated commit for mechanism {}: {}",
                mechanism_id,
                &commit_hash_hex[..16]
            );

            // Add to batch
            batch_calls.push(BatchCall::commit_mechanism_weights(
                netuid,
                *mechanism_id,
                &commit_hash,
            ));

            // Store pending commit for later reveal
            pending_commits.push(PendingMechanismCommit {
                mechanism_id: *mechanism_id,
                hash: commit_hash_hex,
                uids: uids.clone(),
                weights: weights.clone(),
                salt: salt.iter().map(|b| *b as u16).collect(),
                version_key,
            });
        }

        info!(
            "Batch committing weights for {} mechanisms",
            batch_calls.len()
        );

        // Submit all commits in one batch transaction
        let tx_hash = batch_all(
            self.client.client()?,
            self.client.signer()?,
            batch_calls,
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Store pending commits for reveal
        for pending in pending_commits {
            self.pending_mechanism_commits
                .insert(pending.mechanism_id, pending);
        }

        info!(
            "Batch mechanism commits submitted: {} (reveals pending)",
            tx_hash
        );
        Ok(tx_hash)
    }

    /// Reveal all pending mechanism commits
    pub async fn reveal_pending_mechanism_commits(&mut self) -> Result<Option<String>> {
        use bittensor_rs::reveal_mechanism_weights;

        if self.pending_mechanism_commits.is_empty() {
            return Ok(None);
        }

        let pending: Vec<_> = self.pending_mechanism_commits.drain().collect();

        info!("Revealing {} pending mechanism commits", pending.len());

        // Reveal each mechanism's weights
        // Batch reveal via mechanism weights API
        let mut last_tx = String::new();
        for (_, commit) in pending {
            let tx_hash = reveal_mechanism_weights(
                self.client.client()?,
                self.client.signer()?,
                self.client.netuid(),
                commit.mechanism_id,
                &commit.uids,
                &commit.weights,
                &commit.salt,
                commit.version_key,
                ExtrinsicWait::Finalized,
            )
            .await?;

            info!(
                "Revealed mechanism {} weights: {}",
                commit.mechanism_id, tx_hash
            );
            last_tx = tx_hash;
        }

        Ok(Some(last_tx))
    }

    /// Check if there are pending mechanism commits to reveal
    pub fn has_pending_mechanism_commits(&self) -> bool {
        !self.pending_mechanism_commits.is_empty()
    }
}

/// Utility to convert f64 weights to normalized u16
pub fn normalize_to_u16(weights: &[f64]) -> Vec<u16> {
    let sum: f64 = weights.iter().sum();
    if sum == 0.0 {
        return vec![0; weights.len()];
    }

    weights
        .iter()
        .map(|w| ((w / sum) * 65535.0) as u16)
        .collect()
}

/// Mechanism weight manager for handling per-challenge weights
pub struct MechanismWeightManager {
    client: SubtensorClient,
    /// Track last epoch we set weights for each mechanism
    last_weight_epoch: HashMap<u8, u64>,
    /// Pending mechanism commits (mechanism_id -> PendingMechanismCommitV2)
    pending_mechanism_commits: HashMap<u8, PendingMechanismCommitV2>,
}

/// Pending mechanism commit data using subtensor-compatible format (v2)
#[derive(Clone, Debug)]
struct PendingMechanismCommitV2 {
    mechanism_id: u8,
    hash: String,
    uids: Vec<u16>, // u16 to match subtensor
    weights: Vec<u16>,
    salt: Vec<u16>, // u16 salt as required by subtensor
    version_key: u64,
    epoch: u64,
}

impl MechanismWeightManager {
    /// Create a new mechanism weight manager
    pub fn new(client: SubtensorClient) -> Self {
        Self {
            client,
            last_weight_epoch: HashMap::new(),
            pending_mechanism_commits: HashMap::new(),
        }
    }

    /// Get mutable access to the client
    pub fn client_mut(&mut self) -> &mut SubtensorClient {
        &mut self.client
    }

    /// Get the next epoch start block
    pub async fn get_next_epoch(&self) -> Result<u64> {
        let client = self.client.client()?;
        let next_epoch = get_next_epoch_start_block(client, self.client.netuid(), None)
            .await?
            .unwrap_or(0);
        Ok(next_epoch)
    }

    /// Check if weights have already been set for this mechanism in current epoch
    pub fn has_set_weights_for_epoch(&self, mechanism_id: u8, epoch: u64) -> bool {
        self.last_weight_epoch
            .get(&mechanism_id)
            .map(|e| *e >= epoch)
            .unwrap_or(false)
    }

    /// Submit mechanism weights for a specific challenge
    /// Returns Ok(None) if weights already set for this epoch
    pub async fn submit_mechanism_weights(
        &mut self,
        mechanism_id: u8,
        weights: &[WeightAssignment],
        epoch: u64,
    ) -> Result<Option<String>> {
        // Check if already set for this epoch
        if self.has_set_weights_for_epoch(mechanism_id, epoch) {
            info!(
                "Weights already set for mechanism {} in epoch {}, skipping",
                mechanism_id, epoch
            );
            return Ok(None);
        }

        // Prepare weights with fallback to UID 0
        let (uids, weight_values) = self.prepare_weights_with_fallback(weights)?;

        if self.client.use_commit_reveal() {
            self.submit_mechanism_with_commit_reveal(mechanism_id, uids, weight_values, epoch)
                .await
        } else {
            self.submit_mechanism_direct(mechanism_id, uids, weight_values, epoch)
                .await
        }
    }

    /// Submit mechanism weights directly (no commit-reveal)
    async fn submit_mechanism_direct(
        &mut self,
        mechanism_id: u8,
        uids: Vec<u64>,
        weights: Vec<u16>,
        epoch: u64,
    ) -> Result<Option<String>> {
        // Convert u16 weights to f32 for set_mechanism_weights
        let weight_f32: Vec<f32> = weights.iter().map(|w| *w as f32 / 65535.0).collect();

        info!(
            "Submitting {} mechanism {} weights directly",
            uids.len(),
            mechanism_id
        );

        let tx_hash = set_mechanism_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            mechanism_id,
            &uids,
            &weight_f32,
            Some(self.client.version_key()),
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Mark as set for this epoch
        self.last_weight_epoch.insert(mechanism_id, epoch);

        info!("Mechanism {} weights submitted: {}", mechanism_id, tx_hash);
        Ok(Some(tx_hash))
    }

    /// Submit mechanism weights with commit-reveal pattern (v2 - subtensor compatible)
    async fn submit_mechanism_with_commit_reveal(
        &mut self,
        mechanism_id: u8,
        uids: Vec<u64>,
        weights: Vec<u16>,
        epoch: u64,
    ) -> Result<Option<String>> {
        // Check if we have a pending commit to reveal
        if let Some(pending) = self.pending_mechanism_commits.remove(&mechanism_id) {
            return self.reveal_mechanism_pending_v2(pending).await;
        }

        // Convert to u16 for subtensor
        let uids_u16: Vec<u16> = uids.iter().map(|u| *u as u16).collect();

        // Get account public key for hash
        let account = self.client.signer()?.account_id().0;
        let version_key = self.client.version_key();

        // Generate commit using v2 format (subtensor compatible)
        let commit_data = prepare_mechanism_commit_reveal(
            &account,
            self.client.netuid(),
            mechanism_id,
            &uids_u16,
            &weights,
            version_key,
            8, // salt length
        );

        info!(
            "Committing mechanism {} weights hash (v2): {}",
            mechanism_id, commit_data.commit_hash
        );

        let tx_hash = commit_mechanism_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            mechanism_id,
            &commit_data.commit_hash,
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Store pending commit for reveal
        self.pending_mechanism_commits.insert(
            mechanism_id,
            PendingMechanismCommitV2 {
                mechanism_id,
                hash: commit_data.commit_hash,
                uids: commit_data.uids,
                weights: commit_data.weights,
                salt: commit_data.salt,
                version_key: commit_data.version_key,
                epoch,
            },
        );

        info!("Mechanism {} weights committed: {}", mechanism_id, tx_hash);
        Ok(Some(tx_hash))
    }

    /// Reveal pending mechanism commit (v2 format)
    async fn reveal_mechanism_pending_v2(
        &mut self,
        pending: PendingMechanismCommitV2,
    ) -> Result<Option<String>> {
        info!(
            "Revealing mechanism {} weights for commit: {}",
            pending.mechanism_id, pending.hash
        );

        let tx_hash = reveal_mechanism_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            pending.mechanism_id,
            &pending.uids,
            &pending.weights,
            &pending.salt,
            pending.version_key,
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Mark as set for this epoch
        self.last_weight_epoch
            .insert(pending.mechanism_id, pending.epoch);

        info!(
            "Mechanism {} weights revealed: {}",
            pending.mechanism_id, tx_hash
        );
        Ok(Some(tx_hash))
    }

    /// Prepare weights with fallback to UID 0 if empty or sum < 1
    fn prepare_weights_with_fallback(
        &self,
        weights: &[WeightAssignment],
    ) -> Result<(Vec<u64>, Vec<u16>)> {
        let (mut uids, mut weight_values) = self.prepare_weights(weights)?;

        // If no weights, put everything on UID 0
        if uids.is_empty() {
            info!("No valid weights, defaulting to UID 0");
            return Ok((vec![0], vec![65535])); // 100% to UID 0
        }

        // Calculate sum and check if we need to fill
        let sum: u32 = weight_values.iter().map(|w| *w as u32).sum();
        let target_sum: u32 = 65535;

        if sum < target_sum {
            let remaining = (target_sum - sum) as u16;

            // Check if UID 0 is already in the list
            if let Some(pos) = uids.iter().position(|u| *u == 0) {
                // Add remaining to existing UID 0
                weight_values[pos] = weight_values[pos].saturating_add(remaining);
            } else {
                // Add UID 0 with remaining weight
                uids.push(0);
                weight_values.push(remaining);
                info!(
                    "Adding {} weight to UID 0 to fill to sum=1",
                    remaining as f64 / 65535.0
                );
            }
        }

        Ok((uids, weight_values))
    }

    /// Prepare weights for submission (convert hotkeys to UIDs)
    fn prepare_weights(&self, weights: &[WeightAssignment]) -> Result<(Vec<u64>, Vec<u16>)> {
        let hotkeys: Vec<String> = weights.iter().map(|w| w.agent_hash.clone()).collect();

        let uid_map = self.client.get_uids_for_hotkeys(&hotkeys);

        let mut uids = Vec::new();
        let mut weight_values = Vec::new();

        for weight in weights {
            if let Some((_, uid)) = uid_map.iter().find(|(h, _)| h == &weight.agent_hash) {
                uids.push(*uid as u64);
                let w_u16 = (weight.weight.clamp(0.0, 1.0) * 65535.0) as u16;
                weight_values.push(w_u16);
            } else {
                warn!("No UID found for hotkey: {}", weight.agent_hash);
            }
        }

        debug!(
            "Prepared {} weights from {} assignments",
            uids.len(),
            weights.len()
        );
        Ok((uids, weight_values))
    }

    /// Check if we have pending commits to reveal for any mechanism
    pub fn has_pending_commits(&self) -> bool {
        !self.pending_mechanism_commits.is_empty()
    }

    /// Get list of mechanisms with pending commits
    pub fn pending_mechanism_ids(&self) -> Vec<u8> {
        self.pending_mechanism_commits.keys().cloned().collect()
    }

    /// Force reveal all pending mechanism commits
    pub async fn reveal_all_pending(&mut self) -> Result<Vec<(u8, String)>> {
        let mut results = Vec::new();
        let pending_ids: Vec<u8> = self.pending_mechanism_commits.keys().cloned().collect();

        for mec_id in pending_ids {
            if let Some(pending) = self.pending_mechanism_commits.remove(&mec_id) {
                if let Some(tx) = self.reveal_mechanism_pending_v2(pending).await? {
                    results.push((mec_id, tx));
                }
            }
        }

        Ok(results)
    }

    /// Reset epoch tracking (call at epoch boundary)
    pub fn reset_epoch_tracking(&mut self) {
        self.last_weight_epoch.clear();
    }
}
