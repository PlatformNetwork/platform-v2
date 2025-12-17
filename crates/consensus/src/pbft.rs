//! PBFT Consensus Engine

use crate::{ConsensusConfig, ConsensusResult, ConsensusState};
use parking_lot::RwLock;
use platform_core::{
    ChainState, Hotkey, Keypair, MiniChainError, NetworkMessage, Proposal, ProposalAction, Result,
    SignedNetworkMessage, SudoAction, Vote,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// PBFT Consensus Engine
pub struct PBFTEngine {
    /// Local keypair
    keypair: Keypair,

    /// Consensus state
    state: ConsensusState,

    /// Chain state reference
    chain_state: Arc<RwLock<ChainState>>,

    /// Outgoing message sender
    message_tx: mpsc::Sender<SignedNetworkMessage>,
}

impl PBFTEngine {
    pub fn new(
        keypair: Keypair,
        chain_state: Arc<RwLock<ChainState>>,
        message_tx: mpsc::Sender<SignedNetworkMessage>,
    ) -> Self {
        let config = ConsensusConfig::default();
        Self {
            keypair,
            state: ConsensusState::new(config),
            chain_state,
            message_tx,
        }
    }

    /// Update validator count from chain state
    pub fn sync_validators(&self) {
        let count = self.chain_state.read().active_validators().len();
        self.state.set_validator_count(count);
    }

    /// Check if we are the sudo key
    pub fn is_sudo(&self) -> bool {
        self.chain_state.read().is_sudo(&self.keypair.hotkey())
    }

    /// Propose a sudo action (only subnet owner)
    pub async fn propose_sudo(&self, action: SudoAction) -> Result<uuid::Uuid> {
        if !self.is_sudo() {
            return Err(MiniChainError::Unauthorized("Not the subnet owner".into()));
        }

        let block_height = self.chain_state.read().block_height;
        let proposal = Proposal::new(
            ProposalAction::Sudo(action),
            self.keypair.hotkey(),
            block_height,
        );

        let proposal_id = self.state.start_round(proposal.clone());

        // Broadcast proposal
        let msg = NetworkMessage::Proposal(proposal);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        // Self-vote approve
        self.vote(proposal_id, true).await?;

        info!("Proposed sudo action: {:?}", proposal_id);
        Ok(proposal_id)
    }

    /// Propose a new block
    pub async fn propose_block(&self) -> Result<uuid::Uuid> {
        let state = self.chain_state.read();
        let block_height = state.block_height;
        let state_hash = state.state_hash;
        drop(state);

        let proposal = Proposal::new(
            ProposalAction::NewBlock { state_hash },
            self.keypair.hotkey(),
            block_height,
        );

        let proposal_id = self.state.start_round(proposal.clone());

        // Broadcast proposal
        let msg = NetworkMessage::Proposal(proposal);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        // Self-vote approve
        self.vote(proposal_id, true).await?;

        debug!("Proposed new block: {:?}", proposal_id);
        Ok(proposal_id)
    }

    /// Handle incoming proposal
    pub async fn handle_proposal(&self, proposal: Proposal, signer: &Hotkey) -> Result<()> {
        // Verify proposer
        if proposal.proposer != *signer {
            return Err(MiniChainError::InvalidSignature);
        }

        // For sudo actions, verify sender is the sudo key
        if let ProposalAction::Sudo(_) = &proposal.action {
            if !self.chain_state.read().is_sudo(signer) {
                warn!("Non-sudo tried to propose sudo action: {:?}", signer);
                return Err(MiniChainError::Unauthorized("Not sudo".into()));
            }
        }

        // Validate proposal
        if !self.validate_proposal(&proposal) {
            warn!("Invalid proposal: {:?}", proposal.id);
            self.vote(proposal.id, false).await?;
            return Ok(());
        }

        // Start round and vote approve
        self.state.start_round(proposal.clone());
        self.vote(proposal.id, true).await?;

        Ok(())
    }

    /// Vote on a proposal
    async fn vote(&self, proposal_id: uuid::Uuid, approve: bool) -> Result<()> {
        let vote = if approve {
            Vote::approve(proposal_id, self.keypair.hotkey())
        } else {
            Vote::reject(proposal_id, self.keypair.hotkey())
        };

        // Add local vote
        if let Some(result) = self.state.add_vote(vote.clone()) {
            self.handle_consensus_result(result).await?;
        }

        // Broadcast vote
        let msg = NetworkMessage::Vote(vote);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        Ok(())
    }

    /// Handle incoming vote
    pub async fn handle_vote(&self, vote: Vote, signer: &Hotkey) -> Result<()> {
        // Verify voter
        if vote.voter != *signer {
            return Err(MiniChainError::InvalidSignature);
        }

        // Verify voter is a validator
        if self.chain_state.read().get_validator(signer).is_none() {
            warn!("Non-validator tried to vote: {:?}", signer);
            return Ok(());
        }

        // Add vote
        if let Some(result) = self.state.add_vote(vote) {
            self.handle_consensus_result(result).await?;
        }

        Ok(())
    }

    /// Handle consensus result
    async fn handle_consensus_result(&self, result: ConsensusResult) -> Result<()> {
        match result {
            ConsensusResult::Approved(proposal) => {
                info!("Consensus reached for proposal: {:?}", proposal.id);
                self.apply_proposal(proposal).await?;
            }
            ConsensusResult::Rejected {
                proposal_id,
                reason,
            } => {
                warn!("Proposal rejected: {:?} - {}", proposal_id, reason);
            }
            ConsensusResult::Pending => {}
        }
        Ok(())
    }

    /// Apply an approved proposal
    async fn apply_proposal(&self, proposal: Proposal) -> Result<()> {
        let mut state = self.chain_state.write();

        match proposal.action {
            ProposalAction::Sudo(action) => {
                self.apply_sudo_action(&mut state, action)?;
            }
            ProposalAction::NewBlock { state_hash } => {
                if state.state_hash == state_hash {
                    state.increment_block();
                    info!("New block: {}", state.block_height);
                }
            }
            ProposalAction::JobCompletion {
                job_id,
                result,
                validator,
            } => {
                info!(
                    "Job {} completed by {:?} with score {:?}",
                    job_id, validator, result
                );
            }
        }

        Ok(())
    }

    /// Apply a sudo action
    fn apply_sudo_action(&self, state: &mut ChainState, action: SudoAction) -> Result<()> {
        match action {
            SudoAction::UpdateConfig { config } => {
                state.config = config;
                info!("Config updated");
            }
            SudoAction::AddChallenge { config } => {
                // Store challenge config in state
                state
                    .challenge_configs
                    .insert(config.challenge_id, config.clone());
                info!(
                    "Challenge added: {} ({:?})",
                    config.name, config.challenge_id
                );
            }
            SudoAction::UpdateChallenge { config } => {
                state
                    .challenge_configs
                    .insert(config.challenge_id, config.clone());
                info!(
                    "Challenge updated: {} ({:?})",
                    config.name, config.challenge_id
                );
            }
            SudoAction::RemoveChallenge { id } => {
                state.challenge_configs.remove(&id);
                state.remove_challenge(&id);
                info!("Challenge removed: {:?}", id);
            }
            SudoAction::SetRequiredVersion {
                min_version,
                recommended_version,
                docker_image,
                mandatory,
                deadline_block,
                release_notes,
            } => {
                state.required_version = Some(platform_core::RequiredVersion {
                    min_version: min_version.clone(),
                    recommended_version: recommended_version.clone(),
                    docker_image: docker_image.clone(),
                    mandatory: mandatory.clone(),
                    deadline_block: deadline_block.clone(),
                });
                info!(
                    "Required version set: {} (mandatory: {})",
                    min_version, mandatory
                );
            }
            SudoAction::AddValidator { info } => {
                state.add_validator(info)?;
                info!("Validator added");
            }
            SudoAction::RemoveValidator { hotkey } => {
                state.remove_validator(&hotkey);
                info!("Validator removed: {:?}", hotkey);
            }
            SudoAction::EmergencyPause { reason } => {
                warn!("EMERGENCY PAUSE: {}", reason);
            }
            SudoAction::Resume => {
                info!("Network resumed");
            }
            SudoAction::ForceStateUpdate { state: new_state } => {
                *state = new_state;
                warn!("Force state update applied");
            }
            SudoAction::SetChallengeWeight {
                challenge_id,
                mechanism_id,
                weight_ratio,
            } => {
                let allocation = platform_core::ChallengeWeightAllocation::new(
                    challenge_id,
                    mechanism_id,
                    weight_ratio,
                );
                state.challenge_weights.insert(challenge_id, allocation);
                info!(
                    "Challenge weight set: {:?} on mechanism {} = {:.2}%",
                    challenge_id,
                    mechanism_id,
                    weight_ratio * 100.0
                );
            }
            SudoAction::SetMechanismBurnRate {
                mechanism_id,
                burn_rate,
            } => {
                let config = state
                    .mechanism_configs
                    .entry(mechanism_id)
                    .or_insert_with(|| platform_core::MechanismWeightConfig::new(mechanism_id));
                config.base_burn_rate = burn_rate.clamp(0.0, 1.0);
                info!(
                    "Mechanism {} burn rate set to {:.2}%",
                    mechanism_id,
                    burn_rate * 100.0
                );
            }
            SudoAction::SetMechanismConfig {
                mechanism_id,
                config,
            } => {
                state.mechanism_configs.insert(mechanism_id, config.clone());
                info!(
                    "Mechanism {} config updated: burn={:.2}%, cap={:.2}%",
                    mechanism_id,
                    config.base_burn_rate * 100.0,
                    config.max_weight_cap * 100.0
                );
            }
        }

        state.update_hash();
        Ok(())
    }

    /// Validate a proposal
    fn validate_proposal(&self, proposal: &Proposal) -> bool {
        let state = self.chain_state.read();

        // Check block height is current or next
        if proposal.block_height > state.block_height + 1 {
            return false;
        }

        // Proposal-specific validation
        match &proposal.action {
            ProposalAction::Sudo(action) => {
                // Sudo must come from sudo key
                if !state.is_sudo(&proposal.proposer) {
                    return false;
                }
                self.validate_sudo_action(&state, action)
            }
            ProposalAction::NewBlock { .. } => true,
            ProposalAction::JobCompletion { .. } => true,
        }
    }

    /// Validate a sudo action
    fn validate_sudo_action(&self, _state: &ChainState, action: &SudoAction) -> bool {
        match action {
            SudoAction::AddChallenge { config } => {
                // Full validation including Docker image whitelist
                match config.validate() {
                    Ok(()) => {
                        info!(
                            "Challenge config validated: {} ({})",
                            config.name, config.docker_image
                        );
                        true
                    }
                    Err(reason) => {
                        warn!("Challenge config rejected: {}", reason);
                        false
                    }
                }
            }
            SudoAction::UpdateChallenge { config } => {
                // Validate updated config including Docker image whitelist
                match config.validate() {
                    Ok(()) => {
                        info!(
                            "Challenge update validated: {} ({})",
                            config.name, config.docker_image
                        );
                        true
                    }
                    Err(reason) => {
                        warn!("Challenge update rejected: {}", reason);
                        false
                    }
                }
            }
            _ => true,
        }
    }

    /// Check for timeouts and handle them
    pub async fn check_timeouts(&self) -> Result<()> {
        let results = self.state.check_timeouts();
        for result in results {
            self.handle_consensus_result(result).await?;
        }
        Ok(())
    }

    /// Get consensus state for monitoring
    pub fn status(&self) -> ConsensusStatus {
        ConsensusStatus {
            active_rounds: self.state.active_rounds().len(),
            validator_count: self.chain_state.read().validators.len(),
            threshold: self.state.threshold(),
        }
    }
}

/// Consensus status for monitoring
#[derive(Debug, Clone)]
pub struct ConsensusStatus {
    pub active_rounds: usize,
    pub validator_count: usize,
    pub threshold: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{NetworkConfig, Stake, ValidatorInfo};
    use tokio::sync::mpsc;

    fn create_test_engine() -> (PBFTEngine, mpsc::Receiver<SignedNetworkMessage>) {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            NetworkConfig::default(),
        )));
        let (tx, rx) = mpsc::channel(100);

        let engine = PBFTEngine::new(keypair, state, tx);
        (engine, rx)
    }

    #[tokio::test]
    async fn test_sudo_proposal() {
        let (engine, mut rx) = create_test_engine();

        // Add some validators
        {
            let mut state = engine.chain_state.write();
            for _ in 0..4 {
                let kp = Keypair::generate();
                let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
                state.add_validator(info).unwrap();
            }
        }
        engine.sync_validators();

        // Propose sudo action
        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let result = engine.propose_sudo(action).await;
        assert!(result.is_ok());

        // Should have broadcast proposal and vote
        let msg1 = rx.recv().await.unwrap();
        let msg2 = rx.recv().await.unwrap();

        assert!(matches!(msg1.message, NetworkMessage::Proposal(_)));
        assert!(matches!(msg2.message, NetworkMessage::Vote(_)));
    }
}
