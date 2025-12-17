//! Bittensor client wrapper

use crate::BittensorConfig;
use anyhow::Result;
use bittensor_rs::chain::{signer_from_seed, BittensorClient, BittensorSigner};
use bittensor_rs::metagraph::{sync_metagraph, Metagraph};
use tracing::info;

/// Wrapper around bittensor-rs client for Mini-Chain
pub struct SubtensorClient {
    config: BittensorConfig,
    client: Option<BittensorClient>,
    signer: Option<BittensorSigner>,
    metagraph: Option<Metagraph>,
}

impl SubtensorClient {
    /// Create a new client (not connected yet)
    pub fn new(config: BittensorConfig) -> Self {
        Self {
            config,
            client: None,
            signer: None,
            metagraph: None,
        }
    }

    /// Connect to Subtensor
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to Subtensor: {}", self.config.endpoint);

        let client = BittensorClient::new(&self.config.endpoint).await?;
        self.client = Some(client);

        info!("Connected to Subtensor");
        Ok(())
    }

    /// Set the signer from a seed phrase or key
    pub fn set_signer(&mut self, seed: &str) -> Result<()> {
        let signer = signer_from_seed(seed)?;
        self.signer = Some(signer);
        Ok(())
    }

    /// Get the inner client
    pub fn client(&self) -> Result<&BittensorClient> {
        self.client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to Subtensor"))
    }

    /// Get the signer (returns Result)
    pub fn signer(&self) -> Result<&BittensorSigner> {
        self.signer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signer not set"))
    }

    /// Get the signer (returns Option)
    pub fn get_signer(&self) -> Option<&BittensorSigner> {
        self.signer.as_ref()
    }

    /// Get the netuid
    pub fn netuid(&self) -> u16 {
        self.config.netuid
    }

    /// Get the version key
    pub fn version_key(&self) -> u64 {
        self.config.version_key
    }

    /// Check if commit-reveal is enabled
    pub fn use_commit_reveal(&self) -> bool {
        self.config.use_commit_reveal
    }

    /// Sync and get the current metagraph
    pub async fn sync_metagraph(&mut self) -> Result<&Metagraph> {
        let client = self.client()?;
        let metagraph = sync_metagraph(client, self.config.netuid).await?;
        self.metagraph = Some(metagraph);
        Ok(self.metagraph.as_ref().unwrap())
    }

    /// Get cached metagraph (sync first if needed)
    pub fn metagraph(&self) -> Option<&Metagraph> {
        self.metagraph.as_ref()
    }

    /// Get UID for a hotkey from cached metagraph
    pub fn get_uid_for_hotkey(&self, hotkey: &str) -> Option<u16> {
        let metagraph = self.metagraph.as_ref()?;

        // Parse hotkey to AccountId32
        use sp_core::crypto::Ss58Codec;
        let account = sp_core::crypto::AccountId32::from_ss58check(hotkey).ok()?;
        let account_bytes: &[u8; 32] = account.as_ref();

        // Find neuron with matching hotkey
        for (uid, neuron) in &metagraph.neurons {
            let neuron_hotkey: &[u8; 32] = neuron.hotkey.as_ref();
            if neuron_hotkey == account_bytes {
                return Some(*uid as u16);
            }
        }
        None
    }

    /// Get UIDs for a list of hotkeys
    pub fn get_uids_for_hotkeys(&self, hotkeys: &[String]) -> Vec<(String, u16)> {
        let mut results = Vec::new();
        for hotkey in hotkeys {
            if let Some(uid) = self.get_uid_for_hotkey(hotkey) {
                results.push((hotkey.clone(), uid));
            }
        }
        results
    }

    /// Get the number of mechanisms for the subnet
    /// Returns count of mechanisms (0 to count-1 are valid IDs)
    pub async fn get_mechanism_count(&self) -> Result<u8> {
        use bittensor_rs::get_mechanism_count;
        let client = self.client()?;
        get_mechanism_count(client, self.config.netuid).await
    }

    /// Get current epoch from Bittensor
    pub async fn get_current_epoch(&self) -> Result<u64> {
        use bittensor_rs::blocks::{BlockListener, BlockListenerConfig};

        let client = self.client()?;
        let config = BlockListenerConfig {
            netuid: self.config.netuid,
            ..Default::default()
        };
        let listener = BlockListener::new(config);
        let epoch_info = listener.current_epoch_info(client).await?;
        Ok(epoch_info.epoch_number)
    }

    /// Get current epoch info including phase from Bittensor
    pub async fn get_current_epoch_info(&self) -> Result<bittensor_rs::blocks::EpochInfo> {
        use bittensor_rs::blocks::{BlockListener, BlockListenerConfig};

        let client = self.client()?;
        let config = BlockListenerConfig {
            netuid: self.config.netuid,
            ..Default::default()
        };
        let listener = BlockListener::new(config);
        listener.current_epoch_info(client).await
    }

    /// Check if currently in reveal phase
    pub async fn is_in_reveal_phase(&self) -> Result<bool> {
        use bittensor_rs::blocks::EpochPhase;
        let info = self.get_current_epoch_info().await?;
        Ok(matches!(info.phase, EpochPhase::RevealWindow))
    }
}
