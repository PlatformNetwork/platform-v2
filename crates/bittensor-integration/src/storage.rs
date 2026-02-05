//! Direct Bittensor storage reads
//!
//! Provides direct access to on-chain storage for metagraph data,
//! stakes, and validator information without needing to submit transactions.

use crate::{BittensorClient, Metagraph};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Configuration for storage access
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Subtensor RPC endpoint
    pub endpoint: String,
    /// Network UID
    pub netuid: u16,
    /// Cache duration in seconds
    pub cache_duration_secs: u64,
    /// Maximum retries for RPC calls
    pub max_retries: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            endpoint: "wss://entrypoint-finney.opentensor.ai:443".to_string(),
            netuid: 100,
            cache_duration_secs: 60,
            max_retries: 3,
        }
    }
}

/// Validator info from storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub hotkey: String,
    pub coldkey: String,
    pub uid: u16,
    pub stake: u64,
    pub trust: f64,
    pub consensus: f64,
    pub incentive: f64,
    pub dividends: f64,
    pub emission: u64,
    pub is_active: bool,
    pub last_update: u64,
}

/// Stake info from storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakeInfo {
    pub hotkey: String,
    pub coldkey: String,
    pub stake_rao: u64,
    pub stake_tao: f64,
}

/// Weight entry from storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightEntry {
    pub uid: u16,
    pub weight: u16,
}

/// Metagraph snapshot from storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetagraphSnapshot {
    pub netuid: u16,
    pub block_number: u64,
    pub block_hash: String,
    pub n: u16,
    pub validators: Vec<ValidatorInfo>,
    pub stakes: HashMap<String, StakeInfo>,
    pub total_stake: u64,
    pub timestamp: i64,
}

/// Cached metagraph with timestamp
struct CachedMetagraph {
    snapshot: MetagraphSnapshot,
    cached_at: i64,
}

/// Direct storage reader for Bittensor
pub struct StorageReader {
    config: StorageConfig,
    client: Option<BittensorClient>,
    cached_metagraph: RwLock<Option<CachedMetagraph>>,
}

impl StorageReader {
    /// Create new storage reader
    pub fn new(config: StorageConfig) -> Self {
        Self {
            config,
            client: None,
            cached_metagraph: RwLock::new(None),
        }
    }

    /// Connect to Bittensor
    pub async fn connect(&mut self) -> Result<(), StorageError> {
        let client = BittensorClient::new(&self.config.endpoint)
            .await
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;
        self.client = Some(client);
        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    /// Get metagraph snapshot (with caching)
    pub async fn get_metagraph(&self) -> Result<MetagraphSnapshot, StorageError> {
        // Check cache first
        {
            let cache = self.cached_metagraph.read();
            if let Some(cached) = cache.as_ref() {
                let now = chrono::Utc::now().timestamp();
                if now - cached.cached_at < self.config.cache_duration_secs as i64 {
                    return Ok(cached.snapshot.clone());
                }
            }
        }

        // Fetch fresh data
        let snapshot = self.fetch_metagraph().await?;

        // Update cache
        {
            let mut cache = self.cached_metagraph.write();
            *cache = Some(CachedMetagraph {
                snapshot: snapshot.clone(),
                cached_at: chrono::Utc::now().timestamp(),
            });
        }

        Ok(snapshot)
    }

    /// Force refresh metagraph
    pub async fn refresh_metagraph(&self) -> Result<MetagraphSnapshot, StorageError> {
        let snapshot = self.fetch_metagraph().await?;

        let mut cache = self.cached_metagraph.write();
        *cache = Some(CachedMetagraph {
            snapshot: snapshot.clone(),
            cached_at: chrono::Utc::now().timestamp(),
        });

        Ok(snapshot)
    }

    /// Fetch metagraph from chain
    async fn fetch_metagraph(&self) -> Result<MetagraphSnapshot, StorageError> {
        let client = self.client.as_ref().ok_or(StorageError::NotConnected)?;

        // Use existing sync_metagraph function from bittensor-rs
        let metagraph = crate::sync_metagraph(client, self.config.netuid)
            .await
            .map_err(|e| StorageError::RpcError(e.to_string()))?;

        // Convert to snapshot
        self.metagraph_to_snapshot(metagraph)
    }

    /// Convert Metagraph to MetagraphSnapshot
    fn metagraph_to_snapshot(&self, mg: Metagraph) -> Result<MetagraphSnapshot, StorageError> {
        let mut validators = Vec::new();
        let mut stakes = HashMap::new();
        let mut total_stake = 0u64;

        for neuron in mg.neurons.values() {
            let hotkey_bytes: &[u8; 32] = neuron.hotkey.as_ref();
            let coldkey_bytes: &[u8; 32] = neuron.coldkey.as_ref();
            let hotkey_hex = hex::encode(hotkey_bytes);
            let coldkey_hex = hex::encode(coldkey_bytes);

            // Convert stake from u128 to u64, capping at u64::MAX
            let stake_u64 = neuron.stake.min(u64::MAX as u128) as u64;
            total_stake = total_stake.saturating_add(stake_u64);

            // Convert emission from f64 to u64
            let emission_u64 = neuron.emission as u64;

            let validator_info = ValidatorInfo {
                hotkey: hotkey_hex.clone(),
                coldkey: coldkey_hex.clone(),
                uid: neuron.uid as u16,
                stake: stake_u64,
                trust: neuron.trust / u16::MAX as f64,
                consensus: neuron.consensus / u16::MAX as f64,
                incentive: neuron.incentive / u16::MAX as f64,
                dividends: neuron.dividends / u16::MAX as f64,
                emission: emission_u64,
                is_active: neuron.active,
                last_update: neuron.last_update,
            };
            validators.push(validator_info);

            stakes.insert(
                hotkey_hex.clone(),
                StakeInfo {
                    hotkey: hotkey_hex,
                    coldkey: coldkey_hex,
                    stake_rao: stake_u64,
                    stake_tao: stake_u64 as f64 / 1_000_000_000.0,
                },
            );
        }

        // Convert n from u64 to u16, capping at u16::MAX
        let n = mg.n.min(u16::MAX as u64) as u16;

        Ok(MetagraphSnapshot {
            netuid: self.config.netuid,
            block_number: mg.block,
            block_hash: String::new(), // Block hash not available in Metagraph struct
            n,
            validators,
            stakes,
            total_stake,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    /// Get validator by hotkey
    pub async fn get_validator(&self, hotkey: &str) -> Result<Option<ValidatorInfo>, StorageError> {
        let snapshot = self.get_metagraph().await?;
        Ok(snapshot
            .validators
            .iter()
            .find(|v| v.hotkey == hotkey)
            .cloned())
    }

    /// Get stake for hotkey
    pub async fn get_stake(&self, hotkey: &str) -> Result<Option<StakeInfo>, StorageError> {
        let snapshot = self.get_metagraph().await?;
        Ok(snapshot.stakes.get(hotkey).cloned())
    }

    /// Get total network stake
    pub async fn get_total_stake(&self) -> Result<u64, StorageError> {
        let snapshot = self.get_metagraph().await?;
        Ok(snapshot.total_stake)
    }

    /// Get validator count
    pub async fn get_validator_count(&self) -> Result<u16, StorageError> {
        let snapshot = self.get_metagraph().await?;
        Ok(snapshot.n)
    }

    /// Get all validators above minimum stake
    pub async fn get_active_validators(
        &self,
        min_stake_rao: u64,
    ) -> Result<Vec<ValidatorInfo>, StorageError> {
        let snapshot = self.get_metagraph().await?;
        Ok(snapshot
            .validators
            .into_iter()
            .filter(|v| v.stake >= min_stake_rao && v.is_active)
            .collect())
    }

    /// Get current block number from chain
    pub async fn get_current_block(&self) -> Result<u64, StorageError> {
        let client = self.client.as_ref().ok_or(StorageError::NotConnected)?;

        let block = client
            .block_number()
            .await
            .map_err(|e| StorageError::RpcError(e.to_string()))?;

        Ok(block)
    }

    /// Invalidate cache
    pub fn invalidate_cache(&self) {
        let mut cache = self.cached_metagraph.write();
        *cache = None;
    }
}

/// Storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Not connected to Bittensor")]
    NotConnected,
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Storage key not found: {0}")]
    KeyNotFound(String),
    #[error("Decode error: {0}")]
    DecodeError(String),
    #[error("Cache expired")]
    CacheExpired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.netuid, 100);
        assert_eq!(config.cache_duration_secs, 60);
        assert_eq!(config.max_retries, 3);
        assert!(config.endpoint.contains("entrypoint-finney"));
    }

    #[test]
    fn test_storage_reader_not_connected() {
        let reader = StorageReader::new(StorageConfig::default());
        assert!(!reader.is_connected());
    }

    #[test]
    fn test_validator_info_serialization() {
        let info = ValidatorInfo {
            hotkey: "abc123".to_string(),
            coldkey: "def456".to_string(),
            uid: 1,
            stake: 1_000_000_000_000,
            trust: 0.9,
            consensus: 0.8,
            incentive: 0.7,
            dividends: 0.6,
            emission: 1000,
            is_active: true,
            last_update: 12345,
        };
        assert_eq!(info.uid, 1);
        assert!(info.is_active);
        assert_eq!(info.stake, 1_000_000_000_000);

        // Test serialization
        let serialized = serde_json::to_string(&info).expect("serialization should succeed");
        let deserialized: ValidatorInfo =
            serde_json::from_str(&serialized).expect("deserialization should succeed");
        assert_eq!(deserialized.uid, info.uid);
        assert_eq!(deserialized.hotkey, info.hotkey);
    }

    #[test]
    fn test_stake_info() {
        let stake = StakeInfo {
            hotkey: "abc".to_string(),
            coldkey: "def".to_string(),
            stake_rao: 1_000_000_000,
            stake_tao: 1.0,
        };
        assert_eq!(stake.stake_tao, 1.0);
        assert_eq!(stake.stake_rao, 1_000_000_000);
    }

    #[test]
    fn test_weight_entry() {
        let entry = WeightEntry {
            uid: 5,
            weight: 100,
        };
        assert_eq!(entry.uid, 5);
        assert_eq!(entry.weight, 100);
    }

    #[test]
    fn test_metagraph_snapshot() {
        let mut stakes = HashMap::new();
        stakes.insert(
            "abc".to_string(),
            StakeInfo {
                hotkey: "abc".to_string(),
                coldkey: "xyz".to_string(),
                stake_rao: 1_000_000_000,
                stake_tao: 1.0,
            },
        );

        let snapshot = MetagraphSnapshot {
            netuid: 100,
            block_number: 12345,
            block_hash: String::new(),
            n: 10,
            validators: vec![],
            stakes,
            total_stake: 1_000_000_000,
            timestamp: 0,
        };

        assert_eq!(snapshot.netuid, 100);
        assert_eq!(snapshot.n, 10);
        assert_eq!(snapshot.block_number, 12345);
    }

    #[test]
    fn test_storage_error_display() {
        let err = StorageError::NotConnected;
        assert_eq!(format!("{}", err), "Not connected to Bittensor");

        let err = StorageError::ConnectionError("timeout".to_string());
        assert_eq!(format!("{}", err), "Connection error: timeout");

        let err = StorageError::RpcError("failed".to_string());
        assert_eq!(format!("{}", err), "RPC error: failed");

        let err = StorageError::KeyNotFound("missing".to_string());
        assert_eq!(format!("{}", err), "Storage key not found: missing");
    }

    #[test]
    fn test_storage_config_custom() {
        let config = StorageConfig {
            endpoint: "wss://test.com".to_string(),
            netuid: 50,
            cache_duration_secs: 120,
            max_retries: 5,
        };
        assert_eq!(config.endpoint, "wss://test.com");
        assert_eq!(config.netuid, 50);
        assert_eq!(config.cache_duration_secs, 120);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_invalidate_cache() {
        let reader = StorageReader::new(StorageConfig::default());

        // Cache starts empty
        {
            let cache = reader.cached_metagraph.read();
            assert!(cache.is_none());
        }

        // Invalidate should work even when empty
        reader.invalidate_cache();

        {
            let cache = reader.cached_metagraph.read();
            assert!(cache.is_none());
        }
    }
}
