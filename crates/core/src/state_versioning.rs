//! State versioning and migration system
//!
//! This module provides backward-compatible state serialization with automatic
//! migration support. When ChainState structure changes between versions,
//! old data can still be loaded and migrated to the current format.
//!
//! # Usage
//!
//! Instead of directly serializing/deserializing ChainState, use:
//! - `VersionedState::from_state()` to wrap a ChainState for serialization
//! - `VersionedState::into_state()` to get the migrated ChainState
//!
//! # Adding a new version
//!
//! 1. Increment `CURRENT_STATE_VERSION`
//! 2. Keep the old `ChainStateVX` struct as-is (rename current to VX)
//! 3. Create new `ChainState` with your changes
//! 4. Implement migration in `migrate_state()`
//! 5. Add `#[serde(default)]` to any new fields

use crate::{
    BlockHeight, Challenge, ChallengeContainerConfig, ChallengeId, ChallengeWeightAllocation,
    Hotkey, Job, MechanismWeightConfig, NetworkConfig, Result, Stake, ValidatorInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

/// Current state version - increment when ChainState structure changes
pub const CURRENT_STATE_VERSION: u32 = 2;

/// Minimum supported version for migration
pub const MIN_SUPPORTED_VERSION: u32 = 1;

/// Versioned state wrapper for serialization
///
/// This wrapper allows us to detect the version of serialized state and
/// migrate it to the current format automatically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionedState {
    /// State format version
    pub version: u32,
    /// Serialized state data (version-specific format)
    pub data: Vec<u8>,
}

impl VersionedState {
    /// Create a versioned state from current ChainState
    pub fn from_state(state: &crate::ChainState) -> Result<Self> {
        let data = bincode::serialize(state)
            .map_err(|e| crate::MiniChainError::Serialization(e.to_string()))?;
        Ok(Self {
            version: CURRENT_STATE_VERSION,
            data,
        })
    }

    /// Deserialize and migrate to current ChainState
    pub fn into_state(self) -> Result<crate::ChainState> {
        if self.version == CURRENT_STATE_VERSION {
            // Current version - deserialize directly
            bincode::deserialize(&self.data)
                .map_err(|e| crate::MiniChainError::Serialization(e.to_string()))
        } else if self.version >= MIN_SUPPORTED_VERSION {
            // Old version - migrate
            info!(
                "Migrating state from version {} to {}",
                self.version, CURRENT_STATE_VERSION
            );
            migrate_state(self.version, &self.data)
        } else {
            Err(crate::MiniChainError::Serialization(format!(
                "State version {} is too old (minimum supported: {})",
                self.version, MIN_SUPPORTED_VERSION
            )))
        }
    }
}

// ============================================================================
// Version 1 State (original format, before registered_hotkeys)
// ============================================================================

/// ChainState V1 - original format without registered_hotkeys
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainStateV1 {
    pub block_height: BlockHeight,
    pub epoch: u64,
    pub config: NetworkConfig,
    pub sudo_key: Hotkey,
    pub validators: HashMap<Hotkey, ValidatorInfo>,
    pub challenges: HashMap<ChallengeId, Challenge>,
    pub challenge_configs: HashMap<ChallengeId, ChallengeContainerConfig>,
    pub mechanism_configs: HashMap<u8, MechanismWeightConfig>,
    pub challenge_weights: HashMap<ChallengeId, ChallengeWeightAllocation>,
    pub required_version: Option<crate::RequiredVersion>,
    pub pending_jobs: Vec<Job>,
    pub state_hash: [u8; 32],
    pub last_updated: chrono::DateTime<chrono::Utc>,
    // V1 did NOT have registered_hotkeys
}

impl ChainStateV1 {
    /// Migrate V1 to current ChainState
    pub fn migrate(self) -> crate::ChainState {
        crate::ChainState {
            block_height: self.block_height,
            epoch: self.epoch,
            config: self.config,
            sudo_key: self.sudo_key,
            validators: self.validators,
            challenges: self.challenges,
            challenge_configs: self.challenge_configs,
            mechanism_configs: self.mechanism_configs,
            challenge_weights: self.challenge_weights,
            required_version: self.required_version,
            pending_jobs: self.pending_jobs,
            state_hash: self.state_hash,
            last_updated: self.last_updated,
            // New field in V2 - initialize empty, will be populated from metagraph
            registered_hotkeys: HashSet::new(),
        }
    }
}

// ============================================================================
// Migration Logic
// ============================================================================

/// Migrate state from an old version to current
fn migrate_state(version: u32, data: &[u8]) -> Result<crate::ChainState> {
    match version {
        1 => {
            // V1 -> V2: Add registered_hotkeys field
            let v1: ChainStateV1 = bincode::deserialize(data)
                .map_err(|e| crate::MiniChainError::Serialization(format!("V1 migration failed: {}", e)))?;
            info!(
                "Migrated state V1->V2: block_height={}, validators={}",
                v1.block_height,
                v1.validators.len()
            );
            Ok(v1.migrate())
        }
        _ => Err(crate::MiniChainError::Serialization(format!(
            "Unknown state version: {}",
            version
        ))),
    }
}

// ============================================================================
// Smart Deserialization (tries versioned first, then raw, then legacy)
// ============================================================================

/// Deserialize state with automatic version detection and migration
///
/// This function tries multiple strategies to load state:
/// 1. Try as VersionedState (new format with version header)
/// 2. Try as current ChainState directly (for states saved without version)
/// 3. Try as ChainStateV1 (legacy format)
/// 4. Return error if all fail
pub fn deserialize_state_smart(data: &[u8]) -> Result<crate::ChainState> {
    // Strategy 1: Try as VersionedState (preferred format)
    if let Ok(versioned) = bincode::deserialize::<VersionedState>(data) {
        return versioned.into_state();
    }

    // Strategy 2: Try as current ChainState (unversioned but current format)
    if let Ok(state) = bincode::deserialize::<crate::ChainState>(data) {
        info!("Loaded unversioned state (current format)");
        return Ok(state);
    }

    // Strategy 3: Try as V1 (legacy format without registered_hotkeys)
    if let Ok(v1) = bincode::deserialize::<ChainStateV1>(data) {
        warn!("Loaded legacy V1 state, migrating...");
        return Ok(v1.migrate());
    }

    // All strategies failed
    Err(crate::MiniChainError::Serialization(
        "Failed to deserialize state: incompatible format".to_string(),
    ))
}

/// Serialize state with version header
pub fn serialize_state_versioned(state: &crate::ChainState) -> Result<Vec<u8>> {
    let versioned = VersionedState::from_state(state)?;
    bincode::serialize(&versioned)
        .map_err(|e| crate::MiniChainError::Serialization(e.to_string()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, NetworkConfig};

    fn create_test_state() -> crate::ChainState {
        let sudo = Keypair::generate();
        crate::ChainState::new(sudo.hotkey(), NetworkConfig::default())
    }

    #[test]
    fn test_versioned_roundtrip() {
        let original = create_test_state();
        
        // Serialize with version
        let data = serialize_state_versioned(&original).unwrap();
        
        // Deserialize
        let loaded = deserialize_state_smart(&data).unwrap();
        
        assert_eq!(original.block_height, loaded.block_height);
        assert_eq!(original.epoch, loaded.epoch);
    }

    #[test]
    fn test_v1_migration() {
        // Create a V1 state
        let sudo = Keypair::generate();
        let v1 = ChainStateV1 {
            block_height: 100,
            epoch: 5,
            config: NetworkConfig::default(),
            sudo_key: sudo.hotkey(),
            validators: HashMap::new(),
            challenges: HashMap::new(),
            challenge_configs: HashMap::new(),
            mechanism_configs: HashMap::new(),
            challenge_weights: HashMap::new(),
            required_version: None,
            pending_jobs: Vec::new(),
            state_hash: [0u8; 32],
            last_updated: chrono::Utc::now(),
        };

        // Serialize as V1
        let v1_data = bincode::serialize(&v1).unwrap();

        // Wrap in VersionedState with version 1
        let versioned = VersionedState {
            version: 1,
            data: v1_data,
        };
        let versioned_bytes = bincode::serialize(&versioned).unwrap();

        // Load and migrate
        let migrated = deserialize_state_smart(&versioned_bytes).unwrap();
        
        assert_eq!(migrated.block_height, 100);
        assert_eq!(migrated.epoch, 5);
        assert!(migrated.registered_hotkeys.is_empty()); // New field initialized
    }

    #[test]
    fn test_legacy_v1_direct() {
        // Test loading raw V1 data (no version wrapper)
        let sudo = Keypair::generate();
        let v1 = ChainStateV1 {
            block_height: 50,
            epoch: 2,
            config: NetworkConfig::default(),
            sudo_key: sudo.hotkey(),
            validators: HashMap::new(),
            challenges: HashMap::new(),
            challenge_configs: HashMap::new(),
            mechanism_configs: HashMap::new(),
            challenge_weights: HashMap::new(),
            required_version: None,
            pending_jobs: Vec::new(),
            state_hash: [0u8; 32],
            last_updated: chrono::Utc::now(),
        };

        // Serialize raw V1 (no version wrapper)
        let raw_v1 = bincode::serialize(&v1).unwrap();

        // Smart deserialize should detect and migrate
        let migrated = deserialize_state_smart(&raw_v1).unwrap();
        
        assert_eq!(migrated.block_height, 50);
    }

    #[test]
    fn test_version_constants() {
        assert!(CURRENT_STATE_VERSION >= MIN_SUPPORTED_VERSION);
        assert_eq!(CURRENT_STATE_VERSION, 2);
    }
}
