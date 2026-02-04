//! Challenge registry for managing loaded challenge modules
//!
//! The registry maintains the state of all loaded challenges, their versions,
//! and provides thread-safe access to challenge modules.

use crate::error::{LoaderError, LoaderResult};
use crate::versioning::ChallengeVersion;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use platform_core::{ChallengeConfig, ChallengeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Trait defining the interface for a challenge module
///
/// This trait is implemented by WASM challenge modules and provides
/// the core evaluation capabilities.
pub trait ChallengeModule: Send + Sync {
    /// Evaluate an agent submission and return a score
    fn evaluate(&self, agent_data: &[u8]) -> LoaderResult<f64>;

    /// Validate an agent submission
    fn validate(&self, agent_data: &[u8]) -> LoaderResult<bool>;

    /// Get the challenge name
    fn name(&self) -> &str;

    /// Get the challenge version
    fn version(&self) -> u32;

    /// Get challenge metadata as JSON
    fn metadata(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}

/// A loaded challenge instance with its module and metadata
#[derive(Clone)]
pub struct LoadedChallenge {
    /// Unique challenge identifier
    pub id: ChallengeId,
    /// Human-readable challenge name
    pub name: String,
    /// Current version number
    pub version: u32,
    /// SHA-256 hash of the WASM bytecode
    pub code_hash: String,
    /// The loaded challenge module instance
    pub module: Arc<dyn ChallengeModule>,
    /// Challenge configuration
    pub config: ChallengeConfig,
    /// Timestamp when this challenge was loaded
    pub loaded_at: DateTime<Utc>,
    /// Whether this challenge is currently active
    pub is_active: bool,
}

impl std::fmt::Debug for LoadedChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedChallenge")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("version", &self.version)
            .field("code_hash", &self.code_hash)
            .field("loaded_at", &self.loaded_at)
            .field("is_active", &self.is_active)
            .finish_non_exhaustive()
    }
}

/// Summary information about a loaded challenge (without the module)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeInfo {
    /// Unique challenge identifier
    pub id: ChallengeId,
    /// Human-readable challenge name
    pub name: String,
    /// Current version number
    pub version: u32,
    /// SHA-256 hash of the WASM bytecode
    pub code_hash: String,
    /// Challenge configuration
    pub config: ChallengeConfig,
    /// Timestamp when this challenge was loaded
    pub loaded_at: DateTime<Utc>,
    /// Whether this challenge is currently active
    pub is_active: bool,
}

impl From<&LoadedChallenge> for ChallengeInfo {
    fn from(challenge: &LoadedChallenge) -> Self {
        Self {
            id: challenge.id,
            name: challenge.name.clone(),
            version: challenge.version,
            code_hash: challenge.code_hash.clone(),
            config: challenge.config.clone(),
            loaded_at: challenge.loaded_at,
            is_active: challenge.is_active,
        }
    }
}

/// Registry managing all loaded challenge modules
///
/// The registry provides thread-safe access to loaded challenges and
/// maintains version history for hot-reload and rollback operations.
pub struct ChallengeRegistry {
    /// Loaded challenges indexed by ID
    challenges: RwLock<HashMap<ChallengeId, LoadedChallenge>>,
    /// Version history for each challenge
    versions: RwLock<HashMap<ChallengeId, Vec<ChallengeVersion>>>,
    /// Active version number for each challenge
    active_versions: RwLock<HashMap<ChallengeId, u32>>,
    /// Maximum number of challenges allowed
    max_challenges: usize,
}

impl ChallengeRegistry {
    /// Create a new challenge registry with default capacity
    pub fn new() -> Self {
        Self::with_capacity(1000)
    }

    /// Create a new challenge registry with specified maximum capacity
    pub fn with_capacity(max_challenges: usize) -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
            versions: RwLock::new(HashMap::new()),
            active_versions: RwLock::new(HashMap::new()),
            max_challenges,
        }
    }

    /// Register a new challenge
    ///
    /// Returns error if a challenge with the same ID is already registered.
    pub fn register(
        &self,
        id: ChallengeId,
        name: String,
        version: u32,
        code_hash: String,
        module: Arc<dyn ChallengeModule>,
        config: ChallengeConfig,
    ) -> LoaderResult<()> {
        let mut challenges = self.challenges.write();

        // Check capacity
        if challenges.len() >= self.max_challenges && !challenges.contains_key(&id) {
            return Err(LoaderError::RegistryFull {
                max: self.max_challenges,
            });
        }

        // Check for duplicate
        if challenges.contains_key(&id) {
            return Err(LoaderError::AlreadyLoaded(format!(
                "Challenge {} already registered",
                id
            )));
        }

        let loaded = LoadedChallenge {
            id,
            name: name.clone(),
            version,
            code_hash: code_hash.clone(),
            module,
            config,
            loaded_at: Utc::now(),
            is_active: true,
        };

        challenges.insert(id, loaded);

        // Set as active version
        self.active_versions.write().insert(id, version);

        info!(
            challenge_id = %id,
            name = %name,
            version = version,
            code_hash = %code_hash,
            "Challenge registered in registry"
        );

        Ok(())
    }

    /// Unregister a challenge, removing it from the registry
    ///
    /// Also removes version history.
    pub fn unregister(&self, id: &ChallengeId) -> LoaderResult<LoadedChallenge> {
        let mut challenges = self.challenges.write();
        let challenge = challenges
            .remove(id)
            .ok_or_else(|| LoaderError::ChallengeNotFound(format!("Challenge {} not found", id)))?;

        self.versions.write().remove(id);
        self.active_versions.write().remove(id);

        info!(
            challenge_id = %id,
            name = %challenge.name,
            "Challenge unregistered from registry"
        );

        Ok(challenge)
    }

    /// Get a loaded challenge by ID
    pub fn get(&self, id: &ChallengeId) -> Option<LoadedChallenge> {
        self.challenges.read().get(id).cloned()
    }

    /// Get a challenge module for evaluation
    pub fn get_module(&self, id: &ChallengeId) -> Option<Arc<dyn ChallengeModule>> {
        self.challenges.read().get(id).map(|c| c.module.clone())
    }

    /// Check if a challenge is registered
    pub fn contains(&self, id: &ChallengeId) -> bool {
        self.challenges.read().contains_key(id)
    }

    /// List all loaded challenges
    pub fn list(&self) -> Vec<ChallengeInfo> {
        self.challenges
            .read()
            .values()
            .map(ChallengeInfo::from)
            .collect()
    }

    /// List active challenges only
    pub fn list_active(&self) -> Vec<ChallengeInfo> {
        self.challenges
            .read()
            .values()
            .filter(|c| c.is_active)
            .map(ChallengeInfo::from)
            .collect()
    }

    /// Get the number of loaded challenges
    pub fn count(&self) -> usize {
        self.challenges.read().len()
    }

    /// Update a challenge with a new version
    ///
    /// Preserves version history for potential rollback.
    pub fn update(
        &self,
        id: &ChallengeId,
        version: u32,
        code_hash: String,
        module: Arc<dyn ChallengeModule>,
        wasm_bytes: Vec<u8>,
    ) -> LoaderResult<u32> {
        let mut challenges = self.challenges.write();
        let challenge = challenges
            .get_mut(id)
            .ok_or_else(|| LoaderError::ChallengeNotFound(format!("Challenge {} not found", id)))?;

        let old_version = challenge.version;

        // Store old version in history
        {
            let mut versions = self.versions.write();
            let version_list = versions.entry(*id).or_insert_with(Vec::new);

            // Create version record from current state
            let version_record = ChallengeVersion {
                version: old_version,
                code_hash: challenge.code_hash.clone(),
                wasm_bytes,
                created_at: challenge.loaded_at,
                is_active: false,
            };
            version_list.push(version_record);
        }

        // Update to new version
        challenge.version = version;
        challenge.code_hash = code_hash.clone();
        challenge.module = module;
        challenge.loaded_at = Utc::now();

        // Update active version
        self.active_versions.write().insert(*id, version);

        info!(
            challenge_id = %id,
            old_version = old_version,
            new_version = version,
            code_hash = %code_hash,
            "Challenge updated to new version"
        );

        Ok(old_version)
    }

    /// Set whether a challenge is active
    pub fn set_active(&self, id: &ChallengeId, is_active: bool) -> LoaderResult<()> {
        let mut challenges = self.challenges.write();
        let challenge = challenges
            .get_mut(id)
            .ok_or_else(|| LoaderError::ChallengeNotFound(format!("Challenge {} not found", id)))?;

        challenge.is_active = is_active;

        debug!(
            challenge_id = %id,
            is_active = is_active,
            "Challenge active status changed"
        );

        Ok(())
    }

    /// Get version history for a challenge
    pub fn get_version_history(&self, id: &ChallengeId) -> Vec<ChallengeVersion> {
        self.versions.read().get(id).cloned().unwrap_or_default()
    }

    /// Get the active version for a challenge
    pub fn get_active_version(&self, id: &ChallengeId) -> Option<u32> {
        self.active_versions.read().get(id).copied()
    }

    /// Get all challenge IDs
    pub fn challenge_ids(&self) -> Vec<ChallengeId> {
        self.challenges.read().keys().copied().collect()
    }

    /// Clear all challenges from the registry
    pub fn clear(&self) {
        self.challenges.write().clear();
        self.versions.write().clear();
        self.active_versions.write().clear();

        warn!("Challenge registry cleared");
    }

    /// Get maximum allowed challenges
    pub fn max_challenges(&self) -> usize {
        self.max_challenges
    }

    /// Check remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        let current = self.challenges.read().len();
        self.max_challenges.saturating_sub(current)
    }
}

impl Default for ChallengeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock challenge module for testing
    struct MockModule {
        name: String,
        version: u32,
    }

    impl ChallengeModule for MockModule {
        fn evaluate(&self, _agent_data: &[u8]) -> LoaderResult<f64> {
            Ok(0.85)
        }

        fn validate(&self, _agent_data: &[u8]) -> LoaderResult<bool> {
            Ok(true)
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn version(&self) -> u32 {
            self.version
        }
    }

    fn mock_module(name: &str, version: u32) -> Arc<dyn ChallengeModule> {
        Arc::new(MockModule {
            name: name.to_string(),
            version,
        })
    }

    #[test]
    fn test_register_and_get_challenge() {
        let registry = ChallengeRegistry::new();
        let id = ChallengeId::new();

        registry
            .register(
                id,
                "test-challenge".to_string(),
                1,
                "abc123".to_string(),
                mock_module("test", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        let challenge = registry.get(&id).expect("get challenge");
        assert_eq!(challenge.name, "test-challenge");
        assert_eq!(challenge.version, 1);
        assert_eq!(challenge.code_hash, "abc123");
        assert!(challenge.is_active);
    }

    #[test]
    fn test_register_duplicate_fails() {
        let registry = ChallengeRegistry::new();
        let id = ChallengeId::new();

        registry
            .register(
                id,
                "test".to_string(),
                1,
                "hash1".to_string(),
                mock_module("test", 1),
                ChallengeConfig::default(),
            )
            .expect("first register");

        let result = registry.register(
            id,
            "test".to_string(),
            2,
            "hash2".to_string(),
            mock_module("test", 2),
            ChallengeConfig::default(),
        );

        assert!(matches!(result, Err(LoaderError::AlreadyLoaded(_))));
    }

    #[test]
    fn test_registry_full() {
        let registry = ChallengeRegistry::with_capacity(2);

        for i in 0..2 {
            registry
                .register(
                    ChallengeId::new(),
                    format!("challenge-{}", i),
                    1,
                    format!("hash{}", i),
                    mock_module("test", 1),
                    ChallengeConfig::default(),
                )
                .expect("register");
        }

        let result = registry.register(
            ChallengeId::new(),
            "extra".to_string(),
            1,
            "hash_extra".to_string(),
            mock_module("extra", 1),
            ChallengeConfig::default(),
        );

        assert!(matches!(result, Err(LoaderError::RegistryFull { max: 2 })));
    }

    #[test]
    fn test_unregister_challenge() {
        let registry = ChallengeRegistry::new();
        let id = ChallengeId::new();

        registry
            .register(
                id,
                "test".to_string(),
                1,
                "hash".to_string(),
                mock_module("test", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        assert!(registry.contains(&id));

        let removed = registry.unregister(&id).expect("unregister");
        assert_eq!(removed.name, "test");
        assert!(!registry.contains(&id));
    }

    #[test]
    fn test_unregister_nonexistent_fails() {
        let registry = ChallengeRegistry::new();
        let id = ChallengeId::new();

        let result = registry.unregister(&id);
        assert!(matches!(result, Err(LoaderError::ChallengeNotFound(_))));
    }

    #[test]
    fn test_list_challenges() {
        let registry = ChallengeRegistry::new();

        for i in 0..3 {
            registry
                .register(
                    ChallengeId::new(),
                    format!("challenge-{}", i),
                    1,
                    format!("hash{}", i),
                    mock_module("test", 1),
                    ChallengeConfig::default(),
                )
                .expect("register");
        }

        let list = registry.list();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_list_active_challenges() {
        let registry = ChallengeRegistry::new();
        let id1 = ChallengeId::new();
        let id2 = ChallengeId::new();

        registry
            .register(
                id1,
                "active".to_string(),
                1,
                "hash1".to_string(),
                mock_module("active", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        registry
            .register(
                id2,
                "inactive".to_string(),
                1,
                "hash2".to_string(),
                mock_module("inactive", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        registry.set_active(&id2, false).expect("set inactive");

        let active = registry.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "active");
    }

    #[test]
    fn test_update_challenge() {
        let registry = ChallengeRegistry::new();
        let id = ChallengeId::new();

        registry
            .register(
                id,
                "test".to_string(),
                1,
                "hash1".to_string(),
                mock_module("test", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        let old_version = registry
            .update(
                &id,
                2,
                "hash2".to_string(),
                mock_module("test", 2),
                vec![0u8; 100],
            )
            .expect("update");

        assert_eq!(old_version, 1);

        let challenge = registry.get(&id).expect("get");
        assert_eq!(challenge.version, 2);
        assert_eq!(challenge.code_hash, "hash2");
    }

    #[test]
    fn test_version_history_preserved() {
        let registry = ChallengeRegistry::new();
        let id = ChallengeId::new();

        registry
            .register(
                id,
                "test".to_string(),
                1,
                "hash1".to_string(),
                mock_module("test", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        registry
            .update(
                &id,
                2,
                "hash2".to_string(),
                mock_module("test", 2),
                vec![1u8; 100],
            )
            .expect("update");

        let history = registry.get_version_history(&id);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].version, 1);
        assert_eq!(history[0].code_hash, "hash1");
    }

    #[test]
    fn test_get_module() {
        let registry = ChallengeRegistry::new();
        let id = ChallengeId::new();

        registry
            .register(
                id,
                "test".to_string(),
                1,
                "hash".to_string(),
                mock_module("test", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        let module = registry.get_module(&id).expect("get module");
        assert_eq!(module.name(), "test");
        assert_eq!(module.version(), 1);
    }

    #[test]
    fn test_set_active() {
        let registry = ChallengeRegistry::new();
        let id = ChallengeId::new();

        registry
            .register(
                id,
                "test".to_string(),
                1,
                "hash".to_string(),
                mock_module("test", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        assert!(registry.get(&id).unwrap().is_active);

        registry.set_active(&id, false).expect("deactivate");
        assert!(!registry.get(&id).unwrap().is_active);

        registry.set_active(&id, true).expect("reactivate");
        assert!(registry.get(&id).unwrap().is_active);
    }

    #[test]
    fn test_clear_registry() {
        let registry = ChallengeRegistry::new();

        for i in 0..3 {
            registry
                .register(
                    ChallengeId::new(),
                    format!("challenge-{}", i),
                    1,
                    format!("hash{}", i),
                    mock_module("test", 1),
                    ChallengeConfig::default(),
                )
                .expect("register");
        }

        assert_eq!(registry.count(), 3);

        registry.clear();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_remaining_capacity() {
        let registry = ChallengeRegistry::with_capacity(10);

        assert_eq!(registry.remaining_capacity(), 10);

        for i in 0..4 {
            registry
                .register(
                    ChallengeId::new(),
                    format!("challenge-{}", i),
                    1,
                    format!("hash{}", i),
                    mock_module("test", 1),
                    ChallengeConfig::default(),
                )
                .expect("register");
        }

        assert_eq!(registry.remaining_capacity(), 6);
    }

    #[test]
    fn test_challenge_ids() {
        let registry = ChallengeRegistry::new();
        let id1 = ChallengeId::new();
        let id2 = ChallengeId::new();

        registry
            .register(
                id1,
                "test1".to_string(),
                1,
                "hash1".to_string(),
                mock_module("test1", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        registry
            .register(
                id2,
                "test2".to_string(),
                1,
                "hash2".to_string(),
                mock_module("test2", 1),
                ChallengeConfig::default(),
            )
            .expect("register");

        let ids = registry.challenge_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_challenge_info_from_loaded() {
        let id = ChallengeId::new();
        let loaded = LoadedChallenge {
            id,
            name: "test".to_string(),
            version: 5,
            code_hash: "abc".to_string(),
            module: mock_module("test", 5),
            config: ChallengeConfig::default(),
            loaded_at: Utc::now(),
            is_active: true,
        };

        let info: ChallengeInfo = (&loaded).into();
        assert_eq!(info.id, id);
        assert_eq!(info.name, "test");
        assert_eq!(info.version, 5);
        assert_eq!(info.code_hash, "abc");
        assert!(info.is_active);
    }

    #[test]
    fn test_module_evaluate() {
        let module = mock_module("test", 1);
        let score = module.evaluate(b"agent_data").expect("evaluate");
        assert!((score - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_module_validate() {
        let module = mock_module("test", 1);
        let valid = module.validate(b"agent_data").expect("validate");
        assert!(valid);
    }
}
