//! Version management for challenge modules
//!
//! This module provides version tracking, history management, and rollback
//! capabilities for loaded challenge modules.

use crate::error::{LoaderError, LoaderResult};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// A specific version of a challenge module
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeVersion {
    /// Version number (monotonically increasing)
    pub version: u32,
    /// SHA-256 hash of the WASM bytecode
    pub code_hash: String,
    /// Raw WASM bytecode for this version
    pub wasm_bytes: Vec<u8>,
    /// Timestamp when this version was registered
    pub created_at: DateTime<Utc>,
    /// Whether this version is currently active
    pub is_active: bool,
}

impl ChallengeVersion {
    /// Create a new challenge version
    pub fn new(version: u32, code_hash: String, wasm_bytes: Vec<u8>) -> Self {
        Self {
            version,
            code_hash,
            wasm_bytes,
            created_at: Utc::now(),
            is_active: false,
        }
    }

    /// Get the size of the WASM bytecode in bytes
    pub fn size_bytes(&self) -> usize {
        self.wasm_bytes.len()
    }
}

/// Manages version history and rollback for challenge modules
pub struct VersionManager {
    /// Version history for each challenge, keyed by challenge ID
    versions: RwLock<HashMap<ChallengeId, Vec<ChallengeVersion>>>,
    /// Maximum number of versions to retain per challenge
    max_versions_per_challenge: usize,
}

impl VersionManager {
    /// Create a new version manager with default settings
    pub fn new() -> Self {
        Self {
            versions: RwLock::new(HashMap::new()),
            max_versions_per_challenge: 10,
        }
    }

    /// Create a version manager with custom max versions limit
    pub fn with_max_versions(max_versions: usize) -> Self {
        Self {
            versions: RwLock::new(HashMap::new()),
            max_versions_per_challenge: max_versions,
        }
    }

    /// Register a new version for a challenge
    ///
    /// Automatically assigns the next version number and marks it as inactive.
    /// To activate a version, call `activate_version` separately.
    pub fn register_version(
        &self,
        id: ChallengeId,
        mut version: ChallengeVersion,
    ) -> LoaderResult<u32> {
        let mut versions = self.versions.write();
        let challenge_versions = versions.entry(id).or_insert_with(Vec::new);

        // Determine next version number
        let next_version = challenge_versions
            .iter()
            .map(|v| v.version)
            .max()
            .map(|v| v + 1)
            .unwrap_or(1);

        // Check for duplicate code hash in recent versions
        if let Some(existing) = challenge_versions
            .iter()
            .find(|v| v.code_hash == version.code_hash)
        {
            warn!(
                challenge_id = %id,
                existing_version = existing.version,
                code_hash = %version.code_hash,
                "Duplicate code hash detected, creating new version anyway"
            );
        }

        version.version = next_version;
        version.created_at = Utc::now();

        info!(
            challenge_id = %id,
            version = next_version,
            code_hash = %version.code_hash,
            size_bytes = version.size_bytes(),
            "Registered new challenge version"
        );

        challenge_versions.push(version);

        // Prune old versions if exceeding limit
        self.prune_versions_internal(challenge_versions);

        Ok(next_version)
    }

    /// Get the latest version number for a challenge
    pub fn latest_version(&self, id: &ChallengeId) -> Option<u32> {
        self.versions
            .read()
            .get(id)
            .and_then(|versions| versions.iter().map(|v| v.version).max())
    }

    /// Get the currently active version number for a challenge
    pub fn active_version(&self, id: &ChallengeId) -> Option<u32> {
        self.versions
            .read()
            .get(id)
            .and_then(|versions| versions.iter().find(|v| v.is_active).map(|v| v.version))
    }

    /// Get the full version history for a challenge
    ///
    /// Returns versions in chronological order (oldest first).
    pub fn version_history(&self, id: &ChallengeId) -> Vec<ChallengeVersion> {
        self.versions
            .read()
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get a specific version by version number
    pub fn get_version(&self, id: &ChallengeId, version: u32) -> Option<ChallengeVersion> {
        self.versions.read().get(id).and_then(|versions| {
            versions
                .iter()
                .find(|v| v.version == version)
                .cloned()
        })
    }

    /// Activate a specific version for a challenge
    ///
    /// Deactivates any previously active version.
    pub fn activate_version(&self, id: &ChallengeId, version: u32) -> LoaderResult<()> {
        let mut versions = self.versions.write();
        let challenge_versions = versions.get_mut(id).ok_or_else(|| {
            LoaderError::ChallengeNotFound(format!("No versions found for challenge {}", id))
        })?;

        let version_exists = challenge_versions.iter().any(|v| v.version == version);
        if !version_exists {
            return Err(LoaderError::VersionConflict(format!(
                "Version {} not found for challenge {}",
                version, id
            )));
        }

        // Deactivate all versions and activate the specified one
        for v in challenge_versions.iter_mut() {
            v.is_active = v.version == version;
        }

        debug!(
            challenge_id = %id,
            version = version,
            "Activated challenge version"
        );

        Ok(())
    }

    /// Rollback to a previous version
    ///
    /// Returns the WASM bytes of the rolled-back version if successful.
    pub fn rollback(&self, id: &ChallengeId, to_version: u32) -> LoaderResult<ChallengeVersion> {
        let versions = self.versions.read();
        let challenge_versions = versions.get(id).ok_or_else(|| {
            LoaderError::ChallengeNotFound(format!("No versions found for challenge {}", id))
        })?;

        let target_version = challenge_versions
            .iter()
            .find(|v| v.version == to_version)
            .ok_or_else(|| {
                LoaderError::VersionConflict(format!(
                    "Version {} not found for challenge {}",
                    to_version, id
                ))
            })?;

        info!(
            challenge_id = %id,
            from_version = ?self.active_version(id),
            to_version = to_version,
            "Rolling back challenge version"
        );

        // Return a clone; the caller should activate and reload
        Ok(target_version.clone())
    }

    /// Remove all versions for a challenge
    pub fn remove_challenge(&self, id: &ChallengeId) -> LoaderResult<usize> {
        let mut versions = self.versions.write();
        let removed = versions.remove(id).map(|v| v.len()).unwrap_or(0);

        if removed > 0 {
            info!(
                challenge_id = %id,
                versions_removed = removed,
                "Removed all versions for challenge"
            );
        }

        Ok(removed)
    }

    /// Get the number of tracked challenges
    pub fn challenge_count(&self) -> usize {
        self.versions.read().len()
    }

    /// Get the total number of versions across all challenges
    pub fn total_version_count(&self) -> usize {
        self.versions.read().values().map(|v| v.len()).sum()
    }

    /// Prune old versions, keeping only the most recent N versions
    fn prune_versions_internal(&self, versions: &mut Vec<ChallengeVersion>) {
        if versions.len() > self.max_versions_per_challenge {
            // Sort by version number descending
            versions.sort_by(|a, b| b.version.cmp(&a.version));

            // Keep only max_versions_per_challenge, but always keep active version
            let active_version = versions.iter().find(|v| v.is_active).map(|v| v.version);

            let to_remove: Vec<usize> = versions
                .iter()
                .enumerate()
                .skip(self.max_versions_per_challenge)
                .filter(|(_, v)| Some(v.version) != active_version)
                .map(|(i, _)| i)
                .collect();

            // Remove from highest index to lowest to preserve indices
            for i in to_remove.into_iter().rev() {
                let removed = versions.remove(i);
                debug!(
                    version = removed.version,
                    "Pruned old challenge version"
                );
            }

            // Re-sort chronologically (oldest first)
            versions.sort_by(|a, b| a.version.cmp(&b.version));
        }
    }
}

impl Default for VersionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_version(code: &[u8]) -> ChallengeVersion {
        use sha2::{Digest, Sha256};
        let hash = hex::encode(Sha256::digest(code));
        ChallengeVersion::new(0, hash, code.to_vec())
    }

    #[test]
    fn test_register_version_assigns_sequential_numbers() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        let v1 = manager
            .register_version(id, make_version(b"code1"))
            .expect("register v1");
        let v2 = manager
            .register_version(id, make_version(b"code2"))
            .expect("register v2");
        let v3 = manager
            .register_version(id, make_version(b"code3"))
            .expect("register v3");

        assert_eq!(v1, 1);
        assert_eq!(v2, 2);
        assert_eq!(v3, 3);
    }

    #[test]
    fn test_latest_version() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        assert!(manager.latest_version(&id).is_none());

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");
        assert_eq!(manager.latest_version(&id), Some(1));

        manager
            .register_version(id, make_version(b"code2"))
            .expect("register");
        assert_eq!(manager.latest_version(&id), Some(2));
    }

    #[test]
    fn test_active_version_and_activate() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");
        manager
            .register_version(id, make_version(b"code2"))
            .expect("register");

        assert!(manager.active_version(&id).is_none());

        manager.activate_version(&id, 1).expect("activate v1");
        assert_eq!(manager.active_version(&id), Some(1));

        manager.activate_version(&id, 2).expect("activate v2");
        assert_eq!(manager.active_version(&id), Some(2));

        // Only one version should be active
        let history = manager.version_history(&id);
        let active_count = history.iter().filter(|v| v.is_active).count();
        assert_eq!(active_count, 1);
    }

    #[test]
    fn test_activate_nonexistent_version_fails() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");

        let result = manager.activate_version(&id, 999);
        assert!(matches!(result, Err(LoaderError::VersionConflict(_))));
    }

    #[test]
    fn test_version_history() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");
        manager
            .register_version(id, make_version(b"code2"))
            .expect("register");

        let history = manager.version_history(&id);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].version, 1);
        assert_eq!(history[1].version, 2);
    }

    #[test]
    fn test_get_version() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");

        let v = manager.get_version(&id, 1);
        assert!(v.is_some());
        assert_eq!(v.as_ref().unwrap().version, 1);

        let missing = manager.get_version(&id, 999);
        assert!(missing.is_none());
    }

    #[test]
    fn test_rollback() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");
        manager
            .register_version(id, make_version(b"code2"))
            .expect("register");
        manager.activate_version(&id, 2).expect("activate");

        let rolled_back = manager.rollback(&id, 1).expect("rollback");
        assert_eq!(rolled_back.version, 1);
        assert_eq!(rolled_back.wasm_bytes, b"code1");
    }

    #[test]
    fn test_rollback_to_nonexistent_version_fails() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");

        let result = manager.rollback(&id, 999);
        assert!(matches!(result, Err(LoaderError::VersionConflict(_))));
    }

    #[test]
    fn test_remove_challenge() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");
        manager
            .register_version(id, make_version(b"code2"))
            .expect("register");

        let removed = manager.remove_challenge(&id).expect("remove");
        assert_eq!(removed, 2);

        let history = manager.version_history(&id);
        assert!(history.is_empty());
    }

    #[test]
    fn test_challenge_and_version_counts() {
        let manager = VersionManager::new();
        let id1 = ChallengeId::new();
        let id2 = ChallengeId::new();

        assert_eq!(manager.challenge_count(), 0);
        assert_eq!(manager.total_version_count(), 0);

        manager
            .register_version(id1, make_version(b"code1"))
            .expect("register");
        manager
            .register_version(id1, make_version(b"code2"))
            .expect("register");
        manager
            .register_version(id2, make_version(b"code3"))
            .expect("register");

        assert_eq!(manager.challenge_count(), 2);
        assert_eq!(manager.total_version_count(), 3);
    }

    #[test]
    fn test_pruning_old_versions() {
        let manager = VersionManager::with_max_versions(3);
        let id = ChallengeId::new();

        for i in 1..=5 {
            let code = format!("code{}", i);
            manager
                .register_version(id, make_version(code.as_bytes()))
                .expect("register");
        }

        let history = manager.version_history(&id);
        assert_eq!(history.len(), 3);

        // Should keep the most recent versions
        let versions: Vec<u32> = history.iter().map(|v| v.version).collect();
        assert!(versions.contains(&5));
        assert!(versions.contains(&4));
        assert!(versions.contains(&3));
    }

    #[test]
    fn test_pruning_preserves_active_version() {
        let manager = VersionManager::with_max_versions(2);
        let id = ChallengeId::new();

        manager
            .register_version(id, make_version(b"code1"))
            .expect("register");
        manager.activate_version(&id, 1).expect("activate");

        for i in 2..=5 {
            let code = format!("code{}", i);
            manager
                .register_version(id, make_version(code.as_bytes()))
                .expect("register");
        }

        // Active version 1 should be preserved even though it's old
        let v1 = manager.get_version(&id, 1);
        assert!(v1.is_some());
        assert!(v1.unwrap().is_active);
    }

    #[test]
    fn test_challenge_version_size_bytes() {
        let wasm_data = vec![0u8; 1024];
        let version = make_version(&wasm_data);
        assert_eq!(version.size_bytes(), 1024);
    }

    #[test]
    fn test_duplicate_code_hash_allowed() {
        let manager = VersionManager::new();
        let id = ChallengeId::new();

        let v1 = manager
            .register_version(id, make_version(b"same_code"))
            .expect("register first");
        let v2 = manager
            .register_version(id, make_version(b"same_code"))
            .expect("register duplicate");

        assert_eq!(v1, 1);
        assert_eq!(v2, 2);
    }

    #[test]
    fn test_multiple_challenges_isolated() {
        let manager = VersionManager::new();
        let id1 = ChallengeId::new();
        let id2 = ChallengeId::new();

        manager
            .register_version(id1, make_version(b"c1v1"))
            .expect("register");
        manager
            .register_version(id1, make_version(b"c1v2"))
            .expect("register");

        manager
            .register_version(id2, make_version(b"c2v1"))
            .expect("register");

        assert_eq!(manager.version_history(&id1).len(), 2);
        assert_eq!(manager.version_history(&id2).len(), 1);
        assert_eq!(manager.latest_version(&id1), Some(2));
        assert_eq!(manager.latest_version(&id2), Some(1));
    }
}
