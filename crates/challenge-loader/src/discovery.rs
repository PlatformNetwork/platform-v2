//! Challenge discovery from various sources
//!
//! This module provides traits and implementations for discovering challenge
//! modules from the filesystem, P2P network, and other sources.

use crate::error::{LoaderError, LoaderResult};
use async_trait::async_trait;
use parking_lot::RwLock;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Source from which a challenge was discovered
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeSource {
    /// Discovered from local filesystem
    Filesystem(PathBuf),
    /// Received from P2P network
    P2P {
        /// Peer ID that provided the challenge
        peer_id: String,
    },
    /// Downloaded from a registry
    Registry {
        /// Registry URL
        url: String,
    },
    /// Manually provided
    Manual,
}

impl std::fmt::Display for ChallengeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeSource::Filesystem(path) => write!(f, "filesystem:{}", path.display()),
            ChallengeSource::P2P { peer_id } => write!(f, "p2p:{}", peer_id),
            ChallengeSource::Registry { url } => write!(f, "registry:{}", url),
            ChallengeSource::Manual => write!(f, "manual"),
        }
    }
}

/// A challenge discovered from some source
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredChallenge {
    /// Challenge identifier
    pub id: ChallengeId,
    /// Human-readable name
    pub name: String,
    /// Version number
    pub version: u32,
    /// SHA-256 hash of the WASM bytecode
    pub code_hash: String,
    /// Source where this challenge was found
    pub source: ChallengeSource,
    /// WASM bytecode (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_bytes: Option<Vec<u8>>,
    /// Optional configuration path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
}

impl DiscoveredChallenge {
    /// Create a new discovered challenge
    pub fn new(
        id: ChallengeId,
        name: String,
        version: u32,
        code_hash: String,
        source: ChallengeSource,
    ) -> Self {
        Self {
            id,
            name,
            version,
            code_hash,
            source,
            wasm_bytes: None,
            config_path: None,
        }
    }

    /// Attach WASM bytecode to the discovery
    pub fn with_wasm_bytes(mut self, wasm_bytes: Vec<u8>) -> Self {
        self.wasm_bytes = Some(wasm_bytes);
        self
    }

    /// Attach config path to the discovery
    pub fn with_config_path(mut self, config_path: PathBuf) -> Self {
        self.config_path = Some(config_path);
        self
    }

    /// Verify the code hash matches the WASM bytes
    pub fn verify_hash(&self) -> bool {
        match &self.wasm_bytes {
            Some(bytes) => {
                let computed = hex::encode(Sha256::digest(bytes));
                computed == self.code_hash
            }
            None => false,
        }
    }
}

/// Update notification for challenge discovery
#[derive(Clone, Debug)]
pub enum ChallengeUpdate {
    /// A new challenge was discovered
    Added(DiscoveredChallenge),
    /// An existing challenge was updated
    Updated {
        /// Challenge ID
        id: ChallengeId,
        /// New version number
        new_version: u32,
        /// New code hash
        new_code_hash: String,
        /// Updated WASM bytes if available
        wasm_bytes: Option<Vec<u8>>,
    },
    /// A challenge was removed
    Removed(ChallengeId),
}

/// Trait for challenge discovery implementations
///
/// Implementations can discover challenges from various sources like
/// the filesystem, P2P network, or remote registries.
#[async_trait]
pub trait ChallengeDiscovery: Send + Sync {
    /// Discover available challenges
    ///
    /// Returns a list of all discoverable challenges from this source.
    async fn discover(&self) -> LoaderResult<Vec<DiscoveredChallenge>>;

    /// Subscribe to challenge updates
    ///
    /// Returns a receiver that will be notified of new, updated, or removed challenges.
    fn subscribe(&self) -> mpsc::Receiver<ChallengeUpdate>;

    /// Start watching for changes (if applicable)
    async fn start_watching(&self) -> LoaderResult<()>;

    /// Stop watching for changes
    async fn stop_watching(&self) -> LoaderResult<()>;

    /// Get the source type name
    fn source_name(&self) -> &'static str;
}

/// Configuration for filesystem discovery
#[derive(Clone, Debug)]
pub struct FilesystemDiscoveryConfig {
    /// Directory to watch for challenge files
    pub watch_dir: PathBuf,
    /// File extension for WASM files
    pub wasm_extension: String,
    /// File extension for config files
    pub config_extension: String,
    /// Enable file watching
    pub watch_enabled: bool,
    /// Watch poll interval in milliseconds
    pub poll_interval_ms: u64,
}

impl Default for FilesystemDiscoveryConfig {
    fn default() -> Self {
        Self {
            watch_dir: PathBuf::from("./challenges"),
            wasm_extension: "wasm".to_string(),
            config_extension: "json".to_string(),
            watch_enabled: true,
            poll_interval_ms: 5000,
        }
    }
}

/// Filesystem-based challenge discovery
///
/// Discovers challenges from a local directory by scanning for WASM files
/// and their associated JSON config files.
pub struct FilesystemDiscovery {
    /// Configuration
    config: FilesystemDiscoveryConfig,
    /// Update sender
    sender: mpsc::Sender<ChallengeUpdate>,
    /// Receivers for subscriptions
    subscribers: Arc<RwLock<Vec<mpsc::Sender<ChallengeUpdate>>>>,
    /// Known challenges (for change detection)
    known_challenges: Arc<RwLock<std::collections::HashMap<PathBuf, String>>>,
    /// Whether watching is active
    watching: Arc<RwLock<bool>>,
}

impl FilesystemDiscovery {
    /// Create a new filesystem discovery instance
    pub fn new(config: FilesystemDiscoveryConfig) -> Self {
        let (sender, _) = mpsc::channel(100);
        Self {
            config,
            sender,
            subscribers: Arc::new(RwLock::new(Vec::new())),
            known_challenges: Arc::new(RwLock::new(std::collections::HashMap::new())),
            watching: Arc::new(RwLock::new(false)),
        }
    }

    /// Create with default configuration for a given directory
    pub fn for_directory(dir: PathBuf) -> Self {
        let config = FilesystemDiscoveryConfig {
            watch_dir: dir,
            ..Default::default()
        };
        Self::new(config)
    }

    /// Scan the directory for challenge files
    async fn scan_directory(&self) -> LoaderResult<Vec<DiscoveredChallenge>> {
        let dir = &self.config.watch_dir;

        if !dir.exists() {
            debug!(path = %dir.display(), "Discovery directory does not exist");
            return Ok(Vec::new());
        }

        let mut discoveries = Vec::new();
        let _wasm_ext = format!(".{}", self.config.wasm_extension);

        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(path = %dir.display(), error = %e, "Failed to read discovery directory");
                return Err(LoaderError::IoError(e));
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some(&self.config.wasm_extension) {
                continue;
            }

            match self.discover_from_file(&path).await {
                Ok(challenge) => {
                    info!(
                        path = %path.display(),
                        name = %challenge.name,
                        version = challenge.version,
                        "Discovered challenge from filesystem"
                    );
                    discoveries.push(challenge);
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to discover challenge");
                }
            }
        }

        Ok(discoveries)
    }

    /// Discover a challenge from a specific WASM file
    async fn discover_from_file(&self, wasm_path: &PathBuf) -> LoaderResult<DiscoveredChallenge> {
        // Read WASM bytes
        let wasm_bytes = std::fs::read(wasm_path)?;
        let code_hash = hex::encode(Sha256::digest(&wasm_bytes));

        // Try to find matching config file
        let config_path = wasm_path.with_extension(&self.config.config_extension);

        // Extract name from filename
        let name = wasm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Try to read version and ID from config
        let (id, version) = if config_path.exists() {
            match self.read_config(&config_path) {
                Ok((id, v)) => (id, v),
                Err(_) => (ChallengeId::from_string(&name), 1),
            }
        } else {
            (ChallengeId::from_string(&name), 1)
        };

        let mut challenge = DiscoveredChallenge::new(
            id,
            name,
            version,
            code_hash,
            ChallengeSource::Filesystem(wasm_path.clone()),
        )
        .with_wasm_bytes(wasm_bytes);

        if config_path.exists() {
            challenge = challenge.with_config_path(config_path);
        }

        Ok(challenge)
    }

    /// Read challenge config from a JSON file
    fn read_config(&self, config_path: &PathBuf) -> LoaderResult<(ChallengeId, u32)> {
        let content = std::fs::read_to_string(config_path)?;
        let config: serde_json::Value = serde_json::from_str(&content)?;

        let id = config
            .get("id")
            .and_then(|v| v.as_str())
            .map(ChallengeId::from_string)
            .unwrap_or_else(ChallengeId::new);

        let version = config
            .get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(1);

        Ok((id, version))
    }

    /// Broadcast an update to all subscribers
    fn broadcast_update(&self, update: ChallengeUpdate) {
        let subscribers = self.subscribers.read();
        for subscriber in subscribers.iter() {
            let update_clone = update.clone();
            let subscriber_clone = subscriber.clone();
            tokio::spawn(async move {
                if subscriber_clone.send(update_clone).await.is_err() {
                    debug!("Subscriber dropped, removing from list");
                }
            });
        }
    }

    /// Check for changes since last scan
    async fn check_for_changes(&self) -> LoaderResult<Vec<ChallengeUpdate>> {
        let current = self.scan_directory().await?;
        let mut updates = Vec::new();
        let mut known = self.known_challenges.write();

        // Track current paths
        let mut current_paths: std::collections::HashSet<PathBuf> =
            std::collections::HashSet::new();

        for challenge in current {
            if let ChallengeSource::Filesystem(ref path) = challenge.source {
                current_paths.insert(path.clone());

                match known.get(path) {
                    Some(old_hash) if old_hash != &challenge.code_hash => {
                        // Changed
                        updates.push(ChallengeUpdate::Updated {
                            id: challenge.id,
                            new_version: challenge.version,
                            new_code_hash: challenge.code_hash.clone(),
                            wasm_bytes: challenge.wasm_bytes.clone(),
                        });
                        known.insert(path.clone(), challenge.code_hash);
                    }
                    None => {
                        // New
                        known.insert(path.clone(), challenge.code_hash.clone());
                        updates.push(ChallengeUpdate::Added(challenge));
                    }
                    _ => {} // Unchanged
                }
            }
        }

        // Check for removals
        let removed_paths: Vec<PathBuf> = known
            .keys()
            .filter(|p| !current_paths.contains(*p))
            .cloned()
            .collect();

        for path in removed_paths {
            known.remove(&path);
            // We don't have the ID stored, so we'd need to track it differently
            // For now, we skip removal notifications
            debug!(path = %path.display(), "Challenge file removed");
        }

        Ok(updates)
    }
}

#[async_trait]
impl ChallengeDiscovery for FilesystemDiscovery {
    async fn discover(&self) -> LoaderResult<Vec<DiscoveredChallenge>> {
        self.scan_directory().await
    }

    fn subscribe(&self) -> mpsc::Receiver<ChallengeUpdate> {
        let (tx, rx) = mpsc::channel(100);
        self.subscribers.write().push(tx);
        rx
    }

    async fn start_watching(&self) -> LoaderResult<()> {
        if !self.config.watch_enabled {
            return Ok(());
        }

        {
            let mut watching = self.watching.write();
            if *watching {
                return Ok(());
            }
            *watching = true;
        }

        let poll_interval = std::time::Duration::from_millis(self.config.poll_interval_ms);
        let discovery = Arc::new(self.clone_inner());

        tokio::spawn(async move {
            loop {
                if !*discovery.watching.read() {
                    break;
                }

                match discovery.check_for_changes().await {
                    Ok(updates) => {
                        for update in updates {
                            discovery.broadcast_update(update);
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Error checking for changes");
                    }
                }

                tokio::time::sleep(poll_interval).await;
            }
        });

        info!(
            dir = %self.config.watch_dir.display(),
            poll_interval_ms = self.config.poll_interval_ms,
            "Started filesystem watching"
        );

        Ok(())
    }

    async fn stop_watching(&self) -> LoaderResult<()> {
        *self.watching.write() = false;
        info!("Stopped filesystem watching");
        Ok(())
    }

    fn source_name(&self) -> &'static str {
        "filesystem"
    }
}

impl FilesystemDiscovery {
    /// Clone internals for spawning watch task
    fn clone_inner(&self) -> Self {
        Self {
            config: self.config.clone(),
            sender: self.sender.clone(),
            subscribers: self.subscribers.clone(),
            known_challenges: self.known_challenges.clone(),
            watching: self.watching.clone(),
        }
    }
}

/// P2P network-based challenge discovery (stub implementation)
///
/// Discovers challenges announced on the P2P network.
pub struct P2PDiscovery {
    /// Whether discovery is enabled
    enabled: bool,
    /// Subscribers
    subscribers: Arc<RwLock<Vec<mpsc::Sender<ChallengeUpdate>>>>,
}

impl P2PDiscovery {
    /// Create a new P2P discovery instance
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            subscribers: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait]
impl ChallengeDiscovery for P2PDiscovery {
    async fn discover(&self) -> LoaderResult<Vec<DiscoveredChallenge>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        // P2P discovery would connect to the network and query for available challenges
        // For now, return empty list
        debug!("P2P discovery: scanning network for challenges");
        Ok(Vec::new())
    }

    fn subscribe(&self) -> mpsc::Receiver<ChallengeUpdate> {
        let (tx, rx) = mpsc::channel(100);
        self.subscribers.write().push(tx);
        rx
    }

    async fn start_watching(&self) -> LoaderResult<()> {
        if !self.enabled {
            return Ok(());
        }
        // Would subscribe to P2P challenge announcements
        info!("P2P discovery watching started (stub)");
        Ok(())
    }

    async fn stop_watching(&self) -> LoaderResult<()> {
        info!("P2P discovery watching stopped");
        Ok(())
    }

    fn source_name(&self) -> &'static str {
        "p2p"
    }
}

/// Composite discovery that aggregates multiple discovery sources
pub struct CompositeDiscovery {
    /// Discovery sources
    sources: Vec<Arc<dyn ChallengeDiscovery>>,
}

impl CompositeDiscovery {
    /// Create a new composite discovery
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Add a discovery source
    pub fn add_source(mut self, source: Arc<dyn ChallengeDiscovery>) -> Self {
        self.sources.push(source);
        self
    }

    /// Get the number of sources
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

impl Default for CompositeDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChallengeDiscovery for CompositeDiscovery {
    async fn discover(&self) -> LoaderResult<Vec<DiscoveredChallenge>> {
        let mut all_challenges = Vec::new();

        for source in &self.sources {
            match source.discover().await {
                Ok(challenges) => {
                    debug!(
                        source = source.source_name(),
                        count = challenges.len(),
                        "Discovered challenges from source"
                    );
                    all_challenges.extend(challenges);
                }
                Err(e) => {
                    warn!(
                        source = source.source_name(),
                        error = %e,
                        "Failed to discover from source"
                    );
                }
            }
        }

        Ok(all_challenges)
    }

    fn subscribe(&self) -> mpsc::Receiver<ChallengeUpdate> {
        // Create a merged receiver from all sources
        let (tx, rx) = mpsc::channel(100);

        for source in &self.sources {
            let mut source_rx = source.subscribe();
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                while let Some(update) = source_rx.recv().await {
                    if tx_clone.send(update).await.is_err() {
                        break;
                    }
                }
            });
        }

        rx
    }

    async fn start_watching(&self) -> LoaderResult<()> {
        for source in &self.sources {
            source.start_watching().await?;
        }
        Ok(())
    }

    async fn stop_watching(&self) -> LoaderResult<()> {
        for source in &self.sources {
            source.stop_watching().await?;
        }
        Ok(())
    }

    fn source_name(&self) -> &'static str {
        "composite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_challenge_source_display() {
        let fs = ChallengeSource::Filesystem(PathBuf::from("/tmp/challenge.wasm"));
        assert!(fs.to_string().contains("filesystem"));

        let p2p = ChallengeSource::P2P {
            peer_id: "peer123".to_string(),
        };
        assert!(p2p.to_string().contains("p2p:peer123"));

        let registry = ChallengeSource::Registry {
            url: "https://example.com".to_string(),
        };
        assert!(registry.to_string().contains("registry"));

        let manual = ChallengeSource::Manual;
        assert_eq!(manual.to_string(), "manual");
    }

    #[test]
    fn test_discovered_challenge_verify_hash() {
        let wasm_bytes = vec![0u8; 100];
        let correct_hash = hex::encode(Sha256::digest(&wasm_bytes));

        let challenge = DiscoveredChallenge::new(
            ChallengeId::new(),
            "test".to_string(),
            1,
            correct_hash.clone(),
            ChallengeSource::Manual,
        )
        .with_wasm_bytes(wasm_bytes);

        assert!(challenge.verify_hash());

        // Wrong hash
        let challenge_wrong = DiscoveredChallenge::new(
            ChallengeId::new(),
            "test".to_string(),
            1,
            "wronghash".to_string(),
            ChallengeSource::Manual,
        )
        .with_wasm_bytes(vec![0u8; 100]);

        assert!(!challenge_wrong.verify_hash());
    }

    #[test]
    fn test_discovered_challenge_no_bytes() {
        let challenge = DiscoveredChallenge::new(
            ChallengeId::new(),
            "test".to_string(),
            1,
            "somehash".to_string(),
            ChallengeSource::Manual,
        );

        assert!(!challenge.verify_hash());
    }

    #[tokio::test]
    async fn test_filesystem_discovery_empty_dir() {
        let temp_dir = TempDir::new().expect("create temp dir");

        let config = FilesystemDiscoveryConfig {
            watch_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let discovery = FilesystemDiscovery::new(config);
        let challenges = discovery.discover().await.expect("discover");

        assert!(challenges.is_empty());
    }

    #[tokio::test]
    async fn test_filesystem_discovery_finds_wasm() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let wasm_path = temp_dir.path().join("test-challenge.wasm");

        // Write fake WASM file
        std::fs::write(&wasm_path, vec![0u8; 100]).expect("write wasm");

        let config = FilesystemDiscoveryConfig {
            watch_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let discovery = FilesystemDiscovery::new(config);
        let challenges = discovery.discover().await.expect("discover");

        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].name, "test-challenge");
        assert!(challenges[0].wasm_bytes.is_some());
        assert!(challenges[0].verify_hash());
    }

    #[tokio::test]
    async fn test_filesystem_discovery_with_config() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let wasm_path = temp_dir.path().join("my-challenge.wasm");
        let config_path = temp_dir.path().join("my-challenge.json");

        // Write WASM and config
        std::fs::write(&wasm_path, vec![1u8; 50]).expect("write wasm");
        std::fs::write(
            &config_path,
            r#"{"id": "custom-id", "version": 5}"#,
        )
        .expect("write config");

        let config = FilesystemDiscoveryConfig {
            watch_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let discovery = FilesystemDiscovery::new(config);
        let challenges = discovery.discover().await.expect("discover");

        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].name, "my-challenge");
        assert_eq!(challenges[0].version, 5);
        assert!(challenges[0].config_path.is_some());
    }

    #[tokio::test]
    async fn test_filesystem_discovery_ignores_non_wasm() {
        let temp_dir = TempDir::new().expect("create temp dir");

        // Write various files
        std::fs::write(temp_dir.path().join("test.wasm"), vec![0u8; 50]).expect("write wasm");
        std::fs::write(temp_dir.path().join("readme.txt"), b"hello").expect("write txt");
        std::fs::write(temp_dir.path().join("config.json"), b"{}").expect("write json");

        let config = FilesystemDiscoveryConfig {
            watch_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let discovery = FilesystemDiscovery::new(config);
        let challenges = discovery.discover().await.expect("discover");

        assert_eq!(challenges.len(), 1);
    }

    #[tokio::test]
    async fn test_filesystem_discovery_nonexistent_dir() {
        let config = FilesystemDiscoveryConfig {
            watch_dir: PathBuf::from("/nonexistent/path/to/challenges"),
            ..Default::default()
        };

        let discovery = FilesystemDiscovery::new(config);
        let challenges = discovery.discover().await.expect("discover");

        assert!(challenges.is_empty());
    }

    #[tokio::test]
    async fn test_p2p_discovery_disabled() {
        let discovery = P2PDiscovery::new(false);
        let challenges = discovery.discover().await.expect("discover");

        assert!(challenges.is_empty());
    }

    #[tokio::test]
    async fn test_composite_discovery_aggregates() {
        let temp_dir = TempDir::new().expect("create temp dir");
        std::fs::write(temp_dir.path().join("test.wasm"), vec![0u8; 50]).expect("write");

        let fs_config = FilesystemDiscoveryConfig {
            watch_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let composite = CompositeDiscovery::new()
            .add_source(Arc::new(FilesystemDiscovery::new(fs_config)))
            .add_source(Arc::new(P2PDiscovery::new(false)));

        assert_eq!(composite.source_count(), 2);

        let challenges = composite.discover().await.expect("discover");
        assert_eq!(challenges.len(), 1);
    }

    #[test]
    fn test_discovered_challenge_builders() {
        let challenge = DiscoveredChallenge::new(
            ChallengeId::new(),
            "test".to_string(),
            1,
            "hash".to_string(),
            ChallengeSource::Manual,
        )
        .with_wasm_bytes(vec![1, 2, 3])
        .with_config_path(PathBuf::from("/config.json"));

        assert_eq!(challenge.wasm_bytes, Some(vec![1, 2, 3]));
        assert_eq!(challenge.config_path, Some(PathBuf::from("/config.json")));
    }

    #[test]
    fn test_challenge_update_variants() {
        let id = ChallengeId::new();

        let added = ChallengeUpdate::Added(DiscoveredChallenge::new(
            id,
            "test".to_string(),
            1,
            "hash".to_string(),
            ChallengeSource::Manual,
        ));

        let updated = ChallengeUpdate::Updated {
            id,
            new_version: 2,
            new_code_hash: "newhash".to_string(),
            wasm_bytes: Some(vec![1, 2, 3]),
        };

        let removed = ChallengeUpdate::Removed(id);

        // Just verify they can be constructed and debugged
        assert!(!format!("{:?}", added).is_empty());
        assert!(!format!("{:?}", updated).is_empty());
        assert!(!format!("{:?}", removed).is_empty());
    }
}
