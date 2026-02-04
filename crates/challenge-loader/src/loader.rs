//! Main challenge loader implementation
//!
//! The `ChallengeLoader` is the primary interface for loading, managing,
//! and hot-reloading WASM challenge modules.

use crate::discovery::{ChallengeDiscovery, ChallengeUpdate, CompositeDiscovery, DiscoveredChallenge, FilesystemDiscovery, FilesystemDiscoveryConfig, P2PDiscovery};
use crate::error::{LoaderError, LoaderResult};
use crate::registry::{ChallengeInfo, ChallengeModule, ChallengeRegistry, LoadedChallenge};
use crate::versioning::{ChallengeVersion, VersionManager};
use parking_lot::RwLock;
use platform_core::{ChallengeConfig, ChallengeId};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Configuration for sandbox execution environment
#[derive(Clone, Debug)]
pub struct SandboxConfig {
    /// Maximum memory in MB
    pub max_memory_mb: u64,
    /// Maximum CPU time in seconds
    pub max_cpu_time_secs: u64,
    /// Enable network access
    pub allow_network: bool,
    /// Enable filesystem access
    pub allow_filesystem: bool,
    /// Custom environment variables
    pub env_vars: Vec<(String, String)>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            max_cpu_time_secs: 60,
            allow_network: false,
            allow_filesystem: false,
            env_vars: Vec::new(),
        }
    }
}

impl SandboxConfig {
    /// Create a restrictive sandbox configuration
    pub fn restrictive() -> Self {
        Self {
            max_memory_mb: 256,
            max_cpu_time_secs: 30,
            allow_network: false,
            allow_filesystem: false,
            env_vars: Vec::new(),
        }
    }

    /// Create a permissive sandbox configuration (for development)
    pub fn permissive() -> Self {
        Self {
            max_memory_mb: 2048,
            max_cpu_time_secs: 300,
            allow_network: true,
            allow_filesystem: true,
            env_vars: Vec::new(),
        }
    }
}

/// Configuration for the challenge loader
#[derive(Clone, Debug)]
pub struct LoaderConfig {
    /// Directory to watch for local challenges
    pub challenges_dir: Option<PathBuf>,
    /// Enable P2P discovery
    pub enable_p2p_discovery: bool,
    /// Maximum challenges to load
    pub max_challenges: usize,
    /// Default sandbox configuration
    pub sandbox_config: SandboxConfig,
    /// Enable auto-reload on file changes
    pub auto_reload: bool,
    /// File watch poll interval in milliseconds
    pub watch_poll_interval_ms: u64,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            challenges_dir: None,
            enable_p2p_discovery: false,
            max_challenges: 100,
            sandbox_config: SandboxConfig::default(),
            auto_reload: true,
            watch_poll_interval_ms: 5000,
        }
    }
}

impl LoaderConfig {
    /// Create a configuration for local development
    pub fn development(challenges_dir: PathBuf) -> Self {
        Self {
            challenges_dir: Some(challenges_dir),
            enable_p2p_discovery: false,
            max_challenges: 50,
            sandbox_config: SandboxConfig::permissive(),
            auto_reload: true,
            watch_poll_interval_ms: 2000,
        }
    }

    /// Create a configuration for production
    pub fn production() -> Self {
        Self {
            challenges_dir: None,
            enable_p2p_discovery: true,
            max_challenges: 1000,
            sandbox_config: SandboxConfig::restrictive(),
            auto_reload: false,
            watch_poll_interval_ms: 30000,
        }
    }
}

/// A stub WASM module implementation for when actual WASM runtime is not available
///
/// In a real implementation, this would be replaced by actual WASM compilation
/// and execution.
struct StubWasmModule {
    name: String,
    version: u32,
    code_hash: String,
}

impl ChallengeModule for StubWasmModule {
    fn evaluate(&self, _agent_data: &[u8]) -> LoaderResult<f64> {
        // In a real implementation, this would execute the WASM module
        warn!(
            name = %self.name,
            "Using stub WASM module - actual WASM runtime not implemented"
        );
        Ok(0.0)
    }

    fn validate(&self, _agent_data: &[u8]) -> LoaderResult<bool> {
        // In a real implementation, this would execute WASM validation
        Ok(true)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "code_hash": self.code_hash,
            "stub": true
        })
    }
}

/// Main challenge loader
///
/// Responsible for discovering, loading, and managing WASM challenge modules.
pub struct ChallengeLoader {
    /// Challenge registry
    registry: Arc<ChallengeRegistry>,
    /// Version manager
    version_manager: Arc<VersionManager>,
    /// Configuration
    config: LoaderConfig,
    /// Discovery sources
    discovery: Arc<RwLock<Option<CompositeDiscovery>>>,
    /// Whether discovery is running
    discovery_running: Arc<RwLock<bool>>,
}

impl ChallengeLoader {
    /// Create a new challenge loader with the given configuration
    pub fn new(config: LoaderConfig) -> LoaderResult<Self> {
        let registry = Arc::new(ChallengeRegistry::with_capacity(config.max_challenges));
        let version_manager = Arc::new(VersionManager::new());

        Ok(Self {
            registry,
            version_manager,
            config,
            discovery: Arc::new(RwLock::new(None)),
            discovery_running: Arc::new(RwLock::new(false)),
        })
    }

    /// Create a new loader with default configuration
    pub fn default_loader() -> LoaderResult<Self> {
        Self::new(LoaderConfig::default())
    }

    /// Load a challenge from WASM bytes
    ///
    /// # Arguments
    /// * `id` - Unique challenge identifier
    /// * `name` - Human-readable challenge name
    /// * `wasm_bytes` - Raw WASM bytecode
    /// * `config` - Challenge configuration
    ///
    /// # Returns
    /// The version number assigned to this challenge
    pub async fn load_challenge(
        &self,
        id: ChallengeId,
        name: String,
        wasm_bytes: Vec<u8>,
        config: ChallengeConfig,
    ) -> LoaderResult<u32> {
        // Validate WASM bytes (basic check)
        if wasm_bytes.is_empty() {
            return Err(LoaderError::InvalidChallenge(
                "WASM bytes cannot be empty".to_string(),
            ));
        }

        // Compute code hash
        let code_hash = hex::encode(Sha256::digest(&wasm_bytes));

        // Check if already loaded
        if self.registry.contains(&id) {
            return Err(LoaderError::AlreadyLoaded(format!(
                "Challenge {} is already loaded",
                id
            )));
        }

        // Compile WASM module (stub implementation)
        let module = self.compile_wasm(&name, 1, &code_hash, &wasm_bytes)?;

        // Register in version manager
        let version_record = ChallengeVersion::new(1, code_hash.clone(), wasm_bytes);
        let version = self.version_manager.register_version(id, version_record)?;
        self.version_manager.activate_version(&id, version)?;

        // Register in registry
        self.registry.register(
            id,
            name.clone(),
            version,
            code_hash.clone(),
            module,
            config,
        )?;

        info!(
            challenge_id = %id,
            name = %name,
            version = version,
            code_hash = %code_hash,
            "Challenge loaded successfully"
        );

        Ok(version)
    }

    /// Unload a challenge
    pub async fn unload_challenge(&self, id: &ChallengeId) -> LoaderResult<()> {
        // Remove from registry
        let challenge = self.registry.unregister(id)?;

        // Remove version history
        self.version_manager.remove_challenge(id)?;

        info!(
            challenge_id = %id,
            name = %challenge.name,
            "Challenge unloaded"
        );

        Ok(())
    }

    /// Get a loaded challenge
    pub fn get_challenge(&self, id: &ChallengeId) -> Option<LoadedChallenge> {
        self.registry.get(id)
    }

    /// Get a challenge module for evaluation
    pub fn get_module(&self, id: &ChallengeId) -> Option<Arc<dyn ChallengeModule>> {
        self.registry.get_module(id)
    }

    /// List all loaded challenges
    pub fn list_challenges(&self) -> Vec<ChallengeInfo> {
        self.registry.list()
    }

    /// List active challenges only
    pub fn list_active_challenges(&self) -> Vec<ChallengeInfo> {
        self.registry.list_active()
    }

    /// Get the number of loaded challenges
    pub fn challenge_count(&self) -> usize {
        self.registry.count()
    }

    /// Hot-reload a challenge with new WASM code
    ///
    /// This updates the challenge to a new version while preserving version history
    /// for potential rollback.
    pub async fn hot_reload(&self, id: &ChallengeId, new_wasm: Vec<u8>) -> LoaderResult<u32> {
        // Validate WASM bytes
        if new_wasm.is_empty() {
            return Err(LoaderError::InvalidChallenge(
                "WASM bytes cannot be empty".to_string(),
            ));
        }

        // Compute new code hash
        let new_code_hash = hex::encode(Sha256::digest(&new_wasm));

        // Get current challenge
        let current = self.registry.get(id).ok_or_else(|| {
            LoaderError::ChallengeNotFound(format!("Challenge {} not found", id))
        })?;

        // Check if code actually changed
        if current.code_hash == new_code_hash {
            debug!(
                challenge_id = %id,
                code_hash = %new_code_hash,
                "Hot-reload skipped: code unchanged"
            );
            return Ok(current.version);
        }

        // Determine new version
        let new_version = self
            .version_manager
            .latest_version(id)
            .map(|v| v + 1)
            .unwrap_or(1);

        // Compile new module
        let new_module = self.compile_wasm(&current.name, new_version, &new_code_hash, &new_wasm)?;

        // Update registry (stores old version in history)
        let old_version = self.registry.update(
            id,
            new_version,
            new_code_hash.clone(),
            new_module,
            new_wasm.clone(),
        )?;

        // Register new version
        let version_record = ChallengeVersion::new(new_version, new_code_hash.clone(), new_wasm);
        self.version_manager.register_version(*id, version_record)?;
        self.version_manager.activate_version(id, new_version)?;

        info!(
            challenge_id = %id,
            old_version = old_version,
            new_version = new_version,
            new_code_hash = %new_code_hash,
            "Challenge hot-reloaded"
        );

        Ok(new_version)
    }

    /// Rollback a challenge to a previous version
    pub async fn rollback(&self, id: &ChallengeId, to_version: u32) -> LoaderResult<()> {
        let version_data = self.version_manager.rollback(id, to_version)?;

        // Compile the old version
        let name = self
            .registry
            .get(id)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let module = self.compile_wasm(
            &name,
            version_data.version,
            &version_data.code_hash,
            &version_data.wasm_bytes,
        )?;

        // Update registry
        self.registry.update(
            id,
            version_data.version,
            version_data.code_hash.clone(),
            module,
            version_data.wasm_bytes,
        )?;

        self.version_manager.activate_version(id, to_version)?;

        info!(
            challenge_id = %id,
            rolled_back_to = to_version,
            "Challenge rolled back"
        );

        Ok(())
    }

    /// Start challenge discovery
    ///
    /// This initializes discovery sources and starts watching for new challenges.
    pub async fn start_discovery(&self) -> LoaderResult<()> {
        if *self.discovery_running.read() {
            debug!("Discovery already running");
            return Ok(());
        }

        let mut composite = CompositeDiscovery::new();

        // Add filesystem discovery if configured
        if let Some(ref dir) = self.config.challenges_dir {
            let fs_config = FilesystemDiscoveryConfig {
                watch_dir: dir.clone(),
                watch_enabled: self.config.auto_reload,
                poll_interval_ms: self.config.watch_poll_interval_ms,
                ..Default::default()
            };
            composite = composite.add_source(Arc::new(FilesystemDiscovery::new(fs_config)));
            debug!(dir = %dir.display(), "Added filesystem discovery source");
        }

        // Add P2P discovery if enabled
        if self.config.enable_p2p_discovery {
            composite = composite.add_source(Arc::new(P2PDiscovery::new(true)));
            debug!("Added P2P discovery source");
        }

        // Initial discovery
        let challenges = composite.discover().await?;
        for challenge in challenges {
            if let Err(e) = self.load_discovered_challenge(challenge).await {
                warn!(error = %e, "Failed to load discovered challenge");
            }
        }

        // Subscribe to updates
        let mut update_rx = composite.subscribe();
        let loader = self.clone_for_task();

        tokio::spawn(async move {
            while let Some(update) = update_rx.recv().await {
                if let Err(e) = loader.handle_discovery_update(update).await {
                    error!(error = %e, "Failed to handle discovery update");
                }
            }
        });

        // Start watching
        composite.start_watching().await?;

        *self.discovery.write() = Some(composite);
        *self.discovery_running.write() = true;

        info!(
            sources = self.discovery.read().as_ref().map(|d| d.source_count()).unwrap_or(0),
            "Challenge discovery started"
        );

        Ok(())
    }

    /// Stop challenge discovery
    pub async fn stop_discovery(&self) -> LoaderResult<()> {
        if let Some(ref discovery) = *self.discovery.read() {
            discovery.stop_watching().await?;
        }

        *self.discovery_running.write() = false;
        info!("Challenge discovery stopped");

        Ok(())
    }

    /// Check if discovery is running
    pub fn is_discovery_running(&self) -> bool {
        *self.discovery_running.read()
    }

    /// Get the challenge registry
    pub fn registry(&self) -> Arc<ChallengeRegistry> {
        self.registry.clone()
    }

    /// Get the version manager
    pub fn version_manager(&self) -> Arc<VersionManager> {
        self.version_manager.clone()
    }

    /// Get the current configuration
    pub fn config(&self) -> &LoaderConfig {
        &self.config
    }

    /// Load a discovered challenge
    async fn load_discovered_challenge(&self, challenge: DiscoveredChallenge) -> LoaderResult<()> {
        let wasm_bytes = challenge.wasm_bytes.ok_or_else(|| {
            LoaderError::InvalidChallenge("No WASM bytes in discovered challenge".to_string())
        })?;

        // Load config from file if available
        let config = if let Some(ref config_path) = challenge.config_path {
            self.load_config_file(config_path)?
        } else {
            ChallengeConfig::default()
        };

        self.load_challenge(challenge.id, challenge.name, wasm_bytes, config)
            .await?;

        Ok(())
    }

    /// Load challenge configuration from a JSON file
    fn load_config_file(&self, path: &PathBuf) -> LoaderResult<ChallengeConfig> {
        let content = std::fs::read_to_string(path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let config = ChallengeConfig {
            mechanism_id: json
                .get("mechanism_id")
                .and_then(|v| v.as_u64())
                .map(|v| v as u8)
                .unwrap_or(1),
            timeout_secs: json
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(300),
            max_memory_mb: json
                .get("max_memory_mb")
                .and_then(|v| v.as_u64())
                .unwrap_or(512),
            max_cpu_secs: json
                .get("max_cpu_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(60),
            emission_weight: json
                .get("emission_weight")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0),
            min_validators: json
                .get("min_validators")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(1),
            params_json: json
                .get("params")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "{}".to_string()),
        };

        Ok(config)
    }

    /// Handle a discovery update
    async fn handle_discovery_update(&self, update: ChallengeUpdate) -> LoaderResult<()> {
        match update {
            ChallengeUpdate::Added(challenge) => {
                info!(
                    challenge_id = %challenge.id,
                    name = %challenge.name,
                    source = %challenge.source,
                    "New challenge discovered"
                );
                self.load_discovered_challenge(challenge).await?;
            }
            ChallengeUpdate::Updated {
                id,
                new_version: _,
                new_code_hash: _,
                wasm_bytes,
            } => {
                if let Some(bytes) = wasm_bytes {
                    info!(challenge_id = %id, "Challenge update detected, hot-reloading");
                    self.hot_reload(&id, bytes).await?;
                }
            }
            ChallengeUpdate::Removed(id) => {
                info!(challenge_id = %id, "Challenge removal detected");
                if self.registry.contains(&id) {
                    self.unload_challenge(&id).await?;
                }
            }
        }

        Ok(())
    }

    /// Compile WASM bytes into a module
    ///
    /// This is a stub implementation that creates a placeholder module.
    /// In a real implementation, this would use a WASM runtime like wasmtime.
    fn compile_wasm(
        &self,
        name: &str,
        version: u32,
        code_hash: &str,
        _wasm_bytes: &[u8],
    ) -> LoaderResult<Arc<dyn ChallengeModule>> {
        // In a real implementation, this would:
        // 1. Validate the WASM module
        // 2. Compile it using wasmtime or similar
        // 3. Set up the sandbox environment
        // 4. Return a proper module implementation

        debug!(
            name = %name,
            version = version,
            code_hash = %code_hash,
            "Creating stub WASM module"
        );

        Ok(Arc::new(StubWasmModule {
            name: name.to_string(),
            version,
            code_hash: code_hash.to_string(),
        }))
    }

    /// Clone for spawning async tasks
    fn clone_for_task(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            version_manager: self.version_manager.clone(),
            config: self.config.clone(),
            discovery: self.discovery.clone(),
            discovery_running: self.discovery_running.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_wasm_bytes() -> Vec<u8> {
        // Minimal valid WASM module (just magic number + version)
        vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
    }

    #[tokio::test]
    async fn test_load_challenge() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        let version = loader
            .load_challenge(
                id,
                "test-challenge".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("load challenge");

        assert_eq!(version, 1);
        assert!(loader.get_challenge(&id).is_some());
        assert_eq!(loader.challenge_count(), 1);
    }

    #[tokio::test]
    async fn test_load_duplicate_fails() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        loader
            .load_challenge(
                id,
                "test".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("first load");

        let result = loader
            .load_challenge(
                id,
                "test".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await;

        assert!(matches!(result, Err(LoaderError::AlreadyLoaded(_))));
    }

    #[tokio::test]
    async fn test_load_empty_wasm_fails() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        let result = loader
            .load_challenge(
                id,
                "test".to_string(),
                vec![],
                ChallengeConfig::default(),
            )
            .await;

        assert!(matches!(result, Err(LoaderError::InvalidChallenge(_))));
    }

    #[tokio::test]
    async fn test_unload_challenge() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        loader
            .load_challenge(
                id,
                "test".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("load");

        assert!(loader.get_challenge(&id).is_some());

        loader.unload_challenge(&id).await.expect("unload");

        assert!(loader.get_challenge(&id).is_none());
        assert_eq!(loader.challenge_count(), 0);
    }

    #[tokio::test]
    async fn test_unload_nonexistent_fails() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        let result = loader.unload_challenge(&id).await;
        assert!(matches!(result, Err(LoaderError::ChallengeNotFound(_))));
    }

    #[tokio::test]
    async fn test_hot_reload() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        loader
            .load_challenge(
                id,
                "test".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("initial load");

        let challenge_v1 = loader.get_challenge(&id).expect("get v1");
        let hash_v1 = challenge_v1.code_hash.clone();

        // New WASM bytes
        let new_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0xFF];

        let new_version = loader.hot_reload(&id, new_wasm).await.expect("hot reload");

        assert_eq!(new_version, 2);

        let challenge_v2 = loader.get_challenge(&id).expect("get v2");
        assert_eq!(challenge_v2.version, 2);
        assert_ne!(challenge_v2.code_hash, hash_v1);
    }

    #[tokio::test]
    async fn test_hot_reload_same_code_skipped() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();
        let wasm = sample_wasm_bytes();

        loader
            .load_challenge(
                id,
                "test".to_string(),
                wasm.clone(),
                ChallengeConfig::default(),
            )
            .await
            .expect("load");

        let version = loader.hot_reload(&id, wasm).await.expect("reload same");

        assert_eq!(version, 1); // Should return same version
    }

    #[tokio::test]
    async fn test_list_challenges() {
        let loader = ChallengeLoader::default_loader().expect("create loader");

        for i in 0..3 {
            loader
                .load_challenge(
                    ChallengeId::new(),
                    format!("challenge-{}", i),
                    sample_wasm_bytes(),
                    ChallengeConfig::default(),
                )
                .await
                .expect("load");
        }

        let list = loader.list_challenges();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn test_list_active_challenges() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id1 = ChallengeId::new();
        let id2 = ChallengeId::new();

        loader
            .load_challenge(
                id1,
                "active".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("load");

        loader
            .load_challenge(
                id2,
                "inactive".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("load");

        loader.registry.set_active(&id2, false).expect("deactivate");

        let active = loader.list_active_challenges();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "active");
    }

    #[tokio::test]
    async fn test_get_module() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        loader
            .load_challenge(
                id,
                "test".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("load");

        let module = loader.get_module(&id).expect("get module");
        assert_eq!(module.name(), "test");
        assert_eq!(module.version(), 1);
    }

    #[test]
    fn test_sandbox_config_presets() {
        let default = SandboxConfig::default();
        assert_eq!(default.max_memory_mb, 512);
        assert!(!default.allow_network);

        let restrictive = SandboxConfig::restrictive();
        assert_eq!(restrictive.max_memory_mb, 256);
        assert!(!restrictive.allow_network);

        let permissive = SandboxConfig::permissive();
        assert_eq!(permissive.max_memory_mb, 2048);
        assert!(permissive.allow_network);
    }

    #[test]
    fn test_loader_config_presets() {
        let default = LoaderConfig::default();
        assert!(default.challenges_dir.is_none());
        assert!(!default.enable_p2p_discovery);

        let dev = LoaderConfig::development(PathBuf::from("/challenges"));
        assert!(dev.challenges_dir.is_some());
        assert!(dev.auto_reload);

        let prod = LoaderConfig::production();
        assert!(prod.enable_p2p_discovery);
        assert!(!prod.auto_reload);
    }

    #[tokio::test]
    async fn test_version_manager_integration() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        loader
            .load_challenge(
                id,
                "test".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("load");

        // Hot reload a few times
        for i in 0..3 {
            let wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, i as u8];
            loader.hot_reload(&id, wasm).await.expect("reload");
        }

        let vm = loader.version_manager();
        let latest = vm.latest_version(&id);
        assert_eq!(latest, Some(4));

        let active = vm.active_version(&id);
        assert_eq!(active, Some(4));
    }

    #[tokio::test]
    async fn test_rollback() {
        let loader = ChallengeLoader::default_loader().expect("create loader");
        let id = ChallengeId::new();

        // Load initial version
        loader
            .load_challenge(
                id,
                "test".to_string(),
                sample_wasm_bytes(),
                ChallengeConfig::default(),
            )
            .await
            .expect("load");

        // Hot reload to v2
        let new_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0xFF];
        loader.hot_reload(&id, new_wasm).await.expect("reload");

        // Rollback to v1
        loader.rollback(&id, 1).await.expect("rollback");

        let challenge = loader.get_challenge(&id).expect("get");
        assert_eq!(challenge.version, 1);
    }

    #[tokio::test]
    async fn test_discovery_lifecycle() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let config = LoaderConfig::development(temp_dir.path().to_path_buf());

        let loader = ChallengeLoader::new(config).expect("create loader");

        assert!(!loader.is_discovery_running());

        loader.start_discovery().await.expect("start discovery");
        assert!(loader.is_discovery_running());

        loader.stop_discovery().await.expect("stop discovery");
        assert!(!loader.is_discovery_running());
    }
}
