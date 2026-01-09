//! Application state

use crate::db::DbPool;
use crate::models::WsEvent;
use crate::orchestration::ChallengeManager;
use crate::websocket::events::EventBroadcaster;
use dashmap::DashMap;
use parking_lot::RwLock;
use platform_bittensor::Metagraph;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

/// System metrics from a validator
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorMetrics {
    pub cpu_percent: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub timestamp: i64,
}

/// In-memory cache for validator metrics (5 minute TTL)
pub struct MetricsCache {
    /// hotkey -> (metrics, last_update_instant)
    metrics: RwLock<HashMap<String, (ValidatorMetrics, Instant)>>,
}

impl MetricsCache {
    pub fn new() -> Self {
        Self {
            metrics: RwLock::new(HashMap::new()),
        }
    }

    /// Update metrics for a validator
    pub fn update(&self, hotkey: &str, metrics: ValidatorMetrics) {
        let mut cache = self.metrics.write();
        cache.insert(hotkey.to_string(), (metrics, Instant::now()));
        // Cleanup entries older than 5 minutes
        cache.retain(|_, (_, instant)| instant.elapsed().as_secs() < 300);
    }

    /// Get all valid metrics (within 5 min TTL)
    pub fn get_all(&self) -> Vec<(String, ValidatorMetrics)> {
        let cache = self.metrics.read();
        cache
            .iter()
            .filter(|(_, (_, instant))| instant.elapsed().as_secs() < 300)
            .map(|(k, (m, _))| (k.clone(), m.clone()))
            .collect()
    }
}

impl Default for MetricsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Default tempo (blocks per epoch) - Bittensor default
pub const DEFAULT_TEMPO: u64 = 360;

pub struct AppState {
    pub db: DbPool,
    pub sessions: DashMap<String, crate::models::AuthSession>,
    pub broadcaster: Arc<EventBroadcaster>,
    pub owner_hotkey: Option<String>,
    /// Dynamic challenge manager
    pub challenge_manager: Option<Arc<ChallengeManager>>,
    /// Metagraph for validator stake lookups
    pub metagraph: RwLock<Option<Metagraph>>,
    /// Static validator whitelist (for testing without metagraph)
    pub validator_whitelist: RwLock<HashSet<String>>,
    /// In-memory cache for validator metrics
    pub metrics_cache: MetricsCache,
    /// Cached tempo (blocks per epoch) from Bittensor
    pub tempo: RwLock<u64>,
    /// Current block number from Bittensor
    pub current_block: RwLock<u64>,
}

impl AppState {
    /// Constructor for dynamic orchestration mode
    #[allow(dead_code)] // Used by bins/platform
    pub fn new_dynamic(
        db: DbPool,
        owner_hotkey: Option<String>,
        challenge_manager: Option<Arc<ChallengeManager>>,
        metagraph: Option<Metagraph>,
    ) -> Self {
        Self {
            db,
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_manager,
            metagraph: RwLock::new(metagraph),
            validator_whitelist: RwLock::new(HashSet::new()),
            metrics_cache: MetricsCache::new(),
            tempo: RwLock::new(DEFAULT_TEMPO),
            current_block: RwLock::new(0),
        }
    }

    /// Constructor for dynamic orchestration mode with validator whitelist
    pub fn new_dynamic_with_whitelist(
        db: DbPool,
        owner_hotkey: Option<String>,
        challenge_manager: Option<Arc<ChallengeManager>>,
        metagraph: Option<Metagraph>,
        validator_whitelist: Vec<String>,
    ) -> Self {
        Self {
            db,
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_manager,
            metagraph: RwLock::new(metagraph),
            validator_whitelist: RwLock::new(validator_whitelist.into_iter().collect()),
            metrics_cache: MetricsCache::new(),
            tempo: RwLock::new(DEFAULT_TEMPO),
            current_block: RwLock::new(0),
        }
    }

    /// Set tempo (called when syncing with Bittensor)
    pub fn set_tempo(&self, tempo: u64) {
        *self.tempo.write() = tempo;
    }

    /// Get cached tempo
    pub fn get_tempo(&self) -> u64 {
        *self.tempo.read()
    }

    /// Set current block
    pub fn set_current_block(&self, block: u64) {
        *self.current_block.write() = block;
    }

    /// Get current block
    pub fn get_current_block(&self) -> u64 {
        *self.current_block.read()
    }

    /// Get validator stake from metagraph (returns 0 if not found)
    /// If validator is in whitelist, returns a high stake value (for testing)
    pub fn get_validator_stake(&self, hotkey: &str) -> u64 {
        // First check whitelist (for testing without metagraph)
        {
            let whitelist = self.validator_whitelist.read();
            if whitelist.contains(hotkey) {
                // Return high stake for whitelisted validators (100k TAO equivalent)
                return 100_000_000_000_000; // 100k TAO in RAO
            }
        }

        // Then check metagraph
        use sp_core::crypto::Ss58Codec;
        let mg = self.metagraph.read();
        if let Some(ref metagraph) = *mg {
            for (_uid, neuron) in &metagraph.neurons {
                if neuron.hotkey.to_ss58check() == hotkey {
                    // Stake is u128, convert to u64 (saturating)
                    return neuron.stake.min(u64::MAX as u128) as u64;
                }
            }
        }
        0
    }

    pub async fn broadcast_event(&self, event: WsEvent) {
        self.broadcaster.broadcast(event);
    }

    pub fn is_owner(&self, hotkey: &str) -> bool {
        self.owner_hotkey
            .as_ref()
            .map(|o| o == hotkey)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuthRole, AuthSession};

    #[test]
    fn test_validator_metrics_cache_new() {
        let cache = MetricsCache::new();
        let metrics = cache.get_all();
        assert_eq!(metrics.len(), 0);
    }

    #[test]
    fn test_validator_metrics_cache_update_and_get() {
        let cache = MetricsCache::new();
        let metrics = ValidatorMetrics {
            cpu_percent: 50.0,
            memory_used_mb: 1024,
            memory_total_mb: 4096,
            timestamp: 1234567890,
        };

        cache.update("hotkey1", metrics.clone());
        let all_metrics = cache.get_all();

        assert_eq!(all_metrics.len(), 1);
        assert_eq!(all_metrics[0].0, "hotkey1");
        assert_eq!(all_metrics[0].1.cpu_percent, 50.0);
        assert_eq!(all_metrics[0].1.memory_used_mb, 1024);
    }

    #[test]
    fn test_validator_metrics_cache_multiple_validators() {
        let cache = MetricsCache::new();

        let metrics1 = ValidatorMetrics {
            cpu_percent: 50.0,
            memory_used_mb: 1024,
            memory_total_mb: 4096,
            timestamp: 1234567890,
        };

        let metrics2 = ValidatorMetrics {
            cpu_percent: 75.0,
            memory_used_mb: 2048,
            memory_total_mb: 8192,
            timestamp: 1234567891,
        };

        cache.update("hotkey1", metrics1);
        cache.update("hotkey2", metrics2);

        let all_metrics = cache.get_all();
        assert_eq!(all_metrics.len(), 2);
    }

    #[test]
    fn test_validator_metrics_cache_update_existing() {
        let cache = MetricsCache::new();

        let metrics1 = ValidatorMetrics {
            cpu_percent: 50.0,
            memory_used_mb: 1024,
            memory_total_mb: 4096,
            timestamp: 1234567890,
        };

        let metrics2 = ValidatorMetrics {
            cpu_percent: 60.0,
            memory_used_mb: 2048,
            memory_total_mb: 4096,
            timestamp: 1234567891,
        };

        cache.update("hotkey1", metrics1);
        cache.update("hotkey1", metrics2);

        let all_metrics = cache.get_all();
        assert_eq!(all_metrics.len(), 1);
        assert_eq!(all_metrics[0].1.cpu_percent, 60.0);
        assert_eq!(all_metrics[0].1.memory_used_mb, 2048);
    }

    #[test]
    fn test_metrics_cache_default() {
        let cache = MetricsCache::default();
        let metrics = cache.get_all();
        assert_eq!(metrics.len(), 0);
    }

    #[test]
    fn test_default_tempo() {
        assert_eq!(DEFAULT_TEMPO, 360);
    }

    #[test]
    fn test_app_state_tempo_operations() {
        let state = create_test_state();
        
        // Default tempo
        assert_eq!(state.get_tempo(), DEFAULT_TEMPO);

        // Set and get tempo
        state.set_tempo(500);
        assert_eq!(state.get_tempo(), 500);

        state.set_tempo(1000);
        assert_eq!(state.get_tempo(), 1000);
    }

    #[test]
    fn test_app_state_current_block_operations() {
        let state = create_test_state();

        // Default block
        assert_eq!(state.get_current_block(), 0);

        // Set and get block
        state.set_current_block(100);
        assert_eq!(state.get_current_block(), 100);

        state.set_current_block(500);
        assert_eq!(state.get_current_block(), 500);
    }

    #[test]
    fn test_app_state_validator_stake_whitelist() {
        let state = create_test_state_with_whitelist(vec!["validator1".to_string()]);

        // Whitelisted validator should have high stake
        let stake = state.get_validator_stake("validator1");
        assert_eq!(stake, 100_000_000_000_000);

        // Non-whitelisted validator should have 0 stake
        let stake = state.get_validator_stake("validator2");
        assert_eq!(stake, 0);
    }

    #[test]
    fn test_app_state_validator_stake_no_metagraph() {
        let state = create_test_state();

        // Without metagraph or whitelist, stake should be 0
        let stake = state.get_validator_stake("any_validator");
        assert_eq!(stake, 0);
    }

    #[test]
    fn test_app_state_is_owner() {
        let state = create_test_state_with_owner("owner_hotkey".to_string());

        assert!(state.is_owner("owner_hotkey"));
        assert!(!state.is_owner("other_hotkey"));
    }

    #[test]
    fn test_app_state_is_owner_none() {
        let state = create_test_state();

        assert!(!state.is_owner("any_hotkey"));
    }

    #[test]
    fn test_app_state_sessions() {
        let state = create_test_state();

        // Sessions should be empty initially
        assert_eq!(state.sessions.len(), 0);

        // Insert a session
        state.sessions.insert(
            "token1".to_string(),
            AuthSession {
                hotkey: "validator1".to_string(),
                role: AuthRole::Validator,
                expires_at: 9999999999,
            },
        );

        assert_eq!(state.sessions.len(), 1);
        assert!(state.sessions.contains_key("token1"));
    }

    // Helper functions for tests
    fn create_test_pool() -> crate::db::DbPool {
        use deadpool_postgres::{Config, Runtime};
        use tokio_postgres::NoTls;

        let mut cfg = Config::new();
        cfg.url = Some("postgresql://localhost/test".to_string());
        cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }

    fn create_test_state() -> AppState {
        AppState::new_dynamic(create_test_pool(), None, None, None)
    }

    fn create_test_state_with_whitelist(whitelist: Vec<String>) -> AppState {
        AppState::new_dynamic_with_whitelist(create_test_pool(), None, None, None, whitelist)
    }

    fn create_test_state_with_owner(owner: String) -> AppState {
        AppState::new_dynamic(create_test_pool(), Some(owner), None, None)
    }
}
