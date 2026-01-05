//! Application state

use crate::challenge_proxy::ChallengeProxy;
use crate::db::DbPool;
use crate::models::{AuthSession, TaskLease, WsEvent};
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

    /// Get metrics for a specific validator (if within 5 min TTL)
    pub fn get(&self, hotkey: &str) -> Option<ValidatorMetrics> {
        let cache = self.metrics.read();
        cache.get(hotkey).and_then(|(m, instant)| {
            if instant.elapsed().as_secs() < 300 {
                Some(m.clone())
            } else {
                None
            }
        })
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

pub struct AppState {
    pub db: DbPool,
    pub challenge_id: Option<String>,
    pub sessions: DashMap<String, AuthSession>,
    pub broadcaster: Arc<EventBroadcaster>,
    pub owner_hotkey: Option<String>,
    pub challenge_proxy: Option<Arc<ChallengeProxy>>,
    /// Dynamic challenge manager
    pub challenge_manager: Option<Arc<ChallengeManager>>,
    /// Active task leases (task_id -> lease info)
    pub task_leases: DashMap<String, TaskLease>,
    /// Metagraph for validator stake lookups
    pub metagraph: RwLock<Option<Metagraph>>,
    /// Static validator whitelist (for testing without metagraph)
    pub validator_whitelist: RwLock<HashSet<String>>,
    /// In-memory cache for validator metrics
    pub metrics_cache: MetricsCache,
}

impl AppState {
    /// Legacy constructor for single challenge mode
    pub fn new(
        db: DbPool,
        challenge_id: String,
        owner_hotkey: Option<String>,
        challenge_proxy: Arc<ChallengeProxy>,
    ) -> Self {
        Self {
            db,
            challenge_id: Some(challenge_id),
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_proxy: Some(challenge_proxy),
            challenge_manager: None,
            task_leases: DashMap::new(),
            metagraph: RwLock::new(None),
            validator_whitelist: RwLock::new(HashSet::new()),
            metrics_cache: MetricsCache::new(),
        }
    }

    /// New constructor for dynamic orchestration mode
    pub fn new_dynamic(
        db: DbPool,
        owner_hotkey: Option<String>,
        challenge_manager: Option<Arc<ChallengeManager>>,
        metagraph: Option<Metagraph>,
    ) -> Self {
        Self {
            db,
            challenge_id: None,
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_proxy: None,
            challenge_manager,
            task_leases: DashMap::new(),
            metagraph: RwLock::new(metagraph),
            validator_whitelist: RwLock::new(HashSet::new()),
            metrics_cache: MetricsCache::new(),
        }
    }

    /// New constructor for dynamic orchestration mode with validator whitelist
    pub fn new_dynamic_with_whitelist(
        db: DbPool,
        owner_hotkey: Option<String>,
        challenge_manager: Option<Arc<ChallengeManager>>,
        metagraph: Option<Metagraph>,
        validator_whitelist: Vec<String>,
    ) -> Self {
        Self {
            db,
            challenge_id: None,
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_proxy: None,
            challenge_manager,
            task_leases: DashMap::new(),
            metagraph: RwLock::new(metagraph),
            validator_whitelist: RwLock::new(validator_whitelist.into_iter().collect()),
            metrics_cache: MetricsCache::new(),
        }
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

    /// Check if a validator is in the whitelist
    pub fn is_whitelisted(&self, hotkey: &str) -> bool {
        self.validator_whitelist.read().contains(hotkey)
    }

    /// Add validator to whitelist
    pub fn add_to_whitelist(&self, hotkey: String) {
        self.validator_whitelist.write().insert(hotkey);
    }

    /// Update metagraph
    pub fn set_metagraph(&self, metagraph: Metagraph) {
        *self.metagraph.write() = Some(metagraph);
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
