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
