//! State synchronization
//!
//! Synchronizes state between validators using:
//! - State root comparison
//! - Merkle proof exchange
//! - Missing data retrieval

use crate::{MerkleProof, MerkleTrie, RocksStorage, SyncData, SyncState};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Sync request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Get current state
    GetState,
    /// Get entries with state root
    GetEntries { state_root: [u8; 32] },
    /// Get specific key
    GetKey { collection: String, key: Vec<u8> },
    /// Get Merkle proof for key
    GetProof { key: Vec<u8> },
    /// Get missing keys (keys we have that peer doesn't)
    GetMissingKeys { our_keys: Vec<Vec<u8>> },
}

/// Sync response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Current state
    State(SyncState),
    /// Entries data
    Entries(SyncData),
    /// Single key value
    KeyValue(Option<Vec<u8>>),
    /// Merkle proof
    Proof(Option<MerkleProof>),
    /// Missing keys (keys we have that peer requested)
    MissingKeys(Vec<(String, Vec<u8>, Vec<u8>)>),
    /// Error
    Error(String),
}

/// Peer identifier (simplified without libp2p)
pub type PeerId = String;

/// State synchronizer
pub struct StateSynchronizer {
    /// Local storage
    storage: Arc<RocksStorage>,
    /// Merkle trie
    merkle: Arc<RwLock<MerkleTrie>>,
    /// Known peers and their state roots
    peer_states: Arc<RwLock<HashMap<PeerId, SyncState>>>,
    /// Pending sync requests
    pending_syncs: Arc<RwLock<HashMap<PeerId, SyncState>>>,
    /// Event sender
    event_tx: mpsc::UnboundedSender<SyncEvent>,
}

/// Sync event
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Peer state updated
    PeerStateUpdated { peer: PeerId, state: SyncState },
    /// Sync completed with peer
    SyncCompleted {
        peer: PeerId,
        entries_received: usize,
    },
    /// Sync failed
    SyncFailed { peer: PeerId, error: String },
    /// State divergence detected
    StateDivergence {
        peer: PeerId,
        our_root: [u8; 32],
        their_root: [u8; 32],
    },
}

impl StateSynchronizer {
    /// Create a new synchronizer
    pub fn new(
        storage: Arc<RocksStorage>,
        merkle: Arc<RwLock<MerkleTrie>>,
    ) -> (Self, mpsc::UnboundedReceiver<SyncEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        (
            Self {
                storage,
                merkle,
                peer_states: Arc::new(RwLock::new(HashMap::new())),
                pending_syncs: Arc::new(RwLock::new(HashMap::new())),
                event_tx,
            },
            event_rx,
        )
    }

    /// Handle incoming sync request
    pub fn handle_request(&self, request: SyncRequest) -> SyncResponse {
        match request {
            SyncRequest::GetState => {
                let root = self.merkle.read().root_hash();
                SyncResponse::State(SyncState {
                    state_root: root,
                    block_number: 0,
                    pending_count: 0,
                })
            }
            SyncRequest::GetEntries { state_root } => {
                let our_root = self.merkle.read().root_hash();
                if our_root == state_root {
                    return SyncResponse::Entries(SyncData {
                        state_root: our_root,
                        entries: Vec::new(),
                    });
                }

                let mut entries = Vec::new();
                if let Ok(collections) = self.storage.list_collections() {
                    for collection in collections {
                        if let Ok(items) = self.storage.iter_collection(&collection) {
                            for (key, value) in items {
                                entries.push((collection.clone(), key, value));
                            }
                        }
                    }
                }

                SyncResponse::Entries(SyncData {
                    state_root: our_root,
                    entries,
                })
            }
            SyncRequest::GetKey { collection, key } => match self.storage.get(&collection, &key) {
                Ok(value) => SyncResponse::KeyValue(value),
                Err(e) => SyncResponse::Error(e.to_string()),
            },
            SyncRequest::GetProof { key } => {
                let proof = self.merkle.read().generate_proof(&key);
                SyncResponse::Proof(proof)
            }
            SyncRequest::GetMissingKeys { our_keys } => {
                let mut missing = Vec::new();
                if let Ok(collections) = self.storage.list_collections() {
                    for collection in collections {
                        if let Ok(items) = self.storage.iter_collection(&collection) {
                            for (key, value) in items {
                                let full_key = format!("{}:{}", collection, hex::encode(&key));
                                if !our_keys.iter().any(|k| k == full_key.as_bytes()) {
                                    missing.push((collection.clone(), key, value));
                                }
                            }
                        }
                    }
                }

                SyncResponse::MissingKeys(missing)
            }
        }
    }

    /// Update peer state
    pub fn update_peer_state(&self, peer: PeerId, state: SyncState) {
        let our_root = self.merkle.read().root_hash();

        if state.state_root != our_root {
            let _ = self.event_tx.send(SyncEvent::StateDivergence {
                peer: peer.clone(),
                our_root,
                their_root: state.state_root,
            });

            self.pending_syncs
                .write()
                .insert(peer.clone(), state.clone());
        }

        self.peer_states.write().insert(peer.clone(), state.clone());
        let _ = self
            .event_tx
            .send(SyncEvent::PeerStateUpdated { peer, state });
    }

    /// Apply sync data from peer
    pub fn apply_sync_data(&self, peer: PeerId, data: SyncData) -> anyhow::Result<()> {
        let entries_count = data.entries.len();

        for (collection, key, value) in data.entries {
            self.storage.put(&collection, &key, &value)?;

            let full_key = format!("{}:{}", collection, hex::encode(&key));
            self.merkle.write().insert(full_key.as_bytes(), &value);
        }

        let _ = self.event_tx.send(SyncEvent::SyncCompleted {
            peer: peer.clone(),
            entries_received: entries_count,
        });

        self.pending_syncs.write().remove(&peer);

        Ok(())
    }

    /// Get peers that need sync
    pub fn peers_needing_sync(&self) -> Vec<(PeerId, SyncState)> {
        self.pending_syncs
            .read()
            .iter()
            .map(|(p, s)| (p.clone(), s.clone()))
            .collect()
    }

    /// Get all known peer states
    pub fn peer_states(&self) -> HashMap<PeerId, SyncState> {
        self.peer_states.read().clone()
    }

    /// Check if we're in sync with majority
    pub fn is_in_sync(&self) -> bool {
        let our_root = self.merkle.read().root_hash();
        let states = self.peer_states.read();

        if states.is_empty() {
            return true;
        }

        let matching = states.values().filter(|s| s.state_root == our_root).count();
        matching > states.len() / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sync_request_response() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(RocksStorage::open(dir.path()).unwrap());
        let merkle = Arc::new(RwLock::new(MerkleTrie::new()));

        let (sync, _rx) = StateSynchronizer::new(storage.clone(), merkle.clone());

        // Add some data
        storage.put("challenges", b"test", b"data").unwrap();
        merkle.write().insert(b"challenges:test", b"data");

        // Test GetState
        let response = sync.handle_request(SyncRequest::GetState);
        if let SyncResponse::State(state) = response {
            assert_ne!(state.state_root, [0u8; 32]);
        } else {
            panic!("Expected State response");
        }

        // Test GetKey
        let response = sync.handle_request(SyncRequest::GetKey {
            collection: "challenges".to_string(),
            key: b"test".to_vec(),
        });
        if let SyncResponse::KeyValue(Some(value)) = response {
            assert_eq!(value, b"data");
        } else {
            panic!("Expected KeyValue response");
        }
    }
}
