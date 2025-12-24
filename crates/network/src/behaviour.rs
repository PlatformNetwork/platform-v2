//! Network behaviour combining gossipsub and request-response

use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identify, mdns,
    request_response::{self, ProtocolSupport},
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour},
    StreamProtocol,
};
use std::time::Duration;

use crate::protocol::GOSSIP_TOPIC;

/// Combined network behaviour
#[derive(NetworkBehaviour)]
pub struct MiniChainBehaviour {
    /// Gossipsub for broadcast messages
    pub gossipsub: gossipsub::Behaviour,

    /// mDNS for local peer discovery (optional, disabled by default)
    pub mdns: Toggle<mdns::tokio::Behaviour>,

    /// Identify protocol
    pub identify: identify::Behaviour,

    /// Request-response for direct messages
    pub request_response: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
}

impl MiniChainBehaviour {
    /// Create new behaviour with optional hotkey for identify protocol
    /// If hotkey is provided, it will be included in agent_version for stake validation
    pub fn new(local_key: &libp2p::identity::Keypair, enable_mdns: bool) -> anyhow::Result<Self> {
        Self::with_hotkey(local_key, enable_mdns, None)
    }

    /// Create new behaviour with hotkey for stake validation
    pub fn with_hotkey(
        local_key: &libp2p::identity::Keypair,
        enable_mdns: bool,
        hotkey: Option<&str>,
    ) -> anyhow::Result<Self> {
        // Gossipsub configuration with peer exchange enabled
        // Supports up to 64 validators in the network
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .mesh_n(6) // Target mesh size
            .mesh_n_low(1) // Allow mesh with just 1 peer (important for small networks)
            .mesh_n_high(12) // Maximum mesh size before pruning
            .mesh_outbound_min(0) // No outbound requirement (bootnode has only inbound connections)
            .gossip_lazy(6) // Peers to gossip to outside mesh
            .gossip_factor(0.25) // Fraction of peers to gossip to
            .do_px() // Enable peer exchange on PRUNE for discovery
            .flood_publish(true) // Send to ALL peers when mesh is low/empty
            .prune_backoff(Duration::from_secs(30)) // Backoff before re-grafting after PRUNE
            .message_id_fn(|msg| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&msg.data, &mut hasher);
                std::hash::Hash::hash(&msg.source, &mut hasher);
                gossipsub::MessageId::from(std::hash::Hasher::finish(&hasher).to_string())
            })
            .build()
            .map_err(|e| anyhow::anyhow!("Gossipsub config error: {}", e))?;

        let gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| anyhow::anyhow!("Gossipsub error: {}", e))?;

        // mDNS for local discovery (optional)
        let mdns = if enable_mdns {
            Toggle::from(Some(mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                local_key.public().to_peer_id(),
            )?))
        } else {
            Toggle::from(None)
        };

        // Identify protocol - include hotkey in agent_version for stake validation
        let agent_version = match hotkey {
            Some(hk) => format!("platform-validator/1.0.0/{}", hk),
            None => "platform-validator/1.0.0".to_string(),
        };
        let identify_config =
            identify::Config::new("/platform/id/1.0.0".into(), local_key.public())
                .with_agent_version(agent_version);
        let identify = identify::Behaviour::new(identify_config);

        // Request-response for sync
        let request_response = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/platform/sync/1.0.0"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );

        Ok(Self {
            gossipsub,
            mdns,
            identify,
            request_response,
        })
    }

    /// Subscribe to the gossip topic
    pub fn subscribe(&mut self) -> anyhow::Result<()> {
        let topic = IdentTopic::new(GOSSIP_TOPIC);
        self.gossipsub
            .subscribe(&topic)
            .map_err(|e| anyhow::anyhow!("Subscribe error: {:?}", e))?;
        Ok(())
    }

    /// Publish a message to the gossip topic
    pub fn publish(&mut self, data: Vec<u8>) -> anyhow::Result<()> {
        let topic = IdentTopic::new(GOSSIP_TOPIC);
        self.gossipsub
            .publish(topic, data)
            .map_err(|e| anyhow::anyhow!("Publish error: {:?}", e))?;
        Ok(())
    }

    /// Get the number of peers in the mesh for our topic
    pub fn mesh_peer_count(&self) -> usize {
        let topic = gossipsub::IdentTopic::new(GOSSIP_TOPIC);
        self.gossipsub.mesh_peers(&topic.hash()).count()
    }

    /// Get all peers subscribed to our topic (including those not in mesh)
    pub fn topic_peer_count(&self) -> usize {
        let topic_hash = gossipsub::IdentTopic::new(GOSSIP_TOPIC).hash();
        self.gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.iter().any(|t| **t == topic_hash))
            .count()
    }

    /// Force re-subscribe to refresh SUBSCRIBE messages to all peers
    /// This is useful when new peers join and don't receive our subscription
    pub fn refresh_subscription(&mut self) -> anyhow::Result<()> {
        let topic = IdentTopic::new(GOSSIP_TOPIC);
        // Unsubscribe and re-subscribe to force sending SUBSCRIBE to all peers
        let _ = self.gossipsub.unsubscribe(&topic);
        self.gossipsub
            .subscribe(&topic)
            .map_err(|e| anyhow::anyhow!("Re-subscribe error: {:?}", e))?;
        Ok(())
    }

    /// Add a peer to the mesh by sending GRAFT
    /// Note: This only works if the peer is already subscribed to the topic
    pub fn add_peer_to_mesh(&mut self, peer_id: &libp2p::PeerId) {
        // Add as explicit peer temporarily to force mesh inclusion
        // Then remove to allow normal mesh behavior
        self.gossipsub.add_explicit_peer(peer_id);
    }

    /// Remove explicit peer status (allows normal mesh behavior)
    pub fn remove_explicit_peer(&mut self, peer_id: &libp2p::PeerId) {
        self.gossipsub.remove_explicit_peer(peer_id);
    }
}

/// Sync request message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SyncRequest {
    /// Request full state
    FullState,

    /// Request state snapshot
    Snapshot,

    /// Request specific challenge
    Challenge { id: String },

    /// Request validators list
    Validators,
}

/// Sync response message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SyncResponse {
    /// Full state data
    FullState { data: Vec<u8> },

    /// State snapshot
    Snapshot { data: Vec<u8> },

    /// Challenge data
    Challenge { data: Option<Vec<u8>> },

    /// Validators list
    Validators { data: Vec<u8> },

    /// Error response
    Error { message: String },
}
