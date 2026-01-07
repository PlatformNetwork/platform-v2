//! WebSocket event types and broadcasting

use crate::models::WsEvent;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

pub type EventSender = broadcast::Sender<WsEvent>;
pub type EventReceiver = broadcast::Receiver<WsEvent>;

#[derive(Clone)]
pub struct WsConnection {
    pub id: Uuid,
    pub hotkey: Option<String>,
}

pub struct EventBroadcaster {
    sender: EventSender,
    connections: Arc<RwLock<HashMap<Uuid, WsConnection>>>,
}

impl EventBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn subscribe(&self) -> EventReceiver {
        self.sender.subscribe()
    }

    pub fn broadcast(&self, event: WsEvent) {
        let _ = self.sender.send(event);
    }

    pub fn add_connection(&self, conn: WsConnection) {
        self.connections.write().insert(conn.id, conn);
    }

    pub fn remove_connection(&self, id: &Uuid) {
        self.connections.write().remove(id);
    }

    pub fn connection_count(&self) -> usize {
        self.connections.read().len()
    }

    pub fn get_connections(&self) -> Vec<WsConnection> {
        self.connections.read().values().cloned().collect()
    }
}

impl Default for EventBroadcaster {
    fn default() -> Self {
        Self::new(1000)
    }
}
