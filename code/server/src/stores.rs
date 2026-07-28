use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

pub type SessionId = [u8; 4];
pub type RoutingToken = [u8; 16];

#[derive(Debug, Clone)]
pub struct MetadataEntry {
    pub incoming_addr: SocketAddr,
    pub session_id: SessionId,
    pub expiry: Instant,
}

#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub receiver_token: RoutingToken,
    pub payload: Vec<u8>,
    pub expiry: Instant,
}

pub struct Tables {
    pub active_links: HashMap<SessionId, [u8; 32]>,
    metadata: HashMap<RoutingToken, MetadataEntry>,
    outbound_queue: VecDeque<OutboundMessage>,
}

impl Tables {
    pub fn new() -> Self {
        Self {
            active_links: HashMap::new(),
            metadata: HashMap::new(),
            outbound_queue: VecDeque::new(),
        }
    }

    pub fn register_link(&mut self, session_id: SessionId, link_key: [u8; 32]) {
        self.active_links.insert(session_id, link_key);
    }

    pub fn get_link_key(&self, session_id: &SessionId) -> Option<&[u8; 32]> {
        self.active_links.get(session_id)
    }

    pub fn update_metadata(
        &mut self,
        token: RoutingToken,
        addr: SocketAddr,
        session_id: SessionId,
        ttl: Duration,
    ) {
        self.metadata.insert(
            token,
            MetadataEntry {
                incoming_addr: addr,
                session_id,
                expiry: Instant::now() + ttl,
            },
        );
    }

    pub fn enqueue_message(
        &mut self,
        receiver_token: RoutingToken,
        payload: Vec<u8>,
        ttl: Duration,
    ) {
        self.outbound_queue.push_back(OutboundMessage {
            receiver_token,
            payload,
            expiry: Instant::now() + ttl,
        });
    }

    pub fn sweep_metadata(&mut self) {
        let now = Instant::now();
        self.metadata.retain(|_, entry| entry.expiry > now);
    }

    pub fn sweep_expired_messages(&mut self) {
        let now = Instant::now();
        self.outbound_queue.retain(|msg| msg.expiry > now);
    }

    pub fn get_metadata(&self, token: &RoutingToken) -> Option<&MetadataEntry> {
        self.metadata.get(token)
    }

    pub fn metadata_iter(&self) -> impl Iterator<Item = (&RoutingToken, &MetadataEntry)> {
        self.metadata.iter()
    }

    pub fn outbound_messages(&self) -> Vec<OutboundMessage> {
        self.outbound_queue.iter().cloned().collect()
    }
}
