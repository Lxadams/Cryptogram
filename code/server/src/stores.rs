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
    pub active_links: HashMap<SessionId, ([u8; 32], Instant)>,
    metadata: HashMap<RoutingToken, MetadataEntry>,
    message_queues: HashMap<RoutingToken, VecDeque<OutboundMessage>>,
}

impl Tables {
    pub fn new() -> Self {
        Self {
            active_links: HashMap::new(),
            metadata: HashMap::new(),
            message_queues: HashMap::new(),
        }
    }

    pub fn register_link(&mut self, session_id: SessionId, link_key: [u8; 32]) {
        self.active_links.insert(
            session_id,
            (link_key, Instant::now() + Duration::from_secs(3600)),
        );
    }

    pub fn get_link_key(&self, session_id: &SessionId) -> Option<&[u8; 32]> {
        self.active_links.get(session_id).map(|(k, _)| k)
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
        let queue = self
            .message_queues
            .entry(receiver_token)
            .or_default();
        queue.push_back(OutboundMessage {
            receiver_token,
            payload,
            expiry: Instant::now() + ttl,
        });

        // Bounded queue to prevent DoS (max 50 messages per token)
        if queue.len() > 50 {
            queue.pop_front();
        }
    }

    pub fn sweep_active_links(&mut self) {
        let now = Instant::now();
        self.active_links.retain(|_, (_, expiry)| *expiry > now);
    }

    pub fn sweep_metadata(&mut self) {
        let now = Instant::now();
        self.metadata.retain(|_, entry| entry.expiry > now);
    }

    pub fn sweep_expired_messages(&mut self) {
        let now = Instant::now();
        for queue in self.message_queues.values_mut() {
            queue.retain(|msg| msg.expiry > now);
        }
        self.message_queues.retain(|_, queue| !queue.is_empty());
    }

    pub fn get_metadata(&self, token: &RoutingToken) -> Option<&MetadataEntry> {
        self.metadata.get(token)
    }

    #[allow(dead_code)]
    pub fn metadata_iter(&self) -> impl Iterator<Item = (&RoutingToken, &MetadataEntry)> {
        self.metadata.iter()
    }

    #[allow(dead_code)]
    pub fn get_queued_packets(&self, token: &RoutingToken) -> Option<&VecDeque<OutboundMessage>> {
        self.message_queues.get(token)
    }

    pub fn outbound_messages(&mut self) -> Vec<OutboundMessage> {
        let mut ready = Vec::new();
        for token in self.metadata.keys() {
            if let Some(mut queue) = self.message_queues.remove(token) {
                ready.extend(queue.drain(..));
            }
        }
        ready
    }
}
