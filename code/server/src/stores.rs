use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

pub type SessionId = String;

#[derive(Debug, Clone)]
pub struct MetadataEntry {
    pub incoming_addr: SocketAddr,
    pub expiry: Instant,
}

#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub receiver_session_id: SessionId,
    pub payload: Vec<u8>,
    pub expiry: Instant,
}

pub struct Tables {
    metadata: HashMap<SessionId, MetadataEntry>,
    outbound_queue: VecDeque<OutboundMessage>,
}

impl Tables {
    pub fn new() -> Self {
        Self {
            metadata: HashMap::new(),
            outbound_queue: VecDeque::new(),
        }
    }

    /// Sync request
    pub fn update_metadata(
        &mut self,
        session_id: SessionId,
        addr: SocketAddr,
        ttl: Duration,
    ) {
        self.metadata.insert(
            session_id,
            MetadataEntry {
                incoming_addr: addr,
                expiry: Instant::now() + ttl,
            },
        );
    }

    /// Forward request
    pub fn enqueue_message(
        &mut self,
        receiver: SessionId,
        payload: Vec<u8>,
        ttl: Duration,
    ) {
        self.outbound_queue.push_back(OutboundMessage {
            receiver_session_id: receiver,
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

    pub fn dequeue_message(&mut self) -> Option<OutboundMessage> {
        self.outbound_queue.pop_front()
    }

    pub fn get_metadata(
        &self,
        session_id: &SessionId,
    ) -> Option<&MetadataEntry> {
        self.metadata.get(session_id)
    }

    pub fn metadata_iter(
        &self,
    ) -> impl Iterator<Item = (&SessionId, &MetadataEntry)> {
        self.metadata.iter()
    }
}