use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

pub type SessionId = [u8; 4];
pub type RoutingToken = [u8; 16];

/// Payload bytes held per recipient token. Clients send each message as a
/// burst of FEC packets (~7 KB for a short one, up to ~330 KB for the
/// longest), so this holds a few hundred short messages for an offline
/// recipient. Bounded so one token can't eat the relay's RAM.
pub const MAX_QUEUED_BYTES_PER_TOKEN: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct MetadataEntry {
    pub incoming_addr: SocketAddr,
    pub session_id: SessionId,
    pub expiry: Instant,
}

#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub payload: Vec<u8>,
    pub expiry: Instant,
}

/// A recipient's queued packets, and when the relay may send them the next
/// one (see `Tables::take_due`).
#[derive(Default)]
struct TokenQueue {
    packets: VecDeque<OutboundMessage>,
    bytes: usize,
    next_send: Option<Instant>,
}

/// A packet `take_due` released for sending: where to, and on which link.
pub struct DuePacket {
    pub addr: SocketAddr,
    pub session_id: SessionId,
    pub payload: Vec<u8>,
}

pub struct Tables {
    pub active_links: HashMap<SessionId, ([u8; 32], Instant)>,
    metadata: HashMap<RoutingToken, MetadataEntry>,
    message_queues: HashMap<RoutingToken, TokenQueue>,
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

    /// Queue a packet for `receiver_token`. Once the token's queue is full
    /// (`MAX_QUEUED_BYTES_PER_TOKEN`), new packets are refused rather than
    /// old ones evicted: evicting would keep cutting the front off whole
    /// queued messages, and losing an older one that carries a PQ ratchet
    /// update leaves every later one undecryptable anyway. Returns whether
    /// it was queued.
    pub fn enqueue_message(
        &mut self,
        receiver_token: RoutingToken,
        payload: Vec<u8>,
        ttl: Duration,
    ) -> bool {
        let queue = self.message_queues.entry(receiver_token).or_default();
        if queue.bytes + payload.len() > MAX_QUEUED_BYTES_PER_TOKEN {
            return false;
        }
        queue.bytes += payload.len();
        queue.packets.push_back(OutboundMessage {
            payload,
            expiry: Instant::now() + ttl,
        });
        true
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
            queue.packets.retain(|msg| msg.expiry > now);
            queue.bytes = queue.packets.iter().map(|msg| msg.payload.len()).sum();
        }
        self.message_queues
            .retain(|_, queue| !queue.packets.is_empty());
    }

    #[allow(dead_code)]
    pub fn get_metadata(&self, token: &RoutingToken) -> Option<&MetadataEntry> {
        self.metadata.get(token)
    }

    #[allow(dead_code)]
    pub fn metadata_iter(&self) -> impl Iterator<Item = (&RoutingToken, &MetadataEntry)> {
        self.metadata.iter()
    }

    #[allow(dead_code)]
    pub fn get_queued_packets(&self, token: &RoutingToken) -> Option<&VecDeque<OutboundMessage>> {
        self.message_queues
            .get(token)
            .map(|queue| &queue.packets)
            .filter(|packets| !packets.is_empty())
    }

    /// Release at most one queued packet per online recipient whose pacing
    /// slot has come round, then schedule its next slot `spacing` later —
    /// so a backlog (a recipient coming back online) is paced out rather
    /// than blasted at line rate, while a live burst passes straight
    /// through. Also returns when the next slot falls due, if anything is
    /// still waiting for an online recipient. Only tokens with something
    /// queued are looked at.
    pub fn take_due(
        &mut self,
        now: Instant,
        spacing: Duration,
    ) -> (Vec<DuePacket>, Option<Instant>) {
        let mut due = Vec::new();
        let mut next_due: Option<Instant> = None;
        for (token, queue) in &mut self.message_queues {
            let Some(metadata) = self.metadata.get(token) else {
                continue; // offline: keep it queued
            };
            if queue.next_send.is_none_or(|at| at <= now) {
                let Some(packet) = queue.packets.pop_front() else {
                    continue;
                };
                queue.bytes -= packet.payload.len();
                queue.next_send = Some(now + spacing);
                due.push(DuePacket {
                    addr: metadata.incoming_addr,
                    session_id: metadata.session_id,
                    payload: packet.payload,
                });
            }
            if !queue.packets.is_empty() {
                let at = queue.next_send.unwrap_or(now);
                next_due = Some(next_due.map_or(at, |n| n.min(at)));
            }
        }
        self.message_queues.retain(|_, queue| {
            !queue.packets.is_empty() || queue.next_send.is_some_and(|at| at > now)
        });
        (due, next_due)
    }
}
