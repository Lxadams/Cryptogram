use rand_core::{OsRng, RngCore};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

pub type SessionId = [u8; 4];
pub type RoutingToken = [u8; 16];
/// Random ID the relay gives each queued message. Sent to the recipient in
/// the 16-byte prefix of the forwarded packet, and echoed back in its ack.
pub type DeliveryId = [u8; 16];

/// Most messages kept for one recipient. Each chunk of a long message counts
/// as one (see code/client/src/chunks.rs), so this is a few dozen long
/// messages or a few hundred short ones.
pub const MAX_QUEUED_PER_TOKEN: usize = 512;

/// First resend of an unacknowledged message is this long after the first
/// send. Each later one waits twice as long, up to `MAX_RESEND_DELAY`.
const FIRST_RESEND_DELAY: Duration = Duration::from_secs(2);
const MAX_RESEND_DELAY: Duration = Duration::from_secs(60);

/// A sync after this much silence means the recipient was asleep or frozen
/// (clients sync every 15s while running), so anything still unacknowledged
/// is resent straight away instead of waiting out its backoff.
const SILENCE_BEFORE_RESEND: Duration = Duration::from_secs(30);

/// How long a fire-and-forget message waits for its recipient's first send.
const EPHEMERAL_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct MetadataEntry {
    pub incoming_addr: SocketAddr,
    pub session_id: SessionId,
    pub expiry: Instant,
    last_sync: Instant,
}

#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub receiver_token: RoutingToken,
    pub id: DeliveryId,
    pub payload: Vec<u8>,
    pub expiry: Instant,
    /// Sent once, never resent or acknowledged (presence pings).
    ephemeral: bool,
    next_attempt: Instant,
    attempts: u32,
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
        let now = Instant::now();
        let woke_up = match self.metadata.get(&token) {
            Some(prev) => {
                prev.incoming_addr != addr
                    || prev.session_id != session_id
                    || now.duration_since(prev.last_sync) > SILENCE_BEFORE_RESEND
            }
            None => true,
        };
        self.metadata.insert(
            token,
            MetadataEntry {
                incoming_addr: addr,
                session_id,
                expiry: now + ttl,
                last_sync: now,
            },
        );
        // Whatever we sent to its old address (or while it was asleep)
        // probably never arrived, so send it again now.
        if woke_up && let Some(queue) = self.message_queues.get_mut(&token) {
            for msg in queue.iter_mut() {
                msg.next_attempt = now;
            }
        }
    }

    /// Queue `payload` for `receiver_token` until the recipient acknowledges
    /// it (see `acknowledge`) or `ttl` runs out. Returns its delivery ID.
    pub fn enqueue_message(
        &mut self,
        receiver_token: RoutingToken,
        payload: Vec<u8>,
        ttl: Duration,
    ) -> DeliveryId {
        self.push(receiver_token, payload, ttl, false)
    }

    /// Queue `payload` for a single send, only if the recipient is reachable
    /// right now. For traffic that's useless late, like presence pings, and
    /// that would otherwise crowd real messages out of an offline
    /// recipient's queue.
    pub fn enqueue_ephemeral(&mut self, receiver_token: RoutingToken, payload: Vec<u8>) {
        if self.metadata.contains_key(&receiver_token) {
            self.push(receiver_token, payload, EPHEMERAL_TTL, true);
        }
    }

    fn push(
        &mut self,
        receiver_token: RoutingToken,
        payload: Vec<u8>,
        ttl: Duration,
        ephemeral: bool,
    ) -> DeliveryId {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let now = Instant::now();
        let queue = self.message_queues.entry(receiver_token).or_default();
        queue.push_back(OutboundMessage {
            receiver_token,
            id,
            payload,
            expiry: now + ttl,
            ephemeral,
            next_attempt: now,
            attempts: 0,
        });

        // Bounded queue to prevent DoS
        if queue.len() > MAX_QUEUED_PER_TOKEN {
            queue.pop_front();
        }
        id
    }

    /// Drop the messages `ids` from `token`'s queue, now that its recipient
    /// has them. Only that token's current link session may do this, so
    /// nobody else can delete someone's messages. Returns how many it
    /// dropped.
    pub fn acknowledge(
        &mut self,
        token: &RoutingToken,
        session_id: &SessionId,
        ids: &[DeliveryId],
    ) -> usize {
        match self.metadata.get(token) {
            Some(entry) if entry.session_id == *session_id => {}
            _ => return 0,
        }
        let Some(queue) = self.message_queues.get_mut(token) else {
            return 0;
        };
        let before = queue.len();
        queue.retain(|msg| !ids.contains(&msg.id));
        let removed = before - queue.len();
        if queue.is_empty() {
            self.message_queues.remove(token);
        }
        removed
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

    /// Messages due to be sent now to recipients with a known address. Each
    /// stays queued until acknowledged, with its next resend pushed back
    /// (see `FIRST_RESEND_DELAY`), except ephemeral ones, which are sent
    /// once and dropped.
    pub fn outbound_messages(&mut self) -> Vec<OutboundMessage> {
        let now = Instant::now();
        let mut ready = Vec::new();
        for token in self.metadata.keys() {
            let Some(queue) = self.message_queues.get_mut(token) else {
                continue;
            };
            for msg in queue.iter_mut().filter(|msg| msg.next_attempt <= now) {
                ready.push(msg.clone());
                msg.attempts += 1;
                msg.next_attempt = now + resend_delay(msg.attempts);
            }
            queue.retain(|msg| !(msg.ephemeral && msg.attempts > 0));
            if queue.is_empty() {
                self.message_queues.remove(token);
            }
        }
        ready
    }
}

/// Wait before the next resend of a message already sent `attempts` times.
fn resend_delay(attempts: u32) -> Duration {
    FIRST_RESEND_DELAY
        .saturating_mul(1 << attempts.saturating_sub(1).min(16))
        .min(MAX_RESEND_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: RoutingToken = [0xCC; 16];
    const SESSION: SessionId = [0xBB; 4];

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn online_tables() -> Tables {
        let mut tables = Tables::new();
        tables.update_metadata(TOKEN, addr(50000), SESSION, Duration::from_secs(60));
        tables
    }

    #[test]
    fn unacknowledged_message_is_resent_after_backoff() {
        let mut tables = online_tables();
        let id = tables.enqueue_message(TOKEN, b"hi".to_vec(), Duration::from_secs(60));

        let first = tables.outbound_messages();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, id);
        assert!(
            tables.outbound_messages().is_empty(),
            "not resent before its backoff"
        );
        assert_eq!(tables.get_queued_packets(&TOKEN).unwrap().len(), 1);

        // Pretend the backoff has passed.
        tables.message_queues.get_mut(&TOKEN).unwrap()[0].next_attempt = Instant::now();
        assert_eq!(tables.outbound_messages()[0].id, id);
    }

    #[test]
    fn ack_from_recipient_session_removes_message() {
        let mut tables = online_tables();
        let id = tables.enqueue_message(TOKEN, b"hi".to_vec(), Duration::from_secs(60));
        tables.outbound_messages();

        assert_eq!(
            tables.acknowledge(&TOKEN, &[0x99; 4], &[id]),
            0,
            "wrong session"
        );
        assert_eq!(
            tables.acknowledge(&TOKEN, &SESSION, &[[0u8; 16]]),
            0,
            "unknown id"
        );
        assert_eq!(tables.acknowledge(&TOKEN, &SESSION, &[id]), 1);
        assert!(tables.get_queued_packets(&TOKEN).is_none());
    }

    #[test]
    fn sync_after_silence_or_from_new_address_resends_immediately() {
        let mut tables = online_tables();
        tables.enqueue_message(TOKEN, b"hi".to_vec(), Duration::from_secs(60));
        tables.outbound_messages();

        // A routine keepalive from the same address doesn't skip the backoff.
        tables.update_metadata(TOKEN, addr(50000), SESSION, Duration::from_secs(60));
        assert!(tables.outbound_messages().is_empty());

        // A new address (e.g. the phone's NAT mapping changed) does.
        tables.update_metadata(TOKEN, addr(50001), SESSION, Duration::from_secs(60));
        assert_eq!(tables.outbound_messages().len(), 1);

        // So does a sync after a long silence.
        tables.metadata.get_mut(&TOKEN).unwrap().last_sync =
            Instant::now() - SILENCE_BEFORE_RESEND - Duration::from_secs(1);
        tables.update_metadata(TOKEN, addr(50001), SESSION, Duration::from_secs(60));
        assert_eq!(tables.outbound_messages().len(), 1);
    }

    #[test]
    fn ephemeral_is_dropped_when_offline_and_sent_once_when_online() {
        let mut tables = Tables::new();
        tables.enqueue_ephemeral(TOKEN, b"ping".to_vec());
        assert!(tables.get_queued_packets(&TOKEN).is_none());

        let mut tables = online_tables();
        tables.enqueue_ephemeral(TOKEN, b"ping".to_vec());
        assert_eq!(tables.outbound_messages().len(), 1);
        assert!(tables.get_queued_packets(&TOKEN).is_none());
    }

    #[test]
    fn resend_delay_doubles_up_to_cap() {
        assert_eq!(resend_delay(1), Duration::from_secs(2));
        assert_eq!(resend_delay(2), Duration::from_secs(4));
        assert_eq!(resend_delay(5), Duration::from_secs(32));
        assert_eq!(resend_delay(6), MAX_RESEND_DELAY);
        assert_eq!(resend_delay(u32::MAX), MAX_RESEND_DELAY);
    }
}
