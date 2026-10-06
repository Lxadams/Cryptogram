use rand_core::{OsRng, RngCore};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

pub type SessionId = [u8; 4];
pub type RoutingToken = [u8; 16];
/// Random ID the relay gives each queued packet. Sent to the recipient in
/// the 16-byte prefix of the forwarded packet, and echoed back in its ack.
pub type DeliveryId = [u8; 16];

/// Payload bytes held per recipient token. Clients send each message as a
/// burst of FEC packets (~7 KB for a short one, up to ~330 KB for the
/// longest), so this holds a few hundred short messages for an offline
/// recipient. Bounded so one token can't eat the relay's RAM.
pub const MAX_QUEUED_BYTES_PER_TOKEN: usize = 2 * 1024 * 1024;

/// A packet stays queued until its recipient acknowledges it (see
/// `Tables::acknowledge`). The first resend comes this long after the first
/// send, and each later one waits twice as long, up to `MAX_RESEND_DELAY`.
pub const FIRST_RESEND_DELAY: Duration = Duration::from_secs(2);
const MAX_RESEND_DELAY: Duration = Duration::from_secs(60);

/// A sync after this much silence means the recipient was asleep or frozen
/// (clients sync every 15s while running), so anything still unacknowledged
/// is resent straight away instead of waiting out its backoff.
const SILENCE_BEFORE_RESEND: Duration = Duration::from_secs(30);

/// How long a fire-and-forget packet waits for its recipient's pacing slot.
const EPHEMERAL_TTL: Duration = Duration::from_secs(30);

/// How long a link key lives after its last use (see `touch_link`). Clients
/// don't redo the handshake, so this must outlast a phone asleep overnight,
/// or it wakes to a link the relay has forgotten; it matches how long
/// packets wait for an offline recipient (`MESSAGE_TTL` in main.rs).
const LINK_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug, Clone)]
pub struct MetadataEntry {
    pub incoming_addr: SocketAddr,
    pub session_id: SessionId,
    pub expiry: Instant,
    last_sync: Instant,
}

#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub id: DeliveryId,
    pub payload: Vec<u8>,
    pub expiry: Instant,
    /// Sent once, never resent or acknowledged (presence pings).
    ephemeral: bool,
    /// When it's next due to be sent: straight away when queued, then
    /// after each send, the resend backoff.
    next_attempt: Instant,
    attempts: u32,
}

/// A recipient's queued packets, and when the relay may send them the next
/// one (see `Tables::take_due`).
#[derive(Default)]
struct TokenQueue {
    packets: VecDeque<OutboundMessage>,
    bytes: usize,
    next_send: Option<Instant>,
}

/// A packet `take_due` released for sending: where to, on which link, and
/// the delivery ID the recipient acks it with.
pub struct DuePacket {
    pub addr: SocketAddr,
    pub session_id: SessionId,
    pub id: DeliveryId,
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
        self.active_links
            .insert(session_id, (link_key, Instant::now() + LINK_TTL));
    }

    /// Push a link's expiry back, because its client just used it. A client
    /// that keeps syncing keeps its link for as long as it runs.
    pub fn touch_link(&mut self, session_id: &SessionId) {
        if let Some((_, expiry)) = self.active_links.get_mut(session_id) {
            *expiry = Instant::now() + LINK_TTL;
        }
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
            for packet in &mut queue.packets {
                packet.next_attempt = now;
            }
        }
    }

    /// Queue a packet for `receiver_token`, to be sent (and resent) until
    /// the recipient acknowledges it or `ttl` runs out. Once the token's
    /// queue is full (`MAX_QUEUED_BYTES_PER_TOKEN`), new packets are refused
    /// rather than old ones evicted: evicting would keep cutting the front
    /// off whole queued messages, and losing an older one that carries a PQ
    /// ratchet update leaves every later one undecryptable anyway. Returns
    /// its delivery ID, or `None` if it was refused.
    pub fn enqueue_message(
        &mut self,
        receiver_token: RoutingToken,
        payload: Vec<u8>,
        ttl: Duration,
    ) -> Option<DeliveryId> {
        self.push(receiver_token, payload, ttl, false)
    }

    /// Queue a packet for a single send, only if the recipient is reachable
    /// right now. For traffic that's useless late, like presence pings, and
    /// that would otherwise fill an offline recipient's queue.
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
    ) -> Option<DeliveryId> {
        let queue = self.message_queues.entry(receiver_token).or_default();
        if queue.bytes + payload.len() > MAX_QUEUED_BYTES_PER_TOKEN {
            return None;
        }
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let now = Instant::now();
        queue.bytes += payload.len();
        queue.packets.push_back(OutboundMessage {
            id,
            payload,
            expiry: now + ttl,
            ephemeral,
            next_attempt: now,
            attempts: 0,
        });
        Some(id)
    }

    /// Drop the packets `ids` from `token`'s queue, now that its recipient
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
        let before = queue.packets.len();
        queue.packets.retain(|packet| !ids.contains(&packet.id));
        queue.bytes = queue.packets.iter().map(|p| p.payload.len()).sum();
        before - queue.packets.len()
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

    /// Release at most one packet per online recipient whose pacing slot
    /// has come round, then schedule its next slot `spacing` later — so a
    /// backlog (a recipient coming back online) is paced out rather than
    /// blasted at line rate, while a live burst passes straight through.
    /// The packet released is the oldest one due (new, or its resend
    /// backoff passed), so a backlog goes out in order. It stays queued
    /// until acknowledged, with its next resend pushed back; only an
    /// ephemeral packet is dropped once sent. Also returns when this next
    /// needs calling, if anything is still waiting for an online recipient.
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
            if queue.next_send.is_none_or(|at| at <= now)
                && let Some(i) = queue.packets.iter().position(|p| p.next_attempt <= now)
            {
                let packet = &mut queue.packets[i];
                due.push(DuePacket {
                    addr: metadata.incoming_addr,
                    session_id: metadata.session_id,
                    id: packet.id,
                    payload: packet.payload.clone(),
                });
                if packet.ephemeral {
                    let len = packet.payload.len();
                    queue.packets.remove(i);
                    queue.bytes -= len;
                } else {
                    packet.attempts += 1;
                    packet.next_attempt = now + resend_delay(packet.attempts);
                }
                queue.next_send = Some(now + spacing);
            }
            // This recipient's next send: its earliest packet due, but not
            // before its next pacing slot.
            if let Some(earliest) = queue.packets.iter().map(|p| p.next_attempt).min() {
                let at = queue.next_send.map_or(earliest, |slot| slot.max(earliest));
                next_due = Some(next_due.map_or(at, |n| n.min(at)));
            }
        }
        self.message_queues.retain(|_, queue| {
            !queue.packets.is_empty() || queue.next_send.is_some_and(|at| at > now)
        });
        (due, next_due)
    }
}

/// Wait before the next resend of a packet already sent `attempts` times.
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
    const SPACING: Duration = Duration::from_millis(5);

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn online_tables() -> Tables {
        let mut tables = Tables::new();
        tables.update_metadata(TOKEN, addr(50000), SESSION, Duration::from_secs(60));
        tables
    }

    #[test]
    fn unacknowledged_packet_is_resent_after_backoff() {
        let mut tables = online_tables();
        let id = tables
            .enqueue_message(TOKEN, b"hi".to_vec(), Duration::from_secs(60))
            .unwrap();
        let now = Instant::now();

        let (first, next_due) = tables.take_due(now, SPACING);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, id);
        assert_eq!(next_due, Some(now + FIRST_RESEND_DELAY));
        assert!(
            tables.take_due(now + SPACING, SPACING).0.is_empty(),
            "not resent before its backoff"
        );
        assert_eq!(tables.get_queued_packets(&TOKEN).unwrap().len(), 1);

        let (resent, _) = tables.take_due(now + FIRST_RESEND_DELAY, SPACING);
        assert_eq!(resent[0].id, id);
    }

    #[test]
    fn ack_from_recipient_session_removes_packet() {
        let mut tables = online_tables();
        let id = tables
            .enqueue_message(TOKEN, b"hi".to_vec(), Duration::from_secs(60))
            .unwrap();
        tables.take_due(Instant::now(), SPACING);

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
        assert_eq!(tables.message_queues[&TOKEN].bytes, 0);
    }

    #[test]
    fn sync_after_silence_or_from_new_address_resends_immediately() {
        let mut tables = online_tables();
        tables.enqueue_message(TOKEN, b"hi".to_vec(), Duration::from_secs(60));
        tables.take_due(Instant::now(), SPACING);
        let later = Instant::now() + SPACING;

        // A routine keepalive from the same address doesn't skip the backoff.
        tables.update_metadata(TOKEN, addr(50000), SESSION, Duration::from_secs(60));
        assert!(tables.take_due(later, SPACING).0.is_empty());

        // A new address (e.g. the phone's NAT mapping changed) does.
        tables.update_metadata(TOKEN, addr(50001), SESSION, Duration::from_secs(60));
        assert_eq!(tables.take_due(later + SPACING, SPACING).0.len(), 1);

        // So does a sync after a long silence.
        tables.metadata.get_mut(&TOKEN).unwrap().last_sync =
            Instant::now() - SILENCE_BEFORE_RESEND - Duration::from_secs(1);
        tables.update_metadata(TOKEN, addr(50001), SESSION, Duration::from_secs(60));
        let now = Instant::now() + SPACING * 3;
        assert_eq!(tables.take_due(now, SPACING).0.len(), 1);
    }

    #[test]
    fn ephemeral_is_dropped_when_offline_and_sent_once_when_online() {
        let mut tables = Tables::new();
        tables.enqueue_ephemeral(TOKEN, b"ping".to_vec());
        assert!(tables.get_queued_packets(&TOKEN).is_none());

        let mut tables = online_tables();
        tables.enqueue_ephemeral(TOKEN, b"ping".to_vec());
        let now = Instant::now();
        let (due, next_due) = tables.take_due(now, SPACING);
        assert_eq!(due.len(), 1);
        assert_eq!(next_due, None, "nothing left to resend");
        assert!(tables.get_queued_packets(&TOKEN).is_none());
    }

    #[test]
    fn using_a_link_keeps_it_alive() {
        let mut tables = Tables::new();
        tables.register_link(SESSION, [1; 32]);
        tables.active_links.get_mut(&SESSION).unwrap().1 = Instant::now();
        tables.touch_link(&SESSION);
        tables.sweep_active_links();
        assert!(
            tables.get_link_key(&SESSION).is_some(),
            "touched, so not swept"
        );

        tables.active_links.get_mut(&SESSION).unwrap().1 = Instant::now();
        tables.sweep_active_links();
        assert!(tables.get_link_key(&SESSION).is_none(), "unused, so swept");
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
