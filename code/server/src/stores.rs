use rand_core::{OsRng, RngCore};
use relay_link::{AdmissionTag, DeliveryId, RoutingToken, SessionId};
use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    net::SocketAddr,
    time::{Duration, Instant},
};

/// Payload bytes held per recipient token for its contacts (and for
/// everyone, until it has registered who its contacts are; see
/// `Tables::enqueue_message`). Clients send each message as a burst of FEC
/// packets (~7 KB for a short one, up to ~330 KB for the longest), so this
/// holds a few hundred short messages for an offline recipient. Bounded so
/// one token can't eat the relay's RAM.
pub const MAX_QUEUED_BYTES_PER_TOKEN: usize = 2 * 1024 * 1024;

/// Payload bytes held per recipient token for packets from anyone who
/// isn't one of its contacts: mostly contact requests (about 45
/// KeyExchanges fit). Kept apart and small, so someone who only knows the
/// token, say from its QR code, can't fill the queue its contacts' messages
/// wait in. The oldest go first when it's full, so a flood that has stopped
/// doesn't keep newer requests out.
pub const MAX_UNADMITTED_BYTES_PER_TOKEN: usize = 64 * 1024;

/// A packet stays queued until its recipient acknowledges it (see
/// `Tables::acknowledge`). The first resend comes this long after the first
/// send, and each later one waits twice as long, up to `MAX_RESEND_DELAY`.
pub const FIRST_RESEND_DELAY: Duration = Duration::from_secs(2);
const MAX_RESEND_DELAY: Duration = Duration::from_secs(60);

/// A sync after this much silence means the recipient was asleep or frozen
/// (clients sync every 15s while running), so anything still unacknowledged
/// is resent straight away instead of waiting out its backoff.
const SILENCE_BEFORE_RESEND: Duration = Duration::from_secs(30);

/// How long a link key lives after its last use (see `touch_link`). Clients
/// don't redo the handshake, so this must outlast a phone asleep overnight,
/// or it wakes to a link the relay has forgotten; it matches how long
/// packets wait for an offline recipient (`MESSAGE_TTL` in main.rs).
const LINK_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long a recipient's admission tags last after its last sync: as long
/// as packets wait for it (`MESSAGE_TTL` in main.rs), so they keep
/// protecting its queue while it's offline, which is when it fills up.
const ADMISSION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// One client's link: its key, and the one address the relay sends it
/// anything at.
pub struct Link {
    key: [u8; 32],
    expiry: Instant,
    /// Where the link has shown it is: the address it handshook from, or
    /// one it later answered a path challenge from. Never just the source
    /// of some packet, which anyone could replay from anywhere.
    pub addr: SocketAddr,
    /// The routing token last synced on this link, if any.
    token: Option<RoutingToken>,
}

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
    /// Whether it counts against the queue for contacts, rather than the
    /// small one for everyone else (see `MAX_UNADMITTED_BYTES_PER_TOKEN`).
    pub admitted: bool,
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
    /// Payload bytes of admitted and of unadmitted packets.
    bytes: usize,
    unadmitted_bytes: usize,
    next_send: Option<Instant>,
}

impl TokenQueue {
    fn recount(&mut self) {
        let (admitted, unadmitted): (Vec<_>, Vec<_>) =
            self.packets.iter().partition(|packet| packet.admitted);
        self.bytes = admitted.iter().map(|p| p.payload.len()).sum();
        self.unadmitted_bytes = unadmitted.iter().map(|p| p.payload.len()).sum();
    }
}

/// The admission tags a recipient registered in its last sync: one per
/// contact (see `relay_link::Sync`).
struct Admission {
    tags: HashSet<AdmissionTag>,
    expiry: Instant,
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
    active_links: HashMap<SessionId, Link>,
    metadata: HashMap<RoutingToken, MetadataEntry>,
    message_queues: HashMap<RoutingToken, TokenQueue>,
    admission: HashMap<RoutingToken, Admission>,
}

impl Tables {
    pub fn new() -> Self {
        Self {
            active_links: HashMap::new(),
            metadata: HashMap::new(),
            message_queues: HashMap::new(),
            admission: HashMap::new(),
        }
    }

    /// Register a new link from `addr`, which just handshook from there,
    /// and return the session ID it gets: random, and never one a live link
    /// already has. Session IDs are in the clear, so if a handshake could
    /// pick its own, anyone who saw one could take over that link.
    pub fn register_link(&mut self, link_key: [u8; 32], addr: SocketAddr) -> SessionId {
        loop {
            let mut session_id = [0u8; 4];
            OsRng.fill_bytes(&mut session_id);
            if let Entry::Vacant(slot) = self.active_links.entry(session_id) {
                slot.insert(Link {
                    key: link_key,
                    expiry: Instant::now() + LINK_TTL,
                    addr,
                    token: None,
                });
                return session_id;
            }
        }
    }

    /// Push a link's expiry back, because its client just used it. A client
    /// that keeps syncing keeps its link for as long as it runs.
    pub fn touch_link(&mut self, session_id: &SessionId) {
        if let Some(link) = self.active_links.get_mut(session_id) {
            link.expiry = Instant::now() + LINK_TTL;
        }
    }

    pub fn get_link_key(&self, session_id: &SessionId) -> Option<&[u8; 32]> {
        self.active_links.get(session_id).map(|link| &link.key)
    }

    pub fn link_addr(&self, session_id: &SessionId) -> Option<SocketAddr> {
        self.active_links.get(session_id).map(|link| link.addr)
    }

    /// Take in a verified sync for `token` that arrived from its link's own
    /// address: deliver the token's packets over this link from now on, and
    /// replace its admission tags. If the token was on another link before,
    /// that link is retired: only the token's owner could have moved it, and
    /// a sync from the old link replayed later mustn't move it back.
    pub fn apply_sync(
        &mut self,
        token: RoutingToken,
        session_id: SessionId,
        admission: Vec<AdmissionTag>,
        ttl: Duration,
    ) {
        let Some(link) = self.active_links.get_mut(&session_id) else {
            return;
        };
        link.token = Some(token);
        let addr = link.addr;
        if let Some(previous) = self.metadata.get(&token)
            && previous.session_id != session_id
        {
            self.active_links.remove(&previous.session_id);
        }
        self.update_metadata(token, addr, session_id, ttl);
        self.admission.insert(
            token,
            Admission {
                tags: admission.into_iter().collect(),
                expiry: Instant::now() + ADMISSION_TTL,
            },
        );
    }

    /// A link answered a path challenge from `addr`, proving that's where it
    /// is now (say, its NAT mapping changed). Send it everything there from
    /// now on, starting with whatever it hasn't acknowledged.
    pub fn move_link(&mut self, session_id: &SessionId, addr: SocketAddr, ttl: Duration) {
        let Some(link) = self.active_links.get_mut(session_id) else {
            return;
        };
        link.addr = addr;
        if let Some(token) = link.token
            && self
                .metadata
                .get(&token)
                .is_some_and(|entry| entry.session_id == *session_id)
        {
            self.update_metadata(token, addr, *session_id, ttl);
        }
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
    /// the recipient acknowledges it or `ttl` runs out. Returns its delivery
    /// ID, or `None` if it was refused.
    ///
    /// Once the recipient has registered admission tags (see `apply_sync`),
    /// a packet carrying one of them is from a contact and counts against
    /// `MAX_QUEUED_BYTES_PER_TOKEN`; anything else counts against the small
    /// `MAX_UNADMITTED_BYTES_PER_TOKEN`. Before then, everything shares the
    /// first. A full queue for contacts refuses new packets rather than
    /// evicting old ones: evicting would keep cutting the front off whole
    /// queued messages, and losing an older one that carries a PQ ratchet
    /// update leaves every later one undecryptable anyway. A full queue for
    /// everyone else evicts its oldest instead: those are contact requests
    /// and junk, and fresh requests matter more than stale ones.
    pub fn enqueue_message(
        &mut self,
        receiver_token: RoutingToken,
        payload: Vec<u8>,
        ttl: Duration,
        tag: Option<AdmissionTag>,
    ) -> Option<DeliveryId> {
        let admitted = match self.admission.get(&receiver_token) {
            Some(admission) => tag.is_some_and(|tag| admission.tags.contains(&tag)),
            None => true,
        };
        let queue = self.message_queues.entry(receiver_token).or_default();
        if admitted {
            if queue.bytes + payload.len() > MAX_QUEUED_BYTES_PER_TOKEN {
                return None;
            }
            queue.bytes += payload.len();
        } else {
            if payload.len() > MAX_UNADMITTED_BYTES_PER_TOKEN {
                return None;
            }
            while queue.unadmitted_bytes + payload.len() > MAX_UNADMITTED_BYTES_PER_TOKEN {
                let oldest = queue.packets.iter().position(|p| !p.admitted)?;
                let evicted = queue.packets.remove(oldest)?;
                queue.unadmitted_bytes -= evicted.payload.len();
            }
            queue.unadmitted_bytes += payload.len();
        }
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let now = Instant::now();
        queue.packets.push_back(OutboundMessage {
            id,
            payload,
            expiry: now + ttl,
            admitted,
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
        queue.recount();
        before - queue.packets.len()
    }

    pub fn sweep_active_links(&mut self) {
        let now = Instant::now();
        self.active_links.retain(|_, link| link.expiry > now);
    }

    pub fn sweep_metadata(&mut self) {
        let now = Instant::now();
        self.metadata.retain(|_, entry| entry.expiry > now);
        self.admission.retain(|_, admission| admission.expiry > now);
    }

    pub fn sweep_expired_messages(&mut self) {
        let now = Instant::now();
        for queue in self.message_queues.values_mut() {
            queue.packets.retain(|msg| msg.expiry > now);
            queue.recount();
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
    /// until acknowledged, with its next resend pushed back. Also returns
    /// when this next needs calling, if anything is still waiting for an online recipient.
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
                packet.attempts += 1;
                packet.next_attempt = now + resend_delay(packet.attempts);
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
    const SPACING: Duration = Duration::from_millis(5);
    const TTL: Duration = Duration::from_secs(60);

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Tables with one recipient, `TOKEN`, online on a link from port 50000.
    /// Returns the link's session ID.
    fn online_tables() -> (Tables, SessionId) {
        let mut tables = Tables::new();
        let session = tables.register_link([1; 32], addr(50000));
        tables.update_metadata(TOKEN, addr(50000), session, TTL);
        (tables, session)
    }

    #[test]
    fn unacknowledged_packet_is_resent_after_backoff() {
        let (mut tables, _) = online_tables();
        let id = tables
            .enqueue_message(TOKEN, b"hi".to_vec(), TTL, None)
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
        let (mut tables, session) = online_tables();
        let id = tables
            .enqueue_message(TOKEN, b"hi".to_vec(), TTL, None)
            .unwrap();
        tables.take_due(Instant::now(), SPACING);

        assert_eq!(
            tables.acknowledge(&TOKEN, &[0x99; 4], &[id]),
            0,
            "wrong session"
        );
        assert_eq!(
            tables.acknowledge(&TOKEN, &session, &[[0u8; 16]]),
            0,
            "unknown id"
        );
        assert_eq!(tables.acknowledge(&TOKEN, &session, &[id]), 1);
        assert!(tables.get_queued_packets(&TOKEN).is_none());
        assert_eq!(tables.message_queues[&TOKEN].bytes, 0);
    }

    #[test]
    fn sync_after_silence_or_from_new_address_resends_immediately() {
        let (mut tables, session) = online_tables();
        tables.enqueue_message(TOKEN, b"hi".to_vec(), TTL, None);
        tables.take_due(Instant::now(), SPACING);
        let later = Instant::now() + SPACING;

        // A routine keepalive from the same address doesn't skip the backoff.
        tables.update_metadata(TOKEN, addr(50000), session, TTL);
        assert!(tables.take_due(later, SPACING).0.is_empty());

        // A new address (e.g. the phone's NAT mapping changed) does.
        tables.update_metadata(TOKEN, addr(50001), session, TTL);
        assert_eq!(tables.take_due(later + SPACING, SPACING).0.len(), 1);

        // So does a sync after a long silence.
        tables.metadata.get_mut(&TOKEN).unwrap().last_sync =
            Instant::now() - SILENCE_BEFORE_RESEND - Duration::from_secs(1);
        tables.update_metadata(TOKEN, addr(50001), session, TTL);
        let now = Instant::now() + SPACING * 3;
        assert_eq!(tables.take_due(now, SPACING).0.len(), 1);
    }

    #[test]
    fn using_a_link_keeps_it_alive() {
        let mut tables = Tables::new();
        let session = tables.register_link([1; 32], addr(50000));
        tables.active_links.get_mut(&session).unwrap().expiry = Instant::now();
        tables.touch_link(&session);
        tables.sweep_active_links();
        assert!(
            tables.get_link_key(&session).is_some(),
            "touched, so not swept"
        );

        tables.active_links.get_mut(&session).unwrap().expiry = Instant::now();
        tables.sweep_active_links();
        assert!(tables.get_link_key(&session).is_none(), "unused, so swept");
    }

    #[test]
    fn every_link_gets_its_own_session_id() {
        let mut tables = Tables::new();
        let ids: HashSet<SessionId> = (0..1000)
            .map(|port| tables.register_link([port as u8; 32], addr(port)))
            .collect();
        assert_eq!(ids.len(), 1000);
    }

    /// Moving a token to a new link retires its old one, so nothing from
    /// the old link, like a copy of its last sync, can move it back.
    #[test]
    fn syncing_on_a_new_link_retires_the_old_one() {
        let (mut tables, old) = online_tables();
        let new = tables.register_link([2; 32], addr(50001));
        tables.apply_sync(TOKEN, new, Vec::new(), TTL);
        assert!(tables.get_link_key(&old).is_none());
        assert_eq!(tables.get_metadata(&TOKEN).unwrap().session_id, new);
        assert_eq!(
            tables.get_metadata(&TOKEN).unwrap().incoming_addr,
            addr(50001)
        );

        // Another sync on the same link keeps it.
        tables.apply_sync(TOKEN, new, Vec::new(), TTL);
        assert!(tables.get_link_key(&new).is_some());
    }

    #[test]
    fn a_moved_link_gets_its_packets_at_the_new_address_at_once() {
        let mut tables = Tables::new();
        let session = tables.register_link([1; 32], addr(50000));
        tables.apply_sync(TOKEN, session, Vec::new(), TTL);
        tables.enqueue_message(TOKEN, b"hi".to_vec(), TTL, None);
        let now = Instant::now();
        assert_eq!(tables.take_due(now, SPACING).0[0].addr, addr(50000));

        tables.move_link(&session, addr(50001), TTL);
        assert_eq!(tables.link_addr(&session), Some(addr(50001)));
        let (resent, _) = tables.take_due(Instant::now() + SPACING, SPACING);
        assert_eq!(resent.len(), 1, "resent without waiting out the backoff");
        assert_eq!(resent[0].addr, addr(50001));
    }

    /// Once a recipient has registered its contacts' tags, packets without
    /// one can only fill a small queue of their own, oldest out first, and
    /// contacts' packets still get in.
    #[test]
    fn strangers_cannot_crowd_out_contacts() {
        let (mut tables, session) = online_tables();
        tables.apply_sync(TOKEN, session, vec![[7; 8]], TTL);
        let junk = vec![0xAB; 1000];
        for i in 0..200u32 {
            let mut packet = junk.clone();
            packet[..4].copy_from_slice(&i.to_be_bytes());
            assert!(
                tables
                    .enqueue_message(TOKEN, packet, TTL, Some([9; 8]))
                    .is_some(),
                "always room for the newest"
            );
        }
        let queue = &tables.message_queues[&TOKEN];
        assert_eq!(queue.unadmitted_bytes, 65 * 1000);
        assert_eq!(
            queue.packets.front().unwrap().payload[..4],
            135u32.to_be_bytes(),
            "the oldest were evicted"
        );

        let contact = tables.enqueue_message(TOKEN, vec![1; 1000], TTL, Some([7; 8]));
        assert!(contact.is_some());
        assert_eq!(tables.message_queues[&TOKEN].bytes, 1000);
        assert!(
            tables.message_queues[&TOKEN]
                .packets
                .back()
                .unwrap()
                .admitted
        );
    }

    /// Before a recipient registers any tags (it hasn't synced since the
    /// relay started, say), everything shares the queue, as it always did.
    #[test]
    fn without_admission_tags_everything_shares_one_queue() {
        let mut tables = Tables::new();
        for _ in 0..10 {
            tables.enqueue_message(TOKEN, vec![0; 10_000], TTL, None);
        }
        let queue = &tables.message_queues[&TOKEN];
        assert_eq!(queue.bytes, 100_000);
        assert_eq!(queue.unadmitted_bytes, 0);
    }

    #[test]
    fn admission_tags_outlast_the_recipients_metadata() {
        let (mut tables, session) = online_tables();
        tables.apply_sync(TOKEN, session, vec![[7; 8]], TTL);
        tables.metadata.get_mut(&TOKEN).unwrap().expiry = Instant::now();
        tables.sweep_metadata();
        assert!(tables.get_metadata(&TOKEN).is_none(), "offline now");
        tables.enqueue_message(TOKEN, vec![0; 10], TTL, None);
        assert!(
            !tables.message_queues[&TOKEN].packets[0].admitted,
            "its contacts are still known"
        );
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
