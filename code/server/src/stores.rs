use rand_core::{OsRng, RngCore};
use relay_link::{
    AdmissionTag, DeliveryId, Header, Lane, LinkEnd, LinkError, LinkKeys, RoutingToken, SessionId,
    Side,
};
use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    fmt,
    net::{IpAddr, SocketAddr},
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

/// Payload bytes held in all, across every recipient that hasn't registered
/// admission tags: ones that haven't synced since the relay started, and
/// tokens nobody owns. Anyone can make up tokens, and each can hold
/// `MAX_QUEUED_BYTES_PER_TOKEN`, so without this, queueing for made-up
/// tokens could take all the relay's memory. Once it's used up, new packets
/// for such recipients are refused until some expire. Recipients who have
/// synced aren't affected. (Smaller under test, so tests can fill it.)
pub const MAX_UNREGISTERED_QUEUED_BYTES: usize = if cfg!(test) {
    2 * MAX_QUEUED_BYTES_PER_TOKEN
} else {
    64 * 1024 * 1024
};

/// A packet stays queued until its recipient acknowledges it (see
/// `Tables::acknowledge`). The first resend comes this long after the first
/// send, and each later one waits twice as long, up to `MAX_RESEND_DELAY`.
pub const FIRST_RESEND_DELAY: Duration = Duration::from_secs(2);
const MAX_RESEND_DELAY: Duration = Duration::from_secs(60);

/// A sync after this much silence means the recipient was asleep or frozen
/// (clients sync every 15s while running), so anything still unacknowledged
/// is resent straight away instead of waiting out its backoff.
const SILENCE_BEFORE_RESEND: Duration = Duration::from_secs(30);

/// How long a link lives after its last use (see `Tables::open`), once its
/// client has synced on it. Clients sync every 15 s while running, and do
/// the handshake again once their syncs stop being acked (say a phone slept
/// longer than this), so a link this quiet has been left behind.
pub const LINK_TTL: Duration = Duration::from_secs(60 * 60);

/// The same, for a link nobody has synced on yet. A client syncs straight
/// after its handshake, so a link that still hasn't by now never will:
/// someone is handshaking just to fill the table.
pub const UNSYNCED_LINK_TTL: Duration = Duration::from_secs(60);

/// Most links kept at once. A handshake past this is refused until expired
/// links make room, so a flood of handshakes can't grow the table without
/// bound. (Smaller under test, so tests can fill it.)
pub const MAX_LINKS: usize = if cfg!(test) { 64 } else { 100_000 };

/// How long a recipient's admission tags last after its last sync: as long
/// as packets wait for it (`MESSAGE_TTL` in main.rs), so they keep
/// protecting its queue while it's offline, which is when it fills up.
const ADMISSION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Most recipients whose admission tags are kept at once. Past this, a
/// recipient syncing for the first time is still served, but its tags
/// aren't kept, so its packets share one queue as they did before tags
/// existed, until expired entries make room. (Smaller under test, so tests
/// can fill it.)
pub const MAX_ADMISSION_ENTRIES: usize = if cfg!(test) { 64 } else { 100_000 };

/// How long the relay remembers its reply to a handshake init. A client
/// sends each init several times over (it's one packet, and loss is the
/// norm), and a copy of one just answered gets the same reply: the same
/// link, not a link per copy. As long as a link nobody has synced on lives.
const RECENT_HANDSHAKE_TTL: Duration = UNSYNCED_LINK_TTL;

/// Handshakes each source address may start (see `Tables::allow_handshake`):
/// a burst of `HANDSHAKE_BURST`, then `HANDSHAKE_RATE` a second. A
/// handshake costs the relay a key agreement and a signature, so this keeps
/// one sender from taking its CPU. Copies of an init already answered don't
/// count. Generous, as many clients can share one address behind a NAT.
const HANDSHAKE_BURST: f64 = 20.0;
const HANDSHAKE_RATE: f64 = 1.0;
/// Most source addresses whose handshake budgets are tracked at once.
/// Past this, a new address isn't limited (someone spoofing addresses gets
/// round any per-address limit anyway, and `MAX_LINKS` still bounds what
/// they can take). Smaller under test, so tests can fill it.
const MAX_HANDSHAKE_SOURCES: usize = if cfg!(test) { 64 } else { 65_536 };

/// One client's link: the relay's end of it (its keys, and the packet
/// numbers sent and taken in), and the one address the relay sends it
/// anything at.
pub struct Link {
    end: LinkEnd,
    expiry: Instant,
    /// Where the link has shown it is: the address it handshook from, or
    /// one it later answered a path challenge from. Never just the source
    /// of some packet, which anyone could replay from anywhere.
    pub addr: SocketAddr,
    /// The routing token synced on this link, if any yet. A link only ever
    /// carries one (see `Tables::apply_sync`).
    token: Option<RoutingToken>,
}

impl Link {
    /// How long the link lives after its last use.
    fn ttl(&self) -> Duration {
        match self.token {
            Some(_) => LINK_TTL,
            None => UNSYNCED_LINK_TTL,
        }
    }
}

/// A packet a client sent on one of the relay's links, opened (see
/// `Tables::open`).
pub struct OpenedPacket {
    pub header: Header,
    pub plaintext: Vec<u8>,
    /// The link's keys, which a sync's signature must be bound to.
    pub keys: LinkKeys,
}

/// Why `Tables::apply_sync` refused a sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncRefused {
    /// For a link that has expired or been retired since.
    UnknownLink,
    /// For a token other than the one this link already carries.
    OtherToken,
}

impl fmt::Display for SyncRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SyncRefused::UnknownLink => "the link is gone",
            SyncRefused::OtherToken => "the link already carries another token",
        })
    }
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
    /// Sorted, to look a tag up by binary search.
    tags: Box<[AdmissionTag]>,
    expiry: Instant,
}

/// The relay's reply to a recent handshake init (see
/// `RECENT_HANDSHAKE_TTL`).
struct RecentHandshake {
    session_id: SessionId,
    reply: Vec<u8>,
    at: Instant,
}

/// What's left of a source address's handshake budget (see
/// `HANDSHAKE_BURST`), as of `at`.
struct HandshakeBudget {
    tokens: f64,
    at: Instant,
}

impl HandshakeBudget {
    /// The budget refilled up to `now`.
    fn refilled(&self, now: Instant) -> f64 {
        let refill = now.saturating_duration_since(self.at).as_secs_f64() * HANDSHAKE_RATE;
        (self.tokens + refill).min(HANDSHAKE_BURST)
    }
}

/// Which handshake budget a source address draws on: the address itself
/// for IPv4, and its /64 for IPv6, as one host can have a whole /64.
fn handshake_source(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => {
            let mut prefix = [0u8; 16];
            prefix[..8].copy_from_slice(&ip.octets()[..8]);
            prefix
        }
    }
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
    /// The link each routing token was last synced on, so a sync on another
    /// link retires it (see `apply_sync`) however long ago it was last used.
    token_links: HashMap<RoutingToken, SessionId>,
    metadata: HashMap<RoutingToken, MetadataEntry>,
    message_queues: HashMap<RoutingToken, TokenQueue>,
    admission: HashMap<RoutingToken, Admission>,
    /// Payload bytes queued for recipients without admission tags (see
    /// `MAX_UNREGISTERED_QUEUED_BYTES`). Added to as packets are queued and
    /// recounted at every sweep (`sweep_expired_messages`), so in between
    /// it can run high, but never low.
    unregistered_bytes: usize,
    /// Recent replies to handshake inits, by the client's ephemeral key.
    recent_handshakes: HashMap<[u8; 32], RecentHandshake>,
    handshake_budgets: HashMap<[u8; 16], HandshakeBudget>,
}

impl Tables {
    pub fn new() -> Self {
        Self {
            active_links: HashMap::new(),
            token_links: HashMap::new(),
            metadata: HashMap::new(),
            message_queues: HashMap::new(),
            admission: HashMap::new(),
            unregistered_bytes: 0,
            recent_handshakes: HashMap::new(),
            handshake_budgets: HashMap::new(),
        }
    }

    /// The reply the relay sent a handshake init with the ephemeral key
    /// `client_ephemeral` lately, if its link is still unused or in use:
    /// what a copy of that init gets, rather than a new link.
    pub fn recent_handshake_reply(&self, client_ephemeral: &[u8; 32]) -> Option<Vec<u8>> {
        let recent = self.recent_handshakes.get(client_ephemeral)?;
        (recent.at.elapsed() < RECENT_HANDSHAKE_TTL
            && self.active_links.contains_key(&recent.session_id))
        .then(|| recent.reply.clone())
    }

    /// Remember `reply`, to the init with `client_ephemeral`, which gave
    /// `session_id` its link (see `recent_handshake_reply`). There's room
    /// for one per link.
    pub fn remember_handshake(
        &mut self,
        client_ephemeral: [u8; 32],
        session_id: SessionId,
        reply: Vec<u8>,
    ) {
        if self.recent_handshakes.len() < MAX_LINKS {
            self.recent_handshakes.insert(
                client_ephemeral,
                RecentHandshake {
                    session_id,
                    reply,
                    at: Instant::now(),
                },
            );
        }
    }

    /// Whether a new handshake from `ip` is within its address's budget
    /// (see `HANDSHAKE_BURST`), taking one from it if so.
    pub fn allow_handshake(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let source = handshake_source(ip);
        if !self.handshake_budgets.contains_key(&source)
            && self.handshake_budgets.len() >= MAX_HANDSHAKE_SOURCES
        {
            return true;
        }
        let budget = self
            .handshake_budgets
            .entry(source)
            .or_insert(HandshakeBudget {
                tokens: HANDSHAKE_BURST,
                at: now,
            });
        budget.tokens = budget.refilled(now);
        budget.at = now;
        if budget.tokens < 1.0 {
            return false;
        }
        budget.tokens -= 1.0;
        true
    }

    /// Register a new link from `addr`, which just handshook from there,
    /// and return the session ID it gets: random, and never one a live link
    /// already has. Session IDs are in the clear, so if a handshake could
    /// pick its own, anyone who saw one could take over that link. `None`
    /// if the table is full (see `MAX_LINKS`).
    pub fn register_link(&mut self, keys: LinkKeys, addr: SocketAddr) -> Option<SessionId> {
        if self.links_full() {
            return None;
        }
        loop {
            let mut session_id = [0u8; 4];
            OsRng.fill_bytes(&mut session_id);
            if let Entry::Vacant(slot) = self.active_links.entry(session_id) {
                slot.insert(Link {
                    end: LinkEnd::new(Side::Relay, keys, session_id),
                    expiry: Instant::now() + UNSYNCED_LINK_TTL,
                    addr,
                    token: None,
                });
                return Some(session_id);
            }
        }
    }

    pub fn links_full(&self) -> bool {
        self.active_links.len() >= MAX_LINKS
    }

    pub fn admission_full(&self) -> bool {
        self.admission.len() >= MAX_ADMISSION_ENTRIES
    }

    pub fn unregistered_queues_full(&self) -> bool {
        self.unregistered_bytes >= MAX_UNREGISTERED_QUEUED_BYTES
    }

    /// Open a packet a client sent on one of our links (see
    /// `LinkEnd::open`): refused if it's for no link we have, doesn't
    /// authenticate, or is a copy of one taken in already. Authentic
    /// traffic keeps its link alive: a client that keeps syncing keeps its
    /// link for as long as it runs.
    pub fn open(&mut self, packet: &[u8]) -> Result<OpenedPacket, LinkError> {
        let session_id = relay_link::header(packet)
            .ok_or(LinkError::Malformed)?
            .session_id;
        let link = self
            .active_links
            .get_mut(&session_id)
            .ok_or(LinkError::WrongLink)?;
        let (header, plaintext) = link.end.open(packet)?;
        link.expiry = Instant::now() + link.ttl();
        Ok(OpenedPacket {
            header,
            plaintext,
            keys: *link.end.keys(),
        })
    }

    /// Seal `plaintext` as a `packet_type` packet to the client on link
    /// `session_id`, if the link is still there.
    pub fn seal_for(
        &mut self,
        session_id: &SessionId,
        packet_type: u8,
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        let link = self.active_links.get_mut(session_id)?;
        Some(link.end.seal(Lane::Direct, packet_type, plaintext))
    }

    /// `packet`, sealed for the client on its link, if the link is still
    /// there.
    pub fn forward(&mut self, packet: &DuePacket) -> Option<Vec<u8>> {
        let link = self.active_links.get_mut(&packet.session_id)?;
        Some(relay_link::forwarded_packet(
            &mut link.end,
            &packet.id,
            &packet.payload,
        ))
    }

    #[cfg(test)]
    pub fn link_count(&self) -> usize {
        self.active_links.len()
    }

    #[cfg(test)]
    pub fn expire_link(&mut self, session_id: &SessionId) {
        self.active_links.remove(session_id);
    }

    #[allow(dead_code)]
    pub fn get_link_keys(&self, session_id: &SessionId) -> Option<&LinkKeys> {
        self.active_links
            .get(session_id)
            .map(|link| link.end.keys())
    }

    pub fn link_addr(&self, session_id: &SessionId) -> Option<SocketAddr> {
        self.active_links.get(session_id).map(|link| link.addr)
    }

    /// Take in a verified sync for `token` that arrived from its link's own
    /// address: deliver the token's packets over this link from now on, and
    /// replace its admission tags. A link carries one token for good, so a
    /// sync for another is refused. If the token was on another link before,
    /// that link is retired, however long ago it was last used: only the
    /// token's owner could have moved it, and nothing from the old link
    /// (like a copy of its last sync) must move it back.
    pub fn apply_sync(
        &mut self,
        token: RoutingToken,
        session_id: SessionId,
        admission: Vec<AdmissionTag>,
        ttl: Duration,
    ) -> Result<(), SyncRefused> {
        let link = self
            .active_links
            .get_mut(&session_id)
            .ok_or(SyncRefused::UnknownLink)?;
        if link.token.is_some_and(|synced| synced != token) {
            return Err(SyncRefused::OtherToken);
        }
        link.token = Some(token);
        link.expiry = Instant::now() + LINK_TTL;
        let addr = link.addr;
        if let Some(previous) = self.token_links.insert(token, session_id)
            && previous != session_id
        {
            self.active_links.remove(&previous);
        }
        self.update_metadata(token, addr, session_id, ttl);
        self.set_admission(token, admission);
        Ok(())
    }

    /// Replace `token`'s admission tags, unless it has none yet and the
    /// table is full (see `MAX_ADMISSION_ENTRIES`).
    fn set_admission(&mut self, token: RoutingToken, mut tags: Vec<AdmissionTag>) {
        if self.admission_full() && !self.admission.contains_key(&token) {
            return;
        }
        tags.sort_unstable();
        tags.dedup();
        self.admission.insert(
            token,
            Admission {
                tags: tags.into_boxed_slice(),
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
    /// first, and also counts against `MAX_UNREGISTERED_QUEUED_BYTES`. A
    /// full queue for contacts refuses new packets rather than evicting old
    /// ones: evicting would keep cutting the front off whole queued
    /// messages, and losing an older one that carries a PQ ratchet update
    /// leaves every later one undecryptable anyway. A full queue for
    /// everyone else evicts its oldest instead: those are contact requests
    /// and junk, and fresh requests matter more than stale ones.
    pub fn enqueue_message(
        &mut self,
        receiver_token: RoutingToken,
        payload: Vec<u8>,
        ttl: Duration,
        tag: Option<AdmissionTag>,
    ) -> Option<DeliveryId> {
        let (registered, admitted) = match self.admission.get(&receiver_token) {
            Some(admission) => (
                true,
                tag.is_some_and(|tag| admission.tags.binary_search(&tag).is_ok()),
            ),
            None => (false, true),
        };
        if !registered && self.unregistered_bytes + payload.len() > MAX_UNREGISTERED_QUEUED_BYTES {
            return None;
        }
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
        if !registered {
            self.unregistered_bytes += payload.len();
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
        let links = &self.active_links;
        self.token_links
            .retain(|_, session_id| links.contains_key(session_id));
        self.recent_handshakes.retain(|_, recent| {
            now.duration_since(recent.at) < RECENT_HANDSHAKE_TTL
                && links.contains_key(&recent.session_id)
        });
        // A budget that has refilled is the same as none at all.
        self.handshake_budgets
            .retain(|_, budget| budget.refilled(now) < HANDSHAKE_BURST);
    }

    pub fn sweep_metadata(&mut self) {
        let now = Instant::now();
        self.metadata.retain(|_, entry| entry.expiry > now);
        self.admission.retain(|_, admission| admission.expiry > now);
    }

    /// Drop expired packets, then recount `unregistered_bytes` (after
    /// `sweep_metadata`, so it counts the recipients whose tags just
    /// expired).
    pub fn sweep_expired_messages(&mut self) {
        let now = Instant::now();
        for queue in self.message_queues.values_mut() {
            queue.packets.retain(|msg| msg.expiry > now);
            queue.recount();
        }
        self.message_queues
            .retain(|_, queue| !queue.packets.is_empty());
        let admission = &self.admission;
        self.unregistered_bytes = self
            .message_queues
            .iter()
            .filter(|(token, _)| !admission.contains_key(*token))
            .map(|(_, queue)| queue.bytes + queue.unadmitted_bytes)
            .sum();
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
    use relay_link::{TYPE_ACK, TYPE_DATA};

    const TOKEN: RoutingToken = [0xCC; 16];
    const SPACING: Duration = Duration::from_millis(5);
    const TTL: Duration = Duration::from_secs(60);

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn keys(byte: u8) -> LinkKeys {
        LinkKeys {
            to_relay: [byte; 32],
            to_client: [byte; 32],
        }
    }

    /// Tables with one recipient, `TOKEN`, online on a link from port 50000.
    /// Returns the link's session ID.
    fn online_tables() -> (Tables, SessionId) {
        let mut tables = Tables::new();
        let session = tables.register_link(keys(1), addr(50000)).unwrap();
        tables.apply_sync(TOKEN, session, Vec::new(), TTL).unwrap();
        (tables, session)
    }

    fn expire_link(tables: &mut Tables, session: &SessionId) {
        tables.active_links.get_mut(session).unwrap().expiry = Instant::now();
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

    /// Authentic packets keep a link alive; anything else doesn't. A link
    /// nobody syncs on goes after `UNSYNCED_LINK_TTL`, and one that's
    /// synced lives `LINK_TTL` past its last use.
    #[test]
    fn using_a_link_keeps_it_alive() {
        let expiry = |tables: &Tables, session| tables.active_links[session].expiry;
        let mut tables = Tables::new();
        let session = tables.register_link(keys(1), addr(50000)).unwrap();
        let mut client = LinkEnd::new(Side::Client, keys(1), session);
        assert!(expiry(&tables, &session) <= Instant::now() + UNSYNCED_LINK_TTL);

        let packet = client.seal(Lane::Direct, TYPE_ACK, &[0; 16]);
        expire_link(&mut tables, &session);
        tables.open(&packet).unwrap();
        tables.sweep_active_links();
        assert!(tables.get_link_keys(&session).is_some(), "used, so kept");
        assert!(expiry(&tables, &session) <= Instant::now() + UNSYNCED_LINK_TTL);

        expire_link(&mut tables, &session);
        let forged =
            LinkEnd::new(Side::Client, keys(2), session).seal(Lane::Direct, TYPE_ACK, &[0; 16]);
        assert_eq!(tables.open(&forged).err(), Some(LinkError::Forged));
        assert_eq!(tables.open(&packet).err(), Some(LinkError::Replayed));
        tables.sweep_active_links();
        assert!(tables.get_link_keys(&session).is_none(), "unused, so swept");

        let (mut tables, session) = online_tables();
        assert!(expiry(&tables, &session) > Instant::now() + UNSYNCED_LINK_TTL);
        assert!(expiry(&tables, &session) <= Instant::now() + LINK_TTL);
        expire_link(&mut tables, &session);
        tables.sweep_active_links();
        assert!(tables.token_links.is_empty(), "the index forgets it too");
    }

    #[test]
    fn every_link_gets_its_own_session_id_until_the_table_is_full() {
        let mut tables = Tables::new();
        let ids: std::collections::HashSet<SessionId> = (0..MAX_LINKS)
            .map(|port| {
                tables
                    .register_link(keys(port as u8), addr(port as u16))
                    .unwrap()
            })
            .collect();
        assert_eq!(ids.len(), MAX_LINKS);
        assert!(tables.links_full());
        assert!(tables.register_link(keys(0), addr(1)).is_none(), "full");

        let first = *ids.iter().next().unwrap();
        expire_link(&mut tables, &first);
        tables.sweep_active_links();
        assert!(
            tables.register_link(keys(0), addr(1)).is_some(),
            "room again"
        );
    }

    /// Moving a token to a new link retires its old one, so nothing from
    /// the old link, like a copy of its last sync, can move it back.
    #[test]
    fn syncing_on_a_new_link_retires_the_old_one() {
        let (mut tables, old) = online_tables();
        let new = tables.register_link(keys(2), addr(50001)).unwrap();
        tables.apply_sync(TOKEN, new, Vec::new(), TTL).unwrap();
        assert!(tables.get_link_keys(&old).is_none());
        assert_eq!(tables.get_metadata(&TOKEN).unwrap().session_id, new);
        assert_eq!(
            tables.get_metadata(&TOKEN).unwrap().incoming_addr,
            addr(50001)
        );

        // Another sync on the same link keeps it.
        tables.apply_sync(TOKEN, new, Vec::new(), TTL).unwrap();
        assert!(tables.get_link_keys(&new).is_some());
    }

    /// The old link is retired even when the token's metadata expired before
    /// the new link synced (a phone offline for a while, then relaunched):
    /// it's the token's last link that counts, not its metadata.
    #[test]
    fn a_token_moved_after_its_metadata_expired_still_retires_its_old_link() {
        let (mut tables, old) = online_tables();
        tables.metadata.get_mut(&TOKEN).unwrap().expiry = Instant::now();
        tables.sweep_metadata();
        assert!(tables.get_metadata(&TOKEN).is_none());
        assert!(tables.get_link_keys(&old).is_some());

        let new = tables.register_link(keys(2), addr(50001)).unwrap();
        tables.apply_sync(TOKEN, new, Vec::new(), TTL).unwrap();
        assert!(tables.get_link_keys(&old).is_none(), "retired");
        assert_eq!(
            tables.apply_sync(TOKEN, old, Vec::new(), TTL),
            Err(SyncRefused::UnknownLink)
        );
        assert_eq!(tables.get_metadata(&TOKEN).unwrap().session_id, new);
    }

    /// A link carries one token, so one link can't register any number of
    /// made-up tokens (each with admission tags kept for days).
    #[test]
    fn a_link_carries_one_token() {
        let (mut tables, session) = online_tables();
        assert_eq!(
            tables.apply_sync([0xDD; 16], session, vec![[1; 8]], TTL),
            Err(SyncRefused::OtherToken)
        );
        assert!(tables.get_metadata(&[0xDD; 16]).is_none());
        assert!(!tables.admission.contains_key(&[0xDD; 16]));
        assert!(tables.apply_sync(TOKEN, session, Vec::new(), TTL).is_ok());
    }

    #[test]
    fn admission_table_is_capped() {
        let mut tables = Tables::new();
        for i in 0..MAX_ADMISSION_ENTRIES {
            tables.set_admission([i as u8; 16], vec![[1; 8]]);
        }
        assert!(tables.admission_full());
        tables.set_admission([0xFF; 16], vec![[1; 8]]);
        assert!(!tables.admission.contains_key(&[0xFF; 16]), "full");
        tables.set_admission([0; 16], vec![[2; 8], [2; 8], [1; 8]]);
        assert_eq!(
            *tables.admission[&[0; 16]].tags,
            [[1; 8], [2; 8]],
            "an existing entry still updates, sorted and deduplicated"
        );
    }

    #[test]
    fn a_moved_link_gets_its_packets_at_the_new_address_at_once() {
        let mut tables = Tables::new();
        let session = tables.register_link(keys(1), addr(50000)).unwrap();
        tables.apply_sync(TOKEN, session, Vec::new(), TTL).unwrap();
        tables.enqueue_message(TOKEN, b"hi".to_vec(), TTL, None);
        let now = Instant::now();
        assert_eq!(tables.take_due(now, SPACING).0[0].addr, addr(50000));

        tables.move_link(&session, addr(50001), TTL);
        assert_eq!(tables.link_addr(&session), Some(addr(50001)));
        let (resent, _) = tables.take_due(Instant::now() + SPACING, SPACING);
        assert_eq!(resent.len(), 1, "resent without waiting out the backoff");
        assert_eq!(resent[0].addr, addr(50001));
    }

    /// What the relay forwards is sealed on the recipient's link, each copy
    /// with its own packet number, so a resend isn't refused as a replay.
    #[test]
    fn forwarded_packets_are_sealed_on_the_recipients_link() {
        let (mut tables, session) = online_tables();
        let mut client = LinkEnd::new(Side::Client, keys(1), session);
        tables.enqueue_message(TOKEN, b"hi".to_vec(), TTL, None);
        let now = Instant::now();
        let (due, _) = tables.take_due(now, SPACING);
        let (resend, _) = tables.take_due(now + FIRST_RESEND_DELAY, SPACING);
        for packet in [&due[0], &resend[0]] {
            let sealed = tables.forward(packet).unwrap();
            let (header, plaintext) = client.open(&sealed).unwrap();
            assert_eq!(header.packet_type, TYPE_DATA);
            assert_eq!(
                relay_link::parse_forwarded(&plaintext),
                Some((due[0].id, b"hi".as_slice()))
            );
        }
    }

    /// Once a recipient has registered its contacts' tags, packets without
    /// one can only fill a small queue of their own, oldest out first, and
    /// contacts' packets still get in.
    #[test]
    fn strangers_cannot_crowd_out_contacts() {
        let (mut tables, session) = online_tables();
        tables
            .apply_sync(TOKEN, session, vec![[7; 8]], TTL)
            .unwrap();
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

    /// Queues for recipients without tags (including made-up tokens) share
    /// one budget, so filling it with junk can't take the relay's memory,
    /// and doesn't stop packets for recipients who have synced.
    #[test]
    fn recipients_without_tags_share_a_budget() {
        let (mut tables, session) = online_tables();
        tables
            .apply_sync(TOKEN, session, vec![[7; 8]], TTL)
            .unwrap();
        let packet = vec![0xAB; 64 * 1024];
        let mut queued = 0;
        for token in 0..=(MAX_UNREGISTERED_QUEUED_BYTES / MAX_QUEUED_BYTES_PER_TOKEN) as u8 {
            while tables
                .enqueue_message([token; 16], packet.clone(), TTL, None)
                .is_some()
            {
                queued += packet.len();
            }
        }
        assert!(queued <= MAX_UNREGISTERED_QUEUED_BYTES);
        assert!(queued + packet.len() > MAX_UNREGISTERED_QUEUED_BYTES);
        assert!(tables.unregistered_queues_full());
        assert!(
            tables
                .enqueue_message(TOKEN, vec![1; 1000], TTL, Some([7; 8]))
                .is_some(),
            "a recipient who has synced still gets its packets"
        );

        // The budget is recounted at the sweep, so expired junk frees it.
        for queue in tables.message_queues.values_mut() {
            for packet in &mut queue.packets {
                packet.expiry = Instant::now();
            }
        }
        tables.sweep_expired_messages();
        assert_eq!(tables.unregistered_bytes, 0);
        assert!(
            tables
                .enqueue_message([0xEE; 16], packet, TTL, None)
                .is_some()
        );
    }

    #[test]
    fn admission_tags_outlast_the_recipients_metadata() {
        let (mut tables, session) = online_tables();
        tables
            .apply_sync(TOKEN, session, vec![[7; 8]], TTL)
            .unwrap();
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
