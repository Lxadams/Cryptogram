//! The link between a client and the relay: every UDP packet that crosses
//! it, the handshake that sets it up, and what a client proves to the relay.
//!
//! The client (`code/client`) and the relay (`code/server`) both build on
//! this crate, so a layout, label or key derivation lives here once instead
//! of being copied into each side, where the copies could drift apart.
//!
//! # Packets
//!
//! The handshake is two plain packets (`handshake_init`, `handshake_resp`).
//! It gives the link a session ID, chosen by the relay, and a key for each
//! direction (`LinkKeys`). It doesn't say who the client is: a client only
//! proves anything in its sync. Every packet after the handshake is a *link
//! packet*, which each end seals and opens with its `LinkEnd`:
//!
//!   [1-byte type | 4-byte session ID | 8-byte packet number | ChaCha20-Poly1305(plaintext)]
//!
//! The header is in the clear, so the relay can find the link's keys, and
//! it's authenticated along with the plaintext. The packet number is the
//! nonce: each end numbers what it sends, and takes each number in at most
//! once (see `ReplayWindow`), so a copy of a packet replayed by someone on
//! the network path is refused. And as each direction has its own key, a
//! packet can't be bounced back to the end that sent it. The plaintexts
//! are:
//!
//! | Type | Direction | Plaintext |
//! |---|---|---|
//! | `TYPE_DATA` | client -> relay | recipient's token, inner payload |
//! | `TYPE_ADMITTED_DATA` | client -> relay | recipient's token, admission tag, inner payload |
//! | `TYPE_DATA` | relay -> client | delivery ID, inner payload |
//! | `TYPE_ACK` | client -> relay | own token, delivery IDs |
//! | `TYPE_SYNC` | client -> relay | see `Sync` |
//! | `TYPE_SYNC_ACK` | relay -> client | the sync's packet number |
//! | `TYPE_PATH_CHALLENGE` | relay -> client | a challenge |
//! | `TYPE_PATH_RESPONSE` | client -> relay | the same challenge |
//!
//! The inner payload is the clients' own business (end-to-end encrypted
//! wherever it says anything private); the relay only routes it.
//!
//! # Packet numbers
//!
//! A client numbers what it sends in two lanes (`Lane`): message bursts,
//! which are sealed all at once and then paced out over the next few
//! seconds, and everything else, which goes out as soon as it's sealed.
//! Each lane leaves in the order it was numbered, so the relay only needs a
//! short window per lane for packets reordered on the way. The relay sends
//! in one lane.
//!
//! # What a client proves
//!
//! - **The link is its own.** The relay picks an unused session ID for every
//!   handshake, so seeing a link's ID on the wire doesn't let anyone else
//!   take it over.
//! - **It owns its routing token.** A token is a hash of an Ed25519 key
//!   (`routing_token_for`), and a `Sync` is signed with that key, bound to
//!   the link it arrives on.
//! - **It's at the address it syncs from.** A sync from an address the link
//!   hasn't used yet only takes effect once a `TYPE_PATH_CHALLENGE` sent
//!   there comes back over the link from that address. Packet numbers keep
//!   both the sync and the answer from being replayed from anywhere else.
//! - **Who its contacts are.** A sync registers one admission tag per
//!   contact, which only that contact can compute, and contacts put it on
//!   what they send (`TYPE_ADMITTED_DATA`). Packets without one, including
//!   from anyone who only knows the token from a QR code, share a small
//!   queue of their own, so they can't crowd out messages from contacts.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek::PublicKey as X25519PublicKey;

/// Where the relay delivers a packet: whoever proves ownership of it in a
/// `Sync` (see `routing_token_for`).
pub type RoutingToken = [u8; 16];
/// Identifies a link to the relay. In the clear on every link packet.
pub type SessionId = [u8; 4];
/// The relay's ID for one packet it forwards, which the recipient echoes
/// back in an ack so the relay stops resending it. All zeros on a packet
/// that needs no ack.
pub type DeliveryId = [u8; 16];
/// Marks a packet as coming from one of the recipient's contacts (see
/// `TYPE_ADMITTED_DATA`). Eight bytes is plenty: it can only be guessed one
/// packet at a time.
pub type AdmissionTag = [u8; 8];
/// What a `TYPE_PATH_CHALLENGE` carries, and its response echoes.
pub type Challenge = [u8; 16];
/// A link packet's number: its lane in the top bit (see `Lane`), then its
/// place in that lane. Also its nonce.
pub type PacketNumber = u64;

pub const TYPE_HANDSHAKE_INIT: u8 = 0;
pub const TYPE_DATA: u8 = 1;
pub const TYPE_HANDSHAKE_RESP: u8 = 2;
pub const TYPE_ACK: u8 = 3;
pub const TYPE_SYNC: u8 = 4;
/// Data from one of the recipient's contacts, carrying the admission tag
/// the recipient registered for them in its `Sync`.
pub const TYPE_ADMITTED_DATA: u8 = 5;
/// The relay asking a link to prove it's at the address it just synced
/// from.
pub const TYPE_PATH_CHALLENGE: u8 = 6;
/// The client's answer to a `TYPE_PATH_CHALLENGE`, from that address.
pub const TYPE_PATH_RESPONSE: u8 = 7;
/// The relay telling a client it has taken in one of its syncs, so the
/// client knows its link is still there. A client whose syncs stop being
/// acked does the handshake again.
pub const TYPE_SYNC_ACK: u8 = 8;

/// Most admission tags one `Sync` registers. Keeps a sync to one small
/// datagram; contacts beyond this share the queue for everyone else.
pub const MAX_ADMISSION_TAGS: usize = 64;

/// Inner payload of a forwarded chat packet. Clients send chat as sealed FEC
/// symbols, and every chunk inside is padded to a fixed block, so every
/// symbol is the maximum size:
///   1 type + 16 sender token + 24 nonce + 12 FEC header + 1024 symbol + 16 tag.
/// The relay's dummy packets are this size too, so the two look alike.
pub const CHAT_INNER_PAYLOAD_LEN: usize = 1 + 16 + 24 + 12 + 1024 + 16;

/// A link packet's header: type, session ID and packet number.
const HEADER_LEN: usize = 1 + 4 + 8;
/// What a link packet adds around its plaintext: its header and AEAD tag.
pub const LINK_OVERHEAD: usize = HEADER_LEN + 16;

/// A handshake init is padded to more than the reply it gets, so the relay
/// never sends an address more than it received from it: a handshake with
/// someone else's source address can't make the relay an amplifier.
pub const HANDSHAKE_INIT_LEN: usize = 1 + 32 + 96;
pub const HANDSHAKE_RESP_LEN: usize = 1 + 4 + 32 + 64;
const SYNC_BASE_LEN: usize = 16 + 32 + 64;

const HKDF_SALT: &[u8] = b"e2e-messenger-v1";
const TO_RELAY_KEY_LABEL: &[u8] = b"e2e-messenger/link/v2/to-relay";
const TO_CLIENT_KEY_LABEL: &[u8] = b"e2e-messenger/link/v2/to-client";
const HANDSHAKE_LABEL: &[u8] = b"e2e-messenger/handshake/v2";
const ROUTING_TOKEN_LABEL: &[u8] = b"e2e-messenger/routing-token/v1";
const SYNC_BINDING_LABEL: &[u8] = b"e2e-messenger/sync-binding/v2";
const SYNC_SIGNATURE_LABEL: &[u8] = b"e2e-messenger/sync/v2";

/// Why a packet was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// The wrong length or type, or a key that isn't a valid one.
    Malformed,
    /// A signature that doesn't verify.
    BadSignature,
    /// A sync for a routing token that isn't its key's.
    TokenNotOwned,
    /// A link packet for another link.
    WrongLink,
    /// A link packet that wasn't sealed with the link's key as it reads.
    Forged,
    /// A link packet whose number was taken in already, or is too old to
    /// tell (see `ReplayWindow`).
    Replayed,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LinkError::Malformed => "malformed packet",
            LinkError::BadSignature => "invalid signature",
            LinkError::TokenNotOwned => "sync for a routing token its key doesn't own",
            LinkError::WrongLink => "packet for another link",
            LinkError::Forged => "packet that doesn't authenticate",
            LinkError::Replayed => "replayed packet",
        })
    }
}

impl std::error::Error for LinkError {}

/// A link's keys, one per direction, both from the handshake's X25519
/// shared secret (see `derive_link_keys`).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkKeys {
    /// Seals what the client sends the relay.
    pub to_relay: [u8; 32],
    /// Seals what the relay sends the client.
    pub to_client: [u8; 32],
}

impl fmt::Debug for LinkKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinkKeys { .. }")
    }
}

/// The link's keys, which both ends derive from the handshake's X25519
/// shared secret.
pub fn derive_link_keys(shared_secret: &[u8; 32]) -> LinkKeys {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    let mut keys = LinkKeys::default();
    for (label, key) in [
        (TO_RELAY_KEY_LABEL, &mut keys.to_relay),
        (TO_CLIENT_KEY_LABEL, &mut keys.to_client),
    ] {
        hkdf.expand(label, key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
    }
    keys
}

/// The two runs of packet numbers a client sends in (see the crate docs).
/// Each is numbered, and has its numbers taken in, on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// Packets that go out as soon as they're sealed: syncs, acks,
    /// KeyExchanges and the like. The relay sends everything in this one.
    Direct,
    /// Message bursts: sealed all at once, then paced out over the next few
    /// seconds, behind any bursts already going out.
    Paced,
}

/// The top bit of a packet number: which lane it's in.
const LANE_BIT: PacketNumber = 1 << 63;

impl Lane {
    fn index(self) -> usize {
        self as usize
    }

    fn of(packet_number: PacketNumber) -> Self {
        if packet_number & LANE_BIT == 0 {
            Lane::Direct
        } else {
            Lane::Paced
        }
    }
}

fn nonce(packet_number: PacketNumber) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&packet_number.to_be_bytes());
    nonce.into()
}

/// Seal `plaintext` as packet `packet_number` of `packet_type` on link
/// `session_id`, with the key for the direction it's going. A key must
/// never seal two packets with one number, as the number is the nonce:
/// `LinkEnd` sees to that.
pub fn seal(
    key: &[u8; 32],
    packet_type: u8,
    session_id: &SessionId,
    packet_number: PacketNumber,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(LINK_OVERHEAD + plaintext.len());
    packet.push(packet_type);
    packet.extend_from_slice(session_id);
    packet.extend_from_slice(&packet_number.to_be_bytes());
    let ciphertext = ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            &nonce(packet_number),
            Payload {
                msg: plaintext,
                aad: &packet[..HEADER_LEN],
            },
        )
        .expect("ChaCha20-Poly1305 encryption is infallible for in-memory buffers");
    packet.extend_from_slice(&ciphertext);
    packet
}

/// A link packet's header, which is in the clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub packet_type: u8,
    pub session_id: SessionId,
    pub packet_number: PacketNumber,
}

/// A link packet's header, or `None` if it's too short to be one.
pub fn header(packet: &[u8]) -> Option<Header> {
    if packet.len() < LINK_OVERHEAD {
        return None;
    }
    Some(Header {
        packet_type: packet[0],
        session_id: packet[1..5].try_into().unwrap(),
        packet_number: PacketNumber::from_be_bytes(packet[5..HEADER_LEN].try_into().unwrap()),
    })
}

/// Open a link packet sealed with `key`: its plaintext, or `None` unless it
/// was sealed exactly as it reads, header included. This doesn't know
/// whether it's a replay; `LinkEnd::open` checks that too.
pub fn open(key: &[u8; 32], packet: &[u8]) -> Option<Vec<u8>> {
    let header = header(packet)?;
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            &nonce(header.packet_number),
            Payload {
                msg: &packet[HEADER_LEN..],
                aad: &packet[..HEADER_LEN],
            },
        )
        .ok()
}

/// How many packet numbers behind the newest a lane still takes in, to
/// allow for packets reordered on the way. Anything older is refused, as
/// it can't be told from a replay.
pub const REPLAY_WINDOW: u64 = 1024;
const WINDOW_WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// The packet numbers one lane has taken in: the newest, and which of the
/// `REPLAY_WINDOW` before it (RFC 6479's sliding window).
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    /// One past the newest number taken in, so 0 before the first.
    next: u64,
    /// Bit `n % REPLAY_WINDOW`: whether `n` was taken in, for each `n` in
    /// the window.
    seen: [u64; WINDOW_WORDS],
}

impl ReplayWindow {
    fn bit(n: u64) -> (usize, u64) {
        (((n / 64) % WINDOW_WORDS as u64) as usize, 1 << (n % 64))
    }

    /// Take in number `n`: `true`, recording it, unless it was taken in
    /// before or is more than `REPLAY_WINDOW` behind the newest. Only call
    /// this for a packet that has authenticated, or a forged one could move
    /// the window.
    pub fn accept(&mut self, n: u64) -> bool {
        if n >= self.next {
            if n - self.next >= REPLAY_WINDOW {
                self.seen = [0; WINDOW_WORDS];
            } else {
                // The numbers skipped take over bits last used a window ago.
                for skipped in self.next..n {
                    let (word, mask) = Self::bit(skipped);
                    self.seen[word] &= !mask;
                }
            }
            self.next = n + 1;
        } else if self.next - n > REPLAY_WINDOW {
            return false;
        } else {
            let (word, mask) = Self::bit(n);
            if self.seen[word] & mask != 0 {
                return false;
            }
        }
        let (word, mask) = Self::bit(n);
        self.seen[word] |= mask;
        true
    }
}

/// One end of a link: the keys, how it numbers what it sends, and which
/// numbers it has taken in from the other end.
#[derive(Clone, Debug)]
pub struct LinkEnd {
    session_id: SessionId,
    keys: LinkKeys,
    side: Side,
    /// The next packet number each lane sends with.
    next: [PacketNumber; 2],
    received: [ReplayWindow; 2],
}

/// Which end of a link a `LinkEnd` is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Relay,
}

impl LinkEnd {
    pub fn new(side: Side, keys: LinkKeys, session_id: SessionId) -> Self {
        Self {
            session_id,
            keys,
            side,
            next: [0, LANE_BIT],
            received: Default::default(),
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn keys(&self) -> &LinkKeys {
        &self.keys
    }

    fn sealing_key(&self) -> &[u8; 32] {
        match self.side {
            Side::Client => &self.keys.to_relay,
            Side::Relay => &self.keys.to_client,
        }
    }

    fn opening_key(&self) -> &[u8; 32] {
        match self.side {
            Side::Client => &self.keys.to_client,
            Side::Relay => &self.keys.to_relay,
        }
    }

    /// The number the next packet sealed in `lane` gets.
    pub fn next_packet_number(&self, lane: Lane) -> PacketNumber {
        self.next[lane.index()]
    }

    /// Seal `plaintext` as the next `packet_type` packet in `lane`.
    pub fn seal(&mut self, lane: Lane, packet_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let packet_number = self.next[lane.index()];
        self.next[lane.index()] += 1;
        seal(
            self.sealing_key(),
            packet_type,
            &self.session_id,
            packet_number,
            plaintext,
        )
    }

    /// Open a packet from the other end: its header and plaintext, if it's
    /// for this link, authenticates, and has a packet number not taken in
    /// before, which now has been.
    pub fn open(&mut self, packet: &[u8]) -> Result<(Header, Vec<u8>), LinkError> {
        let header = header(packet).ok_or(LinkError::Malformed)?;
        if header.session_id != self.session_id {
            return Err(LinkError::WrongLink);
        }
        let plaintext = open(self.opening_key(), packet).ok_or(LinkError::Forged)?;
        let lane = Lane::of(header.packet_number);
        if !self.received[lane.index()].accept(header.packet_number & !LANE_BIT) {
            return Err(LinkError::Replayed);
        }
        Ok((header, plaintext))
    }
}

/// The client's first packet: the fresh X25519 key the link's keys come
/// from, padded (see `HANDSHAKE_INIT_LEN`).
pub fn handshake_init(ephemeral: &X25519PublicKey) -> Vec<u8> {
    let mut packet = vec![0u8; HANDSHAKE_INIT_LEN];
    packet[0] = TYPE_HANDSHAKE_INIT;
    packet[1..33].copy_from_slice(ephemeral.as_bytes());
    packet
}

/// The client's ephemeral key from its handshake init, if the packet is
/// well formed.
pub fn parse_handshake_init(packet: &[u8]) -> Result<X25519PublicKey, LinkError> {
    if packet.len() != HANDSHAKE_INIT_LEN
        || packet[0] != TYPE_HANDSHAKE_INIT
        || packet[33..].iter().any(|&byte| byte != 0)
    {
        return Err(LinkError::Malformed);
    }
    Ok(X25519PublicKey::from(
        <[u8; 32]>::try_from(&packet[1..33]).unwrap(),
    ))
}

/// What the relay signs in its handshake reply. Covers the client's
/// ephemeral key, so the reply fits no other handshake, and the session ID,
/// so nobody on the path can swap it.
fn handshake_transcript(
    client_ephemeral: &X25519PublicKey,
    relay_ephemeral: &X25519PublicKey,
    session_id: &SessionId,
) -> Vec<u8> {
    [
        HANDSHAKE_LABEL,
        client_ephemeral.as_bytes(),
        relay_ephemeral.as_bytes(),
        session_id,
    ]
    .concat()
}

/// The relay's reply to a handshake init: the session ID it gives the
/// link, its own fresh X25519 key, and its signature over both (see
/// `handshake_transcript`).
pub fn handshake_resp(
    relay_identity: &SigningKey,
    client_ephemeral: &X25519PublicKey,
    relay_ephemeral: &X25519PublicKey,
    session_id: &SessionId,
) -> Vec<u8> {
    let signature = relay_identity.sign(&handshake_transcript(
        client_ephemeral,
        relay_ephemeral,
        session_id,
    ));
    let mut packet = Vec::with_capacity(HANDSHAKE_RESP_LEN);
    packet.push(TYPE_HANDSHAKE_RESP);
    packet.extend_from_slice(session_id);
    packet.extend_from_slice(relay_ephemeral.as_bytes());
    packet.extend_from_slice(&signature.to_bytes());
    packet
}

/// Check the relay's reply to our handshake init: signed by the relay we
/// expect, for the ephemeral key we sent. Returns the link's session ID and
/// the relay's ephemeral key.
pub fn parse_handshake_resp(
    packet: &[u8],
    relay_public: &VerifyingKey,
    client_ephemeral: &X25519PublicKey,
) -> Result<(SessionId, X25519PublicKey), LinkError> {
    if packet.len() != HANDSHAKE_RESP_LEN || packet[0] != TYPE_HANDSHAKE_RESP {
        return Err(LinkError::Malformed);
    }
    let session_id: SessionId = packet[1..5].try_into().unwrap();
    let relay_ephemeral = X25519PublicKey::from(<[u8; 32]>::try_from(&packet[5..37]).unwrap());
    let signature = Signature::from_bytes(packet[37..].try_into().unwrap());
    relay_public
        .verify_strict(
            &handshake_transcript(client_ephemeral, &relay_ephemeral, &session_id),
            &signature,
        )
        .map_err(|_| LinkError::BadSignature)?;
    Ok((session_id, relay_ephemeral))
}

/// The routing token owned by `token_public`: a truncated hash of it, so a
/// `Sync` can prove ownership by signing with the matching secret key.
pub fn routing_token_for(token_public: &VerifyingKey) -> RoutingToken {
    let digest = Sha256::new()
        .chain_update(ROUTING_TOKEN_LABEL)
        .chain_update(token_public.as_bytes())
        .finalize();
    digest[..16].try_into().unwrap()
}

/// What a sync's signature covers: a value derived from the link's keys,
/// which only the link's two ends know, so a signed sync proves nothing on
/// any other link.
pub fn sync_signing_input(link: &LinkKeys) -> Vec<u8> {
    let mut binding = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), &link.to_relay)
        .expand(SYNC_BINDING_LABEL, &mut binding)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    [SYNC_SIGNATURE_LABEL, &binding].concat()
}

/// A client telling the relay that its routing token lives on this link,
/// proving it owns the token, and saying which contacts' packets get its
/// main queue. Clients send one when they connect and as a keepalive.
///
///   [16-byte token | 32-byte token public key | 64-byte signature | 8-byte admission tag...]
pub struct Sync {
    pub token: RoutingToken,
    pub token_public: VerifyingKey,
    /// Over `sync_signing_input` for the link, by the token's key.
    pub signature: Signature,
    /// One per contact, at most `MAX_ADMISSION_TAGS`. Replaces whatever the
    /// last sync registered.
    pub admission: Vec<AdmissionTag>,
}

impl Sync {
    /// A sync for the token `token_secret` owns, on the link with keys
    /// `link`. Only the first `MAX_ADMISSION_TAGS` tags are kept.
    pub fn new(
        token_secret: &SigningKey,
        link: &LinkKeys,
        mut admission: Vec<AdmissionTag>,
    ) -> Self {
        admission.truncate(MAX_ADMISSION_TAGS);
        let token_public = token_secret.verifying_key();
        Self {
            token: routing_token_for(&token_public),
            token_public,
            signature: token_secret.sign(&sync_signing_input(link)),
            admission,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SYNC_BASE_LEN + 8 * self.admission.len());
        out.extend_from_slice(&self.token);
        out.extend_from_slice(self.token_public.as_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(self.admission.as_flattened());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LinkError> {
        if bytes.len() < SYNC_BASE_LEN {
            return Err(LinkError::Malformed);
        }
        let (tags, rest) = bytes[SYNC_BASE_LEN..].as_chunks::<8>();
        if !rest.is_empty() || tags.len() > MAX_ADMISSION_TAGS {
            return Err(LinkError::Malformed);
        }
        Ok(Self {
            token: bytes[..16].try_into().unwrap(),
            token_public: VerifyingKey::from_bytes(bytes[16..48].try_into().unwrap())
                .map_err(|_| LinkError::Malformed)?,
            signature: Signature::from_bytes(bytes[48..SYNC_BASE_LEN].try_into().unwrap()),
            admission: tags.to_vec(),
        })
    }

    /// Whether this proves the token's owner is on the link with keys
    /// `link`: the token is the key's, and the signature covers this link.
    pub fn verify(&self, link: &LinkKeys) -> Result<(), LinkError> {
        if routing_token_for(&self.token_public) != self.token {
            return Err(LinkError::TokenNotOwned);
        }
        self.token_public
            .verify_strict(&sync_signing_input(link), &self.signature)
            .map_err(|_| LinkError::BadSignature)
    }
}

/// A `TYPE_SYNC_ACK` plaintext: the number of the sync it acks.
pub fn sync_ack_plaintext(sync_packet_number: PacketNumber) -> [u8; 8] {
    sync_packet_number.to_be_bytes()
}

pub fn parse_sync_ack(plaintext: &[u8]) -> Option<PacketNumber> {
    Some(PacketNumber::from_be_bytes(plaintext.try_into().ok()?))
}

/// A client's packet for `recipient`, sealed on `link` in `lane`:
/// `TYPE_ADMITTED_DATA` carrying `admission` if there is one, otherwise
/// `TYPE_DATA`.
pub fn data_packet(
    link: &mut LinkEnd,
    lane: Lane,
    recipient: &RoutingToken,
    admission: Option<&AdmissionTag>,
    inner: &[u8],
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(16 + 8 + inner.len());
    plaintext.extend_from_slice(recipient);
    let packet_type = match admission {
        Some(tag) => {
            plaintext.extend_from_slice(tag);
            TYPE_ADMITTED_DATA
        }
        None => TYPE_DATA,
    };
    plaintext.extend_from_slice(inner);
    link.seal(lane, packet_type, &plaintext)
}

/// The plaintext of a client's `TYPE_DATA` or `TYPE_ADMITTED_DATA` packet:
/// the recipient, the admission tag if it has one, and the inner payload.
pub fn parse_data(
    packet_type: u8,
    plaintext: &[u8],
) -> Option<(RoutingToken, Option<AdmissionTag>, &[u8])> {
    let (recipient, rest) = plaintext.split_first_chunk::<16>()?;
    match packet_type {
        TYPE_DATA => Some((*recipient, None, rest)),
        TYPE_ADMITTED_DATA => {
            let (tag, inner) = rest.split_first_chunk::<8>()?;
            Some((*recipient, Some(*tag), inner))
        }
        _ => None,
    }
}

/// The relay forwarding `inner` to the client on `link`, with the delivery
/// ID it acks it with.
pub fn forwarded_packet(link: &mut LinkEnd, delivery_id: &DeliveryId, inner: &[u8]) -> Vec<u8> {
    link.seal(
        Lane::Direct,
        TYPE_DATA,
        &[delivery_id.as_slice(), inner].concat(),
    )
}

/// A forwarded packet's plaintext: its delivery ID and inner payload.
pub fn parse_forwarded(plaintext: &[u8]) -> Option<(DeliveryId, &[u8])> {
    let (id, inner) = plaintext.split_first_chunk::<16>()?;
    Some((*id, inner))
}

/// An ack's plaintext: the acking client's own token, then the delivery IDs
/// of the packets it has.
pub fn ack_plaintext(own_token: &RoutingToken, ids: &[DeliveryId]) -> Vec<u8> {
    [own_token.as_slice(), ids.as_flattened()].concat()
}

pub fn parse_ack(plaintext: &[u8]) -> Option<(RoutingToken, &[DeliveryId])> {
    let (token, ids) = plaintext.split_first_chunk::<16>()?;
    let (ids, rest) = ids.as_chunks::<16>();
    rest.is_empty().then_some((*token, ids))
}

/// The challenge in a `TYPE_PATH_CHALLENGE` or `TYPE_PATH_RESPONSE`
/// plaintext.
pub fn parse_challenge(plaintext: &[u8]) -> Option<Challenge> {
    plaintext.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::EphemeralSecret;

    fn signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn ephemeral() -> X25519PublicKey {
        X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng))
    }

    fn keys() -> LinkKeys {
        derive_link_keys(&[3u8; 32])
    }

    /// A client's end and the relay's end of one link.
    fn ends() -> (LinkEnd, LinkEnd) {
        (
            LinkEnd::new(Side::Client, keys(), [1, 2, 3, 4]),
            LinkEnd::new(Side::Relay, keys(), [1, 2, 3, 4]),
        )
    }

    #[test]
    fn link_packets_open_only_as_sealed() {
        let key = [7u8; 32];
        let packet = seal(&key, TYPE_SYNC, &[1, 2, 3, 4], 9, b"hello");
        assert_eq!(packet.len(), LINK_OVERHEAD + 5);
        assert_eq!(
            header(&packet),
            Some(Header {
                packet_type: TYPE_SYNC,
                session_id: [1, 2, 3, 4],
                packet_number: 9
            })
        );
        assert_eq!(open(&key, &packet).unwrap(), b"hello");
        assert!(open(&[8u8; 32], &packet).is_none(), "another link's key");

        // The whole header is authenticated: a packet can't be relabelled
        // as another type, moved to another link, or renumbered.
        for byte in 0..HEADER_LEN {
            let mut tampered = packet.clone();
            tampered[byte] ^= 1;
            assert!(open(&key, &tampered).is_none(), "byte {byte}");
        }
        assert!(open(&key, &packet[..LINK_OVERHEAD - 1]).is_none());
    }

    #[test]
    fn each_direction_has_its_own_key() {
        let keys = keys();
        assert_ne!(keys.to_relay, keys.to_client);
        let (mut client, mut relay) = ends();
        let to_client = relay.seal(Lane::Direct, TYPE_DATA, b"for the client");
        assert_eq!(client.open(&to_client).unwrap().1, b"for the client");
        // The same packet bounced back to the relay doesn't open there.
        assert_eq!(relay.open(&to_client), Err(LinkError::Forged));

        let to_relay = client.seal(Lane::Direct, TYPE_DATA, b"for the relay");
        assert_eq!(relay.open(&to_relay).unwrap().1, b"for the relay");
        assert_eq!(client.open(&to_relay), Err(LinkError::Forged));
    }

    #[test]
    fn a_packet_is_taken_in_once() {
        let (mut client, mut relay) = ends();
        let first = client.seal(Lane::Direct, TYPE_ACK, b"a");
        let second = client.seal(Lane::Direct, TYPE_ACK, b"b");
        assert_eq!(relay.open(&second).unwrap().1, b"b");
        assert_eq!(relay.open(&first).unwrap().1, b"a", "reordered is fine");
        assert_eq!(relay.open(&first), Err(LinkError::Replayed));
        assert_eq!(relay.open(&second), Err(LinkError::Replayed));

        let mut other_link = LinkEnd::new(Side::Relay, keys(), [9, 9, 9, 9]);
        let third = client.seal(Lane::Direct, TYPE_ACK, b"c");
        assert_eq!(other_link.open(&third), Err(LinkError::WrongLink));
    }

    /// A burst sealed before some direct packets but sent after them is
    /// still taken in: the lanes are numbered and windowed apart.
    #[test]
    fn lanes_are_numbered_apart() {
        let (mut client, mut relay) = ends();
        let burst: Vec<_> = (0..300)
            .map(|_| client.seal(Lane::Paced, TYPE_DATA, b"burst"))
            .collect();
        for _ in 0..2 * REPLAY_WINDOW {
            let direct = client.seal(Lane::Direct, TYPE_ACK, b"ack");
            assert!(relay.open(&direct).is_ok());
        }
        for packet in &burst {
            assert!(relay.open(packet).is_ok());
        }
        assert_eq!(header(&burst[0]).unwrap().packet_number, LANE_BIT);
        assert_eq!(client.next_packet_number(Lane::Direct), 2 * REPLAY_WINDOW);
    }

    #[test]
    fn replay_window_takes_in_each_number_once_within_its_reach() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(0));
        assert!(!window.accept(0));
        assert!(window.accept(5));
        assert!(window.accept(3), "behind the newest, within the window");
        assert!(!window.accept(3));
        assert!(window.accept(4));

        assert!(window.accept(5 + REPLAY_WINDOW));
        assert!(window.accept(6), "exactly a window behind");
        assert!(!window.accept(5), "more than a window behind");
        assert!(window.accept(7), "not taken in before");
        assert!(!window.accept(6));

        // A jump of more than a window forgets everything before it.
        let far = 10 * REPLAY_WINDOW;
        assert!(window.accept(far));
        assert!(window.accept(far - 1));
        assert!(!window.accept(far - REPLAY_WINDOW - 1));
        // Bits reused after the window moves on start clear.
        for n in far + 1..far + 3 * REPLAY_WINDOW {
            assert!(window.accept(n), "{n}");
        }
    }

    #[test]
    fn handshake_gives_both_ends_the_session_id_and_keys() {
        let relay = signing_key();
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_ephemeral = X25519PublicKey::from(&client_secret);
        let init = handshake_init(&client_ephemeral);
        assert_eq!(init.len(), HANDSHAKE_INIT_LEN);
        assert_eq!(parse_handshake_init(&init), Ok(client_ephemeral));

        let relay_secret = EphemeralSecret::random_from_rng(OsRng);
        let relay_ephemeral = X25519PublicKey::from(&relay_secret);
        let resp = handshake_resp(&relay, &client_ephemeral, &relay_ephemeral, &[9, 9, 9, 9]);
        assert!(resp.len() < init.len(), "never an amplifier");
        let (session_id, got_ephemeral) =
            parse_handshake_resp(&resp, &relay.verifying_key(), &client_ephemeral).unwrap();
        assert_eq!(session_id, [9, 9, 9, 9]);
        assert_eq!(
            derive_link_keys(client_secret.diffie_hellman(&got_ephemeral).as_bytes()),
            derive_link_keys(relay_secret.diffie_hellman(&client_ephemeral).as_bytes()),
        );
    }

    #[test]
    fn handshake_reply_fits_only_its_own_handshake() {
        let relay = signing_key();
        let client_ephemeral = ephemeral();
        let resp = handshake_resp(&relay, &client_ephemeral, &ephemeral(), &[1; 4]);

        let impostor = signing_key().verifying_key();
        assert_eq!(
            parse_handshake_resp(&resp, &impostor, &client_ephemeral),
            Err(LinkError::BadSignature)
        );
        assert_eq!(
            parse_handshake_resp(&resp, &relay.verifying_key(), &ephemeral()),
            Err(LinkError::BadSignature),
            "a reply to someone else's handshake"
        );
        let mut swapped_id = resp.clone();
        swapped_id[1] ^= 1;
        assert_eq!(
            parse_handshake_resp(&swapped_id, &relay.verifying_key(), &client_ephemeral),
            Err(LinkError::BadSignature)
        );
        assert_eq!(
            parse_handshake_resp(
                &resp[..resp.len() - 1],
                &relay.verifying_key(),
                &client_ephemeral
            ),
            Err(LinkError::Malformed)
        );

        let mut init = handshake_init(&client_ephemeral);
        assert_eq!(
            parse_handshake_init(&init[..init.len() - 1]),
            Err(LinkError::Malformed)
        );
        init[HANDSHAKE_INIT_LEN - 1] = 1;
        assert_eq!(
            parse_handshake_init(&init),
            Err(LinkError::Malformed),
            "the padding is zeros"
        );
    }

    #[test]
    fn sync_proves_token_ownership_on_one_link_only() {
        let token_key = signing_key();
        let link = keys();
        let sync = Sync::new(&token_key, &link, vec![[1; 8], [2; 8]]);
        let parsed = Sync::from_bytes(&sync.to_bytes()).unwrap();
        assert_eq!(parsed.token, routing_token_for(&token_key.verifying_key()));
        assert_eq!(parsed.admission, [[1; 8], [2; 8]]);
        assert_eq!(parsed.verify(&link), Ok(()));
        assert_eq!(
            parsed.verify(&derive_link_keys(&[4u8; 32])),
            Err(LinkError::BadSignature)
        );

        // Someone else's token, with your own key.
        let mut claim = Sync::new(&signing_key(), &link, Vec::new());
        claim.token = parsed.token;
        assert_eq!(claim.verify(&link), Err(LinkError::TokenNotOwned));
    }

    #[test]
    fn sync_admission_tags_are_bounded() {
        let token_key = signing_key();
        let sync = Sync::new(&token_key, &keys(), vec![[5; 8]; MAX_ADMISSION_TAGS + 3]);
        assert_eq!(sync.admission.len(), MAX_ADMISSION_TAGS);

        let mut too_many = sync.to_bytes();
        too_many.extend_from_slice(&[6; 8]);
        assert!(Sync::from_bytes(&too_many).is_err());
        let mut ragged = sync.to_bytes();
        ragged.pop();
        assert!(Sync::from_bytes(&ragged).is_err());
        assert!(Sync::from_bytes(&[0; SYNC_BASE_LEN - 1]).is_err());
    }

    #[test]
    fn data_packets_carry_an_admission_tag_only_when_admitted() {
        let (mut client, mut relay) = ends();
        for admission in [None, Some([7u8; 8])] {
            let packet = data_packet(
                &mut client,
                Lane::Paced,
                &[9; 16],
                admission.as_ref(),
                b"inner",
            );
            let (header, plaintext) = relay.open(&packet).unwrap();
            assert_eq!(
                parse_data(header.packet_type, &plaintext),
                Some(([9; 16], admission, b"inner".as_slice()))
            );
        }
        assert_eq!(parse_data(TYPE_ADMITTED_DATA, &[0; 23]), None);
        assert_eq!(parse_data(TYPE_SYNC, &[0; 40]), None);
    }

    #[test]
    fn forwarded_packets_and_acks_round_trip() {
        let (mut client, mut relay) = ends();
        let packet = forwarded_packet(&mut relay, &[3; 16], b"inner");
        let (header, plaintext) = client.open(&packet).unwrap();
        assert_eq!(header.packet_type, TYPE_DATA);
        assert_eq!(
            parse_forwarded(&plaintext),
            Some(([3; 16], b"inner".as_slice()))
        );

        let ack = ack_plaintext(&[4; 16], &[[5; 16], [6; 16]]);
        assert_eq!(
            parse_ack(&ack),
            Some(([4; 16], [[5; 16], [6; 16]].as_slice()))
        );
        assert_eq!(parse_ack(&ack[..ack.len() - 1]), None);

        assert_eq!(parse_sync_ack(&sync_ack_plaintext(42)), Some(42));
        assert_eq!(parse_sync_ack(&[0; 7]), None);
    }
}
