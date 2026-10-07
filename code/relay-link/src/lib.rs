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
//! It gives the link a session ID, chosen by the relay, and a key. Every
//! packet after it is a *link packet* (`seal`):
//!
//!   [1-byte type | 4-byte session ID | 24-byte nonce | XChaCha20-Poly1305(plaintext)]
//!
//! The type and session ID are in the clear so the relay can find the key,
//! and they're authenticated along with the plaintext. The plaintexts are:
//!
//! | Type | Direction | Plaintext |
//! |---|---|---|
//! | `TYPE_DATA` | client -> relay | recipient's token, inner payload |
//! | `TYPE_ADMITTED_DATA` | client -> relay | recipient's token, admission tag, inner payload |
//! | `TYPE_DATA` | relay -> client | delivery ID, inner payload |
//! | `TYPE_ACK` | client -> relay | own token, delivery IDs |
//! | `TYPE_SYNC` | client -> relay | see `Sync` |
//! | `TYPE_PATH_CHALLENGE` | relay -> client | a challenge |
//! | `TYPE_PATH_RESPONSE` | client -> relay | the same challenge |
//!
//! The inner payload is the clients' own business (end-to-end encrypted
//! wherever it says anything private); the relay only routes it.
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
//!   there comes back over the link, so a sync copied off the wire and
//!   replayed from somewhere else can't move anyone's messages.
//! - **Who its contacts are.** A sync registers one admission tag per
//!   contact, which only that contact can compute, and contacts put it on
//!   what they send (`TYPE_ADMITTED_DATA`). Packets without one, including
//!   from anyone who only knows the token from a QR code, share a small
//!   queue of their own, so they can't crowd out messages from contacts.

use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
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

/// Most admission tags one `Sync` registers. Keeps a sync to one small
/// datagram; contacts beyond this share the queue for everyone else.
pub const MAX_ADMISSION_TAGS: usize = 64;

/// Inner payload of a forwarded chat packet. Clients send chat as sealed FEC
/// symbols, and every chunk inside is padded to a fixed block, so every
/// symbol is the maximum size:
///   1 type + 16 sender token + 24 nonce + 12 FEC header + 1024 symbol + 16 tag.
/// The relay's dummy packets are this size too, so the two look alike.
pub const CHAT_INNER_PAYLOAD_LEN: usize = 1 + 16 + 24 + 12 + 1024 + 16;

const NONCE_LEN: usize = 24;
/// What a link packet adds around its plaintext: type, session ID, nonce
/// and AEAD tag.
pub const LINK_OVERHEAD: usize = 1 + 4 + NONCE_LEN + 16;

pub const HANDSHAKE_INIT_LEN: usize = 1 + 32 + 32 + 64;
pub const HANDSHAKE_RESP_LEN: usize = 1 + 4 + 32 + 64;
const SYNC_BASE_LEN: usize = 16 + 32 + 64;

const HKDF_SALT: &[u8] = b"e2e-messenger-v1";
const LINK_KEY_LABEL: &[u8] = b"wireguard-lite-link";
const HANDSHAKE_LABEL: &[u8] = b"e2e-messenger/handshake/v1";
const ROUTING_TOKEN_LABEL: &[u8] = b"e2e-messenger/routing-token/v1";
const SYNC_SIGNATURE_LABEL: &[u8] = b"e2e-messenger/sync/v1";

/// Why a packet was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// The wrong length or type, or a key that isn't a valid one.
    Malformed,
    /// A signature that doesn't verify.
    BadSignature,
    /// A sync for a routing token that isn't its key's.
    TokenNotOwned,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LinkError::Malformed => "malformed packet",
            LinkError::BadSignature => "invalid signature",
            LinkError::TokenNotOwned => "sync for a routing token its key doesn't own",
        })
    }
}

impl std::error::Error for LinkError {}

fn cipher(link_key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(link_key))
}

/// Seal `plaintext` as a link packet of `packet_type` on link `session_id`.
pub fn seal(
    link_key: &[u8; 32],
    packet_type: u8,
    session_id: &SessionId,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(LINK_OVERHEAD + plaintext.len());
    packet.push(packet_type);
    packet.extend_from_slice(session_id);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher(link_key)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &packet[..5],
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers");
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ciphertext);
    packet
}

/// A link packet's type and session ID, or `None` if it's too short to be
/// one.
pub fn header(packet: &[u8]) -> Option<(u8, SessionId)> {
    if packet.len() < LINK_OVERHEAD {
        return None;
    }
    Some((packet[0], packet[1..5].try_into().unwrap()))
}

/// Open a link packet: its plaintext, or `None` unless it was sealed with
/// `link_key` exactly as it reads, type and session ID included.
pub fn open(link_key: &[u8; 32], packet: &[u8]) -> Option<Vec<u8>> {
    header(packet)?;
    cipher(link_key)
        .decrypt(
            XNonce::from_slice(&packet[5..5 + NONCE_LEN]),
            Payload {
                msg: &packet[5 + NONCE_LEN..],
                aad: &packet[..5],
            },
        )
        .ok()
}

/// The link key both ends derive from the handshake's X25519 shared secret.
pub fn derive_link_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret)
        .expand(LINK_KEY_LABEL, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// The client's first packet: a fresh X25519 key for the link key, and
/// its Ed25519 identity key's signature over it.
pub fn handshake_init(identity: &SigningKey, ephemeral: &X25519PublicKey) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HANDSHAKE_INIT_LEN);
    packet.push(TYPE_HANDSHAKE_INIT);
    packet.extend_from_slice(ephemeral.as_bytes());
    packet.extend_from_slice(identity.verifying_key().as_bytes());
    packet.extend_from_slice(&identity.sign(ephemeral.as_bytes()).to_bytes());
    packet
}

/// The client's ephemeral key from its handshake init, if the packet is
/// well formed and its signature checks out.
pub fn parse_handshake_init(packet: &[u8]) -> Result<X25519PublicKey, LinkError> {
    if packet.len() != HANDSHAKE_INIT_LEN || packet[0] != TYPE_HANDSHAKE_INIT {
        return Err(LinkError::Malformed);
    }
    let ephemeral: [u8; 32] = packet[1..33].try_into().unwrap();
    let identity = VerifyingKey::from_bytes(packet[33..65].try_into().unwrap())
        .map_err(|_| LinkError::Malformed)?;
    let signature = Signature::from_bytes(packet[65..].try_into().unwrap());
    identity
        .verify_strict(&ephemeral, &signature)
        .map_err(|_| LinkError::BadSignature)?;
    Ok(X25519PublicKey::from(ephemeral))
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

/// What a sync's signature covers: a value derived from the link key, which
/// only the link's two ends know, so a signed sync proves nothing on any
/// other link.
pub fn sync_signing_input(link_key: &[u8; 32]) -> Vec<u8> {
    let mut binding = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), link_key)
        .expand(b"sync-binding", &mut binding)
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
    /// A sync for the token `token_secret` owns, on the link with key
    /// `link_key`. Only the first `MAX_ADMISSION_TAGS` tags are kept.
    pub fn new(
        token_secret: &SigningKey,
        link_key: &[u8; 32],
        mut admission: Vec<AdmissionTag>,
    ) -> Self {
        admission.truncate(MAX_ADMISSION_TAGS);
        let token_public = token_secret.verifying_key();
        Self {
            token: routing_token_for(&token_public),
            token_public,
            signature: token_secret.sign(&sync_signing_input(link_key)),
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

    /// Whether this proves the token's owner is on the link with key
    /// `link_key`: the token is the key's, and the signature covers this
    /// link.
    pub fn verify(&self, link_key: &[u8; 32]) -> Result<(), LinkError> {
        if routing_token_for(&self.token_public) != self.token {
            return Err(LinkError::TokenNotOwned);
        }
        self.token_public
            .verify_strict(&sync_signing_input(link_key), &self.signature)
            .map_err(|_| LinkError::BadSignature)
    }
}

/// A client's packet for `recipient`: `TYPE_ADMITTED_DATA` carrying
/// `admission` if there is one, otherwise `TYPE_DATA`.
pub fn data_packet(
    link_key: &[u8; 32],
    session_id: &SessionId,
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
    seal(link_key, packet_type, session_id, &plaintext)
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

/// The relay forwarding `inner` to a recipient, with the delivery ID it
/// acks it with.
pub fn forwarded_packet(
    link_key: &[u8; 32],
    session_id: &SessionId,
    delivery_id: &DeliveryId,
    inner: &[u8],
) -> Vec<u8> {
    seal(
        link_key,
        TYPE_DATA,
        session_id,
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
    use x25519_dalek::EphemeralSecret;

    fn signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn ephemeral() -> X25519PublicKey {
        X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng))
    }

    #[test]
    fn link_packets_open_only_as_sealed() {
        let key = [7u8; 32];
        let packet = seal(&key, TYPE_SYNC, &[1, 2, 3, 4], b"hello");
        assert_eq!(packet.len(), LINK_OVERHEAD + 5);
        assert_eq!(header(&packet), Some((TYPE_SYNC, [1, 2, 3, 4])));
        assert_eq!(open(&key, &packet).unwrap(), b"hello");
        assert!(open(&[8u8; 32], &packet).is_none(), "another link's key");

        // The type and session ID are authenticated too: a packet can't be
        // relabelled as another type, or moved to another link.
        for byte in 0..5 {
            let mut tampered = packet.clone();
            tampered[byte] ^= 1;
            assert!(open(&key, &tampered).is_none(), "byte {byte}");
        }
        assert!(open(&key, &packet[..LINK_OVERHEAD - 1]).is_none());
    }

    #[test]
    fn handshake_gives_both_ends_the_session_id_and_key() {
        let (client, relay) = (signing_key(), signing_key());
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_ephemeral = X25519PublicKey::from(&client_secret);
        let init = handshake_init(&client, &client_ephemeral);
        assert_eq!(parse_handshake_init(&init), Ok(client_ephemeral));

        let relay_secret = EphemeralSecret::random_from_rng(OsRng);
        let relay_ephemeral = X25519PublicKey::from(&relay_secret);
        let resp = handshake_resp(&relay, &client_ephemeral, &relay_ephemeral, &[9, 9, 9, 9]);
        let (session_id, got_ephemeral) =
            parse_handshake_resp(&resp, &relay.verifying_key(), &client_ephemeral).unwrap();
        assert_eq!(session_id, [9, 9, 9, 9]);
        assert_eq!(
            derive_link_key(client_secret.diffie_hellman(&got_ephemeral).as_bytes()),
            derive_link_key(relay_secret.diffie_hellman(&client_ephemeral).as_bytes()),
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

        let mut forged_init = handshake_init(&signing_key(), &client_ephemeral);
        forged_init[1] ^= 1;
        assert_eq!(
            parse_handshake_init(&forged_init),
            Err(LinkError::BadSignature)
        );
    }

    #[test]
    fn sync_proves_token_ownership_on_one_link_only() {
        let token_key = signing_key();
        let link_key = [3u8; 32];
        let sync = Sync::new(&token_key, &link_key, vec![[1; 8], [2; 8]]);
        let parsed = Sync::from_bytes(&sync.to_bytes()).unwrap();
        assert_eq!(parsed.token, routing_token_for(&token_key.verifying_key()));
        assert_eq!(parsed.admission, [[1; 8], [2; 8]]);
        assert_eq!(parsed.verify(&link_key), Ok(()));
        assert_eq!(parsed.verify(&[4u8; 32]), Err(LinkError::BadSignature));

        // Someone else's token, with your own key.
        let mut claim = Sync::new(&signing_key(), &link_key, Vec::new());
        claim.token = parsed.token;
        assert_eq!(claim.verify(&link_key), Err(LinkError::TokenNotOwned));
    }

    #[test]
    fn sync_admission_tags_are_bounded() {
        let token_key = signing_key();
        let sync = Sync::new(&token_key, &[0; 32], vec![[5; 8]; MAX_ADMISSION_TAGS + 3]);
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
        let key = [1u8; 32];
        let session = [2; 4];
        for admission in [None, Some([7u8; 8])] {
            let packet = data_packet(&key, &session, &[9; 16], admission.as_ref(), b"inner");
            let (packet_type, _) = header(&packet).unwrap();
            let plaintext = open(&key, &packet).unwrap();
            assert_eq!(
                parse_data(packet_type, &plaintext),
                Some(([9; 16], admission, b"inner".as_slice()))
            );
        }
        assert_eq!(parse_data(TYPE_ADMITTED_DATA, &[0; 23]), None);
        assert_eq!(parse_data(TYPE_SYNC, &[0; 40]), None);
    }

    #[test]
    fn forwarded_packets_and_acks_round_trip() {
        let key = [1u8; 32];
        let packet = forwarded_packet(&key, &[2; 4], &[3; 16], b"inner");
        let plaintext = open(&key, &packet).unwrap();
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
    }
}
