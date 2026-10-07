use crate::{RoutingToken, UserIdentity};
use anyhow::{Result, anyhow};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use pqcrypto_kyber::kyber768::{Ciphertext, PublicKey};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::PublicKey as X25519PublicKey;

// Every signed payload below has the same shape on the wire:
//
//   [16-byte sender token | 16-byte target token | 8-byte BE timestamp |
//    payload-specific fields... | 64-byte Ed25519 signature]
//
// and the signature covers everything before it. So each payload only
// defines `signed_bytes()` (the part before the signature); `to_bytes()`,
// `verify()` and signing in `generate()` are all derived from that one
// function, which is what keeps the signed and serialized layouts from ever
// drifting apart. (PQInjectPayload's signature also covers a session binding
// that isn't sent — see its `signing_input`.)

const TOKEN_LEN: usize = 16;
/// Sender token + target token + timestamp.
const HEADER_LEN: usize = TOKEN_LEN * 2 + 8;
const SIG_LEN: usize = 64;
const KYBER_PUB_LEN: usize = 1184;
const KYBER_CT_LEN: usize = 1088;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn write_header(
    out: &mut Vec<u8>,
    routing_token: &RoutingToken,
    target_token: &RoutingToken,
    timestamp: u64,
) {
    out.extend_from_slice(routing_token);
    out.extend_from_slice(target_token);
    out.extend_from_slice(&timestamp.to_be_bytes());
}

/// Splits a received payload into its header fields, the payload-specific
/// middle, and the trailing signature — after checking it's exactly
/// `total_len` bytes.
fn split_payload<'a>(
    bytes: &'a [u8],
    total_len: usize,
    what: &str,
) -> Result<(RoutingToken, RoutingToken, u64, &'a [u8], Signature)> {
    if bytes.len() != total_len {
        return Err(anyhow!("Invalid {what} payload size"));
    }
    let routing_token = bytes[0..16].try_into().unwrap();
    let target_token = bytes[16..32].try_into().unwrap();
    let timestamp = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let body = &bytes[HEADER_LEN..total_len - SIG_LEN];
    let signature = Signature::from_bytes(bytes[total_len - SIG_LEN..].try_into().unwrap());
    Ok((routing_token, target_token, timestamp, body, signature))
}

fn check_signature(signed: &[u8], signature: &Signature, key: &VerifyingKey) -> Result<()> {
    key.verify(signed, signature)
        .map_err(|_| anyhow!("Signature verification failed"))
}

fn with_signature(mut signed: Vec<u8>, signature: &Signature) -> Vec<u8> {
    signed.extend_from_slice(&signature.to_bytes());
    signed
}

/// Placeholder a payload is built with in `generate()` before its real
/// signature (which covers the rest of the payload) is computed.
fn unsigned() -> Signature {
    Signature::from_bytes(&[0u8; SIG_LEN])
}

// ============================================================
// KeyExchangePayload (0x02) — 1393 bytes
// ============================================================

/// Fixed on-wire width of the self-chosen display name carried in
/// `KeyExchangePayload`. Plenty for a pseudonym (e.g. "alice"); longer
/// names are truncated by `encode_name`.
const NAME_LEN: usize = 32;
const KX_LEN: usize = HEADER_LEN + 32 + 32 + KYBER_PUB_LEN + NAME_LEN + 1 + 4 + 4 + SIG_LEN;

// Bits of a KeyExchange's flags byte.
const KX_HAS_PEER_KEYS: u8 = 1;
const KX_HAS_SESSION: u8 = 2;

/// Right-pads `name`'s UTF-8 bytes into a fixed `NAME_LEN` buffer,
/// truncating on a char boundary if it doesn't fit.
fn encode_name(name: &str) -> [u8; NAME_LEN] {
    let mut buf = [0u8; NAME_LEN];
    let bytes = name.as_bytes();
    let mut end = bytes.len().min(NAME_LEN);
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    buf[..end].copy_from_slice(&bytes[..end]);
    buf
}

/// Inverse of `encode_name` — reads up to the first zero byte (or the
/// whole buffer, for a name that exactly fills it) and lossily decodes it.
fn decode_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub struct KeyExchangePayload {
    pub routing_token: RoutingToken,
    pub target_token: RoutingToken,
    pub timestamp: u64,
    pub ed25519_public: VerifyingKey,
    pub x25519_public: X25519PublicKey,
    pub kyber_public: PublicKey,
    /// Sender's self-chosen display name (their login username), empty if
    /// none was set. Part of the signed message, so a blind relay can't
    /// tamper with or inject one.
    pub name: String,
    /// Whether the sender already has the target's KeyExchange. `false`
    /// asks the target to send theirs (again); see
    /// `Client::handle_key_exchange`.
    pub has_peer_keys: bool,
    /// The sender's add ID for the target (see `AddIds` in lib.rs).
    pub add_id: u32,
    /// The session the sender has with the target, named by the target's
    /// add ID it was made for, or `None` if it has none. From the
    /// responder, `None` asks for a session, and the establisher's own add
    /// ID confirms the one it offered.
    pub session: Option<u32>,
    pub signature: Signature,
}

impl KeyExchangePayload {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KX_LEN);
        write_header(
            &mut out,
            &self.routing_token,
            &self.target_token,
            self.timestamp,
        );
        out.extend_from_slice(self.ed25519_public.as_bytes());
        out.extend_from_slice(self.x25519_public.as_bytes());
        out.extend_from_slice(self.kyber_public.as_bytes());
        out.extend_from_slice(&encode_name(&self.name));
        let mut flags = 0;
        if self.has_peer_keys {
            flags |= KX_HAS_PEER_KEYS;
        }
        if self.session.is_some() {
            flags |= KX_HAS_SESSION;
        }
        out.push(flags);
        out.extend_from_slice(&self.add_id.to_be_bytes());
        out.extend_from_slice(&self.session.unwrap_or(0).to_be_bytes());
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        with_signature(self.signed_bytes(), &self.signature)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (routing_token, target_token, timestamp, body, signature) =
            split_payload(bytes, KX_LEN, "key exchange")?;
        let (body, ids) = body.split_at(body.len() - 8);
        let (body, flags) = body.split_at(body.len() - 1);
        if flags[0] & !(KX_HAS_PEER_KEYS | KX_HAS_SESSION) != 0 {
            return Err(anyhow!("Invalid key exchange flags"));
        }
        let add_id = u32::from_be_bytes(ids[..4].try_into().unwrap());
        let session_add_id = u32::from_be_bytes(ids[4..].try_into().unwrap());
        let ed25519_public = VerifyingKey::from_bytes(body[0..32].try_into().unwrap())
            .map_err(|_| anyhow!("Invalid Ed25519"))?;
        let x25519_public = X25519PublicKey::from(<[u8; 32]>::try_from(&body[32..64]).unwrap());
        let kyber_public = PublicKey::from_bytes(&body[64..64 + KYBER_PUB_LEN])
            .map_err(|_| anyhow!("Invalid Kyber"))?;
        let name = decode_name(&body[64 + KYBER_PUB_LEN..]);
        Ok(Self {
            routing_token,
            target_token,
            timestamp,
            ed25519_public,
            x25519_public,
            kyber_public,
            name,
            has_peer_keys: flags[0] & KX_HAS_PEER_KEYS != 0,
            add_id,
            session: (flags[0] & KX_HAS_SESSION != 0).then_some(session_add_id),
            signature,
        })
    }

    pub fn generate(
        identity: &UserIdentity,
        target_token: RoutingToken,
        name: &str,
        has_peer_keys: bool,
        add_id: u32,
        session: Option<u32>,
    ) -> Self {
        let mut payload = Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp: now_secs(),
            ed25519_public: identity.ed25519_public,
            x25519_public: identity.x25519_public,
            kyber_public: identity.kyber_public,
            name: name.to_string(),
            has_peer_keys,
            add_id,
            session,
            signature: unsigned(),
        };
        payload.signature = identity.ed25519_secret.sign(&payload.signed_bytes());
        payload
    }

    pub fn verify(&self, verifier: &VerifyingKey) -> Result<()> {
        check_signature(&self.signed_bytes(), &self.signature, verifier)
    }
}

// ============================================================
// SessionEstablishPayload (0x04) — 1232 bytes
// ============================================================

const EST_LEN: usize = HEADER_LEN + KYBER_CT_LEN + 32 + 4 + 4 + SIG_LEN;

pub struct SessionEstablishPayload {
    pub routing_token: RoutingToken,
    pub target_token: RoutingToken,
    pub timestamp: u64,
    pub kyber_ct: Ciphertext,
    pub eph_x25519_pub: X25519PublicKey,
    /// The add IDs (see `AddIds` in lib.rs) this session was made for: the
    /// establisher's (the sender's) and the responder's.
    pub establisher_add_id: u32,
    pub responder_add_id: u32,
    pub signature: Signature,
}

impl SessionEstablishPayload {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EST_LEN);
        write_header(
            &mut out,
            &self.routing_token,
            &self.target_token,
            self.timestamp,
        );
        out.extend_from_slice(self.kyber_ct.as_bytes());
        out.extend_from_slice(self.eph_x25519_pub.as_bytes());
        out.extend_from_slice(&self.establisher_add_id.to_be_bytes());
        out.extend_from_slice(&self.responder_add_id.to_be_bytes());
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        with_signature(self.signed_bytes(), &self.signature)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (routing_token, target_token, timestamp, body, signature) =
            split_payload(bytes, EST_LEN, "session establish")?;
        let kyber_ct = Ciphertext::from_bytes(&body[..KYBER_CT_LEN])
            .map_err(|_| anyhow!("Invalid Kyber CT"))?;
        let ids = &body[KYBER_CT_LEN + 32..];
        let eph_x25519_pub = X25519PublicKey::from(
            <[u8; 32]>::try_from(&body[KYBER_CT_LEN..KYBER_CT_LEN + 32]).unwrap(),
        );
        Ok(Self {
            routing_token,
            target_token,
            timestamp,
            kyber_ct,
            eph_x25519_pub,
            establisher_add_id: u32::from_be_bytes(ids[..4].try_into().unwrap()),
            responder_add_id: u32::from_be_bytes(ids[4..].try_into().unwrap()),
            signature,
        })
    }

    pub fn generate(
        identity: &UserIdentity,
        target_token: RoutingToken,
        kyber_ct: Ciphertext,
        eph_x25519_pub: X25519PublicKey,
        establisher_add_id: u32,
        responder_add_id: u32,
    ) -> Self {
        let mut payload = Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp: now_secs(),
            kyber_ct,
            eph_x25519_pub,
            establisher_add_id,
            responder_add_id,
            signature: unsigned(),
        };
        payload.signature = identity.ed25519_secret.sign(&payload.signed_bytes());
        payload
    }

    pub fn verify(&self, ed25519_pub: &VerifyingKey) -> Result<()> {
        check_signature(&self.signed_bytes(), &self.signature, ed25519_pub)
    }
}

// ============================================================
// PQInjectPayload (0x05) — 1200 bytes
// ============================================================

const PQI_LEN: usize = HEADER_LEN + 8 + KYBER_CT_LEN + SIG_LEN;

pub struct PQInjectPayload {
    pub routing_token: RoutingToken,
    pub target_token: RoutingToken,
    pub timestamp: u64,
    /// The sender's `send_count` when it mixed this refresh into its send
    /// chain, i.e. the sequence number of the first message encrypted on
    /// the refreshed chain. Lets the receiver mix it in at exactly the same
    /// point, whatever order the refresh and the messages around it arrive
    /// in, and recognise a resent copy (see
    /// `SymmetricSessionState::accept_pq_inject`).
    pub applies_at: u64,
    pub kyber_ct: Ciphertext,
    pub signature: Signature,
}

impl PQInjectPayload {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PQI_LEN);
        write_header(
            &mut out,
            &self.routing_token,
            &self.target_token,
            self.timestamp,
        );
        out.extend_from_slice(&self.applies_at.to_be_bytes());
        out.extend_from_slice(self.kyber_ct.as_bytes());
        out
    }

    /// What the signature covers: everything before it on the wire, plus
    /// `session_binding` (see `SymmetricSessionState::pq_inject_binding`),
    /// which isn't sent. That ties the refresh to the one session it was
    /// made for, so it can't be replayed into a later session with the same
    /// peer, where its `applies_at` position would come round again.
    fn signing_input(&self, session_binding: &[u8; 32]) -> Vec<u8> {
        let mut input = self.signed_bytes();
        input.extend_from_slice(session_binding);
        input
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        with_signature(self.signed_bytes(), &self.signature)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (routing_token, target_token, timestamp, body, signature) =
            split_payload(bytes, PQI_LEN, "PQ inject")?;
        let applies_at = u64::from_be_bytes(body[..8].try_into().unwrap());
        let kyber_ct =
            Ciphertext::from_bytes(&body[8..]).map_err(|_| anyhow!("Invalid Kyber CT"))?;
        Ok(Self {
            routing_token,
            target_token,
            timestamp,
            applies_at,
            kyber_ct,
            signature,
        })
    }

    pub fn generate(
        identity: &UserIdentity,
        target_token: RoutingToken,
        applies_at: u64,
        kyber_ct: Ciphertext,
        session_binding: &[u8; 32],
    ) -> Self {
        let mut payload = Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp: now_secs(),
            applies_at,
            kyber_ct,
            signature: unsigned(),
        };
        payload.signature = identity
            .ed25519_secret
            .sign(&payload.signing_input(session_binding));
        payload
    }

    pub fn verify(&self, ed25519_pub: &VerifyingKey, session_binding: &[u8; 32]) -> Result<()> {
        check_signature(
            &self.signing_input(session_binding),
            &self.signature,
            ed25519_pub,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire sizes are part of the protocol (peers running older builds
    /// must still parse these), so pin them against the documented values.
    #[test]
    fn payload_sizes_match_the_wire_format() {
        assert_eq!(KX_LEN, 1393);
        assert_eq!(EST_LEN, 1232);
        assert_eq!(PQI_LEN, 1200);
    }

    /// Byte-for-byte layout pin: the same fields concatenated by hand, in
    /// the order the original (pre-refactor) implementation wrote them.
    #[test]
    fn key_exchange_bytes_match_the_original_layout() {
        let identity = UserIdentity::generate();
        let target = [9u8; 16];
        let kx = KeyExchangePayload::generate(&identity, target, "alice", true, 7, Some(9));

        let mut expected = Vec::new();
        expected.extend_from_slice(&identity.routing_token);
        expected.extend_from_slice(&target);
        expected.extend_from_slice(&kx.timestamp.to_be_bytes());
        expected.extend_from_slice(identity.ed25519_public.as_bytes());
        expected.extend_from_slice(identity.x25519_public.as_bytes());
        expected.extend_from_slice(identity.kyber_public.as_bytes());
        expected.extend_from_slice(&encode_name("alice"));
        expected.push(KX_HAS_PEER_KEYS | KX_HAS_SESSION);
        expected.extend_from_slice(&7u32.to_be_bytes());
        expected.extend_from_slice(&9u32.to_be_bytes());
        identity
            .ed25519_public
            .verify(&expected, &kx.signature)
            .expect("signature covers exactly the original signed layout");
        expected.extend_from_slice(&kx.signature.to_bytes());

        assert_eq!(kx.to_bytes(), expected);
        let parsed = KeyExchangePayload::from_bytes(&expected).unwrap();
        assert_eq!(parsed.name, "alice");
        assert!(parsed.has_peer_keys);
        assert_eq!((parsed.add_id, parsed.session), (7, Some(9)));
        assert!(parsed.verify(&identity.ed25519_public).is_ok());

        let mut bad_flag = expected;
        bad_flag[KX_LEN - SIG_LEN - 9] = 4;
        assert!(KeyExchangePayload::from_bytes(&bad_flag).is_err());
    }

    /// No session is `None`, not a session for add ID 0 (which a contact
    /// added before add IDs existed has).
    #[test]
    fn key_exchange_tells_no_session_from_add_id_zero() {
        let identity = UserIdentity::generate();
        for session in [None, Some(0), Some(u32::MAX)] {
            let kx = KeyExchangePayload::generate(&identity, [9u8; 16], "", false, 0, session);
            let parsed = KeyExchangePayload::from_bytes(&kx.to_bytes()).unwrap();
            assert_eq!(parsed.session, session);
            assert!(!parsed.has_peer_keys);
        }
    }
}
