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
// KeyExchangePayload (0x02) — 1384 bytes
// ============================================================

/// Fixed on-wire width of the self-chosen display name carried in
/// `KeyExchangePayload`. Plenty for a pseudonym (e.g. "alice"); longer
/// names are truncated by `encode_name`.
const NAME_LEN: usize = 32;
const KX_LEN: usize = HEADER_LEN + 32 + 32 + KYBER_PUB_LEN + NAME_LEN + SIG_LEN;

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
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        with_signature(self.signed_bytes(), &self.signature)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (routing_token, target_token, timestamp, body, signature) =
            split_payload(bytes, KX_LEN, "key exchange")?;
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
            signature,
        })
    }

    pub fn generate(identity: &UserIdentity, target_token: RoutingToken, name: &str) -> Self {
        let mut payload = Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp: now_secs(),
            ed25519_public: identity.ed25519_public,
            x25519_public: identity.x25519_public,
            kyber_public: identity.kyber_public,
            name: name.to_string(),
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
// SessionEstablishPayload (0x04) — 1224 bytes
// ============================================================

const EST_LEN: usize = HEADER_LEN + KYBER_CT_LEN + 32 + SIG_LEN;

pub struct SessionEstablishPayload {
    pub routing_token: RoutingToken,
    pub target_token: RoutingToken,
    pub timestamp: u64,
    pub kyber_ct: Ciphertext,
    pub eph_x25519_pub: X25519PublicKey,
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
        let eph_x25519_pub =
            X25519PublicKey::from(<[u8; 32]>::try_from(&body[KYBER_CT_LEN..]).unwrap());
        Ok(Self {
            routing_token,
            target_token,
            timestamp,
            kyber_ct,
            eph_x25519_pub,
            signature,
        })
    }

    pub fn generate(
        identity: &UserIdentity,
        target_token: RoutingToken,
        kyber_ct: Ciphertext,
        eph_x25519_pub: X25519PublicKey,
    ) -> Self {
        let mut payload = Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp: now_secs(),
            kyber_ct,
            eph_x25519_pub,
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

// ============================================================
// PresencePayload (0x06) — 104 bytes
// ============================================================

const PRESENCE_LEN: usize = HEADER_LEN + SIG_LEN;

/// A lightweight "I'm still here" signal sent periodically to each
/// established contact so their client can show an online/offline marker.
/// Deliberately outside the E2E double ratchet (unlike 0x01 Msg) — it
/// doesn't need confidentiality (liveness isn't secret, and the relay
/// already sees routing-token traffic patterns), only authenticity and
/// freshness, so it's just signed like KeyExchange/PQInject rather than
/// consuming a ratchet step (which would also trigger PQ re-injection
/// every `PQ_INJECT_INTERVAL` pings for no reason).
pub struct PresencePayload {
    pub routing_token: RoutingToken,
    pub target_token: RoutingToken,
    pub timestamp: u64,
    pub signature: Signature,
}

impl PresencePayload {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PRESENCE_LEN);
        write_header(
            &mut out,
            &self.routing_token,
            &self.target_token,
            self.timestamp,
        );
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        with_signature(self.signed_bytes(), &self.signature)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (routing_token, target_token, timestamp, _body, signature) =
            split_payload(bytes, PRESENCE_LEN, "presence")?;
        Ok(Self {
            routing_token,
            target_token,
            timestamp,
            signature,
        })
    }

    pub fn generate(identity: &UserIdentity, target_token: RoutingToken) -> Self {
        let mut payload = Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp: now_secs(),
            signature: unsigned(),
        };
        payload.signature = identity.ed25519_secret.sign(&payload.signed_bytes());
        payload
    }

    pub fn verify(&self, ed25519_pub: &VerifyingKey) -> Result<()> {
        check_signature(&self.signed_bytes(), &self.signature, ed25519_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire sizes are part of the protocol (peers running older builds
    /// must still parse these), so pin them against the documented values.
    #[test]
    fn payload_sizes_match_the_wire_format() {
        assert_eq!(KX_LEN, 1384);
        assert_eq!(EST_LEN, 1224);
        assert_eq!(PQI_LEN, 1200);
        assert_eq!(PRESENCE_LEN, 104);
    }

    /// Byte-for-byte layout pin: the same fields concatenated by hand, in
    /// the order the original (pre-refactor) implementation wrote them.
    #[test]
    fn key_exchange_bytes_match_the_original_layout() {
        let identity = UserIdentity::generate();
        let target = [9u8; 16];
        let kx = KeyExchangePayload::generate(&identity, target, "alice");

        let mut expected = Vec::new();
        expected.extend_from_slice(&identity.routing_token);
        expected.extend_from_slice(&target);
        expected.extend_from_slice(&kx.timestamp.to_be_bytes());
        expected.extend_from_slice(identity.ed25519_public.as_bytes());
        expected.extend_from_slice(identity.x25519_public.as_bytes());
        expected.extend_from_slice(identity.kyber_public.as_bytes());
        expected.extend_from_slice(&encode_name("alice"));
        identity
            .ed25519_public
            .verify(&expected, &kx.signature)
            .expect("signature covers exactly the original signed layout");
        expected.extend_from_slice(&kx.signature.to_bytes());

        assert_eq!(kx.to_bytes(), expected);
        let parsed = KeyExchangePayload::from_bytes(&expected).unwrap();
        assert_eq!(parsed.name, "alice");
        assert!(parsed.verify(&identity.ed25519_public).is_ok());
    }
}
