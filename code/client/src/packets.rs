use crate::{RoutingToken, UserIdentity};
use anyhow::{Result, anyhow};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use pqcrypto_kyber::kyber768::{Ciphertext, PublicKey};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::PublicKey as X25519PublicKey;

// ============================================================
// KeyExchangePayload (0x02) — 1384 bytes
// ============================================================

/// Fixed on-wire width of the self-chosen display name carried in
/// `KeyExchangePayload`. Plenty for a pseudonym (e.g. "alice"); longer
/// names are truncated by `encode_name`.
const NAME_LEN: usize = 32;

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
    /// Sender's self-chosen display name (e.g. set via
    /// `./runpeer.sh alice`), empty if none was set. Part of the signed
    /// message, so a blind relay can't tamper with or inject one.
    pub name: String,
    pub signature: Signature,
}

impl KeyExchangePayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1384);
        out.extend_from_slice(&self.routing_token);
        out.extend_from_slice(&self.target_token);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(self.ed25519_public.as_bytes());
        out.extend_from_slice(self.x25519_public.as_bytes());
        out.extend_from_slice(self.kyber_public.as_bytes());
        out.extend_from_slice(&encode_name(&self.name));
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 1384 {
            return Err(anyhow!("Invalid key exchange payload size"));
        }
        let mut routing_token = [0u8; 16];
        routing_token.copy_from_slice(&bytes[0..16]);
        let mut target_token = [0u8; 16];
        target_token.copy_from_slice(&bytes[16..32]);
        let mut ts_arr = [0u8; 8];
        ts_arr.copy_from_slice(&bytes[32..40]);
        let timestamp = u64::from_be_bytes(ts_arr);
        let mut ed_arr = [0u8; 32];
        ed_arr.copy_from_slice(&bytes[40..72]);
        let ed25519_public =
            VerifyingKey::from_bytes(&ed_arr).map_err(|_| anyhow!("Invalid Ed25519"))?;
        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&bytes[72..104]);
        let x25519_public = X25519PublicKey::from(x_arr);
        let kyber_public =
            PublicKey::from_bytes(&bytes[104..1288]).map_err(|_| anyhow!("Invalid Kyber"))?;
        let name = decode_name(&bytes[1288..1320]);
        let signature = Signature::from_bytes(bytes[1320..1384].try_into().unwrap());
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
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut msg = Vec::with_capacity(1320);
        msg.extend_from_slice(&identity.routing_token);
        msg.extend_from_slice(&target_token);
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(identity.ed25519_public.as_bytes());
        msg.extend_from_slice(identity.x25519_public.as_bytes());
        msg.extend_from_slice(identity.kyber_public.as_bytes());
        msg.extend_from_slice(&encode_name(name));
        let signature = identity.ed25519_secret.sign(&msg);
        Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp,
            ed25519_public: identity.ed25519_public,
            x25519_public: identity.x25519_public,
            kyber_public: identity.kyber_public,
            name: name.to_string(),
            signature,
        }
    }

    pub fn verify(&self, verifier: &VerifyingKey) -> Result<()> {
        let mut msg = Vec::with_capacity(1320);
        msg.extend_from_slice(&self.routing_token);
        msg.extend_from_slice(&self.target_token);
        msg.extend_from_slice(&self.timestamp.to_be_bytes());
        msg.extend_from_slice(self.ed25519_public.as_bytes());
        msg.extend_from_slice(self.x25519_public.as_bytes());
        msg.extend_from_slice(self.kyber_public.as_bytes());
        msg.extend_from_slice(&encode_name(&self.name));
        verifier
            .verify(&msg, &self.signature)
            .map_err(|_| anyhow!("Signature verification failed"))
    }
}

// ============================================================
// SessionEstablishPayload (0x04) — 1224 bytes
// ============================================================

pub struct SessionEstablishPayload {
    pub routing_token: RoutingToken,
    pub target_token: RoutingToken,
    pub timestamp: u64,
    pub kyber_ct: Ciphertext,
    pub eph_x25519_pub: X25519PublicKey,
    pub signature: Signature,
}

impl SessionEstablishPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1224);
        out.extend_from_slice(&self.routing_token);
        out.extend_from_slice(&self.target_token);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(self.kyber_ct.as_bytes());
        out.extend_from_slice(self.eph_x25519_pub.as_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 1224 {
            return Err(anyhow!("Invalid session establish payload size"));
        }
        let mut routing_token = [0u8; 16];
        routing_token.copy_from_slice(&bytes[0..16]);
        let mut target_token = [0u8; 16];
        target_token.copy_from_slice(&bytes[16..32]);
        let mut ts_arr = [0u8; 8];
        ts_arr.copy_from_slice(&bytes[32..40]);
        let timestamp = u64::from_be_bytes(ts_arr);
        let kyber_ct =
            Ciphertext::from_bytes(&bytes[40..1128]).map_err(|_| anyhow!("Invalid Kyber CT"))?;
        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&bytes[1128..1160]);
        let eph_x25519_pub = X25519PublicKey::from(x_arr);
        let signature = Signature::from_bytes(bytes[1160..1224].try_into().unwrap());
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
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut msg = Vec::with_capacity(1160);
        msg.extend_from_slice(&identity.routing_token);
        msg.extend_from_slice(&target_token);
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(kyber_ct.as_bytes());
        msg.extend_from_slice(eph_x25519_pub.as_bytes());
        let signature = identity.ed25519_secret.sign(&msg);
        Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp,
            kyber_ct,
            eph_x25519_pub,
            signature,
        }
    }

    pub fn verify(&self, ed25519_pub: &VerifyingKey) -> Result<()> {
        let mut msg = Vec::with_capacity(1160);
        msg.extend_from_slice(&self.routing_token);
        msg.extend_from_slice(&self.target_token);
        msg.extend_from_slice(&self.timestamp.to_be_bytes());
        msg.extend_from_slice(self.kyber_ct.as_bytes());
        msg.extend_from_slice(self.eph_x25519_pub.as_bytes());
        ed25519_pub
            .verify(&msg, &self.signature)
            .map_err(|_| anyhow!("Signature verification failed"))
    }
}

// ============================================================
// PQInjectPayload (0x05) — 1192 bytes
// ============================================================

pub struct PQInjectPayload {
    pub routing_token: RoutingToken,
    pub target_token: RoutingToken,
    pub timestamp: u64,
    pub kyber_ct: Ciphertext,
    pub signature: Signature,
}

impl PQInjectPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1192);
        out.extend_from_slice(&self.routing_token); // 0..16
        out.extend_from_slice(&self.target_token); // 16..32
        out.extend_from_slice(&self.timestamp.to_be_bytes()); // 32..40
        out.extend_from_slice(self.kyber_ct.as_bytes()); // 40..1128
        out.extend_from_slice(&self.signature.to_bytes()); // 1128..1192
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 1192 {
            return Err(anyhow!("Invalid PQ inject payload size"));
        }
        let mut routing_token = [0u8; 16];
        routing_token.copy_from_slice(&bytes[0..16]);
        let mut target_token = [0u8; 16];
        target_token.copy_from_slice(&bytes[16..32]);
        let mut ts_arr = [0u8; 8];
        ts_arr.copy_from_slice(&bytes[32..40]);
        let timestamp = u64::from_be_bytes(ts_arr);
        let kyber_ct =
            Ciphertext::from_bytes(&bytes[40..1128]).map_err(|_| anyhow!("Invalid Kyber CT"))?;
        let signature = Signature::from_bytes(bytes[1128..1192].try_into().unwrap());
        Ok(Self {
            routing_token,
            target_token,
            timestamp,
            kyber_ct,
            signature,
        })
    }

    pub fn generate(
        identity: &UserIdentity,
        target_token: RoutingToken,
        kyber_ct: Ciphertext,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut msg = Vec::with_capacity(1128);
        msg.extend_from_slice(&identity.routing_token);
        msg.extend_from_slice(&target_token);
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(kyber_ct.as_bytes());
        let signature = identity.ed25519_secret.sign(&msg);
        Self {
            routing_token: identity.routing_token,
            target_token,
            timestamp,
            kyber_ct,
            signature,
        }
    }

    pub fn verify(&self, ed25519_pub: &VerifyingKey) -> Result<()> {
        let mut msg = Vec::with_capacity(1128);
        msg.extend_from_slice(&self.routing_token);
        msg.extend_from_slice(&self.target_token);
        msg.extend_from_slice(&self.timestamp.to_be_bytes());
        msg.extend_from_slice(self.kyber_ct.as_bytes());
        ed25519_pub
            .verify(&msg, &self.signature)
            .map_err(|_| anyhow!("Signature verification failed"))
    }
}
