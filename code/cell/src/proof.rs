//! The hello a client opens its link with.
//!
//! TLS authenticates the relay (the app pins its key) but not the client,
//! which stays anonymous at the TLS level: no client certificate, and
//! nothing about the user's identity. Inside the connection, the client's
//! first cells carry a `Frame::Hello` proving two things:
//!
//! 1. **It's the app.** An HMAC under the access key every copy of the app
//!    ships with. The relay ignores the datagrams of a connection without
//!    one, so anyone else who connects (a censor probing the address)
//!    finds only an ordinary HTTP/3 website.
//! 2. **It owns its routing token**: the token is a hash of an Ed25519 key
//!    (see `routing_token_for`), and the hello is signed with it. Only then
//!    does the relay send the token's messages down this link.
//!
//! Both are bound to this connection's TLS session through an exporter
//! value (RFC 5705 / 8446 §7.5) both ends derive: `binding` below. A hello
//! copied from one connection proves nothing on another.

use crate::RoutingToken;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

/// The secret every copy of the app carries, so the relay can tell the app
/// from anyone else who connects.
pub type AccessKey = [u8; 32];

/// access proof | routing token | token public key | signature
pub const HELLO_LEN: usize = 32 + 16 + 32 + 64;

/// Must not change: existing routing tokens (in contacts' QR codes) are
/// derived with it.
const ROUTING_TOKEN_LABEL: &[u8] = b"e2e-messenger/routing-token/v1";
const ACCESS_LABEL: &[u8] = b"e2e-messenger/access/v1";
const SYNC_SIGNATURE_LABEL: &[u8] = b"e2e-messenger/sync/v2";
const HKDF_SALT: &[u8] = b"e2e-messenger-v1";

/// The routing token owned by `token_public`: a truncated hash of it.
pub fn routing_token_for(token_public: &VerifyingKey) -> RoutingToken {
    let digest = Sha256::new()
        .chain_update(ROUTING_TOKEN_LABEL)
        .chain_update(token_public.as_bytes())
        .finalize();
    digest[..16].try_into().unwrap()
}

fn access_mac(access_key: &AccessKey, binding: &[u8; 32]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(access_key).expect("HMAC takes any key length");
    mac.update(ACCESS_LABEL);
    mac.update(binding);
    mac
}

/// What the token key signs: a value derived from this connection's
/// binding, so the signature proves nothing on any other connection.
fn sync_signing_input(binding: &[u8; 32]) -> Vec<u8> {
    let mut derived = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), binding)
        .expand(b"sync-binding", &mut derived)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    [SYNC_SIGNATURE_LABEL, &derived].concat()
}

/// The hello for the connection with `binding`.
pub fn hello(
    access_key: &AccessKey,
    token_secret: &SigningKey,
    binding: &[u8; 32],
) -> [u8; HELLO_LEN] {
    let token_public = token_secret.verifying_key();
    let mut out = [0u8; HELLO_LEN];
    out[..32].copy_from_slice(&access_mac(access_key, binding).finalize().into_bytes());
    out[32..48].copy_from_slice(&routing_token_for(&token_public));
    out[48..80].copy_from_slice(token_public.as_bytes());
    out[80..].copy_from_slice(&token_secret.sign(&sync_signing_input(binding)).to_bytes());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloError {
    /// No valid access proof: not the app (or not this connection's hello).
    NoAccess,
    /// The token isn't the hash of the key offered for it.
    WrongTokenKey,
    /// The token key or its signature doesn't check out.
    BadSignature,
}

impl fmt::Display for HelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HelloError::NoAccess => "hello without a valid access proof",
            HelloError::WrongTokenKey => "hello for a routing token its key doesn't own",
            HelloError::BadSignature => "hello with an invalid token signature",
        })
    }
}

impl std::error::Error for HelloError {}

/// Check a hello against the access key and this connection's binding.
/// Returns the routing token it proved ownership of.
pub fn verify_hello(
    hello: &[u8; HELLO_LEN],
    access_key: &AccessKey,
    binding: &[u8; 32],
) -> Result<RoutingToken, HelloError> {
    // Constant time, and first: nothing else is looked at for a connection
    // that isn't the app.
    access_mac(access_key, binding)
        .verify_slice(&hello[..32])
        .map_err(|_| HelloError::NoAccess)?;
    let token: RoutingToken = hello[32..48].try_into().unwrap();
    let token_public = VerifyingKey::from_bytes(hello[48..80].try_into().unwrap())
        .map_err(|_| HelloError::BadSignature)?;
    if routing_token_for(&token_public) != token {
        return Err(HelloError::WrongTokenKey);
    }
    let signature = Signature::from_bytes(hello[80..].try_into().unwrap());
    token_public
        .verify_strict(&sync_signing_input(binding), &signature)
        .map_err(|_| HelloError::BadSignature)?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    fn signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn a_hello_proves_access_and_token_ownership() {
        let (access, binding, key) = ([1u8; 32], [2u8; 32], signing_key());
        let h = hello(&access, &key, &binding);
        assert_eq!(
            verify_hello(&h, &access, &binding),
            Ok(routing_token_for(&key.verifying_key()))
        );
    }

    #[test]
    fn without_the_access_key_or_on_another_connection_it_proves_nothing() {
        let (access, binding, key) = ([1u8; 32], [2u8; 32], signing_key());
        let h = hello(&access, &key, &binding);
        assert_eq!(
            verify_hello(&h, &[9u8; 32], &binding),
            Err(HelloError::NoAccess)
        );
        assert_eq!(
            verify_hello(&h, &access, &[3u8; 32]),
            Err(HelloError::NoAccess),
            "replayed on another connection"
        );
        let guessed = hello(&[0u8; 32], &key, &binding);
        assert_eq!(
            verify_hello(&guessed, &access, &binding),
            Err(HelloError::NoAccess)
        );
    }

    /// Someone with the app (so the access key) still can't claim another
    /// user's routing token, with their own key or the victim's public key.
    #[test]
    fn nobody_can_claim_someone_elses_token() {
        let (access, binding) = ([1u8; 32], [2u8; 32]);
        let (victim, attacker) = (signing_key(), signing_key());
        let victim_token = routing_token_for(&victim.verifying_key());

        let mut claim = hello(&access, &attacker, &binding);
        claim[32..48].copy_from_slice(&victim_token);
        assert_eq!(
            verify_hello(&claim, &access, &binding),
            Err(HelloError::WrongTokenKey)
        );

        let mut forged = hello(&access, &attacker, &binding);
        forged[32..48].copy_from_slice(&victim_token);
        forged[48..80].copy_from_slice(victim.verifying_key().as_bytes());
        assert_eq!(
            verify_hello(&forged, &access, &binding),
            Err(HelloError::BadSignature)
        );
    }
}
