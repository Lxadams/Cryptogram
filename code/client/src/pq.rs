//! ML-KEM-768 (FIPS 203): the post-quantum half of every session's
//! handshake, and the PQ ratchet refreshes (see lib.rs). It's Cryspen's
//! formally verified implementation (`libcrux-ml-kem`), behind the small
//! interface the rest of the crate uses: keys and ciphertexts as fixed-size
//! byte arrays, and key generation and encapsulation drawing their
//! randomness from the OS.
//!
//! Keys and ciphertexts are the sizes round-3 Kyber-768's were, in the same
//! layout, so identities saved with Kyber keys load as ML-KEM keys.

use anyhow::{Result, anyhow};
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PUBLIC_KEY_LEN: usize = 1184;
pub const SECRET_KEY_LEN: usize = 2400;
pub const CIPHERTEXT_LEN: usize = 1088;

/// An ML-KEM-768 encapsulation key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

/// An ML-KEM-768 decapsulation key, wiped from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

/// An ML-KEM-768 ciphertext.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext([u8; CIPHERTEXT_LEN]);

/// A shared secret from encapsulation or decapsulation, wiped from memory
/// when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl PublicKey {
    /// A key as a contact sent it. Refused unless it's a valid encapsulation
    /// key (FIPS 203's input check), so nothing is ever encapsulated to a
    /// malformed one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| anyhow!("An ML-KEM public key is {PUBLIC_KEY_LEN} bytes"))?;
        if !mlkem768::validate_public_key(&MlKem768PublicKey::from(bytes)) {
            return Err(anyhow!("Invalid ML-KEM public key"));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| {
            anyhow!("An ML-KEM secret key is {SECRET_KEY_LEN} bytes")
        })?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Ciphertext {
    /// Any bytes of the right length: decapsulating a bad ciphertext gives
    /// a secret that matches nobody's (FIPS 203's implicit rejection).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| {
            anyhow!("An ML-KEM ciphertext is {CIPHERTEXT_LEN} bytes")
        })?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A fresh key pair.
pub fn keypair() -> (PublicKey, SecretKey) {
    let mut seed = [0u8; 64];
    OsRng.fill_bytes(&mut seed);
    let pair = mlkem768::generate_key_pair(seed);
    seed.zeroize();
    (
        PublicKey(*pair.public_key().as_slice()),
        SecretKey(*pair.private_key().as_slice()),
    )
}

/// A fresh secret, and its encapsulation to `public_key`.
pub fn encapsulate(public_key: &PublicKey) -> (SharedSecret, Ciphertext) {
    let mut randomness = [0u8; 32];
    OsRng.fill_bytes(&mut randomness);
    let (ciphertext, secret) =
        mlkem768::encapsulate(&MlKem768PublicKey::from(public_key.0), randomness);
    randomness.zeroize();
    (SharedSecret(secret), Ciphertext(*ciphertext.as_slice()))
}

/// The secret `ciphertext` encapsulates, for the holder of `secret_key`.
pub fn decapsulate(ciphertext: &Ciphertext, secret_key: &SecretKey) -> SharedSecret {
    SharedSecret(mlkem768::decapsulate(
        &MlKem768PrivateKey::from(secret_key.0),
        &MlKem768Ciphertext::from(ciphertext.0),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulated_secrets_decapsulate_and_keys_round_trip() {
        let (public_key, secret_key) = keypair();
        let (sent, ciphertext) = encapsulate(&public_key);
        assert_eq!(
            decapsulate(&ciphertext, &secret_key).as_bytes(),
            sent.as_bytes()
        );

        let public_again = PublicKey::from_bytes(public_key.as_bytes()).unwrap();
        let secret_again = SecretKey::from_bytes(secret_key.as_bytes()).unwrap();
        let ciphertext_again = Ciphertext::from_bytes(ciphertext.as_bytes()).unwrap();
        assert!(public_again == public_key);
        assert_eq!(
            decapsulate(&ciphertext_again, &secret_again).as_bytes(),
            sent.as_bytes()
        );

        // Another key pair gets a different secret from the same ciphertext.
        let (_, other) = keypair();
        assert_ne!(
            decapsulate(&ciphertext, &other).as_bytes(),
            sent.as_bytes()
        );
    }

    #[test]
    fn malformed_keys_are_refused() {
        assert!(PublicKey::from_bytes(&[0; PUBLIC_KEY_LEN - 1]).is_err());
        // Coefficients of 0xFFF are out of range (over the modulus, 3329).
        assert!(PublicKey::from_bytes(&[0xFF; PUBLIC_KEY_LEN]).is_err());
        assert!(SecretKey::from_bytes(&[0; SECRET_KEY_LEN + 1]).is_err());
        assert!(Ciphertext::from_bytes(&[0; CIPHERTEXT_LEN - 1]).is_err());
    }
}
