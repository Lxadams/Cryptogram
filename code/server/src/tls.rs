//! The relay's TLS identity, and the secret that tells the app apart.
//!
//! In production the relay has a real domain and a real certificate for it
//! (`TLS_CERT` and `TLS_KEY`, e.g. Let's Encrypt's `fullchain.pem` and
//! `privkey.pem`), so anyone who connects sees an ordinary HTTPS site. For
//! local testing it makes itself a self-signed certificate instead, saved
//! next to it so its key survives restarts.
//!
//! Either way the app trusts the certificate's *key*, not who signed it: it
//! ships with the key's pin (`--print-pubkey`, see `cell::quic::key_pin`).
//! So renewing the certificate must keep the key (certbot's `--reuse-key`).

use anyhow::{Context, Result, anyhow};
use cell::proof::AccessKey;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::rustls::{
    self,
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};
use rand_core::{OsRng, RngCore};
use std::{fs, io::Write, path::Path, sync::Arc};
use tracing::info;

/// Where a self-signed certificate and its key are kept when `TLS_CERT` and
/// `TLS_KEY` aren't set (in the working directory: /data in Docker).
const DEV_CERT_PATH: &str = "relay_cert.pem";
const DEV_KEY_PATH: &str = "relay_key.pem";
/// Where the access key is kept if `SERVER_ACCESS_KEY` isn't set.
const ACCESS_KEY_PATH: &str = "relay_access_key";

pub struct TlsIdentity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// What the app pins (`SERVER_PUBKEY`).
    pub pin: [u8; 32],
}

/// The certificate from `TLS_CERT`/`TLS_KEY`, or the saved self-signed one
/// (made for `SERVER_NAME`, default "localhost", if there isn't one yet).
pub fn load_or_create_identity() -> Result<TlsIdentity> {
    let (chain, key) = match (std::env::var("TLS_CERT"), std::env::var("TLS_KEY")) {
        (Ok(cert), Ok(key)) => read_pem(Path::new(&cert), Path::new(&key))?,
        (Err(_), Err(_)) => load_or_create_self_signed()?,
        _ => return Err(anyhow!("Set both TLS_CERT and TLS_KEY, or neither")),
    };
    identity(chain, key)
}

fn identity(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsIdentity> {
    let leaf = chain
        .first()
        .ok_or_else(|| anyhow!("The certificate file has no certificate in it"))?;
    let pin = cell::quic::key_pin(leaf)?;
    Ok(TlsIdentity { chain, key, pin })
}

/// A fresh self-signed certificate for `names`, kept in memory (tests).
pub fn self_signed(names: Vec<String>) -> Result<TlsIdentity> {
    let generated = rcgen::generate_simple_self_signed(names)?;
    identity(
        vec![generated.cert.der().clone()],
        PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into(),
    )
}

fn read_pem(
    cert: &Path,
    key: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let chain = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", cert.display()))?;
    let key =
        PrivateKeyDer::from_pem_file(key).with_context(|| format!("reading {}", key.display()))?;
    Ok((chain, key))
}

fn load_or_create_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let (cert, key) = (Path::new(DEV_CERT_PATH), Path::new(DEV_KEY_PATH));
    if cert.exists() && key.exists() {
        return read_pem(cert, key);
    }
    let names: Vec<String> = std::env::var("SERVER_NAME")
        .unwrap_or_else(|_| "localhost".to_string())
        .split(',')
        .map(|name| name.trim().to_string())
        .collect();
    info!("No TLS certificate configured; making a self-signed one for {names:?}");
    let generated = rcgen::generate_simple_self_signed(names)?;
    fs::write(cert, generated.cert.pem())?;
    write_secret(key, generated.signing_key.serialize_pem().as_bytes())?;
    read_pem(cert, key)
}

/// Write a file only its owner can read.
fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .and_then(|mut file| file.write_all(contents))
        .with_context(|| format!("writing {}", path.display()))
}

/// The access key the app ships with (see `cell::proof`): from
/// `SERVER_ACCESS_KEY` (hex), or saved next to the relay, made on first run.
pub fn load_or_create_access_key() -> Result<AccessKey> {
    let hex_key = match std::env::var("SERVER_ACCESS_KEY") {
        Ok(key) => key,
        Err(_) => match fs::read_to_string(ACCESS_KEY_PATH) {
            Ok(saved) => saved,
            Err(_) => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                write_secret(Path::new(ACCESS_KEY_PATH), hex::encode(key).as_bytes())?;
                info!("Generated a new access key ({ACCESS_KEY_PATH})");
                return Ok(key);
            }
        },
    };
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut key)
        .map_err(|_| anyhow!("The access key must be 64 hex characters"))?;
    Ok(key)
}

/// TLS 1.3 only (QUIC requires it), the hybrid post-quantum X25519MLKEM768
/// key exchange first (the app offers nothing else), and the classical
/// groups browsers fall back to, so the website works for everyone.
pub fn server_config(identity: TlsIdentity) -> Result<quinn::ServerConfig> {
    let provider = CryptoProvider {
        kx_groups: vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
            aws_lc_rs::kx_group::SECP256R1,
            aws_lc_rs::kx_group::SECP384R1,
        ],
        ..aws_lc_rs::default_provider()
    };
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(identity.chain, identity.key)?;
    tls.alpn_protocols = vec![cell::quic::ALPN.to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(Arc::new(cell::quic::transport_config()));
    Ok(config)
}
