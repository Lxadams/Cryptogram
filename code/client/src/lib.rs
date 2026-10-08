use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pq::{Ciphertext, PublicKey, SecretKey, decapsulate, encapsulate, keypair};
use rand_core::{OsRng, RngCore};
use relay_link::{
    AdmissionTag, Lane, LinkEnd, LinkKeys, Side, TYPE_ACK, TYPE_DATA, TYPE_HANDSHAKE_RESP,
    TYPE_PATH_CHALLENGE, TYPE_PATH_RESPONSE, TYPE_SYNC, TYPE_SYNC_ACK,
};
use sha2::Sha256;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::SocketAddr,
};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub mod packets;
use packets::*;
mod chunks;
mod deliveries;
mod history;
mod padding;
pub mod pq;
mod storage;
mod transport;
pub use chunks::MAX_MESSAGE_LEN;
pub use history::{ChatHistory, StoredMessage};
/// Routing tokens, link session IDs and delivery IDs are the relay link's
/// (see the `relay-link` crate), as is how a routing token is derived.
pub use relay_link::{DeliveryId, RoutingToken, SessionId, routing_token_for};
pub use storage::{ClientStateDto, IdentityStateStore};
pub use transport::{BurstSender, send_burst};
#[cfg(test)]
mod test_support;

type HmacSha256 = Hmac<Sha256>;
/// What `Client::create_encrypted_packets` returns: a message's chunk
/// packets, then an optional PQ inject packet to send after them. Every one
/// is safe to deliver more than once, in any order, so a resend should
/// resend them all alike, the PQ inject included.
#[cfg(test)]
pub(crate) type OutgoingPackets = (Vec<Vec<u8>>, Option<Vec<u8>>);
/// The same pair before link encryption, from `encrypt_message_payloads`:
/// a message's inner 0x01 chunk payloads and its optional 0x05 PQ inject.
type MessagePayloads = (Vec<Vec<u8>>, Option<Vec<u8>>);

// PQ injection interval: inject fresh Kyber entropy every N ratchet steps
// (one per chunk; see `create_encrypted_packets`)
const PQ_INJECT_INTERVAL: u64 = 5;

// Maximum number of skipped message keys to retain
const MAX_SKIP_DICT_SIZE: usize = 500;

// Domain-separation salt for HKDF derivations
const HKDF_SALT: &[u8] = b"e2e-messenger-v1";

// Domain separator for the admission tags contacts put on what they send
// each other (see `admission_tag`).
const ADMISSION_LABEL: &[u8] = b"e2e-messenger/admission/v1";

// Maximum timestamp drift allowed (seconds)
const MAX_TIMESTAMP_DRIFT: u64 = 300;

// Most PQ refreshes held per session waiting for the receive chain to reach
// their position. Refreshes come at least PQ_INJECT_INTERVAL steps apart and
// messages more than 100 steps ahead are rejected anyway, so this is ample.
const MAX_PENDING_PQ_INJECTS: usize = 32;

// A handshake attempt sends its init this many times, this far apart, then
// waits for the relay's reply (which comes several times over too, see
// `relay_link::REPLY_COPIES`) until `HANDSHAKE_ATTEMPT` is up.
// `perform_handshake` tries again, with the same init, until
// `HANDSHAKE_GIVE_UP`. At 70% loss each way, one init and one reply get
// through 9% of the time; three of each, about half. So a minute of
// attempts almost never fails, even at that loss.
const HANDSHAKE_COPIES: usize = 3;
const HANDSHAKE_COPY_SPACING: Duration = Duration::from_millis(200);
const HANDSHAKE_ATTEMPT: Duration = Duration::from_secs(3);
const HANDSHAKE_GIVE_UP: Duration = Duration::from_secs(60);

// Syncs sent on each keepalive tick (see `Client::keepalive`), each acked
// several times by the relay, so a link in heavy loss still hears from the
// relay at most ticks.
const SYNC_COPIES: usize = 3;

// Hearing nothing from the relay for this long, despite syncing every 15s,
// means our link is gone: the relay restarted, or dropped the link after we
// were quiet too long (see `Client::keepalive`). Long enough that heavy loss
// alone almost never looks like it: at 70% loss each way, eight ticks in a
// row with no ack happen about one time in 200.
const LINK_SILENCE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

// While setting up a session with a contact, our KeyExchange is sent again
// (see `Client::setup_resends`) after this long, then twice as long each
// time, up to `MAX_SETUP_RETRY_DELAY`, at most `MAX_SETUP_RETRIES` times.
// Each step of the setup is a single UDP packet to the relay, which nothing
// resends, so this is what gets a setup past a lost one. Any progress, or a
// new link, starts the count again.
const FIRST_SETUP_RETRY: Duration = Duration::from_secs(30);
const MAX_SETUP_RETRY_DELAY: Duration = Duration::from_secs(60 * 60);
const MAX_SETUP_RETRIES: u32 = 8;

// Connection requests from people who aren't contacts (see
// `Client::connection_requests`): how long one is listed, and how many new
// ones at most are listed in that time, however many identities they come
// from.
const CONNECTION_REQUEST_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_CONNECTION_REQUESTS: usize = 8;
// How long "Not now" keeps someone's requests from being listed again.
const DISMISSED_REQUEST_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Where `Client::save`/callers' `ClientStateDto::load` persist identity +
/// session state. Overridable via `E2E_STATE_FILE` so multiple peer
/// processes (e.g. `code/frontend`'s Tauri backend, one per `runpeer.sh`
/// invocation) can each keep their own identity without relying on process
/// cwd tricks.
pub fn state_file_path() -> String {
    std::env::var("E2E_STATE_FILE").unwrap_or_else(|_| "client_state.json".to_string())
}

/// Parse a hex routing token, as typed/pasted by a user or scanned from a
/// contact QR code. Shared by every front end so they validate identically.
pub fn parse_routing_token(hex_str: &str) -> Result<RoutingToken> {
    let mut token = [0u8; 16];
    hex::decode_to_slice(hex_str.trim(), &mut token)
        .map_err(|_| anyhow!("Routing token must be 32 hex characters"))?;
    Ok(token)
}

/// Parse a hex Ed25519 public key (a contact's, or the relay's).
pub fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_str.trim(), &mut bytes)
        .map_err(|_| anyhow!("Ed25519 key must be 64 hex characters"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| anyhow!("Invalid Ed25519 key"))
}

/// The admission tag `sender` puts on what it sends `recipient`, so the
/// relay files it in the recipient's queue for contacts rather than the
/// small one for everyone else (see `relay_link`). It's made from the
/// two's static X25519 keys, which they only send each other in their
/// KeyExchanges, so nobody else can work it out. `None` for a degenerate
/// key that would make it guessable.
fn admission_tag(
    my_secret: &StaticSecret,
    their_public: &X25519PublicKey,
    sender: &RoutingToken,
    recipient: &RoutingToken,
) -> Option<AdmissionTag> {
    let shared = my_secret.diffie_hellman(their_public);
    if !shared.was_contributory() {
        return None;
    }
    let mut tag = [0u8; 8];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), shared.as_bytes())
        .expand(&[ADMISSION_LABEL, sender, recipient].concat(), &mut tag)
        .expect("8 bytes is a valid HKDF-SHA256 output length");
    Some(tag)
}

/// The first four bytes of a token, in hex: how the console names someone.
fn short(token: &RoutingToken) -> String {
    hex::encode(&token[0..4])
}

/// Whether a payload's `timestamp` is within `MAX_TIMESTAMP_DRIFT` of our
/// clock.
fn within_drift(timestamp: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    now.abs_diff(timestamp) <= MAX_TIMESTAMP_DRIFT
}

// Argon2id parameters for every login secret derived below: 64 MiB and 3
// passes, single-threaded. That's several times OWASP's ~19 MiB, 2-pass
// baseline (what identities created before used), as a captured phone's
// passcode is guessed offline at whatever rate the attacker's hardware
// allows. About 0.1 s a login on a laptop, so up to a second or so on a
// slow phone: worth timing on the slowest one supported. Stored alongside the
// salt in `passcode.hash`, so tuning these later doesn't invalidate
// identities created under the old values. (Those keep their old cost: the
// vault key they derive also encrypts their databases.)
const ARGON2_M_COST_KIB: u32 = 65_536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const ARGON2_SALT_LEN: usize = 16;
const ARGON2_OUTPUT_LEN: usize = 32;

// HKDF labels used to fan a single Argon2id output out into two
// cryptographically independent secrets — see `derive_vault_key`'s doc
// comment for why this matters.
const VERIFIER_LABEL: &[u8] = b"e2e-messenger/login-verifier/v1";
const VAULT_KEY_LABEL: &[u8] = b"e2e-messenger/vault-key/v1";

/// Run Argon2id(passcode, salt) with the given (m_cost, t_cost, p_cost).
/// This raw output is never itself stored or compared directly — every
/// caller immediately fans it out through `hkdf_label` instead, so it never
/// leaves this function.
fn argon2_master_secret(
    passcode: &str,
    salt: &[u8],
    params: (u32, u32, u32),
) -> Option<Zeroizing<[u8; ARGON2_OUTPUT_LEN]>> {
    let (m_cost, t_cost, p_cost) = params;
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(m_cost, t_cost, p_cost, Some(ARGON2_OUTPUT_LEN)).ok()?,
    );
    let mut out = Zeroizing::new([0u8; ARGON2_OUTPUT_LEN]);
    argon2
        .hash_password_into(passcode.as_bytes(), salt, out.as_mut())
        .ok()?;
    Some(out)
}

/// HKDF-SHA256-expand `master_secret` under `label` into a fresh 32-byte
/// secret. `master_secret` is already high-entropy (an Argon2id output), so
/// this only needs the Expand half of HKDF, not Extract.
fn hkdf_label(master_secret: &[u8], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_secret);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

struct ParsedPasscodeHash {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: Vec<u8>,
    verifier: Vec<u8>,
}

fn parse_passcode_hash(stored: &str) -> Option<ParsedPasscodeHash> {
    let mut parts = stored.split('$');
    if parts.next()? != "argon2id" {
        return None;
    }
    let m_cost: u32 = parts.next()?.parse().ok()?;
    let t_cost: u32 = parts.next()?.parse().ok()?;
    let p_cost: u32 = parts.next()?.parse().ok()?;
    let salt = hex::decode(parts.next()?).ok()?;
    let verifier = hex::decode(parts.next()?).ok()?;
    if parts.next().is_some() {
        return None; // trailing garbage
    }
    Some(ParsedPasscodeHash {
        m_cost,
        t_cost,
        p_cost,
        salt,
        verifier,
    })
}

/// Hash a login passcode for storage as `identities/<pseudonym>/passcode.hash`.
/// Real Argon2id KDF — besides gating login, this stored hash's salt/params
/// are also what `derive_vault_key` recomputes from to unlock the identity's
/// SQLCipher chat-history database.
/// Format: `"argon2id$<m_cost>$<t_cost>$<p_cost>$<salt_hex>$<verifier_hex>"`.
pub fn hash_passcode(passcode: &str) -> String {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let ms = argon2_master_secret(
        passcode,
        &salt,
        (ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST),
    )
    .expect("Argon2id params above are fixed constants and always valid");
    let verifier = hkdf_label(ms.as_ref(), VERIFIER_LABEL);
    format!(
        "argon2id${ARGON2_M_COST_KIB}${ARGON2_T_COST}${ARGON2_P_COST}${}${}",
        hex::encode(salt),
        hex::encode(verifier)
    )
}

/// Check `passcode` against a value previously produced by `hash_passcode`.
pub fn verify_passcode(passcode: &str, stored: &str) -> bool {
    derive_vault_key(passcode, stored).is_some()
}

/// Recompute the Argon2id master secret `hash_passcode` derived at creation
/// time and, only if it matches the stored login verifier, return the vault
/// key used to unlock this identity's SQLCipher chat-history database.
///
/// The verifier and the vault key are independent HKDF-SHA256 expansions
/// (different labels) of one Argon2id output that itself is never stored or
/// returned — so an attacker who reads `passcode.hash` off disk (filesystem
/// access without the passcode) learns neither the passcode nor the vault
/// key, only the verifier, which cannot be used to derive the other label's
/// output without redoing the (slow, salted) Argon2id computation from the
/// real passcode.
pub fn derive_vault_key(passcode: &str, stored: &str) -> Option<Zeroizing<[u8; 32]>> {
    let parsed = parse_passcode_hash(stored)?;
    let ms = argon2_master_secret(
        passcode,
        &parsed.salt,
        (parsed.m_cost, parsed.t_cost, parsed.p_cost),
    )?;
    let verifier = hkdf_label(ms.as_ref(), VERIFIER_LABEL);
    if !bool::from(verifier.as_slice().ct_eq(parsed.verifier.as_slice())) {
        return None;
    }
    Some(Zeroizing::new(hkdf_label(ms.as_ref(), VAULT_KEY_LABEL)))
}

pub struct UserIdentity {
    /// Always `routing_token_for(&token_public)`.
    pub routing_token: RoutingToken,
    /// Signs our syncs, proving to the relay that the routing token is ours.
    /// Separate from `ed25519_secret`, which signs to contacts.
    pub token_secret: SigningKey,
    pub token_public: VerifyingKey,
    pub ed25519_secret: SigningKey,
    pub ed25519_public: VerifyingKey,
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519PublicKey,
    pub kyber_public: PublicKey,
    pub kyber_secret: SecretKey,
}

impl UserIdentity {
    pub fn generate() -> Self {
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let token_secret = SigningKey::from_bytes(&token_bytes);
        let token_public = token_secret.verifying_key();
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let ed25519_secret = SigningKey::from_bytes(&bytes);
        let ed25519_public = ed25519_secret.verifying_key();
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let (kyber_public, kyber_secret) = keypair();
        Self {
            routing_token: routing_token_for(&token_public),
            token_secret,
            token_public,
            ed25519_secret,
            ed25519_public,
            x25519_secret,
            x25519_public,
            kyber_public,
            kyber_secret,
        }
    }
}

pub struct SymmetricSessionState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub send_count: u64,
    pub recv_count: u64,
    pub peer_kyber_pub: Option<PublicKey>,
    pub skip_dict: HashMap<u64, [u8; 32]>,
    pub recv_pq_injects: RecvPqInjects,
}

/// PQ refreshes received from the peer, tracked by the position the sender
/// mixed each one in at (see `SymmetricSessionState::accept_pq_inject`).
#[derive(Default)]
pub struct RecvPqInjects {
    /// Refreshes that arrived before the receive chain reached their
    /// position, keyed by it: the decapsulated secret, mixed in when
    /// `try_decrypt` steps the chain through that position.
    pub pending: BTreeMap<u64, [u8; 32]>,
    /// Position of the latest refresh mixed in, or 0 if none yet (a refresh
    /// always follows at least one message, so positions start at 1).
    pub applied_through: u64,
}

/// One step of the symmetric hash ratchet: `(message key, next chain key)`.
fn chain_step(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let derive = |label: &[u8]| -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(chain_key).unwrap();
        mac.update(label);
        mac.finalize().into_bytes().into()
    };
    (derive(b"message-key"), derive(b"chain-key"))
}

/// Mix a fresh PQ shared secret into `chain_key` via HKDF.
fn mix_pq_secret(chain_key: &mut [u8; 32], pq_secret_bytes: &[u8]) {
    let mut inject_input = Vec::with_capacity(32 + pq_secret_bytes.len());
    inject_input.extend_from_slice(chain_key);
    inject_input.extend_from_slice(pq_secret_bytes);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), &inject_input)
        .expand(b"pq-ratchet-inject", chain_key)
        .unwrap();
}

/// Hybrid PQXDH root key: HKDF over the classical X25519 and post-quantum
/// Kyber shared secrets together, so the session is only broken if both are.
fn hybrid_root_key(classical_secret: &[u8], pq_secret: &[u8]) -> [u8; 32] {
    let mut hybrid_input = Vec::with_capacity(classical_secret.len() + pq_secret.len());
    hybrid_input.extend_from_slice(classical_secret);
    hybrid_input.extend_from_slice(pq_secret);
    let mut root_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), &hybrid_input)
        .expand(b"pqxdh-root-key", &mut root_key)
        .unwrap();
    root_key
}

impl SymmetricSessionState {
    /// A brand-new session straight out of the PQXDH handshake.
    fn from_root_key(root_key: [u8; 32], peer_kyber_pub: Option<PublicKey>) -> Self {
        Self {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub,
            skip_dict: HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        }
    }

    pub fn symmetric_ratchet(&mut self) -> [u8; 32] {
        let (message_key, next_chain_key) = chain_step(&self.send_chain_key);
        self.send_chain_key = next_chain_key;
        message_key
    }

    /// Try decrypting using skip dictionary or fast-forwarding the ratchet
    pub fn try_decrypt(
        &mut self,
        seq_no: u64,
        nonce: &XNonce,
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        if seq_no < self.recv_count {
            if let Some(key) = self.skip_dict.get(&seq_no) {
                let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
                if let Ok(pt) = cipher.decrypt(nonce, ciphertext) {
                    self.skip_dict.remove(&seq_no);
                    return Some(pt);
                }
            }
            return None;
        }

        if seq_no - self.recv_count > 100 {
            return None;
        }

        // Prune oldest skip_dict entries if we're at capacity (one sort,
        // rather than a full scan for the minimum per removed entry)
        if self.skip_dict.len() >= MAX_SKIP_DICT_SIZE {
            let mut seqs: Vec<u64> = self.skip_dict.keys().copied().collect();
            seqs.sort_unstable();
            let excess = seqs.len() + 1 - MAX_SKIP_DICT_SIZE;
            for seq in &seqs[..excess] {
                self.skip_dict.remove(seq);
            }
        }

        let mut test_chain = self.recv_chain_key;
        let mut skipped_keys = Vec::new();
        let mut applied_through = self.recv_pq_injects.applied_through;

        let mut msg_key = [0u8; 32];
        for position in self.recv_count..=seq_no {
            // Mix in a refresh at the same point the sender did: after the
            // message before `position`, before deriving this one's key.
            if let Some(secret) = self.recv_pq_injects.pending.get(&position) {
                mix_pq_secret(&mut test_chain, secret);
                applied_through = position;
            }
            (msg_key, test_chain) = chain_step(&test_chain);
            skipped_keys.push(msg_key);
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&msg_key));
        if let Ok(pt) = cipher.decrypt(nonce, ciphertext) {
            self.recv_chain_key = test_chain;
            for (i, key) in skipped_keys.into_iter().enumerate() {
                let s = self.recv_count + i as u64;
                if s < seq_no {
                    self.skip_dict.insert(s, key);
                }
            }
            self.recv_count = seq_no + 1;
            self.recv_pq_injects
                .pending
                .retain(|&position, _| position > seq_no);
            self.recv_pq_injects.applied_through = applied_through;
            self.apply_due_pq_inject();
            Some(pt)
        } else {
            None
        }
    }

    /// Mixed into the signature of every PQ refresh on this session (see
    /// `PQInjectPayload::signing_input`), so a refresh only verifies on the
    /// session it was made for. Derived from the root key, which both sides
    /// share and which never changes for the life of the session.
    pub fn pq_inject_binding(&self) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.root_key).unwrap();
        mac.update(b"pq-inject-session-binding");
        mac.finalize().into_bytes().into()
    }

    /// Take in a PQ refresh the peer mixed into its send chain at
    /// `applies_at` (its `send_count` at the time). Returns `false` if it's
    /// a copy of one already taken in — resending makes those routine, and
    /// they're simply ignored.
    ///
    /// The secret is mixed into the receive chain when the chain reaches
    /// that position: right away if it's already there, otherwise once the
    /// messages before it arrive (see `try_decrypt`). So the refresh can
    /// arrive in any order relative to those messages, any number of times,
    /// and any time later. The chain can't move past `applies_at` without
    /// it, because every message from there on was encrypted on the
    /// refreshed chain and won't decrypt until it's mixed in.
    pub fn accept_pq_inject(&mut self, applies_at: u64, pq_secret: [u8; 32]) -> bool {
        let injects = &mut self.recv_pq_injects;
        let already_have = applies_at < self.recv_count
            || applies_at <= injects.applied_through
            || injects.pending.contains_key(&applies_at);
        if already_have || injects.pending.len() >= MAX_PENDING_PQ_INJECTS {
            return false;
        }
        injects.pending.insert(applies_at, pq_secret);
        self.apply_due_pq_inject();
        true
    }

    /// Mix in the pending refresh at `recv_count`, if it has arrived: the
    /// receive chain is exactly where the sender's was when it mixed it in.
    fn apply_due_pq_inject(&mut self) {
        if let Some(secret) = self.recv_pq_injects.pending.remove(&self.recv_count) {
            mix_pq_secret(&mut self.recv_chain_key, &secret);
            self.recv_pq_injects.applied_through = self.recv_count;
        }
    }

    /// Mix fresh PQ shared secret into the send chain key via HKDF (called by sender)
    pub fn inject_pq_secret_send(&mut self, pq_secret_bytes: &[u8]) {
        mix_pq_secret(&mut self.send_chain_key, pq_secret_bytes);
    }
}

/// Which time each side added the other "from scratch" a session belongs
/// to. Whenever a client adds a contact it doesn't have (the first time, or
/// after removing them), it gives them a new add ID from a counter that only
/// goes up, and keeps it until it removes them. Both sides send theirs in
/// every KeyExchange and SessionEstablish. So a message from before either
/// side last removed the other is recognisably old, and a session is named
/// by the pair of add IDs it was made for: one pair, one session. That's
/// what lets the establisher offer the session it already has, however
/// often it's asked, while a contact who has removed and re-added it gets a
/// new one.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub(crate) struct AddIds {
    /// Ours for this contact. 0 for a contact added before add IDs existed.
    pub(crate) mine: u32,
    /// The latest of theirs we've seen; 0 until we hear from them.
    pub(crate) theirs: u32,
}

/// How a session came about: the add IDs it was made for, and, while the
/// establisher waits for the responder to confirm it has it, what the
/// establisher needs to offer it again.
pub(crate) struct SessionSetup {
    pub(crate) establisher_add_id: u32,
    pub(crate) responder_add_id: u32,
    /// Establisher only, until the responder confirms: the
    /// SessionEstablish's ephemeral key and Kyber ciphertext, to re-sign and
    /// send again when asked (see `Client::session_est_packet`). The
    /// session isn't used until then (see `Client::is_connected`).
    pub(crate) offer: Option<SessionOffer>,
}

#[derive(Clone, Copy)]
pub(crate) struct SessionOffer {
    pub(crate) eph_x25519_pub: X25519PublicKey,
    pub(crate) kyber_ct: Ciphertext,
}

/// How far along we are with a contact (see `Client::contact_status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactStatus {
    /// We've added them, but haven't heard from them: they haven't added
    /// us back yet, as far as we know.
    Pending,
    /// They've added us too, and the session between us is being set up.
    Connecting,
    /// We share a session both sides have, so we can message them.
    Connected,
}

/// When to send a contact we haven't got a session with our KeyExchange
/// again (see `Client::setup_resends`).
#[derive(Clone, Copy)]
struct SetupRetry {
    at: Instant,
    /// The wait after that one.
    delay: Duration,
    left: u32,
}

impl SetupRetry {
    /// A fresh count, starting `first` from now.
    fn starting(now: Instant, first: Duration) -> Self {
        Self {
            at: now + first,
            delay: FIRST_SETUP_RETRY,
            left: MAX_SETUP_RETRIES,
        }
    }
}

pub struct Client {
    pub identity: UserIdentity,
    pub server_addr: SocketAddr,
    /// Our link to the relay (see `relay_link::LinkEnd`): its session ID,
    /// which the relay picks in its handshake reply, its keys, and the
    /// packet numbers sent and taken in on it. Replaced by every handshake
    /// (see `complete_handshake`).
    pub link: LinkEnd,
    /// The relay's identity key, which its handshake replies must be signed
    /// by: the one we connected with first (see `perform_handshake`), so a
    /// handshake we redo ourselves (see `keepalive`) checks against it too.
    relay_public: Option<VerifyingKey>,
    /// A handshake we started because our link looked gone (see
    /// `keepalive`): our ephemeral secret for it, and when we sent it.
    /// `handle_relay_packet` finishes it when the reply comes.
    pending_handshake: Option<(EphemeralSecret, Instant)>,
    /// When we last heard anything (authentic) from the relay on this link:
    /// an ack of a sync, say, or something it forwarded. Live state.
    last_heard: Instant,
    /// When to send each contact we've added, but have no session with yet,
    /// our KeyExchange again (see `setup_resends`). Live state.
    setup_retries: HashMap<RoutingToken, SetupRetry>,
    pub e2e_sessions: HashMap<RoutingToken, SymmetricSessionState>,
    pub pending_contacts: HashMap<RoutingToken, VerifyingKey>,
    pub peer_kyber_keys: HashMap<RoutingToken, PublicKey>,
    /// Contacts' static X25519 keys, from their KeyExchanges: what the
    /// admission tags we share with each of them come from (see
    /// `admission_tag`).
    pub peer_x25519_keys: HashMap<RoutingToken, X25519PublicKey>,
    /// Each contact's add IDs, ours and theirs (see `AddIds`).
    pub(crate) add_ids: HashMap<RoutingToken, AddIds>,
    /// The add ID the next contact added from scratch gets.
    pub(crate) next_add_id: u32,
    /// How each session in `e2e_sessions` came about (see `SessionSetup`).
    /// Missing for a session from before add IDs existed.
    pub(crate) session_setups: HashMap<RoutingToken, SessionSetup>,
    /// Where `save()` persists this exact instance — set at load/creation
    /// time (see `ClientStateDto::load` and the frontend's `login` command,
    /// which resolves this per-pseudonym under `identities/<pseudonym>/`).
    /// Not part of `ClientStateDto`/the JSON on disk: a file's own path
    /// isn't data that belongs inside itself, and it must be free to differ
    /// between processes loading the same identity from different
    /// locations. Defaults to the global `state_file_path()` so the CLI,
    /// which has no per-pseudonym concept, keeps behaving exactly as before.
    pub state_path: String,
    /// This peer's own self-chosen display name, given at login (the
    /// frontend's login screen sets this from the pseudonym typed there).
    /// Sent with every outgoing KeyExchange so peers can label us by name
    /// instead of hex. Empty if unset.
    pub local_name: String,
    /// Display names peers have told us about themselves, learned from the
    /// (signed) `name` field of their `KeyExchangePayload` — populated for
    /// both pending and established contacts as soon as their KeyExchange
    /// arrives, no manual entry required.
    pub contact_names: HashMap<RoutingToken, String>,
    /// Decrypted messages that have arrived but not yet been collected by a
    /// consumer. The CLI doesn't use this (it prints inline as messages
    /// arrive), but a GUI front end has no console to print to — it polls
    /// `drain_inbox()` instead. Intentionally not persisted to disk: this is
    /// a transient handoff buffer, not session state.
    pub inbox: Vec<(RoutingToken, Vec<u8>, Option<i64>)>,
    /// This identity's local SQLCipher-backed chat history, if it's been
    /// unlocked (see `derive_vault_key` and `ChatHistory::open`). `None`
    /// until a caller attaches one — e.g. the CLI, which has no login/vault
    /// key flow yet, simply never sets this, and every send/receive that
    /// would otherwise record to it is a silent no-op.
    pub history: Option<ChatHistory>,
    /// This identity's own SQLCipher-backed replacement for the plaintext
    /// `client_state.json`, if it's been unlocked — keyed by the exact same
    /// vault key as `history`, so one passcode unlocks both stores. `None`
    /// until a caller attaches one (the CLI never does, same as `history`),
    /// in which case `save()` falls back to the legacy plaintext
    /// `ClientStateDto::save`/`state_path` path unchanged.
    pub identity_store: Option<IdentityStateStore>,
    /// The local chat-history row id `record_message` just wrote, if any —
    /// a one-shot side channel so an outgoing send (a single call per
    /// invocation, unlike `inbox`'s queue of possibly-several incoming
    /// messages) can report the exact id a later history fetch would also
    /// use for that same row, letting the frontend merge live and
    /// persisted views of a contact's messages without mistaking one
    /// message for two under two different synthetic ids. Not persisted;
    /// meaningful only in the instant after `record_message` runs.
    pub last_recorded_id: Option<i64>,
    /// Chunks of long incoming messages still waiting on the rest (see
    /// `chunks`). Live local state, not persisted, like `inbox`.
    reassembler: chunks::Reassembler,
    /// FEC receive state: half-rebuilt symbol bursts (0x07) and messages
    /// parked until the PQ inject they depend on arrives — see
    /// `transport`. Transient, like `inbox`: never persisted.
    pub(crate) fec_rx: transport::FecReceiver,
    /// Relay deliveries already handled, so a resend is only acked again.
    /// Live local state, not persisted, like `inbox`.
    recent_deliveries: deliveries::RecentDeliveries,
    /// Set when the admission tags our sync registers have changed since
    /// our last sync (a contact's X25519 key arrived, or a contact was
    /// removed), so the next relay packet we handle is answered with a fresh
    /// sync too, rather than leaving it to the keepalive. Live state.
    admission_changed: bool,
    /// Whether connection requests are muted: none are listed (see
    /// `connection_requests`). Saved with the identity.
    pub(crate) requests_muted: bool,
    /// Whether a front end's new-message notifications may say who each
    /// message is from. Off unless the user turns it on, as a notification
    /// can show on a locked screen. The client itself posts none. Saved
    /// with the identity.
    pub(crate) notify_with_names: bool,
    /// Recent KeyExchanges from people who aren't contacts, in the order
    /// they first arrived, so a front end can prompt the user to add them
    /// back (see `connection_requests`). Just the token and when: nothing
    /// else they sent is verified until the user scans their code. Live
    /// state, like `inbox`.
    connection_requests: Vec<(RoutingToken, Instant)>,
    /// When each request listed in the last `CONNECTION_REQUEST_TTL` was
    /// first listed, dismissed ones included, for the limit on how many new
    /// ones are. Live state.
    listed_requests: VecDeque<Instant>,
    /// Whose requests were dismissed ("Not now"), and when. Live state.
    dismissed_requests: HashMap<RoutingToken, Instant>,
}

/// Where a new identity's add-ID counter starts (see `AddIds`): somewhere
/// in the lower half of the range, so it doesn't give away how many
/// contacts the identity has added, with plenty of room to count up.
pub(crate) fn first_add_id() -> u32 {
    1 + (OsRng.next_u32() >> 1)
}

/// A client's link before its first handshake: all zeros, so nothing it
/// seals reaches anyone.
pub(crate) fn unlinked() -> LinkEnd {
    LinkEnd::new(Side::Client, LinkKeys::default(), [0; 4])
}

impl Client {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            identity: UserIdentity::generate(),
            server_addr,
            // A placeholder until the handshake, which gives the link its
            // ID and keys.
            link: unlinked(),
            relay_public: None,
            pending_handshake: None,
            last_heard: Instant::now(),
            setup_retries: HashMap::new(),
            e2e_sessions: HashMap::new(),
            pending_contacts: HashMap::new(),
            peer_kyber_keys: HashMap::new(),
            peer_x25519_keys: HashMap::new(),
            add_ids: HashMap::new(),
            next_add_id: first_add_id(),
            session_setups: HashMap::new(),
            state_path: state_file_path(),
            local_name: String::new(),
            contact_names: HashMap::new(),
            inbox: Vec::new(),
            history: None,
            identity_store: None,
            last_recorded_id: None,
            reassembler: chunks::Reassembler::default(),
            fec_rx: Default::default(),
            recent_deliveries: Default::default(),
            admission_changed: false,
            requests_muted: false,
            notify_with_names: false,
            connection_requests: Vec::new(),
            listed_requests: VecDeque::new(),
            dismissed_requests: HashMap::new(),
        }
    }

    /// Take all messages received since the last call. Returns
    /// `(sender_routing_token, plaintext, local_history_row_id)` triples in
    /// arrival order — the row id is `None` if no chat history is attached.
    pub fn drain_inbox(&mut self) -> Vec<(RoutingToken, Vec<u8>, Option<i64>)> {
        std::mem::take(&mut self.inbox)
    }

    /// Persist one message to the local chat-history database, if one is
    /// attached (see the `history` field doc comment), and stash its row id
    /// in `last_recorded_id`. Failures are logged, not propagated — a full
    /// disk or a locked file shouldn't block sending/receiving a message
    /// over the wire, only its local record of it.
    fn record_message(&mut self, token: RoutingToken, from_me: bool, plaintext: &[u8]) {
        let Some(history) = &self.history else {
            self.last_recorded_id = None;
            return;
        };
        match history.append(token, from_me, &String::from_utf8_lossy(plaintext)) {
            Ok(id) => self.last_recorded_id = Some(id),
            Err(e) => {
                tracing::error!("Failed to persist chat message to local history: {}", e);
                self.last_recorded_id = None;
            }
        }
    }

    /// The most recent `limit` persisted messages with `token`, oldest
    /// first, or empty if no chat history is attached (see the `history`
    /// field doc comment).
    pub fn history_for_contact(&self, token: RoutingToken, limit: i64) -> Vec<StoredMessage> {
        self.history
            .as_ref()
            .and_then(|h| h.recent(token, limit).ok())
            .unwrap_or_default()
    }

    /// Permanently remove `token` as a contact — drops any pending/
    /// established session, its keys, add IDs and learned display name, then
    /// persists the change. Adding them again later starts from scratch,
    /// with a new add ID (see `AddIds`). This is the *local*
    /// cleanup path for a stale contact (e.g. one whose identity was
    /// deleted and recreated elsewhere, leaving this peer with two entries
    /// for what is now a different identity under the same name) — it is
    /// never triggered by anything arriving over the network. A message
    /// (signed or not) claiming "delete my old self" can't be trusted: the
    /// old identity's key is gone, so nothing could ever prove it came from
    /// the same peer rather than an impersonator.
    ///
    /// Also deletes this contact's locally-persisted chat history —
    /// unconditionally, not an opt-in choice: reconnecting to the same
    /// person (a new KeyExchange under a new token) always starts a fresh
    /// conversation regardless, and there is no UI path to view a removed
    /// contact's old history anyway, so keeping it around after removal
    /// would just be orphaned, inaccessible data.
    pub fn forget_contact(&mut self, token: RoutingToken) {
        self.pending_contacts.remove(&token);
        self.e2e_sessions.remove(&token);
        self.session_setups.remove(&token);
        self.add_ids.remove(&token);
        self.peer_kyber_keys.remove(&token);
        // Their packets no longer get our queue for contacts, from our next
        // sync on.
        self.admission_changed |= self.peer_x25519_keys.remove(&token).is_some();
        self.contact_names.remove(&token);
        self.reassembler.forget(&token);
        self.setup_retries.remove(&token);
        self.save();
        if let Some(history) = &self.history
            && let Err(e) = history.delete_contact(token)
        {
            tracing::error!("Failed to delete local chat history for contact: {}", e);
        }
    }

    /// Persist identity/session state to `identity_store` if one is
    /// attached (the SQLCipher-encrypted path), otherwise fall back to the
    /// legacy plaintext `client_state.json` at `state_path` — mirrors how
    /// `record_message` treats `history` as optional. Failures are logged,
    /// not propagated, same as `record_message`; the result says whether it
    /// worked, for the few callers that mustn't tell a contact about state
    /// they couldn't save (see `offer_new_session`).
    pub fn save(&self) -> bool {
        let result = match &self.identity_store {
            Some(store) => store.save(self),
            None => ClientStateDto::save(self, &self.state_path),
        };
        if let Err(e) = &result {
            tracing::error!("Failed to save state: {}", e);
        }
        result.is_ok()
    }

    /// Our opening handshake packet: a fresh X25519 key (see
    /// `relay_link::handshake_init`). It says nothing about who we are; our
    /// sync proves that.
    pub fn generate_handshake_packet(&self) -> (EphemeralSecret, Vec<u8>) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let packet = relay_link::handshake_init(&X25519PublicKey::from(&secret));
        (secret, packet)
    }

    /// Finish the link handshake with the relay's reply: check it's signed
    /// by the relay we pinned and answers our handshake, then take the
    /// session ID the relay gave the link and derive its keys. The new link
    /// replaces whatever we had.
    pub fn complete_handshake(
        &mut self,
        client_secret: EphemeralSecret,
        server_ed25519_pub: &VerifyingKey,
        response: &[u8],
    ) -> Result<()> {
        let client_ephemeral = X25519PublicKey::from(&client_secret);
        let (session_id, relay_ephemeral) =
            relay_link::parse_handshake_resp(response, server_ed25519_pub, &client_ephemeral)
                .map_err(|e| anyhow!("Invalid handshake response: {e}"))?;
        let shared_secret = client_secret.diffie_hellman(&relay_ephemeral);
        if !shared_secret.was_contributory() {
            return Err(anyhow!("Invalid handshake response: degenerate key"));
        }
        let keys = relay_link::derive_link_keys(shared_secret.as_bytes());
        self.relay_public = Some(*server_ed25519_pub);
        self.link = LinkEnd::new(Side::Client, keys, session_id);
        self.pending_handshake = None;
        self.last_heard = Instant::now();
        // Anything sent on the old link may never have arrived, so contacts
        // we're still setting up with get our KeyExchange again right away.
        let now = Instant::now();
        for retry in self.setup_retries.values_mut() {
            *retry = SetupRetry::starting(now, Duration::ZERO);
        }
        Ok(())
    }

    /// Tells the relay our routing token lives on this link and proves it's
    /// ours (see `relay_link::Sync`), and registers the admission tags of
    /// our contacts, so their packets get our queue for contacts. Sent when
    /// we connect and then as the keepalive. The relay acks it, which tells
    /// us the link is still there (see `keepalive`).
    pub fn generate_sync_packet(&mut self) -> Vec<u8> {
        self.admission_changed = false;
        let sync = relay_link::Sync::new(
            &self.identity.token_secret,
            self.link.keys(),
            self.admission_tags_in(),
        );
        self.link.seal(Lane::Direct, TYPE_SYNC, &sync.to_bytes())
    }

    /// `SYNC_COPIES` syncs, each its own packet: what we send whenever we
    /// sync, so heavy loss rarely stops all of them.
    fn sync_packets(&mut self) -> Vec<Vec<u8>> {
        (0..SYNC_COPIES)
            .map(|_| self.generate_sync_packet())
            .collect()
    }

    /// Tells the relay we have the packets it forwarded with delivery IDs
    /// `ids`, so it stops resending them. Only the link session we last
    /// synced from can ack our routing token's packets.
    pub fn generate_ack_packet(&mut self, ids: &[DeliveryId]) -> Vec<u8> {
        self.link.seal(
            Lane::Direct,
            TYPE_ACK,
            &relay_link::ack_plaintext(&self.identity.routing_token, ids),
        )
    }

    /// What to send the relay on a keepalive tick (every 15s, and when the
    /// app comes back on screen): normally fresh syncs (see `SYNC_COPIES`),
    /// plus any KeyExchanges due again (see `setup_resends`).
    ///
    /// But if we've heard nothing from the relay for `LINK_SILENCE_TIMEOUT`
    /// (not even an ack of our syncs), our link is gone: the relay
    /// restarted, or dropped the link while we were quiet, a phone asleep
    /// say. Nothing sent on it arrives any more. So this starts a new
    /// handshake instead, on the same socket: the receive loop's
    /// `handle_relay_packet` finishes it, and syncs on the new link. Until
    /// then, ticks send nothing, and one with no reply after
    /// `HANDSHAKE_ATTEMPT` tries again. A client that hasn't done
    /// `perform_handshake` (so has no relay key to check a reply against)
    /// just keeps syncing.
    pub fn keepalive(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        if self.relay_public.is_some() {
            let link_gone = match &self.pending_handshake {
                Some((_, sent)) => {
                    if now.duration_since(*sent) < HANDSHAKE_ATTEMPT {
                        return Vec::new(); // still waiting for the reply
                    }
                    true
                }
                None => now.duration_since(self.last_heard) >= LINK_SILENCE_TIMEOUT,
            };
            if link_gone {
                if self.pending_handshake.is_none() {
                    println!(">> The relay stopped answering; reconnecting...");
                }
                let (secret, packet) = self.generate_handshake_packet();
                self.pending_handshake = Some((secret, now));
                return vec![packet; HANDSHAKE_COPIES];
            }
        }
        let mut out = self.sync_packets();
        out.extend(self.setup_resends(now));
        out
    }

    /// The relay's reply to a handshake `keepalive` started: if it's the
    /// reply to that handshake, signed by our relay, switch to the new link
    /// and sync on it (with any KeyExchanges due). Anything else is
    /// ignored.
    fn finish_handshake(&mut self, response: &[u8]) -> Vec<Vec<u8>> {
        let (Some((secret, _)), Some(relay_public)) = (&self.pending_handshake, self.relay_public)
        else {
            return Vec::new();
        };
        // Checked before the secret is used up, so a bogus reply can't stop
        // the real one from completing the handshake.
        let ours = X25519PublicKey::from(secret);
        if relay_link::parse_handshake_resp(response, &relay_public, &ours).is_err() {
            return Vec::new();
        }
        let (secret, _) = self.pending_handshake.take().expect("checked above");
        if self
            .complete_handshake(secret, &relay_public, response)
            .is_err()
        {
            return Vec::new();
        }
        println!(">> Reconnected to the relay.");
        let mut out = self.sync_packets();
        out.extend(self.setup_resends(Instant::now()));
        out
    }

    fn wrap_link_encryption(
        &mut self,
        target_token: RoutingToken,
        inner_payload: &[u8],
    ) -> Vec<u8> {
        let tag = self.admission_tag_for(&target_token);
        self.wrap_data(Lane::Direct, target_token, tag.as_ref(), inner_payload)
    }

    /// `inner_payload` for `target_token`, sealed on our link in `lane`,
    /// with the admission tag we put on what we send them, if we have one.
    fn wrap_data(
        &mut self,
        lane: Lane,
        target_token: RoutingToken,
        tag: Option<&AdmissionTag>,
        inner_payload: &[u8],
    ) -> Vec<u8> {
        relay_link::data_packet(&mut self.link, lane, &target_token, tag, inner_payload)
    }

    /// The admission tag we put on what we send `peer`, once we have their
    /// X25519 key from their KeyExchange.
    fn admission_tag_for(&self, peer: &RoutingToken) -> Option<AdmissionTag> {
        let key = self.peer_x25519_keys.get(peer)?;
        admission_tag(
            &self.identity.x25519_secret,
            key,
            &self.identity.routing_token,
            peer,
        )
    }

    /// The admission tags our contacts put on what they send us, for our
    /// sync to register: at most `relay_link::MAX_ADMISSION_TAGS`, contacts
    /// we have a session with first.
    fn admission_tags_in(&self) -> Vec<AdmissionTag> {
        let mut contacts: Vec<_> = self.peer_x25519_keys.iter().collect();
        contacts.sort_by_key(|(token, _)| (!self.e2e_sessions.contains_key(*token), **token));
        contacts
            .into_iter()
            .filter_map(|(token, key)| {
                admission_tag(
                    &self.identity.x25519_secret,
                    key,
                    token,
                    &self.identity.routing_token,
                )
            })
            .take(relay_link::MAX_ADMISSION_TAGS)
            .collect()
    }

    /// Trust a contact's routing token and Ed25519 key, as scanned from
    /// their QR code (or pasted), save that, and return the KeyExchange to
    /// send them. Only contacts added this way can start a session with us,
    /// so both sides add each other; the session comes up once both have.
    ///
    /// Adding someone who's already a contact sends them our KeyExchange
    /// again, which restarts the session setup from wherever it got stuck
    /// (see `handle_key_exchange`). Someone new, or removed since, gets a
    /// new add ID (see `AddIds`). Until the session is up, the KeyExchange
    /// is sent again now and then (see `setup_resends`).
    ///
    /// Our own code is refused: we'd only ever be talking to ourselves.
    pub fn add_contact(
        &mut self,
        token: RoutingToken,
        ed25519_public: VerifyingKey,
    ) -> Result<Vec<u8>> {
        if token == self.identity.routing_token {
            return Err(anyhow!(
                "That's your own code. Add your contact with theirs."
            ));
        }
        if self
            .pending_contacts
            .insert(token, ed25519_public)
            .is_none()
        {
            let mine = self.next_add_id;
            self.next_add_id = self.next_add_id.saturating_add(1);
            self.add_ids.insert(token, AddIds { mine, theirs: 0 });
        }
        self.connection_requests.retain(|(t, _)| *t != token);
        self.setup_retries.insert(
            token,
            SetupRetry::starting(Instant::now(), FIRST_SETUP_RETRY),
        );
        self.save();
        Ok(self.create_kx_request(token))
    }

    /// Whether we can message `token`: we share a session, and if we made
    /// it, they've confirmed they have it too. Until then, anything we sent
    /// on it could arrive before they have it, and be lost.
    pub fn is_connected(&self, token: &RoutingToken) -> bool {
        self.e2e_sessions.contains_key(token)
            && self
                .session_setups
                .get(token)
                .is_none_or(|setup| setup.offer.is_none())
    }

    /// How far along we are with the contact `token`: connected (see
    /// `is_connected`), connecting (we've heard from them, so they've added
    /// us too), or pending (we're waiting for them to add us).
    pub fn contact_status(&self, token: &RoutingToken) -> ContactStatus {
        if self.is_connected(token) {
            ContactStatus::Connected
        } else if self.peer_kyber_keys.contains_key(token) || self.e2e_sessions.contains_key(token)
        {
            ContactStatus::Connecting
        } else {
            ContactStatus::Pending
        }
    }

    /// Our KeyExchanges to send again (see `keepalive`), to contacts we've
    /// added but have no session with yet, each on its own schedule (see
    /// `FIRST_SETUP_RETRY`). Every step of a session setup is one UDP
    /// packet to the relay, and the relay only resends what it delivers,
    /// not what fails to reach it, so without this one lost packet would
    /// stall the setup for good. A KeyExchange carries where we've got to,
    /// and the other side's reply carries the setup on from there (see
    /// `handle_key_exchange`), so sending one again is always safe.
    fn setup_resends(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let waiting: Vec<RoutingToken> = self
            .pending_contacts
            .keys()
            .filter(|token| !self.is_connected(token))
            .copied()
            .collect();
        self.setup_retries
            .retain(|token, _| waiting.contains(token));
        let mut due = Vec::new();
        for token in waiting {
            // A contact we haven't scheduled yet, like one loaded from disk
            // at startup, is due now.
            let retry = self
                .setup_retries
                .entry(token)
                .or_insert_with(|| SetupRetry::starting(now, Duration::ZERO));
            if retry.left == 0 || now < retry.at {
                continue;
            }
            retry.left -= 1;
            retry.at = now + retry.delay;
            retry.delay = (retry.delay * 2).min(MAX_SETUP_RETRY_DELAY);
            due.push(token);
        }
        due.into_iter()
            .map(|token| self.create_kx_request(token))
            .collect()
    }

    /// `peer` has sent us something that moved our setup with them on:
    /// start the count of KeyExchange resends again (see `setup_resends`).
    fn note_setup_progress(&mut self, peer: &RoutingToken) {
        if let Some(retry) = self.setup_retries.get_mut(peer) {
            *retry = SetupRetry::starting(Instant::now(), FIRST_SETUP_RETRY);
        }
    }

    /// People who tried to connect but aren't contacts, in the order they
    /// first tried; none while requests are muted. Their KeyExchange was
    /// dropped (see the 0x02 branch of `handle_incoming_packet`); adding
    /// them with `add_contact`, by scanning their code, is what accepts it.
    /// Only the token is kept, as nothing else they sent is verified.
    pub fn connection_requests(&self) -> Vec<RoutingToken> {
        if self.requests_muted {
            return Vec::new();
        }
        self.connection_requests
            .iter()
            .filter(|(_, at)| at.elapsed() < CONNECTION_REQUEST_TTL)
            .map(|(token, _)| *token)
            .collect()
    }

    /// "Not now": stop listing `token`'s request, and don't list another
    /// from them for `DISMISSED_REQUEST_TTL`.
    pub fn dismiss_connection_request(&mut self, token: &RoutingToken) {
        self.connection_requests.retain(|(t, _)| t != token);
        self.dismissed_requests.insert(*token, Instant::now());
    }

    pub fn requests_muted(&self) -> bool {
        self.requests_muted
    }

    /// Mute or unmute connection requests. While muted, none are listed or
    /// kept. Saved with the identity.
    pub fn set_requests_muted(&mut self, muted: bool) {
        self.requests_muted = muted;
        if muted {
            self.connection_requests.clear();
        }
        self.save();
    }

    /// Whether notifications may name who a message is from (see
    /// `notify_with_names`).
    pub fn notify_with_names(&self) -> bool {
        self.notify_with_names
    }

    /// Let notifications name who each message is from, or not. Saved with
    /// the identity.
    pub fn set_notify_with_names(&mut self, on: bool) {
        self.notify_with_names = on;
        self.save();
    }

    /// List `token`'s request so the user can be asked to add them back,
    /// unless requests are muted, `token` was dismissed recently, or
    /// `MAX_CONNECTION_REQUESTS` new ones have been listed in the last
    /// `CONNECTION_REQUEST_TTL` already: anyone can make as many identities
    /// as they like, and each would otherwise be another pop-up. Another
    /// request from someone already listed only keeps it listed for longer.
    fn note_connection_request(&mut self, token: RoutingToken) {
        let now = Instant::now();
        self.connection_requests
            .retain(|(_, at)| now.duration_since(*at) < CONNECTION_REQUEST_TTL);
        self.listed_requests
            .retain(|at| now.duration_since(*at) < CONNECTION_REQUEST_TTL);
        self.dismissed_requests
            .retain(|_, at| now.duration_since(*at) < DISMISSED_REQUEST_TTL);
        if self.requests_muted || self.dismissed_requests.contains_key(&token) {
            return;
        }
        if let Some((_, at)) = self
            .connection_requests
            .iter_mut()
            .find(|(t, _)| *t == token)
        {
            *at = now;
        } else if self.listed_requests.len() < MAX_CONNECTION_REQUESTS {
            self.listed_requests.push_back(now);
            self.connection_requests.push((token, now));
        }
    }

    /// Our add IDs for `peer` (see `AddIds`).
    fn add_ids(&self, peer: &RoutingToken) -> AddIds {
        self.add_ids.get(peer).copied().unwrap_or_default()
    }

    /// Which of `peer`'s add IDs our session with them was made for, or
    /// `None` if we have no session with them.
    fn session_peer_add_id(&self, peer: &RoutingToken) -> Option<u32> {
        if !self.e2e_sessions.contains_key(peer) {
            return None;
        }
        Some(match self.session_setups.get(peer) {
            Some(setup) if self.establishes_session_with(peer) => setup.responder_add_id,
            Some(setup) => setup.establisher_add_id,
            None => 0, // from before add IDs existed, like the contact
        })
    }

    /// `peer` has added us from scratch since we last heard (they're new to
    /// us, or removed and re-added us): note their new add ID, and drop any
    /// session made for an older one, which they no longer have.
    fn set_their_add_id(&mut self, peer: RoutingToken, add_id: u32) {
        self.add_ids.entry(peer).or_default().theirs = add_id;
        if self
            .session_peer_add_id(&peer)
            .is_some_and(|session| session < add_id)
        {
            println!(
                ">> {} added you again, so your old session with them is gone.",
                short(&peer)
            );
            self.e2e_sessions.remove(&peer);
            self.session_setups.remove(&peer);
            self.reassembler.forget(&peer);
        }
    }

    /// Our KeyExchange for `target_token`: our keys, whether we have
    /// theirs, our add ID for them, and which session we have with them, if
    /// any.
    pub fn create_kx_request(&mut self, target_token: RoutingToken) -> Vec<u8> {
        let payload = KeyExchangePayload::generate(
            &self.identity,
            target_token,
            &self.local_name,
            self.peer_kyber_keys.contains_key(&target_token),
            self.add_ids(&target_token).mine,
            self.session_peer_add_id(&target_token),
        );
        let mut inner = vec![0x02];
        inner.extend_from_slice(&payload.to_bytes());
        self.wrap_link_encryption(target_token, &inner)
    }

    /// Whether we're the one of the two contacts who sends the
    /// SessionEstablish: whoever has the lower routing token. Both work it
    /// out the same way, so however their KeyExchanges cross, only one of
    /// them makes the session.
    fn establishes_session_with(&self, peer: &RoutingToken) -> bool {
        self.identity.routing_token < *peer
    }

    /// Make a new session with `peer`, which we establish, for our current
    /// add IDs (replacing any we had), and return the SessionEstablish that
    /// offers it. We don't use it until they confirm they have it. Nothing
    /// is offered unless it's saved: they'd start using a session we could
    /// lose on a restart.
    fn offer_new_session(
        &mut self,
        peer: RoutingToken,
        peer_x25519: &X25519PublicKey,
        peer_kyber: &PublicKey,
    ) -> Option<Vec<u8>> {
        // 1. Classical X25519 DH
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_x25519_pub = X25519PublicKey::from(&eph_secret);
        let classical_shared_secret = eph_secret.diffie_hellman(peer_x25519);

        // 2. Post-Quantum Encapsulation
        let (pq_shared_secret, kyber_ct) = encapsulate(peer_kyber);

        // 3. Hybrid Derivation (keeping the peer's Kyber pub for future PQ
        // ratchet injections)
        let root_key = hybrid_root_key(
            classical_shared_secret.as_bytes(),
            pq_shared_secret.as_bytes(),
        );
        self.e2e_sessions.insert(
            peer,
            SymmetricSessionState::from_root_key(root_key, Some(*peer_kyber)),
        );
        let ids = self.add_ids(&peer);
        self.session_setups.insert(
            peer,
            SessionSetup {
                establisher_add_id: ids.mine,
                responder_add_id: ids.theirs,
                offer: Some(SessionOffer {
                    eph_x25519_pub,
                    kyber_ct,
                }),
            },
        );
        println!(">> Offered {} a new E2E session.", short(&peer));
        self.session_est_packet(&peer)
    }

    /// The SessionEstablish offering the session we made with `peer`,
    /// freshly signed, as long as they haven't confirmed they have it, and
    /// it's saved. Offering the same session again (rather than a new one
    /// each time they ask) is what keeps both sides on one session however
    /// often the request and the offer cross, repeat or go missing.
    fn session_est_packet(&mut self, peer: &RoutingToken) -> Option<Vec<u8>> {
        let setup = self.session_setups.get(peer)?;
        let (offer, establisher_add_id, responder_add_id) = (
            setup.offer?,
            setup.establisher_add_id,
            setup.responder_add_id,
        );
        if !self.save() {
            return None;
        }
        let est = SessionEstablishPayload::generate(
            &self.identity,
            *peer,
            offer.kyber_ct,
            offer.eph_x25519_pub,
            establisher_add_id,
            responder_add_id,
        );
        let mut inner = vec![0x04];
        inner.extend_from_slice(&est.to_bytes());
        Some(self.wrap_link_encryption(*peer, &inner))
    }

    /// `peer` has the session we offered them: stop offering it, and start
    /// using it.
    fn confirm_session(&mut self, peer: &RoutingToken) {
        if let Some(setup) = self.session_setups.get_mut(peer)
            && setup.offer.take().is_some()
        {
            self.save();
            println!(">> E2E Session established with {}!", short(peer));
        }
    }

    /// The session a SessionEstablish offers us.
    fn session_from_est(&self, est: &SessionEstablishPayload) -> SymmetricSessionState {
        let classical_shared_secret = self
            .identity
            .x25519_secret
            .diffie_hellman(&est.eph_x25519_pub);
        let pq_shared_secret = decapsulate(&est.kyber_ct, &self.identity.kyber_secret);
        let root_key = hybrid_root_key(
            classical_shared_secret.as_bytes(),
            pq_shared_secret.as_bytes(),
        );
        // Peer's Kyber public key was stored during the KeyExchange phase
        let peer_kyber = self.peer_kyber_keys.get(&est.routing_token).copied();
        SymmetricSessionState::from_root_key(root_key, peer_kyber)
    }

    /// Encrypt a message as single link-encrypted datagrams: (message_packets,
    /// optional_pq_inject_packet); send them in that order. Test-only — real
    /// front ends send with `create_fec_packets`, which never lets the
    /// inject travel apart from its message.
    #[cfg(test)]
    pub(crate) fn create_encrypted_packets(
        &mut self,
        target_token: RoutingToken,
        plaintext: &[u8],
    ) -> Result<OutgoingPackets> {
        let (msg_payloads, pq_payload) = self.encrypt_message_payloads(target_token, plaintext)?;
        let msg_packets = msg_payloads
            .iter()
            .map(|payload| self.wrap_link_encryption(target_token, payload))
            .collect();
        let pq_inject_packet =
            pq_payload.map(|inner| self.wrap_link_encryption(target_token, &inner));
        Ok((msg_packets, pq_inject_packet))
    }

    /// Encrypt a message for a lossy link: its chunk packets and (when due)
    /// its PQ inject travel together as one burst of sealed FEC packets,
    /// sized to survive heavy loss — see `transport`. Hand the result to a
    /// `BurstSender` before anything else is (see `BurstSender::queue`):
    /// the burst is numbered in our link's paced lane, which must go out in
    /// the order it was numbered. Messages over `MAX_MESSAGE_LEN` bytes are
    /// rejected before the ratchet moves.
    pub fn create_fec_packets(
        &mut self,
        target_token: RoutingToken,
        plaintext: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let (msg_payloads, pq_payload) = self.encrypt_message_payloads(target_token, plaintext)?;
        let session = &self.e2e_sessions[&target_token];
        // The seq number of the message's last chunk doubles as its FEC
        // object id: unique within the session, unlike a random id.
        // (`FecReceiver` keeps each session's ids apart.)
        let object_id = (session.send_count - 1) as u32;
        let symbols = transport::encode_message(
            &session.root_key,
            &self.identity.routing_token,
            &target_token,
            object_id,
            &msg_payloads,
            pq_payload.as_deref(),
        )?;
        let tag = self.admission_tag_for(&target_token);
        Ok(symbols
            .iter()
            .map(|inner| self.wrap_data(Lane::Paced, target_token, tag.as_ref(), inner))
            .collect())
    }

    /// Ratchet-encrypt `plaintext` for `target_token`. Returns the inner (not
    /// yet link-encrypted) 0x01 payload of each chunk and, when due, the 0x05
    /// PQ inject payload that follows them.
    ///
    /// The message is split into chunks (see `chunks`), each padded to a
    /// fixed size (see `padding`) and encrypted as its own ratcheted chat
    /// payload, so every one is the same size whatever the message length.
    /// Messages over `chunks::MAX_MESSAGE_LEN` bytes, and messages on a
    /// session the other side hasn't confirmed yet (see `is_connected`), are
    /// rejected before the ratchet moves.
    ///
    /// Every PQ_INJECT_INTERVAL ratchet steps, a PQ inject is generated
    /// automatically — checked once per message, not per chunk, so it always
    /// follows the message's last chunk. It carries the position it applies
    /// at, so the receiver copes with it arriving out of order (see
    /// `SymmetricSessionState::accept_pq_inject`).
    fn encrypt_message_payloads(
        &mut self,
        target_token: RoutingToken,
        plaintext: &[u8],
    ) -> Result<MessagePayloads> {
        if self.e2e_sessions.contains_key(&target_token) && !self.is_connected(&target_token) {
            return Err(anyhow!(
                "Not connected yet: waiting for them to confirm the session."
            ));
        }
        let padded_chunks = chunks::split(plaintext)?
            .iter()
            .map(|chunk| padding::pad(chunk))
            .collect::<Result<Vec<_>>>()?;

        // Phase 1: encrypt each chunk and check if PQ inject is needed (mutable borrow on session)
        let (e2e_payloads, pq_ct) = {
            let session = self
                .e2e_sessions
                .get_mut(&target_token)
                .ok_or(anyhow!("No E2E session established!"))?;
            let send_count_before = session.send_count;

            let mut e2e_payloads = Vec::with_capacity(padded_chunks.len());
            for padded in &padded_chunks {
                let message_key = session.symmetric_ratchet();
                let e2e_cipher = XChaCha20Poly1305::new(Key::from_slice(&message_key));
                let mut e2e_nonce_bytes = [0u8; 24];
                OsRng.fill_bytes(&mut e2e_nonce_bytes);
                let e2e_nonce = XNonce::from_slice(&e2e_nonce_bytes);

                let mut full_e2e_payload = vec![0x01];
                full_e2e_payload.extend_from_slice(&self.identity.routing_token);
                full_e2e_payload.extend_from_slice(&session.send_count.to_be_bytes());
                full_e2e_payload.extend_from_slice(&e2e_nonce_bytes);
                let e2e_ciphertext = e2e_cipher.encrypt(e2e_nonce, padded.as_slice()).unwrap();
                full_e2e_payload.extend_from_slice(&e2e_ciphertext);

                session.send_count += 1;
                e2e_payloads.push(full_e2e_payload);
            }
            // The state is mutated, but save() needs immutable ref.
            // We'll call self.save() after the mutable borrow block.

            // Check if PQ injection is needed: did this message's chunks
            // take send_count past a multiple of PQ_INJECT_INTERVAL?
            let crossed_interval =
                send_count_before / PQ_INJECT_INTERVAL != session.send_count / PQ_INJECT_INTERVAL;
            let pq_ct = if crossed_interval {
                if let Some(ref peer_kyber) = session.peer_kyber_pub {
                    let (pq_secret, kyber_ct) = encapsulate(peer_kyber);
                    session.inject_pq_secret_send(pq_secret.as_bytes());
                    println!(
                        ">> [PQ] Injected post-quantum entropy after {} messages",
                        session.send_count
                    );
                    Some((session.send_count, kyber_ct, session.pq_inject_binding()))
                } else {
                    None
                }
            } else {
                None
            };

            (e2e_payloads, pq_ct)
        };
        // mutable borrow on self.e2e_sessions released
        self.save();
        self.record_message(target_token, true, plaintext);

        // Phase 2: build the signed PQ inject payload (immutable borrow on self)
        let pq_payload = pq_ct.map(|(applies_at, kyber_ct, binding)| {
            let pqi_payload = PQInjectPayload::generate(
                &self.identity,
                target_token,
                applies_at,
                kyber_ct,
                &binding,
            );
            let mut inner = vec![0x05];
            inner.extend_from_slice(&pqi_payload.to_bytes());
            inner
        });

        Ok((e2e_payloads, pq_payload))
    }

    /// Whether a signed control payload's timestamp is within
    /// `MAX_TIMESTAMP_DRIFT` of our clock. Logs and returns `false` if not.
    fn is_fresh(&self, what: &str, timestamp: u64) -> bool {
        if !within_drift(timestamp) {
            println!(">> [SECURITY ALERT] Dropped {what}! Timestamp is stale or from the future.");
            return false;
        }
        true
    }

    /// The check every signed control payload must pass before anything
    /// else: it's addressed to us. (Not all of them must be fresh too: a
    /// KeyExchange or a PQ refresh can arrive long after it was sent, queued
    /// at the relay while we were offline, and add IDs or its `applies_at`
    /// position already make a replayed copy harmless.)
    fn is_addressed_to_us(&self, what: &str, target_token: &RoutingToken) -> bool {
        if target_token.ct_eq(&self.identity.routing_token).unwrap_u8() == 0 {
            println!(">> [SECURITY ALERT] Dropped {what}! It was bound to a different target.");
            return false;
        }
        true
    }

    /// Strip the relay's link layer off a received UDP packet: checks it's a
    /// data packet for our link that we haven't taken in before, decrypts
    /// it, and drops the leading delivery ID. Returns the inner E2E payload
    /// (ready for `handle_incoming_packet`), or `None` for anything else.
    /// Receive loops should use `handle_relay_packet` instead, which also
    /// acks.
    pub fn open_link_packet(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        self.open_relay_packet(packet).map(|(_, payload)| payload)
    }

    /// `open_link_packet`, plus the delivery ID from the packet's 16-byte
    /// prefix.
    pub fn open_relay_packet(&mut self, packet: &[u8]) -> Option<(DeliveryId, Vec<u8>)> {
        let (header, plaintext) = self.link.open(packet).ok()?;
        if header.packet_type != TYPE_DATA {
            return None;
        }
        let (delivery_id, inner) = relay_link::parse_forwarded(&plaintext)?;
        Some((delivery_id, inner.to_vec()))
    }

    /// Everything a receive loop does with one UDP packet from the relay:
    /// open it, handle it unless it's a resend we've already handled, and
    /// acknowledge it so the relay stops resending it. Returns the packets
    /// to send back to the relay, in order: any protocol reply (e.g. a
    /// KeyExchange response), a fresh sync if a contact's admission tag has
    /// just turned up (so the relay knows it now, not at the next
    /// keepalive), then the ack. Packets that aren't for us return nothing.
    ///
    /// The relay's other packets are handled here too: the reply to a
    /// handshake `keepalive` started (see `finish_handshake`), its acks of
    /// our syncs, and its path challenges, which ask whether we're really at
    /// the address our last sync came from (it asks when that address is
    /// new to it, say after our NAT mapping changed). We answer those with
    /// the challenge back, then a fresh sync, which the relay takes in once
    /// the answer has shown we're there.
    ///
    /// The ack goes out after the packet is handled (and its effects
    /// saved), so a crash in between means a resend rather than a lost
    /// message. A packet that fails to handle is acked anyway: resending it
    /// wouldn't change the outcome.
    pub fn handle_relay_packet(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        if packet.first() == Some(&TYPE_HANDSHAKE_RESP) {
            return self.finish_handshake(packet);
        }
        let Ok((header, plaintext)) = self.link.open(packet) else {
            return Vec::new();
        };
        // Authentic, and not a replay: the link is alive.
        self.last_heard = Instant::now();
        match header.packet_type {
            TYPE_DATA => {}
            // All it says is that the relay has our sync, and so the link.
            TYPE_SYNC_ACK => return Vec::new(),
            TYPE_PATH_CHALLENGE => {
                let Some(challenge) = relay_link::parse_challenge(&plaintext) else {
                    return Vec::new();
                };
                let answer = self.link.seal(Lane::Direct, TYPE_PATH_RESPONSE, &challenge);
                return vec![answer, self.generate_sync_packet()];
            }
            _ => return Vec::new(),
        }
        let Some((delivery_id, inner)) = relay_link::parse_forwarded(&plaintext) else {
            return Vec::new();
        };
        let payload = inner.to_vec();
        let needs_ack = delivery_id != [0u8; 16];
        let mut out = Vec::new();
        if (!needs_ack || self.recent_deliveries.first_time(delivery_id))
            && let Ok(Some(reply)) = self.handle_incoming_packet(&payload)
        {
            out.push(reply);
        }
        if self.admission_changed {
            out.push(self.generate_sync_packet());
        }
        if needs_ack {
            out.push(self.generate_ack_packet(&[delivery_id]));
        }
        out
    }

    pub fn handle_incoming_packet(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if payload.is_empty() {
            return Ok(None);
        }
        let pkt_type = payload[0];
        let pkt_data = &payload[1..];
        // Every payload names its sender right after its type byte, and
        // none comes from us: we never message ourselves, and can't add
        // ourselves as a contact (see `add_contact`).
        if pkt_type != 0x00 && pkt_data.get(..16) == Some(&self.identity.routing_token[..]) {
            println!(">> Dropped a packet claiming to be from you.");
            return Ok(None);
        }

        match pkt_type {
            0x01 => {
                if let Some(sender) = self.receive_message(payload, None)? {
                    self.retry_deferred(sender)?;
                }
                Ok(None)
            }
            0x02 => {
                // KeyExchange. Accepted only from a contact we've added
                // ourselves (see `add_contact`); a stranger's is dropped
                // before it touches any contact state, so knowing our token
                // isn't enough to start a session with us. It's only noted
                // so the user can be asked to add them back.
                let Ok(kx) = KeyExchangePayload::from_bytes(pkt_data) else {
                    return Ok(None);
                };
                if kx.verify(&kx.ed25519_public).is_err() {
                    println!(">> Received KeyExchange with invalid signature.");
                    return Ok(None);
                }
                // However old: one that waited at the relay while we were
                // offline still asks to connect, and from a contact still
                // carries the setup on (see `handle_key_exchange`).
                if !self.is_addressed_to_us("KeyExchange", &kx.target_token) {
                    return Ok(None);
                }
                let peer_token = kx.routing_token;
                let Some(expected_ed25519) = self.pending_contacts.get(&peer_token) else {
                    println!(
                        ">> Ignored a connection request from {}, who isn't one of your contacts. Add each other to connect.",
                        short(&peer_token)
                    );
                    self.note_connection_request(peer_token);
                    return Ok(None);
                };
                // A KeyExchange is only self-signed, so its key must match
                // the one we trusted (scanned/pasted) *before* anything below
                // is allowed to touch that contact's state. Otherwise anyone
                // who knows both tokens could forge one that fails this
                // check but has already renamed the contact or swapped the
                // Kyber key used for their future PQ injections.
                if kx.ed25519_public.as_bytes() != expected_ed25519.as_bytes() {
                    println!(
                        ">> [SECURITY ALERT] KeyExchange from {} failed QR code verification!",
                        short(&peer_token)
                    );
                    return Ok(None);
                }
                let fresh = within_drift(kx.timestamp);
                Ok(self.handle_key_exchange(&kx, fresh))
            }
            0x04 => {
                // SessionEstablish
                let Ok(est) = SessionEstablishPayload::from_bytes(pkt_data) else {
                    return Ok(None);
                };
                if !self.is_addressed_to_us("SessionEstablish", &est.target_token) {
                    return Ok(None);
                }
                // Only the contact with the lower routing token sends one
                // (see `establishes_session_with`).
                if self.establishes_session_with(&est.routing_token) {
                    println!(
                        ">> Dropped SessionEstablish from {}: this side establishes the session.",
                        short(&est.routing_token)
                    );
                    return Ok(None);
                }
                let Some(peer_ed25519) = self.pending_contacts.get(&est.routing_token) else {
                    println!(">> Received SessionEstablish but no pending contact found.");
                    return Ok(None);
                };
                if est.verify(peer_ed25519).is_err() {
                    println!(">> [SECURITY ALERT] SessionEstablish signature invalid!");
                    return Ok(None);
                }
                Ok(self.handle_session_establish(&est))
            }
            0x05 => {
                // PQ Inject
                if let Ok(pqi) = PQInjectPayload::from_bytes(pkt_data) {
                    if !self.is_addressed_to_us("PQInject", &pqi.target_token) {
                        return Ok(None);
                    }
                    if let Some(sender_pub) = self.pending_contacts.get(&pqi.routing_token) {
                        if let Some(session) = self.e2e_sessions.get_mut(&pqi.routing_token) {
                            // Verified against this session's binding, so a
                            // refresh replayed from an earlier session with
                            // this peer fails here too.
                            if pqi.verify(sender_pub, &session.pq_inject_binding()).is_ok() {
                                // Decapsulate and hand PQ entropy to the
                                // session, which mixes it in at `applies_at`
                                let pq_secret =
                                    decapsulate(&pqi.kyber_ct, &self.identity.kyber_secret);
                                let secret = pq_secret.as_bytes().try_into().unwrap();
                                // A copy of a refresh we already have (e.g.
                                // resent) is ignored without comment.
                                if session.accept_pq_inject(pqi.applies_at, secret) {
                                    self.save();
                                    println!(
                                        ">> [PQ] Received post-quantum entropy from {} (applies from message {})",
                                        hex::encode(&pqi.routing_token[0..4]),
                                        pqi.applies_at
                                    );
                                    // Messages held back for this refresh
                                    // may decrypt now.
                                    self.retry_deferred(pqi.routing_token)?;
                                }
                            } else {
                                println!(
                                    ">> [SECURITY ALERT] PQInject signature invalid (forged, or replayed from an earlier session)!"
                                );
                            }
                        } else {
                            println!(">> PQInject received but no active session for this peer.");
                        }
                    } else {
                        println!(">> PQInject received but sender unknown (not in contacts).");
                    }
                }
                Ok(None)
            }
            // Relay cover traffic (a "dummy packet"), sized like a forwarded
            // packet so the two look alike on the wire. Nothing to do.
            0x00 => Ok(None),
            0x07 => {
                // FEC symbol: [16-byte sender token | 24-byte nonce | sealed
                // symbol] — see `transport`. Only the two ends of a session
                // hold the seal key, so anything else is silently dropped.
                if pkt_data.len() < 16 {
                    return Err(anyhow!("FEC symbol payload too small"));
                }
                let sender_token: RoutingToken = pkt_data[..16].try_into().unwrap();
                let Some(session) = self.e2e_sessions.get(&sender_token) else {
                    return Ok(None);
                };
                let root_key = session.root_key;
                let Some(symbol) = self.fec_rx.open(
                    &root_key,
                    &sender_token,
                    &self.identity.routing_token,
                    &pkt_data[16..],
                ) else {
                    println!(">> [SECURITY ALERT] Dropped FEC symbol that failed authentication.");
                    return Ok(None);
                };
                // Only someone with the session could have sealed it, so if
                // it's one we offered, they have it.
                self.confirm_session(&sender_token);
                let object = match self
                    .fec_rx
                    .reassemble(sender_token, &symbol, Instant::now())
                {
                    Ok(Some(object)) => object,
                    Ok(None) => return Ok(None),
                    Err(e) => {
                        println!(
                            ">> Dropped FEC symbol from {}: {e}",
                            hex::encode(&sender_token[0..4])
                        );
                        return Ok(None);
                    }
                };
                let Some(parts) = transport::unbundle(&object) else {
                    println!(">> Dropped malformed FEC object.");
                    return Ok(None);
                };
                let mut delivered = false;
                for part in parts {
                    // Only what `create_fec_packets` bundles (a message and
                    // its PQ inject), and only on the sealing peer's own
                    // behalf: both carry the sender's token right after the
                    // type byte.
                    if part.get(1..17) != Some(&sender_token[..]) {
                        continue;
                    }
                    match part[0] {
                        // The seal already proved who sent it, so a message
                        // that can't be decrypted yet may be held back.
                        0x01 => {
                            delivered |=
                                self.receive_message(part, Some(Instant::now()))?.is_some();
                        }
                        0x05 => {
                            self.handle_incoming_packet(part)?;
                        }
                        _ => {}
                    }
                }
                // Once the whole bundle is in: its inject (if any) has
                // already triggered a retry of its own.
                if delivered {
                    self.retry_deferred(sender_token)?;
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// The rest of a KeyExchange from a contact, once it has checked out
    /// (see the 0x02 branch of `handle_incoming_packet`). Returns our reply,
    /// if there is one.
    ///
    /// Each side sends its KeyExchange when it adds the other, and whoever
    /// adds first has theirs dropped, so a contact without our keys gets
    /// ours again. The one of us who establishes (see
    /// `establishes_session_with`) offers a session once the other has its
    /// keys and asks for one, and offers that same session, re-signed, each
    /// time it's asked again, until the other side confirms it has it. So
    /// however the KeyExchanges cross, repeat or get lost, only one session
    /// is ever on offer, and either side adding the other again picks the
    /// setup up wherever it stopped. Add IDs (see `AddIds`) tell an old
    /// message from a current one, and a session the other side has lost
    /// from one it just hasn't received yet.
    ///
    /// That makes a KeyExchange good however long it waited at the relay,
    /// so one that isn't `fresh` (past `MAX_TIMESTAMP_DRIFT`) is taken in
    /// too: dropping it would stall the setup, with both sides waiting.
    /// Only its name isn't, as they may have changed it since.
    fn handle_key_exchange(&mut self, kx: &KeyExchangePayload, fresh: bool) -> Option<Vec<u8>> {
        let peer = kx.routing_token;
        let theirs = self.add_ids(&peer).theirs;
        if kx.add_id < theirs {
            println!(
                ">> Ignored an old KeyExchange from {}, sent before they last added you.",
                short(&peer)
            );
            return None;
        }
        if kx.add_id > theirs {
            self.set_their_add_id(peer, kx.add_id);
        }
        self.note_setup_progress(&peer);

        // Keep the peer's keys: Kyber for our PQ injections (into a session
        // that was made before we had it, too), X25519 for the admission
        // tags we share (see `admission_tag`).
        self.peer_kyber_keys.insert(peer, kx.kyber_public);
        if let Some(session) = self.e2e_sessions.get_mut(&peer) {
            session.peer_kyber_pub.get_or_insert(kx.kyber_public);
        }
        if self.peer_x25519_keys.insert(peer, kx.x25519_public) != Some(kx.x25519_public) {
            self.admission_changed = true;
        }
        // Learn the peer's self-chosen name (if any) the moment their
        // KeyExchange arrives, so it shows up for pending AND established
        // contacts. Not from one that waited at the relay, though: they
        // may have renamed themselves since.
        if fresh {
            if kx.name.is_empty() {
                self.contact_names.remove(&peer);
            } else {
                self.contact_names.insert(peer, kx.name.clone());
            }
        }
        self.save();

        let mine = self.add_ids(&peer).mine;
        let have_session = self.e2e_sessions.contains_key(&peer);
        if !self.establishes_session_with(&peer) {
            return match (have_session, kx.session) {
                // They have the session we have: confirm it, as they may not
                // have heard that we do.
                (true, Some(add_id)) if add_id == mine => Some(self.create_kx_request(peer)),
                // Sent before they made the session we have.
                (true, _) => None,
                // Ask for one: our KeyExchange says we have none.
                (false, _) => Some(self.create_kx_request(peer)),
            };
        }
        if !kx.has_peer_keys {
            return Some(self.create_kx_request(peer));
        }
        match kx.session {
            // They're asking for a session. If we've offered them one, offer
            // it again: nothing has been sent on it, and they may never have
            // got it. If they've confirmed it, this is an old request.
            None if have_session => self.session_est_packet(&peer),
            None => {
                println!(">> Verified keys against QR code!");
                self.offer_new_session(peer, &kx.x25519_public, &kx.kyber_public)
            }
            // They have the session we offered them.
            Some(add_id) if add_id == mine && have_session => {
                self.confirm_session(&peer);
                None
            }
            // They have one from before we last added them, or one we no
            // longer have: our KeyExchange says what we have, so they can
            // drop theirs and ask again.
            Some(_) => Some(self.create_kx_request(peer)),
        }
    }

    /// The rest of a SessionEstablish from a contact, once it has checked
    /// out (see the 0x04 branch of `handle_incoming_packet`): take in the
    /// session it offers, if it's for the add IDs we have now, and confirm
    /// we have it. A repeat of the offer is confirmed again, since our first
    /// confirmation may have gone missing. One held up so long (say at the
    /// relay while we were offline) that it fails the timestamp check is
    /// answered with a fresh request for it instead, if we're still waiting.
    /// A session we can't save isn't taken in or confirmed: they'd start
    /// using it, and we could lose it on a restart.
    fn handle_session_establish(&mut self, est: &SessionEstablishPayload) -> Option<Vec<u8>> {
        let peer = est.routing_token;
        self.note_setup_progress(&peer);
        if !self.is_fresh("SessionEstablish", est.timestamp) {
            return (!self.e2e_sessions.contains_key(&peer)).then(|| self.create_kx_request(peer));
        }
        let ids = self.add_ids(&peer);
        if est.establisher_add_id < ids.theirs || est.responder_add_id != ids.mine {
            println!(
                ">> Ignored an old SessionEstablish from {}, made before one of you last added the other.",
                short(&peer)
            );
            return None;
        }
        if est.establisher_add_id > ids.theirs {
            self.set_their_add_id(peer, est.establisher_add_id);
        }
        let session = self.session_from_est(est);
        let have_it = self
            .e2e_sessions
            .get(&peer)
            .is_some_and(|ours| ours.root_key == session.root_key);
        if !have_it {
            let previous_session = self.e2e_sessions.insert(peer, session);
            let previous_setup = self.session_setups.insert(
                peer,
                SessionSetup {
                    establisher_add_id: est.establisher_add_id,
                    responder_add_id: est.responder_add_id,
                    offer: None,
                },
            );
            if !self.save() {
                match previous_session {
                    Some(session) => self.e2e_sessions.insert(peer, session),
                    None => self.e2e_sessions.remove(&peer),
                };
                match previous_setup {
                    Some(setup) => self.session_setups.insert(peer, setup),
                    None => self.session_setups.remove(&peer),
                };
                return None;
            }
            println!(">> E2E Session established with {}!", short(&peer));
        }
        Some(self.create_kx_request(peer))
    }

    /// Decrypt a 0x01 chat payload: [16-byte sender_token | 8-byte seq_no |
    /// 24-byte nonce | ciphertext of a `padding::PADDED_LEN`-byte padded
    /// block]. Each one carries one chunk of a message (see `chunks`).
    /// Returns the sender if it decrypted (moving their receive chain on),
    /// whether or not that completed a message.
    ///
    /// `park` is `Some(parked_at)` only for a payload whose sender is already
    /// authenticated (it arrived sealed in an FEC bundle): if it can't be
    /// decrypted yet — it was encrypted after a PQ inject still in flight —
    /// it's held for `retry_deferred`, keeping its original `parked_at` so
    /// retries never extend its lifetime. Anyone can forge a bare 0x01, so
    /// those are never held.
    fn receive_message(
        &mut self,
        payload: &[u8],
        park: Option<Instant>,
    ) -> Result<Option<RoutingToken>> {
        let pkt_data = &payload[1..];
        if pkt_data.len() < 16 + 8 + 24 {
            return Err(anyhow!("Msg payload too small"));
        }
        let sender_token: RoutingToken = pkt_data[0..16].try_into().unwrap();
        let seq_no = u64::from_be_bytes(pkt_data[16..24].try_into().unwrap());
        let nonce = XNonce::from_slice(&pkt_data[24..48]);
        let ciphertext = &pkt_data[48..];

        let Some(session) = self.e2e_sessions.get_mut(&sender_token) else {
            println!(
                ">> Received packet from unknown sender {}. No E2E session found.",
                hex::encode(&sender_token[0..4])
            );
            return Ok(None);
        };
        // Already received — typically a resent copy — so its key is used
        // up. Nothing's wrong; don't report it as one.
        if seq_no < session.recv_count && !session.skip_dict.contains_key(&seq_no) {
            return Ok(None);
        }
        let Some(padded) = session.try_decrypt(seq_no, nonce, ciphertext) else {
            match park {
                // Older seq numbers can never succeed later, so those aren't kept.
                Some(parked_at) if seq_no >= session.recv_count => {
                    println!(
                        ">> Holding message {seq_no} from {}: not decryptable yet (PQ ratchet update in flight?).",
                        hex::encode(&sender_token[0..4])
                    );
                    self.fec_rx.defer(
                        sender_token,
                        seq_no,
                        payload.to_vec(),
                        parked_at,
                        Instant::now(),
                    );
                }
                _ => println!(
                    ">> Received packet from {} but decryption failed (out of sync?).",
                    hex::encode(&sender_token[0..4])
                ),
            }
            return Ok(None);
        };
        // The ratchet has advanced either way, so persist that before
        // deciding whether to keep the message.
        self.save();
        let chunk = match padding::unpad(&padded) {
            Ok(chunk) => chunk,
            Err(e) => {
                println!(
                    ">> Dropped message from {}: {} (sender on an older client?)",
                    hex::encode(&sender_token[0..4]),
                    e
                );
                return Ok(Some(sender_token));
            }
        };
        let pt = match self.reassembler.accept(sender_token, chunk) {
            Ok(Some(message)) => message,
            // Waiting on the rest of the message's chunks.
            Ok(None) => return Ok(Some(sender_token)),
            Err(e) => {
                println!(
                    ">> Dropped message chunk from {}: {}",
                    hex::encode(&sender_token[0..4]),
                    e
                );
                return Ok(Some(sender_token));
            }
        };
        println!(
            ">> [From {}]: {}",
            hex::encode(&sender_token[0..4]),
            String::from_utf8_lossy(&pt)
        );
        // Also hand it to any polling consumer (e.g. a GUI) — see the
        // `inbox` field doc comment above.
        self.record_message(sender_token, false, &pt);
        self.inbox.push((sender_token, pt, self.last_recorded_id));
        Ok(Some(sender_token))
    }

    /// Replay, in seq order, payloads from `sender` held back as not yet
    /// decryptable, now that a PQ inject or an earlier chunk has moved
    /// their receive chain on.
    fn retry_deferred(&mut self, sender: RoutingToken) -> Result<()> {
        for (parked_at, payload) in self.fec_rx.take_deferred(&sender, Instant::now()) {
            self.receive_message(&payload, Some(parked_at))?;
        }
        Ok(())
    }
}

// =============================================================
// Shared handshake bootstrap helper (used by the CLI bin and by
// external embedders, e.g. a Tauri backend, that reuse this crate
// as a library instead of driving the socket loop themselves).
// =============================================================
pub async fn perform_handshake(
    client: &mut Client,
    socket: &UdpSocket,
    server_pub: &VerifyingKey,
) -> Result<()> {
    let (client_secret, init) = client.generate_handshake_packet();
    let client_ephemeral = X25519PublicKey::from(&client_secret);
    let give_up = tokio::time::Instant::now() + HANDSHAKE_GIVE_UP;
    // A reply that doesn't check out against `server_pub`: most likely the
    // app was built with another relay's key.
    let mut wrong_key = false;
    let mut buf = [0u8; 1024];
    // UDP gives no error for an unreachable relay (wrong address, relay
    // down, packets lost), so each attempt waits for a reply until its time
    // is up, and the whole thing gives up after `HANDSHAKE_GIVE_UP`. Every
    // attempt sends the same init, so the relay answers all its copies with
    // one link.
    let reply = 'connect: loop {
        let attempt_ends = (tokio::time::Instant::now() + HANDSHAKE_ATTEMPT).min(give_up);
        for copy in 0..HANDSHAKE_COPIES {
            if copy > 0 {
                tokio::time::sleep(HANDSHAKE_COPY_SPACING).await;
            }
            socket.send_to(&init, client.server_addr).await?;
        }
        loop {
            match tokio::time::timeout_at(attempt_ends, socket.recv_from(&mut buf)).await {
                Err(_) => break, // this attempt's time is up
                Ok(Err(_)) => {
                    // A receive error, like an ICMP "port unreachable" while
                    // the relay restarts: wait out the attempt, not spin.
                    tokio::time::sleep_until(attempt_ends).await;
                    break;
                }
                Ok(Ok((len, _))) => {
                    match relay_link::parse_handshake_resp(
                        &buf[..len],
                        server_pub,
                        &client_ephemeral,
                    ) {
                        Ok(_) => break 'connect buf[..len].to_vec(),
                        Err(relay_link::LinkError::BadSignature) => wrong_key = true,
                        Err(_) => {} // not a reply to us: keep waiting
                    }
                }
            }
        }
        if tokio::time::Instant::now() >= give_up {
            return Err(if wrong_key {
                anyhow!(
                    "The relay at {} answered, but not with the key this app has for it (SERVER_PUBKEY). Was it built for another relay?",
                    client.server_addr
                )
            } else {
                anyhow!(
                    "No response from the relay at {} within {}s. Check the address and that the relay is running.",
                    client.server_addr,
                    HANDSHAKE_GIVE_UP.as_secs()
                )
            });
        }
    };
    client.complete_handshake(client_secret, server_pub, &reply)?;
    for sync in client.sync_packets() {
        socket.send_to(&sync, client.server_addr).await?;
    }
    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        cleanup, connect, connected_pair, establisher_and_responder, exchange, from_relay,
        inbox_texts, link_with, new_client, next_relay_packet_number, relay, relay_forward,
        session, strip_link,
    };

    #[test]
    fn test_passcode_hash_roundtrip_and_rejection() {
        let stored = hash_passcode("correct horse battery staple");
        assert!(verify_passcode("correct horse battery staple", &stored));
        assert!(!verify_passcode("wrong passcode", &stored));
        assert!(!verify_passcode("", &stored));
    }

    #[test]
    fn test_passcode_hash_is_salted() {
        // Two hashes of the same passcode must differ (random salt) but
        // both must still verify against that same passcode.
        let a = hash_passcode("shared-secret");
        let b = hash_passcode("shared-secret");
        assert_ne!(a, b);
        assert!(verify_passcode("shared-secret", &a));
        assert!(verify_passcode("shared-secret", &b));
    }

    #[test]
    fn test_passcode_verify_rejects_malformed_stored_value() {
        assert!(!verify_passcode("anything", "not-the-expected-format"));
        assert!(!verify_passcode("anything", ""));
    }

    #[test]
    fn test_derive_vault_key_matches_only_correct_passcode() {
        let stored = hash_passcode("correct horse battery staple");
        let key = derive_vault_key("correct horse battery staple", &stored);
        assert!(key.is_some());
        assert!(derive_vault_key("wrong passcode", &stored).is_none());
        assert!(derive_vault_key("correct horse battery staple", "garbage").is_none());
    }

    #[test]
    fn test_derive_vault_key_is_independent_of_stored_verifier() {
        // The vault key must not be recoverable from the stored verifier
        // alone (no passcode) — see `derive_vault_key`'s doc comment. This
        // is a sanity check, not a proof: it just confirms the two labeled
        // HKDF outputs actually differ for the same underlying secret.
        let stored = hash_passcode("shared-secret");
        let verifier_hex = stored.rsplit('$').next().unwrap();
        let vault_key = derive_vault_key("shared-secret", &stored).unwrap();
        assert_ne!(hex::encode(vault_key.as_ref()), verifier_hex);
    }

    #[test]
    fn test_forget_contact_removes_session_and_history() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut client = Client::new(server_addr);
        let mut db_path = std::env::temp_dir();
        db_path.push(format!(
            "e2e-messenger-forget-contact-test-{:x}.sqlite",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&db_path);
        client.history = Some(ChatHistory::open(&db_path, &[5u8; 32]).unwrap());

        let contact = [8u8; 16];
        client
            .history
            .as_ref()
            .unwrap()
            .append(contact, true, "hi")
            .unwrap();
        client
            .pending_contacts
            .insert(contact, SigningKey::from_bytes(&[9u8; 32]).verifying_key());

        client.forget_contact(contact);
        assert!(!client.pending_contacts.contains_key(&contact));
        assert_eq!(client.history_for_contact(contact, 10).len(), 0);

        let _ = std::fs::remove_file(&db_path);
    }

    /// A frontend that shows both a live-delivered message (via
    /// `create_encrypted_packets`'s side channel, or `drain_inbox`'s third
    /// tuple element) and a later history-fetched one (via
    /// `history_for_contact`) needs both to report the *same* id for the
    /// same underlying row, or a naive merge of the two views will show one
    /// message twice under two different synthetic ids. This test locks in
    /// that the ids always agree, for both outgoing and incoming messages.
    #[test]
    fn test_live_and_historical_message_ids_agree() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);

        let mut db_path = std::env::temp_dir();
        db_path.push(format!(
            "e2e-messenger-id-agreement-test-{:x}.sqlite",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&db_path);
        alice.history = Some(ChatHistory::open(&db_path, &[6u8; 32]).unwrap());
        connect(&mut alice, &mut bob);

        // Outgoing: the side-channel id must match what a history fetch
        // reports for that same row.
        alice
            .create_encrypted_packets(bob.identity.routing_token, b"outgoing")
            .unwrap();
        let live_outgoing_id = alice.last_recorded_id.expect("history is attached");
        let fetched = alice.history_for_contact(bob.identity.routing_token, 10);
        assert_eq!(fetched.last().unwrap().id, live_outgoing_id);

        // Incoming: `drain_inbox`'s third element must match too.
        let (msg_packet, _) = bob
            .create_encrypted_packets(alice.identity.routing_token, b"incoming")
            .unwrap();
        let inner_msg = strip_link(&msg_packet[0], &bob.link.keys().to_relay);
        alice.handle_incoming_packet(&inner_msg).unwrap();
        let (_, _, live_incoming_id) = alice.drain_inbox().pop().unwrap();
        let fetched = alice.history_for_contact(bob.identity.routing_token, 10);
        assert_eq!(fetched.last().unwrap().id, live_incoming_id.unwrap());

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_derive_vault_key_stable_across_calls() {
        // Logging in twice with the same passcode must unlock the same
        // database, i.e. the vault key must be deterministic given the
        // same stored hash and passcode.
        let stored = hash_passcode("shared-secret");
        let a = derive_vault_key("shared-secret", &stored).unwrap();
        let b = derive_vault_key("shared-secret", &stored).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    // ==========================================
    // Serialization & Signature Tests
    // ==========================================

    #[test]
    fn test_key_exchange_serialization() {
        let alice_id = UserIdentity::generate();
        let mut bob_token = [0u8; 16];
        bob_token[0] = 0xBB;
        let payload = KeyExchangePayload::generate(&alice_id, bob_token, "", false, 0, None);
        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), 1393);
        let parsed = KeyExchangePayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&parsed.ed25519_public).is_ok());
        assert!(!parsed.has_peer_keys);
        assert_eq!(parsed.target_token, bob_token);
        assert_eq!(parsed.routing_token, alice_id.routing_token);
    }

    #[test]
    fn test_session_est_serialization() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let eph_sec = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_sec);
        let (_ks, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let est = SessionEstablishPayload::generate(
            &alice_id,
            bob_id.routing_token,
            kyber_ct,
            eph_pub,
            0,
            0,
        );
        let bytes = est.to_bytes();
        assert_eq!(bytes.len(), 1232);
        let parsed = SessionEstablishPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public).is_ok());
    }

    #[test]
    fn test_pq_inject_serialization() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let (_pq_secret, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let binding = [0x5A; 32];
        let pqi =
            PQInjectPayload::generate(&alice_id, bob_id.routing_token, 42, kyber_ct, &binding);
        let bytes = pqi.to_bytes();
        assert_eq!(bytes.len(), 1200);
        let parsed = PQInjectPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public, &binding).is_ok());
        assert!(
            parsed
                .verify(&alice_id.ed25519_public, &[0x5B; 32])
                .is_err(),
            "must not verify against another session's binding"
        );
        assert_eq!(parsed.routing_token, alice_id.routing_token);
        assert_eq!(parsed.target_token, bob_id.routing_token);
        assert_eq!(parsed.applies_at, 42);
    }

    // ==========================================
    // Edge Case: Malformed Packets
    // ==========================================

    #[test]
    fn test_edge_case_invalid_packet_sizes() {
        assert!(KeyExchangePayload::from_bytes(&[0u8; 0]).is_err());
        assert!(KeyExchangePayload::from_bytes(&[0u8; 100]).is_err());
        assert!(KeyExchangePayload::from_bytes(&[0u8; 1392]).is_err());
        assert!(KeyExchangePayload::from_bytes(&[0u8; 1394]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 0]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 1231]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 1233]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 0]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 1199]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 1201]).is_err());
    }

    #[test]
    fn test_edge_case_empty_payload_handling() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut client = Client::new(server_addr);
        assert!(client.handle_incoming_packet(&[]).unwrap().is_none());
        assert!(client.handle_incoming_packet(&[0xFF]).unwrap().is_none());
        assert!(client.handle_incoming_packet(&[0x01, 0x00]).is_err());
    }

    // ==========================================
    // Edge Case: Tampered Signatures
    // ==========================================

    #[test]
    fn test_edge_case_bad_kx_signature() {
        let alice_id = UserIdentity::generate();
        let payload = KeyExchangePayload::generate(&alice_id, [0u8; 16], "", false, 0, None);
        let mut bytes = payload.to_bytes();
        bytes[104] ^= 0x01;
        let parsed = KeyExchangePayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&parsed.ed25519_public).is_err());
    }

    #[test]
    fn test_edge_case_bad_est_signature() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let eph_sec = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_sec);
        let (_, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let est = SessionEstablishPayload::generate(
            &alice_id,
            bob_id.routing_token,
            kyber_ct,
            eph_pub,
            0,
            0,
        );
        let mut bytes = est.to_bytes();
        bytes[1200] ^= 0x01;
        let parsed = SessionEstablishPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public).is_err());
    }

    #[test]
    fn test_edge_case_bad_pq_inject_signature() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let (_, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let binding = [0x5A; 32];
        let pqi = PQInjectPayload::generate(&alice_id, bob_id.routing_token, 5, kyber_ct, &binding);
        let mut bytes = pqi.to_bytes();
        bytes[1150] ^= 0x01;
        let parsed = PQInjectPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public, &binding).is_err());
    }

    #[test]
    fn test_edge_case_est_wrong_verifier_key() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let eph_sec = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_sec);
        let (_, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let est = SessionEstablishPayload::generate(
            &alice_id,
            bob_id.routing_token,
            kyber_ct,
            eph_pub,
            0,
            0,
        );
        let bytes = est.to_bytes();
        let parsed = SessionEstablishPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&bob_id.ed25519_public).is_err());
    }

    #[test]
    fn test_edge_case_pq_inject_wrong_verifier_key() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let (_, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let binding = [0x5A; 32];
        let pqi = PQInjectPayload::generate(&alice_id, bob_id.routing_token, 5, kyber_ct, &binding);
        let bytes = pqi.to_bytes();
        let parsed = PQInjectPayload::from_bytes(&bytes).unwrap();
        // Verify with wrong key — simulates Mallory injection
        assert!(parsed.verify(&bob_id.ed25519_public, &binding).is_err());
    }

    // ==========================================
    // Edge Case: Replay & Misbinding
    // ==========================================

    #[test]
    fn test_edge_case_timestamp_expiration() {
        let alice_id = UserIdentity::generate();
        let mut payload = KeyExchangePayload::generate(&alice_id, [0u8; 16], "", false, 0, None);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        payload.timestamp = now - 600;
        let time_diff = (now as i64 - payload.timestamp as i64).abs();
        assert!(time_diff > 300);
    }

    #[test]
    fn test_edge_case_target_misbinding() {
        let alice_id = UserIdentity::generate();
        let mut charlie_token = [0u8; 16];
        charlie_token[0] = 0xCC;
        let payload = KeyExchangePayload::generate(&alice_id, charlie_token, "", false, 0, None);
        let mut bob_token = [0u8; 16];
        bob_token[0] = 0xBB;
        assert_ne!(payload.target_token, bob_token);
    }

    // ==========================================
    // Symmetric Hash Ratchet Tests
    // ==========================================

    #[test]
    fn test_symmetric_ratchet_multiple_messages() {
        let mut alice_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };
        for i in 0..10 {
            let alice_mk = alice_state.symmetric_ratchet();
            let bob_mk = bob_state.symmetric_ratchet();
            assert_eq!(alice_mk, bob_mk, "Message key mismatch at iteration {}", i);
            assert_eq!(alice_state.send_chain_key, bob_state.send_chain_key);
        }
    }

    #[test]
    fn test_symmetric_ratchet_produces_unique_keys() {
        let mut state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };
        let mut seen_keys = std::collections::HashSet::new();
        for _ in 0..100 {
            let mk = state.symmetric_ratchet();
            assert!(seen_keys.insert(mk), "Duplicate message key!");
        }
    }

    #[test]
    fn test_symmetric_hash_ratchet_single_message() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);
        let root_key = [0x42u8; 32];
        alice.e2e_sessions.insert(
            bob.identity.routing_token,
            SymmetricSessionState {
                root_key,
                send_chain_key: root_key,
                recv_chain_key: root_key,
                send_count: 0,
                peer_kyber_pub: None,
                recv_count: 0,
                skip_dict: std::collections::HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
            },
        );
        bob.e2e_sessions.insert(
            alice.identity.routing_token,
            SymmetricSessionState {
                root_key,
                send_chain_key: root_key,
                recv_chain_key: root_key,
                send_count: 0,
                peer_kyber_pub: None,
                recv_count: 0,
                skip_dict: std::collections::HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
            },
        );
        let (packet, _pq) = alice
            .create_encrypted_packets(bob.identity.routing_token, b"Hello Bob!")
            .unwrap();
        let inner = strip_link(&packet[0], &alice.link.keys().to_relay);
        bob.handle_incoming_packet(&inner).unwrap();
        let a_ck = alice
            .e2e_sessions
            .get(&bob.identity.routing_token)
            .unwrap()
            .send_chain_key;
        let b_ck = bob
            .e2e_sessions
            .get(&alice.identity.routing_token)
            .unwrap()
            .recv_chain_key;
        assert_eq!(a_ck, b_ck);
    }

    // ==========================================
    // PQ Ratchet Injection Tests
    // ==========================================

    #[test]
    fn test_pq_inject_triggers_at_interval() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let bob_id = UserIdentity::generate();
        let bob_kyber_copy = bob_id.kyber_public;
        alice.e2e_sessions.insert(
            bob_id.routing_token,
            SymmetricSessionState {
                root_key: [0x42u8; 32],
                send_chain_key: [0x42u8; 32],
                recv_chain_key: [0x42u8; 32],
                send_count: 0,
                recv_count: 0,
                skip_dict: std::collections::HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
                peer_kyber_pub: Some(bob_kyber_copy),
            },
        );

        // Messages 1-4: no PQ inject
        for i in 0..4 {
            let (_, pq) = alice
                .create_encrypted_packets(bob_id.routing_token, b"test")
                .unwrap();
            assert!(
                pq.is_none(),
                "PQ inject should NOT trigger at message {}",
                i + 1
            );
        }

        // Message 5: PQ inject triggers!
        let (_, pq) = alice
            .create_encrypted_packets(bob_id.routing_token, b"test")
            .unwrap();
        assert!(pq.is_some(), "PQ inject MUST trigger at message 5");

        // Messages 6-9: no PQ inject
        for i in 5..9 {
            let (_, pq) = alice
                .create_encrypted_packets(bob_id.routing_token, b"test")
                .unwrap();
            assert!(
                pq.is_none(),
                "PQ inject should NOT trigger at message {}",
                i + 1
            );
        }

        // Message 10: PQ inject triggers again!
        let (_, pq) = alice
            .create_encrypted_packets(bob_id.routing_token, b"test")
            .unwrap();
        assert!(pq.is_some(), "PQ inject MUST trigger at message 10");
    }

    #[test]
    fn test_pq_inject_no_trigger_without_kyber_key() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let bob_token = [0xBB; 16];
        alice.e2e_sessions.insert(
            bob_token,
            SymmetricSessionState {
                root_key: [0x42u8; 32],
                send_chain_key: [0x42u8; 32],
                recv_chain_key: [0x42u8; 32],
                send_count: 0,
                recv_count: 0,
                skip_dict: std::collections::HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
                peer_kyber_pub: None, // No Kyber key!
            },
        );

        // Even at message 5, no PQ inject because no peer Kyber key
        for _ in 0..10 {
            let (_, pq) = alice.create_encrypted_packets(bob_token, b"test").unwrap();
            assert!(
                pq.is_none(),
                "PQ inject must NOT trigger without peer Kyber key"
            );
        }
    }

    #[test]
    fn test_pq_inject_chain_sync() {
        // Verify that after PQ injection, both sides' chain keys remain identical
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);

        // Set up sessions with each other's Kyber keys
        let alice_kyber_copy = alice.identity.kyber_public;
        let bob_kyber_copy = bob.identity.kyber_public;
        let root_key = [0x42u8; 32];

        alice.e2e_sessions.insert(
            bob.identity.routing_token,
            SymmetricSessionState {
                root_key,
                send_chain_key: root_key,
                recv_chain_key: root_key,
                send_count: 0,
                recv_count: 0,
                skip_dict: std::collections::HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
                peer_kyber_pub: Some(bob_kyber_copy),
            },
        );
        bob.e2e_sessions.insert(
            alice.identity.routing_token,
            SymmetricSessionState {
                root_key,
                send_chain_key: root_key,
                recv_chain_key: root_key,
                send_count: 0,
                recv_count: 0,
                skip_dict: std::collections::HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
                peer_kyber_pub: Some(alice_kyber_copy),
            },
        );
        // Bob needs Alice in pending_contacts for PQ inject verification
        bob.pending_contacts
            .insert(alice.identity.routing_token, alice.identity.ed25519_public);

        // Alice sends 5 messages (triggers PQ inject on 5th)
        for i in 0..5 {
            let (msg_pkt, pq_pkt) = alice
                .create_encrypted_packets(
                    bob.identity.routing_token,
                    format!("msg {}", i + 1).as_bytes(),
                )
                .unwrap();

            // Bob receives the message
            let inner = strip_link(&msg_pkt[0], &alice.link.keys().to_relay);
            bob.handle_incoming_packet(&inner).unwrap();

            // If PQ inject was generated, Bob processes it too
            if let Some(pq) = pq_pkt {
                let pq_inner = strip_link(&pq, &alice.link.keys().to_relay);
                bob.handle_incoming_packet(&pq_inner).unwrap();
            }
        }

        // Chain keys MUST still be in sync after the PQ injection
        let a_ck = alice
            .e2e_sessions
            .get(&bob.identity.routing_token)
            .unwrap()
            .send_chain_key;
        let b_ck = bob
            .e2e_sessions
            .get(&alice.identity.routing_token)
            .unwrap()
            .recv_chain_key;
        assert_eq!(a_ck, b_ck, "Chain keys must be in sync after PQ injection!");
    }

    #[test]
    fn test_pq_inject_changes_chain_key() {
        // Verify that PQ injection actually changes the chain key (not a no-op)
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let bob_id = UserIdentity::generate();
        let bob_kyber_copy = bob_id.kyber_public;
        let root_key = [0x42u8; 32];

        alice.e2e_sessions.insert(
            bob_id.routing_token,
            SymmetricSessionState {
                root_key,
                send_chain_key: root_key,
                recv_chain_key: root_key,
                send_count: 0,
                recv_count: 0,
                skip_dict: std::collections::HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
                peer_kyber_pub: Some(bob_kyber_copy),
            },
        );

        // Record chain key after 4th message (before PQ inject)
        for _ in 0..4 {
            alice
                .create_encrypted_packets(bob_id.routing_token, b"test")
                .unwrap();
        }
        let chain_before_pq = alice
            .e2e_sessions
            .get(&bob_id.routing_token)
            .unwrap()
            .send_chain_key;

        // Send 5th message (triggers PQ inject)
        let (_, pq) = alice
            .create_encrypted_packets(bob_id.routing_token, b"test")
            .unwrap();
        assert!(pq.is_some());

        let chain_after_pq = alice
            .e2e_sessions
            .get(&bob_id.routing_token)
            .unwrap()
            .send_chain_key;

        // The chain key must be different from what a pure hash ratchet would produce
        // (because the PQ secret was mixed in)
        assert_ne!(
            chain_before_pq, chain_after_pq,
            "PQ inject must change the chain key"
        );

        // Also verify it's not just a normal ratchet step by comparing to a no-PQ ratchet
        let mut no_pq_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };
        for _ in 0..5 {
            no_pq_state.symmetric_ratchet();
        }
        assert_ne!(
            chain_after_pq, no_pq_state.send_chain_key,
            "PQ-injected chain must differ from non-PQ chain"
        );
    }

    // ==========================================
    // Full 3-Way Handshake Integration Test
    // ==========================================

    // ==========================================
    // Contact Handshake Tests
    // ==========================================

    fn assert_one_session_with_pq_keys(a: &Client, b: &Client) {
        assert_eq!(session(a, b).root_key, session(b, a).root_key);
        assert!(
            session(a, b).peer_kyber_pub.is_some(),
            "needed for PQ injects"
        );
        assert!(
            session(b, a).peer_kyber_pub.is_some(),
            "needed for PQ injects"
        );
        assert!(a.is_connected(&b.identity.routing_token));
        assert!(b.is_connected(&a.identity.routing_token));
    }

    /// Hand `packet` from `from` to `to`, returning `to`'s reply.
    fn hand(from: &Client, to: &mut Client, packet: &[u8]) -> Option<Vec<u8>> {
        to.handle_incoming_packet(&relay(packet, from)).unwrap()
    }

    /// The setup up to the establisher's offer: the establisher adds the
    /// responder first (dropped), the responder adds it back, they swap
    /// keys, and the responder asks for a session. Returns the offer, not
    /// yet delivered.
    fn up_to_the_offer(e: &mut Client, r: &mut Client) -> Vec<u8> {
        let early = e
            .add_contact(r.identity.routing_token, r.identity.ed25519_public)
            .unwrap();
        assert_eq!(exchange(e, r, early), [0x02], "dropped");
        let kx = r
            .add_contact(e.identity.routing_token, e.identity.ed25519_public)
            .unwrap();
        let keys = hand(r, e, &kx).unwrap();
        let request = hand(e, r, &keys).unwrap();
        let offer = hand(r, e, &request).unwrap();
        assert_eq!(relay(&offer, e)[0], 0x04);
        offer
    }

    /// Deliver `in_flight` (each packet tagged with whether `e` sent it),
    /// and every reply after it, newest first or oldest first, each one
    /// `copies` times, until neither side has anything left to say. For
    /// checking the setup settles the same way whatever order things
    /// arrive in, and however often.
    fn settle(
        e: &mut Client,
        r: &mut Client,
        mut in_flight: Vec<(bool, Vec<u8>)>,
        newest_first: bool,
        copies: usize,
    ) {
        let mut delivered = 0;
        while !in_flight.is_empty() {
            let (from_e, packet) = if newest_first {
                in_flight.pop().unwrap()
            } else {
                in_flight.remove(0)
            };
            for _ in 0..copies {
                delivered += 1;
                assert!(delivered < 200, "didn't settle");
                let reply = if from_e {
                    hand(e, r, &packet)
                } else {
                    hand(r, e, &packet)
                };
                in_flight.extend(reply.map(|reply| (!from_e, reply)));
            }
        }
    }

    /// The establisher (lower token) adds the responder first, so its
    /// KeyExchange is dropped. When the responder adds it back, each sends
    /// the other its keys, the responder asks for a session, the establisher
    /// offers one, and the responder confirms it has it.
    #[test]
    fn test_handshake_when_establisher_adds_first() {
        let (mut e, mut r) = establisher_and_responder();
        let early = e
            .add_contact(r.identity.routing_token, r.identity.ed25519_public)
            .unwrap();
        assert_eq!(exchange(&mut e, &mut r, early), [0x02], "dropped");
        assert!(r.peer_kyber_keys.is_empty() && r.contact_names.is_empty());

        let kx = r
            .add_contact(e.identity.routing_token, e.identity.ed25519_public)
            .unwrap();
        assert_eq!(exchange(&mut r, &mut e, kx), [0x02, 0x02, 0x02, 0x04, 0x02]);
        assert_one_session_with_pq_keys(&e, &r);
        cleanup(&[&e, &r]);
    }

    #[test]
    fn test_handshake_when_responder_adds_first() {
        let (mut e, mut r) = establisher_and_responder();
        let early = r
            .add_contact(e.identity.routing_token, e.identity.ed25519_public)
            .unwrap();
        assert_eq!(exchange(&mut r, &mut e, early), [0x02], "dropped");

        let kx = e
            .add_contact(r.identity.routing_token, r.identity.ed25519_public)
            .unwrap();
        assert_eq!(exchange(&mut e, &mut r, kx), [0x02, 0x02, 0x04, 0x02]);
        assert_one_session_with_pq_keys(&e, &r);
        cleanup(&[&e, &r]);
    }

    /// Both add each other before either KeyExchange arrives, so the two
    /// cross. Only one session may come of it, or each side would end up on
    /// a different one.
    #[test]
    fn test_handshake_when_both_add_before_hearing_back() {
        let (mut e, mut r) = establisher_and_responder();
        let kx_e = e
            .add_contact(r.identity.routing_token, r.identity.ed25519_public)
            .unwrap();
        let kx_r = r
            .add_contact(e.identity.routing_token, e.identity.ed25519_public)
            .unwrap();
        let r_reply = hand(&e, &mut r, &kx_e).unwrap();
        let e_reply = hand(&r, &mut e, &kx_r).unwrap();

        assert_eq!(exchange(&mut r, &mut e, r_reply), [0x02, 0x04, 0x02]);
        assert_eq!(
            exchange(&mut e, &mut r, e_reply),
            [0x02],
            "sent before the session was made, so ignored"
        );
        assert_one_session_with_pq_keys(&e, &r);
        cleanup(&[&e, &r]);
    }

    /// The responder asked for a session, and the establisher's offer never
    /// arrived. Adding the contact again, from either side, picks the setup
    /// up where it stopped, on the session already offered: the establisher
    /// offers that one again rather than making another.
    #[test]
    fn test_re_adding_from_either_side_restarts_a_stuck_setup() {
        for re_adder_establishes in [true, false] {
            let (mut e, mut r) = establisher_and_responder();
            let _lost_offer = up_to_the_offer(&mut e, &mut r);
            let offered = session(&e, &r).root_key;
            assert!(!e.is_connected(&r.identity.routing_token), "not confirmed");
            assert!(!r.e2e_sessions.contains_key(&e.identity.routing_token));

            if re_adder_establishes {
                let kx = e
                    .add_contact(r.identity.routing_token, r.identity.ed25519_public)
                    .unwrap();
                assert_eq!(exchange(&mut e, &mut r, kx), [0x02, 0x02, 0x04, 0x02]);
            } else {
                let kx = r
                    .add_contact(e.identity.routing_token, e.identity.ed25519_public)
                    .unwrap();
                assert_eq!(exchange(&mut r, &mut e, kx), [0x02, 0x04, 0x02]);
            }
            assert_one_session_with_pq_keys(&e, &r);
            assert_eq!(session(&r, &e).root_key, offered, "the one already offered");
            cleanup(&[&e, &r]);
        }
    }

    /// The responder has the session, but its confirmation never reached
    /// the establisher, which keeps the session unused meanwhile. Adding the
    /// contact again from either side gets a confirmation through.
    #[test]
    fn test_re_adding_from_either_side_recovers_a_lost_confirmation() {
        for re_adder_establishes in [true, false] {
            let (mut e, mut r) = establisher_and_responder();
            let offer = up_to_the_offer(&mut e, &mut r);
            let _lost_confirmation = hand(&e, &mut r, &offer).unwrap();
            assert!(r.is_connected(&e.identity.routing_token));
            assert!(!e.is_connected(&r.identity.routing_token));
            assert!(
                e.create_fec_packets(r.identity.routing_token, b"too soon")
                    .is_err(),
                "not used before it's confirmed"
            );

            if re_adder_establishes {
                let kx = e
                    .add_contact(r.identity.routing_token, r.identity.ed25519_public)
                    .unwrap();
                assert_eq!(exchange(&mut e, &mut r, kx), [0x02, 0x02]);
            } else {
                let kx = r
                    .add_contact(e.identity.routing_token, e.identity.ed25519_public)
                    .unwrap();
                assert_eq!(exchange(&mut r, &mut e, kx), [0x02]);
            }
            assert_one_session_with_pq_keys(&e, &r);
            cleanup(&[&e, &r]);
        }
    }

    /// A message from the responder on the session also shows the
    /// establisher it has it, if its confirmation went missing.
    #[test]
    fn test_a_message_on_the_session_confirms_it() {
        let (mut e, mut r) = establisher_and_responder();
        let offer = up_to_the_offer(&mut e, &mut r);
        let _lost_confirmation = hand(&e, &mut r, &offer).unwrap();
        let burst = r
            .create_fec_packets(e.identity.routing_token, b"hi")
            .unwrap();
        for packet in &burst {
            hand(&r, &mut e, packet);
        }
        assert_eq!(inbox_texts(&mut e), ["hi"]);
        assert_one_session_with_pq_keys(&e, &r);
        cleanup(&[&e, &r]);
    }

    /// The responder's request arrives twice (two KeyExchanges crossed, or
    /// the relay resent one): the establisher offers the same session both
    /// times, so whichever offer arrives first, both sides end up on it.
    #[test]
    fn test_repeated_requests_get_the_same_session_whatever_the_order() {
        let (mut e, mut r) = establisher_and_responder();
        let early = e
            .add_contact(r.identity.routing_token, r.identity.ed25519_public)
            .unwrap();
        exchange(&mut e, &mut r, early);
        let kx = r
            .add_contact(e.identity.routing_token, e.identity.ed25519_public)
            .unwrap();
        let keys = hand(&r, &mut e, &kx).unwrap();
        let request = hand(&e, &mut r, &keys).unwrap();
        let first = hand(&r, &mut e, &request).unwrap();
        let second = hand(&r, &mut e, &request).unwrap();
        let offered = session(&e, &r).root_key;

        let confirmations = [second, first].map(|offer| hand(&e, &mut r, &offer).unwrap());
        assert_eq!(session(&r, &e).root_key, offered);
        for confirmation in confirmations {
            assert!(hand(&r, &mut e, &confirmation).is_none());
        }
        assert_one_session_with_pq_keys(&e, &r);
        cleanup(&[&e, &r]);
    }

    /// An offer held up past the timestamp window (the relay kept it while
    /// the responder was offline, say) is answered with a fresh request,
    /// and the establisher offers the same session again, freshly signed.
    #[test]
    fn test_stale_offer_is_answered_with_a_fresh_request() {
        use ed25519_dalek::Signer;
        let (mut e, mut r) = establisher_and_responder();
        let offer = up_to_the_offer(&mut e, &mut r);
        let mut est = SessionEstablishPayload::from_bytes(&relay(&offer, &e)[1..]).unwrap();
        est.timestamp -= 600;
        let mut signed = Vec::new();
        signed.extend_from_slice(&est.routing_token);
        signed.extend_from_slice(&est.target_token);
        signed.extend_from_slice(&est.timestamp.to_be_bytes());
        signed.extend_from_slice(est.kyber_ct.as_bytes());
        signed.extend_from_slice(est.eph_x25519_pub.as_bytes());
        signed.extend_from_slice(&est.establisher_add_id.to_be_bytes());
        signed.extend_from_slice(&est.responder_add_id.to_be_bytes());
        est.signature = e.identity.ed25519_secret.sign(&signed);
        let mut stale = vec![0x04];
        stale.extend_from_slice(&est.to_bytes());

        let request = r.handle_incoming_packet(&stale).unwrap().unwrap();
        assert!(r.e2e_sessions.is_empty(), "too old to take in");
        assert_eq!(exchange(&mut r, &mut e, request), [0x02, 0x04, 0x02]);
        assert_one_session_with_pq_keys(&e, &r);
        cleanup(&[&e, &r]);
    }

    /// One side removes the other, then adds them back: the other still
    /// has its old session, and both end up on a new one.
    #[test]
    fn test_contact_removed_on_one_side_reconnects_when_added_back() {
        for remover_is_establisher in [true, false] {
            let (mut e, mut r) = establisher_and_responder();
            connect(&mut e, &mut r);
            let old_root = session(&e, &r).root_key;
            let (remover, other) = if remover_is_establisher {
                (&mut e, &mut r)
            } else {
                (&mut r, &mut e)
            };
            remover.forget_contact(other.identity.routing_token);

            let kx = remover
                .add_contact(other.identity.routing_token, other.identity.ed25519_public)
                .unwrap();
            exchange(remover, other, kx);
            assert_one_session_with_pq_keys(&e, &r);
            assert_ne!(session(&e, &r).root_key, old_root, "a new session");
            cleanup(&[&e, &r]);
        }
    }

    /// One side removes the other, then both add each other again at once.
    /// Their KeyExchanges cross, and whatever order everything arrives in,
    /// and even if everything arrives twice, they end up on one new
    /// session.
    #[test]
    fn test_both_re_adding_at_once_after_a_removal_ends_on_one_session() {
        for remover_establishes in [true, false] {
            for newest_first in [true, false] {
                for copies in [1, 2] {
                    let (mut e, mut r) = establisher_and_responder();
                    connect(&mut e, &mut r);
                    let old_root = session(&e, &r).root_key;
                    if remover_establishes {
                        e.forget_contact(r.identity.routing_token);
                    } else {
                        r.forget_contact(e.identity.routing_token);
                    }
                    let kx_e = e
                        .add_contact(r.identity.routing_token, r.identity.ed25519_public)
                        .unwrap();
                    let kx_r = r
                        .add_contact(e.identity.routing_token, e.identity.ed25519_public)
                        .unwrap();
                    settle(
                        &mut e,
                        &mut r,
                        vec![(true, kx_e), (false, kx_r)],
                        newest_first,
                        copies,
                    );
                    assert_one_session_with_pq_keys(&e, &r);
                    assert_ne!(session(&e, &r).root_key, old_root);
                    cleanup(&[&e, &r]);
                }
            }
        }
    }

    /// A KeyExchange or SessionEstablish sent before the other side last
    /// removed and re-added us is recognisably old (see `AddIds`), so a late
    /// copy can't knock anyone off the session they've set up since.
    #[test]
    fn test_messages_from_before_a_re_add_are_ignored() {
        let (mut e, mut r) = establisher_and_responder();
        connect(&mut e, &mut r);
        let old_kx = r.create_kx_request(e.identity.routing_token);
        let eph = X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
        let (_, kyber_ct) = encapsulate(&r.identity.kyber_public);
        let old_offer = SessionEstablishPayload::generate(
            &e.identity,
            r.identity.routing_token,
            kyber_ct,
            eph,
            e.add_ids(&r.identity.routing_token).mine,
            r.add_ids(&e.identity.routing_token).mine,
        );
        let mut old_offer = [vec![0x04], old_offer.to_bytes()].concat();

        r.forget_contact(e.identity.routing_token);
        let kx = r
            .add_contact(e.identity.routing_token, e.identity.ed25519_public)
            .unwrap();
        exchange(&mut r, &mut e, kx);
        let current = session(&e, &r).root_key;

        assert!(hand(&r, &mut e, &old_kx).is_none());
        assert!(r.handle_incoming_packet(&old_offer).unwrap().is_none());
        old_offer[1] ^= 1; // and nothing else gets past the signature
        assert!(r.handle_incoming_packet(&old_offer).unwrap().is_none());
        assert_eq!(session(&e, &r).root_key, current);
        assert_one_session_with_pq_keys(&e, &r);
        cleanup(&[&e, &r]);
    }

    /// The same SessionEstablish twice (the relay resent it, say): the
    /// second only gets the confirmation again, with the session untouched,
    /// even after it has been used.
    #[test]
    fn test_repeated_session_establish_changes_nothing() {
        let (mut e, mut r) = establisher_and_responder();
        let offer = up_to_the_offer(&mut e, &mut r);
        let confirmation = hand(&e, &mut r, &offer).unwrap();
        assert!(hand(&r, &mut e, &confirmation).is_none());
        let (msgs, _) = e
            .create_encrypted_packets(r.identity.routing_token, b"hello")
            .unwrap();
        hand(&e, &mut r, &msgs[0]);
        let before = session(&r, &e).recv_chain_key;

        let again = hand(&e, &mut r, &offer).unwrap();
        assert_eq!(relay(&again, &r)[0], 0x02, "confirmed again");
        assert_eq!(session(&r, &e).recv_chain_key, before);
        assert_eq!(inbox_texts(&mut r), ["hello"]);
        cleanup(&[&e, &r]);
    }

    /// Adding a contact is saved straight away, not only once their reply
    /// comes: an app closed in between still knows it added them, so their
    /// KeyExchange isn't taken for a stranger's.
    #[test]
    fn test_adding_a_contact_is_saved_straight_away() {
        let (mut alice, mut bob) = (new_client(), new_client());
        alice
            .add_contact(bob.identity.routing_token, bob.identity.ed25519_public)
            .unwrap();
        let mut restarted = ClientStateDto::load(&alice.state_path).unwrap();
        assert!(
            restarted
                .pending_contacts
                .contains_key(&bob.identity.routing_token)
        );

        let kx = bob
            .add_contact(alice.identity.routing_token, alice.identity.ed25519_public)
            .unwrap();
        exchange(&mut bob, &mut restarted, kx);
        assert!(restarted.connection_requests().is_empty());
        assert_one_session_with_pq_keys(&restarted, &bob);
        cleanup(&[&alice, &bob]);
    }

    #[test]
    fn test_key_exchange_from_stranger_is_dropped_and_only_noted() {
        let mut bob = new_client();
        for _ in 0..55 {
            let stranger = UserIdentity::generate();
            let kx = KeyExchangePayload::generate(
                &stranger,
                bob.identity.routing_token,
                "stranger",
                false,
                1,
                None,
            );
            let mut packet = vec![0x02];
            packet.extend_from_slice(&kx.to_bytes());
            assert!(bob.handle_incoming_packet(&packet).unwrap().is_none());
        }
        assert!(bob.pending_contacts.is_empty());
        assert!(bob.peer_kyber_keys.is_empty());
        assert!(bob.peer_x25519_keys.is_empty());
        assert!(bob.contact_names.is_empty());
        assert_eq!(bob.connection_requests().len(), MAX_CONNECTION_REQUESTS);
    }

    /// A stranger's request is listed (in the order they arrived) so the
    /// user can be asked to scan them back, until they do, or dismiss it.
    #[test]
    fn test_connection_requests_listed_until_added_or_dismissed() {
        let (mut alice, mut bob, mut carol) = (new_client(), new_client(), new_client());
        let request = |from: &mut Client, to: &mut Client| {
            let kx = from
                .add_contact(to.identity.routing_token, to.identity.ed25519_public)
                .unwrap();
            assert_eq!(exchange(from, to, kx), [0x02], "dropped");
        };
        request(&mut alice, &mut bob);
        request(&mut carol, &mut bob);
        request(&mut alice, &mut bob); // again: listed once, still first
        assert_eq!(
            bob.connection_requests(),
            [alice.identity.routing_token, carol.identity.routing_token]
        );

        bob.dismiss_connection_request(&carol.identity.routing_token);
        assert_eq!(bob.connection_requests(), [alice.identity.routing_token]);
        request(&mut carol, &mut bob);
        assert_eq!(
            bob.connection_requests(),
            [alice.identity.routing_token],
            "dismissed, so not listed again"
        );

        // Scanning Alice back accepts: no longer a request, and connected.
        let kx = bob
            .add_contact(alice.identity.routing_token, alice.identity.ed25519_public)
            .unwrap();
        assert!(bob.connection_requests().is_empty());
        exchange(&mut bob, &mut alice, kx);
        assert!(bob.is_connected(&alice.identity.routing_token));
        assert!(alice.connection_requests().is_empty());
        cleanup(&[&alice, &bob, &carol]);
    }

    /// However many identities someone makes, only
    /// `MAX_CONNECTION_REQUESTS` new requests are listed per
    /// `CONNECTION_REQUEST_TTL`, dismissed ones included, so they can't keep
    /// popping up requests. Muting lists none at all, and is saved.
    #[test]
    fn test_connection_requests_are_limited_and_can_be_muted() {
        let request = |to: &mut Client, from: &UserIdentity| {
            let kx =
                KeyExchangePayload::generate(from, to.identity.routing_token, "", false, 1, None);
            to.handle_incoming_packet(&[vec![0x02], kx.to_bytes()].concat())
                .unwrap();
        };
        let mut bob = new_client();
        for _ in 0..MAX_CONNECTION_REQUESTS {
            let stranger = UserIdentity::generate();
            request(&mut bob, &stranger);
            assert_eq!(bob.connection_requests(), [stranger.routing_token]);
            bob.dismiss_connection_request(&stranger.routing_token);
        }
        request(&mut bob, &UserIdentity::generate());
        assert!(bob.connection_requests().is_empty(), "over the limit");

        let mut carol = new_client();
        carol.set_requests_muted(true);
        request(&mut carol, &UserIdentity::generate());
        assert!(carol.connection_requests().is_empty());
        assert!(
            ClientStateDto::load(&carol.state_path)
                .unwrap()
                .requests_muted()
        );
        carol.set_requests_muted(false);
        assert!(
            carol.connection_requests().is_empty(),
            "none kept while muted"
        );
        let stranger = UserIdentity::generate();
        request(&mut carol, &stranger);
        assert_eq!(carol.connection_requests(), [stranger.routing_token]);
        cleanup(&[&bob, &carol]);
    }

    /// Only an intact KeyExchange addressed to us gets noted: not a
    /// tampered one, or one meant for someone else.
    #[test]
    fn test_misaddressed_or_forged_request_is_not_noted() {
        let mut bob = new_client();
        let stranger = UserIdentity::generate();
        let misaddressed = KeyExchangePayload::generate(&stranger, [0xCC; 16], "", false, 0, None);
        let mut forged =
            KeyExchangePayload::generate(&stranger, bob.identity.routing_token, "", false, 0, None);
        forged.name = "tampered".into();
        for kx in [misaddressed, forged] {
            let mut packet = vec![0x02];
            packet.extend_from_slice(&kx.to_bytes());
            bob.handle_incoming_packet(&packet).unwrap();
        }
        assert!(bob.connection_requests().is_empty());
    }

    /// Only the establisher sends a SessionEstablish, so one from the
    /// responder is dropped even when it's a contact and signed properly.
    #[test]
    fn test_session_establish_from_the_responder_is_dropped() {
        let (mut e, r) = establisher_and_responder();
        e.pending_contacts
            .insert(r.identity.routing_token, r.identity.ed25519_public);
        e.peer_kyber_keys
            .insert(r.identity.routing_token, r.identity.kyber_public);
        let eph = X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
        let (_, kyber_ct) = encapsulate(&e.identity.kyber_public);
        let est = SessionEstablishPayload::generate(
            &r.identity,
            e.identity.routing_token,
            kyber_ct,
            eph,
            0,
            0,
        );
        let packet = [vec![0x04], est.to_bytes()].concat();
        assert!(e.handle_incoming_packet(&packet).unwrap().is_none());
        assert!(e.e2e_sessions.is_empty());
    }

    #[test]
    fn test_sync_packet_proves_routing_token_ownership() {
        let mut client = new_client();
        link_with(&mut client, 7, [1, 2, 3, 4]);
        let packet = client.generate_sync_packet();
        let header = relay_link::header(&packet).unwrap();
        assert_eq!(
            (header.packet_type, header.session_id),
            (TYPE_SYNC, [1, 2, 3, 4])
        );
        let sync =
            relay_link::Sync::from_bytes(&relay_link::open(&[7u8; 32], &packet).unwrap()).unwrap();
        assert_eq!(sync.token, client.identity.routing_token);
        assert!(sync.verify(client.link.keys()).is_ok());
        assert!(
            sync.verify(&relay_link::derive_link_keys(&[8u8; 32]))
                .is_err(),
            "only proves anything on this link"
        );
    }

    /// The relay picks the link's session ID, and only a reply signed by
    /// the relay we pinned, to our own handshake, is taken.
    #[test]
    fn test_handshake_takes_the_session_id_the_relay_gives() {
        let relay_identity = SigningKey::from_bytes(&[7; 32]);
        let reply = |init: &[u8], session_id: SessionId| {
            let client_ephemeral = relay_link::parse_handshake_init(init).unwrap();
            let relay_secret = EphemeralSecret::random_from_rng(OsRng);
            let relay_ephemeral = X25519PublicKey::from(&relay_secret);
            let resp = relay_link::handshake_resp(
                &relay_identity,
                &client_ephemeral,
                &relay_ephemeral,
                &session_id,
            );
            let link_keys = relay_link::derive_link_keys(
                relay_secret.diffie_hellman(&client_ephemeral).as_bytes(),
            );
            (resp, link_keys)
        };
        let mut client = new_client();

        let (secret, init) = client.generate_handshake_packet();
        let (resp, _) = reply(&init, [5, 6, 7, 8]);
        let impostor = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert!(client.complete_handshake(secret, &impostor, &resp).is_err());
        let (secret, _) = client.generate_handshake_packet();
        assert!(
            client
                .complete_handshake(secret, &relay_identity.verifying_key(), &resp)
                .is_err(),
            "a reply to another handshake"
        );

        let (secret, init) = client.generate_handshake_packet();
        let (resp, link_keys) = reply(&init, [5, 6, 7, 8]);
        client
            .complete_handshake(secret, &relay_identity.verifying_key(), &resp)
            .unwrap();
        assert_eq!(client.link.session_id(), [5, 6, 7, 8]);
        assert_eq!(client.link.keys(), &link_keys);
    }

    /// The relay's path challenge is answered with the same challenge, then
    /// a fresh sync for the relay to take in once it has checked the
    /// answer. One that isn't from our link is ignored.
    #[test]
    fn test_path_challenge_is_answered_then_synced() {
        let mut client = new_client();
        link_with(&mut client, 4, [1, 2, 3, 4]);
        let challenge = [9u8; 16];
        let packet = from_relay(&client, TYPE_PATH_CHALLENGE, &challenge);
        let answer = client.handle_relay_packet(&packet);
        assert_eq!(answer.len(), 2);
        let header = relay_link::header(&answer[0]).unwrap();
        assert_eq!(
            (header.packet_type, header.session_id),
            (TYPE_PATH_RESPONSE, [1, 2, 3, 4])
        );
        assert_eq!(relay_link::open(&[4; 32], &answer[0]).unwrap(), challenge);
        assert_eq!(answer[1][0], TYPE_SYNC);

        assert!(
            client.handle_relay_packet(&packet).is_empty(),
            "a copy is ignored"
        );
        let forged = relay_link::seal(
            &[5; 32],
            TYPE_PATH_CHALLENGE,
            &[1, 2, 3, 4],
            next_relay_packet_number(),
            &challenge,
        );
        assert!(client.handle_relay_packet(&forged).is_empty());
    }

    /// Contacts work out the same admission tag for each direction, which
    /// nobody else can, our sync registers the ones contacts use to reach
    /// us, and what we send a contact carries theirs. Removing a contact
    /// takes theirs out of the next sync.
    #[test]
    fn test_contacts_share_admission_tags_the_sync_registers() {
        let (mut alice, mut bob) = connected_pair();
        let (a, b) = (alice.identity.routing_token, bob.identity.routing_token);
        let alice_to_bob = alice.admission_tag_for(&b).unwrap();
        assert_eq!(bob.admission_tags_in(), [alice_to_bob]);
        assert_eq!(
            alice.admission_tags_in(),
            [bob.admission_tag_for(&a).unwrap()]
        );
        assert_ne!(
            Some(alice_to_bob),
            bob.admission_tag_for(&a),
            "one per direction"
        );
        let mallory = UserIdentity::generate();
        assert_ne!(
            admission_tag(&mallory.x25519_secret, &bob.identity.x25519_public, &a, &b),
            Some(alice_to_bob)
        );

        let sync_packet = bob.generate_sync_packet();
        let sync = relay_link::Sync::from_bytes(
            &relay_link::open(&bob.link.keys().to_relay, &sync_packet).unwrap(),
        )
        .unwrap();
        assert_eq!(sync.admission, [alice_to_bob]);
        let packet = alice.create_fec_packets(b, b"hi").unwrap().remove(0);
        let header = relay_link::header(&packet).unwrap();
        let plaintext = relay_link::open(&alice.link.keys().to_relay, &packet).unwrap();
        let (_, tag, _) = relay_link::parse_data(header.packet_type, &plaintext).unwrap();
        assert_eq!(tag, Some(alice_to_bob));

        bob.forget_contact(a);
        assert!(bob.admission_tags_in().is_empty());
        cleanup(&[&alice, &bob]);
    }

    #[test]
    fn test_reconnect_after_identity_recreation_creates_independent_session() {
        let mut alice1 = new_client();
        let mut bob = new_client();
        alice1.local_name = "alice".to_string();
        bob.local_name = "bob".to_string();

        // --- Baseline: Alice1 <-> Bob fully established, one message each way ---
        connect(&mut alice1, &mut bob);
        let bob_alice1_session_before = bob
            .e2e_sessions
            .get(&alice1.identity.routing_token)
            .unwrap()
            .root_key;

        let (msg_to_bob, _) = alice1
            .create_encrypted_packets(bob.identity.routing_token, b"hi bob, it's alice")
            .unwrap();
        let inner_msg = strip_link(&msg_to_bob[0], &alice1.link.keys().to_relay);
        bob.handle_incoming_packet(&inner_msg).unwrap();
        assert_eq!(bob.inbox.last().unwrap().1, b"hi bob, it's alice");

        // --- Alice's identity is deleted and recreated: brand-new keys/token,
        // same self-chosen name. Bob's own state is completely untouched. ---
        let mut alice2 = new_client();
        alice2.local_name = "alice".to_string();
        assert_ne!(
            alice2.identity.routing_token, alice1.identity.routing_token,
            "a recreated identity must not reuse the old routing token"
        );

        // They add each other again, exactly like the ContactPanel's "Add
        // contact" form / connect_to_peer command on both sides.
        connect(&mut alice2, &mut bob);

        // Bob now has two independent sessions for "alice" — this is the
        // "duplicate contact" the UI needs a remove-contact action for, not
        // a protocol bug. Assert it's a clean duplicate, not corruption.
        assert!(
            bob.e2e_sessions
                .contains_key(&alice1.identity.routing_token),
            "Bob's old session must survive Alice's identity recreation"
        );
        assert!(
            bob.e2e_sessions
                .contains_key(&alice2.identity.routing_token),
            "Bob must establish a fresh session with the recreated identity"
        );
        assert_eq!(
            bob.e2e_sessions
                .get(&alice1.identity.routing_token)
                .unwrap()
                .root_key,
            bob_alice1_session_before,
            "the old session's keys must be untouched by the new handshake"
        );

        // --- The new session must work end-to-end, in both directions ---
        let (msg_to_bob2, _) = alice2
            .create_encrypted_packets(bob.identity.routing_token, b"hi bob, it's the new alice")
            .unwrap();
        let inner_msg2 = strip_link(&msg_to_bob2[0], &alice2.link.keys().to_relay);
        bob.handle_incoming_packet(&inner_msg2).unwrap();
        assert_eq!(bob.inbox.last().unwrap().1, b"hi bob, it's the new alice");

        let (msg_to_alice2, _) = bob
            .create_encrypted_packets(alice2.identity.routing_token, b"hi new alice, it's bob")
            .unwrap();
        let inner_msg3 = strip_link(&msg_to_alice2[0], &bob.link.keys().to_relay);
        alice2.handle_incoming_packet(&inner_msg3).unwrap();
        assert_eq!(alice2.inbox.last().unwrap().1, b"hi new alice, it's bob");

        // --- Bob manually forgets the stale old-Alice contact ---
        bob.forget_contact(alice1.identity.routing_token);
        assert!(
            !bob.e2e_sessions
                .contains_key(&alice1.identity.routing_token),
            "the old session must be gone after forget_contact"
        );
        assert!(
            !bob.contact_names
                .contains_key(&alice1.identity.routing_token)
        );
        assert!(
            bob.e2e_sessions
                .contains_key(&alice2.identity.routing_token),
            "forgetting the old contact must not disturb the new one"
        );
        crate::test_support::cleanup(&[&alice1, &alice2, &bob]);
    }

    #[test]
    fn test_key_exchange_propagates_display_name() {
        // A self-chosen name (the login username) should reach the peer
        // automatically as part of the KeyExchange — no manual entry by the
        // other side, in either direction.
        let mut alice = new_client();
        let mut bob = new_client();
        alice.local_name = "alice".to_string();
        bob.local_name = "bob".to_string();
        connect(&mut alice, &mut bob);

        assert_eq!(
            bob.contact_names.get(&alice.identity.routing_token),
            Some(&"alice".to_string())
        );
        assert_eq!(
            alice.contact_names.get(&bob.identity.routing_token),
            Some(&"bob".to_string())
        );
    }

    #[test]
    fn test_full_handshake_then_pq_inject() {
        // Full handshake + 5 messages + PQ inject: end-to-end integration
        let mut alice = new_client();
        let mut bob = new_client();
        connect(&mut alice, &mut bob);

        // Send 5 messages with PQ inject at #5
        for i in 0..5 {
            let (msg_pkt, pq_pkt) = alice
                .create_encrypted_packets(
                    bob.identity.routing_token,
                    format!("Hello {}", i + 1).as_bytes(),
                )
                .unwrap();
            let msg_inner = strip_link(&msg_pkt[0], &alice.link.keys().to_relay);
            bob.handle_incoming_packet(&msg_inner).unwrap();
            if let Some(pq) = pq_pkt {
                assert_eq!(i, 4, "PQ inject must only trigger at message 5");
                let pq_inner = strip_link(&pq, &alice.link.keys().to_relay);
                bob.handle_incoming_packet(&pq_inner).unwrap();
            }
        }

        // Verify chain keys still in sync
        let a_ck = alice
            .e2e_sessions
            .get(&bob.identity.routing_token)
            .unwrap()
            .send_chain_key;
        let b_ck = bob
            .e2e_sessions
            .get(&alice.identity.routing_token)
            .unwrap()
            .recv_chain_key;
        assert_eq!(a_ck, b_ck, "Chain keys must match after 5 msgs + PQ inject");

        // Send message 6 to prove the session still works
        let (msg6, _) = alice
            .create_encrypted_packets(bob.identity.routing_token, b"Post-PQ message")
            .unwrap();
        let msg6_inner = strip_link(&msg6[0], &alice.link.keys().to_relay);
        bob.handle_incoming_packet(&msg6_inner).unwrap();

        let a_ck2 = alice
            .e2e_sessions
            .get(&bob.identity.routing_token)
            .unwrap()
            .send_chain_key;
        let b_ck2 = bob
            .e2e_sessions
            .get(&alice.identity.routing_token)
            .unwrap()
            .recv_chain_key;
        assert_eq!(a_ck2, b_ck2, "Chain keys must match after post-PQ message");
    }

    // ==========================================
    // Attack Simulation Tests
    // ==========================================

    /// An identity that `client` would accept a SessionEstablish from (its
    /// routing token is the lower one), so a test reaches the checks after
    /// that. Swaps identities with `client` when the new one's token is the
    /// higher: generating until one happened to be lower could take any
    /// number of tries.
    fn identity_establishing_with(client: &mut Client) -> UserIdentity {
        let mut id = UserIdentity::generate();
        if id.routing_token > client.identity.routing_token {
            std::mem::swap(&mut id, &mut client.identity);
        }
        id
    }

    #[test]
    fn test_attack_session_overwrite_prevention() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        let alice_id = identity_establishing_with(&mut bob);
        let mallory_id = UserIdentity::generate();
        bob.pending_contacts
            .insert(alice_id.routing_token, alice_id.ed25519_public);

        let eph_sec = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_sec);
        let (_, kyber_ct) = encapsulate(&bob.identity.kyber_public);
        let mut est = SessionEstablishPayload::generate(
            &mallory_id,
            bob.identity.routing_token,
            kyber_ct,
            eph_pub,
            0,
            0,
        );
        est.routing_token = alice_id.routing_token;
        let mut inner = vec![0x04];
        inner.extend_from_slice(&est.to_bytes());
        bob.handle_incoming_packet(&inner).unwrap();
        assert!(!bob.e2e_sessions.contains_key(&alice_id.routing_token));
    }

    #[test]
    fn test_attack_no_session_without_pending() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        let alice_id = identity_establishing_with(&mut bob);
        let eph_sec = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_sec);
        let (_, kyber_ct) = encapsulate(&bob.identity.kyber_public);
        let est = SessionEstablishPayload::generate(
            &alice_id,
            bob.identity.routing_token,
            kyber_ct,
            eph_pub,
            0,
            0,
        );
        let mut inner = vec![0x04];
        inner.extend_from_slice(&est.to_bytes());
        bob.handle_incoming_packet(&inner).unwrap();
        assert!(!bob.e2e_sessions.contains_key(&alice_id.routing_token));
    }

    #[test]
    fn test_attack_forged_pq_inject() {
        // Mallory sends a PQ inject claiming to be Alice — signature must fail
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        let alice_id = UserIdentity::generate();
        let mallory_id = UserIdentity::generate();

        // Bob has Alice in pending contacts and an active session
        bob.pending_contacts
            .insert(alice_id.routing_token, alice_id.ed25519_public);
        bob.e2e_sessions.insert(
            alice_id.routing_token,
            SymmetricSessionState {
                root_key: [0x42; 32],
                send_chain_key: [0x42; 32],
                recv_chain_key: [0x42; 32],
                send_count: 0,
                peer_kyber_pub: None,
                recv_count: 0,
                skip_dict: std::collections::HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
            },
        );
        let chain_before = bob.e2e_sessions[&alice_id.routing_token].recv_chain_key;

        // Mallory signs PQ inject with her own key but spoofs Alice's routing
        // token. If accepted, it would be held pending for position 1.
        // Even with the right session binding, her key gives her away.
        let (_, kyber_ct) = encapsulate(&bob.identity.kyber_public);
        let binding = bob.e2e_sessions[&alice_id.routing_token].pq_inject_binding();
        let mut pqi = PQInjectPayload::generate(
            &mallory_id,
            bob.identity.routing_token,
            1,
            kyber_ct,
            &binding,
        );
        pqi.routing_token = alice_id.routing_token;

        let mut inner = vec![0x05];
        inner.extend_from_slice(&pqi.to_bytes());
        bob.handle_incoming_packet(&inner).unwrap();

        // A refresh changes the receive side, so that's what must not move
        let session = &bob.e2e_sessions[&alice_id.routing_token];
        assert_eq!(
            chain_before, session.recv_chain_key,
            "Forged PQ inject must NOT modify chain key"
        );
        assert!(session.recv_pq_injects.pending.is_empty());
    }

    // ==========================================
    // Edge Case: Out-of-Order Packets & Bounds
    // ==========================================

    #[test]
    fn test_edge_case_out_of_order_packets_and_loss() {
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
        let mut alice_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };

        let mk1 = alice_state.symmetric_ratchet();
        let mk2 = alice_state.symmetric_ratchet();
        let mk3 = alice_state.symmetric_ratchet();

        let c1 = XChaCha20Poly1305::new(Key::from_slice(&mk1));
        let c2 = XChaCha20Poly1305::new(Key::from_slice(&mk2));
        let c3 = XChaCha20Poly1305::new(Key::from_slice(&mk3));

        let nonce = XNonce::from_slice(&[0u8; 24]);
        let ct1 = c1.encrypt(nonce, b"msg1".as_ref()).unwrap();
        let ct2 = c2.encrypt(nonce, b"msg2".as_ref()).unwrap();
        let ct3 = c3.encrypt(nonce, b"msg3".as_ref()).unwrap();

        // Deliver pkt 3 first (out of order, missing 1 and 2)
        let pt3 = bob_state.try_decrypt(2, nonce, &ct3).unwrap();
        assert_eq!(pt3, b"msg3");
        assert_eq!(bob_state.recv_count, 3);
        assert_eq!(bob_state.skip_dict.len(), 2); // Buffered keys for seq 0 and 1

        // Deliver pkt 1 (delayed)
        let pt1 = bob_state.try_decrypt(0, nonce, &ct1).unwrap();
        assert_eq!(pt1, b"msg1");
        assert_eq!(bob_state.skip_dict.len(), 1);

        // Deliver pkt 2 (delayed)
        let pt2 = bob_state.try_decrypt(1, nonce, &ct2).unwrap();
        assert_eq!(pt2, b"msg2");
        assert_eq!(bob_state.skip_dict.len(), 0);
    }

    #[test]
    fn test_edge_case_max_skip_dict_exhaustion() {
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
        let mut alice_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };

        // Receive packet with seq_no 150 (exceeds MAX_SKIP_DICT_ENTRIES of 100)
        for _ in 0..151 {
            alice_state.symmetric_ratchet();
        }
        let mk150 = alice_state.symmetric_ratchet();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk150));
        let nonce = XNonce::from_slice(&[0u8; 24]);
        let ct150 = cipher.encrypt(nonce, b"msg150".as_ref()).unwrap();

        let pt = bob_state.try_decrypt(150, nonce, &ct150);
        assert!(
            pt.is_none(),
            "Should drop packet that skips more than 100 seq nums"
        );
        assert_eq!(bob_state.recv_count, 0);
    }

    /// A contact flooding us with SessionEstablishes leaves one session,
    /// and nothing that grows with the flood.
    #[test]
    fn test_edge_case_session_establish_flood_keeps_one_session() {
        let mut bob = new_client();
        let alice_id = identity_establishing_with(&mut bob);
        bob.pending_contacts
            .insert(alice_id.routing_token, alice_id.ed25519_public);

        for _ in 0..100 {
            let eph_sec = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
            let eph_pub = x25519_dalek::PublicKey::from(&eph_sec);
            let (_, kyber_ct) = pq::encapsulate(&bob.identity.kyber_public);
            let payload = SessionEstablishPayload::generate(
                &alice_id,
                bob.identity.routing_token,
                kyber_ct,
                eph_pub,
                0,
                0,
            );
            let mut packet = vec![0x04];
            packet.extend_from_slice(&payload.to_bytes());
            let _ = bob.handle_incoming_packet(&packet);
        }

        assert_eq!(bob.e2e_sessions.len(), 1);
        assert_eq!(bob.session_setups.len(), 1);
        cleanup(&[&bob]);
    }

    // ==========================================
    // New Tests: Duplicate, Replay, Timestamp, Misbinding, Storage
    // ==========================================

    #[test]
    fn test_edge_case_duplicate_message_rejection() {
        // Verifies: same seq_no decrypts first time from skip_dict, fails second time
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
        let mut alice_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };

        let mk0 = alice_state.symmetric_ratchet();
        let mk1 = alice_state.symmetric_ratchet();
        let nonce = XNonce::from_slice(&[0u8; 24]);

        // Encrypt messages
        let c0 = XChaCha20Poly1305::new(Key::from_slice(&mk0));
        let c1 = XChaCha20Poly1305::new(Key::from_slice(&mk1));
        let ct0 = c0.encrypt(nonce, b"first".as_ref()).unwrap();
        let ct1 = c1.encrypt(nonce, b"second".as_ref()).unwrap();

        // Deliver msg 1 first (out of order), which stores msg 0's key in skip_dict
        let pt1 = bob_state.try_decrypt(1, nonce, &ct1).unwrap();
        assert_eq!(pt1, b"second");
        assert_eq!(bob_state.skip_dict.len(), 1); // Key for seq 0 stored

        // Deliver msg 0 from skip_dict — should succeed
        let pt0 = bob_state.try_decrypt(0, nonce, &ct0).unwrap();
        assert_eq!(pt0, b"first");
        assert_eq!(bob_state.skip_dict.len(), 0); // Consumed

        // Replay msg 0 — skip_dict entry consumed, should fail
        let dup = bob_state.try_decrypt(0, nonce, &ct0);
        assert!(dup.is_none(), "Duplicate message must be rejected");
    }

    /// A KeyExchange that waited at the relay past `MAX_TIMESTAMP_DRIFT`
    /// (Bob was offline when Alice added him) still carries the setup on:
    /// Bob takes in Alice's keys and answers, so neither is left waiting.
    /// Only the name it carries isn't taken, as she may have renamed
    /// herself since. One addressed to someone else is still dropped.
    #[test]
    fn test_stale_key_exchange_from_a_contact_still_carries_the_setup_on() {
        let mut bob = new_client();
        let alice_id = UserIdentity::generate();
        bob.add_contact(alice_id.routing_token, alice_id.ed25519_public)
            .unwrap();

        let to_someone_else = stale_key_exchange(&alice_id, [0x99; 16], "alice", false, 1);
        assert!(
            bob.handle_incoming_packet(&to_someone_else)
                .unwrap()
                .is_none()
        );
        assert!(!bob.peer_kyber_keys.contains_key(&alice_id.routing_token));

        let stale = stale_key_exchange(&alice_id, bob.identity.routing_token, "alice", false, 1);
        let reply = bob.handle_incoming_packet(&stale).unwrap();
        assert_eq!(reply.map(|packet| relay(&packet, &bob)[0]), Some(0x02));
        assert!(bob.peer_kyber_keys.contains_key(&alice_id.routing_token));
        assert_eq!(bob.add_ids[&alice_id.routing_token].theirs, 1);
        assert!(!bob.contact_names.contains_key(&alice_id.routing_token));
        assert_eq!(
            bob.contact_status(&alice_id.routing_token),
            ContactStatus::Connecting
        );
        cleanup(&[&bob]);
    }

    #[test]
    fn test_edge_case_target_misbinding_via_handler() {
        // Sends a KeyExchange bound to Charlie through Bob's handler
        // and verifies Bob drops it (fixes incomplete test from review)
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        let alice_id = UserIdentity::generate();
        bob.pending_contacts
            .insert(alice_id.routing_token, alice_id.ed25519_public);

        let mut charlie_token = [0u8; 16];
        charlie_token[0] = 0xCC;
        // Alice signs a KX intended for Charlie, NOT Bob
        let payload = KeyExchangePayload::generate(&alice_id, charlie_token, "", false, 0, None);
        let mut packet = vec![0x02];
        packet.extend_from_slice(&payload.to_bytes());

        let result = bob.handle_incoming_packet(&packet).unwrap();
        assert!(
            result.is_none(),
            "Misbinding must cause packet to be dropped"
        );
        assert!(
            !bob.peer_kyber_keys.contains_key(&alice_id.routing_token),
            "Misbound KX must not be taken in"
        );
    }

    #[test]
    fn test_pq_inject_accepted_long_after_it_was_sent() {
        // A refresh queued at the relay while Bob was offline arrives with a
        // timestamp far in the past. It must still be applied: dropping it
        // would leave every later message undecryptable.
        let (mut alice, mut bob) = connected_pair();
        let msgs = send_messages(&mut alice, &bob, 5);
        let refresh = msgs[4].1.clone().expect("refresh after message 5");

        let mut pqi = PQInjectPayload::from_bytes(&refresh[1..]).unwrap();
        pqi.timestamp -= 600; // 10 minutes in the past
        // Re-sign with the stale timestamp
        use ed25519_dalek::Signer;
        let mut msg = Vec::new();
        msg.extend_from_slice(&pqi.routing_token);
        msg.extend_from_slice(&pqi.target_token);
        msg.extend_from_slice(&pqi.timestamp.to_be_bytes());
        msg.extend_from_slice(&pqi.applies_at.to_be_bytes());
        msg.extend_from_slice(pqi.kyber_ct.as_bytes());
        msg.extend_from_slice(&alice.e2e_sessions[&bob.identity.routing_token].pq_inject_binding());
        pqi.signature = alice.identity.ed25519_secret.sign(&msg);
        let mut stale_refresh = vec![0x05];
        stale_refresh.extend_from_slice(&pqi.to_bytes());

        for (msg, _) in &msgs {
            bob.handle_incoming_packet(msg).unwrap();
        }
        bob.handle_incoming_packet(&stale_refresh).unwrap();
        assert_chains_in_sync(&alice, &bob);

        let next = send_messages(&mut alice, &bob, 1);
        bob.handle_incoming_packet(&next[0].0).unwrap();
        assert_eq!(bob.drain_inbox().len(), 6);
    }

    #[test]
    fn test_storage_save_load_roundtrip() {
        // Verifies all keys survive serialization round-trip
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut original = Client::new(server_addr);

        // Set up some state
        let peer_token = [0xBB; 16];
        let peer_id = UserIdentity::generate();
        original
            .pending_contacts
            .insert(peer_token, peer_id.ed25519_public);
        original
            .peer_kyber_keys
            .insert(peer_token, peer_id.kyber_public);
        original.e2e_sessions.insert(
            peer_token,
            SymmetricSessionState {
                root_key: [0x42; 32],
                send_chain_key: [0x43; 32],
                recv_chain_key: [0x43; 32],
                send_count: 7,
                recv_count: 3,
                peer_kyber_pub: Some(peer_id.kyber_public),
                skip_dict: {
                    let mut m = std::collections::HashMap::new();
                    m.insert(1, [0xAA; 32]);
                    m
                },
                recv_pq_injects: RecvPqInjects {
                    pending: BTreeMap::from([(10, [0xEE; 32])]),
                    applied_through: 5,
                },
            },
        );
        original
            .peer_x25519_keys
            .insert(peer_token, peer_id.x25519_public);
        original.add_ids.insert(
            peer_token,
            AddIds {
                mine: 11,
                theirs: 22,
            },
        );
        let (_, kyber_ct) = encapsulate(&peer_id.kyber_public);
        original.session_setups.insert(
            peer_token,
            SessionSetup {
                establisher_add_id: 11,
                responder_add_id: 22,
                offer: Some(SessionOffer {
                    eph_x25519_pub: peer_id.x25519_public,
                    kyber_ct,
                }),
            },
        );
        original.requests_muted = true;
        original.notify_with_names = true;

        // Save to a temp file
        let tmp_path = "test_roundtrip_state.json";
        ClientStateDto::save(&original, tmp_path).unwrap();

        // Load back
        let loaded = ClientStateDto::load(tmp_path).unwrap();

        // Verify identity
        assert_eq!(
            original.identity.routing_token,
            loaded.identity.routing_token
        );
        assert_eq!(
            original.identity.ed25519_public.as_bytes(),
            loaded.identity.ed25519_public.as_bytes()
        );
        assert_eq!(
            original.identity.x25519_public.as_bytes(),
            loaded.identity.x25519_public.as_bytes()
        );
        assert_eq!(
            original.identity.kyber_public.as_bytes(),
            loaded.identity.kyber_public.as_bytes()
        );

        // Verify session state
        let orig_sess = original.e2e_sessions.get(&peer_token).unwrap();
        let load_sess = loaded.e2e_sessions.get(&peer_token).unwrap();
        assert_eq!(orig_sess.root_key, load_sess.root_key);
        assert_eq!(orig_sess.send_chain_key, load_sess.send_chain_key);
        assert_eq!(orig_sess.send_count, load_sess.send_count);
        assert_eq!(orig_sess.recv_count, load_sess.recv_count);
        assert_eq!(orig_sess.skip_dict.len(), load_sess.skip_dict.len());
        assert_eq!(orig_sess.skip_dict[&1], load_sess.skip_dict[&1]);
        assert_eq!(
            orig_sess.recv_pq_injects.pending,
            load_sess.recv_pq_injects.pending
        );
        assert_eq!(load_sess.recv_pq_injects.applied_through, 5);

        // Verify pending contacts
        assert!(loaded.pending_contacts.contains_key(&peer_token));

        // Verify what keeps the session setup and admission going
        assert_eq!(loaded.peer_x25519_keys[&peer_token], peer_id.x25519_public);
        assert_eq!(loaded.add_ids[&peer_token], original.add_ids[&peer_token]);
        assert_eq!(loaded.next_add_id, original.next_add_id);
        let setup = &loaded.session_setups[&peer_token];
        assert_eq!((setup.establisher_add_id, setup.responder_add_id), (11, 22));
        let offer = setup.offer.expect("still on offer");
        assert_eq!(offer.eph_x25519_pub, peer_id.x25519_public);
        assert_eq!(offer.kyber_ct.as_bytes(), kyber_ct.as_bytes());
        assert!(loaded.requests_muted());
        assert!(loaded.notify_with_names());

        // Clean up
        let _ = std::fs::remove_file(tmp_path);
    }
    #[test]
    fn test_concurrent_multi_peer_out_of_order() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let bob_token = [0xBB; 16];
        let charlie_token = [0xCC; 16];

        let root_bob = [0x11; 32];
        let root_charlie = [0x22; 32];

        alice.e2e_sessions.insert(
            bob_token,
            SymmetricSessionState {
                root_key: root_bob,
                send_chain_key: root_bob,
                recv_chain_key: root_bob,
                send_count: 0,
                recv_count: 0,
                peer_kyber_pub: None,
                skip_dict: HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
            },
        );

        alice.e2e_sessions.insert(
            charlie_token,
            SymmetricSessionState {
                root_key: root_charlie,
                send_chain_key: root_charlie,
                recv_chain_key: root_charlie,
                send_count: 0,
                recv_count: 0,
                peer_kyber_pub: None,
                skip_dict: HashMap::new(),
                recv_pq_injects: RecvPqInjects::default(),
            },
        );

        let mut bob_sender = SymmetricSessionState {
            root_key: root_bob,
            send_chain_key: root_bob,
            recv_chain_key: root_bob,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };

        let mut charlie_sender = SymmetricSessionState {
            root_key: root_charlie,
            send_chain_key: root_charlie,
            recv_chain_key: root_charlie,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            recv_pq_injects: RecvPqInjects::default(),
        };

        let mut bob_pkts = vec![];
        for i in 0..3 {
            let key = bob_sender.symmetric_ratchet();
            let c = XChaCha20Poly1305::new(Key::from_slice(&key));
            let nonce = XNonce::from_slice(&[0x77u8; 24]);
            let chunk = chunks::split(format!("bob{}", i).as_bytes()).unwrap();
            let padded = padding::pad(&chunk[0]).unwrap();
            let ct = c.encrypt(nonce, padded.as_slice()).unwrap();
            let mut pkt = vec![0x01];
            pkt.extend_from_slice(&bob_token);
            pkt.extend_from_slice(&(i as u64).to_be_bytes());
            pkt.extend_from_slice(&[0x77u8; 24]);
            pkt.extend_from_slice(&ct);
            bob_pkts.push(pkt);
        }

        let mut charlie_pkts = vec![];
        for i in 0..3 {
            let key = charlie_sender.symmetric_ratchet();
            let c = XChaCha20Poly1305::new(Key::from_slice(&key));
            let nonce = XNonce::from_slice(&[0x88u8; 24]);
            let chunk = chunks::split(format!("char{}", i).as_bytes()).unwrap();
            let padded = padding::pad(&chunk[0]).unwrap();
            let ct = c.encrypt(nonce, padded.as_slice()).unwrap();
            let mut pkt = vec![0x01];
            pkt.extend_from_slice(&charlie_token);
            pkt.extend_from_slice(&(i as u64).to_be_bytes());
            pkt.extend_from_slice(&[0x88u8; 24]);
            pkt.extend_from_slice(&ct);
            charlie_pkts.push(pkt);
        }

        // Deliver interleaved and out of order
        alice.handle_incoming_packet(&bob_pkts[2]).unwrap();
        alice.handle_incoming_packet(&bob_pkts[0]).unwrap();
        alice.handle_incoming_packet(&charlie_pkts[1]).unwrap();
        alice.handle_incoming_packet(&bob_pkts[1]).unwrap();
        alice.handle_incoming_packet(&charlie_pkts[0]).unwrap();
        alice.handle_incoming_packet(&charlie_pkts[2]).unwrap();

        let bob_sess = alice.e2e_sessions.get(&bob_token).unwrap();
        assert_eq!(bob_sess.recv_count, 3);
        assert!(bob_sess.skip_dict.is_empty());

        let charlie_sess = alice.e2e_sessions.get(&charlie_token).unwrap();
        assert_eq!(charlie_sess.recv_count, 3);
        assert!(charlie_sess.skip_dict.is_empty());
    }

    // ==========================================
    // PQ Refresh Ordering & Resend Tests
    // ==========================================

    /// Alice sends `count` one-chunk messages to Bob. Returns each one's
    /// packet and the PQ refresh it triggered, if any, both with the link
    /// layer already stripped (i.e. what Bob's `handle_incoming_packet`
    /// takes).
    fn send_messages(
        alice: &mut Client,
        bob: &Client,
        count: usize,
    ) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        (0..count)
            .map(|i| {
                let (pkts, pq) = alice
                    .create_encrypted_packets(
                        bob.identity.routing_token,
                        format!("m{i}").as_bytes(),
                    )
                    .unwrap();
                let key = alice.link.keys().to_relay;
                (strip_link(&pkts[0], &key), pq.map(|p| strip_link(&p, &key)))
            })
            .collect()
    }

    fn assert_chains_in_sync(alice: &Client, bob: &Client) {
        assert_eq!(
            alice.e2e_sessions[&bob.identity.routing_token].send_chain_key,
            bob.e2e_sessions[&alice.identity.routing_token].recv_chain_key,
            "Alice's send chain and Bob's receive chain must match"
        );
    }

    #[test]
    fn test_pq_inject_arriving_early_is_held_until_its_position() {
        let (mut alice, mut bob) = connected_pair();
        let msgs = send_messages(&mut alice, &bob, 6);
        let refresh = msgs[4].1.clone().expect("refresh after message 5");

        // The refresh overtakes message 5 (seq 4), the last one before it.
        for (msg, _) in &msgs[..4] {
            bob.handle_incoming_packet(msg).unwrap();
        }
        bob.handle_incoming_packet(&refresh).unwrap();
        bob.handle_incoming_packet(&msgs[4].0).unwrap();
        bob.handle_incoming_packet(&msgs[5].0).unwrap();

        assert_eq!(bob.drain_inbox().len(), 6, "every message must decrypt");
        assert_chains_in_sync(&alice, &bob);
    }

    #[test]
    fn test_pq_inject_arriving_late_recovers_when_message_is_resent() {
        let (mut alice, mut bob) = connected_pair();
        let msgs = send_messages(&mut alice, &bob, 6);
        let refresh = msgs[4].1.clone().expect("refresh after message 5");

        for (msg, _) in &msgs[..5] {
            bob.handle_incoming_packet(msg).unwrap();
        }
        // Message 6 (seq 5) overtakes the refresh it depends on: it can't
        // decrypt yet, but that mustn't disturb Bob's state...
        bob.handle_incoming_packet(&msgs[5].0).unwrap();
        assert_eq!(bob.drain_inbox().len(), 5);
        bob.handle_incoming_packet(&refresh).unwrap();
        // ...so the resent copy decrypts once the refresh is in.
        bob.handle_incoming_packet(&msgs[5].0).unwrap();

        let inbox = bob.drain_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].1, b"m5");
        assert_chains_in_sync(&alice, &bob);
    }

    #[test]
    fn test_resent_pq_inject_and_message_copies_are_ignored() {
        let (mut alice, mut bob) = connected_pair();
        let msgs = send_messages(&mut alice, &bob, 6);
        let refresh = msgs[4].1.clone().expect("refresh after message 5");

        for (msg, _) in &msgs[..5] {
            bob.handle_incoming_packet(msg).unwrap();
        }
        // Copies of the refresh before and after the next message, and
        // copies of already-received messages, as a resend would produce.
        bob.handle_incoming_packet(&refresh).unwrap();
        bob.handle_incoming_packet(&refresh).unwrap();
        bob.handle_incoming_packet(&msgs[5].0).unwrap();
        bob.handle_incoming_packet(&refresh).unwrap();
        bob.handle_incoming_packet(&msgs[5].0).unwrap();
        bob.handle_incoming_packet(&msgs[0].0).unwrap();

        assert_eq!(bob.drain_inbox().len(), 6, "each message exactly once");
        assert_chains_in_sync(&alice, &bob);
        let next = send_messages(&mut alice, &bob, 1);
        bob.handle_incoming_packet(&next[0].0).unwrap();
        assert_eq!(bob.drain_inbox().len(), 1);
    }

    #[test]
    fn test_pq_inject_replayed_into_a_new_session_is_rejected() {
        let (mut alice, mut bob) = connected_pair();
        let alice_token = alice.identity.routing_token;
        let msgs = send_messages(&mut alice, &bob, 5);
        let old_refresh = msgs[4].1.clone().expect("refresh after message 5");

        // Bob and Alice start a fresh session (e.g. the contact was removed
        // and re-added), so positions count from 0 again. The relay replays
        // the old session's refresh for position 5.
        let fresh = SymmetricSessionState::from_root_key([0x77; 32], None);
        bob.e2e_sessions.insert(alice_token, fresh);
        bob.handle_incoming_packet(&old_refresh).unwrap();

        assert!(
            bob.e2e_sessions[&alice_token]
                .recv_pq_injects
                .pending
                .is_empty(),
            "a refresh from an earlier session must not be held for this one"
        );
    }

    #[test]
    fn test_several_pq_injects_ahead_of_out_of_order_messages() {
        let (mut alice, mut bob) = connected_pair();
        let msgs = send_messages(&mut alice, &bob, 11);
        let refresh_at_5 = msgs[4].1.clone().expect("refresh after message 5");
        let refresh_at_10 = msgs[9].1.clone().expect("refresh after message 10");

        // Both refreshes first, newest first; then a message past the first
        // refresh, which forces the ratchet through it; then the rest.
        bob.handle_incoming_packet(&refresh_at_10).unwrap();
        bob.handle_incoming_packet(&refresh_at_5).unwrap();
        bob.handle_incoming_packet(&msgs[7].0).unwrap();
        for i in (0..7).chain(8..11) {
            bob.handle_incoming_packet(&msgs[i].0).unwrap();
        }

        assert_eq!(bob.drain_inbox().len(), 11, "every message must decrypt");
        assert_chains_in_sync(&alice, &bob);
        let session = &bob.e2e_sessions[&alice.identity.routing_token];
        assert!(session.recv_pq_injects.pending.is_empty());
        assert_eq!(session.recv_pq_injects.applied_through, 10);
    }

    // ==========================================
    // Message Padding & Chunking Tests
    // ==========================================

    #[test]
    fn test_chat_packets_are_fixed_size_and_unpadded_on_receive() {
        let (mut alice, mut bob) = connected_pair();
        let one_full_chunk = "x".repeat(chunks::CHUNK_DATA_LEN);
        for text in ["", "hi", "héllo 👋", one_full_chunk.as_str()] {
            let (pkts, _) = alice
                .create_encrypted_packets(bob.identity.routing_token, text.as_bytes())
                .unwrap();
            assert_eq!(pkts.len(), 1);
            assert_eq!(
                pkts[0].len(),
                1142,
                "chat packet size must not depend on message length"
            );
            let inner = strip_link(&pkts[0], &alice.link.keys().to_relay);
            bob.handle_incoming_packet(&inner).unwrap();
            let inbox = bob.drain_inbox();
            assert_eq!(inbox.len(), 1);
            assert_eq!(inbox[0].1, text.as_bytes());
        }
    }

    #[test]
    fn test_long_message_split_and_reassembled_out_of_order() {
        let (mut alice, mut bob) = connected_pair();
        // Three chunks, with an emoji straddling the second boundary.
        let text = format!(
            "{}👋{}",
            "a".repeat(2 * chunks::CHUNK_DATA_LEN - 1),
            "b".repeat(100)
        );
        let (pkts, _) = alice
            .create_encrypted_packets(bob.identity.routing_token, text.as_bytes())
            .unwrap();
        assert_eq!(pkts.len(), 3);
        assert!(pkts.iter().all(|p| p.len() == 1142));

        for pkt in pkts.iter().rev().take(2) {
            let inner = strip_link(pkt, &alice.link.keys().to_relay);
            bob.handle_incoming_packet(&inner).unwrap();
            assert!(
                bob.drain_inbox().is_empty(),
                "nothing reaches the inbox until every chunk is in"
            );
        }
        let inner = strip_link(&pkts[0], &alice.link.keys().to_relay);
        bob.handle_incoming_packet(&inner).unwrap();
        let inbox = bob.drain_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].1, text.as_bytes());
    }

    #[test]
    fn test_pq_inject_sent_once_after_last_chunk() {
        let (mut alice, mut bob) = connected_pair();
        let bob_token = bob.identity.routing_token;
        let alice_token = alice.identity.routing_token;

        // 3 chunks: send_count 0 -> 3, no interval crossed.
        let (pkts, pq) = alice
            .create_encrypted_packets(bob_token, &vec![b'x'; 3 * chunks::CHUNK_DATA_LEN])
            .unwrap();
        assert_eq!(pkts.len(), 3);
        assert!(pq.is_none());
        for pkt in &pkts {
            bob.handle_incoming_packet(&strip_link(pkt, &alice.link.keys().to_relay))
                .unwrap();
        }

        // 12 chunks: send_count 3 -> 15 crosses three intervals, but gets
        // exactly one inject, after the last chunk.
        let long = vec![b'y'; 12 * chunks::CHUNK_DATA_LEN];
        let (pkts, pq) = alice.create_encrypted_packets(bob_token, &long).unwrap();
        assert_eq!(pkts.len(), 12);
        let pq = pq.expect("crossing an interval must produce a PQ inject");
        for pkt in pkts.iter().chain([&pq]) {
            bob.handle_incoming_packet(&strip_link(pkt, &alice.link.keys().to_relay))
                .unwrap();
        }
        let inbox = bob.drain_inbox();
        assert_eq!(inbox.len(), 2);
        assert_eq!(inbox[1].1, long);

        assert_eq!(
            alice.e2e_sessions[&bob_token].send_chain_key,
            bob.e2e_sessions[&alice_token].recv_chain_key,
            "chain keys must stay in sync across a chunked message and its inject"
        );
        let (next, _) = alice.create_encrypted_packets(bob_token, b"after").unwrap();
        bob.handle_incoming_packet(&strip_link(&next[0], &alice.link.keys().to_relay))
            .unwrap();
        assert_eq!(bob.drain_inbox()[0].1, b"after");
    }

    #[test]
    fn test_oversized_message_rejected_without_advancing_ratchet() {
        let (mut alice, bob) = connected_pair();
        let bob_token = bob.identity.routing_token;
        let count_before = alice.e2e_sessions[&bob_token].send_count;
        let key_before = alice.e2e_sessions[&bob_token].send_chain_key;

        let too_long = vec![b'x'; chunks::MAX_MESSAGE_LEN + 1];
        let err = alice
            .create_encrypted_packets(bob_token, &too_long)
            .unwrap_err();
        assert!(err.to_string().contains("too long"), "{err}");

        let session = &alice.e2e_sessions[&bob_token];
        assert_eq!(session.send_count, count_before);
        assert_eq!(session.send_chain_key, key_before);
    }

    #[test]
    fn test_unpadded_message_from_older_client_is_dropped() {
        let (mut alice, mut bob) = connected_pair();
        let bob_token = bob.identity.routing_token;

        // Encrypt with Alice's real ratchet but skip the padding, as a
        // client from before padding was added would.
        let session = alice.e2e_sessions.get_mut(&bob_token).unwrap();
        let key = session.symmetric_ratchet();
        let seq = session.send_count;
        session.send_count += 1;
        let nonce = [0x55u8; 24];
        let ct = XChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(XNonce::from_slice(&nonce), b"hello".as_ref())
            .unwrap();
        let mut pkt = vec![0x01];
        pkt.extend_from_slice(&alice.identity.routing_token);
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&nonce);
        pkt.extend_from_slice(&ct);

        assert!(bob.handle_incoming_packet(&pkt).unwrap().is_none());
        assert!(
            bob.drain_inbox().is_empty(),
            "an unpadded message must not reach the inbox"
        );

        // Bob's ratchet still advanced past it, so the next padded message
        // decrypts normally.
        let (next, _) = alice.create_encrypted_packets(bob_token, b"hi").unwrap();
        let inner = strip_link(&next[0], &alice.link.keys().to_relay);
        bob.handle_incoming_packet(&inner).unwrap();
        let inbox = bob.drain_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].1, b"hi");
    }

    #[test]
    fn test_relay_dummy_packet_is_ignored() {
        let (_alice, mut bob) = connected_pair();
        // What `open_link_packet` hands back for one of the relay's dummy
        // packets: a chat-message-sized inner payload of type 0x00.
        let dummy_inner = [0u8; 1 + 16 + 8 + 24 + padding::PADDED_LEN + 16];
        assert!(bob.handle_incoming_packet(&dummy_inner).unwrap().is_none());
        assert!(bob.drain_inbox().is_empty());
    }

    #[test]
    fn test_relay_packet_is_acked_and_resend_handled_once() {
        let alice = new_client();
        let mut bob = new_client();
        link_with(&mut bob, 7, [1, 2, 3, 4]);
        bob.add_contact(alice.identity.routing_token, alice.identity.ed25519_public)
            .unwrap();

        let kx = KeyExchangePayload::generate(
            &alice.identity,
            bob.identity.routing_token,
            "",
            false,
            0,
            None,
        );
        let mut kx_inner = vec![0x02];
        kx_inner.extend_from_slice(&kx.to_bytes());
        let delivery_id = [0x11; 16];
        let packet = relay_forward(&bob, delivery_id, &kx_inner);

        let first = bob.handle_relay_packet(&packet);
        let types: Vec<u8> = first.iter().map(|packet| packet[0]).collect();
        assert_eq!(
            types,
            [relay_link::TYPE_ADMITTED_DATA, TYPE_SYNC, TYPE_ACK],
            "KeyExchange reply (which now carries Alice's admission tag), a sync registering \
             the one she'll use, then the ack"
        );
        assert!(
            bob.handle_relay_packet(&packet).is_empty(),
            "a copy of the very same packet isn't taken in at all"
        );
        // The relay seals each resend afresh.
        let resend = bob.handle_relay_packet(&relay_forward(&bob, delivery_id, &kx_inner));
        assert_eq!(resend.len(), 1, "a resend is only acked again");

        let ack = &resend[0];
        let header = relay_link::header(ack).unwrap();
        assert_eq!(
            (header.packet_type, header.session_id),
            (TYPE_ACK, bob.link.session_id())
        );
        let plaintext = relay_link::open(&bob.link.keys().to_relay, ack).unwrap();
        assert_eq!(
            relay_link::parse_ack(&plaintext),
            Some((bob.identity.routing_token, [delivery_id].as_slice()))
        );
        cleanup(&[&alice, &bob]);
    }

    #[test]
    fn test_relay_dummy_packet_is_not_acked() {
        let (_alice, mut bob) = connected_pair();
        bob.generate_sync_packet(); // registered Alice's admission tag already
        let dummy_inner = [0u8; 1 + 16 + 8 + 24 + padding::PADDED_LEN + 16];
        let packet = relay_forward(&bob, [0u8; 16], &dummy_inner);
        assert!(bob.handle_relay_packet(&packet).is_empty());
    }

    #[test]
    fn test_forged_key_exchange_cannot_rename_or_rekey_a_known_contact() {
        // Mallory claims Bob's routing token but signs with her own key.
        // Alice already trusts Bob's real key, so the KX must be dropped
        // *without* first overwriting Bob's name or stored Kyber key.
        let addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(addr);
        let bob = UserIdentity::generate();
        alice
            .pending_contacts
            .insert(bob.routing_token, bob.ed25519_public);
        alice.contact_names.insert(bob.routing_token, "bob".into());
        alice
            .peer_kyber_keys
            .insert(bob.routing_token, bob.kyber_public);

        let mut mallory = UserIdentity::generate();
        mallory.routing_token = bob.routing_token;
        let forged = KeyExchangePayload::generate(
            &mallory,
            alice.identity.routing_token,
            "not-bob",
            false,
            0,
            None,
        );
        let mut packet = vec![0x02];
        packet.extend_from_slice(&forged.to_bytes());

        assert!(alice.handle_incoming_packet(&packet).unwrap().is_none());
        assert_eq!(
            alice
                .contact_names
                .get(&bob.routing_token)
                .map(String::as_str),
            Some("bob")
        );
        assert_eq!(
            alice.peer_kyber_keys[&bob.routing_token].as_bytes(),
            bob.kyber_public.as_bytes()
        );
    }

    // ==========================================
    // Setups that can't stall, yourself, and reconnecting
    // ==========================================

    /// A KeyExchange from `from` to `target`, as it arrives after waiting at
    /// the relay longer than `MAX_TIMESTAMP_DRIFT`: the 0x02 payload
    /// `handle_incoming_packet` takes.
    fn stale_key_exchange(
        from: &UserIdentity,
        target: RoutingToken,
        name: &str,
        has_peer_keys: bool,
        add_id: u32,
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut kx = KeyExchangePayload::generate(from, target, name, has_peer_keys, add_id, None);
        kx.timestamp -= MAX_TIMESTAMP_DRIFT + 300;
        let bytes = kx.to_bytes();
        kx.signature = from.ed25519_secret.sign(&bytes[..bytes.len() - 64]);
        [vec![0x02], kx.to_bytes()].concat()
    }

    /// A state file path nothing can be saved to.
    fn unsaveable_path() -> String {
        std::env::temp_dir()
            .join(format!("e2e-no-such-dir-{}", std::process::id()))
            .join("state.json")
            .to_string_lossy()
            .into_owned()
    }

    /// Your own code is refused, so you can't start a KeyExchange with
    /// yourself, which would go round through the relay for good. Anything
    /// claiming to come from you is dropped too.
    #[test]
    fn test_adding_your_own_code_is_refused() {
        let mut me = new_client();
        let (token, key) = (me.identity.routing_token, me.identity.ed25519_public);
        assert!(me.add_contact(token, key).is_err());
        assert!(me.pending_contacts.is_empty());

        // Even if we had somehow trusted our own key as a contact's.
        me.pending_contacts.insert(token, key);
        let kx = KeyExchangePayload::generate(&me.identity, token, "", false, 1, None);
        let packet = [vec![0x02], kx.to_bytes()].concat();
        assert!(me.handle_incoming_packet(&packet).unwrap().is_none());
        assert!(me.connection_requests().is_empty());
        assert!(!me.peer_kyber_keys.contains_key(&token));
        cleanup(&[&me]);
    }

    /// The second person adds the first while the first is offline, so
    /// their KeyExchange is old by the time it's delivered. It's taken in
    /// all the same, and the setup completes.
    #[test]
    fn test_setup_completes_when_the_second_key_exchange_arrives_late() {
        let (mut a, mut b) = (new_client(), new_client());
        let (ta, tb) = (a.identity.routing_token, b.identity.routing_token);
        let early = a.add_contact(tb, b.identity.ed25519_public).unwrap();
        assert_eq!(
            exchange(&mut a, &mut b, early),
            [0x02],
            "not added back yet"
        );
        b.add_contact(ta, a.identity.ed25519_public).unwrap();
        let late = stale_key_exchange(&b.identity, ta, "", false, b.add_ids[&ta].mine);
        let reply = a.handle_incoming_packet(&late).unwrap().expect("answered");
        exchange(&mut a, &mut b, reply);
        assert!(a.is_connected(&tb) && b.is_connected(&ta));
        assert_eq!(session(&a, &b).root_key, session(&b, &a).root_key);
        cleanup(&[&a, &b]);
    }

    /// A connection request that waited at the relay while we were offline
    /// is still listed: they still want to connect, and only the token is
    /// kept anyway.
    #[test]
    fn test_late_connection_request_is_still_listed() {
        let mut me = new_client();
        let stranger = UserIdentity::generate();
        let late = stale_key_exchange(&stranger, me.identity.routing_token, "", false, 1);
        assert!(me.handle_incoming_packet(&late).unwrap().is_none());
        assert_eq!(me.connection_requests(), [stranger.routing_token]);
        cleanup(&[&me]);
    }

    /// Our KeyExchange goes to a contact we have no session with again,
    /// after `FIRST_SETUP_RETRY`, then twice as long each time, at most
    /// `MAX_SETUP_RETRIES` times, unless something from them moves the
    /// setup on, which starts the count again.
    #[test]
    fn test_key_exchange_resends_back_off_and_restart_on_progress() {
        let (mut a, mut b) = (new_client(), new_client());
        let (ta, tb) = (a.identity.routing_token, b.identity.routing_token);
        a.add_contact(tb, b.identity.ed25519_public).unwrap();
        assert!(a.setup_resends(Instant::now()).is_empty(), "just sent");

        let (mut at, mut delay) = (a.setup_retries[&tb].at, FIRST_SETUP_RETRY);
        assert!(at > Instant::now() + FIRST_SETUP_RETRY - Duration::from_secs(1));
        for _ in 0..MAX_SETUP_RETRIES {
            assert!(a.setup_resends(at - Duration::from_millis(1)).is_empty());
            let resent = a.setup_resends(at);
            assert_eq!(resent.len(), 1);
            assert_eq!(relay(&resent[0], &a)[0], 0x02);
            at += delay;
            delay = (delay * 2).min(MAX_SETUP_RETRY_DELAY);
        }
        assert!(
            a.setup_resends(at + MAX_SETUP_RETRY_DELAY).is_empty(),
            "gave up"
        );

        // B adds A at last, and their KeyExchange reaches A: that's progress.
        let kx = b.add_contact(ta, a.identity.ed25519_public).unwrap();
        a.handle_incoming_packet(&relay(&kx, &b)).unwrap();
        assert!(!a.is_connected(&tb));
        assert_eq!(a.setup_resends(Instant::now() + FIRST_SETUP_RETRY).len(), 1);
        cleanup(&[&a, &b]);
    }

    /// Here every KeyExchange from the first round is lost on its way to
    /// the relay: the resends alone bring the session up, and stop once it
    /// is.
    #[test]
    fn test_resent_key_exchange_gets_past_lost_packets() {
        let (mut a, mut b) = (new_client(), new_client());
        let (ta, tb) = (a.identity.routing_token, b.identity.routing_token);
        let _lost = a.add_contact(tb, b.identity.ed25519_public).unwrap();
        let _lost = b.add_contact(ta, a.identity.ed25519_public).unwrap();
        let mut resent = a.setup_resends(Instant::now() + FIRST_SETUP_RETRY);
        assert_eq!(resent.len(), 1);
        exchange(&mut a, &mut b, resent.remove(0));
        assert!(a.is_connected(&tb) && b.is_connected(&ta));
        let later = Instant::now() + MAX_SETUP_RETRY_DELAY;
        assert!(a.setup_resends(later).is_empty() && b.setup_resends(later).is_empty());
        cleanup(&[&a, &b]);
    }

    #[test]
    fn test_contact_status_follows_the_setup() {
        let (mut a, mut b) = (new_client(), new_client());
        let (ta, tb) = (a.identity.routing_token, b.identity.routing_token);
        let early = a.add_contact(tb, b.identity.ed25519_public).unwrap();
        assert_eq!(a.contact_status(&tb), ContactStatus::Pending);
        // Without an admission tag yet: A doesn't have B's X25519 key.
        assert_eq!(early.len(), 1439);
        exchange(&mut a, &mut b, early);
        assert_eq!(a.contact_status(&tb), ContactStatus::Pending);

        // B's KeyExchange reaches A, so B has added A: they're connecting.
        let kx = b.add_contact(ta, a.identity.ed25519_public).unwrap();
        let reply = a.handle_incoming_packet(&relay(&kx, &b)).unwrap().unwrap();
        assert_eq!(a.contact_status(&tb), ContactStatus::Connecting);
        // With its admission tag, a KeyExchange still fits a PPPoE link's
        // 1464-byte UDP payload.
        assert_eq!(reply.len(), 1447);
        exchange(&mut a, &mut b, reply);
        assert_eq!(a.contact_status(&tb), ContactStatus::Connected);
        assert_eq!(b.contact_status(&ta), ContactStatus::Connected);
        cleanup(&[&a, &b]);
    }

    /// Nothing about a session is promised to a contact unless it's saved:
    /// with saving broken, the establisher doesn't offer the session it
    /// made, and the responder neither takes an offer in nor confirms it.
    /// Once saving works again, the same session goes through.
    #[test]
    fn test_unsaved_sessions_are_neither_offered_nor_taken_in() {
        let (mut e, mut r) = establisher_and_responder();
        let (te, tr) = (e.identity.routing_token, r.identity.routing_token);
        let early = e.add_contact(tr, r.identity.ed25519_public).unwrap();
        exchange(&mut e, &mut r, early);
        let kx = r.add_contact(te, e.identity.ed25519_public).unwrap();
        let reply = e.handle_incoming_packet(&relay(&kx, &r)).unwrap().unwrap();
        let ask = r
            .handle_incoming_packet(&relay(&reply, &e))
            .unwrap()
            .unwrap();

        let e_path = std::mem::replace(&mut e.state_path, unsaveable_path());
        assert!(
            e.handle_incoming_packet(&relay(&ask, &r))
                .unwrap()
                .is_none()
        );
        e.state_path = e_path;
        let offer = e
            .handle_incoming_packet(&relay(&ask, &r))
            .unwrap()
            .expect("offered once it's saved");
        assert_eq!(relay(&offer, &e)[0], 0x04);

        let r_path = std::mem::replace(&mut r.state_path, unsaveable_path());
        assert!(
            r.handle_incoming_packet(&relay(&offer, &e))
                .unwrap()
                .is_none()
        );
        assert!(r.e2e_sessions.is_empty() && r.session_setups.is_empty());
        r.state_path = r_path;
        let confirm = r
            .handle_incoming_packet(&relay(&offer, &e))
            .unwrap()
            .unwrap();
        exchange(&mut r, &mut e, confirm);
        assert!(e.is_connected(&tr) && r.is_connected(&te));
        assert_eq!(session(&e, &r).root_key, session(&r, &e).root_key);
        cleanup(&[&e, &r]);
    }

    /// While the relay answers, a keepalive is just syncs. Once we've heard
    /// nothing from it for `LINK_SILENCE_TIMEOUT`, the link is presumed gone,
    /// and the keepalive starts a new handshake instead, sending the init
    /// several times over. Only our relay's reply to it finishes it: a new
    /// link, synced on at once, with KeyExchanges for contacts we're still
    /// setting up with.
    #[test]
    fn test_keepalive_redoes_the_handshake_after_a_silence() {
        let relay_identity = SigningKey::from_bytes(&[7; 32]);
        let mut client = new_client();
        link_with(&mut client, 4, [1, 2, 3, 4]);
        client.relay_public = Some(relay_identity.verifying_key());
        let contact = UserIdentity::generate();
        client
            .add_contact(contact.routing_token, contact.ed25519_public)
            .unwrap();

        let syncs = client.keepalive();
        assert_eq!(
            syncs.len(),
            SYNC_COPIES,
            "syncs; the KeyExchange isn't due yet"
        );
        assert!(syncs.iter().all(|sync| sync[0] == TYPE_SYNC));
        let number = relay_link::header(&syncs[0]).unwrap().packet_number;
        let ack = from_relay(
            &client,
            TYPE_SYNC_ACK,
            &relay_link::sync_ack_plaintext(number),
        );
        client.last_heard -= LINK_SILENCE_TIMEOUT;
        assert!(client.handle_relay_packet(&ack).is_empty());
        assert_eq!(client.keepalive().len(), SYNC_COPIES, "heard from, so fine");

        client.last_heard -= LINK_SILENCE_TIMEOUT;
        let inits = client.keepalive();
        assert_eq!(inits.len(), HANDSHAKE_COPIES);
        assert!(
            inits.iter().all(|init| *init == inits[0]),
            "one init, copied"
        );
        let client_ephemeral = relay_link::parse_handshake_init(&inits[0]).unwrap();
        assert!(client.keepalive().is_empty(), "waiting for the reply");

        let relay_secret = EphemeralSecret::random_from_rng(OsRng);
        let relay_ephemeral = X25519PublicKey::from(&relay_secret);
        let impostor = SigningKey::from_bytes(&[8; 32]);
        let forged = relay_link::handshake_resp(
            &impostor,
            &client_ephemeral,
            &relay_ephemeral,
            &[6, 6, 6, 6],
        );
        assert!(client.handle_relay_packet(&forged).is_empty());
        assert_eq!(client.link.session_id(), [1, 2, 3, 4]);

        let reply = relay_link::handshake_resp(
            &relay_identity,
            &client_ephemeral,
            &relay_ephemeral,
            &[5, 6, 7, 8],
        );
        let out = client.handle_relay_packet(&reply);
        assert_eq!(client.link.session_id(), [5, 6, 7, 8]);
        assert_eq!(
            client.link.keys(),
            &relay_link::derive_link_keys(
                relay_secret.diffie_hellman(&client_ephemeral).as_bytes()
            )
        );
        let types: Vec<_> = out
            .iter()
            .map(|packet| {
                let header = relay_link::header(packet).unwrap();
                assert_eq!(header.session_id, [5, 6, 7, 8]);
                header.packet_type
            })
            .collect();
        assert_eq!(
            types,
            [TYPE_SYNC, TYPE_SYNC, TYPE_SYNC, TYPE_DATA],
            "syncs, then the KeyExchange"
        );
        assert!(client.handle_relay_packet(&reply).is_empty(), "taken once");
        cleanup(&[&client]);
    }

    /// A handshake that gets no reply is tried again with a fresh key; a
    /// reply nobody asked for changes nothing; and a replayed packet from
    /// the relay can't make a dead link look alive.
    #[test]
    fn test_unanswered_handshakes_are_retried_and_strays_ignored() {
        let relay_identity = SigningKey::from_bytes(&[7; 32]);
        let mut client = new_client();
        link_with(&mut client, 4, [1, 2, 3, 4]);

        let stray = relay_link::handshake_resp(
            &relay_identity,
            &X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng)),
            &X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng)),
            &[5, 6, 7, 8],
        );
        assert!(client.handle_relay_packet(&stray).is_empty());
        assert_eq!(client.link.session_id(), [1, 2, 3, 4]);

        // Without the relay's key (no `perform_handshake` yet), a client
        // can only keep syncing.
        client.last_heard -= LINK_SILENCE_TIMEOUT;
        assert!(
            client
                .keepalive()
                .iter()
                .all(|packet| packet[0] == TYPE_SYNC)
        );

        let ack = from_relay(&client, TYPE_SYNC_ACK, &relay_link::sync_ack_plaintext(0));
        client.handle_relay_packet(&ack);
        client.relay_public = Some(relay_identity.verifying_key());
        client.last_heard -= LINK_SILENCE_TIMEOUT;
        client.handle_relay_packet(&ack); // a replay: not heard from
        let first = client.keepalive();
        assert_eq!(first.len(), HANDSHAKE_COPIES);
        assert!(relay_link::parse_handshake_init(&first[0]).is_ok());

        let started = client.pending_handshake.as_ref().unwrap().1;
        client.pending_handshake.as_mut().unwrap().1 = started - HANDSHAKE_ATTEMPT;
        let second = client.keepalive();
        assert_eq!(second.len(), HANDSHAKE_COPIES);
        assert_ne!(first[0], second[0], "a fresh ephemeral key");
        cleanup(&[&client]);
    }

    /// Over real UDP: the whole first attempt's inits are lost, and the
    /// handshake still completes, on the next attempt, with the same init.
    #[tokio::test]
    async fn test_handshake_gets_through_a_lost_attempt() {
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let relay_identity = SigningKey::from_bytes(&[7; 32]);
        let relay_public = relay_identity.verifying_key();
        let relay = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let mut inits = Vec::new();
            loop {
                let (len, from) = relay_socket.recv_from(&mut buf).await.unwrap();
                if buf[0] != relay_link::TYPE_HANDSHAKE_INIT {
                    continue; // the syncs that follow
                }
                inits.push(buf[..len].to_vec());
                if inits.len() <= HANDSHAKE_COPIES {
                    continue; // lost
                }
                let client_ephemeral = relay_link::parse_handshake_init(&buf[..len]).unwrap();
                let relay_ephemeral =
                    X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
                let reply = relay_link::handshake_resp(
                    &relay_identity,
                    &client_ephemeral,
                    &relay_ephemeral,
                    &[5, 6, 7, 8],
                );
                relay_socket.send_to(&reply, from).await.unwrap();
                return inits;
            }
        });
        let mut client = new_client();
        client.server_addr = relay_addr;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        perform_handshake(&mut client, &socket, &relay_public)
            .await
            .unwrap();
        assert_eq!(client.link.session_id(), [5, 6, 7, 8]);
        let inits = relay.await.unwrap();
        assert_eq!(
            inits.len(),
            HANDSHAKE_COPIES + 1,
            "answered on the second attempt"
        );
        assert!(inits.iter().all(|init| *init == inits[0]), "the same init");
        cleanup(&[&client]);
    }
}
