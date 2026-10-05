use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pqcrypto_kyber::kyber768::*;
use pqcrypto_traits::kem::SharedSecret as _;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub mod packets;
use packets::*;
mod history;
mod storage;
mod transport;
pub use history::{ChatHistory, StoredMessage};
use std::collections::HashSet;
pub use storage::{ClientStateDto, IdentityStateStore};
pub use transport::{BurstSender, MAX_FEC_MESSAGE_LEN, send_burst};
#[cfg(test)]
mod test_support;

type HmacSha256 = Hmac<Sha256>;
pub type SessionId = [u8; 4];
pub type RoutingToken = [u8; 16];

// PQ injection interval: inject fresh Kyber entropy every N messages
const PQ_INJECT_INTERVAL: u64 = 5;

// Maximum number of skipped message keys to retain
const MAX_SKIP_DICT_SIZE: usize = 500;

/// Furthest ahead of the receive chain a message (or a PQ inject's
/// position) may be before it's dropped as bogus.
const MAX_SKIP: u64 = 100;

// Domain-separation salt for HKDF derivations
const HKDF_SALT: &[u8] = b"e2e-messenger-v1";

// Maximum timestamp drift allowed (seconds)
const MAX_TIMESTAMP_DRIFT: u64 = 300;

// How long `perform_handshake` waits for the relay's reply
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

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

// Argon2id parameters for every login secret derived below (OWASP's
// baseline recommendation for Argon2id: ~19 MiB, 2 passes, single-threaded —
// generous enough for a login gate, cheap enough not to make every app
// launch feel slow). Stored alongside the salt in `passcode.hash` so tuning
// these later doesn't invalidate identities created under the old values.
const ARGON2_M_COST_KIB: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
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

// Request Types for Server
const TYPE_HANDSHAKE_INIT: u8 = 0;
pub const TYPE_DATA: u8 = 1;
const TYPE_HANDSHAKE_RESP: u8 = 2;

pub struct UserIdentity {
    pub routing_token: RoutingToken,
    pub ed25519_secret: SigningKey,
    pub ed25519_public: VerifyingKey,
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519PublicKey,
    pub kyber_public: PublicKey,
    pub kyber_secret: SecretKey,
}

impl UserIdentity {
    pub fn generate() -> Self {
        let mut routing_token = [0u8; 16];
        OsRng.fill_bytes(&mut routing_token);
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let ed25519_secret = SigningKey::from_bytes(&bytes);
        let ed25519_public = ed25519_secret.verifying_key();
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let (kyber_public, kyber_secret) = keypair();
        Self {
            routing_token,
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
    pub pq_inject_replay_cache: HashSet<[u8; 64]>,
    /// PQ secrets received ahead of their chain position (`PQInjectPayload::seq`),
    /// keyed by it. Always `> recv_count`: one at `recv_count` is mixed in
    /// as soon as the chain gets there — see `accept_pq_inject`.
    pub pending_pq: BTreeMap<u64, Vec<u8>>,
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
            pq_inject_replay_cache: HashSet::new(),
            pending_pq: BTreeMap::new(),
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

        if seq_no - self.recv_count > MAX_SKIP {
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

        let mut msg_key = [0u8; 32];
        for s in self.recv_count..=seq_no {
            // Any PQ inject already received for a position on the way gets
            // mixed in exactly where the sender mixed it.
            if let Some(secret) = self.pending_pq.get(&s) {
                mix_pq_secret(&mut test_chain, secret);
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
            self.pending_pq.retain(|&s, _| s > seq_no);
            self.apply_due_pq_inject();
            Some(pt)
        } else {
            None
        }
    }

    /// Take in a verified PQ inject's secret for chain position `seq`: mixed
    /// into the receive chain now if that's where the chain is, or held until
    /// it gets there. `false` for a position already passed or already held
    /// (a replay), or further ahead than any message could be (which also
    /// bounds how many are held).
    pub fn accept_pq_inject(&mut self, seq: u64, pq_secret_bytes: &[u8]) -> bool {
        if seq < self.recv_count
            || seq - self.recv_count > MAX_SKIP + 1
            || self.pending_pq.contains_key(&seq)
        {
            return false;
        }
        self.pending_pq.insert(seq, pq_secret_bytes.to_vec());
        self.apply_due_pq_inject();
        true
    }

    /// Mix in the held PQ inject for `recv_count`, if any, so `recv_chain_key`
    /// always matches the sender's chain key at that position.
    fn apply_due_pq_inject(&mut self) {
        if let Some(secret) = self.pending_pq.remove(&self.recv_count) {
            mix_pq_secret(&mut self.recv_chain_key, &secret);
        }
    }

    /// Mix fresh PQ shared secret into the send chain key via HKDF (called by sender)
    pub fn inject_pq_secret_send(&mut self, pq_secret_bytes: &[u8]) {
        mix_pq_secret(&mut self.send_chain_key, pq_secret_bytes);
    }
}

pub struct Client {
    pub identity: UserIdentity,
    pub server_addr: SocketAddr,
    pub link_master_key: [u8; 32],
    pub session_id: SessionId,
    pub e2e_sessions: HashMap<RoutingToken, SymmetricSessionState>,
    pub pending_contacts: HashMap<RoutingToken, VerifyingKey>,
    pub peer_kyber_keys: HashMap<RoutingToken, PublicKey>,
    pub seen_session_keys: HashSet<[u8; 32]>,
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
    /// Last time we heard *anything* authenticated from this peer — a real
    /// chat message or a presence ping (see `PresencePayload`), both update
    /// this. Front ends use it to show an online/offline marker. Like
    /// `inbox`, this is live local state, not persisted: it should always
    /// start empty ("unknown/offline") on relaunch rather than showing a
    /// stale "online" from a previous run.
    pub last_seen: HashMap<RoutingToken, Instant>,
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
    /// FEC receive state: half-rebuilt symbol bursts (0x07) and messages
    /// parked until the PQ inject they depend on arrives — see
    /// `transport`. Transient, like `inbox`: never persisted.
    pub(crate) fec_rx: transport::FecReceiver,
}

impl Client {
    pub fn new(server_addr: SocketAddr) -> Self {
        let identity = UserIdentity::generate();
        let mut session_id = [0u8; 4];
        OsRng.fill_bytes(&mut session_id);
        Self {
            identity,
            server_addr,
            link_master_key: [0u8; 32],
            session_id,
            e2e_sessions: HashMap::new(),
            pending_contacts: HashMap::new(),
            peer_kyber_keys: HashMap::new(),
            seen_session_keys: HashSet::new(),
            state_path: state_file_path(),
            local_name: String::new(),
            contact_names: HashMap::new(),
            inbox: Vec::new(),
            last_seen: HashMap::new(),
            history: None,
            identity_store: None,
            last_recorded_id: None,
            fec_rx: Default::default(),
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
    /// established session, its Kyber key, learned display name, and
    /// presence state, then persists the change. This is the *local*
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
        self.peer_kyber_keys.remove(&token);
        self.contact_names.remove(&token);
        self.last_seen.remove(&token);
        self.save();
        if let Some(history) = &self.history
            && let Err(e) = history.delete_contact(token)
        {
            tracing::error!("Failed to delete local chat history for contact: {}", e);
        }
    }

    /// True if `token` has sent us a chat message or presence ping within
    /// the last `freshness` window. A local liveness heuristic for the UI
    /// only — not part of the protocol's trust model.
    pub fn is_online(&self, token: &RoutingToken, freshness: Duration) -> bool {
        self.last_seen
            .get(token)
            .is_some_and(|seen| seen.elapsed() < freshness)
    }

    /// Build a signed presence ping for `target_token` (see
    /// `PresencePayload`) and link-encrypt it for the relay, the same way
    /// `create_encrypted_packet` does for a chat message. Deliberately
    /// outside the E2E double ratchet — see the doc comment on
    /// `PresencePayload` for why.
    pub fn generate_presence_packet(&self, target_token: RoutingToken) -> Vec<u8> {
        let payload = PresencePayload::generate(&self.identity, target_token);
        let mut inner = vec![0x06];
        inner.extend_from_slice(&payload.to_bytes());
        self.wrap_link_encryption(target_token, &inner)
    }

    /// Persist identity/session state to `identity_store` if one is
    /// attached (the SQLCipher-encrypted path), otherwise fall back to the
    /// legacy plaintext `client_state.json` at `state_path` — mirrors how
    /// `record_message` treats `history` as optional. Failures are logged,
    /// not propagated, same as `record_message`.
    pub fn save(&self) {
        let result = match &self.identity_store {
            Some(store) => store.save(self),
            None => ClientStateDto::save(self, &self.state_path),
        };
        if let Err(e) = result {
            tracing::error!("Failed to save state: {}", e);
        }
    }

    pub fn generate_handshake_packet(&self) -> (EphemeralSecret, Vec<u8>) {
        use ed25519_dalek::Signer;
        let client_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_ephemeral_public = X25519PublicKey::from(&client_ephemeral_secret);
        // Sign the ephemeral X25519 public key with our Ed25519 identity
        let signature = self
            .identity
            .ed25519_secret
            .sign(client_ephemeral_public.as_bytes());
        let mut packet = vec![TYPE_HANDSHAKE_INIT];
        packet.extend_from_slice(&self.session_id);
        packet.extend_from_slice(client_ephemeral_public.as_bytes());
        packet.extend_from_slice(self.identity.ed25519_public.as_bytes());
        packet.extend_from_slice(&signature.to_bytes());
        (client_ephemeral_secret, packet)
    }

    pub fn complete_handshake(
        &mut self,
        client_secret: EphemeralSecret,
        server_ed25519_pub: &VerifyingKey,
        response: &[u8],
    ) -> Result<()> {
        if response.len() < 1 + 4 + 32 + 64 || response[0] != TYPE_HANDSHAKE_RESP {
            return Err(anyhow!("Invalid handshake response"));
        }
        let mut server_eph_pub_bytes = [0u8; 32];
        server_eph_pub_bytes.copy_from_slice(&response[5..37]);
        let server_eph_pub = X25519PublicKey::from(server_eph_pub_bytes);

        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(&response[37..101]);
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        let client_pub = X25519PublicKey::from(&client_secret);
        let mut msg = Vec::new();
        msg.extend_from_slice(client_pub.as_bytes());
        msg.extend_from_slice(server_eph_pub.as_bytes());

        server_ed25519_pub.verify(&msg, &signature)?;

        let shared_secret = client_secret.diffie_hellman(&server_eph_pub);
        Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes())
            .expand(b"wireguard-lite-link", &mut self.link_master_key)
            .unwrap();
        Ok(())
    }

    /// Tells the relay which routing token lives at our current address:
    /// just our own token, link-encrypted, with no inner payload.
    pub fn generate_sync_packet(&self) -> Vec<u8> {
        self.wrap_link_encryption(self.identity.routing_token, &[])
    }

    fn wrap_link_encryption(&self, target_token: RoutingToken, inner_payload: &[u8]) -> Vec<u8> {
        let mut raw_udp_payload = Vec::new();
        raw_udp_payload.extend_from_slice(&target_token);
        raw_udp_payload.extend_from_slice(inner_payload);

        let link_cipher = XChaCha20Poly1305::new(Key::from_slice(&self.link_master_key));
        let mut link_nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut link_nonce_bytes);
        let link_nonce = XNonce::from_slice(&link_nonce_bytes);
        let link_ciphertext = link_cipher
            .encrypt(link_nonce, raw_udp_payload.as_ref())
            .unwrap();

        let mut final_packet = vec![TYPE_DATA];
        final_packet.extend_from_slice(&self.session_id);
        final_packet.extend_from_slice(&link_nonce_bytes);
        final_packet.extend_from_slice(&link_ciphertext);
        final_packet
    }

    pub fn create_kx_request(&self, target_token: RoutingToken) -> Vec<u8> {
        let payload = KeyExchangePayload::generate(&self.identity, target_token, &self.local_name);
        let mut inner = vec![0x02];
        inner.extend_from_slice(&payload.to_bytes());
        self.wrap_link_encryption(target_token, &inner)
    }

    pub fn create_session_est_packet(
        &self,
        target_token: RoutingToken,
        bob_x25519: &X25519PublicKey,
        bob_kyber: &PublicKey,
    ) -> (Vec<u8>, SymmetricSessionState) {
        // 1. Classical X25519 DH
        let alice_e2e_secret = EphemeralSecret::random_from_rng(OsRng);
        let alice_e2e_pub = X25519PublicKey::from(&alice_e2e_secret);
        let classical_shared_secret = alice_e2e_secret.diffie_hellman(bob_x25519);

        // 2. Post-Quantum Encapsulation
        let (pq_shared_secret, kyber_ct) = encapsulate(bob_kyber);

        // 3. Hybrid Derivation (keeping the peer's Kyber pub for future PQ
        // ratchet injections)
        let root_key = hybrid_root_key(
            classical_shared_secret.as_bytes(),
            pq_shared_secret.as_bytes(),
        );
        let session_state = SymmetricSessionState::from_root_key(root_key, Some(*bob_kyber));

        let est_payload = SessionEstablishPayload::generate(
            &self.identity,
            target_token,
            kyber_ct,
            alice_e2e_pub,
        );
        let mut inner = vec![0x04];
        inner.extend_from_slice(&est_payload.to_bytes());
        let packet = self.wrap_link_encryption(target_token, &inner);
        (packet, session_state)
    }

    pub fn accept_session_est(&mut self, est: &SessionEstablishPayload) {
        let alice_x25519_pub = est.eph_x25519_pub;
        let kyber_ciphertext = &est.kyber_ct;

        let classical_shared_secret = self
            .identity
            .x25519_secret
            .diffie_hellman(&alice_x25519_pub);
        let pq_shared_secret = decapsulate(kyber_ciphertext, &self.identity.kyber_secret);

        let root_key = hybrid_root_key(
            classical_shared_secret.as_bytes(),
            pq_shared_secret.as_bytes(),
        );
        // Peer's Kyber public key was stored during the KeyExchange phase
        let peer_kyber = self.peer_kyber_keys.get(&est.routing_token).copied();
        let session_state = SymmetricSessionState::from_root_key(root_key, peer_kyber);
        self.e2e_sessions.insert(est.routing_token, session_state);
        self.save();
        println!(
            ">> E2E Session established with {}!",
            hex::encode(&est.routing_token[0..4])
        );
    }

    /// Encrypt a message as single link-encrypted datagrams: (message_packet,
    /// optional_pq_inject_packet), the latter every PQ_INJECT_INTERVAL
    /// messages. Test-only — real front ends send with `create_fec_packets`,
    /// which never lets the inject travel apart from its message.
    #[cfg(test)]
    pub(crate) fn create_encrypted_packet(
        &mut self,
        target_token: RoutingToken,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let (msg_payload, pq_payload) = self.encrypt_message_payloads(target_token, plaintext)?;
        let msg_packet = self.wrap_link_encryption(target_token, &msg_payload);
        let pq_inject_packet =
            pq_payload.map(|inner| self.wrap_link_encryption(target_token, &inner));
        Ok((msg_packet, pq_inject_packet))
    }

    /// Encrypt a message for a lossy link: the message and (every
    /// PQ_INJECT_INTERVAL messages) its PQ inject travel together as one
    /// burst of sealed FEC packets, sized to survive `FEC_DESIGN_LOSS` —
    /// see `transport`. Hand the result to `send_burst`.
    pub fn create_fec_packets(
        &mut self,
        target_token: RoutingToken,
        plaintext: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        // Checked before encrypting: a message that can't be sent mustn't
        // advance the ratchet or land in chat history.
        if plaintext.len() > MAX_FEC_MESSAGE_LEN {
            return Err(anyhow!(
                "Message too long ({} bytes, max {MAX_FEC_MESSAGE_LEN})",
                plaintext.len()
            ));
        }
        let (msg_payload, pq_payload) = self.encrypt_message_payloads(target_token, plaintext)?;
        let session = &self.e2e_sessions[&target_token];
        // The message's seq number doubles as its FEC object id: unique
        // within the session, unlike a random id. (`FecReceiver` keeps each
        // session's ids apart.)
        let object_id = (session.send_count - 1) as u32;
        let symbols = transport::encode_message(
            &session.root_key,
            &self.identity.routing_token,
            &target_token,
            object_id,
            &msg_payload,
            pq_payload.as_deref(),
        )?;
        Ok(symbols
            .iter()
            .map(|inner| self.wrap_link_encryption(target_token, inner))
            .collect())
    }

    /// Ratchet-encrypt `plaintext` for `target_token`. Returns the inner (not
    /// yet link-encrypted) 0x01 message payload and, every
    /// PQ_INJECT_INTERVAL messages, the 0x05 PQ inject payload that must
    /// reach the peer right after it.
    fn encrypt_message_payloads(
        &mut self,
        target_token: RoutingToken,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        // Phase 1: encrypt the message and check if PQ inject is needed (mutable borrow on session)
        let (full_e2e_payload, pq_ct) = {
            let session = self
                .e2e_sessions
                .get_mut(&target_token)
                .ok_or(anyhow!("No E2E session established!"))?;

            let message_key = session.symmetric_ratchet();
            let e2e_cipher = XChaCha20Poly1305::new(Key::from_slice(&message_key));
            let mut e2e_nonce_bytes = [0u8; 24];
            OsRng.fill_bytes(&mut e2e_nonce_bytes);
            let e2e_nonce = XNonce::from_slice(&e2e_nonce_bytes);

            let mut full_e2e_payload = vec![0x01];
            full_e2e_payload.extend_from_slice(&self.identity.routing_token);
            full_e2e_payload.extend_from_slice(&session.send_count.to_be_bytes());
            full_e2e_payload.extend_from_slice(&e2e_nonce_bytes);
            let e2e_ciphertext = e2e_cipher.encrypt(e2e_nonce, plaintext).unwrap();
            full_e2e_payload.extend_from_slice(&e2e_ciphertext);

            session.send_count += 1;
            // The state is mutated, but save() needs immutable ref.
            // We'll call self.save() after the mutable borrow block.

            // Check if PQ injection is needed. It's mixed in at chain
            // position `send_count` (the next message's), which the inject
            // payload names so the peer can apply it at exactly that point.
            let pq_ct = if session.send_count % PQ_INJECT_INTERVAL == 0 {
                if let Some(ref peer_kyber) = session.peer_kyber_pub {
                    let (pq_secret, kyber_ct) = encapsulate(peer_kyber);
                    session.inject_pq_secret_send(pq_secret.as_bytes());
                    println!(
                        ">> [PQ] Injected post-quantum entropy after {} messages",
                        session.send_count
                    );
                    Some((session.send_count, kyber_ct))
                } else {
                    None
                }
            } else {
                None
            };

            (full_e2e_payload, pq_ct)
        };
        // mutable borrow on self.e2e_sessions released
        self.save();
        self.record_message(target_token, true, plaintext);

        // Phase 2: build the signed PQ inject payload (immutable borrow on self)
        let pq_payload = pq_ct.map(|(seq, kyber_ct)| {
            let pqi_payload =
                PQInjectPayload::generate(&self.identity, target_token, seq, kyber_ct);
            let mut inner = vec![0x05];
            inner.extend_from_slice(&pqi_payload.to_bytes());
            inner
        });

        Ok((full_e2e_payload, pq_payload))
    }

    /// The checks every signed control payload (KeyExchange,
    /// SessionEstablish, PQInject, Presence) must pass before anything else:
    /// it's addressed to us, and its timestamp is within
    /// `MAX_TIMESTAMP_DRIFT` of our clock. Logs and returns `false` if not.
    fn accepts_payload(&self, what: &str, target_token: &RoutingToken, timestamp: u64) -> bool {
        if !self.addressed_to_me(what, target_token) {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now.abs_diff(timestamp) > MAX_TIMESTAMP_DRIFT {
            println!(">> [SECURITY ALERT] Dropped {what}! Timestamp is stale or from the future.");
            return false;
        }
        true
    }

    /// The target-binding half of `accepts_payload`, on its own.
    fn addressed_to_me(&self, what: &str, target_token: &RoutingToken) -> bool {
        if target_token.ct_eq(&self.identity.routing_token).unwrap_u8() == 0 {
            println!(">> [SECURITY ALERT] Dropped {what}! It was bound to a different target.");
            return false;
        }
        true
    }

    /// Strip the relay's link layer off a received UDP packet: checks it's a
    /// data packet for our link session, decrypts it with the link key, and
    /// drops the leading routing token. Returns the inner E2E payload (ready
    /// for `handle_incoming_packet`), or `None` for anything else — shared by
    /// every front end's receive loop so none of them re-implement it.
    pub fn open_link_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 1 + 4 + 24 + 16
            || packet[0] != TYPE_DATA
            || packet[1..5] != self.session_id
        {
            return None;
        }
        let link_cipher = XChaCha20Poly1305::new(Key::from_slice(&self.link_master_key));
        let mut inner = link_cipher
            .decrypt(XNonce::from_slice(&packet[5..29]), &packet[29..])
            .ok()?;
        if inner.len() < 16 {
            return None;
        }
        Some(inner.split_off(16))
    }

    pub fn handle_incoming_packet(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if payload.is_empty() {
            return Ok(None);
        }
        let pkt_type = payload[0];
        let pkt_data = &payload[1..];

        match pkt_type {
            0x01 => {
                if let Some(sender) = self.receive_message(payload, None)? {
                    self.retry_deferred(sender)?;
                }
                Ok(None)
            }
            0x02 => {
                // KeyExchange
                if let Ok(kx) = KeyExchangePayload::from_bytes(pkt_data) {
                    if kx.verify(&kx.ed25519_public).is_ok() {
                        if !self.accepts_payload("KeyExchange", &kx.target_token, kx.timestamp) {
                            return Ok(None);
                        }

                        let peer_token = kx.routing_token;
                        let is_initiator = self.pending_contacts.contains_key(&peer_token);

                        if !is_initiator && self.pending_contacts.len() > 50 {
                            println!(
                                ">> [SECURITY ALERT] Dropped KeyExchange! Too many pending contacts."
                            );
                            return Ok(None);
                        }

                        // A KeyExchange is only self-signed, so for a token we
                        // already know, its key must match the one we trusted
                        // (scanned/pasted) *before* anything below is allowed to
                        // touch that contact's state. Otherwise anyone who knows
                        // both tokens could forge one that fails this check but
                        // has already renamed the contact or swapped the Kyber
                        // key used for their future PQ injections.
                        if is_initiator {
                            let expected_ed25519 = self.pending_contacts.get(&peer_token).unwrap();
                            if kx.ed25519_public.as_bytes() != expected_ed25519.as_bytes() {
                                println!(
                                    ">> [SECURITY ALERT] KeyExchange from {} failed QR code verification!",
                                    hex::encode(&peer_token[0..4])
                                );
                                return Ok(None);
                            }
                        }

                        // Store peer's Kyber key for future PQ injections
                        self.peer_kyber_keys.insert(peer_token, kx.kyber_public);

                        // Learn the peer's self-chosen name (if any) the moment
                        // their KeyExchange arrives — before either branch below,
                        // so it shows up for pending AND established contacts.
                        if kx.name.is_empty() {
                            self.contact_names.remove(&peer_token);
                        } else {
                            self.contact_names.insert(peer_token, kx.name.clone());
                        }

                        if is_initiator {
                            println!(">> Verified Bob's keys against QR code!");

                            let (est_packet, session) = self.create_session_est_packet(
                                peer_token,
                                &kx.x25519_public,
                                &kx.kyber_public,
                            );
                            self.e2e_sessions.insert(peer_token, session);
                            println!(
                                ">> E2E Session established with {}!",
                                hex::encode(&peer_token[0..4])
                            );
                            return Ok(Some(est_packet));
                        } else {
                            println!(
                                ">> [SECURITY WARNING: Unverified Contact] Received connection request from {}. Auto-accepting for demo...",
                                hex::encode(&peer_token[0..4])
                            );
                            self.pending_contacts.insert(peer_token, kx.ed25519_public);
                            let reply_packet = self.create_kx_request(peer_token);
                            return Ok(Some(reply_packet));
                        }
                    } else {
                        println!(">> Received KeyExchange with invalid signature.");
                    }
                }
                Ok(None)
            }
            0x04 => {
                // SessionEstablish

                if let Ok(est) = SessionEstablishPayload::from_bytes(pkt_data) {
                    if !self.accepts_payload("SessionEstablish", &est.target_token, est.timestamp) {
                        return Ok(None);
                    }
                    if let Some(alice_pub) = self.pending_contacts.get(&est.routing_token) {
                        if est.verify(alice_pub).is_ok() {
                            if !self.seen_session_keys.insert(est.eph_x25519_pub.to_bytes()) {
                                println!(
                                    ">> [SECURITY ALERT] Dropped SessionEstablish! Replay detected (key already seen)."
                                );
                                return Ok(None);
                            }
                            if self.seen_session_keys.len() > 1000 {
                                self.seen_session_keys.clear();
                            }
                            self.accept_session_est(&est);
                        } else {
                            println!(">> [SECURITY ALERT] SessionEstablish signature invalid!");
                        }
                    } else {
                        println!(">> Received SessionEstablish but no pending contact found.");
                    }
                }
                Ok(None)
            }
            0x05 => {
                // PQ Inject. No timestamp freshness check: its signed chain
                // position (`seq`) is what rules out replays, and one queued
                // at the relay can legitimately be older than
                // MAX_TIMESTAMP_DRIFT.
                if let Ok(pqi) = PQInjectPayload::from_bytes(pkt_data) {
                    if !self.addressed_to_me("PQInject", &pqi.target_token) {
                        return Ok(None);
                    }
                    if let Some(sender_pub) = self.pending_contacts.get(&pqi.routing_token) {
                        if pqi.verify(sender_pub).is_ok() {
                            // Decapsulate and inject PQ entropy into the session

                            let pq_secret = decapsulate(&pqi.kyber_ct, &self.identity.kyber_secret);
                            if let Some(session) = self.e2e_sessions.get_mut(&pqi.routing_token) {
                                let sig_bytes = pqi.signature.to_bytes();
                                if session.pq_inject_replay_cache.contains(&sig_bytes) {
                                    println!(
                                        ">> [SECURITY ALERT] Dropped PQInject! Replay detected."
                                    );
                                    return Ok(None);
                                }
                                if !session.accept_pq_inject(pqi.seq, pq_secret.as_bytes()) {
                                    println!(
                                        ">> [SECURITY ALERT] Dropped PQInject for chain position {} (stale, duplicate or out of range).",
                                        pqi.seq
                                    );
                                    return Ok(None);
                                }
                                if session.pq_inject_replay_cache.len() > 1000 {
                                    session.pq_inject_replay_cache.clear();
                                }
                                session.pq_inject_replay_cache.insert(sig_bytes);
                                self.save();

                                println!(
                                    ">> [PQ] Received and injected post-quantum entropy from {}!",
                                    hex::encode(&pqi.routing_token[0..4])
                                );
                                self.retry_deferred(pqi.routing_token)?;
                            } else {
                                println!(
                                    ">> PQInject received but no active session for this peer."
                                );
                            }
                        } else {
                            println!(">> [SECURITY ALERT] PQInject signature invalid!");
                        }
                    } else {
                        println!(">> PQInject received but sender unknown (not in contacts).");
                    }
                }
                Ok(None)
            }
            0x06 => {
                // Presence ping — see PresencePayload's doc comment. Only
                // ever updates `last_seen`; never reaches `inbox`.
                if let Ok(presence) = PresencePayload::from_bytes(pkt_data) {
                    if !self.accepts_payload(
                        "Presence ping",
                        &presence.target_token,
                        presence.timestamp,
                    ) {
                        return Ok(None);
                    }
                    if let Some(sender_pub) = self.pending_contacts.get(&presence.routing_token) {
                        if presence.verify(sender_pub).is_ok() {
                            self.last_seen
                                .insert(presence.routing_token, Instant::now());
                        } else {
                            println!(">> [SECURITY ALERT] Presence ping signature invalid!");
                        }
                    }
                }
                Ok(None)
            }
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

    /// Decrypt a 0x01 chat message: [16-byte sender_token | 8-byte seq_no |
    /// 24-byte nonce | ciphertext]. Returns the sender if it was delivered.
    ///
    /// `park` is `Some(parked_at)` only for a message whose sender is
    /// already authenticated (it arrived sealed in an FEC bundle): if it
    /// can't be decrypted yet — it was encrypted after a PQ inject still in
    /// flight — it's held for `retry_deferred`, keeping its original
    /// `parked_at` so retries never extend its lifetime. Anyone can forge a
    /// bare 0x01, so those are never held.
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
        if let Some(pt) = session.try_decrypt(seq_no, nonce, ciphertext) {
            self.save();
            println!(
                ">> [From {}]: {}",
                hex::encode(&sender_token[0..4]),
                String::from_utf8_lossy(&pt)
            );
            // Also hand it to any polling consumer (e.g. a GUI) — see the
            // `inbox` field doc comment above.
            self.record_message(sender_token, false, &pt);
            self.inbox.push((sender_token, pt, self.last_recorded_id));
            self.last_seen.insert(sender_token, Instant::now());
            return Ok(Some(sender_token));
        }
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
        Ok(None)
    }

    /// Replay, in seq order, messages from `sender` held back as not yet
    /// decryptable, now that a PQ inject or an earlier message has moved
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
    let (client_secret, hs_packet) = client.generate_handshake_packet();
    socket.send_to(&hs_packet, client.server_addr).await?;

    // UDP gives no error for an unreachable relay (wrong address, relay
    // down, packet lost) — without a deadline this would wait forever.
    let mut resp_buf = [0u8; 1024];
    let (len, _) = tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv_from(&mut resp_buf))
        .await
        .map_err(|_| {
            anyhow!(
                "No response from the relay at {} within {}s. Check the address and that the relay is running.",
                client.server_addr,
                HANDSHAKE_TIMEOUT.as_secs()
            )
        })??;
    client.complete_handshake(client_secret, server_pub, &resp_buf[..len])?;

    let sync_packet = client.generate_sync_packet();
    socket.send_to(&sync_packet, client.server_addr).await?;
    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{connected_pair, strip_link};
    use pqcrypto_traits::kem::PublicKey as _;

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
    /// `create_encrypted_packet`'s side channel, or `drain_inbox`'s third
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

        alice
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);
        let kx = KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token, "");
        let mut kx_inner = vec![0x02];
        kx_inner.extend_from_slice(&kx.to_bytes());
        let bob_reply = bob.handle_incoming_packet(&kx_inner).unwrap().unwrap();
        let inner = strip_link(&bob_reply, &bob.link_master_key);
        let alice_est = alice.handle_incoming_packet(&inner).unwrap().unwrap();
        let inner_est = strip_link(&alice_est, &alice.link_master_key);
        bob.handle_incoming_packet(&inner_est).unwrap();

        // Outgoing: the side-channel id must match what a history fetch
        // reports for that same row.
        alice
            .create_encrypted_packet(bob.identity.routing_token, b"outgoing")
            .unwrap();
        let live_outgoing_id = alice.last_recorded_id.expect("history is attached");
        let fetched = alice.history_for_contact(bob.identity.routing_token, 10);
        assert_eq!(fetched.last().unwrap().id, live_outgoing_id);

        // Incoming: `drain_inbox`'s third element must match too.
        let (msg_packet, _) = bob
            .create_encrypted_packet(alice.identity.routing_token, b"incoming")
            .unwrap();
        let inner_msg = strip_link(&msg_packet, &bob.link_master_key);
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
        let payload = KeyExchangePayload::generate(&alice_id, bob_token, "");
        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), 1384);
        let parsed = KeyExchangePayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&parsed.ed25519_public).is_ok());
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
        let est =
            SessionEstablishPayload::generate(&alice_id, bob_id.routing_token, kyber_ct, eph_pub);
        let bytes = est.to_bytes();
        assert_eq!(bytes.len(), 1224);
        let parsed = SessionEstablishPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public).is_ok());
    }

    #[test]
    fn test_pq_inject_serialization() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let (_pq_secret, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let pqi = PQInjectPayload::generate(&alice_id, bob_id.routing_token, 5, kyber_ct);
        let bytes = pqi.to_bytes();
        assert_eq!(bytes.len(), 1200);
        let parsed = PQInjectPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public).is_ok());
        assert_eq!(parsed.routing_token, alice_id.routing_token);
        assert_eq!(parsed.target_token, bob_id.routing_token);
        assert_eq!(parsed.seq, 5);
    }

    // ==========================================
    // Edge Case: Malformed Packets
    // ==========================================

    #[test]
    fn test_edge_case_invalid_packet_sizes() {
        assert!(KeyExchangePayload::from_bytes(&[0u8; 0]).is_err());
        assert!(KeyExchangePayload::from_bytes(&[0u8; 100]).is_err());
        assert!(KeyExchangePayload::from_bytes(&[0u8; 1351]).is_err());
        assert!(KeyExchangePayload::from_bytes(&[0u8; 1353]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 0]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 1223]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 1225]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 0]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 1191]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 1193]).is_err());
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
        let payload = KeyExchangePayload::generate(&alice_id, [0u8; 16], "");
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
        let est =
            SessionEstablishPayload::generate(&alice_id, bob_id.routing_token, kyber_ct, eph_pub);
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
        let pqi = PQInjectPayload::generate(&alice_id, bob_id.routing_token, 5, kyber_ct);
        let mut bytes = pqi.to_bytes();
        bytes[1150] ^= 0x01;
        let parsed = PQInjectPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public).is_err());
    }

    #[test]
    fn test_edge_case_est_wrong_verifier_key() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let eph_sec = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_sec);
        let (_, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let est =
            SessionEstablishPayload::generate(&alice_id, bob_id.routing_token, kyber_ct, eph_pub);
        let bytes = est.to_bytes();
        let parsed = SessionEstablishPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&bob_id.ed25519_public).is_err());
    }

    #[test]
    fn test_edge_case_pq_inject_wrong_verifier_key() {
        let alice_id = UserIdentity::generate();
        let bob_id = UserIdentity::generate();
        let (_, kyber_ct) = encapsulate(&bob_id.kyber_public);
        let pqi = PQInjectPayload::generate(&alice_id, bob_id.routing_token, 5, kyber_ct);
        let bytes = pqi.to_bytes();
        let parsed = PQInjectPayload::from_bytes(&bytes).unwrap();
        // Verify with wrong key — simulates Mallory injection
        assert!(parsed.verify(&bob_id.ed25519_public).is_err());
    }

    // ==========================================
    // Edge Case: Replay & Misbinding
    // ==========================================

    #[test]
    fn test_edge_case_timestamp_expiration() {
        let alice_id = UserIdentity::generate();
        let mut payload = KeyExchangePayload::generate(&alice_id, [0u8; 16], "");
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
        let payload = KeyExchangePayload::generate(&alice_id, charlie_token, "");
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
            pq_inject_replay_cache: HashSet::new(),
            pending_pq: Default::default(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
            pending_pq: Default::default(),
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
            pq_inject_replay_cache: HashSet::new(),
            pending_pq: Default::default(),
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: Default::default(),
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: Default::default(),
            },
        );
        let (packet, _pq) = alice
            .create_encrypted_packet(bob.identity.routing_token, b"Hello Bob!")
            .unwrap();
        let inner = strip_link(&packet, &alice.link_master_key);
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: Default::default(),
                peer_kyber_pub: Some(bob_kyber_copy),
            },
        );

        // Messages 1-4: no PQ inject
        for i in 0..4 {
            let (_, pq) = alice
                .create_encrypted_packet(bob_id.routing_token, b"test")
                .unwrap();
            assert!(
                pq.is_none(),
                "PQ inject should NOT trigger at message {}",
                i + 1
            );
        }

        // Message 5: PQ inject triggers!
        let (_, pq) = alice
            .create_encrypted_packet(bob_id.routing_token, b"test")
            .unwrap();
        assert!(pq.is_some(), "PQ inject MUST trigger at message 5");

        // Messages 6-9: no PQ inject
        for i in 5..9 {
            let (_, pq) = alice
                .create_encrypted_packet(bob_id.routing_token, b"test")
                .unwrap();
            assert!(
                pq.is_none(),
                "PQ inject should NOT trigger at message {}",
                i + 1
            );
        }

        // Message 10: PQ inject triggers again!
        let (_, pq) = alice
            .create_encrypted_packet(bob_id.routing_token, b"test")
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: Default::default(),
                peer_kyber_pub: None, // No Kyber key!
            },
        );

        // Even at message 5, no PQ inject because no peer Kyber key
        for _ in 0..10 {
            let (_, pq) = alice.create_encrypted_packet(bob_token, b"test").unwrap();
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: Default::default(),
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: Default::default(),
                peer_kyber_pub: Some(alice_kyber_copy),
            },
        );
        // Bob needs Alice in pending_contacts for PQ inject verification
        bob.pending_contacts
            .insert(alice.identity.routing_token, alice.identity.ed25519_public);

        // Alice sends 5 messages (triggers PQ inject on 5th)
        for i in 0..5 {
            let (msg_pkt, pq_pkt) = alice
                .create_encrypted_packet(
                    bob.identity.routing_token,
                    format!("msg {}", i + 1).as_bytes(),
                )
                .unwrap();

            // Bob receives the message
            let inner = strip_link(&msg_pkt, &alice.link_master_key);
            bob.handle_incoming_packet(&inner).unwrap();

            // If PQ inject was generated, Bob processes it too
            if let Some(pq) = pq_pkt {
                let pq_inner = strip_link(&pq, &alice.link_master_key);
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: Default::default(),
                peer_kyber_pub: Some(bob_kyber_copy),
            },
        );

        // Record chain key after 4th message (before PQ inject)
        for _ in 0..4 {
            alice
                .create_encrypted_packet(bob_id.routing_token, b"test")
                .unwrap();
        }
        let chain_before_pq = alice
            .e2e_sessions
            .get(&bob_id.routing_token)
            .unwrap()
            .send_chain_key;

        // Send 5th message (triggers PQ inject)
        let (_, pq) = alice
            .create_encrypted_packet(bob_id.routing_token, b"test")
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
            pq_inject_replay_cache: HashSet::new(),
            pending_pq: Default::default(),
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

    #[test]
    fn test_full_3way_handshake() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);

        // Step 0: Alice "scans" Bob's QR code
        alice
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);

        // Step 1: Alice sends KeyExchange to Bob
        let alice_kx =
            KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token, "");
        let mut kx_inner = vec![0x02];
        kx_inner.extend_from_slice(&alice_kx.to_bytes());
        let bob_reply = bob.handle_incoming_packet(&kx_inner).unwrap();
        assert!(bob_reply.is_some());
        assert!(
            bob.pending_contacts
                .contains_key(&alice.identity.routing_token)
        );

        // Step 2: Alice receives Bob's KeyExchange reply
        let inner = strip_link(&bob_reply.unwrap(), &bob.link_master_key);
        let alice_reply = alice.handle_incoming_packet(&inner).unwrap();
        assert!(alice_reply.is_some());
        assert!(alice.e2e_sessions.contains_key(&bob.identity.routing_token));

        // Step 3: Bob receives SessionEstablish
        let inner2 = strip_link(&alice_reply.unwrap(), &alice.link_master_key);
        let bob_final = bob.handle_incoming_packet(&inner2).unwrap();
        assert!(bob_final.is_none());
        assert!(bob.e2e_sessions.contains_key(&alice.identity.routing_token));

        // Verify matching keys
        let a_sess = alice.e2e_sessions.get(&bob.identity.routing_token).unwrap();
        let b_sess = bob.e2e_sessions.get(&alice.identity.routing_token).unwrap();
        assert_eq!(a_sess.root_key, b_sess.root_key);
        assert_eq!(a_sess.send_chain_key, b_sess.send_chain_key);

        // Verify both sessions have peer Kyber keys for future PQ injections
        assert!(
            a_sess.peer_kyber_pub.is_some(),
            "Alice must have Bob's Kyber key"
        );
        assert!(
            b_sess.peer_kyber_pub.is_some(),
            "Bob must have Alice's Kyber key"
        );
    }

    /// Simulates "delete an identity, then create a new one with the same
    /// display name and reconnect to an existing contact" (a real workflow
    /// once the login screen's delete/create identity commands exist).
    /// Recreating an identity mints a brand-new routing token — from the
    /// surviving peer's (Bob's) perspective, "new Alice" is a completely
    /// unrelated identity that happens to share a name, not a resumed
    /// session. This test asserts what the protocol layer actually
    /// guarantees in that situation: the new session establishes correctly
    /// and works end-to-end, and Bob's old session for the deleted identity
    /// is left completely intact rather than corrupted or silently merged.
    /// It does *not* claim this is good UX — see the "duplicate contact"
    /// follow-up work, which is a UI/contact-management concern layered on
    /// top of this correct-but-confusing protocol behavior.
    #[test]
    fn test_reconnect_after_identity_recreation_creates_independent_session() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice1 = Client::new(server_addr);
        let mut bob = Client::new(server_addr);
        alice1.local_name = "alice".to_string();
        bob.local_name = "bob".to_string();

        // --- Baseline: Alice1 <-> Bob fully established, one message each way ---
        alice1
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);
        let kx1 =
            KeyExchangePayload::generate(&alice1.identity, bob.identity.routing_token, "alice");
        let mut kx1_inner = vec![0x02];
        kx1_inner.extend_from_slice(&kx1.to_bytes());
        let bob_reply1 = bob.handle_incoming_packet(&kx1_inner).unwrap().unwrap();
        let inner1 = strip_link(&bob_reply1, &bob.link_master_key);
        let alice1_reply = alice1.handle_incoming_packet(&inner1).unwrap().unwrap();
        let inner1b = strip_link(&alice1_reply, &alice1.link_master_key);
        bob.handle_incoming_packet(&inner1b).unwrap();

        assert!(
            bob.e2e_sessions
                .contains_key(&alice1.identity.routing_token)
        );
        assert!(
            alice1
                .e2e_sessions
                .contains_key(&bob.identity.routing_token)
        );
        let bob_alice1_session_before = bob
            .e2e_sessions
            .get(&alice1.identity.routing_token)
            .unwrap()
            .root_key;

        let (msg_to_bob, _) = alice1
            .create_encrypted_packet(bob.identity.routing_token, b"hi bob, it's alice")
            .unwrap();
        let inner_msg = strip_link(&msg_to_bob, &alice1.link_master_key);
        bob.handle_incoming_packet(&inner_msg).unwrap();
        assert_eq!(bob.inbox.last().unwrap().1, b"hi bob, it's alice");

        // --- Alice's identity is deleted and recreated: brand-new keys/token,
        // same self-chosen name. Bob's own state is completely untouched. ---
        let mut alice2 = Client::new(server_addr);
        alice2.local_name = "alice".to_string();
        assert_ne!(
            alice2.identity.routing_token, alice1.identity.routing_token,
            "a recreated identity must not reuse the old routing token"
        );

        // Alice2 re-adds Bob using his (unchanged) token/key, exactly like
        // the ContactPanel's "Add contact" form / connect_to_peer command.
        alice2
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);
        let kx2 =
            KeyExchangePayload::generate(&alice2.identity, bob.identity.routing_token, "alice");
        let mut kx2_inner = vec![0x02];
        kx2_inner.extend_from_slice(&kx2.to_bytes());
        let bob_reply2 = bob.handle_incoming_packet(&kx2_inner).unwrap().unwrap();
        let inner2 = strip_link(&bob_reply2, &bob.link_master_key);
        let alice2_reply = alice2.handle_incoming_packet(&inner2).unwrap().unwrap();
        let inner2b = strip_link(&alice2_reply, &alice2.link_master_key);
        bob.handle_incoming_packet(&inner2b).unwrap();

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
        assert!(
            alice2
                .e2e_sessions
                .contains_key(&bob.identity.routing_token)
        );

        // --- The new session must work end-to-end, in both directions ---
        let (msg_to_bob2, _) = alice2
            .create_encrypted_packet(bob.identity.routing_token, b"hi bob, it's the new alice")
            .unwrap();
        let inner_msg2 = strip_link(&msg_to_bob2, &alice2.link_master_key);
        bob.handle_incoming_packet(&inner_msg2).unwrap();
        assert_eq!(bob.inbox.last().unwrap().1, b"hi bob, it's the new alice");

        let (msg_to_alice2, _) = bob
            .create_encrypted_packet(alice2.identity.routing_token, b"hi new alice, it's bob")
            .unwrap();
        let inner_msg3 = strip_link(&msg_to_alice2, &bob.link_master_key);
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
    }

    #[test]
    fn test_key_exchange_propagates_display_name() {
        // A self-chosen name (e.g. set via `./runpeer.sh alice`) should
        // reach the peer automatically as part of the KeyExchange — no
        // manual entry by the other side, in either direction.
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);
        alice.local_name = "alice".to_string();
        bob.local_name = "bob".to_string();

        alice
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);

        let alice_kx = KeyExchangePayload::generate(
            &alice.identity,
            bob.identity.routing_token,
            &alice.local_name,
        );
        let mut kx_inner = vec![0x02];
        kx_inner.extend_from_slice(&alice_kx.to_bytes());
        let bob_reply = bob.handle_incoming_packet(&kx_inner).unwrap().unwrap();

        assert_eq!(
            bob.contact_names.get(&alice.identity.routing_token),
            Some(&"alice".to_string()),
            "Bob should learn Alice's name straight from her KeyExchange, while still only 'pending'"
        );

        let inner = strip_link(&bob_reply, &bob.link_master_key);
        alice.handle_incoming_packet(&inner).unwrap();

        assert_eq!(
            alice.contact_names.get(&bob.identity.routing_token),
            Some(&"bob".to_string()),
            "Alice should learn Bob's name from his auto-reply, without typing it in herself"
        );
    }

    #[test]
    fn test_full_handshake_then_pq_inject() {
        // Full handshake + 5 messages + PQ inject: end-to-end integration
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);

        // Handshake
        alice
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);
        let alice_kx =
            KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token, "");
        let mut kx_inner = vec![0x02];
        kx_inner.extend_from_slice(&alice_kx.to_bytes());
        let bob_reply = bob.handle_incoming_packet(&kx_inner).unwrap().unwrap();
        let inner = strip_link(&bob_reply, &bob.link_master_key);
        let alice_reply = alice.handle_incoming_packet(&inner).unwrap().unwrap();
        let inner2 = strip_link(&alice_reply, &alice.link_master_key);
        bob.handle_incoming_packet(&inner2).unwrap();

        // Send 5 messages with PQ inject at #5
        for i in 0..5 {
            let (msg_pkt, pq_pkt) = alice
                .create_encrypted_packet(
                    bob.identity.routing_token,
                    format!("Hello {}", i + 1).as_bytes(),
                )
                .unwrap();
            let msg_inner = strip_link(&msg_pkt, &alice.link_master_key);
            bob.handle_incoming_packet(&msg_inner).unwrap();
            if let Some(pq) = pq_pkt {
                assert_eq!(i, 4, "PQ inject must only trigger at message 5");
                let pq_inner = strip_link(&pq, &alice.link_master_key);
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
            .create_encrypted_packet(bob.identity.routing_token, b"Post-PQ message")
            .unwrap();
        let msg6_inner = strip_link(&msg6, &alice.link_master_key);
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

    #[test]
    fn test_attack_session_overwrite_prevention() {
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        let alice_id = UserIdentity::generate();
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
        let alice_id = UserIdentity::generate();
        let eph_sec = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_sec);
        let (_, kyber_ct) = encapsulate(&bob.identity.kyber_public);
        let est = SessionEstablishPayload::generate(
            &alice_id,
            bob.identity.routing_token,
            kyber_ct,
            eph_pub,
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: Default::default(),
            },
        );
        let chain_before = bob
            .e2e_sessions
            .get(&alice_id.routing_token)
            .unwrap()
            .send_chain_key;

        // Mallory signs PQ inject with her own key but spoofs Alice's routing token
        let (_, kyber_ct) = encapsulate(&bob.identity.kyber_public);
        let mut pqi =
            PQInjectPayload::generate(&mallory_id, bob.identity.routing_token, 0, kyber_ct);
        pqi.routing_token = alice_id.routing_token;

        let mut inner = vec![0x05];
        inner.extend_from_slice(&pqi.to_bytes());
        bob.handle_incoming_packet(&inner).unwrap();

        // Chain key must NOT have changed
        let chain_after = bob
            .e2e_sessions
            .get(&alice_id.routing_token)
            .unwrap()
            .send_chain_key;
        assert_eq!(
            chain_before, chain_after,
            "Forged PQ inject must NOT modify chain key"
        );
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
            pq_inject_replay_cache: std::collections::HashSet::new(),
            pending_pq: Default::default(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            pq_inject_replay_cache: std::collections::HashSet::new(),
            pending_pq: Default::default(),
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
            pq_inject_replay_cache: std::collections::HashSet::new(),
            pending_pq: Default::default(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            pq_inject_replay_cache: std::collections::HashSet::new(),
            pending_pq: Default::default(),
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

    #[test]
    fn test_edge_case_pending_contacts_exhaustion() {
        let server_addr: std::net::SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);

        // Flood with 55 KeyExchanges
        for _ in 0..55 {
            let alice_id = UserIdentity::generate();
            let payload = KeyExchangePayload::generate(&alice_id, bob.identity.routing_token, "");
            let mut packet = vec![0x02];
            packet.extend_from_slice(&payload.to_bytes());

            // Send
            let _ = bob.handle_incoming_packet(&packet);
        }

        // Ensure bounded to 51 (inserts up to 50, drops if > 50 which allows 51)
        assert_eq!(bob.pending_contacts.len(), 51);
        assert_eq!(bob.peer_kyber_keys.len(), 51);
    }

    #[test]
    fn test_edge_case_seen_session_keys_exhaustion() {
        let server_addr: std::net::SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);

        // Insert a dummy pending contact to allow verification
        let alice_id = UserIdentity::generate();
        bob.pending_contacts
            .insert(alice_id.routing_token, alice_id.ed25519_public);

        // Flood with 1050 SessionEstablish payloads
        for _ in 0..1050 {
            let eph_sec = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
            let eph_pub = x25519_dalek::PublicKey::from(&eph_sec);
            let (_, kyber_ct) = pqcrypto_kyber::kyber768::encapsulate(&alice_id.kyber_public);
            let payload = SessionEstablishPayload::generate(
                &alice_id,
                bob.identity.routing_token,
                kyber_ct,
                eph_pub,
            );

            let mut packet = vec![0x04];
            packet.extend_from_slice(&payload.to_bytes());

            let _ = bob.handle_incoming_packet(&packet);
        }

        // Ensure bounded to 1000 or cleared
        assert!(bob.seen_session_keys.len() <= 1000);
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
            pq_inject_replay_cache: std::collections::HashSet::new(),
            pending_pq: Default::default(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            peer_kyber_pub: None,
            recv_count: 0,
            skip_dict: std::collections::HashMap::new(),
            pq_inject_replay_cache: std::collections::HashSet::new(),
            pending_pq: Default::default(),
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

    #[test]
    fn test_edge_case_timestamp_rejection_via_handler() {
        // Sends a stale-timestamp KeyExchange through handle_incoming_packet
        // and verifies it is rejected (fixes incomplete test from review)
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        let alice_id = UserIdentity::generate();

        // Generate a valid payload, then manually set a stale timestamp and re-sign
        let mut payload = KeyExchangePayload::generate(&alice_id, bob.identity.routing_token, "");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        payload.timestamp = now - 600; // 10 minutes in the past
        // Re-sign with the stale timestamp
        use ed25519_dalek::Signer;
        let mut msg = Vec::new();
        msg.extend_from_slice(&payload.routing_token);
        msg.extend_from_slice(&payload.target_token);
        msg.extend_from_slice(&payload.timestamp.to_be_bytes());
        msg.extend_from_slice(payload.ed25519_public.as_bytes());
        msg.extend_from_slice(payload.x25519_public.as_bytes());
        msg.extend_from_slice(payload.kyber_public.as_bytes());
        payload.signature = alice_id.ed25519_secret.sign(&msg);

        let mut packet = vec![0x02];
        packet.extend_from_slice(&payload.to_bytes());
        let result = bob.handle_incoming_packet(&packet).unwrap();
        assert!(
            result.is_none(),
            "Stale timestamp must cause packet to be dropped"
        );
        // Bob should NOT have added alice to pending_contacts
        assert!(
            !bob.pending_contacts.contains_key(&alice_id.routing_token),
            "Stale KX must not create a pending contact"
        );
    }

    #[test]
    fn test_edge_case_target_misbinding_via_handler() {
        // Sends a KeyExchange bound to Charlie through Bob's handler
        // and verifies Bob drops it (fixes incomplete test from review)
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        let alice_id = UserIdentity::generate();

        let mut charlie_token = [0u8; 16];
        charlie_token[0] = 0xCC;
        // Alice signs a KX intended for Charlie, NOT Bob
        let payload = KeyExchangePayload::generate(&alice_id, charlie_token, "");
        let mut packet = vec![0x02];
        packet.extend_from_slice(&payload.to_bytes());

        let result = bob.handle_incoming_packet(&packet).unwrap();
        assert!(
            result.is_none(),
            "Misbinding must cause packet to be dropped"
        );
        assert!(
            !bob.pending_contacts.contains_key(&alice_id.routing_token),
            "Misbinding must not create a pending contact"
        );
    }

    #[test]
    fn test_edge_case_session_establish_replay_detection() {
        // Sends the same SessionEstablish twice; second must be dropped
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);

        // Set up pending contacts
        alice
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);

        // Alice sends KX, Bob replies, Alice sends SessionEstablish
        let alice_kx =
            KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token, "");
        let mut kx_inner = vec![0x02];
        kx_inner.extend_from_slice(&alice_kx.to_bytes());
        let bob_reply = bob.handle_incoming_packet(&kx_inner).unwrap().unwrap();
        let inner = strip_link(&bob_reply, &bob.link_master_key);
        let alice_reply = alice.handle_incoming_packet(&inner).unwrap().unwrap();

        // Bob processes SessionEstablish — first time should succeed
        let est_inner = strip_link(&alice_reply, &alice.link_master_key);
        let result1 = bob.handle_incoming_packet(&est_inner).unwrap();
        assert!(result1.is_none()); // SessionEstablish returns None on success
        assert!(bob.e2e_sessions.contains_key(&alice.identity.routing_token));

        // Remove the session to test replay detection (session already exists,
        // but seen_session_keys should still block replay)
        bob.e2e_sessions.remove(&alice.identity.routing_token);

        // Replay the same SessionEstablish — must be rejected via seen_session_keys
        let result2 = bob.handle_incoming_packet(&est_inner).unwrap();
        assert!(result2.is_none());
        assert!(
            !bob.e2e_sessions.contains_key(&alice.identity.routing_token),
            "Replayed SessionEstablish must NOT create a new session"
        );
    }

    /// Bob with a session to Alice at `recv_count`, and an inject from her
    /// for chain position `seq`, signed with `timestamp`.
    fn pq_inject_fixture(recv_count: u64, seq: u64, timestamp: u64) -> (Client, Vec<u8>) {
        let mut bob = Client::new("127.0.0.1:4430".parse().unwrap());
        let alice_id = UserIdentity::generate();
        bob.pending_contacts
            .insert(alice_id.routing_token, alice_id.ed25519_public);
        let mut session = SymmetricSessionState::from_root_key([0x42; 32], None);
        session.recv_count = recv_count;
        bob.e2e_sessions.insert(alice_id.routing_token, session);

        let (_, kyber_ct) = encapsulate(&bob.identity.kyber_public);
        let mut pqi =
            PQInjectPayload::generate(&alice_id, bob.identity.routing_token, seq, kyber_ct);
        pqi.timestamp = timestamp;
        // Re-sign over the changed timestamp
        use ed25519_dalek::Signer;
        use pqcrypto_traits::kem::Ciphertext as _;
        let mut msg = Vec::new();
        msg.extend_from_slice(&pqi.routing_token);
        msg.extend_from_slice(&pqi.target_token);
        msg.extend_from_slice(&pqi.timestamp.to_be_bytes());
        msg.extend_from_slice(&pqi.seq.to_be_bytes());
        msg.extend_from_slice(pqi.kyber_ct.as_bytes());
        pqi.signature = alice_id.ed25519_secret.sign(&msg);

        let mut packet = vec![0x05];
        packet.extend_from_slice(&pqi.to_bytes());
        (bob, packet)
    }

    fn only_recv_chain(client: &Client) -> [u8; 32] {
        client.e2e_sessions.values().next().unwrap().recv_chain_key
    }

    #[test]
    fn test_edge_case_pq_inject_older_than_timestamp_window_still_applies() {
        // Queued at the relay past MAX_TIMESTAMP_DRIFT: its chain position,
        // not its age, decides — dropping it would desync the session.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (mut bob, packet) = pq_inject_fixture(5, 5, now - 600);
        let before = only_recv_chain(&bob);
        bob.handle_incoming_packet(&packet).unwrap();
        assert_ne!(only_recv_chain(&bob), before, "late PQ inject must apply");

        // A replay of it must not apply twice.
        let applied = only_recv_chain(&bob);
        bob.handle_incoming_packet(&packet).unwrap();
        assert_eq!(only_recv_chain(&bob), applied);
    }

    #[test]
    fn test_edge_case_pq_inject_for_passed_or_far_position_rejected() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (recv_count, seq) in [(6, 5), (0, MAX_SKIP + 2)] {
            let (mut bob, packet) = pq_inject_fixture(recv_count, seq, now);
            let before = only_recv_chain(&bob);
            bob.handle_incoming_packet(&packet).unwrap();
            assert_eq!(only_recv_chain(&bob), before);
            let session = bob.e2e_sessions.values().next().unwrap();
            assert!(session.pending_pq.is_empty(), "seq {seq} at {recv_count}");
        }
    }

    #[test]
    fn test_pq_inject_ahead_of_chain_is_held_until_its_position() {
        // An inject for a position the chain hasn't reached is held, not
        // mixed in early.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (mut bob, packet) = pq_inject_fixture(2, 5, now);
        let before = only_recv_chain(&bob);
        bob.handle_incoming_packet(&packet).unwrap();
        assert_eq!(only_recv_chain(&bob), before);
        let session = bob.e2e_sessions.values().next().unwrap();
        assert!(session.pending_pq.contains_key(&5));
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
                pq_inject_replay_cache: std::collections::HashSet::new(),
                pending_pq: BTreeMap::from([(10, vec![0xBC; 32])]),
            },
        );
        original.seen_session_keys.insert([0xDD; 32]);

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
        assert_eq!(orig_sess.pending_pq, load_sess.pending_pq);

        // Verify pending contacts
        assert!(loaded.pending_contacts.contains_key(&peer_token));

        // Verify seen_session_keys
        assert!(loaded.seen_session_keys.contains(&[0xDD; 32]));

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
                pq_inject_replay_cache: HashSet::new(),
                pending_pq: Default::default(),
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
                pq_inject_replay_cache: HashSet::new(),
                pending_pq: Default::default(),
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
            pq_inject_replay_cache: HashSet::new(),
            pending_pq: Default::default(),
        };

        let mut charlie_sender = SymmetricSessionState {
            root_key: root_charlie,
            send_chain_key: root_charlie,
            recv_chain_key: root_charlie,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
            pending_pq: Default::default(),
        };

        let mut bob_pkts = vec![];
        for i in 0..3 {
            let key = bob_sender.symmetric_ratchet();
            let c = XChaCha20Poly1305::new(Key::from_slice(&key));
            let nonce = XNonce::from_slice(&[0x77u8; 24]);
            let ct = c.encrypt(nonce, format!("bob{}", i).as_bytes()).unwrap();
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
            let ct = c.encrypt(nonce, format!("char{}", i).as_bytes()).unwrap();
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
    // Presence Ping Tests
    // ==========================================

    /// Runs the same 3-way handshake as `test_full_3way_handshake` and
    /// returns the two established clients, to avoid repeating the setup
    /// in every presence test below.
    #[test]
    fn test_presence_ping_marks_peer_online() {
        let (alice, mut bob) = connected_pair();
        let freshness = Duration::from_secs(60);

        assert!(
            !bob.is_online(&alice.identity.routing_token, freshness),
            "must be offline before any ping has arrived"
        );

        let ping = alice.generate_presence_packet(bob.identity.routing_token);
        let inner = strip_link(&ping, &alice.link_master_key);
        bob.handle_incoming_packet(&inner).unwrap();

        assert!(
            bob.is_online(&alice.identity.routing_token, freshness),
            "must be online immediately after a valid ping"
        );
        assert!(
            bob.drain_inbox().is_empty(),
            "a presence ping must never surface as a chat message"
        );
    }

    #[test]
    fn test_presence_ping_expires_after_freshness_window() {
        let (alice, mut bob) = connected_pair();
        let tiny_freshness = Duration::from_millis(20);

        let ping = alice.generate_presence_packet(bob.identity.routing_token);
        let inner = strip_link(&ping, &alice.link_master_key);
        bob.handle_incoming_packet(&inner).unwrap();
        assert!(bob.is_online(&alice.identity.routing_token, tiny_freshness));

        std::thread::sleep(Duration::from_millis(40));
        assert!(
            !bob.is_online(&alice.identity.routing_token, tiny_freshness),
            "must go offline once the freshness window has elapsed"
        );
    }

    #[test]
    fn test_chat_message_also_marks_peer_online() {
        let (mut alice, mut bob) = connected_pair();
        let freshness = Duration::from_secs(60);

        let (msg_pkt, _) = alice
            .create_encrypted_packet(bob.identity.routing_token, b"hi")
            .unwrap();
        let inner = strip_link(&msg_pkt, &alice.link_master_key);
        bob.handle_incoming_packet(&inner).unwrap();

        assert!(bob.is_online(&alice.identity.routing_token, freshness));
    }

    #[test]
    fn test_presence_ping_rejects_wrong_target() {
        let (alice, mut bob) = connected_pair();
        let mallory = Client::new("127.0.0.1:4430".parse().unwrap());

        // A ping Alice generated for someone else must not mark her online
        // to Bob if somehow routed to him.
        let misdirected = alice.generate_presence_packet(mallory.identity.routing_token);
        let inner = strip_link(&misdirected, &alice.link_master_key);
        bob.handle_incoming_packet(&inner).unwrap();

        assert!(!bob.is_online(&alice.identity.routing_token, Duration::from_secs(60)));
    }

    #[test]
    fn test_presence_ping_rejects_unknown_sender() {
        // Bob has no session/pending_contacts entry for a stranger — a
        // ping claiming to be from them must be silently dropped, not
        // marked online.
        let mut bob = Client::new("127.0.0.1:4430".parse().unwrap());
        let stranger = Client::new("127.0.0.1:4430".parse().unwrap());

        let ping = PresencePayload::generate(&stranger.identity, bob.identity.routing_token);
        let mut inner = vec![0x06];
        inner.extend_from_slice(&ping.to_bytes());
        bob.handle_incoming_packet(&inner).unwrap();

        assert!(!bob.is_online(&stranger.identity.routing_token, Duration::from_secs(60)));
    }

    #[test]
    fn test_presence_payload_serialization_roundtrip() {
        let alice_id = UserIdentity::generate();
        let bob_token = [7u8; 16];
        let payload = PresencePayload::generate(&alice_id, bob_token);
        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), 104);
        let parsed = PresencePayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public).is_ok());
        assert_eq!(parsed.routing_token, alice_id.routing_token);
        assert_eq!(parsed.target_token, bob_token);
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
        let forged =
            KeyExchangePayload::generate(&mallory, alice.identity.routing_token, "not-bob");
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
}
