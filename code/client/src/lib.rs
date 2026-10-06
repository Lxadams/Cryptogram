use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pqcrypto_kyber::kyber768::*;
use pqcrypto_traits::kem::SharedSecret as _;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub mod packets;
use packets::*;
mod chunks;
mod history;
pub mod link;
mod padding;
mod storage;
mod transport;
pub use cell::proof::routing_token_for;
pub use chunks::MAX_MESSAGE_LEN;
pub use history::{ChatHistory, StoredMessage};
use std::collections::HashSet;
pub use storage::{ClientStateDto, IdentityStateStore};
pub use transport::Outgoing;
#[cfg(test)]
mod test_support;

type HmacSha256 = Hmac<Sha256>;
pub type RoutingToken = [u8; 16];
/// From `encrypt_message_payloads`: a message's inner 0x01 chunk payloads
/// and its optional 0x05 PQ inject.
type MessagePayloads = (Vec<Vec<u8>>, Option<Vec<u8>>);

// PQ injection interval: inject fresh Kyber entropy every N ratchet steps
// (one per chunk; see `create_encrypted_packets`)
const PQ_INJECT_INTERVAL: u64 = 5;

// Maximum number of skipped message keys to retain
const MAX_SKIP_DICT_SIZE: usize = 500;

// Domain-separation salt for HKDF derivations
const HKDF_SALT: &[u8] = b"e2e-messenger-v1";

// Maximum timestamp drift allowed (seconds)
const MAX_TIMESTAMP_DRIFT: u64 = 300;

// Most PQ refreshes held per session waiting for the receive chain to reach
// their position. Refreshes come at least PQ_INJECT_INTERVAL steps apart and
// messages more than 100 steps ahead are rejected anyway, so this is ample.
const MAX_PENDING_PQ_INJECTS: usize = 32;

// How long a connection request from someone who isn't a contact is kept
// to show the user (see `Client::connection_requests`), and how many.
const CONNECTION_REQUEST_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_CONNECTION_REQUESTS: usize = 8;

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

pub struct UserIdentity {
    /// Always `routing_token_for(&token_public)`.
    pub routing_token: RoutingToken,
    /// Signs our hello to the relay, proving the routing token is ours (see
    /// `cell::proof`).
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

pub struct Client {
    pub identity: UserIdentity,
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
    /// Contacts we've sent a KeyExchange asking for a SessionEstablish, and
    /// haven't had one from yet, so we ask each of them only once (see the
    /// 0x02 branch of `handle_incoming_packet`). Live state, like `inbox`.
    awaiting_session_est: HashSet<RoutingToken>,
    /// Recent KeyExchanges from people who aren't contacts, oldest first,
    /// so a front end can prompt the user to add them back (see
    /// `connection_requests`). Just the token and when: nothing else they
    /// sent is verified until the user scans their code. Live state, like
    /// `inbox`.
    connection_requests: Vec<(RoutingToken, Instant)>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// A brand-new identity with no contacts. The relay it talks to is the
    /// link's business (see `link`), not part of this state.
    pub fn new() -> Self {
        Self {
            identity: UserIdentity::generate(),
            e2e_sessions: HashMap::new(),
            pending_contacts: HashMap::new(),
            peer_kyber_keys: HashMap::new(),
            seen_session_keys: HashSet::new(),
            state_path: state_file_path(),
            local_name: String::new(),
            contact_names: HashMap::new(),
            inbox: Vec::new(),
            history: None,
            identity_store: None,
            last_recorded_id: None,
            reassembler: chunks::Reassembler::default(),
            fec_rx: Default::default(),
            awaiting_session_est: HashSet::new(),
            connection_requests: Vec::new(),
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
    /// established session, its Kyber key and learned display name, then
    /// persists the change. This is the *local*
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
        self.awaiting_session_est.remove(&token);
        self.reassembler.forget(&token);
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

    /// Trust a contact's routing token and Ed25519 key, as scanned from
    /// their QR code (or pasted), and return the KeyExchange to send them.
    /// Only contacts added this way can start a session with us, so both
    /// sides add each other; the session comes up once both have.
    pub fn add_contact(&mut self, token: RoutingToken, ed25519_public: VerifyingKey) -> Outgoing {
        self.pending_contacts.insert(token, ed25519_public);
        self.dismiss_connection_request(&token);
        // Re-adding a contact whose keys we have asks them for a new
        // session, if they're the one who sends it.
        if self.peer_kyber_keys.contains_key(&token) && !self.establishes_session_with(&token) {
            self.awaiting_session_est.insert(token);
        }
        self.create_kx_request(token)
    }

    /// People who tried to connect but aren't contacts, newest first. Their
    /// KeyExchange was dropped (see the 0x02 branch of
    /// `handle_incoming_packet`); adding them with `add_contact`, by
    /// scanning their code, is what accepts it. Only the token is kept, as
    /// nothing else they sent is verified.
    pub fn connection_requests(&self) -> Vec<RoutingToken> {
        self.connection_requests
            .iter()
            .rev()
            .filter(|(_, at)| at.elapsed() < CONNECTION_REQUEST_TTL)
            .map(|(token, _)| *token)
            .collect()
    }

    /// Stop listing `token`'s connection request, until they send another.
    pub fn dismiss_connection_request(&mut self, token: &RoutingToken) {
        self.connection_requests.retain(|(t, _)| t != token);
    }

    fn note_connection_request(&mut self, token: RoutingToken) {
        self.connection_requests
            .retain(|(t, at)| *t != token && at.elapsed() < CONNECTION_REQUEST_TTL);
        if self.connection_requests.len() >= MAX_CONNECTION_REQUESTS {
            self.connection_requests.remove(0);
        }
        self.connection_requests.push((token, Instant::now()));
    }

    /// Our KeyExchange for `target_token`, as an FEC object (see
    /// `transport`) ready for the link.
    pub fn create_kx_request(&self, target_token: RoutingToken) -> Outgoing {
        self.control_object(target_token, &self.kx_payload(target_token))
    }

    /// Our KeyExchange for `target_token` as a bare 0x02 inner payload.
    pub(crate) fn kx_payload(&self, target_token: RoutingToken) -> Vec<u8> {
        let payload = KeyExchangePayload::generate(
            &self.identity,
            target_token,
            &self.local_name,
            self.peer_kyber_keys.contains_key(&target_token),
        );
        let mut inner = vec![0x02];
        inner.extend_from_slice(&payload.to_bytes());
        inner
    }

    /// A contact request (`inner`, a 0x02 or 0x04 payload) as an FEC
    /// object of plain symbols.
    fn control_object(&self, target_token: RoutingToken, inner: &[u8]) -> Outgoing {
        transport::encode_control(&self.identity.routing_token, &target_token, inner)
            .expect("a contact request is a fixed size well inside one FEC object")
    }

    /// Whether we're the one of the two contacts who sends the
    /// SessionEstablish: whoever has the lower routing token. Both work it
    /// out the same way, so however their KeyExchanges cross, only one of
    /// them makes the session.
    fn establishes_session_with(&self, peer: &RoutingToken) -> bool {
        self.identity.routing_token < *peer
    }

    pub fn create_session_est_packet(
        &self,
        target_token: RoutingToken,
        bob_x25519: &X25519PublicKey,
        bob_kyber: &PublicKey,
    ) -> (Outgoing, SymmetricSessionState) {
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
        (self.control_object(target_token, &inner), session_state)
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

    /// Encrypt a message as bare inner payloads, one per chunk, then an
    /// optional PQ inject to deliver after them. Every one is safe to
    /// deliver more than once, in any order. Test-only — real front ends
    /// send with `create_message`, which never lets the inject travel apart
    /// from its message.
    #[cfg(test)]
    pub(crate) fn create_encrypted_packets(
        &mut self,
        target_token: RoutingToken,
        plaintext: &[u8],
    ) -> Result<MessagePayloads> {
        self.encrypt_message_payloads(target_token, plaintext)
    }

    /// Encrypt a message for a lossy link: its chunks and (when due) its PQ
    /// inject travel together as one FEC object of sealed symbols — see
    /// `transport`. Hand the result to the link (`link::RelayLink::send`).
    /// Messages over `MAX_MESSAGE_LEN` bytes are rejected before the
    /// ratchet moves.
    pub fn create_message(
        &mut self,
        target_token: RoutingToken,
        plaintext: &[u8],
    ) -> Result<Outgoing> {
        let (msg_payloads, pq_payload) = self.encrypt_message_payloads(target_token, plaintext)?;
        let session = &self.e2e_sessions[&target_token];
        // The seq number of the message's last chunk doubles as its FEC
        // object id: unique within the session, unlike a random id.
        // (`FecReceiver` keeps each session's ids apart.)
        let object_id = (session.send_count - 1) as u32;
        transport::encode_message(
            &session.root_key,
            &self.identity.routing_token,
            &target_token,
            object_id,
            &msg_payloads,
            pq_payload.as_deref(),
        )
    }

    /// Ratchet-encrypt `plaintext` for `target_token`. Returns the inner (not
    /// yet link-encrypted) 0x01 payload of each chunk and, when due, the 0x05
    /// PQ inject payload that follows them.
    ///
    /// The message is split into chunks (see `chunks`), each padded to a
    /// fixed size (see `padding`) and encrypted as its own ratcheted chat
    /// payload, so every one is the same size whatever the message length.
    /// Messages over `chunks::MAX_MESSAGE_LEN` bytes are rejected before the
    /// ratchet moves.
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

    /// The checks every signed control payload (KeyExchange,
    /// SessionEstablish) must pass before anything else: it's
    /// addressed to us, and its timestamp is within `MAX_TIMESTAMP_DRIFT` of
    /// our clock. Logs and returns `false` if not.
    fn accepts_payload(&self, what: &str, target_token: &RoutingToken, timestamp: u64) -> bool {
        if !self.is_addressed_to_us(what, target_token) {
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

    /// The first of `accepts_payload`'s checks, on its own for PQInject: a
    /// refresh can legitimately arrive long after it was sent (queued at the
    /// relay while we were offline, or resent), and its `applies_at`
    /// position already makes a replayed copy harmless, so it skips the
    /// timestamp check.
    fn is_addressed_to_us(&self, what: &str, target_token: &RoutingToken) -> bool {
        if target_token.ct_eq(&self.identity.routing_token).unwrap_u8() == 0 {
            println!(">> [SECURITY ALERT] Dropped {what}! It was bound to a different target.");
            return false;
        }
        true
    }

    /// Handle one inner payload the relay delivered (see `link`). Returns
    /// the reply to send back, if there is one: a KeyExchange or
    /// SessionEstablish while contacts are connecting.
    pub fn handle_incoming_packet(&mut self, payload: &[u8]) -> Result<Option<Outgoing>> {
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
                if !self.accepts_payload("KeyExchange", &kx.target_token, kx.timestamp) {
                    return Ok(None);
                }
                let peer_token = kx.routing_token;
                let Some(expected_ed25519) = self.pending_contacts.get(&peer_token) else {
                    println!(
                        ">> Ignored a connection request from {}, who isn't one of your contacts. Add each other to connect.",
                        hex::encode(&peer_token[0..4])
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
                        hex::encode(&peer_token[0..4])
                    );
                    return Ok(None);
                }

                // Store peer's Kyber key for future PQ injections
                self.peer_kyber_keys.insert(peer_token, kx.kyber_public);

                // Learn the peer's self-chosen name (if any) the moment
                // their KeyExchange arrives, so it shows up for pending AND
                // established contacts.
                if kx.name.is_empty() {
                    self.contact_names.remove(&peer_token);
                } else {
                    self.contact_names.insert(peer_token, kx.name.clone());
                }
                self.save();

                // Each side sends its KeyExchange when it adds the other,
                // and whoever adds first has theirs dropped. So a contact
                // without our keys gets ours again, and the one of us who
                // establishes (see `establishes_session_with`) does so only
                // once the other has our keys, or their PQ injections would
                // have nothing to encapsulate to.
                let establisher = self.establishes_session_with(&peer_token);
                if !kx.has_peer_keys {
                    if !establisher {
                        self.awaiting_session_est.insert(peer_token);
                    }
                    return Ok(Some(self.create_kx_request(peer_token)));
                }
                if establisher {
                    println!(">> Verified keys against QR code!");
                    let (est_packet, session) = self.create_session_est_packet(
                        peer_token,
                        &kx.x25519_public,
                        &kx.kyber_public,
                    );
                    self.e2e_sessions.insert(peer_token, session);
                    self.save();
                    println!(
                        ">> E2E Session established with {}!",
                        hex::encode(&peer_token[0..4])
                    );
                    return Ok(Some(est_packet));
                }
                // They have our keys, so they're waiting on us to ask for a
                // session, unless we have one or already asked.
                if self.e2e_sessions.contains_key(&peer_token)
                    || !self.awaiting_session_est.insert(peer_token)
                {
                    return Ok(None);
                }
                Ok(Some(self.create_kx_request(peer_token)))
            }
            0x04 => {
                // SessionEstablish

                if let Ok(est) = SessionEstablishPayload::from_bytes(pkt_data) {
                    if !self.accepts_payload("SessionEstablish", &est.target_token, est.timestamp) {
                        return Ok(None);
                    }
                    // Only the contact with the lower routing token sends
                    // one (see `establishes_session_with`).
                    if self.establishes_session_with(&est.routing_token) {
                        println!(
                            ">> Dropped SessionEstablish from {}: this side establishes the session.",
                            hex::encode(&est.routing_token[0..4])
                        );
                        return Ok(None);
                    }
                    if let Some(alice_pub) = self.pending_contacts.get(&est.routing_token) {
                        if est.verify(alice_pub).is_ok() {
                            self.awaiting_session_est.remove(&est.routing_token);
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
                    // Only what `create_message` bundles (a message and
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
            0x08 => {
                // Contact request symbol: [16-byte sender token | FEC
                // packet] — see `transport`. Plain, since there's no session
                // to seal it under yet: nothing is trusted until the
                // KeyExchange or SessionEstablish inside checks out.
                if pkt_data.len() < 16 {
                    return Err(anyhow!("Contact request symbol too small"));
                }
                let sender_token: RoutingToken = pkt_data[..16].try_into().unwrap();
                let object = match self.fec_rx.reassemble_control(
                    sender_token,
                    &pkt_data[16..],
                    Instant::now(),
                ) {
                    Ok(Some(object)) => object,
                    Ok(None) => return Ok(None),
                    Err(e) => {
                        println!(">> Dropped contact request symbol: {e}");
                        return Ok(None);
                    }
                };
                // Exactly one KeyExchange or SessionEstablish, from the
                // sender its symbols name.
                match transport::unbundle(&object).as_deref() {
                    Some([part])
                        if matches!(part.first(), Some(0x02 | 0x04))
                            && part.get(1..17) == Some(&sender_token[..]) =>
                    {
                        self.handle_incoming_packet(part)
                    }
                    _ => {
                        println!(">> Dropped a malformed contact request.");
                        Ok(None)
                    }
                }
            }
            _ => Ok(None),
        }
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

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        connect, connected_pair, deliver, establisher_and_responder, exchange, new_client, session,
    };
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
        let mut client = Client::new();
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
        let mut alice = Client::new();
        let mut bob = Client::new();

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
        let inner_msg = msg_packet[0].to_vec();
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
        let payload = KeyExchangePayload::generate(&alice_id, bob_token, "", false);
        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), 1385);
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
        assert!(KeyExchangePayload::from_bytes(&[0u8; 1384]).is_err());
        assert!(KeyExchangePayload::from_bytes(&[0u8; 1386]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 0]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 1223]).is_err());
        assert!(SessionEstablishPayload::from_bytes(&[0u8; 1225]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 0]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 1199]).is_err());
        assert!(PQInjectPayload::from_bytes(&[0u8; 1201]).is_err());
    }

    #[test]
    fn test_edge_case_empty_payload_handling() {
        let mut client = Client::new();
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
        let payload = KeyExchangePayload::generate(&alice_id, [0u8; 16], "", false);
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
        let mut payload = KeyExchangePayload::generate(&alice_id, [0u8; 16], "", false);
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
        let payload = KeyExchangePayload::generate(&alice_id, charlie_token, "", false);
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
        let mut alice = Client::new();
        let mut bob = Client::new();
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
        let inner = packet[0].to_vec();
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
        let mut alice = Client::new();
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
        let mut alice = Client::new();
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
        let mut alice = Client::new();
        let mut bob = Client::new();

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
            let inner = msg_pkt[0].to_vec();
            bob.handle_incoming_packet(&inner).unwrap();

            // If PQ inject was generated, Bob processes it too
            if let Some(pq) = pq_pkt {
                let pq_inner = pq.to_vec();
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
        let mut alice = Client::new();
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
    }

    /// The establisher (lower token) adds the responder first, so its
    /// KeyExchange is dropped. When the responder adds it back, each sends
    /// the other its keys before the session is made.
    #[test]
    fn test_handshake_when_establisher_adds_first() {
        let (mut e, mut r) = establisher_and_responder();
        let early = e.add_contact(r.identity.routing_token, r.identity.ed25519_public);
        assert_eq!(exchange(&mut e, &mut r, early), [0x02], "dropped");
        assert!(r.peer_kyber_keys.is_empty() && r.contact_names.is_empty());

        let kx = r.add_contact(e.identity.routing_token, e.identity.ed25519_public);
        assert_eq!(exchange(&mut r, &mut e, kx), [0x02, 0x02, 0x02, 0x04]);
        assert_one_session_with_pq_keys(&e, &r);
    }

    #[test]
    fn test_handshake_when_responder_adds_first() {
        let (mut e, mut r) = establisher_and_responder();
        let early = r.add_contact(e.identity.routing_token, e.identity.ed25519_public);
        assert_eq!(exchange(&mut r, &mut e, early), [0x02], "dropped");

        let kx = e.add_contact(r.identity.routing_token, r.identity.ed25519_public);
        assert_eq!(exchange(&mut e, &mut r, kx), [0x02, 0x02, 0x04]);
        assert_one_session_with_pq_keys(&e, &r);
    }

    /// Both add each other before either KeyExchange arrives, so the two
    /// cross. Only one SessionEstablish may come of it, or each side would
    /// end up on the other's session.
    #[test]
    fn test_handshake_when_both_add_before_hearing_back() {
        let (mut e, mut r) = establisher_and_responder();
        let kx_e = e.add_contact(r.identity.routing_token, r.identity.ed25519_public);
        let kx_r = r.add_contact(e.identity.routing_token, e.identity.ed25519_public);
        let r_reply = deliver(&mut r, kx_e).unwrap();
        let e_reply = deliver(&mut e, kx_r).unwrap();

        assert_eq!(exchange(&mut r, &mut e, r_reply), [0x02, 0x04]);
        assert_eq!(
            exchange(&mut e, &mut r, e_reply),
            [0x02],
            "the responder already asked for (and got) the session"
        );
        assert_one_session_with_pq_keys(&e, &r);
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

            let kx =
                remover.add_contact(other.identity.routing_token, other.identity.ed25519_public);
            exchange(remover, other, kx);
            assert_one_session_with_pq_keys(&e, &r);
            assert_ne!(session(&e, &r).root_key, old_root, "a new session");
        }
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
            );
            let mut packet = vec![0x02];
            packet.extend_from_slice(&kx.to_bytes());
            assert!(bob.handle_incoming_packet(&packet).unwrap().is_none());
        }
        assert!(bob.pending_contacts.is_empty());
        assert!(bob.peer_kyber_keys.is_empty());
        assert!(bob.contact_names.is_empty());
        assert!(bob.awaiting_session_est.is_empty());
        assert_eq!(bob.connection_requests().len(), MAX_CONNECTION_REQUESTS);
    }

    /// A stranger's request is listed (newest first) so the user can be
    /// asked to scan them back, until they do, or dismiss it.
    #[test]
    fn test_connection_requests_listed_until_added_or_dismissed() {
        let (mut alice, mut bob, mut carol) = (new_client(), new_client(), new_client());
        let request = |from: &mut Client, to: &mut Client| {
            let kx = from.add_contact(to.identity.routing_token, to.identity.ed25519_public);
            assert_eq!(exchange(from, to, kx), [0x02], "dropped");
        };
        request(&mut alice, &mut bob);
        request(&mut carol, &mut bob);
        request(&mut alice, &mut bob); // again: moves to the front, once
        assert_eq!(
            bob.connection_requests(),
            [alice.identity.routing_token, carol.identity.routing_token]
        );

        bob.dismiss_connection_request(&carol.identity.routing_token);
        assert_eq!(bob.connection_requests(), [alice.identity.routing_token]);

        // Scanning Alice back accepts: no longer a request, and connected.
        let kx = bob.add_contact(alice.identity.routing_token, alice.identity.ed25519_public);
        assert!(bob.connection_requests().is_empty());
        exchange(&mut bob, &mut alice, kx);
        assert!(bob.e2e_sessions.contains_key(&alice.identity.routing_token));
        assert!(alice.connection_requests().is_empty());
        crate::test_support::cleanup(&[&alice, &bob, &carol]);
    }

    /// Only an intact KeyExchange addressed to us gets noted: not a
    /// tampered one, or one meant for someone else.
    #[test]
    fn test_misaddressed_or_forged_request_is_not_noted() {
        let mut bob = new_client();
        let stranger = UserIdentity::generate();
        let misaddressed = KeyExchangePayload::generate(&stranger, [0xCC; 16], "", false);
        let mut forged =
            KeyExchangePayload::generate(&stranger, bob.identity.routing_token, "", false);
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
        let (e, r) = establisher_and_responder();
        let mut e = e;
        e.pending_contacts
            .insert(r.identity.routing_token, r.identity.ed25519_public);
        e.peer_kyber_keys
            .insert(r.identity.routing_token, r.identity.kyber_public);
        let (est, _) = r.create_session_est_packet(
            e.identity.routing_token,
            &e.identity.x25519_public,
            &e.identity.kyber_public,
        );
        assert!(deliver(&mut e, est).is_none());
        assert!(e.e2e_sessions.is_empty());
    }

    /// Our hello to the relay proves we own our routing token (see
    /// `cell::proof`), with the key the identity keeps for that.
    #[test]
    fn test_hello_proves_routing_token_ownership() {
        let client = new_client();
        let (access, binding) = ([1u8; 32], [2u8; 32]);
        let hello = cell::proof::hello(&access, &client.identity.token_secret, &binding);
        assert_eq!(
            cell::proof::verify_hello(&hello, &access, &binding),
            Ok(client.identity.routing_token)
        );
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
        let inner_msg = msg_to_bob[0].to_vec();
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
        let inner_msg2 = msg_to_bob2[0].to_vec();
        bob.handle_incoming_packet(&inner_msg2).unwrap();
        assert_eq!(bob.inbox.last().unwrap().1, b"hi bob, it's the new alice");

        let (msg_to_alice2, _) = bob
            .create_encrypted_packets(alice2.identity.routing_token, b"hi new alice, it's bob")
            .unwrap();
        let inner_msg3 = msg_to_alice2[0].to_vec();
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
        let mut alice = Client::new();
        let mut bob = Client::new();
        connect(&mut alice, &mut bob);

        // Send 5 messages with PQ inject at #5
        for i in 0..5 {
            let (msg_pkt, pq_pkt) = alice
                .create_encrypted_packets(
                    bob.identity.routing_token,
                    format!("Hello {}", i + 1).as_bytes(),
                )
                .unwrap();
            let msg_inner = msg_pkt[0].to_vec();
            bob.handle_incoming_packet(&msg_inner).unwrap();
            if let Some(pq) = pq_pkt {
                assert_eq!(i, 4, "PQ inject must only trigger at message 5");
                let pq_inner = pq.to_vec();
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
        let msg6_inner = msg6[0].to_vec();
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
    /// that.
    fn identity_establishing_with(client: &Client) -> UserIdentity {
        loop {
            let id = UserIdentity::generate();
            if id.routing_token < client.identity.routing_token {
                return id;
            }
        }
    }

    #[test]
    fn test_attack_session_overwrite_prevention() {
        let mut bob = Client::new();
        let alice_id = identity_establishing_with(&bob);
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
        let mut bob = Client::new();
        let alice_id = identity_establishing_with(&bob);
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
        let mut bob = Client::new();
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

    #[test]
    fn test_edge_case_seen_session_keys_exhaustion() {
        let mut bob = Client::new();

        // Insert a dummy pending contact to allow verification
        let alice_id = identity_establishing_with(&bob);
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

    #[test]
    fn test_edge_case_timestamp_rejection_via_handler() {
        // Sends a stale-timestamp KeyExchange through handle_incoming_packet
        // and verifies it is rejected (fixes incomplete test from review)
        let mut bob = Client::new();
        let alice_id = UserIdentity::generate();
        bob.pending_contacts
            .insert(alice_id.routing_token, alice_id.ed25519_public);

        // Generate a valid payload, then manually set a stale timestamp and re-sign
        let mut payload =
            KeyExchangePayload::generate(&alice_id, bob.identity.routing_token, "", false);
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
        msg.extend_from_slice(&[0u8; 32]); // empty name
        msg.push(0); // has_peer_keys
        payload.signature = alice_id.ed25519_secret.sign(&msg);
        assert!(payload.verify(&alice_id.ed25519_public).is_ok());

        let mut packet = vec![0x02];
        packet.extend_from_slice(&payload.to_bytes());
        let result = bob.handle_incoming_packet(&packet).unwrap();
        assert!(
            result.is_none(),
            "Stale timestamp must cause packet to be dropped"
        );
        assert!(
            !bob.peer_kyber_keys.contains_key(&alice_id.routing_token),
            "Stale KX must not be taken in"
        );
    }

    #[test]
    fn test_edge_case_target_misbinding_via_handler() {
        // Sends a KeyExchange bound to Charlie through Bob's handler
        // and verifies Bob drops it (fixes incomplete test from review)
        let mut bob = Client::new();
        let alice_id = UserIdentity::generate();
        bob.pending_contacts
            .insert(alice_id.routing_token, alice_id.ed25519_public);

        let mut charlie_token = [0u8; 16];
        charlie_token[0] = 0xCC;
        // Alice signs a KX intended for Charlie, NOT Bob
        let payload = KeyExchangePayload::generate(&alice_id, charlie_token, "", false);
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
    fn test_edge_case_session_establish_replay_detection() {
        // Sends the same SessionEstablish twice; second must be dropped
        let (mut alice, mut bob) = establisher_and_responder();
        alice
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);
        alice
            .peer_kyber_keys
            .insert(bob.identity.routing_token, bob.identity.kyber_public);
        bob.add_contact(alice.identity.routing_token, alice.identity.ed25519_public);
        bob.peer_kyber_keys
            .insert(alice.identity.routing_token, alice.identity.kyber_public);

        // Bob (who has Alice's keys) asks; Alice sends SessionEstablish
        let kx = bob.kx_payload(alice.identity.routing_token);
        let alice_reply = alice.handle_incoming_packet(&kx).unwrap().unwrap();

        // Bob processes SessionEstablish — first time should succeed
        let est_inner = crate::test_support::control_payload(alice_reply);
        assert_eq!(est_inner[0], 0x04);
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
        crate::test_support::cleanup(&[&alice, &bob]);
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
        use pqcrypto_traits::kem::Ciphertext as _;
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
        let mut original = Client::new();

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
        assert_eq!(
            orig_sess.recv_pq_injects.pending,
            load_sess.recv_pq_injects.pending
        );
        assert_eq!(load_sess.recv_pq_injects.applied_through, 5);

        // Verify pending contacts
        assert!(loaded.pending_contacts.contains_key(&peer_token));

        // Verify seen_session_keys
        assert!(loaded.seen_session_keys.contains(&[0xDD; 32]));

        // Clean up
        let _ = std::fs::remove_file(tmp_path);
    }
    #[test]
    fn test_concurrent_multi_peer_out_of_order() {
        let mut alice = Client::new();
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
                (pkts[0].clone(), pq)
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

    /// Every chunk's 0x01 payload: type, sender token, seq number, nonce,
    /// the padded block, and the AEAD tag.
    const CHAT_PAYLOAD_LEN: usize = 1 + 16 + 8 + 24 + padding::PADDED_LEN + 16;

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
                CHAT_PAYLOAD_LEN,
                "chat packet size must not depend on message length"
            );
            let inner = pkts[0].to_vec();
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
        assert!(pkts.iter().all(|p| p.len() == CHAT_PAYLOAD_LEN));

        for pkt in pkts.iter().rev().take(2) {
            let inner = pkt.to_vec();
            bob.handle_incoming_packet(&inner).unwrap();
            assert!(
                bob.drain_inbox().is_empty(),
                "nothing reaches the inbox until every chunk is in"
            );
        }
        let inner = pkts[0].to_vec();
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
            bob.handle_incoming_packet(&pkt.to_vec()).unwrap();
        }

        // 12 chunks: send_count 3 -> 15 crosses three intervals, but gets
        // exactly one inject, after the last chunk.
        let long = vec![b'y'; 12 * chunks::CHUNK_DATA_LEN];
        let (pkts, pq) = alice.create_encrypted_packets(bob_token, &long).unwrap();
        assert_eq!(pkts.len(), 12);
        let pq = pq.expect("crossing an interval must produce a PQ inject");
        for pkt in pkts.iter().chain([&pq]) {
            bob.handle_incoming_packet(&pkt.to_vec()).unwrap();
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
        bob.handle_incoming_packet(&next[0].to_vec()).unwrap();
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
        let inner = next[0].to_vec();
        bob.handle_incoming_packet(&inner).unwrap();
        let inbox = bob.drain_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].1, b"hi");
    }

    #[test]
    fn test_relay_dummy_packet_is_ignored() {
        let (_alice, mut bob) = connected_pair();
        // A chat-message-sized inner payload of type 0x00, what the relay's
        // cover traffic used to carry before idle cells became plain padding.
        let dummy_inner = [0u8; 1 + 16 + 8 + 24 + padding::PADDED_LEN + 16];
        assert!(bob.handle_incoming_packet(&dummy_inner).unwrap().is_none());
        assert!(bob.drain_inbox().is_empty());
    }

    #[test]
    fn test_forged_key_exchange_cannot_rename_or_rekey_a_known_contact() {
        // Mallory claims Bob's routing token but signs with her own key.
        // Alice already trusts Bob's real key, so the KX must be dropped
        // *without* first overwriting Bob's name or stored Kyber key.
        let mut alice = Client::new();
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
            KeyExchangePayload::generate(&mallory, alice.identity.routing_token, "not-bob", false);
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
