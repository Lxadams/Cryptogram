use crate::{Client, SymmetricSessionState, UserIdentity};
use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pqcrypto_kyber::kyber768::{PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Serialize, Deserialize)]
pub struct ClientStateDto {
    pub identity: UserIdentityDto,
    pub server_addr: String,
    pub session_id: String,
    pub e2e_sessions: HashMap<String, SymmetricSessionStateDto>,
    pub pending_contacts: HashMap<String, String>,
    pub peer_kyber_keys: HashMap<String, String>,
    pub seen_session_keys: Vec<String>,
    /// Peer display names learned via KeyExchange. Older state files
    /// predate this field entirely.
    #[serde(default)]
    pub contact_names: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct UserIdentityDto {
    pub routing_token: String,
    pub ed25519_secret: String,
    pub ed25519_public: String,
    pub x25519_secret: String,
    pub x25519_public: String,
    pub kyber_public: String,
    pub kyber_secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct SymmetricSessionStateDto {
    pub root_key: String,
    // Older state files predate the send/recv chain key split and only have
    // a single `chain_key`; `into_client` mirrors it into both directions
    // when `recv_chain_key` is absent.
    #[serde(alias = "chain_key")]
    pub send_chain_key: String,
    #[serde(default)]
    pub recv_chain_key: String,
    pub send_count: u64,
    pub recv_count: u64,
    pub peer_kyber_pub: Option<String>,
    pub skip_dict: HashMap<u64, String>,
    // Older state files predate the PQ-inject replay cache.
    #[serde(default)]
    pub pq_inject_replay_cache: HashSet<String>,
    // PQ inject secrets held for a chain position not yet reached (hex).
    #[serde(default)]
    pub pending_pq: BTreeMap<u64, String>,
}

impl ClientStateDto {
    pub fn save(client: &Client, path: &str) -> Result<()> {
        let dto = Self::from_client(client);
        let json = serde_json::to_string_pretty(&dto)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Client> {
        let json = fs::read_to_string(path)?;
        let dto: ClientStateDto = serde_json::from_str(&json)?;
        dto.into_client(path)
    }

    fn from_client(client: &Client) -> Self {
        let identity = UserIdentityDto {
            routing_token: hex::encode(client.identity.routing_token),
            ed25519_secret: hex::encode(client.identity.ed25519_secret.to_bytes()),
            ed25519_public: hex::encode(client.identity.ed25519_public.as_bytes()),
            x25519_secret: hex::encode(client.identity.x25519_secret.to_bytes()),
            x25519_public: hex::encode(client.identity.x25519_public.as_bytes()),
            kyber_public: hex::encode(client.identity.kyber_public.as_bytes()),
            kyber_secret: hex::encode(client.identity.kyber_secret.as_bytes()),
        };

        let mut e2e_sessions = HashMap::new();
        for (token, state) in &client.e2e_sessions {
            let mut skip_dict = HashMap::new();
            for (k, v) in &state.skip_dict {
                skip_dict.insert(*k, hex::encode(v));
            }
            let mut pq_inject_replay_cache = HashSet::new();
            for sig in &state.pq_inject_replay_cache {
                pq_inject_replay_cache.insert(hex::encode(sig));
            }

            e2e_sessions.insert(
                hex::encode(token),
                SymmetricSessionStateDto {
                    root_key: hex::encode(state.root_key),
                    send_chain_key: hex::encode(state.send_chain_key),
                    recv_chain_key: hex::encode(state.recv_chain_key),
                    send_count: state.send_count,
                    recv_count: state.recv_count,
                    peer_kyber_pub: state
                        .peer_kyber_pub
                        .as_ref()
                        .map(|k| hex::encode(k.as_bytes())),
                    skip_dict,
                    pq_inject_replay_cache,
                    pending_pq: state
                        .pending_pq
                        .iter()
                        .map(|(seq, secret)| (*seq, hex::encode(secret)))
                        .collect(),
                },
            );
        }

        let mut pending_contacts = HashMap::new();
        for (token, key) in &client.pending_contacts {
            pending_contacts.insert(hex::encode(token), hex::encode(key.as_bytes()));
        }

        let mut peer_kyber_keys = HashMap::new();
        for (token, key) in &client.peer_kyber_keys {
            peer_kyber_keys.insert(hex::encode(token), hex::encode(key.as_bytes()));
        }

        let seen_session_keys = client.seen_session_keys.iter().map(hex::encode).collect();

        let mut contact_names = HashMap::new();
        for (token, name) in &client.contact_names {
            contact_names.insert(hex::encode(token), name.clone());
        }

        Self {
            identity,
            server_addr: client.server_addr.to_string(),
            session_id: hex::encode(client.session_id),
            e2e_sessions,
            pending_contacts,
            peer_kyber_keys,
            seen_session_keys,
            contact_names,
        }
    }

    fn into_client(self, path: &str) -> Result<Client> {
        let mut r_token = [0u8; 16];
        hex::decode_to_slice(&self.identity.routing_token, &mut r_token)?;

        let mut ed_sec = [0u8; 32];
        hex::decode_to_slice(&self.identity.ed25519_secret, &mut ed_sec)?;
        let ed25519_secret = SigningKey::from_bytes(&ed_sec);

        let mut ed_pub = [0u8; 32];
        hex::decode_to_slice(&self.identity.ed25519_public, &mut ed_pub)?;
        let ed25519_public = VerifyingKey::from_bytes(&ed_pub)?;

        let mut x_sec = [0u8; 32];
        hex::decode_to_slice(&self.identity.x25519_secret, &mut x_sec)?;
        let x25519_secret = StaticSecret::from(x_sec);

        let mut x_pub = [0u8; 32];
        hex::decode_to_slice(&self.identity.x25519_public, &mut x_pub)?;
        let x25519_public = X25519PublicKey::from(x_pub);

        let kyber_pub = PublicKey::from_bytes(&hex::decode(&self.identity.kyber_public)?)
            .map_err(|_| anyhow::anyhow!("Kyber pub err"))?;
        let kyber_sec = SecretKey::from_bytes(&hex::decode(&self.identity.kyber_secret)?)
            .map_err(|_| anyhow::anyhow!("Kyber sec err"))?;

        let identity = UserIdentity {
            routing_token: r_token,
            ed25519_secret,
            ed25519_public,
            x25519_secret,
            x25519_public,
            kyber_public: kyber_pub,
            kyber_secret: kyber_sec,
        };

        let server_addr: SocketAddr = self.server_addr.parse()?;

        let mut session_id = [0u8; 4];
        hex::decode_to_slice(&self.session_id, &mut session_id)?;

        let mut e2e_sessions = HashMap::new();
        for (hex_tok, dto_state) in self.e2e_sessions {
            let mut tok = [0u8; 16];
            hex::decode_to_slice(&hex_tok, &mut tok)?;

            let mut r_key = [0u8; 32];
            hex::decode_to_slice(&dto_state.root_key, &mut r_key)?;

            let mut sc_key = [0u8; 32];
            hex::decode_to_slice(&dto_state.send_chain_key, &mut sc_key)?;

            // Pre-split state files have no recv_chain_key at all (`#[serde(default)]`
            // leaves it empty) — mirror send into recv, matching the old
            // single-chain-key behavior this session was saved under.
            let rc_key = if dto_state.recv_chain_key.is_empty() {
                sc_key
            } else {
                let mut rc_key = [0u8; 32];
                hex::decode_to_slice(&dto_state.recv_chain_key, &mut rc_key)?;
                rc_key
            };

            let pkp = if let Some(pk_hex) = dto_state.peer_kyber_pub {
                Some(
                    PublicKey::from_bytes(&hex::decode(&pk_hex)?)
                        .map_err(|_| anyhow::anyhow!("Kyber err"))?,
                )
            } else {
                None
            };

            let mut skip_dict = HashMap::new();
            for (k, v) in dto_state.skip_dict {
                let mut mk = [0u8; 32];
                hex::decode_to_slice(&v, &mut mk)?;
                skip_dict.insert(k, mk);
            }
            let mut pq_inject_replay_cache = HashSet::new();
            for hex_sig in dto_state.pq_inject_replay_cache {
                let mut sig = [0u8; 64];
                hex::decode_to_slice(&hex_sig, &mut sig)?;
                pq_inject_replay_cache.insert(sig);
            }
            let mut pending_pq = BTreeMap::new();
            for (seq, hex_secret) in dto_state.pending_pq {
                pending_pq.insert(seq, hex::decode(&hex_secret)?);
            }

            e2e_sessions.insert(
                tok,
                SymmetricSessionState {
                    root_key: r_key,
                    send_chain_key: sc_key,
                    recv_chain_key: rc_key,
                    send_count: dto_state.send_count,
                    recv_count: dto_state.recv_count,
                    peer_kyber_pub: pkp,
                    skip_dict,
                    pq_inject_replay_cache,
                    pending_pq,
                },
            );
        }

        let mut pending_contacts = HashMap::new();
        for (hex_tok, hex_key) in self.pending_contacts {
            let mut tok = [0u8; 16];
            hex::decode_to_slice(&hex_tok, &mut tok)?;
            let mut key = [0u8; 32];
            hex::decode_to_slice(&hex_key, &mut key)?;
            pending_contacts.insert(tok, VerifyingKey::from_bytes(&key)?);
        }

        let mut peer_kyber_keys = HashMap::new();
        for (hex_tok, hex_key) in self.peer_kyber_keys {
            let mut tok = [0u8; 16];
            hex::decode_to_slice(&hex_tok, &mut tok)?;
            peer_kyber_keys.insert(
                tok,
                PublicKey::from_bytes(&hex::decode(&hex_key)?)
                    .map_err(|_| anyhow::anyhow!("Kyber err"))?,
            );
        }

        let mut seen_session_keys = HashSet::new();
        for hex_key in self.seen_session_keys {
            let mut key = [0u8; 32];
            hex::decode_to_slice(&hex_key, &mut key)?;
            seen_session_keys.insert(key);
        }

        let mut contact_names = HashMap::new();
        for (hex_tok, name) in self.contact_names {
            let mut tok = [0u8; 16];
            hex::decode_to_slice(&hex_tok, &mut tok)?;
            contact_names.insert(tok, name);
        }

        Ok(Client {
            identity,
            server_addr,
            link_master_key: [0u8; 32], // re-negotiated on boot
            session_id,                 // can reuse the stored session id, or generate new
            e2e_sessions,
            pending_contacts,
            peer_kyber_keys,
            seen_session_keys,
            state_path: path.to_string(),
            local_name: String::new(), // always re-supplied at launch, not persisted
            contact_names,
            inbox: Vec::new(),         // transient handoff buffer, not persisted
            last_seen: HashMap::new(), // live status, not persisted — see Client::last_seen
            history: None,             // attached separately once a vault key is available
            last_recorded_id: None,
            identity_store: None, // attached separately once a vault key is available
            fec_rx: Default::default(), // in-flight FEC state, not persisted
        })
    }
}

/// SQLCipher-backed replacement for the plaintext `client_state.json` file:
/// this identity's own Ed25519/X25519/Kyber secrets and e2e session state,
/// encrypted at rest with the same Argon2id-derived vault key that unlocks
/// `ChatHistory` (see `derive_vault_key`) — one passcode unlocks both
/// stores. Deliberately a single JSON blob in a one-row table rather than a
/// real relational schema: `ClientStateDto` is already the natural unit
/// this is always read and written as a whole, so a key-value table adds
/// nothing a real column layout would justify (same reasoning `ChatHistory`
/// uses per-message, just applied to a single row here).
pub struct IdentityStateStore {
    conn: Connection,
}

impl IdentityStateStore {
    /// Open (creating if absent) the SQLCipher database at `db_path`, keyed
    /// by `vault_key`. Fails fast on the wrong key — see `ChatHistory::open`'s
    /// doc comment for why the canary read matters.
    pub fn open(db_path: &Path, vault_key: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open(db_path)
            .with_context(|| format!("opening identity state db at {}", db_path.display()))?;
        conn.pragma_update(None, "key", format!("x'{}'", hex::encode(vault_key)))?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .context("incorrect vault key, or corrupt identity state database")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS client_state (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                json TEXT NOT NULL
            );",
        )?;
        Ok(Self { conn })
    }

    /// Persist `client`'s current state, overwriting whatever was saved
    /// before.
    pub fn save(&self, client: &Client) -> Result<()> {
        let dto = ClientStateDto::from_client(client);
        let json = serde_json::to_string(&dto)?;
        self.conn.execute(
            "INSERT INTO client_state (id, json) VALUES (0, ?1)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            params![json],
        )?;
        Ok(())
    }

    /// Load the previously-saved `Client`. `Ok(None)` means nothing has been
    /// saved yet; an `Err` means something *was* saved but couldn't be read
    /// back (corrupt row, or a format this build doesn't understand). The
    /// distinction matters: callers mint a fresh identity only for `None`,
    /// never on an error, or a read failure would silently replace the
    /// user's real identity. `state_path` is stamped onto the result exactly
    /// like `ClientStateDto::load` does — see `Client::state_path`'s doc
    /// comment.
    pub fn load(&self, state_path: &str) -> Result<Option<Client>> {
        let json: Option<String> = self
            .conn
            .query_row("SELECT json FROM client_state WHERE id = 0", [], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(json) = json else {
            return Ok(None);
        };
        let dto: ClientStateDto =
            serde_json::from_str(&json).context("saved identity state is unreadable")?;
        dto.into_client(state_path).map(Some)
    }
}

#[cfg(test)]
mod identity_state_store_tests {
    use super::*;
    use crate::Client;
    use std::net::SocketAddr;

    struct ScratchDb(std::path::PathBuf);

    impl ScratchDb {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "e2e-messenger-identity-state-test-{name}-{:x}.sqlite",
                rand_suffix()
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
    }

    impl Drop for ScratchDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn test_addr() -> SocketAddr {
        "127.0.0.1:4430".parse().unwrap()
    }

    #[test]
    fn test_save_and_load_roundtrip_preserves_identity() {
        let db = ScratchDb::new("roundtrip");
        let key = [5u8; 32];
        let store = IdentityStateStore::open(&db.0, &key).unwrap();

        let original = Client::new(test_addr());
        let original_token = original.identity.routing_token;
        store.save(&original).unwrap();

        let loaded = store.load(&db.0.to_string_lossy()).unwrap().unwrap();
        assert_eq!(loaded.identity.routing_token, original_token);
    }

    #[test]
    fn test_state_survives_reopen_with_same_key() {
        let db = ScratchDb::new("reopen");
        let key = [6u8; 32];
        let original_token;
        {
            let store = IdentityStateStore::open(&db.0, &key).unwrap();
            let client = Client::new(test_addr());
            original_token = client.identity.routing_token;
            store.save(&client).unwrap();
        }
        let reopened = IdentityStateStore::open(&db.0, &key).unwrap();
        let loaded = reopened.load(&db.0.to_string_lossy()).unwrap().unwrap();
        assert_eq!(loaded.identity.routing_token, original_token);
    }

    #[test]
    fn test_wrong_key_fails_to_open() {
        let db = ScratchDb::new("wrongkey");
        {
            let store = IdentityStateStore::open(&db.0, &[1u8; 32]).unwrap();
            store.save(&Client::new(test_addr())).unwrap();
        }
        assert!(IdentityStateStore::open(&db.0, &[2u8; 32]).is_err());
    }

    #[test]
    fn test_load_before_any_save_is_none() {
        let db = ScratchDb::new("empty");
        let store = IdentityStateStore::open(&db.0, &[3u8; 32]).unwrap();
        assert!(store.load(&db.0.to_string_lossy()).unwrap().is_none());
    }

    #[test]
    fn test_unreadable_saved_state_is_an_error_not_none() {
        let db = ScratchDb::new("corrupt");
        let store = IdentityStateStore::open(&db.0, &[4u8; 32]).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO client_state (id, json) VALUES (0, ?1)",
                params!["{ not a client state"],
            )
            .unwrap();
        assert!(store.load(&db.0.to_string_lossy()).is_err());
    }
}
