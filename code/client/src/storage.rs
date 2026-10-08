use crate::ordering::{DeliveryOrder, HeldMessage};
use crate::pq::{Ciphertext, PublicKey, SecretKey};
use crate::transport::{Parked, ParkedPayloads};
use crate::{
    AddIds, Client, RecvPqInjects, SessionOffer, SessionSetup, SymmetricSessionState, UserIdentity,
    first_add_id, routing_token_for, unlinked,
};
use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Serialize, Deserialize)]
pub struct ClientStateDto {
    pub identity: UserIdentityDto,
    pub server_addr: String,
    // Older state files also carry the link's `session_id`, which is
    // ignored: every run gets its own link from its handshake.
    pub e2e_sessions: HashMap<String, SymmetricSessionStateDto>,
    pub pending_contacts: HashMap<String, String>,
    pub peer_kyber_keys: HashMap<String, String>,
    /// Peer display names learned via KeyExchange. Older state files
    /// predate this field entirely.
    #[serde(default)]
    pub contact_names: HashMap<String, String>,
    // Contacts' X25519 keys, add IDs, how each session came about, the
    // add-ID counter, whether connection requests are muted and whether
    // notifications may name senders (see `Client`). Older state files predate all of them, and may still carry
    // the `seen_session_keys` they replaced, which is ignored.
    #[serde(default)]
    pub peer_x25519_keys: HashMap<String, String>,
    #[serde(default)]
    pub add_ids: HashMap<String, AddIdsDto>,
    #[serde(default)]
    pub session_setups: HashMap<String, SessionSetupDto>,
    #[serde(default)]
    pub next_add_id: u32,
    #[serde(default)]
    pub requests_muted: bool,
    #[serde(default)]
    pub notify_with_names: bool,
}

#[derive(Serialize, Deserialize)]
pub struct AddIdsDto {
    pub mine: u32,
    pub theirs: u32,
}

#[derive(Serialize, Deserialize)]
pub struct SessionSetupDto {
    pub establisher_add_id: u32,
    pub responder_add_id: u32,
    /// Hex, while the responder hasn't confirmed the session.
    pub offer: Option<SessionOfferDto>,
}

#[derive(Serialize, Deserialize)]
pub struct SessionOfferDto {
    pub eph_x25519_pub: String,
    pub kyber_ct: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserIdentityDto {
    /// Always derived from `token_secret` on load; kept for readability.
    pub routing_token: String,
    /// The key the routing token is a hash of (see `routing_token_for`).
    /// Older state files predate it, and had a random routing token that
    /// can't be proved to the relay, so they get a new token on load.
    #[serde(default)]
    pub token_secret: String,
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
    // PQ refreshes waiting for the receive chain to reach their position,
    // and the latest one applied (see `RecvPqInjects`). Older state files
    // predate both, and may still carry the `pq_inject_replay_cache` these
    // replaced, which is ignored.
    #[serde(default)]
    pub pending_pq_injects: HashMap<u64, String>,
    #[serde(default)]
    pub pq_applied_through: u64,
    // Where handing the peer's messages over in order is up to, and the
    // ones held for an earlier message (see `DeliveryOrder`). Older state
    // files predate both, so their next message is handed over as it comes.
    #[serde(default)]
    pub delivery_next: Option<u64>,
    #[serde(default)]
    pub held_messages: Vec<HeldMessageDto>,
    // The peer's payloads waiting for a PQ inject (see `ParkedPayloads`).
    // Older state files predate them.
    #[serde(default)]
    pub parked_payloads: Vec<ParkedDto>,
}

/// A `Parked` payload, by its seq number.
#[derive(Serialize, Deserialize)]
pub struct ParkedDto {
    pub seq: u64,
    pub payload: String,
    pub parked_at_ms: u64,
}

/// A `HeldMessage`, by the ratchet position of its first chunk.
#[derive(Serialize, Deserialize)]
pub struct HeldMessageDto {
    pub first: u64,
    pub last: u64,
    pub text: Option<String>,
    pub held_at_ms: u64,
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
            token_secret: hex::encode(client.identity.token_secret.to_bytes()),
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
            let mut pending_pq_injects = HashMap::new();
            for (position, secret) in &state.recv_pq_injects.pending {
                pending_pq_injects.insert(*position, hex::encode(secret));
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
                    pending_pq_injects,
                    pq_applied_through: state.recv_pq_injects.applied_through,
                    delivery_next: Some(state.delivery.next),
                    held_messages: state
                        .delivery
                        .held
                        .iter()
                        .map(|(&first, held)| HeldMessageDto {
                            first,
                            last: held.last,
                            text: held.text.as_ref().map(hex::encode),
                            held_at_ms: held.held_at_ms,
                        })
                        .collect(),
                    parked_payloads: state
                        .parked
                        .0
                        .iter()
                        .map(|(&seq, parked)| ParkedDto {
                            seq,
                            payload: hex::encode(&parked.payload),
                            parked_at_ms: parked.parked_at_ms,
                        })
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

        let mut contact_names = HashMap::new();
        for (token, name) in &client.contact_names {
            contact_names.insert(hex::encode(token), name.clone());
        }

        let peer_x25519_keys = client
            .peer_x25519_keys
            .iter()
            .map(|(token, key)| (hex::encode(token), hex::encode(key.as_bytes())))
            .collect();
        let add_ids = client
            .add_ids
            .iter()
            .map(|(token, ids)| {
                let dto = AddIdsDto {
                    mine: ids.mine,
                    theirs: ids.theirs,
                };
                (hex::encode(token), dto)
            })
            .collect();
        let session_setups = client
            .session_setups
            .iter()
            .map(|(token, setup)| {
                let offer = setup.offer.map(|offer| SessionOfferDto {
                    eph_x25519_pub: hex::encode(offer.eph_x25519_pub.as_bytes()),
                    kyber_ct: hex::encode(offer.kyber_ct.as_bytes()),
                });
                let dto = SessionSetupDto {
                    establisher_add_id: setup.establisher_add_id,
                    responder_add_id: setup.responder_add_id,
                    offer,
                };
                (hex::encode(token), dto)
            })
            .collect();

        Self {
            identity,
            server_addr: client.server_addr.to_string(),
            e2e_sessions,
            pending_contacts,
            peer_kyber_keys,
            contact_names,
            peer_x25519_keys,
            add_ids,
            session_setups,
            next_add_id: client.next_add_id,
            requests_muted: client.requests_muted,
            notify_with_names: client.notify_with_names,
        }
    }

    fn into_client(mut self, path: &str) -> Result<Client> {
        let mut token_sec = [0u8; 32];
        if self.identity.token_secret.is_empty() {
            // Its contacts know it by the old token, which nobody can
            // receive at any more, and it knows them by theirs, which they
            // lose the same way. Kept, they'd look connected while nothing
            // got through.
            tracing::warn!(
                "This identity predates signed routing tokens, so it gets a new routing token, and its contacts are removed: they can't reach it at the new one. Add each other again."
            );
            OsRng.fill_bytes(&mut token_sec);
            self.e2e_sessions.clear();
            self.pending_contacts.clear();
            self.peer_kyber_keys.clear();
            self.contact_names.clear();
            self.peer_x25519_keys.clear();
            self.add_ids.clear();
            self.session_setups.clear();
        } else {
            hex::decode_to_slice(&self.identity.token_secret, &mut token_sec)?;
        }
        let token_secret = SigningKey::from_bytes(&token_sec);
        let token_public = token_secret.verifying_key();

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
            routing_token: routing_token_for(&token_public),
            token_secret,
            token_public,
            ed25519_secret,
            ed25519_public,
            x25519_secret,
            x25519_public,
            kyber_public: kyber_pub,
            kyber_secret: kyber_sec,
        };

        let server_addr: SocketAddr = self.server_addr.parse()?;

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
            let mut pending_pq_injects = BTreeMap::new();
            for (position, hex_secret) in dto_state.pending_pq_injects {
                let mut secret = [0u8; 32];
                hex::decode_to_slice(&hex_secret, &mut secret)?;
                pending_pq_injects.insert(position, secret);
            }
            let mut delivery =
                DeliveryOrder::starting_at(dto_state.delivery_next.unwrap_or(dto_state.recv_count));
            for held in dto_state.held_messages {
                delivery.held.insert(
                    held.first,
                    HeldMessage {
                        last: held.last,
                        text: held.text.map(hex::decode).transpose()?,
                        held_at_ms: held.held_at_ms,
                    },
                );
            }

            let mut parked = ParkedPayloads::default();
            for dto in dto_state.parked_payloads {
                parked.0.insert(
                    dto.seq,
                    Parked {
                        payload: hex::decode(&dto.payload)?,
                        parked_at_ms: dto.parked_at_ms,
                    },
                );
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
                    recv_pq_injects: RecvPqInjects {
                        pending: pending_pq_injects,
                        applied_through: dto_state.pq_applied_through,
                    },
                    delivery,
                    parked,
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

        let mut contact_names = HashMap::new();
        for (hex_tok, name) in self.contact_names {
            let mut tok = [0u8; 16];
            hex::decode_to_slice(&hex_tok, &mut tok)?;
            contact_names.insert(tok, name);
        }

        let mut peer_x25519_keys = HashMap::new();
        for (hex_tok, hex_key) in self.peer_x25519_keys {
            let mut tok = [0u8; 16];
            hex::decode_to_slice(&hex_tok, &mut tok)?;
            let mut key = [0u8; 32];
            hex::decode_to_slice(&hex_key, &mut key)?;
            peer_x25519_keys.insert(tok, X25519PublicKey::from(key));
        }

        let mut add_ids = HashMap::new();
        for (hex_tok, ids) in self.add_ids {
            let mut tok = [0u8; 16];
            hex::decode_to_slice(&hex_tok, &mut tok)?;
            add_ids.insert(
                tok,
                AddIds {
                    mine: ids.mine,
                    theirs: ids.theirs,
                },
            );
        }

        let mut session_setups = HashMap::new();
        for (hex_tok, setup) in self.session_setups {
            let mut tok = [0u8; 16];
            hex::decode_to_slice(&hex_tok, &mut tok)?;
            let offer = match setup.offer {
                Some(offer) => {
                    let mut eph = [0u8; 32];
                    hex::decode_to_slice(&offer.eph_x25519_pub, &mut eph)?;
                    Some(SessionOffer {
                        eph_x25519_pub: X25519PublicKey::from(eph),
                        kyber_ct: Ciphertext::from_bytes(&hex::decode(&offer.kyber_ct)?)
                            .map_err(|_| anyhow::anyhow!("Kyber err"))?,
                    })
                }
                None => None,
            };
            session_setups.insert(
                tok,
                SessionSetup {
                    establisher_add_id: setup.establisher_add_id,
                    responder_add_id: setup.responder_add_id,
                    offer,
                },
            );
        }

        Ok(Client {
            identity,
            server_addr,
            link: unlinked(), // every run handshakes for a link of its own
            relay_public: None,
            pending_handshake: None,
            last_heard: std::time::Instant::now(),
            setup_retries: HashMap::new(), // live state, not persisted
            e2e_sessions,
            pending_contacts,
            peer_kyber_keys,
            peer_x25519_keys,
            add_ids,
            next_add_id: match self.next_add_id {
                0 => first_add_id(), // from before add IDs existed
                next => next,
            },
            session_setups,
            state_path: path.to_string(),
            local_name: String::new(), // always re-supplied at launch, not persisted
            contact_names,
            inbox: Vec::new(), // transient handoff buffer, not persisted
            history: None,     // attached separately once a vault key is available
            last_recorded_id: None,
            last_recorded_at_ms: 0,
            confirmations: Default::default(), // live state, not persisted
            send_updates: Vec::new(),          // live state, not persisted
            identity_store: None,              // attached separately once a vault key is available
            reassembler: Default::default(), // live state, not persisted — see Client::reassembler
            fec_rx: Default::default(),      // in-flight FEC state, not persisted
            recent_deliveries: Default::default(), // live state, not persisted
            admission_changed: false,        // live state, not persisted
            requests_muted: self.requests_muted,
            notify_with_names: self.notify_with_names,
            connection_requests: Vec::new(), // live state, not persisted
            listed_requests: Default::default(), // live state, not persisted
            dismissed_requests: HashMap::new(), // live state, not persisted
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

    /// A state file from before routing tokens were derived from a key has
    /// a random token the relay won't accept syncs for, so it loads with a
    /// new, provable one (and the rest of the identity unchanged). Its
    /// contacts know it by the old token, so they're removed rather than
    /// left looking connected when nothing would get through.
    #[test]
    fn test_identity_without_token_key_gets_a_provable_token() {
        let (mut original, mut contact) = (Client::new(test_addr()), Client::new(test_addr()));
        original.state_path = std::env::temp_dir()
            .join(format!("e2e-legacy-test-{}.json", rand_suffix()))
            .to_string_lossy()
            .into_owned();
        contact.state_path = format!("{}-contact", original.state_path);
        crate::test_support::connect(&mut original, &mut contact);
        let mut dto = ClientStateDto::from_client(&original);
        dto.identity.token_secret.clear();
        let loaded = dto.into_client("unused").unwrap();
        crate::test_support::cleanup(&[&original, &contact]);

        assert!(loaded.e2e_sessions.is_empty());
        assert!(loaded.pending_contacts.is_empty());
        assert!(loaded.contact_names.is_empty());
        assert!(loaded.peer_x25519_keys.is_empty());
        assert!(!loaded.is_connected(&contact.identity.routing_token));

        assert_ne!(
            loaded.identity.routing_token,
            original.identity.routing_token
        );
        assert_eq!(
            loaded.identity.routing_token,
            routing_token_for(&loaded.identity.token_public)
        );
        assert_eq!(
            loaded.identity.ed25519_public,
            original.identity.ed25519_public
        );
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
