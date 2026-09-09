use crate::{Client, SymmetricSessionState, UserIdentity};
use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pqcrypto_kyber::kyber768::{PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
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
        dto.into_client()
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

    fn into_client(self) -> Result<Client> {
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
            local_name: String::new(), // always re-supplied at launch, not persisted
            contact_names,
            inbox: Vec::new(), // transient handoff buffer, not persisted
        })
    }
}
