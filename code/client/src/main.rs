use anyhow::{Result, anyhow};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pqcrypto_kyber::kyber768::*;
use pqcrypto_traits::kem::{PublicKey as _, SharedSecret as _};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{io::AsyncBufReadExt, net::UdpSocket, sync::Mutex};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

mod packets;
use packets::*;
mod storage;
use std::collections::HashSet;
use storage::ClientStateDto;

type HmacSha256 = Hmac<Sha256>;
pub type SessionId = [u8; 4];
pub type RoutingToken = [u8; 16];

// PQ injection interval: inject fresh Kyber entropy every N messages
const PQ_INJECT_INTERVAL: u64 = 5;

// Maximum number of skipped message keys to retain
const MAX_SKIP_DICT_SIZE: usize = 500;

// Domain-separation salt for HKDF derivations
const HKDF_SALT: &[u8] = b"e2e-messenger-v1";

// Maximum timestamp drift allowed (seconds)
const MAX_TIMESTAMP_DRIFT: u64 = 300;

// Request Types for Server
const TYPE_HANDSHAKE_INIT: u8 = 0;
const TYPE_DATA: u8 = 1;
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
}

impl SymmetricSessionState {
    pub fn symmetric_ratchet(&mut self) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.send_chain_key).unwrap();
        mac.update(b"message-key");
        let message_key = mac.finalize().into_bytes().into();

        let mut mac_chain = <HmacSha256 as Mac>::new_from_slice(&self.send_chain_key).unwrap();
        mac_chain.update(b"chain-key");
        self.send_chain_key = mac_chain.finalize().into_bytes().into();

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
                    let pt_clone = pt.clone();
                    self.skip_dict.remove(&seq_no);
                    return Some(pt_clone);
                }
            }
            return None;
        }

        if seq_no - self.recv_count > 100 {
            return None;
        }

        // Prune oldest skip_dict entries if we're at capacity
        while self.skip_dict.len() >= MAX_SKIP_DICT_SIZE {
            if let Some(&oldest_key) = self.skip_dict.keys().min() {
                self.skip_dict.remove(&oldest_key);
            } else {
                break;
            }
        }

        let mut test_chain = self.recv_chain_key;
        let mut skipped_keys = Vec::new();

        let mut msg_key = [0u8; 32];
        for _ in self.recv_count..=seq_no {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&test_chain).unwrap();
            mac.update(b"message-key");
            msg_key = mac.finalize().into_bytes().into();

            let mut mac_chain = <HmacSha256 as Mac>::new_from_slice(&test_chain).unwrap();
            mac_chain.update(b"chain-key");
            test_chain = mac_chain.finalize().into_bytes().into();

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
            Some(pt)
        } else {
            None
        }
    }

    /// Mix fresh PQ shared secret into the send chain key via HKDF (called by sender)
    pub fn inject_pq_secret_send(&mut self, pq_secret_bytes: &[u8]) {
        let mut inject_input = Vec::new();
        inject_input.extend_from_slice(&self.send_chain_key);
        inject_input.extend_from_slice(pq_secret_bytes);
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), &inject_input);
        hkdf.expand(b"pq-ratchet-inject", &mut self.send_chain_key)
            .unwrap();
    }

    /// Mix fresh PQ shared secret into the recv chain key via HKDF (called by receiver)
    pub fn inject_pq_secret_recv(&mut self, pq_secret_bytes: &[u8]) {
        let mut inject_input = Vec::new();
        inject_input.extend_from_slice(&self.recv_chain_key);
        inject_input.extend_from_slice(pq_secret_bytes);
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), &inject_input);
        hkdf.expand(b"pq-ratchet-inject", &mut self.recv_chain_key)
            .unwrap();
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
        }
    }

    pub fn save(&self) {
        if let Err(e) = ClientStateDto::save(self, "client_state.json") {
            tracing::error!("Failed to save state: {}", e);
        }
    }

    pub fn generate_handshake_packet(&self) -> (EphemeralSecret, Vec<u8>) {
        use ed25519_dalek::Signer;
        let client_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_ephemeral_public = X25519PublicKey::from(&client_ephemeral_secret);
        // Sign the ephemeral X25519 public key with our Ed25519 identity
        let signature = self.identity.ed25519_secret.sign(client_ephemeral_public.as_bytes());
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

    pub fn generate_sync_packet(&self) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&self.identity.routing_token);
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let link_cipher = XChaCha20Poly1305::new(Key::from_slice(&self.link_master_key));
        let ciphertext = link_cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let mut packet = vec![TYPE_DATA];
        packet.extend_from_slice(&self.session_id);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);
        packet
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
        let payload = KeyExchangePayload::generate(&self.identity, target_token);
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

        // 3. Hybrid Derivation
        let mut hybrid_input = Vec::new();
        hybrid_input.extend_from_slice(classical_shared_secret.as_bytes());
        hybrid_input.extend_from_slice(pq_shared_secret.as_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), &hybrid_input);
        let mut root_key = [0u8; 32];
        hkdf.expand(b"pqxdh-root-key", &mut root_key).unwrap();

        // Store peer's Kyber pub for future PQ ratchet injections
        let peer_kyber_copy = PublicKey::from_bytes(bob_kyber.as_bytes()).unwrap();

        let session_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: Some(peer_kyber_copy),
            skip_dict: std::collections::HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

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

        let mut hybrid_input = Vec::new();
        hybrid_input.extend_from_slice(classical_shared_secret.as_bytes());
        hybrid_input.extend_from_slice(pq_shared_secret.as_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), &hybrid_input);
        let mut root_key = [0u8; 32];
        hkdf.expand(b"pqxdh-root-key", &mut root_key).unwrap();

        // Get peer's Kyber public key (stored during KeyExchange phase)
        let peer_kyber = self
            .peer_kyber_keys
            .get(&est.routing_token)
            .map(|k| PublicKey::from_bytes(k.as_bytes()).unwrap());

        let session_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: peer_kyber,
            skip_dict: std::collections::HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        self.e2e_sessions.insert(est.routing_token, session_state);
        self.save();
        println!(
            ">> E2E Session established with {}!",
            hex::encode(&est.routing_token[0..4])
        );
    }

    /// Encrypt a message. Returns (message_packet, optional_pq_inject_packet).
    /// Every PQ_INJECT_INTERVAL messages, a PQ inject packet is generated automatically.
    pub fn create_encrypted_packet(
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

            // Check if PQ injection is needed
            let pq_ct = if session.send_count % PQ_INJECT_INTERVAL == 0 {
                if let Some(ref peer_kyber) = session.peer_kyber_pub {
                    let (pq_secret, kyber_ct) = encapsulate(peer_kyber);
                    session.inject_pq_secret_send(pq_secret.as_bytes());
                    println!(
                        ">> [PQ] Injected post-quantum entropy after {} messages",
                        session.send_count
                    );
                    Some(kyber_ct)
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

        // Phase 2: link-encrypt everything (immutable borrow on self)
        let msg_packet = self.wrap_link_encryption(target_token, &full_e2e_payload);

        let pq_inject_packet = pq_ct.map(|kyber_ct| {
            let pqi_payload = PQInjectPayload::generate(&self.identity, target_token, kyber_ct);
            let mut inner = vec![0x05];
            inner.extend_from_slice(&pqi_payload.to_bytes());
            self.wrap_link_encryption(target_token, &inner)
        });

        Ok((msg_packet, pq_inject_packet))
    }

    pub fn handle_incoming_packet(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if payload.is_empty() {
            return Ok(None);
        }
        let pkt_type = payload[0];
        let pkt_data = &payload[1..];

        match pkt_type {
            0x01 => {
                // Msg: [16-byte sender_token | 8-byte seq_no | 24-byte nonce | ciphertext]
                if pkt_data.len() < 16 + 8 + 24 {
                    return Err(anyhow!("Msg payload too small"));
                }
                let mut sender_token = [0u8; 16];
                sender_token.copy_from_slice(&pkt_data[0..16]);
                let seq_no = u64::from_be_bytes(pkt_data[16..24].try_into().unwrap());
                let mut nonce_bytes = [0u8; 24];
                nonce_bytes.copy_from_slice(&pkt_data[24..48]);
                let nonce = XNonce::from_slice(&nonce_bytes);
                let ciphertext = &pkt_data[48..];

                if let Some(session) = self.e2e_sessions.get_mut(&sender_token) {
                    if let Some(pt) = session.try_decrypt(seq_no, nonce, ciphertext) {
                        self.save();
                        println!(
                            ">> [From {}]: {}",
                            hex::encode(&sender_token[0..4]),
                            String::from_utf8_lossy(&pt)
                        );
                    } else {
                        println!(
                            ">> Received packet from {} but decryption failed (out of sync?).",
                            hex::encode(&sender_token[0..4])
                        );
                    }
                } else {
                    println!(
                        ">> Received packet from unknown sender {}. No E2E session found.",
                        hex::encode(&sender_token[0..4])
                    );
                }
                Ok(None)
            }
            0x02 => {
                // KeyExchange
                if let Ok(kx) = KeyExchangePayload::from_bytes(pkt_data) {
                    if kx.verify(&kx.ed25519_public).is_ok() {
                        if kx.target_token.ct_eq(&self.identity.routing_token).unwrap_u8() == 0 {
                            println!(
                                ">> [SECURITY ALERT] Dropped KeyExchange! It was bound to a different target."
                            );
                            return Ok(None);
                        }
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let time_diff = now.max(kx.timestamp) - now.min(kx.timestamp);
                        if time_diff > MAX_TIMESTAMP_DRIFT {
                            println!(
                                ">> [SECURITY ALERT] Dropped KeyExchange! Timestamp is stale or from the future."
                            );
                            return Ok(None);
                        }

                        let peer_token = kx.routing_token;
                        let is_initiator = self.pending_contacts.contains_key(&peer_token);

                        if !is_initiator && self.pending_contacts.len() > 50 {
                            println!(">> [SECURITY ALERT] Dropped KeyExchange! Too many pending contacts.");
                            return Ok(None);
                        }

                        // Store peer's Kyber key for future PQ injections
                        self.peer_kyber_keys.insert(
                            peer_token,
                            PublicKey::from_bytes(kx.kyber_public.as_bytes()).unwrap(),
                        );

                        if is_initiator {
                            let expected_ed25519 = self.pending_contacts.get(&peer_token).unwrap();
                            if kx.ed25519_public.as_bytes() != expected_ed25519.as_bytes() {
                                println!(
                                    ">> [SECURITY ALERT] KeyExchange from {} failed QR code verification!",
                                    hex::encode(&peer_token[0..4])
                                );
                                return Ok(None);
                            }
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
                    if est.target_token.ct_eq(&self.identity.routing_token).unwrap_u8() == 0 {
                        println!(
                            ">> [SECURITY ALERT] Dropped SessionEstablish! Bound to different target."
                        );
                        return Ok(None);
                    }
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let time_diff = now.max(est.timestamp) - now.min(est.timestamp);
                    if time_diff > MAX_TIMESTAMP_DRIFT {
                        println!(
                            ">> [SECURITY ALERT] Dropped SessionEstablish! Timestamp is stale."
                        );
                        return Ok(None);
                    }
                    if let Some(alice_pub) = self.pending_contacts.get(&est.routing_token) {
                        if est.verify(alice_pub).is_ok() {
                            if !self.seen_session_keys.insert(est.eph_x25519_pub.to_bytes()) {
                                println!(">> [SECURITY ALERT] Dropped SessionEstablish! Replay detected (key already seen).");
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
                    if pqi.target_token.ct_eq(&self.identity.routing_token).unwrap_u8() == 0 {
                        println!(
                            ">> [SECURITY ALERT] Dropped PQInject! Bound to different target."
                        );
                        return Ok(None);
                    }
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let time_diff = now.max(pqi.timestamp) - now.min(pqi.timestamp);
                    if time_diff > MAX_TIMESTAMP_DRIFT {
                        println!(">> [SECURITY ALERT] Dropped PQInject! Timestamp is stale.");
                        return Ok(None);
                    }
                    if let Some(sender_pub) = self.pending_contacts.get(&pqi.routing_token) {
                        if pqi.verify(sender_pub).is_ok() {
                            // Decapsulate and inject PQ entropy into the session

                            let pq_secret = decapsulate(&pqi.kyber_ct, &self.identity.kyber_secret);
                            if let Some(session) = self.e2e_sessions.get_mut(&pqi.routing_token) {
                                let sig_bytes = pqi.signature.to_bytes();
                                if session.pq_inject_replay_cache.contains(&sig_bytes) {
                                    println!(">> [SECURITY ALERT] Dropped PQInject! Replay detected.");
                                    return Ok(None);
                                }
                                if session.pq_inject_replay_cache.len() > 1000 {
                                    session.pq_inject_replay_cache.clear();
                                }
                                session.pq_inject_replay_cache.insert(sig_bytes);

                                session.inject_pq_secret_recv(pq_secret.as_bytes());

                                println!(
                                    ">> [PQ] Received and injected post-quantum entropy from {}!",
                                    hex::encode(&pqi.routing_token[0..4])
                                );
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
            _ => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <server_ed25519_pubkey_hex>", args[0]);
        std::process::exit(1);
    }

    let server_pub_hex = &args[1];
    let server_pub_bytes =
        hex::decode(server_pub_hex).map_err(|_| anyhow!("Invalid hex for server pubkey"))?;
    if server_pub_bytes.len() != 32 {
        return Err(anyhow!(
            "Server Ed25519 pubkey must be 32 bytes (64 hex chars), got {} bytes",
            server_pub_bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&server_pub_bytes);
    let server_pub =
        VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("Invalid server verifying key"))?;

    let server_addr: SocketAddr = "127.0.0.1:4430".parse()?;

    let client_obj = match ClientStateDto::load("client_state.json") {
        Ok(c) => {
            println!("Loaded client state from disk.");
            c
        }
        Err(_) => Client::new(server_addr),
    };

    let client = Arc::new(Mutex::new(client_obj));

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // Perform Handshake
    {
        let mut c = client.lock().await;
        let (client_secret, hs_packet) = c.generate_handshake_packet();
        socket.send_to(&hs_packet, server_addr).await?;

        let mut resp_buf = [0u8; 1024];
        let (len, _) = socket.recv_from(&mut resp_buf).await?;
        c.complete_handshake(client_secret, &server_pub, &resp_buf[..len])?;
        println!(
            "Completed Server Link Handshake! Session ID: {}",
            hex::encode(c.session_id)
        );
        c.save();

        let sync_packet = c.generate_sync_packet();
        socket.send_to(&sync_packet, server_addr).await?;
        println!("Sent Sync Packet.");

        println!("=== MY IDENTITY ===");
        println!("Token:   {}", hex::encode(c.identity.routing_token));
        println!(
            "Ed25519: {}",
            hex::encode(c.identity.ed25519_public.as_bytes())
        );
        println!("===================");
    }

    let socket_clone = Arc::clone(&socket);
    let client_clone = Arc::clone(&client);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((len, _)) = socket_clone.recv_from(&mut buf).await {
                if len < 1 + 4 + 24 + 16 || buf[0] != TYPE_DATA {
                    continue;
                }

                let mut session_id = [0u8; 4];
                session_id.copy_from_slice(&buf[1..5]);

                let mut c = client_clone.lock().await;
                if session_id != c.session_id {
                    continue;
                }

                let mut nonce_bytes = [0u8; 24];
                nonce_bytes.copy_from_slice(&buf[5..29]);
                let link_nonce = XNonce::from_slice(&nonce_bytes);
                let ciphertext = &buf[29..len];
                let link_cipher = XChaCha20Poly1305::new(Key::from_slice(&c.link_master_key));
                if let Ok(decrypted) = link_cipher.decrypt(link_nonce, ciphertext)
                    && decrypted.len() >= 16
                {
                    let e2e_payload = &decrypted[16..];
                    if let Ok(Some(reply)) = c.handle_incoming_packet(e2e_payload) {
                        let _ = socket_clone.send_to(&reply, c.server_addr).await;
                    }
                }
            }
        }
    });

    println!("Commands:");
    println!("  connect <routing_token_hex> <ed25519_pub_hex>");
    println!("  msg <routing_token_hex> <text...>");

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = stdin.next_line().await {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "connect" => {
                if parts.len() != 3 {
                    println!("Usage: connect <token> <ed25519>");
                    continue;
                }
                let token_bytes = hex::decode(parts[1]).unwrap();
                let mut token = [0u8; 16];
                token.copy_from_slice(&token_bytes);
                let ed25519_bytes = hex::decode(parts[2]).unwrap();
                let mut ed_arr = [0u8; 32];
                ed_arr.copy_from_slice(&ed25519_bytes);
                let bob_ed25519 = VerifyingKey::from_bytes(&ed_arr).unwrap();
                let mut c = client.lock().await;
                c.pending_contacts.insert(token, bob_ed25519);
                let req_packet = c.create_kx_request(token);
                socket.send_to(&req_packet, server_addr).await.unwrap();
                println!("Sent connection request! Waiting for Bob...");
            }
            "msg" => {
                if parts.len() < 3 {
                    println!("Usage: msg <token> <text...>");
                    continue;
                }
                let token_bytes = hex::decode(parts[1]).unwrap();
                let mut token = [0u8; 16];
                token.copy_from_slice(&token_bytes);
                let text = parts[2..].join(" ");
                let mut c = client.lock().await;
                match c.create_encrypted_packet(token, text.as_bytes()) {
                    Ok((msg_packet, pq_inject_packet)) => {
                        socket.send_to(&msg_packet, server_addr).await.unwrap();
                        println!("Sent msg!");
                        if let Some(pq_pkt) = pq_inject_packet {
                            socket.send_to(&pq_pkt, server_addr).await.unwrap();
                            println!("Sent PQ ratchet injection packet!");
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            _ => println!("Unknown command"),
        }
    }

    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: strip link encryption from a packet (simulate server forwarding)
    fn strip_link(packet: &[u8], link_key: &[u8; 32]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes.copy_from_slice(&packet[5..29]);
        let link_nonce = XNonce::from_slice(&nonce_bytes);
        let link_cipher = XChaCha20Poly1305::new(Key::from_slice(link_key));
        let decrypted = link_cipher.decrypt(link_nonce, &packet[29..]).unwrap();
        decrypted[16..].to_vec() // strip routing token
    }

    // ==========================================
    // Serialization & Signature Tests
    // ==========================================

    #[test]
    fn test_key_exchange_serialization() {
        let alice_id = UserIdentity::generate();
        let mut bob_token = [0u8; 16];
        bob_token[0] = 0xBB;
        let payload = KeyExchangePayload::generate(&alice_id, bob_token);
        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), 1352);
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
        let pqi = PQInjectPayload::generate(&alice_id, bob_id.routing_token, kyber_ct);
        let bytes = pqi.to_bytes();
        assert_eq!(bytes.len(), 1192);
        let parsed = PQInjectPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify(&alice_id.ed25519_public).is_ok());
        assert_eq!(parsed.routing_token, alice_id.routing_token);
        assert_eq!(parsed.target_token, bob_id.routing_token);
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
        let payload = KeyExchangePayload::generate(&alice_id, [0u8; 16]);
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
        let pqi = PQInjectPayload::generate(&alice_id, bob_id.routing_token, kyber_ct);
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
        let pqi = PQInjectPayload::generate(&alice_id, bob_id.routing_token, kyber_ct);
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
        let mut payload = KeyExchangePayload::generate(&alice_id, [0u8; 16]);
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
        let payload = KeyExchangePayload::generate(&alice_id, charlie_token);
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
        let bob_kyber_copy = PublicKey::from_bytes(bob_id.kyber_public.as_bytes()).unwrap();
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
        let alice_kyber_copy =
            PublicKey::from_bytes(alice.identity.kyber_public.as_bytes()).unwrap();
        let bob_kyber_copy = PublicKey::from_bytes(bob.identity.kyber_public.as_bytes()).unwrap();
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
        let bob_kyber_copy = PublicKey::from_bytes(bob_id.kyber_public.as_bytes()).unwrap();
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
        let alice_kx = KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token);
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
        assert_eq!(a_sess.send_chain_key, b_sess.recv_chain_key);

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
        let alice_kx = KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token);
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
            },
        );
        let chain_before = bob
            .e2e_sessions
            .get(&alice_id.routing_token)
            .unwrap()
            .recv_chain_key;

        // Mallory signs PQ inject with her own key but spoofs Alice's routing token
        let (_, kyber_ct) = encapsulate(&bob.identity.kyber_public);
        let mut pqi = PQInjectPayload::generate(&mallory_id, bob.identity.routing_token, kyber_ct);
        pqi.routing_token = alice_id.routing_token;

        let mut inner = vec![0x05];
        inner.extend_from_slice(&pqi.to_bytes());
        bob.handle_incoming_packet(&inner).unwrap();

        // Chain key must NOT have changed
        let chain_after = bob
            .e2e_sessions
            .get(&alice_id.routing_token)
            .unwrap()
            .recv_chain_key;
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
        assert!(pt.is_none(), "Should drop packet that skips more than 100 seq nums");
        assert_eq!(bob_state.recv_count, 0);
    }

    #[test]
    fn test_edge_case_pending_contacts_exhaustion() {
        let server_addr: std::net::SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        
        // Flood with 55 KeyExchanges
        for _ in 0..55 {
            let alice_id = UserIdentity::generate();
            let payload = KeyExchangePayload::generate(&alice_id, bob.identity.routing_token);
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
        bob.pending_contacts.insert(alice_id.routing_token, alice_id.ed25519_public);
        
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
        let mut payload = KeyExchangePayload::generate(&alice_id, bob.identity.routing_token);
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
        assert!(result.is_none(), "Stale timestamp must cause packet to be dropped");
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
        let payload = KeyExchangePayload::generate(&alice_id, charlie_token);
        let mut packet = vec![0x02];
        packet.extend_from_slice(&payload.to_bytes());

        let result = bob.handle_incoming_packet(&packet).unwrap();
        assert!(result.is_none(), "Misbinding must cause packet to be dropped");
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
        let alice_kx = KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token);
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

    #[test]
    fn test_edge_case_pq_inject_stale_timestamp() {
        // PQ inject with an expired timestamp must be rejected
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut bob = Client::new(server_addr);
        let alice_id = UserIdentity::generate();

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
            },
        );
        let chain_before = bob
            .e2e_sessions
            .get(&alice_id.routing_token)
            .unwrap()
            .recv_chain_key;

        // Create PQ inject with stale timestamp
        let (_, kyber_ct) = encapsulate(&bob.identity.kyber_public);
        let mut pqi = PQInjectPayload::generate(&alice_id, bob.identity.routing_token, kyber_ct);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        pqi.timestamp = now - 600; // 10 minutes in the past
        // Re-sign with the stale timestamp
        use ed25519_dalek::Signer;
        use pqcrypto_traits::kem::Ciphertext as _;
        let mut msg = Vec::new();
        msg.extend_from_slice(&pqi.routing_token);
        msg.extend_from_slice(&pqi.target_token);
        msg.extend_from_slice(&pqi.timestamp.to_be_bytes());
        msg.extend_from_slice(pqi.kyber_ct.as_bytes());
        pqi.signature = alice_id.ed25519_secret.sign(&msg);

        let mut packet = vec![0x05];
        packet.extend_from_slice(&pqi.to_bytes());
        bob.handle_incoming_packet(&packet).unwrap();

        let chain_after = bob
            .e2e_sessions
            .get(&alice_id.routing_token)
            .unwrap()
            .recv_chain_key;
        assert_eq!(
            chain_before, chain_after,
            "Stale PQ inject must NOT modify chain key"
        );
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
        original.peer_kyber_keys.insert(
            peer_token,
            PublicKey::from_bytes(peer_id.kyber_public.as_bytes()).unwrap(),
        );
        original.e2e_sessions.insert(
            peer_token,
            SymmetricSessionState {
                root_key: [0x42; 32],
                send_chain_key: [0x43; 32],
                recv_chain_key: [0x43; 32],
                send_count: 7,
                recv_count: 3,
                peer_kyber_pub: Some(
                    PublicKey::from_bytes(peer_id.kyber_public.as_bytes()).unwrap(),
                ),
                skip_dict: {
                    let mut m = std::collections::HashMap::new();
                    m.insert(1, [0xAA; 32]);
                    m
                },
                pq_inject_replay_cache: std::collections::HashSet::new(),
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
        assert_eq!(orig_sess.recv_chain_key, load_sess.recv_chain_key);
        assert_eq!(orig_sess.send_count, load_sess.send_count);
        assert_eq!(orig_sess.recv_count, load_sess.recv_count);
        assert_eq!(orig_sess.skip_dict.len(), load_sess.skip_dict.len());
        assert_eq!(orig_sess.skip_dict[&1], load_sess.skip_dict[&1]);

        // Verify pending contacts
        assert!(loaded.pending_contacts.contains_key(&peer_token));

        // Verify seen_session_keys
        assert!(loaded.seen_session_keys.contains(&[0xDD; 32]));

        // Clean up
        let _ = std::fs::remove_file(tmp_path);
    }

    // ==========================================
    // End-to-End Message Content Verification
    // ==========================================

    #[test]
    fn test_e2e_single_message_content_roundtrip() {
        // Verifies the actual plaintext content survives encrypt → decrypt
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

        let root_key = [0x42u8; 32];
        let mut alice_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        let message = b"Hello Bob! This is a secret message.";
        let message_key = alice_state.symmetric_ratchet();
        alice_state.send_count += 1;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&message_key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, message.as_ref()).unwrap();

        // Verify ciphertext is NOT the same as plaintext
        assert_ne!(&ciphertext[..], &message[..], "Ciphertext must differ from plaintext");

        // Bob decrypts
        let plaintext = bob_state.try_decrypt(0, nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, message, "Decrypted content must match original");
    }

    #[test]
    fn test_e2e_multi_message_content_roundtrip() {
        // Verifies multiple messages in sequence all decrypt to correct content
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

        let root_key = [0x42u8; 32];
        let mut alice_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        let messages: Vec<&[u8]> = vec![
            b"Message 1: Hello!",
            b"Message 2: How are you?",
            b"Message 3: Fine thanks",
            b"Message 4: Goodbye!",
            b"Message 5: See you later!",
        ];

        for (i, msg) in messages.iter().enumerate() {
            let mk = alice_state.symmetric_ratchet();
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk));
            let mut nonce_bytes = [0u8; 24];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = XNonce::from_slice(&nonce_bytes);
            let ct = cipher.encrypt(nonce, *msg).unwrap();

            let pt = bob_state.try_decrypt(i as u64, nonce, &ct).unwrap();
            assert_eq!(pt, *msg, "Message {} content mismatch", i + 1);
        }

        // Chain keys must be in sync
        assert_eq!(alice_state.send_chain_key, bob_state.recv_chain_key);
    }

    #[test]
    fn test_e2e_bidirectional_conversation() {
        // Alice and Bob take turns sending messages — verifies both directions work
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

        let root_key = [0x42u8; 32];
        // Alice→Bob session
        let mut alice_send = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut bob_recv = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        // Bob→Alice session (separate chain key)
        let root_key2 = [0x99u8; 32];
        let mut bob_send = SymmetricSessionState {
            root_key: root_key2,
            send_chain_key: root_key2,
            recv_chain_key: root_key2,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut alice_recv = SymmetricSessionState {
            root_key: root_key2,
            send_chain_key: root_key2,
            recv_chain_key: root_key2,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        // Conversation: Alice, Bob, Alice, Bob
        let convo = vec![
            ("alice", b"Hey Bob!" as &[u8]),
            ("bob", b"Hey Alice!" as &[u8]),
            ("alice", b"How's the weather?" as &[u8]),
            ("bob", b"Sunny! You?" as &[u8]),
        ];

        for (i, (sender, msg)) in convo.iter().enumerate() {
            let mut nonce_bytes = [0u8; 24];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = XNonce::from_slice(&nonce_bytes);

            if *sender == "alice" {
                let mk = alice_send.symmetric_ratchet();
                let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk));
                let ct = cipher.encrypt(nonce, *msg).unwrap();
                let seq = alice_send.send_count;
                alice_send.send_count += 1;

                let pt = bob_recv.try_decrypt(seq, nonce, &ct).unwrap();
                assert_eq!(pt, *msg, "Bidirectional msg {} failed (alice→bob)", i);
            } else {
                let mk = bob_send.symmetric_ratchet();
                let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk));
                let ct = cipher.encrypt(nonce, *msg).unwrap();
                let seq = bob_send.send_count;
                bob_send.send_count += 1;

                let pt = alice_recv.try_decrypt(seq, nonce, &ct).unwrap();
                assert_eq!(pt, *msg, "Bidirectional msg {} failed (bob→alice)", i);
            }
        }
    }

    #[test]
    fn test_e2e_tampered_ciphertext_fails() {
        // Verifies that flipping a bit in ciphertext causes decryption failure
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

        let root_key = [0x42u8; 32];
        let mut alice_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        let mk = alice_state.symmetric_ratchet();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk));
        let nonce = XNonce::from_slice(&[0u8; 24]);
        let mut ct = cipher.encrypt(nonce, b"Secret data".as_ref()).unwrap();

        // Tamper with the ciphertext
        ct[0] ^= 0xFF;

        let result = bob_state.try_decrypt(0, nonce, &ct);
        assert!(result.is_none(), "Tampered ciphertext must fail decryption");
    }

    #[test]
    fn test_e2e_wrong_key_fails() {
        // Verifies that using a different chain key fails decryption
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

        let mut alice_state = SymmetricSessionState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x42u8; 32],
            recv_chain_key: [0x42u8; 32],
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key: [0x99u8; 32], // DIFFERENT key!
            send_chain_key: [0x99u8; 32],
            recv_chain_key: [0x99u8; 32],
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        let mk = alice_state.symmetric_ratchet();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk));
        let nonce = XNonce::from_slice(&[0u8; 24]);
        let ct = cipher.encrypt(nonce, b"Secret".as_ref()).unwrap();

        let result = bob_state.try_decrypt(0, nonce, &ct);
        assert!(result.is_none(), "Wrong key must fail decryption");
    }

    #[test]
    fn test_e2e_full_handshake_then_verified_message_exchange() {
        // Full integration: handshake → session establishment → verified bidirectional messaging
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);

        // Step 0: QR code scan
        alice
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);

        // Step 1: Alice→Bob KeyExchange
        let alice_kx = KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token);
        let mut kx_inner = vec![0x02];
        kx_inner.extend_from_slice(&alice_kx.to_bytes());
        let bob_reply = bob.handle_incoming_packet(&kx_inner).unwrap().unwrap();

        // Step 2: Bob→Alice KeyExchange reply
        let inner = strip_link(&bob_reply, &bob.link_master_key);
        let alice_reply = alice.handle_incoming_packet(&inner).unwrap().unwrap();

        // Step 3: Alice→Bob SessionEstablish
        let inner2 = strip_link(&alice_reply, &alice.link_master_key);
        bob.handle_incoming_packet(&inner2).unwrap();

        // Both sessions must be established
        assert!(alice.e2e_sessions.contains_key(&bob.identity.routing_token));
        assert!(bob.e2e_sessions.contains_key(&alice.identity.routing_token));

        // Verify root keys match (hybrid PQXDH derivation produced same result)
        let a_root = alice
            .e2e_sessions
            .get(&bob.identity.routing_token)
            .unwrap()
            .root_key;
        let b_root = bob
            .e2e_sessions
            .get(&alice.identity.routing_token)
            .unwrap()
            .root_key;
        assert_eq!(a_root, b_root, "Root keys must match after PQXDH handshake");

        // Alice sends 3 messages to Bob and verify content at the ratchet level
        let test_messages = [
            "Hello from Alice!",
            "This is message 2.",
            "Third and final message.",
        ];
        for (i, msg_text) in test_messages.iter().enumerate() {
            let (msg_pkt, _pq) = alice
                .create_encrypted_packet(bob.identity.routing_token, msg_text.as_bytes())
                .unwrap();

            // Simulate server forwarding: strip link encryption
            let e2e_inner = strip_link(&msg_pkt, &alice.link_master_key);

            // Verify packet structure: type byte (0x01) + 16 byte sender_token + 8 byte seq_no + 24 byte nonce + ciphertext
            assert_eq!(e2e_inner[0], 0x01, "E2E message type must be 0x01");
            assert_eq!(
                &e2e_inner[1..17],
                &alice.identity.routing_token[..],
                "Sender token must match Alice"
            );
            let seq_no = u64::from_be_bytes(e2e_inner[17..25].try_into().unwrap());
            assert_eq!(seq_no, i as u64, "Sequence number must be {}", i);

            // Bob processes via handle_incoming_packet (prints to stdout)
            let result = bob.handle_incoming_packet(&e2e_inner).unwrap();
            assert!(result.is_none(), "Message handling should return None");
        }

        // Chain keys must remain in sync after all messages
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
        assert_eq!(a_ck, b_ck, "Chain keys must be in sync after message exchange");

        // Verify send/recv counts
        let a_sess = alice.e2e_sessions.get(&bob.identity.routing_token).unwrap();
        let b_sess = bob.e2e_sessions.get(&alice.identity.routing_token).unwrap();
        assert_eq!(a_sess.send_count, 3, "Alice must have sent 3 messages");
        assert_eq!(b_sess.recv_count, 3, "Bob must have received 3 messages");
    }

    #[test]
    fn test_e2e_out_of_order_content_verification() {
        // Verifies that out-of-order delivery still produces correct plaintext content
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

        let root_key = [0x42u8; 32];
        let mut alice_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        // Alice generates 4 messages
        let messages = [b"First" as &[u8], b"Second", b"Third", b"Fourth"];
        let mut encrypted: Vec<(u64, [u8; 24], Vec<u8>)> = Vec::new();

        for (i, msg) in messages.iter().enumerate() {
            let mk = alice_state.symmetric_ratchet();
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk));
            let mut nonce_bytes = [0u8; 24];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = XNonce::from_slice(&nonce_bytes);
            let ct = cipher.encrypt(nonce, *msg).unwrap();
            encrypted.push((i as u64, nonce_bytes, ct));
        }

        // Deliver in order: 1, 4, 3, 2 (0-indexed: 0, 3, 2, 1)
        let delivery_order = [0usize, 3, 2, 1];

        for &idx in &delivery_order {
            let (seq, nonce_bytes, ref ct) = encrypted[idx];
            let nonce = XNonce::from_slice(&nonce_bytes);
            let pt = bob_state.try_decrypt(seq, nonce, ct)
                .unwrap_or_else(|| panic!("Failed to decrypt message {} (seq {})", idx + 1, seq));
            assert_eq!(
                pt, messages[idx],
                "Out-of-order message {} content mismatch",
                idx + 1
            );
        }

        // All skip_dict entries should be consumed
        assert_eq!(bob_state.skip_dict.len(), 0, "All skip_dict entries should be consumed");
        assert_eq!(bob_state.recv_count, 4, "Bob should have received all 4 messages");
    }

    #[test]
    fn test_e2e_empty_and_large_message_content() {
        // Verifies edge case: empty message and large message both round-trip correctly
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

        let root_key = [0x42u8; 32];
        let mut alice_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        // Empty message
        let mk = alice_state.symmetric_ratchet();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk));
        let nonce = XNonce::from_slice(&[1u8; 24]);
        let ct = cipher.encrypt(nonce, b"".as_ref()).unwrap();
        let pt = bob_state.try_decrypt(0, nonce, &ct).unwrap();
        assert_eq!(pt, b"", "Empty message must decrypt correctly");

        // Large message (4KB)
        let large_msg = vec![0xAB_u8; 4096];
        let mk2 = alice_state.symmetric_ratchet();
        let cipher2 = XChaCha20Poly1305::new(Key::from_slice(&mk2));
        let nonce2 = XNonce::from_slice(&[2u8; 24]);
        let ct2 = cipher2.encrypt(nonce2, large_msg.as_ref()).unwrap();
        let pt2 = bob_state.try_decrypt(1, nonce2, &ct2).unwrap();
        assert_eq!(pt2, large_msg, "Large message must decrypt correctly");
    }

    #[test]
    fn test_e2e_unicode_message_content() {
        // Verifies that Unicode/UTF-8 content survives encryption roundtrip
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

        let root_key = [0x42u8; 32];
        let mut alice_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };
        let mut bob_state = SymmetricSessionState {
            root_key,
            send_chain_key: root_key,
            recv_chain_key: root_key,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        let unicode_messages: Vec<&str> = vec![
            "Hello 🌍🔐!",
            "日本語テスト",
            "Привет мир",
            "🔒💬🛡️ End-to-end encrypted!",
            "Mixed: abc 123 αβγ ∞ ≠ ≈",
        ];

        for (i, msg) in unicode_messages.iter().enumerate() {
            let mk = alice_state.symmetric_ratchet();
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&mk));
            let mut nonce_bytes = [0u8; 24];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = XNonce::from_slice(&nonce_bytes);
            let ct = cipher.encrypt(nonce, msg.as_bytes()).unwrap();

            let pt = bob_state.try_decrypt(i as u64, nonce, &ct).unwrap();
            let decrypted_str = String::from_utf8(pt).unwrap();
            assert_eq!(decrypted_str, *msg, "Unicode message {} mismatch", i + 1);
        }
    }

    #[test]
    fn test_e2e_full_handshake_bidirectional_messaging() {
        // Full integration: handshake → Alice sends → Bob sends back → verify both directions
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let mut bob = Client::new(server_addr);

        // Handshake
        alice
            .pending_contacts
            .insert(bob.identity.routing_token, bob.identity.ed25519_public);
        let alice_kx = KeyExchangePayload::generate(&alice.identity, bob.identity.routing_token);
        let mut kx_inner = vec![0x02];
        kx_inner.extend_from_slice(&alice_kx.to_bytes());
        let bob_reply = bob.handle_incoming_packet(&kx_inner).unwrap().unwrap();
        let inner = strip_link(&bob_reply, &bob.link_master_key);
        let alice_reply = alice.handle_incoming_packet(&inner).unwrap().unwrap();
        let inner2 = strip_link(&alice_reply, &alice.link_master_key);
        bob.handle_incoming_packet(&inner2).unwrap();

        // Verify session established
        assert!(alice.e2e_sessions.contains_key(&bob.identity.routing_token));
        assert!(bob.e2e_sessions.contains_key(&alice.identity.routing_token));

        // Alice → Bob: 3 messages
        for i in 0..3 {
            let (msg_pkt, _) = alice
                .create_encrypted_packet(
                    bob.identity.routing_token,
                    format!("Alice says {}", i + 1).as_bytes(),
                )
                .unwrap();
            let e2e_inner = strip_link(&msg_pkt, &alice.link_master_key);
            bob.handle_incoming_packet(&e2e_inner).unwrap();
        }

        // Bob → Alice: 2 messages (Bob uses Alice's routing token to send)
        // For this to work, Bob needs a session keyed to Alice's token
        // which he already has from accept_session_est
        for i in 0..2 {
            let (msg_pkt, _) = bob
                .create_encrypted_packet(
                    alice.identity.routing_token,
                    format!("Bob replies {}", i + 1).as_bytes(),
                )
                .unwrap();
            let e2e_inner = strip_link(&msg_pkt, &bob.link_master_key);
            alice.handle_incoming_packet(&e2e_inner).unwrap();
        }

        // Verify counts
        let a_to_b = alice.e2e_sessions.get(&bob.identity.routing_token).unwrap();
        let b_from_a = bob.e2e_sessions.get(&alice.identity.routing_token).unwrap();
        assert_eq!(a_to_b.send_count, 3, "Alice sent 3");
        assert_eq!(b_from_a.recv_count, 3, "Bob received 3");
        assert_eq!(
            a_to_b.send_chain_key, b_from_a.recv_chain_key,
            "Alice send chain matches Bob recv chain"
        );

        let b_to_a = bob.e2e_sessions.get(&alice.identity.routing_token).unwrap();
        let a_from_b = alice.e2e_sessions.get(&bob.identity.routing_token).unwrap();
        assert_eq!(b_to_a.send_count, 2, "Bob sent 2");
        assert_eq!(a_from_b.recv_count, 2, "Alice received 2");
        assert_eq!(
            b_to_a.send_chain_key, a_from_b.recv_chain_key,
            "Bob send chain matches Alice recv chain"
        );
    }

    #[test]
    fn test_direct_session_lookup_multi_peer_isolation() {
        // Verifies Issue 2 fix: Direct lookup by sender routing token ensures
        // messages for one peer never touch or corrupt another peer's session state.
        let server_addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
        let mut alice = Client::new(server_addr);
        let bob_token = [0xBB; 16];
        let charlie_token = [0xCC; 16];

        let root_bob = [0x11; 32];
        let root_charlie = [0x22; 32];

        // Insert Bob's session
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
            },
        );

        // Insert Charlie's session
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
            },
        );

        // Bob encrypts a message for Alice using Bob's send_chain_key
        let mut bob_sender_state = SymmetricSessionState {
            root_key: root_bob,
            send_chain_key: root_bob,
            recv_chain_key: root_bob,
            send_count: 0,
            recv_count: 0,
            peer_kyber_pub: None,
            skip_dict: HashMap::new(),
            pq_inject_replay_cache: HashSet::new(),
        };

        let msg_key = bob_sender_state.symmetric_ratchet();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let nonce_bytes = [0x77u8; 24];
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, b"Secret from Bob".as_ref()).unwrap();

        // Build 0x01 packet with Bob's routing token as sender
        let mut pkt = vec![0x01];
        pkt.extend_from_slice(&bob_token);
        pkt.extend_from_slice(&0u64.to_be_bytes());
        pkt.extend_from_slice(&nonce_bytes);
        pkt.extend_from_slice(&ciphertext);

        // Alice processes the packet
        let res = alice.handle_incoming_packet(&pkt).unwrap();
        assert!(res.is_none());

        // Verify Bob's session advanced
        let bob_sess = alice.e2e_sessions.get(&bob_token).unwrap();
        assert_eq!(bob_sess.recv_count, 1);
        assert_eq!(bob_sess.recv_chain_key, bob_sender_state.send_chain_key);

        // Verify Charlie's session is COMPLETELY UNTOUCHED
        let charlie_sess = alice.e2e_sessions.get(&charlie_token).unwrap();
        assert_eq!(charlie_sess.recv_count, 0);
        assert_eq!(charlie_sess.send_count, 0);
        assert_eq!(charlie_sess.send_chain_key, root_charlie);
        assert_eq!(charlie_sess.recv_chain_key, root_charlie);
        assert!(charlie_sess.skip_dict.is_empty());

        // Sending a packet from an unknown token also touches no existing sessions
        let unknown_token = [0xEE; 16];
        let mut unknown_pkt = vec![0x01];
        unknown_pkt.extend_from_slice(&unknown_token);
        unknown_pkt.extend_from_slice(&0u64.to_be_bytes());
        unknown_pkt.extend_from_slice(&nonce_bytes);
        unknown_pkt.extend_from_slice(&ciphertext);

        let res2 = alice.handle_incoming_packet(&unknown_pkt).unwrap();
        assert!(res2.is_none());

        let charlie_sess2 = alice.e2e_sessions.get(&charlie_token).unwrap();
        assert_eq!(charlie_sess2.recv_count, 0);
        assert_eq!(charlie_sess2.recv_chain_key, root_charlie);
    }
}

