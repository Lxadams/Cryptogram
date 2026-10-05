use anyhow::{Result, anyhow};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::{
    fs,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Notify};
use tracing::{debug, error, info, warn};
use x25519_dalek::PublicKey as X25519PublicKey;
mod stores;

use crate::stores::Tables;

const METADATA_TTL: Duration = Duration::from_secs(1000);
const MESSAGE_TTL: Duration = Duration::from_secs(1000);
// Minimum gap between packets the relay sends one recipient. Half a
// client's FEC burst spacing (10ms): a live burst passes straight through
// with the spacing it arrived with — even two peers sending at once keep
// up — while a backlog (a recipient coming back online) is spread out
// instead of blasted at line rate, which would overflow their socket
// buffer and hand a jamming spike whole messages at a time.
const RELAY_PACKET_SPACING: Duration = Duration::from_millis(5);
const SWEEPING_TASK_INTERVAL: Duration = Duration::from_secs(120);

// Domain-separation salt for HKDF derivations (must match client)
const HKDF_SALT: &[u8] = b"e2e-messenger-v1";

// Request Types
const TYPE_HANDSHAKE_INIT: u8 = 0;
const TYPE_DATA: u8 = 1;
const TYPE_HANDSHAKE_RESP: u8 = 2;

#[derive(serde::Serialize, serde::Deserialize)]
struct ServerIdentityDto {
    ed25519_secret: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Generate server static identity

    let identity_path = "server_identity.json";
    let server_identity = if let Ok(json) = fs::read_to_string(identity_path) {
        let dto: ServerIdentityDto = serde_json::from_str(&json)?;
        let mut sec_bytes = [0u8; 32];
        hex::decode_to_slice(&dto.ed25519_secret, &mut sec_bytes)?;
        SigningKey::from_bytes(&sec_bytes)
    } else {
        info!("No existing server identity found. Generating new Ed25519 keypair...");
        let mut identity_bytes = [0u8; 32];
        let mut rng = rand_core::OsRng;
        rand_core::RngCore::fill_bytes(&mut rng, &mut identity_bytes);
        let key = SigningKey::from_bytes(&identity_bytes);
        let dto = ServerIdentityDto {
            ed25519_secret: hex::encode(identity_bytes),
        };
        fs::write(identity_path, serde_json::to_string_pretty(&dto)?)?;
        key
    };

    let server_pub = server_identity.verifying_key();

    let mut buffer = [0u8; 2048];

    // Defaults to 127.0.0.1:4430 for local testing without sudo.
    // Override with BIND_ADDR (e.g. "0.0.0.0:443" when running in Docker).
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:4430".to_string());
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
    info!("UDP server listening on {}", socket.local_addr()?);
    info!(
        "Server Static Pubkey: {}",
        hex::encode(server_pub.as_bytes())
    );

    let tables = Arc::new(Mutex::new(Tables::new()));
    // Wakes the outbound task the moment something may be ready to forward
    // (a packet queued, a recipient synced), instead of it polling.
    let outbound_wake = Arc::new(Notify::new());

    spawn_outbound_task(
        Arc::clone(&tables),
        Arc::clone(&socket),
        Arc::clone(&outbound_wake),
    );
    spawn_sweeping_task(Arc::clone(&tables));

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, addr)) => {
                // Per-packet logging is debug-only: a message is tens to
                // hundreds of packets, and this loop must keep draining.
                debug!("Received {} bytes from {}", len, addr);
                if let Err(e) =
                    match handle_request(&tables, &server_identity, addr, &buffer[..len]) {
                        Ok(Some(resp)) => {
                            if let Err(send_err) = socket.send_to(&resp, addr).await {
                                error!("Failed to send response: {}", send_err);
                            }
                            Ok(())
                        }
                        Ok(None) => {
                            outbound_wake.notify_one();
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                {
                    error!("Request handling error from {}: {}", addr, e);
                }
            }
            Err(e) => {
                error!("Receive error: {}", e);
            }
        }
    }
}

fn handle_request(
    tables: &Arc<Mutex<Tables>>,
    server_identity: &SigningKey,
    socket_address: SocketAddr,
    payload: &[u8],
) -> Result<Option<Vec<u8>>> {
    if payload.is_empty() {
        return Err(anyhow!("Empty payload"));
    }

    match payload[0] {
        TYPE_HANDSHAKE_INIT => {
            // Handshake format: [1 byte type] [4 byte SessionId] [32 byte Ephemeral PubKey] [32 byte Client Ed25519 Pub] [64 byte Signature]
            if payload.len() != 1 + 4 + 32 + 32 + 64 {
                return Err(anyhow!("Invalid handshake length"));
            }
            let mut session_id = [0u8; 4];
            session_id.copy_from_slice(&payload[1..5]);

            let mut pubkey_bytes = [0u8; 32];
            pubkey_bytes.copy_from_slice(&payload[5..37]);
            let client_pub = X25519PublicKey::from(pubkey_bytes);

            let mut client_ed_bytes = [0u8; 32];
            client_ed_bytes.copy_from_slice(&payload[37..69]);
            let client_ed_pub = ed25519_dalek::VerifyingKey::from_bytes(&client_ed_bytes)
                .map_err(|_| anyhow!("Invalid client ed25519 key"))?;

            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&payload[69..133]);
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            use ed25519_dalek::Verifier;
            client_ed_pub
                .verify(&pubkey_bytes, &signature)
                .map_err(|_| anyhow!("Invalid client signature"))?;

            let server_eph_secret =
                x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
            let server_eph_pub = X25519PublicKey::from(&server_eph_secret);

            let shared_secret = server_eph_secret.diffie_hellman(&client_pub);
            let mut link_master_key = [0u8; 32];
            Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes())
                .expand(b"wireguard-lite-link", &mut link_master_key)
                .map_err(|e| anyhow!("HKDF error: {}", e))?;

            let mut msg = Vec::new();
            msg.extend_from_slice(client_pub.as_bytes());
            msg.extend_from_slice(server_eph_pub.as_bytes());
            let signature = server_identity.sign(&msg);

            let mut resp = vec![TYPE_HANDSHAKE_RESP];
            resp.extend_from_slice(&session_id);
            resp.extend_from_slice(server_eph_pub.as_bytes());
            resp.extend_from_slice(&signature.to_bytes());

            let mut tables = tables.lock().unwrap();
            tables.register_link(session_id, link_master_key);
            info!("Registered new link for Session ID: {:?}", session_id);

            return Ok(Some(resp));
        }
        TYPE_DATA => {
            // Data format: [1 byte type] [4 byte SessionId] [24 byte Nonce] [Ciphertext...]
            if payload.len() < 1 + 4 + 24 + 16 {
                // 16 bytes for auth tag. If length is exactly 45, decrypted is 0 bytes (sync)
                return Err(anyhow!("Data packet too small"));
            }
            let mut session_id = [0u8; 4];
            session_id.copy_from_slice(&payload[1..5]);

            let mut nonce_bytes = [0u8; 24];
            nonce_bytes.copy_from_slice(&payload[5..29]);
            let nonce = XNonce::from_slice(&nonce_bytes);

            let ciphertext = &payload[29..];

            let link_key = {
                let tables = tables.lock().unwrap();
                match tables.get_link_key(&session_id) {
                    Some(k) => *k,
                    None => return Err(anyhow!("Unknown Session ID")),
                }
            };

            let cipher = XChaCha20Poly1305::new(Key::from_slice(&link_key));
            let plaintext = cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| anyhow!("Invalid link encryption MAC"))?;

            if plaintext.len() < 16 {
                return Err(anyhow!("Decrypted payload too small for routing token"));
            }

            let mut routing_token = [0u8; 16];
            routing_token.copy_from_slice(&plaintext[0..16]);

            let inner_payload = &plaintext[16..];

            if inner_payload.is_empty() {
                debug!("Sync Request mapped to token {:?}", routing_token);
                let mut tables = tables.lock().unwrap();
                tables.update_metadata(routing_token, socket_address, session_id, METADATA_TTL);
            } else {
                debug!("Forward Request for token {:?}", routing_token);
                let mut tables = tables.lock().unwrap();
                if !tables.enqueue_message(routing_token, inner_payload.to_vec(), MESSAGE_TTL) {
                    warn!("Queue full for token {:?}; dropped packet", routing_token);
                }
            }
        }
        _ => return Err(anyhow!("Unknown packet type")),
    }
    Ok(None)
}

fn spawn_outbound_task(tables: Arc<Mutex<Tables>>, socket: Arc<UdpSocket>, wake: Arc<Notify>) {
    tokio::spawn(async move {
        loop {
            let next_due = send_due_packets(&tables, &socket).await;
            // Sleep until the next pacing slot, or until something new
            // arrives (`notify_one` keeps a wake-up that lands mid-send).
            match next_due {
                Some(at) => tokio::select! {
                    _ = tokio::time::sleep_until(at.into()) => {}
                    _ = wake.notified() => {}
                },
                None => wake.notified().await,
            }
        }
    });
}

fn spawn_sweeping_task(tables: Arc<Mutex<Tables>>) {
    tokio::spawn(async move {
        loop {
            {
                let mut tables = tables.lock().unwrap();
                tables.sweep_active_links();
                tables.sweep_metadata();
                tables.sweep_expired_messages();
            }
            tokio::time::sleep(SWEEPING_TASK_INTERVAL).await;
        }
    });
}

/// Forward every packet whose recipient's pacing slot is due (see
/// `Tables::take_due`), re-encrypted under the recipient's link key.
/// Returns when the next slot falls due, if anything is still waiting.
async fn send_due_packets(tables: &Mutex<Tables>, socket: &UdpSocket) -> Option<Instant> {
    use rand_core::{OsRng, RngCore};

    let (due, next_due) = {
        let mut tables = tables.lock().unwrap();
        let (due, next_due) = tables.take_due(Instant::now(), RELAY_PACKET_SPACING);
        let due: Vec<_> = due
            .into_iter()
            .filter_map(|packet| Some((*tables.get_link_key(&packet.session_id)?, packet)))
            .collect();
        (due, next_due)
    };
    for (link_key, due) in due {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&link_key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let mut full_inner = vec![0u8; 16]; // Dummy routing token prefix
        full_inner.extend_from_slice(&due.payload);

        let ciphertext = cipher
            .encrypt(nonce, full_inner.as_slice())
            .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers");

        let mut packet = vec![TYPE_DATA];
        packet.extend_from_slice(&due.session_id);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        // Already taken off the queue: on failure, skip just this one.
        match socket.send_to(&packet, due.addr).await {
            Ok(_) => debug!("Sent {} bytes (re-encrypted) to {}", packet.len(), due.addr),
            Err(e) => error!(
                "Failed to forward {} bytes to {}: {}",
                packet.len(),
                due.addr,
                e
            ),
        }
    }
    next_due
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::EphemeralSecret;

    fn create_handshake_packet(client_secret: &EphemeralSecret, session_id: [u8; 4]) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let client_ed = SigningKey::from_bytes(&bytes);
        let client_ed_pub = client_ed.verifying_key();
        let pubkey = X25519PublicKey::from(client_secret);
        let signature = client_ed.sign(pubkey.as_bytes());

        let mut packet = vec![TYPE_HANDSHAKE_INIT];
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(pubkey.as_bytes());
        packet.extend_from_slice(client_ed_pub.as_bytes());
        packet.extend_from_slice(&signature.to_bytes());
        packet
    }

    fn create_data_packet(
        link_key: [u8; 32],
        session_id: [u8; 4],
        routing_token: [u8; 16],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&routing_token);
        plaintext.extend_from_slice(payload);

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&link_key));
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let mut packet = vec![TYPE_DATA];
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);
        packet
    }

    #[test]
    fn test_sync_then_forward() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let mut identity_bytes = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut identity_bytes);
        let server_identity = SigningKey::from_bytes(&identity_bytes);
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let session_id = [0xAA; 4];
        let routing_token = [0xBB; 16];
        let socket_address = SocketAddr::from(([127, 0, 0, 1], 50000));

        // 1. Handshake
        let handshake_pkt = create_handshake_packet(&client_secret, session_id);
        let resp = handle_request(&tables, &server_identity, socket_address, &handshake_pkt)
            .unwrap()
            .unwrap();

        // Calculate expected link key
        let mut server_eph_pub_bytes = [0u8; 32];
        server_eph_pub_bytes.copy_from_slice(&resp[5..37]);
        let server_eph_pub = X25519PublicKey::from(server_eph_pub_bytes);

        let shared_secret = client_secret.diffie_hellman(&server_eph_pub);
        let mut link_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes())
            .expand(b"wireguard-lite-link", &mut link_key)
            .unwrap();

        // 2. Sync Request (empty payload)
        let sync_pkt = create_data_packet(link_key, session_id, routing_token, b"");
        handle_request(&tables, &server_identity, socket_address, &sync_pkt).unwrap();

        {
            let tables_lock = tables.lock().unwrap();
            let metadata = tables_lock.get_metadata(&routing_token).unwrap();
            assert_eq!(metadata.incoming_addr, socket_address);
            assert_eq!(metadata.session_id, session_id);
        }

        // 3. Forward Request (payload "Hello")
        let forward_pkt = create_data_packet(link_key, session_id, routing_token, b"Hello");
        handle_request(&tables, &server_identity, socket_address, &forward_pkt).unwrap();

        {
            let mut tables_lock = tables.lock().unwrap();
            let (msgs, _) = tables_lock.take_due(Instant::now(), RELAY_PACKET_SPACING);
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].addr, socket_address);
            assert_eq!(msgs[0].payload, b"Hello");
        }
    }

    // ==========================================
    // Missing Edge Case: Server Relay & Handshake Tests
    // ==========================================

    #[test]
    fn test_edge_case_invalid_handshake() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let mut identity_bytes = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut identity_bytes);
        let server_identity = SigningKey::from_bytes(&identity_bytes);
        let socket_address = SocketAddr::from(([127, 0, 0, 1], 50000));

        let res = handle_request(&tables, &server_identity, socket_address, &[]);
        assert!(res.is_err(), "Empty packet should fail");

        let res = handle_request(
            &tables,
            &server_identity,
            socket_address,
            &[TYPE_HANDSHAKE_INIT, 0x01],
        );
        assert!(res.is_err(), "Invalid handshake length should fail");
    }

    #[test]
    fn test_edge_case_handshake_mutual_auth_failure() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let mut identity_bytes = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut identity_bytes);
        let server_identity = SigningKey::from_bytes(&identity_bytes);
        let socket_address = SocketAddr::from(([127, 0, 0, 1], 50000));

        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let mut hs_pkt = create_handshake_packet(&client_secret, [0xAA; 4]);

        // Corrupt the client's signature
        let len = hs_pkt.len();
        hs_pkt[len - 1] ^= 0x01;

        let res = handle_request(&tables, &server_identity, socket_address, &hs_pkt);
        assert!(res.is_err(), "Invalid client signature must fail");
    }

    #[test]
    fn test_edge_case_offline_queuing_and_sync() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let mut identity_bytes = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut identity_bytes);
        let server_identity = SigningKey::from_bytes(&identity_bytes);
        let sender_addr = SocketAddr::from(([127, 0, 0, 1], 50001));
        let receiver_addr = SocketAddr::from(([127, 0, 0, 1], 50002));

        let sender_secret = EphemeralSecret::random_from_rng(OsRng);
        let receiver_secret = EphemeralSecret::random_from_rng(OsRng);
        let sender_session = [0xAA; 4];
        let receiver_session = [0xBB; 4];
        let receiver_token = [0xCC; 16];

        // 1. Sender does handshake
        let hs_pkt = create_handshake_packet(&sender_secret, sender_session);
        let resp = handle_request(&tables, &server_identity, sender_addr, &hs_pkt)
            .unwrap()
            .unwrap();

        let mut server_eph_pub_bytes = [0u8; 32];
        server_eph_pub_bytes.copy_from_slice(&resp[5..37]);
        let server_eph_pub = X25519PublicKey::from(server_eph_pub_bytes);
        let shared_secret = sender_secret.diffie_hellman(&server_eph_pub);
        let mut sender_link_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes())
            .expand(b"wireguard-lite-link", &mut sender_link_key)
            .unwrap();

        // 2. Sender sends message to receiver (receiver is OFFLINE, not synced)
        let forward_pkt = create_data_packet(
            sender_link_key,
            sender_session,
            receiver_token,
            b"QueuedMsg",
        );
        handle_request(&tables, &server_identity, sender_addr, &forward_pkt).unwrap();

        // Ensure it's in the offline queue, NOT the outbound queue
        {
            let mut tables_lock = tables.lock().unwrap();
            let (msgs, next_due) = tables_lock.take_due(Instant::now(), RELAY_PACKET_SPACING);
            assert_eq!(msgs.len(), 0, "Should not be outbound yet");
            assert!(next_due.is_none(), "an offline recipient schedules nothing");
            assert_eq!(
                tables_lock
                    .get_queued_packets(&receiver_token)
                    .unwrap()
                    .len(),
                1
            );
        }

        // 3. Receiver comes online and handshakes
        let hs_pkt = create_handshake_packet(&receiver_secret, receiver_session);
        let resp = handle_request(&tables, &server_identity, receiver_addr, &hs_pkt)
            .unwrap()
            .unwrap();

        let mut server_eph_pub_bytes = [0u8; 32];
        server_eph_pub_bytes.copy_from_slice(&resp[5..37]);
        let server_eph_pub = X25519PublicKey::from(server_eph_pub_bytes);
        let shared_secret = receiver_secret.diffie_hellman(&server_eph_pub);
        let mut receiver_link_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes())
            .expand(b"wireguard-lite-link", &mut receiver_link_key)
            .unwrap();

        // 4. Receiver sends sync packet
        let sync_pkt = create_data_packet(receiver_link_key, receiver_session, receiver_token, b"");
        handle_request(&tables, &server_identity, receiver_addr, &sync_pkt).unwrap();

        // 5. Check that the queued packet was flushed to the outbound queue
        {
            let mut tables_lock = tables.lock().unwrap();
            let (msgs, _) = tables_lock.take_due(Instant::now(), RELAY_PACKET_SPACING);
            assert_eq!(
                msgs.len(),
                1,
                "Queued message should be flushed to outbound"
            );
            assert_eq!(msgs[0].payload, b"QueuedMsg");
            // Queue should be empty/removed now
            assert!(tables_lock.get_queued_packets(&receiver_token).is_none());
        }
    }

    #[test]
    fn test_edge_case_offline_queue_dos_bounds() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let mut identity_bytes = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut identity_bytes);
        let server_identity = SigningKey::from_bytes(&identity_bytes);
        let sender_addr = SocketAddr::from(([127, 0, 0, 1], 50001));

        let sender_secret = EphemeralSecret::random_from_rng(OsRng);
        let sender_session = [0xAA; 4];
        let receiver_token = [0xCC; 16];

        // 1. Sender handshakes
        let hs_pkt = create_handshake_packet(&sender_secret, sender_session);
        let resp = handle_request(&tables, &server_identity, sender_addr, &hs_pkt)
            .unwrap()
            .unwrap();

        let mut server_eph_pub_bytes = [0u8; 32];
        server_eph_pub_bytes.copy_from_slice(&resp[5..37]);
        let server_eph_pub = X25519PublicKey::from(server_eph_pub_bytes);
        let shared_secret = sender_secret.diffie_hellman(&server_eph_pub);
        let mut sender_link_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret.as_bytes())
            .expand(b"wireguard-lite-link", &mut sender_link_key)
            .unwrap();

        // 2. Spam an offline token with more than its queue holds
        let cap = crate::stores::MAX_QUEUED_BYTES_PER_TOKEN;
        let packet = vec![0xAB; 1000];
        let fits = cap / packet.len();
        for i in 0..fits + 5 {
            let mut msg = packet.clone();
            msg[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let forward_pkt =
                create_data_packet(sender_link_key, sender_session, receiver_token, &msg);
            handle_request(&tables, &server_identity, sender_addr, &forward_pkt).unwrap();
        }

        // 3. The queue is bounded by bytes, and keeps the *oldest* packets:
        // later ones are refused, rather than earlier ones evicted.
        {
            let tables_lock = tables.lock().unwrap();
            let queue = tables_lock.get_queued_packets(&receiver_token).unwrap();
            assert_eq!(
                queue.len(),
                fits,
                "Offline queue must refuse packets beyond limit"
            );
            assert_eq!(queue.front().unwrap().payload[..8], 0u64.to_be_bytes());
            assert_eq!(
                queue.back().unwrap().payload[..8],
                (fits as u64 - 1).to_be_bytes()
            );
        }
    }

    /// A backlog for an online recipient comes out whole, in order, and one
    /// packet per pacing slot — never all at once.
    #[test]
    fn test_backlog_is_paced_out_whole_and_in_order() {
        let mut tables = Tables::new();
        let token = [0xDD; 16];
        let addr = SocketAddr::from(([127, 0, 0, 1], 50003));
        tables.update_metadata(token, addr, [0xEE; 4], METADATA_TTL);
        for i in 0..300u32 {
            tables.enqueue_message(token, i.to_be_bytes().to_vec(), MESSAGE_TTL);
        }
        let mut now = Instant::now();
        for i in 0..300u32 {
            let (due, next_due) = tables.take_due(now, RELAY_PACKET_SPACING);
            assert_eq!(due.len(), 1, "one packet per slot");
            assert_eq!(due[0].payload, i.to_be_bytes());
            let (early, _) = tables.take_due(now, RELAY_PACKET_SPACING);
            assert!(early.is_empty(), "nothing before the next slot");
            if i < 299 {
                assert_eq!(next_due, Some(now + RELAY_PACKET_SPACING));
            } else {
                assert_eq!(next_due, None, "drained");
            }
            now += RELAY_PACKET_SPACING;
        }
    }

    /// Recipients are paced independently: one's backlog doesn't hold up
    /// another's packets.
    #[test]
    fn test_recipients_are_paced_independently() {
        let mut tables = Tables::new();
        let (a, b) = ([0xA1; 16], [0xB1; 16]);
        tables.update_metadata(
            a,
            SocketAddr::from(([127, 0, 0, 1], 1)),
            [1; 4],
            METADATA_TTL,
        );
        tables.update_metadata(
            b,
            SocketAddr::from(([127, 0, 0, 1], 2)),
            [2; 4],
            METADATA_TTL,
        );
        for _ in 0..10 {
            tables.enqueue_message(a, vec![0xA], MESSAGE_TTL);
        }
        tables.enqueue_message(b, vec![0xB], MESSAGE_TTL);
        let (due, _) = tables.take_due(Instant::now(), RELAY_PACKET_SPACING);
        let mut payloads: Vec<_> = due.iter().map(|p| p.payload.clone()).collect();
        payloads.sort();
        assert_eq!(payloads, [vec![0xA], vec![0xB]]);
    }

    /// The whole forwarding path: packets queued for an online recipient are
    /// re-encrypted under *their* link key, prefixed with the dummy routing
    /// token, and sent over UDP — all of them, in order, paced, as soon as
    /// the outbound task is woken.
    #[tokio::test]
    async fn test_outbound_forwarding_reencrypts_and_paces_every_packet() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let recipient = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wake = Arc::new(Notify::new());
        spawn_outbound_task(Arc::clone(&tables), relay, Arc::clone(&wake));
        let (session, token, link_key) = ([0x11; 4], [0x22; 16], [0x33; 32]);
        {
            let mut t = tables.lock().unwrap();
            t.register_link(session, link_key);
            t.update_metadata(
                token,
                recipient.local_addr().unwrap(),
                session,
                METADATA_TTL,
            );
            for i in 0..60u8 {
                t.enqueue_message(token, vec![i; 40], MESSAGE_TTL);
            }
        }
        let started = Instant::now();
        wake.notify_one();

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&link_key));
        let mut buf = [0u8; 2048];
        for i in 0..60u8 {
            let (len, _) = recipient.recv_from(&mut buf).await.unwrap();
            let packet = &buf[..len];
            assert_eq!(packet[0], TYPE_DATA);
            assert_eq!(packet[1..5], session);
            let inner = cipher
                .decrypt(XNonce::from_slice(&packet[5..29]), &packet[29..])
                .unwrap();
            assert_eq!(inner[..16], [0u8; 16]);
            assert_eq!(inner[16..], [i; 40]);
        }
        assert!(started.elapsed() >= RELAY_PACKET_SPACING * 59, "paced");
        assert!(tables.lock().unwrap().get_queued_packets(&token).is_none());
    }

    #[test]
    fn test_edge_case_offline_queue_ttl_expiry() {
        let mut tables = Tables::new();
        let receiver_token = [0xCC; 16];

        // Manually enqueue a message with 0 TTL (so it expires immediately)
        tables.enqueue_message(
            receiver_token,
            b"ExpiredMsg".to_vec(),
            std::time::Duration::from_secs(0),
        );

        // Wait 1 ms to ensure 'now' is past the expiry
        std::thread::sleep(std::time::Duration::from_millis(1));

        // Enqueue a valid message
        tables.enqueue_message(
            receiver_token,
            b"ValidMsg".to_vec(),
            std::time::Duration::from_secs(3600),
        );

        assert_eq!(tables.get_queued_packets(&receiver_token).unwrap().len(), 2);

        // Sweep
        tables.sweep_expired_messages();

        // Queue should now only have the valid message
        let queue = tables.get_queued_packets(&receiver_token).unwrap();
        assert_eq!(queue.len(), 1, "Expired message should be swept");
        assert_eq!(queue[0].payload, b"ValidMsg");
    }
}
