use anyhow::{Result, anyhow};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UdpSocket;
use tracing::{error, info};
use x25519_dalek::PublicKey as X25519PublicKey;
mod stores;

use crate::stores::{SessionId, Tables};

const METADATA_TTL: Duration = Duration::from_secs(1000);
const MESSAGE_TTL: Duration = Duration::from_secs(1000);
const OUTBOUND_TASK_INTERVAL: Duration = Duration::from_secs(1);
const SWEEPING_TASK_INTERVAL: Duration = Duration::from_secs(120);

// Request Types
const TYPE_HANDSHAKE_INIT: u8 = 0;
const TYPE_DATA: u8 = 1;
const TYPE_HANDSHAKE_RESP: u8 = 2;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Generate server static identity
    let mut identity_bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut identity_bytes);
    let server_identity = SigningKey::from_bytes(&identity_bytes);
    let server_pub = server_identity.verifying_key();

    let mut buffer = [0u8; 2048];

    // Bind to 127.0.0.1:4430 for local testing without sudo
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:4430").await?);
    info!("UDP server listening on {}", socket.local_addr()?);
    info!(
        "Server Static Pubkey: {}",
        hex::encode(server_pub.as_bytes())
    );

    let tables = Arc::new(Mutex::new(Tables::new()));

    spawn_outbound_task(Arc::clone(&tables), Arc::clone(&socket));
    spawn_sweeping_task(Arc::clone(&tables));

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, addr)) => {
                info!("Received {} bytes from {}", len, addr);
                if let Err(e) =
                    match handle_request(&tables, &server_identity, addr, &buffer[..len]) {
                        Ok(Some(resp)) => {
                            if let Err(send_err) = socket.send_to(&resp, addr).await {
                                error!("Failed to send response: {}", send_err);
                            }
                            Ok(())
                        }
                        Ok(None) => Ok(()),
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
            // Handshake format: [1 byte type] [4 byte SessionId] [32 byte Ephemeral PubKey]
            if payload.len() != 1 + 4 + 32 {
                return Err(anyhow!("Invalid handshake length"));
            }
            let mut session_id = [0u8; 4];
            session_id.copy_from_slice(&payload[1..5]);

            let mut pubkey_bytes = [0u8; 32];
            pubkey_bytes.copy_from_slice(&payload[5..37]);
            let client_pub = X25519PublicKey::from(pubkey_bytes);

            let server_eph_secret =
                x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
            let server_eph_pub = X25519PublicKey::from(&server_eph_secret);

            let shared_secret = server_eph_secret.diffie_hellman(&client_pub);
            let mut link_master_key = [0u8; 32];
            Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
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
                info!("Sync Request mapped to token {:?}", routing_token);
                let mut tables = tables.lock().unwrap();
                tables.update_metadata(routing_token, socket_address, session_id, METADATA_TTL);
            } else {
                info!("Forward Request for token {:?}", routing_token);
                let mut tables = tables.lock().unwrap();
                tables.enqueue_message(routing_token, inner_payload.to_vec(), MESSAGE_TTL);
            }
        }
        _ => return Err(anyhow!("Unknown packet type")),
    }
    Ok(None)
}

fn spawn_outbound_task(tables: Arc<Mutex<Tables>>, socket: Arc<UdpSocket>) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = send_outbound_messages(&tables, &socket).await {
                error!("Error sending outbound messages: {}", e);
            }
            tokio::time::sleep(OUTBOUND_TASK_INTERVAL).await;
        }
    });
}

fn spawn_sweeping_task(tables: Arc<Mutex<Tables>>) {
    tokio::spawn(async move {
        loop {
            {
                let mut tables = tables.lock().unwrap();
                tables.sweep_metadata();
                tables.sweep_expired_messages();
            }
            tokio::time::sleep(SWEEPING_TASK_INTERVAL).await;
        }
    });
}

type OutboundMessages = (Vec<(String, Vec<u8>, SessionId)>, Vec<(String, SessionId)>);

fn prepare_outbound_messages(tables: &Arc<Mutex<Tables>>) -> OutboundMessages {
    let (messages, dummy_targets) = {
        let tables = tables.lock().unwrap();
        let mut sent_tokens = HashSet::new();
        let mut messages = Vec::new();

        for message in tables.outbound_messages() {
            if let Some(metadata) = tables.get_metadata(&message.receiver_token) {
                messages.push((
                    metadata.incoming_addr.to_string(),
                    message.payload,
                    metadata.session_id,
                ));
                sent_tokens.insert(message.receiver_token);
            }
        }

        let mut dummy_targets = Vec::new();

        for (token, metadata) in tables.metadata_iter() {
            if !sent_tokens.contains(token) {
                dummy_targets.push((metadata.incoming_addr.to_string(), metadata.session_id));
            }
        }

        (messages, dummy_targets)
    };
    (messages, dummy_targets)
}

async fn send_outbound_messages(tables: &Arc<Mutex<Tables>>, socket: &UdpSocket) -> Result<()> {
    use rand_core::{OsRng, RngCore};

    let (messages, dummy_targets) = prepare_outbound_messages(tables);
    for (addr, inner_payload, recipient_session_id) in &messages {
        // Look up recipient's link key to re-encrypt
        let link_key = {
            let tables = tables.lock().unwrap();
            match tables.get_link_key(recipient_session_id) {
                Some(k) => *k,
                None => continue,
            }
        };

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&link_key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, inner_payload.as_ref())
            .map_err(|_| anyhow!("Failed to re-encrypt outbound"))?;

        let mut packet = vec![TYPE_DATA];
        packet.extend_from_slice(recipient_session_id);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        socket.send_to(&packet, addr).await?;
        info!("Sent {} bytes (re-encrypted) to {}", packet.len(), addr);
    }

    for (addr, recipient_session_id) in &dummy_targets {
        let link_key = {
            let tables = tables.lock().unwrap();
            match tables.get_link_key(recipient_session_id) {
                Some(k) => *k,
                None => continue,
            }
        };

        // Generate random dummy payload of fixed size
        let mut dummy_payload = vec![0u8; 64];
        OsRng.fill_bytes(&mut dummy_payload);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&link_key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, dummy_payload.as_ref())
            .map_err(|_| anyhow!("Failed to encrypt dummy"))?;

        let mut packet = vec![TYPE_DATA];
        packet.extend_from_slice(recipient_session_id);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        socket.send_to(&packet, addr).await?;
        info!("Sent DUMMY packet (encrypted) to {}", addr);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::EphemeralSecret;

    fn create_handshake_packet(client_secret: &EphemeralSecret, session_id: [u8; 4]) -> Vec<u8> {
        let pubkey = X25519PublicKey::from(client_secret);
        let mut packet = vec![TYPE_HANDSHAKE_INIT];
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(pubkey.as_bytes());
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
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut identity_bytes);
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
        Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
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
            let tables_lock = tables.lock().unwrap();
            let msgs = tables_lock.outbound_messages();
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].receiver_token, routing_token);
            assert_eq!(msgs[0].payload, b"Hello");
        }
    }
}
