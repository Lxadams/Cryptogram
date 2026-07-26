use anyhow::{Result, anyhow};
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UdpSocket;
use tracing::{error, info};
mod stores;

use crate::stores::SessionId;
use stores::Tables;

const DUMMY_PACKET: &[u8] = b"dummy";
const METADATA_TTL: Duration = Duration::from_secs(1000);
const MESSAGE_TTL: Duration = Duration::from_secs(1000);
const OUTBOUND_TASK_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("info").init();

    let mut buffer = [0u8; 1024]; // initialize every byte to zero for 1024 elements

    // Bind to UDP port 443 on all interfaces
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:443").await?);
    info!("UDP server listening on {}", socket.local_addr()?);

    let tables = Arc::new(Mutex::new(Tables::new()));

    // Spawn a background task to handle outbound messages
    spawn_outbound_task(Arc::clone(&tables), Arc::clone(&socket));

    // Main loop to receive incoming UDP packets
    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, addr)) => {
                info!("Received {} bytes from {}", len, addr);
                if let Err(e) = handle_request(&tables, addr, &buffer[..len]) {
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
    socket_address: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    // For demonstration, let's assume the first byte indicates the type of request (0 for sync, 1 for forward)
    // Next two bytes are the session ID (for simplicity, we assume it's a string)
    // The rest of the payload is the actual message or data.

    const SESSION_ID_LEN: usize = 2;

    if payload.len() < 1 + SESSION_ID_LEN {
        return Err(anyhow!(
            "Invalid packet length: expected at least {} bytes, got {}",
            1 + SESSION_ID_LEN,
            payload.len()
        ));
    }

    let peer_session_id = String::from_utf8_lossy(&payload[1..1 + SESSION_ID_LEN]).to_string();
    let blob = &payload[1 + SESSION_ID_LEN..];
    info!(
        "First byte flag: {}, Session ID: {}, Blob: {}",
        payload[0],
        peer_session_id,
        String::from_utf8_lossy(blob)
    );

    match payload.first() {
        Some(0) => {
            info!("Handling sync request for session ID: {}", peer_session_id);
            handle_sync_request(tables, socket_address, &peer_session_id)?;
        }
        Some(1) => {
            info!(
                "Handling forward request for session ID: {}",
                peer_session_id
            );
            handle_forward_request(tables, &peer_session_id, blob.to_vec())?;
        }
        _ => {
            error!("Unknown request type");
        }
    }

    match tables.lock() {
        Ok(tables) => tables.print_state(),
        Err(e) => error!("Tables mutex poisoned while printing state: {e}"),
    }
    Ok(())
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

fn handle_sync_request(
    tables: &Arc<Mutex<Tables>>,
    socket_address: SocketAddr,
    sender_session_id: &SessionId,
) -> Result<()> {
    let mut tables = tables
        .lock()
        .map_err(|e| anyhow!("Tables mutex poisoned: {e}"))?;
    tables.update_metadata(sender_session_id.to_string(), socket_address, METADATA_TTL);

    Ok(())
}

fn handle_forward_request(
    tables: &Arc<Mutex<Tables>>,
    receiver_session_id: &SessionId,
    payload: Vec<u8>,
) -> Result<()> {
    let mut tables = tables.lock().unwrap();
    tables.enqueue_message(receiver_session_id.to_string(), payload, MESSAGE_TTL);

    Ok(())
}

async fn send_udp_message(socket: &UdpSocket, addr: &str, message: &[u8]) -> Result<()> {
    let bytes_sent = socket.send_to(message, addr).await?;
    info!(
        "Sent message: {}, with {} bytes to {}",
        String::from_utf8_lossy(message),
        bytes_sent,
        addr
    );
    Ok(())
}

fn prepare_outbound_messages(tables: &Arc<Mutex<Tables>>) -> (Vec<(String, Vec<u8>)>, Vec<String>) {
    let (messages, dummy_targets) = {
        let mut tables = tables.lock().unwrap();

        tables.sweep_metadata();
        tables.sweep_expired_messages();

        let mut sent_sessions = HashSet::new();
        let mut messages = Vec::new();

        for message in tables.outbound_messages() {
            if let Some(metadata) = tables.get_metadata(&message.receiver_session_id) {
                messages.push((metadata.incoming_addr.to_string(), message.payload));
                sent_sessions.insert(message.receiver_session_id);
            }
        }

        let mut dummy_targets = Vec::new();

        for (session_id, metadata) in tables.metadata_iter() {
            if !sent_sessions.contains(session_id) {
                dummy_targets.push(metadata.incoming_addr.to_string());
            }
        }

        (messages, dummy_targets)
    };
    (messages, dummy_targets)
}

async fn send_outbound_messages(tables: &Arc<Mutex<Tables>>, socket: &UdpSocket) -> Result<()> {
    let (messages, dummy_targets) = prepare_outbound_messages(tables);
    for (addr, payload) in &messages {
        send_udp_message(socket, addr, payload).await?;
    }

    for addr in &dummy_targets {
        send_udp_message(socket, addr, DUMMY_PACKET).await?;
    }

    Ok(())
}

// --------------------- Unit tests ---------------------
#[cfg(test)]
mod tests {
    use super::*;
    use utils::prepare_udp_payload;

    #[test]
    fn test_sync_then_forward_themselves() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let socket_address = SocketAddr::from(([127, 0, 0, 1], 50000));

        let sync_packet = prepare_udp_payload(0, b"01", b"");
        handle_request(&tables, socket_address, &sync_packet).unwrap();

        {
            let tables = tables.lock().unwrap();
            let metadata = tables.metadata_iter().collect::<Vec<_>>();
            let outbound_messages = tables.outbound_messages();

            assert_eq!(metadata.len(), 1);
            assert_eq!(metadata[0].0, "01");
            assert_eq!(metadata[0].1.incoming_addr, socket_address);
            assert!(outbound_messages.is_empty());
        }

        let forward_packet = prepare_udp_payload(1, b"01", b"Hello myself");
        handle_request(&tables, socket_address, &forward_packet).unwrap();

        {
            let (messages, dummy_targets) = prepare_outbound_messages(&tables);
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].0, socket_address.to_string());
            assert_eq!(messages[0].1, b"Hello myself");

            assert_eq!(dummy_targets.len(), 0);

            let tables = tables.lock().unwrap();
            let metadata = tables.metadata_iter().collect::<Vec<_>>();
            let outbound_messages = tables.outbound_messages();

            assert_eq!(metadata.len(), 1);
            assert_eq!(metadata[0].0, "01");
            assert_eq!(metadata[0].1.incoming_addr, socket_address);

            assert_eq!(outbound_messages.len(), 1);
            assert_eq!(outbound_messages[0].receiver_session_id, "01");
            assert_eq!(outbound_messages[0].payload, b"Hello myself");
        }
    }

    #[test]
    fn test_sync_then_forward_to_another_client() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let socket_address_alice = SocketAddr::from(([127, 0, 0, 1], 50000));
        let socket_address_bob = SocketAddr::from(([127, 0, 0, 1], 50001));

        let sync_packet_alice = prepare_udp_payload(0, b"01", b"");
        let sync_packet_bob = prepare_udp_payload(0, b"02", b"");
        handle_request(&tables, socket_address_alice, &sync_packet_alice).unwrap();
        handle_request(&tables, socket_address_bob, &sync_packet_bob).unwrap();

        {
            let tables = tables.lock().unwrap();
            let mut metadata = tables.metadata_iter().collect::<Vec<_>>();
            metadata.sort_by_key(|(session_id, _)| session_id.to_string());
            let outbound_messages = tables.outbound_messages();

            assert_eq!(metadata.len(), 2);
            assert_eq!(metadata[0].0, "01");
            assert_eq!(metadata[0].1.incoming_addr, socket_address_alice);
            assert_eq!(metadata[1].0, "02");
            assert_eq!(metadata[1].1.incoming_addr, socket_address_bob);
            assert!(outbound_messages.is_empty());
        }

        let forward_packet_to_bob = prepare_udp_payload(1, b"02", b"Hello bob");
        handle_request(&tables, socket_address_bob, &forward_packet_to_bob).unwrap();

        {
            let (messages, dummy_targets) = prepare_outbound_messages(&tables);
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].0, socket_address_bob.to_string());
            assert_eq!(messages[0].1, b"Hello bob");

            assert_eq!(dummy_targets.len(), 1);
            assert_eq!(dummy_targets[0], socket_address_alice.to_string());

            let tables = tables.lock().unwrap();
            let mut metadata = tables.metadata_iter().collect::<Vec<_>>();
            metadata.sort_by_key(|(session_id, _)| session_id.to_string());
            let outbound_messages = tables.outbound_messages();

            assert_eq!(metadata.len(), 2);
            assert_eq!(metadata[0].0, "01");
            assert_eq!(metadata[0].1.incoming_addr, socket_address_alice);
            assert_eq!(metadata[1].0, "02");
            assert_eq!(metadata[1].1.incoming_addr, socket_address_bob);

            assert_eq!(outbound_messages.len(), 1);
            assert_eq!(outbound_messages[0].receiver_session_id, "02");
            assert_eq!(outbound_messages[0].payload, b"Hello bob");
        }
    }

    #[test]
    fn test_outbound_queue_sweep() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        {
            let mut tables = tables.lock().unwrap();
            tables.enqueue_message(
                SessionId::from("01"),
                b"Hello".to_vec(),
                Duration::from_millis(1),
            );
            std::thread::sleep(Duration::from_millis(5));
            tables.sweep_expired_messages();
            let outbound_messages = tables.outbound_messages();
            assert!(outbound_messages.is_empty());
        }
    }

    #[test]
    fn test_metadata_sweep() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let socket_address = SocketAddr::from(([127, 0, 0, 1], 50000));
        {
            let mut tables = tables.lock().unwrap();
            tables.update_metadata(
                SessionId::from("01"),
                socket_address,
                Duration::from_micros(1),
            );
            std::thread::sleep(Duration::from_micros(10));

            tables.sweep_metadata();
            let metadata = tables.metadata_iter().collect::<Vec<_>>();
            assert!(metadata.is_empty());
        }
    }
}
