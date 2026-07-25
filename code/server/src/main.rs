use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{error, info};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
mod stores;

use stores::Tables;
const DUMMY_PACKET: &[u8] = b"dummy";

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Bind to UDP port 8080 on all interfaces
    let socket = UdpSocket::bind("0.0.0.0:8080").await?;

    info!("UDP server listening on {}", socket.local_addr()?);

    let mut buffer = [0u8; 1024]; // initialize every byte to zero for 1024 elements

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, addr)) => {
                info!("Received {} bytes from {}", len, addr);

                // Print payload as string
                info!("Payload: {}", String::from_utf8_lossy(&buffer[..len]));
            }
            Err(e) => {
                error!("Receive error: {}", e);
            }
        }
    }
}

async fn send_udp_message(socket: &UdpSocket, addr: &str, message: &[u8]) -> Result<()> {
    let bytes_sent = socket.send_to(message, addr).await?;
    info!("Sent {} bytes to {}", bytes_sent, addr);
    Ok(())
}

async fn send_outbound_messages(
    tables: &Arc<Mutex<Tables>>,
    socket: &UdpSocket,
) -> Result<()> {
    let mut tables = tables.lock().unwrap();

    tables.sweep_metadata();
    tables.sweep_expired_messages();

    let mut sent_sessions = HashSet::new();

    while let Some(message) = tables.dequeue_message() {
        if let Some(metadata) =
            tables.get_metadata(&message.receiver_session_id)
        {
            send_udp_message(socket, &metadata.incoming_addr.to_string(), &message.payload).await?;

            sent_sessions.insert(message.receiver_session_id);
        }

        // else:
        // receiver no longer exists
        // discard message
    }

    for (session_id, metadata) in tables.metadata_iter() {
        if !sent_sessions.contains(session_id) {
            send_udp_message(socket, &metadata.incoming_addr.to_string(), DUMMY_PACKET).await?;
        }
    }

    Ok(())
}