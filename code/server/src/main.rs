use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{error, info};
use std::{
    collections::HashSet,
    net::{SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration},
};
mod stores;

use stores::Tables;

use crate::stores::SessionId;
const DUMMY_PACKET: &[u8] = b"dummy";
const METADATA_TTL: Duration = Duration::from_secs(1000);
const MESSAGE_TTL: Duration = Duration::from_secs(1000);
const OUTBOUND_TASK_INTERVAL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("info").init();

    let mut buffer = [0u8; 1024]; // initialize every byte to zero for 1024 elements
    
    // Bind to UDP port 8080 on all interfaces
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:8080").await?);
    info!("UDP server listening on {}", socket.local_addr()?);

    let tables = Arc::new(Mutex::new(Tables::new()));
    
    // Spawn a background task to handle outbound messages
    spawn_outbound_task(Arc::clone(&tables), Arc::clone(&socket));

    // Main loop to receive incoming UDP packets
    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, addr)) => {
                info!("Received {} bytes from {}", len, addr);

                // Print payload as string
                info!("Payload: {}", String::from_utf8_lossy(&buffer[..len]));
                
                // TODO: differentiate between sync and forward requests based on the payload content
                // let session_id = String::from_utf8_lossy(&buffer[..len]).to_string();
                // handle_sync_request(&tables, addr, &session_id)?;
                // handle_forward_request(&tables, &session_id, buffer[..len].to_vec())?;
            }
            Err(e) => {
                error!("Receive error: {}", e);
            }
        }
    }
}

fn spawn_outbound_task(tables: Arc<Mutex<Tables>>, socket: Arc<UdpSocket>) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = send_outbound_messages(&tables, &socket).await {
                error!("Error sending outbound messages: {}", e);
            }
            info!("Sent outbound messages and dummy packets");
            tokio::time::sleep(OUTBOUND_TASK_INTERVAL).await;
        }
    });
}

fn handle_sync_request(
    tables: &Arc<Mutex<Tables>>,
    socket_address: SocketAddr,
    sender_session_id: &SessionId,
) -> Result<()> {
    let mut tables = tables.lock().unwrap();
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
    info!("Sent {} bytes to {}", bytes_sent, addr);
    Ok(())
}

async fn send_outbound_messages(
    tables: &Arc<Mutex<Tables>>,
    socket: &UdpSocket,
) -> Result<()> {
    let (messages, dummy_targets) = {
        let mut tables = tables.lock().unwrap();

        tables.sweep_metadata();
        tables.sweep_expired_messages();

        let mut sent_sessions = HashSet::new();
        let mut messages = Vec::new();

        while let Some(message) = tables.dequeue_message() {
            if let Some(metadata) =
                tables.get_metadata(&message.receiver_session_id)
            {
                messages.push((
                    metadata.incoming_addr.to_string(),
                    message.payload,
                ));
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

    for (addr, payload) in messages {
        send_udp_message(socket, &addr, &payload).await?;
    }

    for addr in dummy_targets {
        send_udp_message(socket, &addr, DUMMY_PACKET).await?;
    }

    Ok(())
}