// CLI entry point for the `client` crate.
//
// This file used to contain everything: UserIdentity, SymmetricSessionState,
// Client and all its crypto/protocol methods, the packets/storage modules,
// and all 34 unit tests. That logic has been moved into `lib.rs` so it can
// be reused as a library rather than being locked inside this one binary —
// this file now only holds what's actually specific to the terminal REPL
// (arg parsing, the stdin command loop, the socket receive loop). The
// motivation: a Tauri desktop shell (code/frontend/src-tauri) needs to call
// the exact same Client/handshake/ratchet code this CLI uses, and a bin
// crate can't be depended on by another crate — only a lib crate can. This
// split keeps one implementation of the protocol logic instead of forking
// it between two front ends.
use anyhow::{Result, anyhow};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{io::AsyncBufReadExt, net::UdpSocket, sync::Mutex};

use client::{
    BurstSender, Client, ClientStateDto, parse_routing_token, parse_verifying_key,
    perform_handshake, state_file_path,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    // The server's Ed25519 identity pubkey is passed on the command line
    // (printed by the server on boot) so the client can authenticate the
    // link handshake response.
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <server_ed25519_pubkey_hex>", args[0]);
        std::process::exit(1);
    }

    let server_pub =
        parse_verifying_key(&args[1]).map_err(|e| anyhow!("Invalid server pubkey: {e}"))?;

    // Defaults to 127.0.0.1:4430 to match the server's local-dev default.
    // Override with SERVER_ADDR (e.g. "server:443" when running in Docker
    // Compose, where the relay isn't reachable via loopback). Resolved via
    // DNS lookup rather than SocketAddr::parse so a Compose service name
    // works, not just IP literals.
    let server_addr_raw =
        std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:4430".to_string());
    let server_addr: SocketAddr = tokio::net::lookup_host(&server_addr_raw)
        .await?
        .next()
        .ok_or_else(|| anyhow!("Could not resolve SERVER_ADDR: {}", server_addr_raw))?;

    // Resume a previous identity/session set if one was persisted to disk,
    // otherwise mint a fresh identity.
    let client_obj = match ClientStateDto::load(&state_file_path()) {
        Ok(c) => {
            println!("Loaded client state from disk.");
            c
        }
        Err(_) => Client::new(server_addr),
    };

    let client = Arc::new(Mutex::new(client_obj));
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    // Message bursts go out one at a time, in order, paced on their own task.
    let bursts = BurstSender::spawn(Arc::clone(&socket), server_addr);

    // Link-layer handshake with the relay (X25519 DH, the relay's reply
    // signed with the key we were given), then a sync proving our routing
    // token is ours, so the relay can route to our current IP.
    // (perform_handshake lives in lib.rs — shared with any other front end.)
    {
        let mut c = client.lock().await;
        perform_handshake(&mut c, &socket, &server_pub).await?;
        println!(
            "Completed Server Link Handshake! Session ID: {}",
            hex::encode(c.link.session_id())
        );
        c.save();

        println!("=== MY IDENTITY ===");
        println!("Token:   {}", hex::encode(c.identity.routing_token));
        println!(
            "Ed25519: {}",
            hex::encode(c.identity.ed25519_public.as_bytes())
        );
        println!("===================");
    }

    // Background task: continuously read inbound UDP packets and hand them
    // to the client state machine (see `Client::handle_relay_packet`). Any
    // protocol reply it produces (e.g. a KeyExchange response) and the ack
    // the relay waits for are sent straight back out.
    let socket_clone = Arc::clone(&socket);
    let client_clone = Arc::clone(&client);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((len, _)) = socket_clone.recv_from(&mut buf).await {
                let mut c = client_clone.lock().await;
                for packet in c.handle_relay_packet(&buf[..len]) {
                    let _ = socket_clone.send_to(&packet, c.server_addr).await;
                }
            }
        }
    });

    // Background task: the keepalive (see `Client::keepalive`). A sync
    // every 15s keeps our NAT mapping (and the relay's record of where we
    // are) alive, and sends contacts we're still setting up with our
    // KeyExchange again when due. If the relay stops acking our syncs (it
    // restarted, say), this redoes the handshake instead.
    let keepalive_socket = Arc::clone(&socket);
    let keepalive_client = Arc::clone(&client);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(15));
        ticker.tick().await; // the first tick is immediate; we just synced
        loop {
            ticker.tick().await;
            let mut c = keepalive_client.lock().await;
            for packet in c.keepalive() {
                let _ = keepalive_socket.send_to(&packet, c.server_addr).await;
            }
        }
    });

    // Background task, twice a second: print any message held for one sent
    // before it that has waited long enough (see
    // `Client::release_held_messages`), whether or not another packet comes
    // in meanwhile, ask the relay which of our messages it has (see
    // `Client::receipt_requests`), and ask contacts for any PQ refresh we're
    // holding their messages for (see `Client::pq_inject_requests`).
    let tick_socket = Arc::clone(&socket);
    let tick_client = Arc::clone(&client);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        loop {
            ticker.tick().await;
            let mut c = tick_client.lock().await;
            c.release_held_messages();
            let mut packets = c.receipt_requests();
            packets.extend(c.pq_inject_requests());
            for packet in packets {
                let _ = tick_socket.send_to(&packet, c.server_addr).await;
            }
        }
    });

    println!("Commands:");
    println!("  connect <routing_token_hex> <ed25519_pub_hex>");
    println!("  msg <routing_token_hex> <text...>");
    println!("  repair <routing_token_hex>");

    // Simple stdin REPL: `connect <token> <ed25519>` to start a key
    // exchange with a peer, `msg <token> <text>` to send an E2E message.
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
                let (token, bob_ed25519) =
                    match (parse_routing_token(parts[1]), parse_verifying_key(parts[2])) {
                        (Ok(token), Ok(key)) => (token, key),
                        (Err(e), _) | (_, Err(e)) => {
                            println!("Error: {e}");
                            continue;
                        }
                    };
                let mut c = client.lock().await;
                // Trust is asserted here from the (assumed) QR-scanned key;
                // the reply's signature is checked against this on receipt.
                match c.add_contact(token, bob_ed25519) {
                    Ok(req_packet) => {
                        socket.send_to(&req_packet, server_addr).await.unwrap();
                        for packet in c.take_extra_packets() {
                            let _ = socket.send_to(&packet, server_addr).await;
                        }
                        println!("Sent connection request! They need to connect to you too.");
                    }
                    Err(e) => println!("Error: {e}"),
                }
            }
            "repair" => {
                // A new session with a contact whose one has broken (see
                // `Client::repair_session`).
                let token = match parts.get(1).map(|t| parse_routing_token(t)) {
                    Some(Ok(token)) => token,
                    Some(Err(e)) => {
                        println!("Error: {e}");
                        continue;
                    }
                    None => {
                        println!("Usage: repair <token>");
                        continue;
                    }
                };
                let mut c = client.lock().await;
                match c.repair_session(token) {
                    Ok(packet) => {
                        let _ = socket.send_to(&packet, server_addr).await;
                        for packet in c.take_extra_packets() {
                            let _ = socket.send_to(&packet, server_addr).await;
                        }
                        println!("Repairing the session: they'll set up a new one with you.");
                    }
                    Err(e) => println!("Error: {e}"),
                }
            }
            "msg" => {
                if parts.len() < 3 {
                    println!("Usage: msg <token> <text...>");
                    continue;
                }
                let token = match parse_routing_token(parts[1]) {
                    Ok(token) => token,
                    Err(e) => {
                        println!("Error: {e}");
                        continue;
                    }
                };
                let text = parts[2..].join(" ");
                // One burst of FEC packets (with any PQ ratchet injection
                // bundled inside), queued before the lock is released (see
                // `BurstSender::queue`), but waited for after, so the receive
                // loop isn't locked out while the burst drains.
                let mut c = client.lock().await;
                match c.create_fec_packets(token, text.as_bytes()) {
                    Ok(packets) => {
                        let count = packets.len();
                        let first_sent = bursts.queue(packets);
                        drop(c);
                        match first_sent.await {
                            Ok(()) => println!("Sending msg as a burst of {count} packets..."),
                            Err(e) => println!("Error: msg not sent: {e}"),
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
