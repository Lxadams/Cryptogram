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
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::VerifyingKey;
use std::{net::SocketAddr, sync::Arc};
use tokio::{io::AsyncBufReadExt, net::UdpSocket, sync::Mutex};

use client::{Client, ClientStateDto, TYPE_DATA, perform_handshake, state_file_path};

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

    // Link-layer handshake with the relay (X25519 DH + Ed25519 mutual auth),
    // then announce ourselves so the relay can route to our current IP.
    // (perform_handshake lives in lib.rs — shared with any other front end.)
    {
        let mut c = client.lock().await;
        perform_handshake(&mut c, &socket, &server_pub).await?;
        println!(
            "Completed Server Link Handshake! Session ID: {}",
            hex::encode(c.session_id)
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

    // Background task: continuously read inbound UDP packets, strip the
    // link-layer encryption, and hand the inner E2E payload to the client
    // state machine. Any protocol reply it produces (e.g. a KeyExchange
    // response) is sent straight back out.
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
                let token_bytes = hex::decode(parts[1]).unwrap();
                let mut token = [0u8; 16];
                token.copy_from_slice(&token_bytes);
                let ed25519_bytes = hex::decode(parts[2]).unwrap();
                let mut ed_arr = [0u8; 32];
                ed_arr.copy_from_slice(&ed25519_bytes);
                let bob_ed25519 = VerifyingKey::from_bytes(&ed_arr).unwrap();
                let mut c = client.lock().await;
                // Trust is asserted here from the (assumed) QR-scanned key;
                // the reply's signature is checked against this on receipt.
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
                        // Every PQ_INJECT_INTERVAL messages, create_encrypted_packet
                        // also hands back a fresh Kyber ratchet packet to send alongside.
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
