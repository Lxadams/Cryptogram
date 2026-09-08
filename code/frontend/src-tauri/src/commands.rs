//! `#[tauri::command]` functions — these are the only bridge between the
//! Leptos/WASM frontend and the real `client` crate. The frontend never
//! touches sockets or crypto directly; it calls these by name (via
//! `invoke("command_name", args)` on the JS/WASM side) and gets plain,
//! serializable DTOs back.

use crate::state::{AppState, ClientRuntime};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use client::{Client, ClientStateDto, TYPE_DATA, perform_handshake, state_file_path};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};
use tauri::{AppHandle, Manager, State};
use tokio::net::UdpSocket;

/// The relay (server) this prototype always talks to. Hardcoded for now —
/// same assumption the CLI makes (`127.0.0.1:4430`, see runserver.sh).
const SERVER_ADDR: &str = "127.0.0.1:4430";

#[derive(Serialize, Clone)]
pub struct IdentityDto {
    pub routing_token: String,
    pub ed25519_public: String,
    /// This peer's own display name, if launched via `./runpeer.sh <name>`
    /// (read from `E2E_PEER_NAME`). Share it alongside the token/key so a
    /// peer adding you as a contact can label you with it instead of hex.
    pub name: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct ContactDto {
    pub token: String,
    /// "established" once the PQXDH session handshake completed, otherwise
    /// "pending" (KeyExchange sent/received, waiting on SessionEstablish).
    pub status: String,
    /// Locally-entered display name for this contact, if one was given
    /// when adding them (see `connect_to_peer`'s `name` argument).
    pub name: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct IncomingMessageDto {
    pub from_token: String,
    pub text: String,
}

fn identity_dto(client: &Client) -> IdentityDto {
    IdentityDto {
        routing_token: hex::encode(client.identity.routing_token),
        ed25519_public: hex::encode(client.identity.ed25519_public.as_bytes()),
        name: Some(client.local_name.clone()).filter(|n| !n.is_empty()),
    }
}

/// Perform the link-layer handshake with the relay and start listening for
/// inbound packets. Must be called once before any other command will work.
/// Mirrors what the CLI's `main()` does at startup, just triggered by a UI
/// button instead of running unconditionally on process start.
#[tauri::command(rename_all = "snake_case")]
pub async fn bootstrap(
    app: AppHandle,
    state: State<'_, AppState>,
    server_pubkey_hex: String,
) -> Result<IdentityDto, String> {
    let server_pub_bytes = hex::decode(server_pubkey_hex.trim())
        .map_err(|_| "Server public key must be hex".to_string())?;
    let arr: [u8; 32] = server_pub_bytes
        .try_into()
        .map_err(|_| "Server public key must be 32 bytes (64 hex chars)".to_string())?;
    let server_pub =
        VerifyingKey::from_bytes(&arr).map_err(|_| "Invalid server public key".to_string())?;

    let server_addr: SocketAddr = SERVER_ADDR.parse().expect("hardcoded address is valid");

    // Resume a previous identity if one was saved, otherwise mint a new one
    // — identical fallback logic to the CLI.
    let mut client =
        ClientStateDto::load(&state_file_path()).unwrap_or_else(|_| Client::new(server_addr));

    // The pseudonym this peer chose at launch (`./runpeer.sh alice` sets
    // this via E2E_PEER_NAME) — sent with every outgoing KeyExchange so
    // peers can label us by name automatically, with no manual step on
    // their end. Re-applied on every bootstrap rather than persisted, so
    // renaming a peer is just a matter of relaunching it with a new name.
    client.local_name = std::env::var("E2E_PEER_NAME").unwrap_or_default();

    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| e.to_string())?,
    );

    perform_handshake(&mut client, &socket, &server_pub)
        .await
        .map_err(|e| e.to_string())?;
    client.save();

    let identity = identity_dto(&client);

    *state.runtime.lock().await = Some(ClientRuntime {
        client,
        socket: socket.clone(),
    });

    spawn_receive_loop(app, socket);

    Ok(identity)
}

/// Background task: read inbound UDP packets for as long as the app runs,
/// strip the link-layer encryption, and hand the inner payload to the
/// client state machine — exactly what the CLI's spawned task does, just
/// living here instead. Decrypted messages land in `Client::inbox`, which
/// the frontend collects by polling `poll_inbox`.
fn spawn_receive_loop(app: AppHandle, socket: Arc<UdpSocket>) {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let mut buf = [0u8; 4096];
        loop {
            let (len, _addr) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            if len < 1 + 4 + 24 + 16 || buf[0] != TYPE_DATA {
                continue;
            }

            let mut guard = state.runtime.lock().await;
            let Some(rt) = guard.as_mut() else {
                continue;
            };

            let mut session_id = [0u8; 4];
            session_id.copy_from_slice(&buf[1..5]);
            if session_id != rt.client.session_id {
                continue;
            }

            let mut nonce_bytes = [0u8; 24];
            nonce_bytes.copy_from_slice(&buf[5..29]);
            let link_nonce = XNonce::from_slice(&nonce_bytes);
            let ciphertext = &buf[29..len];
            let link_cipher = XChaCha20Poly1305::new(Key::from_slice(&rt.client.link_master_key));

            let Ok(decrypted) = link_cipher.decrypt(link_nonce, ciphertext) else {
                continue;
            };
            if decrypted.len() < 16 {
                continue;
            }

            let e2e_payload = &decrypted[16..];
            if let Ok(Some(reply)) = rt.client.handle_incoming_packet(e2e_payload) {
                let _ = socket.send_to(&reply, rt.client.server_addr).await;
            }
        }
    });
}

#[tauri::command(rename_all = "snake_case")]
pub async fn get_identity(state: State<'_, AppState>) -> Result<IdentityDto, String> {
    let guard = state.runtime.lock().await;
    let rt = guard.as_ref().ok_or("Not connected to relay yet")?;
    Ok(identity_dto(&rt.client))
}

/// Union of `pending_contacts` (KeyExchange in flight) and `e2e_sessions`
/// (fully established) — everyone the UI should show in the contact list,
/// with a status badge for which stage they're at.
#[tauri::command(rename_all = "snake_case")]
pub async fn list_contacts(state: State<'_, AppState>) -> Result<Vec<ContactDto>, String> {
    let guard = state.runtime.lock().await;
    let rt = guard.as_ref().ok_or("Not connected to relay yet")?;

    let mut contacts: Vec<ContactDto> = rt
        .client
        .pending_contacts
        .keys()
        .map(|token| ContactDto {
            token: hex::encode(token),
            status: "pending".to_string(),
            name: rt.client.contact_names.get(token).cloned(),
        })
        .collect();

    for token in rt.client.e2e_sessions.keys() {
        let token_hex = hex::encode(token);
        if let Some(existing) = contacts.iter_mut().find(|c| c.token == token_hex) {
            existing.status = "established".to_string();
        } else {
            contacts.push(ContactDto {
                token: token_hex,
                status: "established".to_string(),
                name: rt.client.contact_names.get(token).cloned(),
            });
        }
    }

    Ok(contacts)
}

/// Start a key exchange with a peer identified by their QR-scanned
/// `(routing_token, ed25519_public_key)` pair. Real trust anchor: the
/// signature check against this exact key happens on the reply (see
/// `Client::handle_incoming_packet`, 0x02 branch, initiator path).
#[tauri::command(rename_all = "snake_case")]
pub async fn connect_to_peer(
    state: State<'_, AppState>,
    token_hex: String,
    ed25519_hex: String,
) -> Result<(), String> {
    let mut guard = state.runtime.lock().await;
    let rt = guard.as_mut().ok_or("Not connected to relay yet")?;

    let token_bytes = hex::decode(token_hex.trim()).map_err(|_| "Bad token hex".to_string())?;
    let token: [u8; 16] = token_bytes
        .try_into()
        .map_err(|_| "Routing token must be 16 bytes".to_string())?;

    let ed_bytes = hex::decode(ed25519_hex.trim()).map_err(|_| "Bad key hex".to_string())?;
    let ed_arr: [u8; 32] = ed_bytes
        .try_into()
        .map_err(|_| "Ed25519 key must be 32 bytes".to_string())?;
    let peer_ed25519 =
        VerifyingKey::from_bytes(&ed_arr).map_err(|_| "Invalid Ed25519 key".to_string())?;

    rt.client.pending_contacts.insert(token, peer_ed25519);
    let req_packet = rt.client.create_kx_request(token);
    rt.socket
        .send_to(&req_packet, rt.client.server_addr)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Encrypt and send an E2E message to an already-established session. Also
/// sends a PQ ratchet-injection packet alongside, transparently, whenever
/// `create_encrypted_packet` produces one (every 5th message).
#[tauri::command(rename_all = "snake_case")]
pub async fn send_message(
    state: State<'_, AppState>,
    token_hex: String,
    text: String,
) -> Result<(), String> {
    let mut guard = state.runtime.lock().await;
    let rt = guard.as_mut().ok_or("Not connected to relay yet")?;

    let token_bytes = hex::decode(token_hex.trim()).map_err(|_| "Bad token hex".to_string())?;
    let token: [u8; 16] = token_bytes
        .try_into()
        .map_err(|_| "Routing token must be 16 bytes".to_string())?;

    let (msg_packet, pq_inject_packet) = rt
        .client
        .create_encrypted_packet(token, text.as_bytes())
        .map_err(|e| e.to_string())?;

    rt.socket
        .send_to(&msg_packet, rt.client.server_addr)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(pq_pkt) = pq_inject_packet {
        rt.socket
            .send_to(&pq_pkt, rt.client.server_addr)
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Collect any messages decrypted since the last poll. The frontend calls
/// this on a timer (see `code/frontend/src/api.rs`) — there's no push
/// channel wired up in this prototype, just polling.
#[tauri::command(rename_all = "snake_case")]
pub async fn poll_inbox(state: State<'_, AppState>) -> Result<Vec<IncomingMessageDto>, String> {
    let mut guard = state.runtime.lock().await;
    let rt = guard.as_mut().ok_or("Not connected to relay yet")?;

    Ok(rt
        .client
        .drain_inbox()
        .into_iter()
        .map(|(token, bytes)| IncomingMessageDto {
            from_token: hex::encode(token),
            text: String::from_utf8_lossy(&bytes).into_owned(),
        })
        .collect())
}
