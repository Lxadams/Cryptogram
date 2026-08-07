//! Shared state held by the Tauri backend between command invocations.
//!
//! `Client` (from the `client` crate) already IS the full protocol/crypto
//! state machine that the CLI drives directly — we just need to keep one
//! alive across GUI events instead of a stdin loop, plus the UDP socket it
//! sends/receives on.

use client::Client;
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::Mutex};

/// Everything needed to actually talk to the relay: the protocol state
/// machine plus the socket it was handshaked on. `None` until the
/// `bootstrap` command successfully completes the link handshake.
pub struct ClientRuntime {
    pub client: Client,
    pub socket: Arc<UdpSocket>,
}

/// Tauri-managed application state (registered via `.manage(...)` in
/// `lib.rs`). A `tokio::sync::Mutex` (not `std::sync::Mutex`) because
/// commands hold the lock across `.await` points (e.g. while sending a UDP
/// packet), which a std mutex guard can't safely do in async code.
#[derive(Default)]
pub struct AppState {
    pub runtime: Mutex<Option<ClientRuntime>>,
}
