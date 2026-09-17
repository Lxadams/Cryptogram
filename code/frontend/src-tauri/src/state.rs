//! Shared state held by the Tauri backend between command invocations.
//!
//! `Client` (from the `client` crate) already IS the full protocol/crypto
//! state machine that the CLI drives directly — we just need to keep one
//! alive across GUI events instead of a stdin loop, plus the UDP socket it
//! sends/receives on.

use client::Client;
use std::{fs::File, sync::Arc};
use tokio::{net::UdpSocket, sync::Mutex};
use zeroize::Zeroizing;

/// Everything needed to actually talk to the relay: the protocol state
/// machine plus the socket it was handshaked on. `None` until the
/// `bootstrap` command successfully completes the link handshake.
pub struct ClientRuntime {
    pub client: Client,
    pub socket: Arc<UdpSocket>,
    /// Handles to the background tasks `bootstrap` spawned (receive,
    /// keepalive, presence loops) — aborted by `logout` so they don't keep
    /// running against an abandoned socket/identity after the user switches
    /// identities without closing the whole app.
    pub tasks: Vec<tauri::async_runtime::JoinHandle<()>>,
}

/// Which identity the `login` command resolved (pseudonym + passcode
/// checked/created), waiting for `bootstrap` to actually load/create the
/// `Client` from `state_path` and perform the relay handshake. Split into
/// its own step because identity resolution (login) doesn't need the relay
/// address, while `Client::new` for a brand-new identity currently does.
#[derive(Clone)]
pub struct PendingIdentity {
    pub pseudonym: String,
    pub state_path: String,
    /// Derived once from the login passcode (see `derive_vault_key` in the
    /// `client` crate) and carried forward only as this key — the passcode
    /// itself is zeroized and dropped inside the `login` command, never
    /// stored in `AppState`. `bootstrap` uses this to open the identity's
    /// SQLCipher chat-history database. `Zeroizing` wipes it from memory
    /// once `bootstrap` takes it (or on logout, whichever comes first).
    pub vault_key: Zeroizing<[u8; 32]>,
}

/// Tauri-managed application state (registered via `.manage(...)` in
/// `lib.rs`). A `tokio::sync::Mutex` (not `std::sync::Mutex`) because
/// commands hold the lock across `.await` points (e.g. while sending a UDP
/// packet), which a std mutex guard can't safely do in async code.
#[derive(Default)]
pub struct AppState {
    pub runtime: Mutex<Option<ClientRuntime>>,
    pub pending_identity: Mutex<Option<PendingIdentity>>,
    /// The open handle to the logged-in identity's `session.lock` file (see
    /// `resolve_login` in `commands.rs`), held for as long as this process
    /// runs so no other process can log into the same identity at the same
    /// time. Never read after being set — its only job is to stay alive
    /// (dropping it, e.g. on process exit, releases the OS-level lock).
    pub identity_lock: Mutex<Option<File>>,
}
