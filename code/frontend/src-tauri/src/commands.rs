//! `#[tauri::command]` functions — these are the only bridge between the
//! Leptos/WASM frontend and the real `client` crate. The frontend never
//! touches sockets or crypto directly; it calls these by name (via
//! `invoke("command_name", args)` on the JS/WASM side) and gets plain,
//! serializable DTOs back.

use crate::state::{AppState, ClientRuntime, PendingIdentity};
use chacha20poly1305::{aead::Aead, Key, KeyInit, XChaCha20Poly1305, XNonce};
use client::{hash_passcode, perform_handshake, verify_passcode, Client, ClientStateDto, TYPE_DATA};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use std::{
    fs::{self, File, TryLockError},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tauri::{AppHandle, Manager, State};
use tokio::net::UdpSocket;

/// Root directory identities are stored under: the OS-standard per-app data
/// directory (e.g. `~/.local/share/<bundle-id>/identities` on Linux —
/// resolved from `tauri.conf.json`'s `identifier`), not a path relative to
/// process cwd. This used to be a bare `identities/` relative to cwd, which
/// broke in practice: `cargo tauri dev` runs its `DevCommand` with cwd set
/// to `src-tauri/` (a `cargo run` implementation detail), while a peer that
/// attaches to an already-running dev server via `runpeer.sh` execs the
/// built binary directly with cwd left at `code/frontend/` — two different
/// processes on the same machine landing in two different `identities/`
/// directories (confirmed: `src-tauri/identities/<name>` vs.
/// `identities/<name>` after testing two peers). Worse, every autosave
/// inside `src-tauri/` looked like a source change to Tauri's dev-mode file
/// watcher (which explicitly watches `src-tauri/`), so it kept killing and
/// relaunching whichever peer had landed there. The app-data dir is fixed
/// by the app's bundle identifier, so every process — host, attached peer,
/// or a real installed build launched however the OS chooses to — resolves
/// to the exact same directory.
fn identities_root(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|dir| dir.join("identities"))
        .map_err(|e| e.to_string())
}

/// Restrict a pseudonym to characters that are safe as a single path
/// component on every OS this might run on, and reject anything that could
/// escape `identities/` (`.`, `..`, `/`, `\`) or that's empty/absurdly long.
/// This is the only place user-typed text becomes part of a filesystem
/// path, so it's a hard boundary, not a UX nicety.
fn sanitize_pseudonym(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Choose a username first.".to_string());
    }
    if trimmed.len() > 40 {
        return Err("Username must be 40 characters or fewer.".to_string());
    }
    let valid = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ');
    if !valid {
        return Err(
            "Username can only contain letters, numbers, spaces, '-' and '_'.".to_string(),
        );
    }
    Ok(trimmed.to_string())
}

/// `(client_state.json path, passcode.hash path, session.lock path)` for a
/// given (already sanitized) pseudonym under `root` (see `identities_root`).
fn identity_paths(root: &Path, pseudonym: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = root.join(pseudonym);
    (
        dir.join("client_state.json"),
        dir.join("passcode.hash"),
        dir.join("session.lock"),
    )
}

/// Become the exclusive holder of an identity's `session.lock` file,
/// creating it if this is the first time it's needed. The caller must keep
/// the returned `File` alive for as long as the lock should be held —
/// dropping it releases the lock. Used both to block a second simultaneous
/// login to the same identity, and to refuse deleting an identity that's
/// currently in use elsewhere.
///
/// No stale-lock cleanup is needed: this is an OS-level advisory lock (via
/// `std::fs::File::try_lock`, stabilized in Rust 1.89), released
/// automatically by the kernel the instant the holding process's file
/// descriptor closes — including on a crash or `kill -9` — never left
/// dangling the way a "lock file that just means 'someone wrote this'"
/// would be.
fn try_acquire_session_lock(lock_path: &Path) -> Result<File, String> {
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| e.to_string())?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            Err("This identity is already logged in elsewhere on this machine.".to_string())
        }
        Err(TryLockError::Error(e)) => Err(e.to_string()),
    }
}

/// The relay (server) this prototype talks to. Defaults to the CLI's own
/// local-dev default (`127.0.0.1:4430`, see runserver.sh); override with
/// the `SERVER_ADDR` env var (e.g. a deployed EC2 host's `<ip>:443`) —
/// mirrors the same override on the CLI (see code/client/src/main.rs).
fn server_addr_raw() -> String {
    std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:4430".to_string())
}

/// How often we send a presence ping to each established contact.
/// Independent of `spawn_keepalive_loop`'s 15s NAT-mapping keepalive —
/// that one's timing-critical against router UDP timeouts, this one is
/// just a UI-freshness tradeoff and free to differ.
const PRESENCE_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// A contact counts as "online" if we've heard from them (ping or chat
/// message) within this long. A little over 2x the ping interval, so one
/// dropped UDP packet doesn't immediately flip the marker to offline.
const PRESENCE_FRESHNESS: std::time::Duration = std::time::Duration::from_secs(45);

#[derive(Serialize, Clone)]
pub struct IdentityDto {
    pub routing_token: String,
    pub ed25519_public: String,
    /// This peer's own display name, chosen on the login screen. Share it
    /// alongside the token/key so a peer adding you as a contact can label
    /// you with it instead of hex.
    pub name: Option<String>,
}

/// What `login` resolved to. `UnknownUsername` is deliberately *not* an
/// `Err` — it's an expected, common outcome (the user hasn't created that
/// identity yet) that the frontend needs to react to specifically (offer
/// "create a new identity?" instead of a generic error), so it's typed
/// instead of asking the frontend to string-match an error message. Genuine
/// failures (wrong passcode, empty fields, invalid characters) stay plain
/// `Err(String)`, same as every other command in this file.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginOutcome {
    Success { pseudonym: String },
    UnknownUsername,
}

/// Internal counterpart to `LoginOutcome` that also carries the resolved
/// `client_state.json` path and the held session lock for `login` to stash
/// in `AppState` — kept out of `LoginOutcome` itself since neither is ever
/// meaningful to the frontend.
#[derive(Debug)]
enum LoginResolution {
    Success {
        pseudonym: String,
        state_path: PathBuf,
        lock: File,
    },
    UnknownUsername,
}

/// Every pseudonym with a saved identity on this machine (i.e. every
/// subdirectory of `root` that has a `passcode.hash`). Split out from the
/// `list_pseudonyms` command (which just wraps this in `Ok`) so it's plain
/// sync code `cargo test` can call directly.
fn list_pseudonyms_sync(root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("passcode.hash").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

/// So the login screen can offer known pseudonyms instead of only accepting
/// free-typed names.
#[tauri::command(rename_all = "snake_case")]
pub async fn list_pseudonyms(app: AppHandle) -> Result<Vec<String>, String> {
    Ok(list_pseudonyms_sync(&identities_root(&app)?))
}

/// All the filesystem-facing logic behind `login`, kept free of `AppState`/
/// Tauri so it can be exercised directly with `cargo test` rather than only
/// through a running app. Only ever verifies an *existing* pseudonym's
/// passcode — creating one is `resolve_create_identity`'s job, on the
/// separate Create Identity screen. An unrecognized username is reported as
/// `LoginResolution::UnknownUsername`, not an `Err` — see its doc comment.
/// A correct passcode still fails if another process already holds this
/// identity's session lock (see `try_acquire_session_lock`) — logging into
/// the same identity twice at once isn't allowed.
fn resolve_login(root: &Path, pseudonym: &str, passcode: &str) -> Result<LoginResolution, String> {
    let pseudonym = sanitize_pseudonym(pseudonym)?;
    if passcode.is_empty() {
        return Err("Enter your passcode.".to_string());
    }

    let (state_path, passcode_path, lock_path) = identity_paths(root, &pseudonym);
    if !passcode_path.is_file() {
        return Ok(LoginResolution::UnknownUsername);
    }
    let stored = fs::read_to_string(&passcode_path).map_err(|e| e.to_string())?;
    if !verify_passcode(passcode, &stored) {
        return Err("Incorrect passcode.".to_string());
    }
    let lock = try_acquire_session_lock(&lock_path)?;

    Ok(LoginResolution::Success { pseudonym, state_path, lock })
}

/// The filesystem-facing logic behind `create_identity`: mint a fresh
/// `passcode.hash` for a pseudonym that doesn't have one yet. Deliberately
/// does *not* log the new identity in (no `AppState` involved) — per the
/// Login/Create Identity screen split, creating an identity always returns
/// to the Login screen rather than proceeding straight to Connect.
fn resolve_create_identity(root: &Path, pseudonym: &str, passcode: &str) -> Result<(), String> {
    let pseudonym = sanitize_pseudonym(pseudonym)?;
    if passcode.is_empty() {
        return Err("Choose a passcode first.".to_string());
    }

    let (state_path, passcode_path, _lock_path) = identity_paths(root, &pseudonym);
    if passcode_path.is_file() {
        return Err("That username is already taken.".to_string());
    }
    let dir = state_path
        .parent()
        .expect("identity_paths always returns a path with a parent");
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    fs::write(&passcode_path, hash_passcode(passcode)).map_err(|e| e.to_string())?;
    Ok(())
}

/// The filesystem-facing logic behind `delete_identity`: permanently erase
/// a pseudonym's saved identity. Deliberately does **not** check the
/// passcode — per the user's request, this is the only recovery path for a
/// forgotten passcode (there is no password reset), so requiring the
/// passcode to delete would defeat the point. It does refuse to delete an
/// identity another process currently holds the session lock for, so you
/// can't delete out from under a live login elsewhere.
fn resolve_delete_identity(root: &Path, pseudonym: &str) -> Result<(), String> {
    let pseudonym = sanitize_pseudonym(pseudonym)?;
    let (state_path, passcode_path, lock_path) = identity_paths(root, &pseudonym);
    if !passcode_path.is_file() {
        return Err("No identity found for that username.".to_string());
    }
    let _lock = try_acquire_session_lock(&lock_path)?;
    let dir = state_path
        .parent()
        .expect("identity_paths always returns a path with a parent");
    fs::remove_dir_all(dir).map_err(|e| e.to_string())?;
    Ok(())
}

/// Verify an existing pseudonym's passcode and stash which identity file
/// `bootstrap` should load next in `AppState::pending_identity`. This is a
/// UI-layer gate only (see `hash_passcode`'s doc comment) — it performs no
/// network activity itself. Returns `LoginOutcome::UnknownUsername` (not an
/// error) if the pseudonym has no saved identity yet — see `create_identity`
/// for that. Also errors (a plain, generic-looking `Err`, same as a wrong
/// passcode) if this identity is already logged in on another process — see
/// `try_acquire_session_lock`.
#[tauri::command(rename_all = "snake_case")]
pub async fn login(
    app: AppHandle,
    state: State<'_, AppState>,
    pseudonym: String,
    passcode: String,
) -> Result<LoginOutcome, String> {
    let root = identities_root(&app)?;
    match resolve_login(&root, &pseudonym, &passcode)? {
        LoginResolution::Success { pseudonym, state_path, lock } => {
            *state.pending_identity.lock().await = Some(PendingIdentity {
                pseudonym: pseudonym.clone(),
                state_path: state_path.to_string_lossy().into_owned(),
            });
            // Held for the rest of this process's life — see
            // `AppState::identity_lock`'s doc comment.
            *state.identity_lock.lock().await = Some(lock);
            Ok(LoginOutcome::Success { pseudonym })
        }
        LoginResolution::UnknownUsername => Ok(LoginOutcome::UnknownUsername),
    }
}

/// Create a brand-new identity gated behind `passcode`. Errors if that
/// username is already taken. Does not log the user in — the Create
/// Identity screen sends them back to Login on success, where they log in
/// with the username/passcode they just chose (see `resolve_create_identity`).
#[tauri::command(rename_all = "snake_case")]
pub async fn create_identity(app: AppHandle, pseudonym: String, passcode: String) -> Result<(), String> {
    resolve_create_identity(&identities_root(&app)?, &pseudonym, &passcode)
}

/// Permanently delete a saved identity. Does not require its passcode — see
/// `resolve_delete_identity`'s doc comment for why — and refuses if that
/// identity is currently logged in on another process.
#[tauri::command(rename_all = "snake_case")]
pub async fn delete_identity(app: AppHandle, pseudonym: String) -> Result<(), String> {
    resolve_delete_identity(&identities_root(&app)?, &pseudonym)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh throwaway directory for one test, so tests never share state
    /// or race each other — unlike an earlier version of these tests, which
    /// switched the process's cwd and needed a lock to keep tests from
    /// stomping on each other's relative paths. Threading `root` through
    /// every function explicitly (instead of resolving it from cwd) avoids
    /// that whole class of problem, in the tests and in the app itself: see
    /// `identities_root`'s doc comment for the real bug that motivated this.
    fn scratch_dir(test_name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "e2e-login-test-{}-{}-{:?}",
            std::process::id(),
            test_name,
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_create_identity_then_login() {
        let root = scratch_dir("create_then_login");
        resolve_create_identity(&root, "alice", "hunter2").unwrap();
        match resolve_login(&root, "alice", "hunter2").unwrap() {
            LoginResolution::Success { pseudonym, state_path, .. } => {
                assert_eq!(pseudonym, "alice");
                assert_eq!(state_path, root.join("alice").join("client_state.json"));
            }
            LoginResolution::UnknownUsername => panic!("expected a successful login"),
        }
    }

    #[test]
    fn test_login_twice_at_once_is_rejected() {
        let root = scratch_dir("double_login");
        resolve_create_identity(&root, "alice", "hunter2").unwrap();
        // Hold the lock as the "other process" would, by keeping the first
        // successful login's `File` alive for the duration of this test.
        let first = resolve_login(&root, "alice", "hunter2").unwrap();
        let LoginResolution::Success { lock: _first_lock, .. } = first else {
            panic!("expected a successful login");
        };
        let err = resolve_login(&root, "alice", "hunter2").unwrap_err();
        assert_eq!(err, "This identity is already logged in elsewhere on this machine.");
    }

    #[test]
    fn test_delete_identity_removes_it_and_requires_recreation() {
        let root = scratch_dir("delete_identity");
        resolve_create_identity(&root, "alice", "hunter2").unwrap();
        resolve_delete_identity(&root, "alice").unwrap();
        assert!(matches!(
            resolve_login(&root, "alice", "hunter2").unwrap(),
            LoginResolution::UnknownUsername
        ));
        // No passcode needed to delete — and deleting an already-deleted
        // (i.e. never-existed) identity is just the usual "not found" error.
        let err = resolve_delete_identity(&root, "alice").unwrap_err();
        assert_eq!(err, "No identity found for that username.");
    }

    #[test]
    fn test_delete_identity_rejects_while_logged_in_elsewhere() {
        let root = scratch_dir("delete_while_locked");
        resolve_create_identity(&root, "alice", "hunter2").unwrap();
        let login = resolve_login(&root, "alice", "hunter2").unwrap();
        let LoginResolution::Success { lock: _held_lock, .. } = login else {
            panic!("expected a successful login");
        };
        let err = resolve_delete_identity(&root, "alice").unwrap_err();
        assert_eq!(err, "This identity is already logged in elsewhere on this machine.");
    }

    #[test]
    fn test_login_before_create_is_unknown_username() {
        let root = scratch_dir("login_before_create");
        let outcome = resolve_login(&root, "nobody", "whatever").unwrap();
        assert!(matches!(outcome, LoginResolution::UnknownUsername));
    }

    #[test]
    fn test_create_identity_rejects_duplicate_username() {
        let root = scratch_dir("duplicate_username");
        resolve_create_identity(&root, "bob", "first-passcode").unwrap();
        let err = resolve_create_identity(&root, "bob", "second-passcode").unwrap_err();
        assert_eq!(err, "That username is already taken.");
        // And the *first* passcode should still be the one that works.
        assert!(resolve_login(&root, "bob", "first-passcode").is_ok());
    }

    #[test]
    fn test_login_rejects_wrong_passcode() {
        let root = scratch_dir("wrong_passcode");
        resolve_create_identity(&root, "carol", "correct-passcode").unwrap();
        let err = resolve_login(&root, "carol", "wrong-passcode").unwrap_err();
        assert_eq!(err, "Incorrect passcode.");
    }

    #[test]
    fn test_rejects_bad_input() {
        let root = scratch_dir("bad_input");
        assert!(resolve_create_identity(&root, "", "pw").is_err());
        assert!(resolve_create_identity(&root, "dave", "").is_err());
        assert!(resolve_create_identity(&root, "../escape", "pw").is_err());
        assert!(resolve_create_identity(&root, "dave/../../etc", "pw").is_err());
        assert!(resolve_login(&root, "", "pw").is_err());
        assert!(resolve_login(&root, "dave", "").is_err());
    }

    #[test]
    fn test_list_pseudonyms_reflects_created_identities() {
        let root = scratch_dir("list_pseudonyms");
        resolve_create_identity(&root, "dave", "pw1").unwrap();
        resolve_create_identity(&root, "erin", "pw2").unwrap();
        let names = list_pseudonyms_sync(&root);
        assert_eq!(names, vec!["dave".to_string(), "erin".to_string()]);
    }
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
    /// True if we've heard a presence ping or chat message from this
    /// contact within `PRESENCE_FRESHNESS`. Always false for a merely
    /// "pending" contact — there's no session to ping over yet.
    pub online: bool,
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

    let server_addr_raw = server_addr_raw();
    let server_addr: SocketAddr = tokio::net::lookup_host(&server_addr_raw)
        .await
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("Could not resolve SERVER_ADDR: {server_addr_raw}"))?;

    // Which identity to load/create was already decided by the `login`
    // command (pseudonym + passcode check), before this screen ever runs.
    let pending = state
        .pending_identity
        .lock()
        .await
        .clone()
        .ok_or("Log in first")?;

    // Resume a previous identity if one was saved, otherwise mint a new one
    // — identical fallback logic to the CLI, just from a per-pseudonym path
    // instead of the single global default.
    let mut client = ClientStateDto::load(&pending.state_path)
        .unwrap_or_else(|_| Client::new(server_addr));
    // `Client::new` defaults `state_path` to the global `state_file_path()`
    // (right for the CLI, which has no pending identity); rebind it here so
    // a freshly-created identity still saves to its own pseudonym's file,
    // not the shared default. A loaded identity already matches, since it
    // was just loaded from this same path, but setting it unconditionally
    // keeps this correct even if that ever changes.
    client.state_path = pending.state_path;
    client.local_name = pending.pseudonym;

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

    // Spawned before being stored: each loop looks up `state.runtime` fresh
    // on every tick (tolerating it being briefly `None`), so spawn order
    // relative to the `state.runtime` write below doesn't matter.
    let tasks = vec![
        spawn_receive_loop(app.clone(), socket.clone()),
        spawn_keepalive_loop(app.clone(), socket.clone()),
        spawn_presence_loop(app, socket.clone()),
    ];

    *state.runtime.lock().await = Some(ClientRuntime {
        client,
        socket,
        tasks,
    });

    Ok(identity)
}

/// Log out of the current identity: stop its background tasks, drop the
/// `Client`/socket, and release its session lock (see
/// `AppState::identity_lock`) so it can be logged into again — by this
/// process or another one. Lets the user switch identities without closing
/// the whole app. Safe to call at any point after `login`, even before
/// `bootstrap` ever ran (e.g. abandoning the Connect screen).
#[tauri::command(rename_all = "snake_case")]
pub async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(rt) = state.runtime.lock().await.take() {
        for task in rt.tasks {
            task.abort();
        }
    }
    state.pending_identity.lock().await.take();
    state.identity_lock.lock().await.take();
    Ok(())
}

/// Background task: periodically resend an empty `sync` packet to the relay
/// (the same packet type `perform_handshake` sends once at bootstrap).
///
/// This only matters once the relay and client are on different machines.
/// The relay learns/refreshes our real `ip:port` purely from the source
/// address of our packets, and its own record has a long TTL (see
/// `METADATA_TTL` in `code/server/src/stores.rs`) — but that's irrelevant if
/// our *own* NAT/router UDP mapping expires first, which home/campus
/// routers typically do within 30-60s of silence. Without this, bootstrap
/// (an immediate round trip on a fresh mapping) succeeds, but any peer
/// packet routed to us minutes later gets silently dropped by our own
/// router before it ever reaches this process. Resending well under that
/// window keeps the mapping (and the relay's record) alive for as long as
/// the app runs. Purely client-side — the relay already handles a resent
/// sync packet identically to the first one.
fn spawn_keepalive_loop(app: AppHandle, socket: Arc<UdpSocket>) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        ticker.tick().await; // first tick fires immediately; skip it, bootstrap just synced
        loop {
            ticker.tick().await;
            let guard = state.runtime.lock().await;
            let Some(rt) = guard.as_ref() else {
                continue;
            };
            let sync_packet = rt.client.generate_sync_packet();
            let server_addr = rt.client.server_addr;
            drop(guard);
            let _ = socket.send_to(&sync_packet, server_addr).await;
        }
    })
}

/// Background task: send a signed presence ping (see `PresencePayload`) to
/// every established contact on a fixed interval, so peers can show an
/// online/offline marker. Separate from `spawn_keepalive_loop` on purpose
/// — that one sends a single fixed packet to the relay and touches no
/// protocol state, this one fans out to N contacts and advances no ratchet
/// state either (pings are signed, not E2E-encrypted), so the two loops
/// have nothing meaningful to share beyond both being timers.
fn spawn_presence_loop(app: AppHandle, socket: Arc<UdpSocket>) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let mut ticker = tokio::time::interval(PRESENCE_PING_INTERVAL);
        loop {
            ticker.tick().await;
            let guard = state.runtime.lock().await;
            let Some(rt) = guard.as_ref() else {
                continue;
            };
            let server_addr = rt.client.server_addr;
            let packets: Vec<Vec<u8>> = rt
                .client
                .e2e_sessions
                .keys()
                .map(|&token| rt.client.generate_presence_packet(token))
                .collect();
            drop(guard);
            for packet in packets {
                let _ = socket.send_to(&packet, server_addr).await;
            }
        }
    })
}

/// Background task: read inbound UDP packets for as long as the app runs,
/// strip the link-layer encryption, and hand the inner payload to the
/// client state machine — exactly what the CLI's spawned task does, just
/// living here instead. Decrypted messages land in `Client::inbox`, which
/// the frontend collects by polling `poll_inbox`.
fn spawn_receive_loop(app: AppHandle, socket: Arc<UdpSocket>) -> tauri::async_runtime::JoinHandle<()> {
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
    })
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
            online: false,
        })
        .collect();

    for token in rt.client.e2e_sessions.keys() {
        let token_hex = hex::encode(token);
        let online = rt.client.is_online(token, PRESENCE_FRESHNESS);
        if let Some(existing) = contacts.iter_mut().find(|c| c.token == token_hex) {
            existing.status = "established".to_string();
            existing.online = online;
        } else {
            contacts.push(ContactDto {
                token: token_hex,
                status: "established".to_string(),
                name: rt.client.contact_names.get(token).cloned(),
                online,
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
