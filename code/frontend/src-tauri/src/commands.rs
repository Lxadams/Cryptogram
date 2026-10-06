//! `#[tauri::command]` functions — these are the only bridge between the
//! Leptos/WASM frontend and the real `client` crate. The frontend never
//! touches sockets or crypto directly; it calls these by name (via
//! `invoke("command_name", args)` on the JS/WASM side) and gets plain,
//! serializable DTOs back.

use crate::state::{AppState, ClientRuntime, PendingIdentity};
use client::{
    derive_vault_key, hash_passcode, parse_routing_token, parse_verifying_key, perform_handshake,
    ChatHistory, Client, ClientStateDto, IdentityStateStore, RoutingToken,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, TryLockError},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tauri::{AppHandle, Manager, State};
use tokio::net::UdpSocket;
use zeroize::Zeroize;

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
        return Err("Username can only contain letters, numbers, spaces, '-' and '_'.".to_string());
    }
    Ok(trimmed.to_string())
}

/// `(client_state.sqlite path, passcode.hash path, session.lock path)` for a
/// given (already sanitized) pseudonym under `root` (see `identities_root`).
/// `client_state.sqlite` is the SQLCipher-encrypted identity store, keyed
/// by the same vault key as `chat_history.sqlite` — see
/// `load_or_migrate_identity_state`.
fn identity_paths(root: &Path, pseudonym: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = root.join(pseudonym);
    (
        dir.join("client_state.sqlite"),
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
    // `truncate(true)`: this file's content is never read, it's purely a
    // lock target — nothing meaningful to preserve across opens.
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
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

/// `client::parse_routing_token` with the `String` error every command here
/// returns.
fn parse_token(token_hex: &str) -> Result<RoutingToken, String> {
    parse_routing_token(token_hex).map_err(|e| e.to_string())
}

/// The relay (server) this prototype talks to. Defaults to the CLI's own
/// local-dev default (`127.0.0.1:4430`, see runserver.sh); override with
/// the `SERVER_ADDR` env var (e.g. a deployed EC2 host's `<ip>:443`) —
/// mirrors the same override on the CLI (see code/client/src/main.rs).
fn server_addr_raw() -> String {
    std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:4430".to_string())
}

/// Ask the relay for its Ed25519 identity pubkey over its `GET /pubkey`
/// HTTP endpoint, served over TCP on the same `host:port` as its UDP relay
/// socket (see `spawn_pubkey_http_task` in code/server/src/main.rs).
///
/// Plain HTTP, so this answer is only as trustworthy as the network path:
/// `bootstrap` pins it on first use rather than trusting it every time.
async fn fetch_relay_pubkey(server_addr_raw: &str) -> Result<String, String> {
    let url = format!("http://{server_addr_raw}/pubkey");
    // reqwest's own message only says the request failed; the innermost
    // source is the useful part (e.g. "Connection refused").
    let unreachable = |e: reqwest::Error| {
        let mut cause: &dyn std::error::Error = &e;
        while let Some(next) = cause.source() {
            cause = next;
        }
        format!("Couldn't fetch the relay's public key from {url} ({cause}). Is the relay running?")
    };
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?
        .get(&url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(unreachable)?
        .text()
        .await
        .map_err(unreachable)
}

/// Relay pubkeys this app has already trusted once, keyed by the
/// `SERVER_ADDR` they were reached at: this app's equivalent of SSH's
/// `known_hosts`. Shared by every identity, like `identities_root`.
fn known_relays_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|dir| dir.join("known_relays.json"))
        .map_err(|e| e.to_string())
}

fn load_known_relays(path: &Path) -> Result<BTreeMap<String, String>, String> {
    match fs::read_to_string(path) {
        Ok(json) => serde_json::from_str(&json).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e.to_string()),
    }
}

/// Trust-on-first-use check for a relay pubkey from `fetch_relay_pubkey`.
/// `Ok(true)` if this exact key is already pinned for `server_addr_raw`,
/// `Ok(false)` if nothing is pinned for it yet (the caller pins it with
/// `pin_relay_pubkey` once a handshake has verified against it), and `Err`
/// if a *different* key is pinned: either the relay's identity was reset,
/// or something between us and the relay handed us its own key.
fn check_relay_pin(path: &Path, server_addr_raw: &str, pubkey_hex: &str) -> Result<bool, String> {
    match load_known_relays(path)?.get(server_addr_raw) {
        None => Ok(false),
        Some(pinned) if pinned == pubkey_hex => Ok(true),
        Some(pinned) => Err(format!(
            "The relay at {server_addr_raw} sent a different public key ({pubkey_hex}) \
             than the one trusted on first connect ({pinned}). Refusing to connect. \
             If the relay's identity was deliberately reset, remove its entry from {}.",
            path.display()
        )),
    }
}

/// Record `pubkey_hex` as the trusted key for `server_addr_raw`. Re-reads
/// the file first so a pin another peer process wrote meanwhile isn't lost.
fn pin_relay_pubkey(path: &Path, server_addr_raw: &str, pubkey_hex: &str) -> Result<(), String> {
    let mut known = load_known_relays(path)?;
    known.insert(server_addr_raw.to_string(), pubkey_hex.to_string());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(&known).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
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
/// `client_state.sqlite` path and the held session lock for `login` to stash
/// in `AppState` — kept out of `LoginOutcome` itself since neither is ever
/// meaningful to the frontend.
enum LoginResolution {
    Success {
        pseudonym: String,
        state_path: PathBuf,
        lock: File,
        vault_key: zeroize::Zeroizing<[u8; 32]>,
    },
    UnknownUsername,
}

// Manual `Debug` (rather than `#[derive(Debug)]`) so a test's `unwrap_err()`
// can never accidentally print the raw vault key.
impl std::fmt::Debug for LoginResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginResolution::Success {
                pseudonym,
                state_path,
                ..
            } => f
                .debug_struct("Success")
                .field("pseudonym", pseudonym)
                .field("state_path", state_path)
                .field("vault_key", &"[redacted]")
                .finish(),
            LoginResolution::UnknownUsername => write!(f, "UnknownUsername"),
        }
    }
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
    let Some(vault_key) = derive_vault_key(passcode, &stored) else {
        return Err("Incorrect passcode.".to_string());
    };
    let lock = try_acquire_session_lock(&lock_path)?;

    Ok(LoginResolution::Success {
        pseudonym,
        state_path,
        lock,
        vault_key,
    })
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

/// Open (or create) `state_path`'s SQLCipher-encrypted identity store,
/// keyed by the vault key `login` already derived from the passcode — the
/// exact same key that unlocks `chat_history.sqlite` (see `ChatHistory::open`),
/// so one login unlocks both stores.
///
/// One-time migration: an identity created before this store existed has
/// its secrets sitting in a plaintext sibling `client_state.json` instead.
/// If no encrypted store exists yet but that legacy file does, this loads
/// it, writes an encrypted copy, and deletes the plaintext original. This
/// is a real migration rather than the "force recreation" precedent used
/// for the old SHA-256 `passcode.hash` format — that format change couldn't
/// be migrated because a one-way hash can't be recomputed without the raw
/// passcode, but the legacy `client_state.json` is fully readable JSON, so
/// there's no reason to make the user re-generate their identity (and lose
/// every peer's record of their public keys) just to protect it at rest.
fn load_or_migrate_identity_state(
    state_path: &Path,
    vault_key: &[u8; 32],
    server_addr: SocketAddr,
) -> Result<Client, String> {
    let store = IdentityStateStore::open(state_path, vault_key).map_err(|e| e.to_string())?;

    // A load *error* (as opposed to `None`, nothing saved yet) is surfaced
    // rather than falling through to `Client::new` below — `bootstrap` saves
    // right after this, so falling through would silently overwrite the
    // user's real identity with a brand-new one.
    let loaded = store
        .load(&state_path.to_string_lossy())
        .map_err(|e| format!("Couldn't load this identity's saved state: {e:#}"))?;
    if let Some(mut client) = loaded {
        // The relay address comes from this launch (`SERVER_ADDR`), not
        // from whatever was saved when the identity was created —
        // otherwise an identity first used against a local relay could
        // never be pointed at a deployed one.
        client.server_addr = server_addr;
        client.identity_store = Some(store);
        return Ok(client);
    }

    let legacy_path = state_path.with_file_name("client_state.json");
    let mut client = if legacy_path.is_file() {
        let legacy_client =
            ClientStateDto::load(&legacy_path.to_string_lossy()).map_err(|e| e.to_string())?;
        store.save(&legacy_client).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&legacy_path);
        legacy_client
    } else {
        Client::new(server_addr)
    };
    client.server_addr = server_addr;
    client.state_path = state_path.to_string_lossy().into_owned();
    client.identity_store = Some(store);
    Ok(client)
}

/// Verify an existing pseudonym's passcode, derive its vault key (see
/// `derive_vault_key` in the `client` crate), and stash both — along with
/// which identity file `bootstrap` should load next — in
/// `AppState::pending_identity`. Performs no network activity itself.
/// Returns `LoginOutcome::UnknownUsername` (not an error) if the pseudonym
/// has no saved identity yet — see `create_identity` for that. Also errors
/// (a plain, generic-looking `Err`, same as a wrong passcode) if this
/// identity is already logged in on another process — see
/// `try_acquire_session_lock`.
///
/// The passcode itself is zeroized before this function returns — only its
/// derived vault key is ever kept in memory beyond this call.
#[tauri::command(rename_all = "snake_case")]
pub async fn login(
    app: AppHandle,
    state: State<'_, AppState>,
    pseudonym: String,
    mut passcode: String,
) -> Result<LoginOutcome, String> {
    let root = identities_root(&app)?;
    let result = resolve_login(&root, &pseudonym, &passcode);
    passcode.zeroize();
    match result? {
        LoginResolution::Success {
            pseudonym,
            state_path,
            lock,
            vault_key,
        } => {
            *state.pending_identity.lock().await = Some(PendingIdentity {
                pseudonym: pseudonym.clone(),
                state_path: state_path.to_string_lossy().into_owned(),
                vault_key,
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
pub async fn create_identity(
    app: AppHandle,
    pseudonym: String,
    mut passcode: String,
) -> Result<(), String> {
    let result = resolve_create_identity(&identities_root(&app)?, &pseudonym, &passcode);
    passcode.zeroize();
    result
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
            LoginResolution::Success {
                pseudonym,
                state_path,
                ..
            } => {
                assert_eq!(pseudonym, "alice");
                assert_eq!(state_path, root.join("alice").join("client_state.sqlite"));
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
        let LoginResolution::Success {
            lock: _first_lock, ..
        } = first
        else {
            panic!("expected a successful login");
        };
        let err = resolve_login(&root, "alice", "hunter2").unwrap_err();
        assert_eq!(
            err,
            "This identity is already logged in elsewhere on this machine."
        );
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
        let LoginResolution::Success {
            lock: _held_lock, ..
        } = login
        else {
            panic!("expected a successful login");
        };
        let err = resolve_delete_identity(&root, "alice").unwrap_err();
        assert_eq!(
            err,
            "This identity is already logged in elsewhere on this machine."
        );
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
    fn test_login_derives_a_vault_key_that_opens_chat_history() {
        let root = scratch_dir("vault_key_opens_history");
        resolve_create_identity(&root, "carol", "correct-passcode").unwrap();
        let LoginResolution::Success { vault_key, .. } =
            resolve_login(&root, "carol", "correct-passcode").unwrap()
        else {
            panic!("expected a successful login");
        };
        let db_path = root.join("carol").join("chat_history.sqlite");
        let history = client::ChatHistory::open(&db_path, &vault_key).unwrap();
        history.append([1u8; 16], true, "hi").unwrap();
        assert_eq!(history.recent([1u8; 16], 10).unwrap().len(), 1);

        // A second login attempt with the wrong passcode must not derive a
        // key that can open the same database.
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

    fn test_addr() -> SocketAddr {
        "127.0.0.1:4430".parse().unwrap()
    }

    #[test]
    fn test_load_or_migrate_creates_fresh_identity_when_nothing_exists() {
        let root = scratch_dir("fresh_identity");
        resolve_create_identity(&root, "alice", "hunter2").unwrap();
        let LoginResolution::Success {
            state_path,
            vault_key,
            ..
        } = resolve_login(&root, "alice", "hunter2").unwrap()
        else {
            panic!("expected a successful login");
        };

        let client = load_or_migrate_identity_state(&state_path, &vault_key, test_addr()).unwrap();
        assert_eq!(client.state_path, state_path.to_string_lossy());
        assert!(state_path.is_file());
    }

    #[test]
    fn test_load_or_migrate_reopens_previously_saved_encrypted_state() {
        let root = scratch_dir("reopen_encrypted");
        resolve_create_identity(&root, "alice", "hunter2").unwrap();
        let LoginResolution::Success {
            state_path,
            vault_key,
            ..
        } = resolve_login(&root, "alice", "hunter2").unwrap()
        else {
            panic!("expected a successful login");
        };

        let first = load_or_migrate_identity_state(&state_path, &vault_key, test_addr()).unwrap();
        let original_token = first.identity.routing_token;
        first.save();

        let second = load_or_migrate_identity_state(&state_path, &vault_key, test_addr()).unwrap();
        assert_eq!(second.identity.routing_token, original_token);
    }

    #[test]
    fn test_load_or_migrate_uses_this_launchs_relay_address_not_the_saved_one() {
        let root = scratch_dir("relay_address_override");
        resolve_create_identity(&root, "alice", "hunter2").unwrap();
        let LoginResolution::Success {
            state_path,
            vault_key,
            ..
        } = resolve_login(&root, "alice", "hunter2").unwrap()
        else {
            panic!("expected a successful login");
        };

        // Created (and saved) against a local relay...
        let first = load_or_migrate_identity_state(&state_path, &vault_key, test_addr()).unwrap();
        first.save();

        // ...then relaunched pointing at a deployed one.
        let deployed: SocketAddr = "3.25.64.73:443".parse().unwrap();
        let second = load_or_migrate_identity_state(&state_path, &vault_key, deployed).unwrap();
        assert_eq!(second.server_addr, deployed);
    }

    #[test]
    fn test_load_or_migrate_upgrades_legacy_plaintext_state_and_deletes_it() {
        let root = scratch_dir("migrate_legacy");
        resolve_create_identity(&root, "alice", "hunter2").unwrap();
        let LoginResolution::Success {
            state_path,
            vault_key,
            ..
        } = resolve_login(&root, "alice", "hunter2").unwrap()
        else {
            panic!("expected a successful login");
        };

        // Simulate a pre-migration identity: a plaintext client_state.json
        // sibling, no client_state.sqlite yet.
        let legacy_path = state_path.with_file_name("client_state.json");
        let legacy_client = Client::new(test_addr());
        let legacy_token = legacy_client.identity.routing_token;
        ClientStateDto::save(&legacy_client, &legacy_path.to_string_lossy()).unwrap();
        assert!(!state_path.is_file());

        let migrated =
            load_or_migrate_identity_state(&state_path, &vault_key, test_addr()).unwrap();
        assert_eq!(migrated.identity.routing_token, legacy_token);
        assert!(state_path.is_file());
        assert!(
            !legacy_path.is_file(),
            "plaintext client_state.json should be removed after migration"
        );

        // And the migrated identity is now readable from the encrypted
        // store alone, without the plaintext file.
        let reloaded =
            load_or_migrate_identity_state(&state_path, &vault_key, test_addr()).unwrap();
        assert_eq!(reloaded.identity.routing_token, legacy_token);
    }

    #[test]
    fn test_list_pseudonyms_reflects_created_identities() {
        let root = scratch_dir("list_pseudonyms");
        resolve_create_identity(&root, "dave", "pw1").unwrap();
        resolve_create_identity(&root, "erin", "pw2").unwrap();
        let names = list_pseudonyms_sync(&root);
        assert_eq!(names, vec!["dave".to_string(), "erin".to_string()]);
    }

    const RELAY_KEY_A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const RELAY_KEY_B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_relay_pubkey_is_trusted_on_first_use_then_pinned() {
        let path = scratch_dir("relay_pin_first_use").join("known_relays.json");
        assert!(!check_relay_pin(&path, "127.0.0.1:4430", RELAY_KEY_A).unwrap());
        pin_relay_pubkey(&path, "127.0.0.1:4430", RELAY_KEY_A).unwrap();
        assert!(check_relay_pin(&path, "127.0.0.1:4430", RELAY_KEY_A).unwrap());
    }

    #[test]
    fn test_relay_pubkey_change_is_rejected() {
        let path = scratch_dir("relay_pin_changed").join("known_relays.json");
        pin_relay_pubkey(&path, "127.0.0.1:4430", RELAY_KEY_A).unwrap();
        let err = check_relay_pin(&path, "127.0.0.1:4430", RELAY_KEY_B).unwrap_err();
        assert!(err.contains("different public key"), "{err}");
    }

    #[test]
    fn test_relay_pins_are_per_address() {
        let path = scratch_dir("relay_pin_per_address").join("known_relays.json");
        pin_relay_pubkey(&path, "127.0.0.1:4430", RELAY_KEY_A).unwrap();
        pin_relay_pubkey(&path, "3.25.64.73:443", RELAY_KEY_B).unwrap();
        assert!(check_relay_pin(&path, "127.0.0.1:4430", RELAY_KEY_A).unwrap());
        assert!(check_relay_pin(&path, "3.25.64.73:443", RELAY_KEY_B).unwrap());
    }
}

#[derive(Serialize, Clone)]
pub struct ContactDto {
    pub token: String,
    /// "established" once the PQXDH session handshake completed, otherwise
    /// "pending" (KeyExchange sent/received, waiting on SessionEstablish).
    pub status: String,
    /// The display name this contact chose for themselves, learned from
    /// their KeyExchange (see `Client::contact_names`), if they set one.
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
    /// Local chat-history row id (`None` if no history is attached) — see
    /// `send_message`'s doc comment for why the frontend needs this instead
    /// of minting its own id for a live-delivered message.
    pub id: Option<i64>,
}

#[derive(Serialize, Clone)]
pub struct StoredMessageDto {
    /// Local chat-history row id — stable per contact, safe to use as both
    /// a list key and a "load older than this" pagination cursor.
    pub id: i64,
    pub from_me: bool,
    pub text: String,
    pub timestamp_ms: i64,
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
/// button instead of running unconditionally on process start — except the
/// relay's pubkey is fetched from the relay and pinned on first use (see
/// `fetch_relay_pubkey`, `check_relay_pin`) instead of passed in by hand.
#[tauri::command(rename_all = "snake_case")]
pub async fn bootstrap(app: AppHandle, state: State<'_, AppState>) -> Result<IdentityDto, String> {
    let server_addr_raw = server_addr_raw();
    let server_pub = parse_verifying_key(&fetch_relay_pubkey(&server_addr_raw).await?)
        .map_err(|e| format!("Relay public key: {e}"))?;
    // Canonical lowercase hex, so the pin compares keys rather than spellings.
    let server_pub_hex = hex::encode(server_pub.as_bytes());
    let known_relays_path = known_relays_path(&app)?;
    let already_pinned = check_relay_pin(&known_relays_path, &server_addr_raw, &server_pub_hex)?;

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

    // Resume a previous identity if one was saved (migrating it out of the
    // legacy plaintext file if needed), otherwise mint a new one.
    let mut client = load_or_migrate_identity_state(
        Path::new(&pending.state_path),
        &pending.vault_key,
        server_addr,
    )?;
    client.local_name = pending.pseudonym;

    // Chat history lives right next to client_state.sqlite under the same
    // identity directory, keyed by the vault key `login` already derived
    // from the passcode — see `PendingIdentity::vault_key`'s doc comment.
    let history_path = Path::new(&client.state_path)
        .parent()
        .expect("client.state_path always has a parent (an identity directory)")
        .join("chat_history.sqlite");
    client.history =
        Some(ChatHistory::open(&history_path, &pending.vault_key).map_err(|e| e.to_string())?);

    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| e.to_string())?,
    );

    perform_handshake(&mut client, &socket, &server_pub)
        .await
        .map_err(|e| e.to_string())?;
    // Pinned only now that a handshake has verified against it, so a bogus
    // key from something that can't also answer as the relay is never kept.
    if !already_pinned {
        pin_relay_pubkey(&known_relays_path, &server_addr_raw, &server_pub_hex)?;
    }
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
fn spawn_keepalive_loop(
    app: AppHandle,
    socket: Arc<UdpSocket>,
) -> tauri::async_runtime::JoinHandle<()> {
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
fn spawn_presence_loop(
    app: AppHandle,
    socket: Arc<UdpSocket>,
) -> tauri::async_runtime::JoinHandle<()> {
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
fn spawn_receive_loop(
    app: AppHandle,
    socket: Arc<UdpSocket>,
) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let mut buf = [0u8; 4096];
        loop {
            let len = match socket.recv_from(&mut buf).await {
                Ok((len, _addr)) => len,
                // Back off briefly rather than spinning a core if the
                // socket keeps erroring (e.g. repeated ICMP "port
                // unreachable" resets on some platforms).
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            let mut guard = state.runtime.lock().await;
            let Some(rt) = guard.as_mut() else {
                continue;
            };
            let Some(e2e_payload) = rt.client.open_link_packet(&buf[..len]) else {
                continue;
            };
            if let Ok(Some(reply)) = rt.client.handle_incoming_packet(&e2e_payload) {
                let _ = socket.send_to(&reply, rt.client.server_addr).await;
            }
        }
    })
}

/// Union of `pending_contacts` (KeyExchange in flight) and `e2e_sessions`
/// (fully established) — everyone the UI should show in the contact list,
/// with a status badge for which stage they're at.
#[tauri::command(rename_all = "snake_case")]
pub async fn list_contacts(state: State<'_, AppState>) -> Result<Vec<ContactDto>, String> {
    let guard = state.runtime.lock().await;
    let rt = guard.as_ref().ok_or("Not connected to relay yet")?;

    let client = &rt.client;
    let tokens: HashSet<&RoutingToken> = client
        .pending_contacts
        .keys()
        .chain(client.e2e_sessions.keys())
        .collect();
    let mut contacts: Vec<ContactDto> = tokens
        .into_iter()
        .map(|token| {
            let established = client.e2e_sessions.contains_key(token);
            ContactDto {
                token: hex::encode(token),
                status: if established {
                    "established"
                } else {
                    "pending"
                }
                .to_string(),
                name: client.contact_names.get(token).cloned(),
                online: established && client.is_online(token, PRESENCE_FRESHNESS),
            }
        })
        .collect();
    // A stable order (by name, then token) so the list doesn't reshuffle
    // between polls — hash-map iteration order is arbitrary.
    contacts.sort_by(|a, b| (&a.name, &a.token).cmp(&(&b.name, &b.token)));

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

    let token = parse_token(&token_hex)?;

    let peer_ed25519 = parse_verifying_key(&ed25519_hex).map_err(|e| e.to_string())?;

    rt.client.pending_contacts.insert(token, peer_ed25519);
    let req_packet = rt.client.create_kx_request(token);
    rt.socket
        .send_to(&req_packet, rt.client.server_addr)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Permanently remove a contact, and its locally-persisted chat history
/// with it — the local cleanup path for a stale entry (most commonly: a
/// peer deleted and recreated their identity, so this contact now shares a
/// name with a different, unrelated one — see `Client::forget_contact`'s
/// doc comment for why this can only ever be a manual, local decision,
/// never something the network can trigger).
#[tauri::command(rename_all = "snake_case")]
pub async fn remove_contact(state: State<'_, AppState>, token_hex: String) -> Result<(), String> {
    let mut guard = state.runtime.lock().await;
    let rt = guard.as_mut().ok_or("Not connected to relay yet")?;

    let token = parse_token(&token_hex)?;

    rt.client.forget_contact(token);
    Ok(())
}

/// Encrypt and send an E2E message to an already-established session — as
/// several chunk packets if it's long — followed by a PQ ratchet-injection
/// packet whenever `create_encrypted_packets` produces one (roughly every 5th
/// packet). Messages over the client's length limit come back as an error.
///
/// Returns the message's local chat-history row id (`None` if no history is
/// attached), so the frontend can label its own optimistic display of this
/// message with the *same* id a later `chat_history` fetch would report for
/// it — otherwise the two views disagree on what identifies "this message"
/// and a merge between them can't tell they're the same one.
#[tauri::command(rename_all = "snake_case")]
pub async fn send_message(
    state: State<'_, AppState>,
    token_hex: String,
    text: String,
) -> Result<Option<i64>, String> {
    let mut guard = state.runtime.lock().await;
    let rt = guard.as_mut().ok_or("Not connected to relay yet")?;

    let token = parse_token(&token_hex)?;

    let (msg_packets, pq_inject_packet) = rt
        .client
        .create_encrypted_packets(token, text.as_bytes())
        .map_err(|e| e.to_string())?;
    let history_id = rt.client.last_recorded_id;

    // In this order: the PQ inject must follow the message's last chunk.
    for packet in msg_packets.iter().chain(&pq_inject_packet) {
        rt.socket
            .send_to(packet, rt.client.server_addr)
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(history_id)
}

/// Collect any messages decrypted since the last poll. The frontend calls
/// this on a timer (see `code/frontend/src/api.rs`) — there's no push
/// channel wired up in this prototype, just polling. Each message's `id` is
/// its local chat-history row id (`None` if no history is attached) — see
/// `send_message`'s doc comment for why this must line up with
/// `chat_history`'s ids for the same message.
#[tauri::command(rename_all = "snake_case")]
pub async fn poll_inbox(state: State<'_, AppState>) -> Result<Vec<IncomingMessageDto>, String> {
    let mut guard = state.runtime.lock().await;
    let rt = guard.as_mut().ok_or("Not connected to relay yet")?;

    Ok(rt
        .client
        .drain_inbox()
        .into_iter()
        .map(|(token, bytes, id)| IncomingMessageDto {
            from_token: hex::encode(token),
            text: String::from_utf8_lossy(&bytes).into_owned(),
            id,
        })
        .collect())
}

/// The most recent `limit` locally-persisted messages with a contact,
/// oldest first — ready to render top-to-bottom in a fresh transcript.
/// This is the peer's own independent copy (see `ChatHistory`'s doc
/// comment): it's unaffected by the other side losing their state,
/// deleting the conversation, or reconnecting, since nothing about it is
/// shared or synced between peers.
#[tauri::command(rename_all = "snake_case")]
pub async fn chat_history(
    state: State<'_, AppState>,
    token_hex: String,
    limit: i64,
) -> Result<Vec<StoredMessageDto>, String> {
    let guard = state.runtime.lock().await;
    let rt = guard.as_ref().ok_or("Not connected to relay yet")?;

    let token = parse_token(&token_hex)?;

    Ok(rt
        .client
        .history_for_contact(token, limit)
        .into_iter()
        .map(|m| StoredMessageDto {
            id: m.id,
            from_me: m.from_me,
            text: m.text,
            timestamp_ms: m.timestamp_ms,
        })
        .collect())
}
