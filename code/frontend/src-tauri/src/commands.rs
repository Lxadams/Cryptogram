//! `#[tauri::command]` functions — these are the only bridge between the
//! Leptos/WASM frontend and the real `client` crate. The frontend never
//! touches sockets or crypto directly; it calls these by name (via
//! `invoke("command_name", args)` on the JS/WASM side) and gets plain,
//! serializable DTOs back.

use crate::background;
use crate::state::{AppState, ClientRuntime, PendingIdentity};
use client::{
    derive_vault_key, hash_passcode, parse_routing_token, parse_verifying_key, perform_handshake,
    BurstSender, ChatHistory, Client, ClientStateDto, ContactStatus, IdentityStateStore,
    RoutingToken,
};
use serde::Serialize;
use std::{
    collections::HashSet,
    fs::{self, File, TryLockError},
    io,
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
///
/// Where the platform has no file locking (`try_lock` reports
/// `Unsupported`, as on Android), this still returns the file, unlocked.
/// That's safe on Android because only one copy of the app can run there,
/// and within one process `login` ends any existing session first and
/// `delete_identity` refuses the logged-in identity, without relying on
/// the lock.
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
        Err(TryLockError::Error(e)) if e.kind() == io::ErrorKind::Unsupported => Ok(file),
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
/// `SERVER_ADDR` set at launch wins; failing that, the value it had at
/// build time is baked in, since a mobile app can't be launched with env
/// vars (see code/frontend/ANDROID.md).
fn server_addr_raw() -> String {
    std::env::var("SERVER_ADDR")
        .ok()
        .or_else(|| option_env!("SERVER_ADDR").map(str::to_string))
        .unwrap_or_else(|| "127.0.0.1:4430".to_string())
}

/// The relay's Ed25519 identity pubkey (hex), which authenticates its side of
/// the link handshake. It ships with the app rather than being asked of the
/// relay, which anyone on the network path could answer with their own key.
/// `SERVER_PUBKEY` set at launch wins; failing that, the value it had at
/// build time is baked in, as for `server_addr_raw`. The relay prints it at
/// startup ("Server Static Pubkey"), or with `--print-pubkey`.
fn relay_pubkey_hex() -> Result<String, String> {
    std::env::var("SERVER_PUBKEY")
        .ok()
        .or_else(|| option_env!("SERVER_PUBKEY").map(str::to_string))
        .ok_or_else(|| {
            "This build doesn't know the relay's public key. Set SERVER_PUBKEY to the \
             \"Server Static Pubkey\" the relay prints, when building or launching the app."
                .to_string()
        })
}

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
/// the same identity twice at once isn't allowed. (Where there's no file
/// locking, i.e. Android, there's also only ever one process.)
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
/// can't delete out from under a live login elsewhere. (This process's own
/// login is checked by the `delete_identity` command, since the lock can't
/// be relied on for that everywhere — see `try_acquire_session_lock`.)
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
    // Normally already logged out (the Login screen only shows then), but
    // never run two sessions side by side: their background loops would
    // share one `AppState`.
    end_session(&state).await;
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
/// identity is currently logged in, here or in another process.
#[tauri::command(rename_all = "snake_case")]
pub async fn delete_identity(
    app: AppHandle,
    state: State<'_, AppState>,
    pseudonym: String,
) -> Result<(), String> {
    let logged_in = state
        .pending_identity
        .lock()
        .await
        .as_ref()
        .map(|p| p.pseudonym.clone());
    if logged_in.is_some() && sanitize_pseudonym(&pseudonym).ok() == logged_in {
        return Err("That identity is logged in right now. Log out first.".to_string());
    }
    resolve_delete_identity(&identities_root(&app)?, &pseudonym)
}

/// What `current_session` reports: who's logged in, and their identity once
/// `bootstrap` has connected them to the relay.
#[derive(Serialize)]
pub struct SessionDto {
    pub pseudonym: String,
    pub identity: Option<IdentityDto>,
}

/// The session this process already has, if any, so a frontend that has
/// just loaded can pick up where it left off instead of showing Login. On
/// Android the UI reloads whenever the app's activity is recreated (e.g.
/// reopening it after swiping it away), while this backend and its relay
/// connection keep running.
#[tauri::command(rename_all = "snake_case")]
pub async fn current_session(state: State<'_, AppState>) -> Result<Option<SessionDto>, String> {
    let pseudonym = state
        .pending_identity
        .lock()
        .await
        .as_ref()
        .map(|p| p.pseudonym.clone());
    let Some(pseudonym) = pseudonym else {
        return Ok(None);
    };
    let identity = state
        .runtime
        .lock()
        .await
        .as_ref()
        .map(|rt| identity_dto(&rt.client));
    Ok(Some(SessionDto {
        pseudonym,
        identity,
    }))
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
}

#[derive(Serialize, Clone)]
pub struct ContactDto {
    pub token: String,
    /// "established" once both sides have the session and messages can be
    /// sent (see `Client::is_connected`), "connecting" once they've added us
    /// too and the session is being set up, otherwise "pending" (we've
    /// added them, and are waiting for them to add us back). See
    /// `Client::contact_status`.
    pub status: String,
    /// The display name this contact chose for themselves, learned from
    /// their KeyExchange (see `Client::contact_names`), if they set one.
    pub name: Option<String>,
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
/// relay's pubkey comes with the app (see `relay_pubkey_hex`) instead of being
/// passed in by hand.
#[tauri::command(rename_all = "snake_case")]
pub async fn bootstrap(app: AppHandle, state: State<'_, AppState>) -> Result<IdentityDto, String> {
    let server_pub =
        parse_verifying_key(&relay_pubkey_hex()?).map_err(|e| format!("SERVER_PUBKEY: {e}"))?;
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
    client.save();

    let identity = identity_dto(&client);

    // Spawned before being stored: each loop looks up `state.runtime` fresh
    // on every tick (tolerating it being briefly `None`), so spawn order
    // relative to the `state.runtime` write below doesn't matter.
    let tasks = vec![
        spawn_receive_loop(app.clone(), socket.clone()),
        spawn_keepalive_loop(app, socket.clone()),
    ];

    let bursts = BurstSender::spawn(socket.clone(), client.server_addr);
    let previous = state.runtime.lock().await.replace(ClientRuntime {
        client,
        socket,
        bursts,
        tasks,
    });
    // A second Connect without logging out in between: stop the old loops
    // rather than leave them running on an abandoned socket.
    if let Some(previous) = previous {
        for task in previous.tasks {
            task.abort();
        }
    }
    background::session_started();

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
    end_session(&state).await;
    Ok(())
}

/// `logout`'s work, shared with `login`.
async fn end_session(state: &AppState) {
    if let Some(rt) = state.runtime.lock().await.take() {
        for task in rt.tasks {
            task.abort();
        }
    }
    let was_logged_in = state.pending_identity.lock().await.take().is_some();
    state.identity_lock.lock().await.take();
    if was_logged_in {
        background::session_ended();
    }
}

/// Background task: the keepalive (see `Client::keepalive`). Every 15s it
/// resends a (signed) `sync` packet to the relay (the same packet type
/// `perform_handshake` sends once at bootstrap), along with any KeyExchange
/// due again to a contact we're still setting up a session with.
///
/// The sync only matters once the relay and client are on different
/// machines. The relay learns/refreshes our real `ip:port` from where our
/// syncs come from, and its own record has a long TTL (see `METADATA_TTL`
/// in `code/server/src/main.rs`) — but that's irrelevant if our *own*
/// NAT/router UDP mapping expires first, which home/campus routers
/// typically do within 30-60s of silence. Without this, bootstrap (an
/// immediate round trip on a fresh mapping) succeeds, but any peer packet
/// routed to us minutes later gets silently dropped by our own router
/// before it ever reaches this process. Resending well under that window
/// keeps the mapping (and the relay's record) alive for as long as the app
/// runs.
///
/// The relay acks every sync. If it stops (it restarted for a deploy, or
/// forgot our link while the phone slept), `keepalive` redoes the handshake
/// on this socket instead, and the receive loop finishes it, so the app
/// reconnects by itself.
fn spawn_keepalive_loop(
    app: AppHandle,
    socket: Arc<UdpSocket>,
) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        ticker.tick().await; // first tick fires immediately; skip it, bootstrap just synced
        loop {
            // Also sync early on request, e.g. when Android brings the app
            // back to the foreground (see `background::RESYNC`).
            tokio::select! {
                _ = ticker.tick() => {}
                _ = background::RESYNC.notified() => {}
            }
            let mut guard = state.runtime.lock().await;
            let Some(rt) = guard.as_mut() else {
                continue;
            };
            let packets = rt.client.keepalive();
            let server_addr = rt.client.server_addr;
            drop(guard);
            for packet in packets {
                let _ = socket.send_to(&packet, server_addr).await;
            }
        }
    })
}

/// Background task: read inbound UDP packets for as long as the app runs
/// and hand them to the client state machine (`Client::handle_relay_packet`,
/// which also produces the ack the relay waits for) — exactly what the
/// CLI's spawned task does, just living here instead. Decrypted messages
/// land in `Client::inbox`, which the frontend collects by polling
/// `poll_inbox`, and are reported to `background` so Android can show a
/// notification while the app isn't on screen.
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
            let inbox_before = rt.client.inbox.len();
            let replies = rt.client.handle_relay_packet(&buf[..len]);
            for _ in inbox_before..rt.client.inbox.len() {
                background::message_received();
            }
            for packet in replies {
                let _ = socket.send_to(&packet, rt.client.server_addr).await;
            }
        }
    })
}

/// Union of `pending_contacts` (KeyExchange in flight) and `e2e_sessions`
/// — everyone the UI should show in the contact list, with a status badge
/// for which stage they're at (see `ContactDto::status`): "established"
/// only once both sides have the session (see `Client::is_connected`).
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
        .map(|token| ContactDto {
            token: hex::encode(token),
            status: match client.contact_status(token) {
                ContactStatus::Connected => "established",
                ContactStatus::Connecting => "connecting",
                ContactStatus::Pending => "pending",
            }
            .to_string(),
            name: client.contact_names.get(token).cloned(),
        })
        .collect();
    // A stable order (by name, then token) so the list doesn't reshuffle
    // between polls — hash-map iteration order is arbitrary.
    contacts.sort_by(|a, b| (&a.name, &a.token).cmp(&(&b.name, &b.token)));

    Ok(contacts)
}

/// Add a contact by their QR-scanned `(routing_token, ed25519_public_key)`
/// pair and send them a key exchange. Only contacts added this way can
/// connect to us, so the session comes up once they've added us too. Real
/// trust anchor: their KeyExchange must carry this exact key (see
/// `Client::add_contact` and the 0x02 branch of
/// `Client::handle_incoming_packet`).
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

    let req_packet = rt
        .client
        .add_contact(token, peer_ed25519)
        .map_err(|e| e.to_string())?;
    rt.socket
        .send_to(&req_packet, rt.client.server_addr)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// What `connection_requests` reports.
#[derive(Serialize, Clone)]
pub struct ConnectionRequestsDto {
    /// People who tried to connect but aren't contacts yet, in the order
    /// they first tried, as token hex. Empty while muted.
    pub tokens: Vec<String>,
    pub muted: bool,
}

/// People who tried to connect but aren't contacts yet (see
/// `Client::connection_requests`), and whether requests are muted. Their
/// request was dropped; the frontend asks the user to scan their code,
/// which is what accepts it.
#[tauri::command(rename_all = "snake_case")]
pub async fn connection_requests(
    state: State<'_, AppState>,
) -> Result<ConnectionRequestsDto, String> {
    let guard = state.runtime.lock().await;
    let rt = guard.as_ref().ok_or("Not connected to relay yet")?;
    Ok(ConnectionRequestsDto {
        tokens: rt
            .client
            .connection_requests()
            .iter()
            .map(hex::encode)
            .collect(),
        muted: rt.client.requests_muted(),
    })
}

/// Mute or unmute connection requests (see `Client::set_requests_muted`).
/// Saved with the identity.
#[tauri::command(rename_all = "snake_case")]
pub async fn set_connection_requests_muted(
    state: State<'_, AppState>,
    muted: bool,
) -> Result<(), String> {
    let mut guard = state.runtime.lock().await;
    let rt = guard.as_mut().ok_or("Not connected to relay yet")?;
    rt.client.set_requests_muted(muted);
    Ok(())
}

/// Stop listing a connection request ("Not now"), and don't list another
/// from them for a day (see `Client::dismiss_connection_request`).
#[tauri::command(rename_all = "snake_case")]
pub async fn dismiss_connection_request(
    state: State<'_, AppState>,
    token_hex: String,
) -> Result<(), String> {
    let mut guard = state.runtime.lock().await;
    let rt = guard.as_mut().ok_or("Not connected to relay yet")?;
    rt.client
        .dismiss_connection_request(&parse_token(&token_hex)?);
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

/// Encrypt and send an E2E message to an already-established session, as a
/// burst of FEC packets sized to survive heavy loss (see `client`'s
/// `create_fec_packets`/`BurstSender`). A long message's chunks, and the PQ
/// ratchet-injection whenever one is due (roughly every 5th chunk), ride
/// inside the same burst, transparently. Errors if the message is over the
/// client's length limit, or if the burst couldn't leave this machine at all
/// (e.g. the network is down).
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

    let packets = rt
        .client
        .create_fec_packets(token, text.as_bytes())
        .map_err(|e| e.to_string())?;
    let history_id = rt.client.last_recorded_id;

    // Queued while we still hold the runtime lock, so bursts go out in the
    // order they were made (see `BurstSender::queue`). It's paced out over a
    // few hundred ms behind any earlier ones, so wait for it without holding
    // the lock (the receive loop needs it). Resolves once its first packet
    // is out.
    let first_sent = rt.bursts.queue(packets);
    drop(guard);
    first_sent
        .await
        .map_err(|e| format!("Message not sent: {e}"))?;

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
