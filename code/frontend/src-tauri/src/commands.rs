//! `#[tauri::command]` functions — these are the only bridge between the
//! Leptos/WASM frontend and the real `client` crate. The frontend never
//! touches sockets or crypto directly; it calls these by name (via
//! `invoke("command_name", args)` on the JS/WASM side) and gets plain,
//! serializable DTOs back.

use crate::background;
use crate::state::{AppState, ClientRuntime, PendingIdentity};
use client::{
    derive_vault_key, hash_passcode,
    link::{Handler, RelayConfig, RelayLink},
    parse_routing_token, parse_verifying_key, ChatHistory, Client, ClientStateDto,
    IdentityStateStore, RoutingToken,
};
use serde::Serialize;
use std::{
    collections::HashSet,
    fs::{self, File, TryLockError},
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroize;

/// How long Connect waits for the relay to accept us.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

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
/// the `SERVER_ADDR` env var (e.g. a deployed host's `<ip>:443`) — mirrors
/// the same override on the CLI (see code/client/src/main.rs). An IP
/// address is used as is, so nothing is looked up; a name is resolved over
/// DNS-over-HTTPS (see `client::link`). `SERVER_ADDR` set at launch wins;
/// failing that, the value it had at build time is baked in, since a
/// mobile app can't be launched with env vars (see code/frontend/ANDROID.md).
fn server_addr_raw() -> String {
    build_setting("SERVER_ADDR").unwrap_or_else(|| "127.0.0.1:4430".to_string())
}

/// A relay setting: from the environment at launch, or failing that as it
/// was at build time.
fn build_setting(name: &str) -> Option<String> {
    let baked = match name {
        "SERVER_ADDR" => option_env!("SERVER_ADDR"),
        "SERVER_NAME" => option_env!("SERVER_NAME"),
        "SERVER_PUBKEY" => option_env!("SERVER_PUBKEY"),
        "SERVER_ACCESS_KEY" => option_env!("SERVER_ACCESS_KEY"),
        _ => None,
    };
    std::env::var(name)
        .ok()
        .or_else(|| baked.map(str::to_string))
        .filter(|value| !value.is_empty())
}

/// The relay's key pin (hex): the app trusts the relay only if it proves it
/// holds that key (see `client::link`). It ships with the app rather than
/// being asked of the relay, which anyone on the network path could answer
/// with their own key. The relay prints it at startup ("Server Static
/// Pubkey"), or with `--print-pubkey`. With the access key (`--print-access-key`),
/// what the app proves to the relay, and `SERVER_NAME`, the name on the
/// relay's certificate when `SERVER_ADDR` is an IP address.
async fn relay_config() -> Result<RelayConfig, String> {
    let missing = |name: &str, flag: &str| {
        format!(
            "This build doesn't know the relay's {name}. Set {} to what `server {flag}` \
             prints, when building or launching the app.",
            if flag == "--print-pubkey" {
                "SERVER_PUBKEY"
            } else {
                "SERVER_ACCESS_KEY"
            }
        )
    };
    let key_pin = build_setting("SERVER_PUBKEY").ok_or_else(|| missing("key", "--print-pubkey"))?;
    let access_key = build_setting("SERVER_ACCESS_KEY")
        .ok_or_else(|| missing("access key", "--print-access-key"))?;
    let name = build_setting("SERVER_NAME");
    RelayConfig::from_settings(&server_addr_raw(), name.as_deref(), &key_pin, &access_key)
        .await
        .map_err(|e| format!("{e:#}"))
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
        Client::new()
    };
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

        let client = load_or_migrate_identity_state(&state_path, &vault_key).unwrap();
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

        let first = load_or_migrate_identity_state(&state_path, &vault_key).unwrap();
        let original_token = first.identity.routing_token;
        first.save();

        let second = load_or_migrate_identity_state(&state_path, &vault_key).unwrap();
        assert_eq!(second.identity.routing_token, original_token);
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
        let legacy_client = Client::new();
        let legacy_token = legacy_client.identity.routing_token;
        ClientStateDto::save(&legacy_client, &legacy_path.to_string_lossy()).unwrap();
        assert!(!state_path.is_file());

        let migrated = load_or_migrate_identity_state(&state_path, &vault_key).unwrap();
        assert_eq!(migrated.identity.routing_token, legacy_token);
        assert!(state_path.is_file());
        assert!(
            !legacy_path.is_file(),
            "plaintext client_state.json should be removed after migration"
        );

        // And the migrated identity is now readable from the encrypted
        // store alone, without the plaintext file.
        let reloaded = load_or_migrate_identity_state(&state_path, &vault_key).unwrap();
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
    /// "established" once the PQXDH session handshake completed, otherwise
    /// "pending" (added, waiting for them to add us back and the handshake
    /// to finish).
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

/// Connect to the relay and start the link (see `client::link`): a QUIC
/// connection carrying a constant-rate stream of cells, which reconnects by
/// itself whenever it drops. Must be called once before any other command
/// will work. Mirrors what the CLI's `main()` does at startup, just
/// triggered by a UI button instead of running unconditionally on process
/// start — except the relay's keys come with the app (see `relay_config`)
/// instead of being passed in by hand.
#[tauri::command(rename_all = "snake_case")]
pub async fn bootstrap(app: AppHandle, state: State<'_, AppState>) -> Result<IdentityDto, String> {
    let config = relay_config().await?;

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
    let mut client =
        load_or_migrate_identity_state(Path::new(&pending.state_path), &pending.vault_key)?;
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
    client.save();

    let identity = identity_dto(&client);
    let token_secret = client.identity.token_secret.clone();
    let link = RelayLink::start(config, token_secret, delivery_handler(app.clone()))
        .map_err(|e| format!("{e:#}"))?;
    let link_status = link.watch();
    let previous = state.runtime.lock().await.replace(ClientRuntime {
        client,
        link,
        tasks: vec![spawn_resume_watcher(app)],
    });
    // A second Connect without logging out in between: stop the old link
    // and its tasks rather than leave them running.
    drop_runtime(previous);

    // Wait for the relay without holding the runtime lock: deliveries that
    // arrive meanwhile need it.
    if let Err(e) = link_status.until_up(CONNECT_TIMEOUT).await {
        drop_runtime(state.runtime.lock().await.take());
        return Err(e.to_string());
    }
    background::session_started();

    Ok(identity)
}

/// Log out of the current identity: stop its link and background tasks,
/// drop the `Client`, and release its session lock (see
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
    drop_runtime(state.runtime.lock().await.take());
    let was_logged_in = state.pending_identity.lock().await.take().is_some();
    state.identity_lock.lock().await.take();
    if was_logged_in {
        background::session_ended();
    }
}

/// Stop a runtime's tasks; dropping it closes its link.
fn drop_runtime(runtime: Option<ClientRuntime>) {
    if let Some(rt) = runtime {
        for task in rt.tasks {
            task.abort();
        }
    }
}

/// What the link does with each payload the relay delivers: hand it to the
/// client state machine (`Client::handle_incoming_packet`), report new
/// messages to `background` so Android can notify while the app isn't on
/// screen, and return any reply (e.g. a KeyExchange response) for the link
/// to send. Decrypted messages land in `Client::inbox`, which the frontend
/// collects by polling `poll_inbox`. With nobody logged in it returns
/// `None`, so the relay delivers the payload again later.
fn delivery_handler(app: AppHandle) -> Handler {
    Arc::new(move |payload| {
        let app = app.clone();
        Box::pin(async move {
            let state = app.state::<AppState>();
            let mut guard = state.runtime.lock().await;
            let rt = guard.as_mut()?;
            let inbox_before = rt.client.inbox.len();
            let reply = rt.client.handle_incoming_packet(&payload).ok().flatten();
            for (from, _, _) in &rt.client.inbox[inbox_before..] {
                background::message_received(&contact_label(&rt.client, from));
            }
            Some(reply.into_iter().collect())
        })
    })
}

/// Background task: when Android brings the app back to the foreground
/// (see `background::RESYNC`), retry a dropped link at once instead of
/// waiting out its backoff. A link that's up just carries on: its cell
/// stream never stops, so nothing needs refreshing.
fn spawn_resume_watcher(app: AppHandle) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        loop {
            background::RESYNC.notified().await;
            if let Some(rt) = state.runtime.lock().await.as_ref() {
                rt.link.reconnect_now();
            }
        }
    })
}

/// How a notification names a contact: their chosen name, or failing that
/// the start of their routing token.
fn contact_label(client: &Client, token: &RoutingToken) -> String {
    client
        .contact_names
        .get(token)
        .cloned()
        .unwrap_or_else(|| hex::encode(&token[..4]))
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
            }
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

    let request = rt.client.add_contact(token, peer_ed25519);
    rt.link.send(request);
    Ok(())
}

/// People who tried to connect but aren't contacts yet, newest first, as
/// token hex (see `Client::connection_requests`). Their request was
/// dropped; the frontend asks the user to scan their code, which is what
/// accepts it.
#[tauri::command(rename_all = "snake_case")]
pub async fn connection_requests(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let guard = state.runtime.lock().await;
    let rt = guard.as_ref().ok_or("Not connected to relay yet")?;
    Ok(rt
        .client
        .connection_requests()
        .iter()
        .map(hex::encode)
        .collect())
}

/// Stop listing a connection request ("Not now"), until they send another.
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

/// Encrypt an E2E message to an already-established session and queue it on
/// the link, as an FEC object that goes out a cell at a time on the link's
/// constant-rate clock, with as much redundancy as the measured loss calls
/// for (see `client::link`). A long message's chunks, and the PQ
/// ratchet-injection whenever one is due (roughly every 5th chunk), ride
/// inside the same object, transparently. Errors if the message is over the
/// client's length limit. If the link is down it waits, queued, for the
/// next connection.
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

    let message = rt
        .client
        .create_message(token, text.as_bytes())
        .map_err(|e| e.to_string())?;
    rt.link.send(message);
    Ok(rt.client.last_recorded_id)
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
