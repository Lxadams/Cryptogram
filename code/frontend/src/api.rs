//! Thin bridge from WASM to the Tauri backend's `#[tauri::command]`
//! functions (see code/frontend/src-tauri/src/commands.rs).
//!
//! There's no JS bundler in this project (Trunk compiles straight to WASM),
//! so we can't `import` the official `@tauri-apps/api` npm package. Instead
//! `tauri.conf.json` sets `app.withGlobalTauri: true`, which makes Tauri
//! inject `window.__TAURI__` into the page itself — we bind directly to
//! `window.__TAURI__.core.invoke` via wasm-bindgen. This only works when
//! this WASM is actually hosted inside a Tauri window (`cargo tauri dev`);
//! running it as a plain browser page (`trunk serve` alone) has no
//! `window.__TAURI__` and every call here will reject.

use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke)]
    fn invoke_raw(cmd: &str, args: JsValue) -> js_sys::Promise;
}

/// Serialize `args`, call the named Tauri command, and deserialize its
/// result. `rename_all = "snake_case"` on every command (backend side)
/// means the field names here can match the Rust structs 1:1 with no
/// camelCase translation to worry about.
async fn call<A: Serialize, R: DeserializeOwned>(cmd: &str, args: &A) -> Result<R, String> {
    let js_args = serde_wasm_bindgen::to_value(args).map_err(|e| e.to_string())?;
    let promise = invoke_raw(cmd, js_args);
    let js_result = wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(|e| js_error_to_string(&e))?;
    serde_wasm_bindgen::from_value(js_result).map_err(|e| e.to_string())
}

/// Tauri command errors (the `Err(String)` side of a command's `Result`)
/// arrive as a plain JS string, not an `Error` object with a `.message`.
fn js_error_to_string(v: &JsValue) -> String {
    v.as_string().unwrap_or_else(|| format!("{v:?}"))
}

// ---------------------------------------------------------------------
// DTOs — must stay field-for-field identical to the Rust structs in
// src-tauri/src/commands.rs, since serde matches by field name.
// ---------------------------------------------------------------------

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct IdentityDto {
    pub routing_token: String,
    pub ed25519_public: String,
    pub name: Option<String>,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct LoginDto {
    pub pseudonym: String,
}

/// Mirrors `LoginOutcome` in `src-tauri/src/commands.rs`. `UnknownUsername`
/// is a normal `Ok` outcome, not an error, so the Login screen can offer
/// "create a new identity?" instead of just showing an error string — see
/// that type's doc comment for why.
#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginOutcome {
    Success { pseudonym: String },
    UnknownUsername,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct ContactDto {
    pub token: String,
    pub status: String,
    pub name: Option<String>,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct IncomingMessageDto {
    pub from_token: String,
    pub text: String,
    /// Local chat-history row id (`None` if no history is attached) — the
    /// same id a `chat_history` fetch reports for this same message, so the
    /// frontend can merge live and persisted views without duplicating it.
    pub id: Option<i64>,
    /// When it arrived, in Unix milliseconds.
    pub timestamp_ms: i64,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct StoredMessageDto {
    pub id: i64,
    pub from_me: bool,
    pub text: String,
    pub timestamp_ms: i64,
    /// For a message we sent: `"sending"`, `"sent"` or `"failed"`. `None`
    /// for received ones, and ones sent before statuses were kept.
    pub status: Option<String>,
}

/// Mirrors `SentMessageDto` in `src-tauri/src/commands.rs`.
#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct SentMessageDto {
    /// Its chat-history row id (see `IncomingMessageDto::id`).
    pub id: Option<i64>,
    /// When it was sent, in Unix milliseconds.
    pub timestamp_ms: i64,
}

/// Mirrors `SentMessageUpdateDto` in `src-tauri/src/commands.rs`.
#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct SentMessageUpdateDto {
    /// The message's chat-history row id.
    pub id: i64,
    /// `"sent"` once the relay confirms it has it, `"failed"` if it didn't
    /// in time.
    pub status: String,
}

#[derive(Serialize)]
struct LoginArgs<'a> {
    pseudonym: &'a str,
    passcode: &'a str,
}

pub async fn login(pseudonym: &str, passcode: &str) -> Result<LoginOutcome, String> {
    call(
        "login",
        &LoginArgs {
            pseudonym,
            passcode,
        },
    )
    .await
}

pub async fn logout() -> Result<(), String> {
    call("logout", &()).await
}

/// Mirrors `SessionDto` in `src-tauri/src/commands.rs`.
#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct SessionDto {
    pub pseudonym: String,
    pub identity: Option<IdentityDto>,
}

/// The session the backend already has, if any (see `App`).
pub async fn current_session() -> Result<Option<SessionDto>, String> {
    call("current_session", &()).await
}

#[derive(Serialize)]
struct CreateIdentityArgs<'a> {
    pseudonym: &'a str,
    passcode: &'a str,
}

pub async fn create_identity(pseudonym: &str, passcode: &str) -> Result<(), String> {
    call(
        "create_identity",
        &CreateIdentityArgs {
            pseudonym,
            passcode,
        },
    )
    .await
}

pub async fn list_pseudonyms() -> Result<Vec<String>, String> {
    call("list_pseudonyms", &()).await
}

#[derive(Serialize)]
struct DeleteIdentityArgs<'a> {
    pseudonym: &'a str,
}

pub async fn delete_identity(pseudonym: &str) -> Result<(), String> {
    call("delete_identity", &DeleteIdentityArgs { pseudonym }).await
}

pub async fn bootstrap() -> Result<IdentityDto, String> {
    call("bootstrap", &()).await
}

pub async fn list_contacts() -> Result<Vec<ContactDto>, String> {
    call("list_contacts", &()).await
}

#[derive(Serialize)]
struct ConnectArgs<'a> {
    token_hex: &'a str,
    ed25519_hex: &'a str,
}

pub async fn connect_to_peer(token_hex: &str, ed25519_hex: &str) -> Result<(), String> {
    call(
        "connect_to_peer",
        &ConnectArgs {
            token_hex,
            ed25519_hex,
        },
    )
    .await
}

#[derive(Serialize)]
struct RemoveContactArgs<'a> {
    token_hex: &'a str,
}

/// Permanently remove a contact locally (session/pending/name), and its
/// locally-persisted chat history with it — the cleanup path for a stale
/// duplicate, e.g. after the other side deleted and recreated their
/// identity.
pub async fn remove_contact(token_hex: &str) -> Result<(), String> {
    call("remove_contact", &RemoveContactArgs { token_hex }).await
}

/// Replace a broken session with a contact with a new one, keeping the
/// contact and chat history (see `repair_session` in commands.rs).
pub async fn repair_session(token_hex: &str) -> Result<(), String> {
    call("repair_session", &RemoveContactArgs { token_hex }).await
}

/// Mirrors `ConnectionRequestsDto` in `src-tauri/src/commands.rs`.
#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ConnectionRequestsDto {
    /// People who tried to connect but aren't contacts yet, in the order
    /// they first tried (token hex). Empty while muted.
    pub tokens: Vec<String>,
    pub muted: bool,
}

/// Who's trying to connect, and whether requests are muted. Scanning their
/// code is what accepts.
pub async fn connection_requests() -> Result<ConnectionRequestsDto, String> {
    call("connection_requests", &()).await
}

#[derive(Serialize)]
struct MuteRequestsArgs {
    muted: bool,
}

/// Stop (or start again) listing connection requests. Saved with the
/// identity.
pub async fn set_connection_requests_muted(muted: bool) -> Result<(), String> {
    call("set_connection_requests_muted", &MuteRequestsArgs { muted }).await
}

#[derive(Serialize)]
struct DismissRequestArgs<'a> {
    token_hex: &'a str,
}

/// "Not now": stop listing their request, and don't list another from them
/// for a day.
pub async fn dismiss_connection_request(token_hex: &str) -> Result<(), String> {
    call(
        "dismiss_connection_request",
        &DismissRequestArgs { token_hex },
    )
    .await
}

/// Mirrors `NotificationSettingsDto` in `src-tauri/src/commands.rs`.
#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq, Default)]
pub struct NotificationSettingsDto {
    /// Whether this device posts new-message notifications at all (only
    /// Android does).
    pub posted: bool,
    /// Whether they say who each message is from.
    pub with_names: bool,
}

/// How new-message notifications work on this device.
pub async fn notification_settings() -> Result<NotificationSettingsDto, String> {
    call("notification_settings", &()).await
}

#[derive(Serialize)]
struct NotifyWithNamesArgs {
    on: bool,
}

/// Let new-message notifications say who each message is from, or not.
/// Saved with the identity.
pub async fn set_notify_with_names(on: bool) -> Result<(), String> {
    call("set_notify_with_names", &NotifyWithNamesArgs { on }).await
}

/// Mirrors `SimulatedLossDto` in `src-tauri/src/commands.rs`.
#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq, Default)]
pub struct SimulatedLossDto {
    /// Percentage of outgoing packets dropped.
    pub send: u8,
    /// Percentage of incoming packets dropped.
    pub receive: u8,
}

/// The network loss this device is simulating.
pub async fn simulated_loss() -> Result<SimulatedLossDto, String> {
    call("simulated_loss", &()).await
}

/// Drop `send`% of outgoing packets and `receive`% of incoming ones on this
/// device, until changed or the app closes.
pub async fn set_simulated_loss(send: u8, receive: u8) -> Result<(), String> {
    call("set_simulated_loss", &SimulatedLossDto { send, receive }).await
}

#[derive(Serialize)]
struct SendMessageArgs<'a> {
    token_hex: &'a str,
    text: &'a str,
}

/// Returns the sent message's local chat-history row id (`None` if no
/// history is attached), for the frontend to label its optimistic display
/// of this message with the same id `chat_history` would later report.
pub async fn send_message(token_hex: &str, text: &str) -> Result<SentMessageDto, String> {
    call("send_message", &SendMessageArgs { token_hex, text }).await
}

pub async fn poll_inbox() -> Result<Vec<IncomingMessageDto>, String> {
    call("poll_inbox", &()).await
}

/// What became of messages we sent since the last call: whether the relay
/// confirmed it has each one, or didn't in time.
pub async fn sent_message_updates() -> Result<Vec<SentMessageUpdateDto>, String> {
    call("sent_message_updates", &()).await
}

#[derive(Serialize)]
struct ChatHistoryArgs<'a> {
    token_hex: &'a str,
    limit: i64,
}

/// This peer's own locally-persisted history with a contact — survives the
/// other side losing their state, deleting the conversation, or
/// reconnecting, since nothing about it is shared/synced between peers.
pub async fn chat_history(token_hex: &str, limit: i64) -> Result<Vec<StoredMessageDto>, String> {
    call("chat_history", &ChatHistoryArgs { token_hex, limit }).await
}
