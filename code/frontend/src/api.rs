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
    pub online: bool,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct IncomingMessageDto {
    pub from_token: String,
    pub text: String,
    /// Local chat-history row id (`None` if no history is attached) — the
    /// same id a `chat_history` fetch reports for this same message, so the
    /// frontend can merge live and persisted views without duplicating it.
    pub id: Option<i64>,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct StoredMessageDto {
    pub id: i64,
    pub from_me: bool,
    pub text: String,
    pub timestamp_ms: i64,
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

#[derive(Serialize)]
struct SendMessageArgs<'a> {
    token_hex: &'a str,
    text: &'a str,
}

/// Returns the sent message's local chat-history row id (`None` if no
/// history is attached), for the frontend to label its optimistic display
/// of this message with the same id `chat_history` would later report.
pub async fn send_message(token_hex: &str, text: &str) -> Result<Option<i64>, String> {
    call("send_message", &SendMessageArgs { token_hex, text }).await
}

pub async fn poll_inbox() -> Result<Vec<IncomingMessageDto>, String> {
    call("poll_inbox", &()).await
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
