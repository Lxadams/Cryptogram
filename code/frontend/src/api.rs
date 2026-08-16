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
    v.as_string()
        .unwrap_or_else(|| format!("{v:?}"))
}

// ---------------------------------------------------------------------
// DTOs — must stay field-for-field identical to the Rust structs in
// src-tauri/src/commands.rs, since serde matches by field name.
// ---------------------------------------------------------------------

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct IdentityDto {
    pub routing_token: String,
    pub ed25519_public: String,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct ContactDto {
    pub token: String,
    pub status: String,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct IncomingMessageDto {
    pub from_token: String,
    pub text: String,
}

#[derive(Serialize)]
struct BootstrapArgs<'a> {
    server_pubkey_hex: &'a str,
}

pub async fn bootstrap(server_pubkey_hex: &str) -> Result<IdentityDto, String> {
    call("bootstrap", &BootstrapArgs { server_pubkey_hex }).await
}

// Note: the backend also exposes a `get_identity` command (re-fetches
// identity without redoing the handshake), but nothing in this UI calls it
// yet — the identity returned by `bootstrap` above is all `App` currently
// needs, so no wrapper is defined here until something actually needs it.

pub async fn list_contacts() -> Result<Vec<ContactDto>, String> {
    call("list_contacts", &()).await
}

#[derive(Serialize)]
struct ConnectArgs<'a> {
    token_hex: &'a str,
    ed25519_hex: &'a str,
}

pub async fn connect_to_peer(token_hex: &str, ed25519_hex: &str) -> Result<(), String> {
    call("connect_to_peer", &ConnectArgs { token_hex, ed25519_hex }).await
}

#[derive(Serialize)]
struct SendMessageArgs<'a> {
    token_hex: &'a str,
    text: &'a str,
}

pub async fn send_message(token_hex: &str, text: &str) -> Result<(), String> {
    call("send_message", &SendMessageArgs { token_hex, text }).await
}

pub async fn poll_inbox() -> Result<Vec<IncomingMessageDto>, String> {
    call("poll_inbox", &()).await
}
