// WASM entry point. Trunk compiles this crate to wasm32-unknown-unknown and
// loads it into index.html's <body>. Runs identically whether the WASM is
// served by a plain browser (via `trunk serve`) or hosted inside a Tauri
// native window (via `cargo tauri dev`) — the app itself doesn't know or
// care which; only `api.rs`'s Tauri `invoke()` calls need the Tauri
// JS runtime to actually be present to succeed.
mod api;
mod app;
mod back_button;
mod contact_code;
mod qr;

fn main() {
    // Turns WASM panics into readable browser-console stack traces instead
    // of an opaque "unreachable executed" trap.
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
