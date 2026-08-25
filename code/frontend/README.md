# E2E-Messenger — Leptos + Tauri Frontend

A working prototype UI wired to the real `code/client` crypto/networking
engine via a Tauri desktop shell (see `documentations/tech-decision-leptos-client.md`,
Option B). No mock data — every screen calls real Tauri commands
(`src-tauri/src/commands.rs`) that drive the actual `Client` from
`code/client`, including a real UDP socket and a real link handshake
against `code/server`.

## Layout

```
code/frontend/
  src/            Leptos UI (compiles to WASM via Trunk)
    app.rs        Screens: Connect -> Identity/Contacts/Chat
    api.rs        Bridge to Tauri's invoke() — see its doc comment for why
    main.rs       WASM entry point
  src-tauri/      Native shell — the only thing with a real UDP socket
    src/
      commands.rs #[tauri::command] functions the UI calls
      state.rs    Shared AppState (the live Client + its socket)
      lib.rs      Registers commands, plugins
    tauri.conf.json
  index.html      Trunk build entry point
  style.css
```

## Prerequisites (one-time per machine)

| What | Install |
|---|---|
| Rust + `wasm32-unknown-unknown` target | `rustup target add wasm32-unknown-unknown` (or your distro's Rust-WASM package) |
| Trunk | `cargo install trunk` |
| `cargo tauri` CLI | `cargo install tauri-cli --version "^2" --locked` |
| Linux native webview (`webkit2gtk-4.1`, `libsoup3`, `gtk3`, `libayatana-appindicator`) | via your distro's package manager, e.g. `sudo pacman -S webkit2gtk-4.1` on Arch. Windows/macOS use their OS-provided webview — no extra install there. |

Cargo dependencies (`leptos`, `tauri`, `wasm-bindgen`, etc.) all fetch
automatically on first build — nothing to install manually there. First
build of each crate is slow (a few minutes, compiling large dependency
trees like `webkit2gtk` bindings and `pqcrypto-kyber`'s C code); every
build after that is fast incremental compilation.

## Running it

### Terminal 1 — start the relay server

From the repo root:
```
./runserver.sh
```
Note the `Server Static Pubkey: <hex>` it prints on boot — every peer
instance needs to paste this into its Connect screen.

### Terminal 2+ — launch a peer, one per terminal

From the repo root:
```
./runpeer.sh alice
```
Run it again in another terminal (any name, or no name at all — see
`./runpeer.sh` in the repo root's own comments) for a second peer, a
third, and so on:
```
./runpeer.sh bob
./runpeer.sh carol
```
The first `runpeer.sh` you start pays the one-time cost of building the
app and hosting the Trunk dev server (`trunk serve` on port 1420, per
`tauri.conf.json`'s `beforeDevCommand`) as well as opening its own window;
every peer after that just opens its own independent window against that
same running dev server — no rebuild, near-instant. Each peer's identity
and session state persists to its own directory under `.peers/<name>/` at
the repo root (`E2E_STATE_FILE`, see `commands.rs` and
`code/client/src/lib.rs`'s `state_file_path()`), so peers never clobber
each other no matter how many are running.

In each window: paste the server's pubkey into the Connect screen. Once
connected, your identity (routing token + Ed25519 key) is shown — that's
what a peer needs to add you as a contact (stand-in for scanning a QR
code, per the Micro-QR design in `doable-cryptographic-flow.md`).

### Testing messaging between peers

1. In alice's window, copy her identity (routing token + Ed25519 key).
2. In bob's window, paste those into "Add contact" and submit.
3. Repeat in the other direction: copy bob's identity, add it as a
   contact in alice's window.
4. Once both sides have sent a connection request to each other, each
   window's contact list should flip that contact's status from
   "pending" to "established" — at that point you can select the contact
   and send messages in either window. The same pattern (both sides add
   each other) applies for any additional peers.

## What's real vs. what's still a prototype shortcut

- **Real**: identity generation, the link handshake, the PQXDH session
  establishment, the symmetric ratchet, PQ injection, message
  encrypt/decrypt — all the same code path the CLI (`code/client/src/main.rs`)
  uses, unmodified.
- **Prototype shortcut**: "adding a contact" is manual hex paste, not an
  actual QR camera scan — no camera integration exists yet. Message
  history is kept only in a UI-side signal for the current window session
  (not persisted); reloading the app loses the transcript, though the
  underlying session/ratchet state itself is still safely persisted to
  each peer's `client_state.json` (under `.peers/<name>/`) regardless.
- **Known limitation**: the receive-loop and `bootstrap` currently assume
  a single relay at `127.0.0.1:4430` (hardcoded in `commands.rs`, matching
  what the CLI and `runserver.sh` also hardcode) — no server address field
  in the UI yet.
