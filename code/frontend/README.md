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
Note the `Server Static Pubkey: <hex>` it prints on boot — every client
instance needs to paste this into its Connect screen.

### Terminal 2 — launch the app (instance A)

```
cd code/frontend
cargo tauri dev
```
This runs `trunk serve` on port 1420 (per `tauri.conf.json`'s
`beforeDevCommand`) and opens a native window pointed at it. First run
compiles everything from scratch (a few minutes); subsequent runs are fast.

In the window: paste the server's pubkey into the Connect screen. Once
connected, your identity (routing token + Ed25519 key) is shown — that's
what a peer needs to add you as a contact (stand-in for scanning a QR
code, per the Micro-QR design in `doable-cryptographic-flow.md`). Keep
this terminal and window running.

### Terminal 3 — launch a second instance (instance B), to test messaging

`cargo tauri dev` itself only needs to run once — a second `cargo tauri
dev` would collide with instance A on Trunk's port 1420. Instead, launch
the debug binary that instance A's build already produced, directly, from
a separate scratch directory (each instance persists its identity to
`client_state.json` in its own current directory — sharing a directory
between two instances would make them clobber each other's identity):

```
mkdir -p /tmp/e2e-peer-b
cd /tmp/e2e-peer-b
/path/to/repo/code/frontend/src-tauri/target/debug/e2e-messenger
```

This opens a second, fully independent native window (its own backend
process, own socket, own identity) that loads the UI from the same
already-running Trunk server — no rebuild needed. Connect it to the relay
the same way as instance A.

### Testing messaging between the two instances

1. In instance A's window, copy its identity (routing token + Ed25519 key).
2. In instance B's window, paste those into "Add contact" and submit.
3. Repeat in the other direction: copy B's identity, add it as a contact
   in A.
4. Once both sides have sent a connection request to each other, each
   window's contact list should flip that contact's status from
   "pending" to "established" — at that point you can select the contact
   and send messages in either window.

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
  `client_state.json` regardless.
- **Known limitation**: the receive-loop and `bootstrap` currently assume
  a single relay at `127.0.0.1:4430` (hardcoded in `commands.rs`, matching
  what the CLI and `runserver.sh` also hardcode) — no server address field
  in the UI yet.
