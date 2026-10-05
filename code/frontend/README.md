# frontend: Leptos + Tauri desktop app

This is the E2E-Messenger desktop app. It has two parts:

- a **Leptos** UI compiled to WebAssembly (`src/`);
- a **Tauri 2** native shell (`src-tauri/`). The shell runs the real [`client`](../client) crate: a real UDP socket, real handshakes, real encryption.

There's no mock data. Every screen calls Tauri commands that drive a live `Client`.

## Layout

```
code/frontend/
├── src/                  Leptos UI, compiled to wasm32 by Trunk
│   ├── app.rs            Screens: Login / Create identity → Connect → Main (identity, contacts, chat)
│   ├── api.rs            Bridge to Tauri's invoke(); DTOs mirroring src-tauri/src/commands.rs
│   ├── contact_code.rs   Contact code format: cryptogram:v1:<token>:<ed25519>
│   ├── qr.rs             QR rendering (qrcode → SVG) and the camera scanner (getUserMedia + rqrr)
│   └── main.rs           WASM entry point
├── src-tauri/            Native shell; the only part with a socket
│   ├── src/commands.rs   Every #[tauri::command], login and identity storage, background tasks
│   ├── src/state.rs      AppState: live Client + socket + task handles, pending login, session lock
│   ├── src/lib.rs        Registers commands and the log plugin; Linux camera opt-in
│   ├── capabilities/     Tauri permissions
│   └── tauri.conf.json   App id nz.ac.waikato.compx374.e2e-messenger, dev server on port 1420
├── index.html            Trunk entry point
├── style.css             Light and dark themes (keyed on <html data-theme>)
├── Trunk.toml            Ignores src-tauri/ so backend file writes don't trigger a UI reload
└── Dockerfile            Build-only Linux bundle (see deployment.md)
```

## Prerequisites

| What | Install |
|---|---|
| Rust **1.89+** (the shell uses `File::try_lock`) with the `wasm32-unknown-unknown` target | `rustup target add wasm32-unknown-unknown` |
| Trunk | `cargo install trunk --locked` |
| Tauri CLI v2 | `cargo install tauri-cli --version "^2" --locked` |
| Perl + make, for SQLCipher's vendored OpenSSL | Linux: usually present. Windows: Strawberry Perl and `nmake` from the VS Build Tools. See the [client README](../client/README.md#building-and-testing). |
| Linux webview and build libraries | Debian/Ubuntu: `libwebkit2gtk-4.1-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev` (what CI installs). Arch: `webkit2gtk-4.1` and friends. |

Windows and macOS use the webview that comes with the OS (WebView2 or WKWebView). Cargo fetches every Rust dependency itself. The first build takes several minutes, because it compiles the `webkit2gtk` bindings, Kyber's C code and OpenSSL. Later builds are incremental.

## Running

**1. Start the relay** (from the repo root) and note the `Server Static Pubkey` it prints:

```bash
./runserver.sh
```

**2. Start one peer per terminal:**

```bash
./runpeer.sh
./runpeer.sh
```

The first `runpeer.sh` builds the app and runs `cargo tauri dev`. That starts `trunk serve` on port 1420 and opens a window, and the terminal must stay open. Each later `runpeer.sh` sees the dev server already running and just launches another window of the built binary (`src-tauri/target/debug/e2e-messenger`), which is almost instant.

`runpeer.sh` uses bash's `/dev/tcp`, written with Linux in mind. Elsewhere, do the same by hand from `code/frontend`: run `cargo tauri dev` once, then run the built binary again for each extra peer.

**Remote relay:** the relay address comes from the `SERVER_ADDR` environment variable, default `127.0.0.1:4430`:

```bash
SERVER_ADDR=<host>:443 ./runpeer.sh
```

There's no address field in the UI.

## Using the app

### Login and Create identity

- **Log in** with a username and passcode. The **Existing identities** dropdown lists the identities on this machine; picking one fills in the username. It refreshes every second, so identities created or deleted in other windows show up straight away.
- Typing a username that doesn't exist offers to **create** it. The Create identity screen asks for a username, a passcode and the passcode again, then sends you back to Login.
  - Usernames are up to 40 characters: letters, digits, spaces, `-` and `_`.
- Each passcode field has an eye icon to show or hide the text.
- **Delete** an identity with the bin icon next to the dropdown. It asks for confirmation but not the passcode. There's no passcode recovery, so this is the only way out of a forgotten one. You can't delete an identity that's logged in elsewhere.
- **One login per identity.** Logging into an identity that's already open in another window is refused, because of the OS file lock on `session.lock`.
- **Log out** (in the header on every screen after Login) stops the background tasks and releases the lock without closing the window.

### Connect

Paste the relay's pubkey and click **Connect**. This loads the identity, or creates its keys on first use, opens its encrypted databases and does the link handshake. If the relay doesn't reply within 5 s, an error is shown. The pubkey isn't remembered, so it has to be pasted after every login.

### Main screen

- **Your Identity** shows your name, routing token and Ed25519 key, each with a copy button. **Present QR code** shows the same token and key as a QR code. Your name isn't in the QR code; it reaches the other person automatically inside the KeyExchange.
- **Contacts** lists everyone you've added or who has added you:
  - a status of `pending` or `established`;
  - a dot showing **online** or offline (online means heard from in the last 45 s);
  - a bin icon to **remove** the contact. Removing deletes its session, keys and **local chat history**.
- **Add contact:** **Scan QR code** opens the camera. Or paste their routing token and Ed25519 key and click **Send Connection Request**. Both paths make the same `connect_to_peer` call.
- **Chat:** select an established contact. Its 200 most recent messages are loaded from local history. **Enter** sends.

### Pairing two peers

1. In Bob's window, click **Present QR code**, or copy his token and key.
2. In Alice's window, click **Scan QR code**, or paste them and click **Send Connection Request**.
3. Bob's window accepts automatically and replies. The relay forwards once a second, so after a few seconds both windows show the other contact as `established`, labelled with the other person's username.
4. For **mutual verification**, also do it the other way round: Alice presents, Bob scans. A one-sided add works, but Bob trusted Alice's key on first use. The second handshake replaces the session with one that's verified in both directions.

## How it works

### Tauri commands

Defined in `src-tauri/src/commands.rs`. Every command uses `rename_all = "snake_case"`, and the request and response types in `src/api.rs` must match these field for field.

| Command | Purpose |
|---|---|
| `list_pseudonyms` | Usernames with a saved identity on this machine |
| `create_identity` | Write `passcode.hash` for a new username. Doesn't log in. |
| `login` | Check the passcode, derive the vault key, take the session lock. Returns `success` or `unknown_username`. |
| `delete_identity` | Delete the identity's directory, unless it's locked |
| `logout` | Stop background tasks, drop the `Client`, release the lock |
| `bootstrap` | Load or create the identity, open both databases, do the link handshake, start background tasks |
| `list_contacts` | Pending and established contacts, with name and online status |
| `connect_to_peer` | Pin a contact's Ed25519 key and send a KeyExchange |
| `remove_contact` | `Client::forget_contact`: delete the session, keys, name and history |
| `send_message` | Encrypt and send, plus a PQInject every 5th message. Returns the message's history row ID. |
| `poll_inbox` | Messages decrypted since the last poll |
| `chat_history` | The most recent *n* stored messages with a contact |

### Timers

| Where | Interval | What |
|---|---|---|
| UI, Main screen | 1 s | Polls `list_contacts` and `poll_inbox`. Nothing is pushed from the backend. |
| UI, Login screen | 1 s | Polls `list_pseudonyms` |
| Backend keepalive | 15 s | Sends a sync packet to the relay, to keep the NAT mapping and the relay's address record alive |
| Backend presence | 20 s | Sends a signed presence ping to each established contact |
| Backend receive loop | continuous | Reads the socket, strips the link layer, `handle_incoming_packet`, sends any automatic reply |

Message IDs: live messages and stored ones share the SQLite row ID, so a message that arrives while history is still loading is never shown twice.

### Local data

Each identity is stored under the OS's per-app data folder, for example `~/.local/share/nz.ac.waikato.compx374.e2e-messenger/identities/<username>/` on Linux. It contains `passcode.hash`, `client_state.sqlite` and `chat_history.sqlite` (both SQLCipher), and `session.lock`. The location deliberately doesn't depend on the working directory: `cargo tauri dev` and a directly launched binary run in different directories, and used to end up with separate `identities/` folders. The full layout and other platforms are in [architecture.md §6](../../documentations/architecture.md#6-local-storage), and the encryption in [cryptography.md §7](../../documentations/cryptography.md#7-local-secret-storage).

Identities created before encrypted storage existed still have a plaintext `client_state.json`. They're migrated on their first login, and the plaintext file is deleted.

### QR codes and the camera

The contact code is `cryptogram:v1:<token hex>:<ed25519 hex>`. The scanner ignores other QR codes and shows an error for them. QR codes are rendered as SVG with `qrcode` and decoded from camera frames with `rqrr`, about every 250 ms, inside the WASM UI. That makes it the same code on every platform. Camera access by platform:

| Platform | Camera access |
|---|---|
| Linux (WebKitGTK) | Turned on by `enable_camera_for_qr_scanner` in `src-tauri/src/lib.rs`. Only video-only requests are allowed. |
| Windows (WebView2) | The OS asks the user |
| macOS / mobile | Needs a camera permission in the app manifest. Not set up yet. |

Showing and decoding QR codes is unit-tested, but scanning hasn't yet been tried with a real camera.

## Building a release

```bash
cd code/frontend
cargo tauri build          # bundles for the current OS (tauri.conf.json: targets "all")
```

To build Linux `.deb` and AppImage bundles in Docker, see [deployment.md](../../documentations/deployment.md#frontend-builder).

## Tests

```bash
cd code/frontend && cargo test            # 6: contact-code parsing, QR encode→decode, SVG output
cd code/frontend/src-tauri && cargo test  # 14: login/create/delete, session lock, vault key, state migration
```

## Known limitations

- The relay address can only be set with `SERVER_ADDR`, and the relay pubkey has to be pasted after every login.
- There's no delivery status. A sent message is shown straight away whether or not it arrived. Packets are sent once, with no retries (no FEC yet).
- Messages over about 1.9 KB of text are dropped by the relay.
- Requests from unknown peers are accepted automatically (trust on first use). There's no "message requests" step.
- The UI polls the backend instead of receiving events.
