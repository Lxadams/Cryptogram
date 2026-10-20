# E2E-Messenger — Leptos + Tauri Frontend

The app, called **Cryptogram**: a Leptos UI wired to the real `code/client`
crypto/networking engine through a Tauri shell, for desktop and Android
(see [`tech-decision-leptos-client.md`](../../documentations/tech-decision-leptos-client.md),
Option B). No mock data: every screen calls real Tauri commands
(`src-tauri/src/commands.rs`) that drive the actual `Client` from
`code/client`, including a real UDP socket and a real link handshake
against `code/server`.

This README is about running the desktop app and testing it. For Android,
see [ANDROID.md](ANDROID.md). For how the UI works inside, see
[Frontend-UI-info.md](../../documentations/Frontend-UI-info.md).

## Layout

```
code/frontend/
  src/              Leptos UI (compiles to WASM via Trunk)
    app.rs          Screens: start page -> Login / Create identity -> Connect -> main screen
    api.rs          Bridge to Tauri's invoke() — see its doc comment for why
    qr.rs           QR codes: drawing yours, and the camera scanner
    contact_code.rs The text a contact QR code carries (CG2: + Base45)
    back_button.rs  Android's back button (closes what's open on top)
    main.rs         WASM entry point
  src-tauri/        Native shell — the only thing with a real UDP socket
    src/
      commands.rs   #[tauri::command] functions the UI calls
      state.rs      Shared AppState (the live Client + its socket)
      background.rs Android: receiving in the background, notifications
      lib.rs        Registers commands, plugins
      main.rs       Desktop entry point
    gen/android/    The Android project (committed; see ANDROID.md)
    icons/          App icons, generated from branding/
    tauri.conf.json
  branding/         Logo and icon sources
  index.html        Trunk build entry point
  style.css
  Trunk.toml        Keeps Trunk from watching src-tauri/
```

After changing anything in `branding/`, regenerate the icons (desktop and
Android) with `cargo tauri icon ../branding/icon.json`, run from
`src-tauri/`.

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
trees like `webkit2gtk` bindings and SQLCipher's bundled OpenSSL); every
build after that is fast incremental compilation.

## Running it

### Terminal 1 — start the relay server

From the repo root:
```
./runserver.sh
```
`runpeer.sh` reads the relay's `Server Static Pubkey` from its identity
file and builds it into the app, which checks the relay against it on
Connect (see `relay_pubkey_hex` in `src-tauri/src/commands.rs`).

### Terminal 2+ — launch a peer, one per terminal

From the repo root, with no arguments — run it again in as many terminals
as you want peers:
```
./runpeer.sh
./runpeer.sh
./runpeer.sh
```
The first `runpeer.sh` you start pays the one-time cost of building the
app and hosting the Trunk dev server (`trunk serve` on port 1420, per
`tauri.conf.json`'s `beforeDevCommand`) as well as opening its own window;
every peer after that just opens its own independent window against that
same running dev server — no rebuild, near-instant.

To use a relay somewhere else (the deployed one, say), give its address
and key: `./runpeer.sh -ip <ip> -p <port> -pk <hex>`. The port defaults to
4430, and `-ip` needs `-pk`. Each peer takes its own, so one window can
use the deployed relay while another uses the local one.

### The screens

Each window opens on a **start page**: the logo, the name and **Sign in**,
which goes to the **Login** screen. Enter a username and passcode for an
identity that already exists. The screen lists usernames already used on
this machine in an "Existing identities" dropdown (pick one to fill the
username field instead of retyping). Picking one also shows a small delete
icon next to the dropdown, with a "Delete? Yes/No" confirm before it
actually removes anything. There is no passcode recovery, so this is the
only way back from a forgotten one, and deleting needs no passcode. The
passcode field has a small eye icon to toggle between masked dots and
plaintext while typing.

No identity for that username yet? Use the **Create identity** button to
switch to a separate screen (username + passcode + confirm passcode); on
success it sends you back to Login to sign in with what you just chose.

Logging into an identity that's already logged in on another running peer
is refused (see `try_acquire_session_lock` in `src-tauri/src/commands.rs`):
one live session per identity at a time. A **Log out** button (in the
header on every screen past Login) releases that session and returns to
the start page, so you can switch identities without closing the window.

Each identity lives under `identities/<username>/` inside this OS's per-app
data directory (e.g. `~/.local/share/nz.ac.waikato.compx374.e2e-messenger/identities/`
on Linux; see `identities_root` in `src-tauri/src/commands.rs`), so peers
never clobber each other however many are running. This is deliberately
*not* a path relative to cwd: `cargo tauri dev` and a directly-run built
binary don't share the same cwd, so two peers once landed in two different
`identities/` directories (and one of them sat inside `src-tauri/`, which
is watched for source changes, so every autosave there restarted that
peer). In that folder:

- `passcode.hash`: the passcode's Argon2id hash, which checks it at login.
- `client_state.sqlite`: your keys, contacts and sessions.
- `chat_history.sqlite`: your messages.
- `session.lock`: the lock that stops a second login (desktop only).

Both databases are SQLCipher, encrypted with a vault key derived from the
passcode with Argon2id (see `derive_vault_key` in `code/client/src/lib.rs`).
Without the passcode, neither can be read.

After logging in, press **Connect**. The app checks the relay against the
pubkey it was given in `SERVER_PUBKEY` (set at launch, or baked in at build
time; `runpeer.sh` sets it) and refuses to connect to anything else. The
main screen appears once connected, no sooner than 2 seconds after
pressing Connect; errors show straight away.

On the main screen, the identity card shows just your name: the username
you logged in with. It rides along automatically in the KeyExchange the
moment you add someone, so their contact list shows "alice" instead of
your hex token with no extra step on their end (see
`Client::local_name`/`contact_names` in `code/client/src/lib.rs`). What a
peer needs to add you:

- **Your QR code:** tap **+** by "Contacts", then **Show QR code**. They
  scan it with **+** → **Scan QR code**.
- **Your routing token and Ed25519 key, as text:** under **Settings** →
  "Show token and key". They paste them into **+** → **Manual add**.

### Peers on other devices (LAN)

`runserver.sh` only accepts peers on the same machine. To let other PCs
and phones on your network connect, start the relay with
`./runserver-lan.sh` instead. It prints this machine's IP. On WSL2, it
also warns you if WSL needs switching to mirrored networking, and says how.
Then, on each client:
```
./runpeer-lan.sh --pc <server-ip>       # desktop peer
./runpeer-lan.sh --mobile <server-ip>   # build + install the Android app
```
Leave out `<server-ip>` when the relay runs on that same machine. For
Android, set up the toolchain first; see [ANDROID.md](ANDROID.md).

### Testing messaging between peers

With several windows on one machine, copying the token and key is the
easy way. Between devices with cameras, scanning each other's QR codes
does the same.

1. In alice's window, copy her identity (routing token + Ed25519 key,
   under Settings → "Show token and key").
2. In bob's window, tap **+** by "Contacts", then **Manual add**, paste
   those in and submit. Alice shows up as "pending": a connection request
   only counts once the other side has added you too, so alice's client
   ignores bob's until then.
3. Repeat in the other direction: copy bob's identity and add it as a
   contact in alice's window.
4. Now that both sides have added each other, the KeyExchange goes
   through: each contact list shows the other's name ("alice", "bob" —
   nobody typed them in) and flips that contact's status from
   "pending" through "connecting" (they've added you, and the session is
   being set up) to "established" — at that point you can select the
   contact and send messages in either window. The same pattern (both
   sides add each other) applies for any additional peers.

The setup carries on by itself if a packet goes missing, or if one of you
was offline when the other added you: until a contact is established, the
app sends them its KeyExchange again now and then (after 10 seconds, then
twice as long each time, up to 8 times). Once they've added you, each
setup packet also goes out three times, so heavy loss rarely stops all of
them. Adding them again, from either side, also picks the setup up where
it stopped, and starts those resends over. If the relay restarts, the app
notices its syncs going unanswered and reconnects by itself once it has
heard nothing from the relay for two minutes, or straight away after a
phone wakes from a long sleep.

Someone who tries to connect before you've added them pops up as "Someone
wants to connect": scanning their code accepts, "Not now" hides them for a
day, and "Mute connection requests" stops the pop-ups until you unmute
them in the contact list. Just closing the pop-up only hides that request
until the app restarts. At most 8 new ones are listed every 10 minutes,
however many identities they come from.

### When something goes wrong

- **A message that didn't send:** your messages show a spinner while
  sending, then ✓ once the relay has them. One the relay hasn't confirmed
  after 30 seconds gets a red **!** and a retry button, which sends it
  again as a new message. If the first try did get through, they get it
  twice.
- **A broken session:** **Repair session**, in the ⋮ menu of an open chat,
  sets up a fresh session with that contact, as removing and re-adding
  them would, but keeps the contact, their name and your chat history.
- **Seeing the connection:** tick **Network stats** under Settings (off by
  default; it sends about 4 KB/s of extra packets while the app is open).
  The **Network** fold then shows the relay, packets sent and received,
  the loss each way and what had to be sent again, and a thin amber bar
  warns when 90% or more is being lost either way.
- **Testing a bad connection:** **Simulated loss**, in the Network fold,
  drops the percentage you set of this device's packets, sending and
  receiving set separately. It works with Network stats off, and resets
  to 0 when the app closes. To make the relay itself lossy for everyone, run
  `./runserver-lan-lossy.sh` instead of `./runserver-lan.sh`.

[Frontend-UI-info.md](../../documentations/Frontend-UI-info.md) covers
each of these in more depth.

## What's real vs. what's still a prototype shortcut

- **Real**: identity generation, the link handshake, the PQXDH session
  establishment, the symmetric ratchet, PQ injection, the RaptorQ FEC
  transport, message encrypt/decrypt — all the same code path the CLI
  (`code/client/src/main.rs`) uses. Adding a contact by scanning their QR
  code works, with the device's camera. Chat history persists across
  restarts, and an identity's state and history are encrypted at rest
  (see [The screens](#the-screens)).
- **Prototype shortcut**: the receive loop and `bootstrap` talk to a single
  relay, whose address and key come from `SERVER_ADDR` and `SERVER_PUBKEY`
  (default `127.0.0.1:4430`), read at launch or baked in at build time,
  or from `runpeer.sh -ip/-p/-pk`, which sets them. There's no relay
  address field in the UI, so it's not something end users configure at
  runtime.
