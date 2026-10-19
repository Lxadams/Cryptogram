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
    app.rs        Screens: Login -> Connect -> Identity/Contacts/Chat
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

Each window opens on a **Login screen**: enter a username and passcode for
an identity that already exists — the screen lists usernames already used
on this machine in an "Existing identities" dropdown (pick one to fill the
username field instead of retyping). Picking one also shows a small delete
icon next to the dropdown, with a "Delete? Yes/No" confirm before it
actually removes anything — there is no passcode recovery, so this is the
only way back from a forgotten one. The passcode field has a small eye
icon to toggle between masked dots and plaintext while typing. Logging
into an identity that's already logged in on another running peer is
refused (see `try_acquire_session_lock` in `src-tauri/src/commands.rs`) —
one live session per identity at a time; a **Log out** button (shown in
the header on every screen past Login) releases that session and returns
to the Login screen so you can switch identities without closing the
window. No identity for that username yet? Use the **Create identity**
button to switch to a separate screen (username + passcode + confirm
passcode); on success it sends you back to Login to sign in with what you
just chose. This is what used to be
`./runpeer.sh <name>` — the identity now lives under `identities/<username>/`
inside this OS's per-app data directory (e.g. `~/.local/share/nz.ac.waikato.compx374.e2e-messenger/identities/`
on Linux; see `identities_root` in `src-tauri/src/commands.rs`) instead of
being picked by a shell argument, so peers never clobber each other no
matter how many are running. This is deliberately *not* a path relative to
cwd — that broke in practice, since `cargo tauri dev` and a directly-run
built binary don't share the same cwd, so two peers landed in two
different `identities/` directories (and one of them sat inside
`src-tauri/`, which is watched for source changes — every autosave there
got mistaken for a code change, killing and restarting that peer). Note:
today this passcode only gates *which* identity file loads — it is not yet
a real encryption key, so `client_state.json` is still plaintext on disk
(same as the old `client_state.json`/`.peers/` files were).

After logging in, press Connect on the Connect screen. The app checks the
relay against the pubkey it was given in `SERVER_PUBKEY` (set at launch, or
baked in at build time; `runpeer.sh` sets it for the local relay) and
refuses to connect to anything else. Once connected, your identity (name + routing token + Ed25519
key) is shown — the routing token + Ed25519 key are what a peer needs to add you as a
contact (stand-in for scanning a QR code, per the Micro-QR design in
`doable-cryptographic-flow.md`). The name is whatever username you logged
in with — it rides along automatically as part of the KeyExchange the
moment you connect to someone, so a peer's contact list shows "alice"
instead of your hex token with no extra step on their end (see
`Client::local_name`/`contact_names` in `code/client/src/lib.rs`).

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

1. In alice's window, copy her identity (routing token + Ed25519 key) —
   just those two fields, same as before names existed.
2. In bob's window, paste those into "Add contact" and submit. Alice
   shows up as "pending": a connection request only counts once the other
   side has added you too, so alice's client ignores bob's until then.
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
them. Adding them again, from either
side, also picks the setup up where it stopped, and starts those resends
over. If the relay restarts, the app notices its syncs going unanswered
and reconnects by itself once it has heard nothing from the relay for two minutes, or straight away after a phone wakes from a long sleep. Someone who tries to connect before you've added them
pops up as "Someone wants to connect": scanning their code accepts, "Not
now" hides them for a day, and "Mute connection requests" stops the pop-ups
until you unmute them in the contact list. Just closing the pop-up only
hides that request until the app restarts. At most 8 new ones are listed
every 10 minutes, however many identities they come from.

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
  each identity's `client_state.json` (under this OS's per-app data
  directory, see the Login screen section above) regardless. The login
  screen's passcode is likewise a UI-layer gate, not at-rest encryption
  yet — see `hash_passcode`'s doc comment in
  `code/client/src/lib.rs`.
- **Known limitation**: the receive-loop and `bootstrap` talk to a single
  relay, defaulting to `127.0.0.1:4430` — override with the `SERVER_ADDR`
  env var (e.g. `SERVER_ADDR=<ec2-host>:443`), same as the CLI. No server
  address field in the UI yet, so it's still env-var-only, not something
  end users configure at runtime.
