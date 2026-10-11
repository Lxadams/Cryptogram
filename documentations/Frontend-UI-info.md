# How the frontend / UI works

What the app's user interface is made of, how it talks to the Rust core, and what happens on each screen. This is the companion to [Logan-info.md](Logan-info.md): that one follows a message across the network, this one stops at the edge of the `client` crate and covers everything in front of it. Covers:

1. [The three layers](#1-the-three-layers) (Leptos UI → Tauri shell → `client` crate)
2. [The bridge](#2-the-bridge-apirs--commandsrs): every command the UI can call
3. [Screens and navigation](#3-screens-and-navigation)
4. [The main screen](#4-the-main-screen), component by component
5. [How the UI stays up to date](#5-how-the-ui-stays-up-to-date-polling) (polling, message ids, the ✓)
6. [QR codes](#6-qr-codes): the contact code, presenting, scanning
7. [Styling, theme and the phone layout](#7-styling-theme-and-the-phone-layout)
8. [Android specifics](#8-android-specifics)
9. [Things I noticed](#9-things-i-noticed-while-tracing-this-possible-follow-ups)

Everything here is from the code as of `Logan/Bug-Fixes` (commit `714eb51`). File references are relative to `code/frontend/`.

---

## The big picture in one paragraph

The UI is a **Leptos** app (Rust compiled to WebAssembly by **Trunk**) that runs inside a **Tauri** webview. The WASM side can't open sockets or touch files, so it does nothing but draw screens and call named **Tauri commands** through `window.__TAURI__.core.invoke`. Those commands live in the native half of the app (`src-tauri/`), which owns the one real `Client` from the `client` crate, its UDP socket, and three background loops. Nothing is pushed from the backend to the UI: the main screen **polls once a second** for contacts, connection requests, new messages and send-status changes. The same WASM and CSS run on desktop and Android. The only per-platform code is in `src-tauri/` (camera opt-in on Linux, a Kotlin foreground service and notifications on Android).

```
 ┌────────────────────────── webview (WASM, no sockets, no files) ───────────────────────────┐
 │  src/main.rs   mount App into <body>                                                      │
 │  src/app.rs    screens + components, all state in Leptos signals                          │
 │  src/qr.rs     QR draw (qrcode) + camera scanner (getUserMedia + rqrr)                    │
 │  src/contact_code.rs   "CG2:<Base45>" contact code encode/parse                           │
 │  src/api.rs    one async fn per command, DTOs mirrored field for field                    │
 └───────────────────────────────────────┬───────────────────────────────────────────────────┘
                                         │ window.__TAURI__.core.invoke("name", args)  (JSON)
 ┌───────────────────────────────────────▼──────────── native process ──────────────────────┐
 │  src-tauri/src/lib.rs        registers the 19 commands, Linux camera opt-in               │
 │  src-tauri/src/commands.rs   #[tauri::command] fns + receive / tick / keepalive loops     │
 │  src-tauri/src/state.rs      AppState { runtime, pending_identity, identity_lock }        │
 │  src-tauri/src/background.rs Android bridge (foreground service, notifications)           │
 │                    │                                                                      │
 │                    ▼                                                                      │
 │  client crate: Client (crypto, ratchet, FEC, history DB)  ──── UDP ────▶ relay            │
 └───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. The three layers

| Layer | Where | Built by | Job |
|---|---|---|---|
| **UI** | `src/`, `index.html`, `style.css` | Trunk → `wasm32-unknown-unknown` | Screens, forms, QR drawing and scanning. Holds no keys and no network code. |
| **Shell** | `src-tauri/` | `cargo tauri` | The native window (webview), the command handlers, shared state, background loops, platform glue. |
| **Core** | `../client/` | plain cargo dependency of the shell | The real protocol: identity, handshake, sessions, ratchet, FEC, chat history. Same code the CLI uses. |

Why it's split this way: a browser/WASM target has no raw UDP, and the transport needs raw UDP. Tauri gives the Rust core real OS sockets while Leptos replaces Kotlin as the UI layer ("Option B" in [tech-decision-leptos-client.md](tech-decision-leptos-client.md)).

### How it's wired together at build time

- `index.html` is Trunk's entry point: an empty `<body>` and one `<link data-trunk rel="css" href="style.css">`. Trunk compiles the crate to WASM and injects the loader script itself.
- `src/main.rs` installs `console_error_panic_hook` (readable panics in the webview console) and calls `mount_to_body(app::App)`.
- `tauri.conf.json`: `beforeDevCommand` is `trunk serve --port 1420`, and `devUrl` points the window at it. For release builds, `trunk build --release` writes `dist/` and Tauri bundles it (`frontendDist`).
- `withGlobalTauri: true` makes Tauri inject `window.__TAURI__` into the page. There's no JS bundler in the project, so `api.rs` binds to that global directly with `wasm-bindgen` instead of importing `@tauri-apps/api`.
- `Trunk.toml` ignores `src-tauri/` in its file watch. Without that, the backend saving state looked like a source change and Trunk hot-reloaded the UI right after every Connect, wiping all its in-memory state.

Opening the Trunk URL in a normal browser draws the UI, but every command call rejects: there's no `window.__TAURI__` there.

---

## 2. The bridge (`api.rs` ↔ `commands.rs`)

`api.rs` has one generic helper, `call(cmd, args)`: serialise the args with `serde-wasm-bindgen`, call `invoke`, await the JS promise, deserialise the result. A command's `Err(String)` arrives as a plain JS string and is returned as `Err(String)`, which the screens show as-is in a red `<p class="error">`.

Two rules keep the two sides in step:

- Every command is declared `#[tauri::command(rename_all = "snake_case")]`, so argument names are identical on both sides (no camelCase translation).
- Every DTO is defined **twice**, once in `commands.rs` (`Serialize`) and once in `api.rs` (`Deserialize`), and serde matches by field name. Change one and you must change the other; nothing checks this at compile time.

All commands lock `AppState.runtime` (a `tokio::sync::Mutex<Option<ClientRuntime>>`). Anything that needs the relay returns `"Not connected to relay yet"` until `bootstrap` has run.

### Session commands (work before Connect)

| Command | Args | Returns | What it does |
|---|---|---|---|
| `list_pseudonyms` | none | `Vec<String>` | Every folder under `identities/` that has a `passcode.hash`, sorted. |
| `create_identity` | `pseudonym`, `passcode` | `()` | Validates the username (≤ 40 chars; letters, digits, space, `-`, `_`), writes `passcode.hash`. Doesn't log in. |
| `login` | `pseudonym`, `passcode` | `LoginOutcome` | Ends any existing session, checks the passcode, derives the **vault key**, takes the identity's `session.lock`, and stores a `PendingIdentity`. No network. `UnknownUsername` is a normal `Ok` result so the UI can offer "Create new identity?". |
| `delete_identity` | `pseudonym` | `()` | Deletes the identity's folder. **No passcode needed** (it's the only way back from a forgotten one). Refused if that identity is logged in here or in another process. |
| `current_session` | none | `Option<SessionDto>` | Who's logged in, and their identity if already connected. Lets a reloaded UI skip straight back to where it was (§8). |
| `bootstrap` | none | `IdentityDto` | The Connect button. Loads or creates the `Client`, opens the chat-history DB with the vault key, binds a UDP socket, does the relay handshake, and spawns the three background loops. |
| `logout` | none | `()` | Aborts the loops, drops the client and socket, releases the session lock. |

### Main-screen commands (need a connected runtime)

| Command | Args | Returns | Called from |
|---|---|---|---|
| `list_contacts` | none | `Vec<ContactDto>` (`token`, `status`, `name`) | 1 s poll |
| `connection_requests` | none | `ConnectionRequestsDto` (`tokens`, `muted`) | 1 s poll |
| `poll_inbox` | none | `Vec<IncomingMessageDto>` (drains the inbox) | 1 s poll |
| `sent_message_updates` | none | `Vec<SentMessageUpdateDto>` (drains) | 1 s poll |
| `chat_history` | `token_hex`, `limit` | `Vec<StoredMessageDto>`, oldest first | first time a contact is selected (limit 200) |
| `send_message` | `token_hex`, `text` | `SentMessageDto` (`id`, `timestamp_ms`) | Send button / Enter |
| `connect_to_peer` | `token_hex`, `ed25519_hex` | `()` | QR scan or manual add |
| `remove_contact` | `token_hex` | `()` (also deletes that chat's history) | bin icon → "Remove? Yes" |
| `dismiss_connection_request` | `token_hex` | `()` | "Not now" |
| `set_connection_requests_muted` | `muted` | `()` | "Mute connection requests" / "Unmute" |
| `notification_settings` | none | `NotificationSettingsDto` (`posted`, `with_names`) | once, when the identity card mounts |
| `set_notify_with_names` | `on` | `()` | Settings checkbox |

Contact `status` is one of three strings: `pending` (we added them, waiting for them to add us), `connecting` (they've added us, session being set up), `established` (can chat).

### Where things live on disk

Under the OS's per-app data directory (on Linux, `~/.local/share/nz.ac.waikato.compx374.e2e-messenger/identities/<username>/`):

| File | What |
|---|---|
| `passcode.hash` | Passcode verifier. Its existence is what makes a username "exist". |
| `client_state.sqlite` | SQLCipher-encrypted identity and session state, keyed by the vault key. |
| `chat_history.sqlite` | SQLCipher-encrypted chat history, same key. |
| `session.lock` | OS file lock: one live login per identity per machine. |

The passcode string is zeroised inside `login`; only the derived 32-byte vault key is kept (in `PendingIdentity`, wrapped in `Zeroizing`).

---

## 3. Screens and navigation

There is no router. `App` (`src/app.rs`) holds a few signals and picks a screen from them:

| Signal | Type | Meaning |
|---|---|---|
| `restoring` | `bool` | `true` until the startup `current_session` call returns. Nothing is drawn while it's true. |
| `login` | `Option<LoginDto>` | `Some` once `login` succeeds. |
| `identity` | `Option<IdentityDto>` | `Some` once `bootstrap` succeeds. |
| `auth_screen` | `Login` / `CreateIdentity` | Which of the two pre-login forms is showing. |
| `theme` | `Light` / `Dark` | See §7. |

```
            app start
               │  current_session()
               ▼
   ┌──────── login == None ────────┐         login == Some            login == Some
   │                               │         identity == None         identity == Some
   │  LoginScreen ⇄ CreateIdentity │ ──────▶ ConnectScreen ─────────▶ MainScreen
   │      ▲    "Create identity" / │  login()        bootstrap()
   │      │    "Back to login"     │
   └──────┼────────────────────────┘
          └──────────────── "Log out" (header, any screen past Login) ◀──────────────
```

The header is always there: the title, a **Log out** button (only when `login` is `Some`), and the **Light mode / Dark mode** toggle. Log out calls `logout` and clears both `identity` and `login`, so it also works as the way out of a stuck Connect screen.

### Login (`LoginScreen`)

- **Existing identities** dropdown, filled from `list_pseudonyms` and refreshed every second (identities are per machine, not per window, so another window creating or deleting one shows up here). Picking one fills the username field.
- With one picked, a bin icon appears. Clicking it swaps to an inline **"Delete? Yes / No"**; Yes calls `delete_identity`.
- Username field, passcode field (`PasswordInput`, with an eye icon to show or hide it), **Log in** and **Create identity** buttons.
- An unknown username gets its own message with a **"Create new identity?"** link, which jumps to the create screen with the typed username carried over (`prefill_create_username`).
- After a successful create, the username is prefilled and a hint says `Identity "x" created — log in below.` (`just_created`).

### Create identity (`CreateIdentityScreen`)

Username, passcode, confirm passcode. The "passcodes match" check is done in the UI; everything else is validated by the backend. On success it goes **back to Login** rather than logging in.

### Connect (`ConnectScreen`)

One button. It calls `bootstrap`, shows "Connecting..." while it runs, and shows the error underneath if it fails (relay down, wrong relay key, corrupt state). The relay's address and public key come from `SERVER_ADDR` / `SERVER_PUBKEY`, read at launch or baked in at build time, so there is nothing to type.

---

## 4. The main screen

`MainScreen` owns the state its children share and passes it down as props:

| Signal | Type | Used by |
|---|---|---|
| `contacts` | `Vec<ContactDto>` | contact list, chat header and status |
| `selected` | `Option<String>` (token hex) | which chat is open |
| `messages` | `HashMap<token, Vec<ChatMessage>>` | transcripts |
| `requests` | `ConnectionRequestsDto` | request pop-up, "muted" hint |
| `scanning` | `bool` | whether the QR scanner dialog is open |
| `history_loaded_for` | `HashSet<token>` | so each chat's history is fetched once |
| `early_updates` | `HashMap<id, SendStatus>` | ✓ results that beat their message (§5) |

```
MainScreen
├─ IdentityCard                 your name, "Present QR code", token/key, settings
├─ div.columns
│  ├─ ContactPanel              contact list, add contact, scanner dialog
│  └─ ChatPanel                 header, transcript, composer
└─ ConnectionRequestNotice      pop-up when a stranger tries to connect
```

### `IdentityCard`

- Your username and a **Present QR code** button, which opens a `Modal` with the QR for your contact code (§6).
- A folded **"Show token and key"** section: name, routing token and Ed25519 key as hex, each with a `CopyButton` (copies, shows a tick for 1.2 s). This is the manual alternative to the QR.
- A folded **Settings** section, shown only where `notification_settings().posted` is true (Android): one checkbox, *"Say who each message is from in notifications"*, off by default.

### `ContactPanel`

- **Contact list.** Each row: the contact's name (or the first 8 hex characters of their token until their name arrives), a status badge, and a bin icon with the same inline **"Remove? Yes / No"** confirm as identity delete. `pending` rows add *"Waiting for them to scan your code"*; `connecting` rows add *"They've added you. Connecting..."*. Clicking a row sets `selected`.
- The list's `<For>` is keyed on `(token, status, name)`, so a row is redrawn when its status or name changes.
- **Add contact.** Two paths, both ending in the same `connect_to_peer(token, key)` call:
  - **Scan QR code** opens the scanner dialog (`scanning = true`).
  - Two hex fields and **Send Connection Request** as the fallback.
- If requests are muted, a hint with an **Unmute** link.

Both people must add each other. Adding someone only sends them a KeyExchange; they ignore it until they've added you too.

### `ChatPanel`

- Nothing selected: *"Select a contact to start chatting."*
- Header: a **← Contacts** back button (only visible in the one-column layout) and "Chat with *name*".
- A hint while the contact is still `pending` or `connecting`. The composer is still there, but sending fails until the session is established and the backend's error is shown.
- **Transcript.** One `<p>` per message, `from-me` (right, accent colour) or `from-peer` (left). Under the text: the time (`format_time`: locale time, with the date in front if it isn't today) and, for your own messages, nothing while sending, **✓** once the relay has it, or a red **!** if it didn't confirm in time. Both marks have tooltips.
- **Auto-scroll.** A `Memo` tracks only *this* chat's message count; when it changes, the transcript scrolls to the bottom on the next task (after the DOM has updated). Traffic in other chats doesn't move it.
- **Composer.** Text field plus Send; Enter also sends. See §5 for what `send_now` does.

### `ConnectionRequestNotice`

Shown when `connection_requests` lists someone who isn't a contact (and requests aren't muted, and the scanner isn't open). It shows the first 8 characters of their token only, since a name they sent is unverified until you scan them.

| Action | Effect |
|---|---|
| **Scan their code** | Closes any open chat and opens the scanner. Scanning is what accepts. |
| **Not now** | `dismiss_connection_request`: hidden for a day. |
| **Mute connection requests** | `set_connection_requests_muted(true)`, saved with the identity. |
| X, click outside, Escape | Hidden only in this UI session (`closed` set), so a stray tap doesn't cost a day. |

### Shared pieces

| Component | What |
|---|---|
| `Modal` | Centred dialog on a dimmed backdrop. Closes on X, backdrop click, or Escape (a window key listener, removed on cleanup). |
| `PasswordInput` | Passcode field with show/hide toggle. |
| `CopyButton` | Copy-to-clipboard icon button. |
| `TrashIcon` | The bin SVG. |
| `stop_on_cleanup` | Clears a `set_interval` when its component unmounts. Without it, a dead screen's poll kept draining `poll_inbox` and stole messages from the live one. |

---

## 5. How the UI stays up to date (polling)

There are no events from the backend to the UI. Two timers do everything:

| Timer | Period | Calls |
|---|---|---|
| `LoginScreen::refresh_known` | 1 s | `list_pseudonyms` |
| `MainScreen::refresh` | 1 s | `list_contacts`, `connection_requests`, `poll_inbox`, `sent_message_updates` |

`refresh` only calls `set` on `contacts` and `requests` when the new value differs from the old one, so a quiet second redraws nothing. Results that land after the screen has unmounted are dropped safely (the `try_*` signal methods).

Meanwhile, in the backend, three loops run regardless of the UI (`commands.rs`): the **receive loop** (every UDP packet), the **tick loop** (500 ms: reorder timeouts and ✓ requests) and the **keepalive loop** (15 s). They fill `Client::inbox` and the send-update queue; the UI's poll drains them. So a received message appears up to 1 s after it was decrypted.

### Message ids: one identity for three sources

A transcript is assembled from three places, and they must agree on what "the same message" is:

| Source | When | Id used |
|---|---|---|
| `chat_history` | first time a contact is selected | history row id |
| `poll_inbox` | live, every second | history row id |
| `send_message` return value | after you send | history row id |

All three use the message's **chat-history row id**, with the top bit set (`history_message_id`). Purely local ids (`next_message_id`, used only if no history is attached) count up from 0, so the two ranges can't collide. That's what lets the history fetch *merge* instead of replace: it drops rows whose id is already in the live list and prepends the rest. A message that arrives while the fetch is in flight is neither lost nor shown twice.

### Sending, step by step (`ChatPanel::send_now`)

1. Empty or whitespace-only text is ignored.
2. The draft is cleared **immediately**.
3. `send_message` is awaited. It returns once the burst's first packet has left (after any earlier bursts), with the row id and timestamp.
4. On `Ok`: the message is appended to `messages[token]` with status `Sending`, unless a result for that id is already waiting in `early_updates`, in which case it takes that status.
5. On `Err` (too long, no session, network down): the text is put back in the draft if the field is still empty, and the error is shown under the composer.

### The ✓ and !, UI side

The backend settles each sent message as `sent` or `failed` (how is in [Logan-info.md §2](Logan-info.md#2-the-tick-mark--and-)). The UI's part:

1. `refresh` drains `sent_message_updates` and looks for a message with that id in any chat.
2. Found: set its `status`. The transcript `<For>` is keyed on `(id, status)`, so that one bubble is redrawn with its mark.
3. Not found: its `send_message` hasn't returned yet. The status is parked in `early_updates` (cleared if it reaches 64 entries) for step 4 above to pick up.

Messages loaded from history carry their stored status, so marks survive a restart. A message still `Sending` when the app was killed comes back as `Failed`.

---

## 6. QR codes

### The contact code (`src/contact_code.rs`)

```
CG2:<Base45( routing token 16 bytes ‖ Ed25519 public key 32 bytes )>
     └──────────────── 72 characters ────────────────┘
```

- Exactly the two values the manual form asks for. The QR is a different input path, not a different trust step.
- **Base45** (RFC 9285) uses only characters QR's alphanumeric mode packs tightly, so the code is a **29×29** QR (version 3) at error-correction level L. Bigger modules read from further away. A unit test pins the size.
- No display name in it: names arrive later, signed, in the KeyExchange.
- `parse` gives a specific message for each failure: not one of ours, from the older `cryptogram:v1:` format, or damaged.

### Presenting (`qr::svg_for`)

The `qrcode` crate renders an SVG, always black on white with a quiet zone whatever the theme. `IdentityCard` builds it once and shows it in a wider-than-usual modal.

### Scanning (`qr::QrScanner`)

All of it runs in the shared WASM, so there is no native scanner plugin:

1. `getUserMedia` with ideal constraints: rear camera, up to 1920×1080, continuous autofocus where supported. Rejections are mapped to plain messages (denied, no camera, in use).
2. The stream plays in a `<video>`. Every **250 ms** a frame is drawn to an off-screen canvas (downscaled to at most 1280 px wide), converted to greyscale, and decoded by **`rqrr`**.
3. `rqrr` is limited to about **25%** of the UI thread: after a decode that took `t`, the next waits `t / 0.25`. Slow phones scan less often instead of stuttering.
4. Optional: *"Also use this device's own scanner"* turns on the webview's `BarcodeDetector` in parallel (on Android that's Google's ML Kit, better with blur and glare). It's off by default, only offered where the API exists, and the choice is kept in `localStorage`.
5. Each decoded string goes to `on_scan`. `Ok` stops the camera; `Err(msg)` shows the message and keeps scanning, and the same rejected string isn't reported again while it stays in view.
6. The camera is released when the dialog closes, including if it closes during the permission prompt.

`ContactPanel`'s `on_scan` parses the contact code, clears any matching connection request, closes the scanner and calls `connect_to_peer`.

Camera access per platform: Linux needs code (`enable_camera_for_qr_scanner` in `src-tauri/src/lib.rs` switches on WebKitGTK's media stream and allows video-only requests); Android needs the `CAMERA` permission in the manifest; Windows prompts by itself.

---

## 7. Styling, theme and the phone layout

One hand-written stylesheet, `style.css` (no framework, no component-scoped CSS).

- **Colours** are CSS custom properties on `:root` (`--bg`, `--panel`, `--sunken`, `--hover`, `--border`, `--text`, `--muted`, `--accent`, `--ok`, `--error`), with one block per theme keyed on `<html data-theme="light|dark">`.
- **Theme choice** (`initial_theme` in `app.rs`): the saved value in `localStorage` (`e2e-messenger-theme`) if there is one, else the system's `prefers-color-scheme`, else dark. An `Effect` writes the attribute and saves the choice whenever the toggle flips it.
- **Page layout:** `body` doesn't scroll. `.app` is a full-height flex column (max width 1100 px); the panels inside scroll on their own, so the composer stays put while the transcript scrolls.
- **Login / Create / Connect** are a centred column, max 440 px.
- **Main screen, wide:** a two-column grid, contacts (220–300 px) beside the chat.
- **Main screen, narrow** (`max-width: 719px`): one column. `MainScreen` adds the class `chat-open` when a contact is selected, and CSS shows *either* the identity card and contact list *or* the chat. The **← Contacts** button sets `selected` back to `None`. No JavaScript-side layout logic is involved.
- **Touch** (`pointer: coarse`): 16 px text in fields (stops mobile webviews zooming on focus) and bigger tap targets.

---

## 8. Android specifics

The UI code is identical; what differs is around it (`src-tauri/src/background.rs` and the Kotlin under `src-tauri/gen/android/app/src/main/java/.../`). Build and install steps are in `code/frontend/ANDROID.md`.

| Piece | What it does |
|---|---|
| `MainActivity.kt` | Sets `FLAG_SECURE` (no screenshots, blank recents thumbnail). Pads the webview by the status bar, navigation bar and **keyboard** insets, so the composer stays visible while typing (done natively because older WebViews report CSS safe-area insets as zero). Asks for notification permission on Android 13+. Starts `NativeBridge`. |
| `NativeBridge.kt` | A thread blocks in the JNI call `nextEvent()` and reacts to strings the Rust side emits: `session_started`, `session_ended`, `message`, `message\t<from>`. |
| `MessageService.kt` | A foreground service that runs while someone is logged in. It does no work; it exists so Android doesn't freeze the process and its UDP socket. Also posts the "N new messages" notification, only when the app isn't on screen, and never with message text. |
| `background.rs` | The Rust half: `session_started` (from `bootstrap`), `session_ended` (from logout), `message_received` (from the receive and tick loops). No-ops on desktop. |

**Swiping the app away.** That destroys the activity and its only window, and Tauri would then exit the process. `on_run_event` prevents the exit while someone is logged in, so the relay connection carries on. When the app is reopened:

1. `MainActivity.onResume` → `NativeBridge.appResumed()`.
2. Rust wakes the keepalive loop at once (`RESYNC`), so queued messages arrive now rather than on the next 15 s tick, and rebuilds the window from `tauri.conf.json` if there isn't one.
3. The fresh webview loads the UI from scratch. `App` calls `current_session`, finds the backend still logged in and connected, and goes straight to the main screen.
4. Transcripts are rebuilt from `chat_history` as each chat is opened.

So on Android the UI is disposable and the backend is the long-lived part. That's also why all durable state (history, statuses, mute and notification settings) lives behind commands, and only the theme and the scanner preference live in `localStorage`.

---

## 9. Things I noticed while tracing this (possible follow-ups)

1. **`code/frontend/README.md` is out of date.** Its "prototype shortcut" section says there is no camera or QR scanning, that message history isn't persisted, and that `client_state.json` is plaintext with the passcode only a UI gate. The code now has all three: the QR scanner, `chat_history.sqlite`, and SQLCipher stores keyed from the passcode. The doc comments on `LoginScreen` / `CreateIdentityScreen` in `app.rs` ("a UI-layer gate only") are stale in the same way, and `ConnectScreen` / `MainScreen` are still labelled "Screen 1" / "Screen 2".
2. **A sent message isn't on screen until `send_message` returns.** The draft clears at once, but the bubble is only added in the `Ok` branch, which waits for the burst's first packet behind any earlier bursts. Sending several messages quickly leaves a gap where the text has left the box and isn't in the transcript yet. The comment on `messages` calls this "added immediately, optimistically", which isn't quite what happens.
3. **No unread indicator.** Messages for a chat that isn't open go into `messages` silently; the contact list shows only name and status. On desktop there's no notification either.
4. **Removing a contact leaves its transcript in memory.** `do_remove` updates `contacts` and `selected`, but `messages[token]` and `history_loaded_for` keep the entry. If the same token is added again in the same session, the old bubbles would still be there although the history DB was wiped. Worth confirming and clearing both on remove.
5. **Only the latest 200 messages load.** `chat_history` is called once per contact with `limit = 200`, and there's no "load older" in the UI (the DTO comment notes the id would work as a pagination cursor).
6. **DTOs are duplicated by hand** between `api.rs` and `commands.rs`. A renamed field fails at runtime, as a deserialisation error string, not at compile time. A small shared crate would remove that.
7. **Polling, not events.** Four command calls per second per window while the main screen is up, each taking the runtime lock. It's simple and it works; Tauri events would cut the up-to-1 s display delay if that ever matters.
8. **Small things:** the Log out button reuses the `theme-toggle` CSS class; `tauri.conf.json` has `"csp": null` (no content security policy on the webview).
