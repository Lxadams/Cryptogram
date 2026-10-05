# Roadmap and decisions

This doc covers what the project set out to build, how far `main` has got, what's next, and the design decisions made along the way.

It replaces three older documents: the original MVP roadmap (`doable-roadmap.md`), the Leptos client proposal (`tech-decision-leptos-client.md`) and the Android UI/FFI personal roadmap (`mobile-ui-ffi-roadmap.md`). The Android plan was superseded when the team moved to Leptos + Tauri (see D4 below).

---

## 1. Goal and scope

The aim is a proof of concept for a 4-person, single-semester project. It should demonstrate:

- **post-quantum key exchange:** a hybrid of X25519 and Kyber-768;
- **trust through QR codes** instead of accounts;
- **a blind relay** that routes by opaque tokens and keeps state only in RAM;
- **extreme loss tolerance:** messages getting through on a network that drops 90% of packets;
- **metadata hiding:** constant-rate traffic, so an observer can't tell when anyone is talking.

### What was deliberately left out

| Cut | Kept instead |
|---|---|
| ML-DSA (Dilithium) signatures | Ed25519 for both users and the relay |
| QUIC and HTTP/3 censorship evasion | Raw UDP on port 443 (D1) |
| Signal Double Ratchet and "blunt-force" session resets | Hash ratchet with Kyber mixed in periodically (D2) |
| Samsung Knox and hardware-backed key storage | SQLCipher with an Argon2id-derived key (D6) |
| Proof-of-work and spilling the relay queue to disk | RAM-only relay with bounded queues |
| Group chat | Stretch goal |

---

## 2. Progress against the plan

✅ done · 🟡 partly done or changed · ❌ not done

### Phase 1: crypto core, QR exchange, PQ bootstrapping

| Task | Status | Notes |
|---|---|---|
| 1.1 Key generation (Ed25519, X25519, Kyber-768) and the hybrid KDF | ✅ | `UserIdentity::generate`, `hybrid_root_key` |
| 1.2 RaptorQ: split a buffer into symbols, drop some, reassemble | ❌ | Not on `main`. Integration is in progress on a separate branch. |
| 1.3 UI bound to the Rust core | ✅ | Leptos + Tauri instead of Kotlin + `uniffi` (D4) |
| 1.4 Camera QR exchange | 🟡 | Showing and scanning QR codes is built. Scanning hasn't been tested with a real camera yet. |

### Phase 2: ratchet and transport

| Task | Status | Notes |
|---|---|---|
| 2.1 Hash ratchet with periodic Kyber injection | ✅ | Every 5 messages |
| 2.1b Skip dictionary with limits | ✅ | 100-message window, at most 500 skipped keys |
| 2.2 Raw `tokio` UDP | ✅ | |
| 2.2 100 ms metronome with dummy packets | ❌ | No cover traffic. The relay's dummy-packet path is never used. |
| 2.2b Link handshake and XChaCha20-Poly1305 link encryption | ✅ | Ephemeral DH, signed by the relay's key |
| 2.3 Android foreground service | ❌ | There's no mobile build yet |

### Phase 3: blind relay

| Task | Status | Notes |
|---|---|---|
| 3.1 Async UDP relay on port 443, deployed to AWS | ✅ | Docker image, EC2 deploy from CI ([deployment.md](deployment.md)) |
| 3.1 Drop invalid traffic without allocating memory | 🟡 | Unknown session IDs and bad MACs are dropped. Queues are capped per token, but any connected client can create a queue for any number of tokens. |
| 3.2 RAM routing table and offline queue | ✅ | At most 50 packets per token, 1000 s TTL |
| 3.3 Collect queued packets on app open | ✅ | The sync packet sent at connect time empties the queue |

### Phase 4: integration and demo

| Task | Status | Notes |
|---|---|---|
| 4.1 Chat UI wired to the core | 🟡 | Type → ratchet encrypt → UDP works. There's no RaptorQ or metronome step yet. |
| 4.1b Session reset (manual or every 100 messages) | ❌ | Replaced in practice by PQ injection. Re-adding a contact is the only way to reset a session. |
| 4.2 UX polish | ✅ | Login, identities, light and dark themes, persistent history, online indicator, display names, QR |
| 4.3 Demo at 90% packet loss | ❌ | Needs FEC first |

### Phase 5 (stretch): ephemeral multicast group chat

Not started. The plan: share a Signal-style *sender key* over the existing 1-on-1 sessions, use `MULTICAST_BIND` control packets to tell the relay which tokens belong to a temporary group, and have the relay copy each group packet into every member's queue.

### Built but not in the original plan

- Usernames and passcodes, several identities per machine, and one live login per identity.
- Encryption at rest: Argon2id + SQLCipher for keys, session state and chat history.
- Signed presence pings and an online indicator, plus a keepalive that holds NAT mappings open.
- Display names carried inside the signed KeyExchange.
- Docker images, a GitHub Actions pipeline (format, lint, build, test) and EC2 deployment.

---

## 3. Next steps

These are roughly in priority order. The `H`, `M` and `L` IDs refer to the open issues in [cryptography.md §9](cryptography.md#9-open-issues).

1. **Forward error correction (RaptorQ).** This is the main promise that isn't built yet. FEC would also fix the biggest reliability problem today: a single lost PQInject or handshake packet breaks a session (H3, M5). The open question is how to send the symbols: in bursts, or over a constant-rate tunnel (next item).
2. **Traffic shaping.** Decide between a constant-rate tunnel with dummy packets (the original 100 ms metronome) and paced bursts, then implement it on both client and relay. Turn down the relay's logging (M4).
3. **Ratchet fixes.** Separate the send and receive chains with labels for each direction, and authenticate the message header (M1). Make PQ injection tolerate loss (H3).
4. **Forward secrecy against long-term key compromise.** Add rotating Kyber and X25519 prekeys or a DH ratchet (H2).
5. **Encrypted CLI and relay keys** (H1). Bring the CLI up to date with the desktop app, including keepalive and presence.
6. **Relay hardening.** Stop session-ID takeover (M3), cap the total number of queues, and accept messages bigger than ~1.9 KB.
7. **Desktop UX.** A relay address field and a remembered relay pubkey, instead of the `SERVER_ADDR` env var and pasting every time. A message-requests step instead of auto-accept (M2). Delivery status for messages.
8. **Mobile.** Try Tauri's Android target: camera permissions, keeping the app running in the background, and battery restrictions.

---

## 4. Decision log

### D1: Raw UDP on port 443 instead of QUIC

**Decided:** early in the project, recorded in the original roadmap.

QUIC's handshakes and congestion control slow down badly on very lossy links like satellite or degraded 2G/3G, and don't work at all at 95% loss. Raw UDP datagrams are as efficient and predictable as it gets. Using port 443 makes the traffic look like it *might* be HTTPS to a quick inspection. That's a much weaker disguise than real QUIC, and the project shouldn't claim more than that.

### D2: Hash ratchet with periodic Kyber injection instead of a Double Ratchet

**Decided:** during Phase 2 crypto work.

A Double Ratchet with post-quantum key exchange mixed in was too much for the timeframe. A blunt-force reset every 100 messages was the first fallback. What got built instead is simpler: an HMAC hash ratchet for each direction, with a fresh Kyber secret mixed into the sender's chain every 5 messages. The cost is weaker forward secrecy if long-term keys leak, and no protection after a compromise beyond the Kyber mixing (see [cryptography.md §9](cryptography.md#9-open-issues), H2).

### D3: Deferred key exchange instead of putting every key in the QR code

**Decided:** during Phase 1.

A Kyber-768 public key is 1184 bytes, too much for a QR code that scans reliably. The QR code (or pasted text) carries only the routing token and Ed25519 key, 48 bytes of data. The large keys are exchanged over the network, signed with that Ed25519 key.

### D4: Leptos + Tauri instead of Android Studio / Kotlin

**Proposed** by Rowan on 2026-07-28 and **adopted** when the Leptos + Tauri desktop prototype was merged (PR #18, 2026-08-16).

The original plan was a native Kotlin Android app that would call the Rust core through `uniffi`/JNI. The Leptos alternative had two options:

- **Option A:** a pure browser app. Browsers don't allow raw UDP sockets, so the relay would have to move to WebTransport or WebSockets.
- **Option B (chosen):** host the Leptos UI in a **Tauri** native shell. The shell keeps real OS sockets, so the raw-UDP design stays as it was. Leptos only replaces Kotlin as the UI layer.

Why Option B:

- **Everything is Rust.** The UI, the core and the shell share one language. There are no FFI bindings to generate, no per-ABI cross-compiling, and no marshalling callbacks across JNI.
- **It runs on more platforms.** Linux, Windows and macOS today. Tauri 2 can also target Android and iOS, so mobile is still possible.
- **Easier for the team.** Contributors don't need Android Studio, Gradle or an emulator.
- **The client core is shared.** The client crate was split into a library and a CLI, so the Tauri shell and the CLI run exactly the same protocol code.

As a result, the Android material (the `uniffi` setup, foreground services, CameraX/ML Kit) is no longer the plan. The pieces that still matter for a future mobile build are in the [learning guide](learning-guide.md#6-if-targeting-mobile).

### D5: The UI polls the backend instead of receiving events

**Decided:** while building the desktop prototype.

The UI calls `list_contacts` and `poll_inbox` once a second instead of subscribing to Tauri events. It's simple, and for a prototype the delay doesn't matter.

### D6: SQLCipher with an Argon2id-derived key for local storage

**Decided:** when the chat history and login work landed.

The original plan was Android Encrypted Shared Preferences or SQLCipher. With a desktop app, SQLCipher works on every platform. One passcode, stretched with Argon2id, unlocks both the identity store and the chat history (see [cryptography.md §7](cryptography.md#7-local-secret-storage)).

### D7: QR codes handled in Rust/WASM

**Decided:** when the QR feature landed.

QR codes are encoded with `qrcode` and decoded with `rqrr` inside the shared WASM UI. Camera frames come from the webview's `getUserMedia`. That means one implementation for every platform and no scanner plugin per platform. The only per-platform work is camera permission: Linux needs a small opt-in in the WebKitGTK webview, mobile and macOS need a permission declared in the manifest, and Windows asks the user.

---

## 5. Team roles

These are the roles from the original plan, adjusted for the platform change.

| Role | Focus |
|---|---|
| UI lead | Leptos UI, Tauri shell and commands, QR exchange, desktop and future mobile packaging |
| Post-quantum crypto lead (Logan) | Hybrid handshake, HKDF derivations, hash ratchet with PQ injection, security review |
| Transport and FEC lead | RaptorQ encoding and decoding, pacing or the metronome, cover traffic, UDP reassembly |
| Server lead | Relay routing, offline queues, Docker and EC2 deployment |
