# Learning guide

This is a map of the concepts you need to understand to work on each part of E2E-Messenger. It isn't a schedule. Each section says why the topic matters *here* and what to go and learn. The depth table at the end shows how far each role needs to go.

It replaces `LEARNING.md` and `UI-FFI_keyConcepts.md`. Those were written for the original Android/Kotlin + `uniffi` plan. Since the move to Leptos + Tauri ([roadmap.md](roadmap.md#d4-leptos--tauri-instead-of-android-studio--kotlin)), the FFI and Android sections have shrunk to the parts that still matter for a future mobile build (§6).

---

## 1. Cryptography

How it's used in this codebase: [cryptography.md](cryptography.md).

- **Ed25519 vs X25519.** Ed25519 *signs*: it proves a payload came from the holder of a key. X25519 *agrees on a shared secret*: two parties combine their private keys with each other's public keys and get the same value. Understand why a contact's Ed25519 key is the trust anchor while X25519 and Kyber supply the key material.
- **Key encapsulation (KEM).** Kyber/ML-KEM doesn't work like Diffie-Hellman. One side encapsulates a random secret to the other's public key, and the other side decapsulates it. Learn the three operations, `KeyGen`, `Encapsulate` and `Decapsulate`, and the size cost: a 1184-byte public key and a 1088-byte ciphertext, which is why the key exchange is deferred.
- **Hybrid key derivation (HKDF).** This is how two secrets are safely combined into one root key: `HKDF(dh ‖ kem)`. If either half holds, the session holds. Learn HKDF's extract and expand steps, and how salt and labels keep different derivations apart (`e2e-messenger-v1`, `pqxdh-root-key` and so on).
- **AEAD (XChaCha20-Poly1305).** Authenticated encryption with associated data. Know why the 24-byte *X* nonce makes random nonces safe, and what "associated data" would add. Message headers aren't authenticated today ([cryptography.md §9](cryptography.md#9-open-issues), M1).
- **Hash ratchet vs Double Ratchet.** A hash ratchet (key → HMAC → next key) gives *forward secrecy*: a stolen key today can't decrypt yesterday's messages. It doesn't recover after a compromise. A Double Ratchet adds a DH step that does. Here, Kyber injection is what partly fills that gap.
- **Out-of-order delivery.** UDP drops and reorders packets. Learn how sequence numbers and a skipped-key dictionary let late messages decrypt, and why the dictionary needs limits (memory exhaustion, DoS).
- **Replay and misbinding.** Timestamps with a tolerance window, binding to a target, and replay caches. Each one blocks a specific attack, listed in [cryptography.md §8](cryptography.md#8-hardening-history).

## 2. Protecting secrets at rest

- **Password hashing vs key derivation.** Argon2id is deliberately slow and memory-hungry, so offline guessing is expensive. Learn why one Argon2id output is split with HKDF into a *login verifier* and a *vault key*, so that reading the stored verifier reveals nothing about the key.
- **SQLCipher.** SQLite with page-level AES encryption. Understand what it protects against (someone copying the files off the disk) and what it doesn't (malware on an unlocked, logged-in machine).
- **Wiping secrets from memory.** The `zeroize` crate, and why the passcode is wiped as soon as login finishes.

## 3. Networking

- **UDP vs TCP and QUIC.** Why a messenger for lossy links avoids retransmissions and connection handshakes ([roadmap.md D1](roadmap.md#d1-raw-udp-on-port-443-instead-of-quic)). With UDP there's no error when a host is unreachable, which is why the handshake has a timeout.
- **NAT mappings.** Home and campus routers forget idle UDP mappings within about 30–60 s. That's why the desktop app re-sends a sync packet every 15 s, and why a client that has gone quiet stops receiving packets.
- **Link encryption between each hop and the next.** The outer XChaCha20-Poly1305 layer, keyed by an ephemeral handshake with the relay, hides inner payloads from anyone on the network. It doesn't hide them from the relay itself, which is why there's a separate end-to-end layer.
- **Routing by token, and a relay that knows nothing.** The relay maps a 16-byte token to an `ip:port` and queues packets for offline users in RAM. Learn what such a relay still finds out (metadata) and what would hide it.
- **Traffic analysis and constant-rate tunnels.** Even encrypted traffic gives away *when* and *how much* people talk. A constant-rate tunnel sends one packet every interval, real or dummy, to hide that. Learn what it costs in bandwidth and battery.

## 4. Forward error correction and RaptorQ

This is the core of the transport lead's work. It isn't on `main` yet.

- **Erasure codes vs ARQ.** Retransmitting after a missing ACK falls apart when round-trip loss is high: both the data and the ACK have to get through. With FEC, enough redundancy is sent up front that no ACKs are needed.
- **Fountain codes (RaptorQ, RFC 6330).** A message of *K* source symbols can produce as many repair symbols as you like. *Any* roughly *K* (+ε) received symbols rebuild it. Learn how to size symbols to fit under the MTU after the link and E2E headers, how much overhead it adds, and how to work out the number of symbols to send for a target loss rate.
- **Where it goes in the stack.** Encrypt end to end first, then split the ciphertext into symbols, then link-encrypt each symbol datagram. Think about how control packets (KeyExchange, PQInject) have to be protected too, not just chat messages.

## 5. The desktop app stack

How it's put together: the [frontend README](../code/frontend/README.md).

- **Rust to WebAssembly with Trunk.** `wasm32-unknown-unknown`, what Trunk builds from `index.html`, and why the UI crate can't open sockets.
- **Leptos.** Signals, effects, components, `spawn_local` for async calls, and cleaning up intervals when a component is removed. The UI is client-side rendered (`csr`).
- **Tauri 2.** `#[tauri::command]` functions, managed state (`AppState`), and `withGlobalTauri` + `window.__TAURI__.core.invoke`, which is how the UI calls the backend without a JS bundler. Understand why every command uses `rename_all = "snake_case"`, and why the DTOs in `api.rs` must match `commands.rs` field for field.
- **Async Rust with Tokio.** Background tasks, `tokio::sync::Mutex` (needed because commands hold the lock across `.await`), and aborting tasks on logout.
- **Webview camera access.** `getUserMedia`, permission prompts on each platform, and WebKitGTK's opt-in on Linux. Also QR capacity: the contact code is about 111 characters of text, well within a medium-size QR code.

## 6. If targeting mobile

Tauri 2 can build for Android and iOS, but nobody has tried it yet. Here's what carries over from the original Android plan:

- **Keeping the app running in the background.** Android's Doze mode and OEM battery managers, Samsung in particular, throttle or kill background timers. A constant-rate tunnel or a keepalive loop on Android would need a foreground service with a persistent notification, and probably a battery-optimisation exemption. Learn how foreground services work (`startForeground`, `foregroundServiceType`) and what `START_STICKY` means.
- **Camera permission.** `CAMERA` must be declared in the manifest and requested at runtime. On iOS, `NSCameraUsageDescription` is required.
- **Cross-compiling.** Android ABIs (`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`) and the NDK. SQLCipher's vendored OpenSSL also has to cross-compile.
- **Threads and the UI.** Callbacks from Rust arrive on background threads. Whatever the UI layer is, only touch UI state from the main thread.

## 7. The relay server

- **Token routing tables:** a `HashMap` from routing token to address and session, plus time limits (TTLs) and periodic cleanup sweeps.
- **Offline queues:** a bounded `VecDeque` for each token, dropping the oldest when full. Think about limits per token vs limits for the whole server.
- **Denial of service:** reject bad traffic cheaply (unknown session ID, failed MAC) before allocating any memory.
- **Running it:** Docker volumes for the relay identity, EC2 security groups for UDP, and why logs matter for privacy ([deployment.md](deployment.md)).

## 8. Stretch goal: group chats

- **Sender keys (Signal).** One symmetric chain per sender, shared with each member over the existing 1-on-1 sessions. It's much cheaper than pairwise sessions for every message.
- **Fan-out at the relay.** One incoming packet tagged with a temporary group token is copied into every member's queue, which saves the sender's upstream bandwidth.

---

## Depth needed by role

| Area | UI lead | Crypto lead | Transport/FEC lead | Server lead |
|---|---|---|---|---|
| Crypto (§1) | Shallow: payload shapes and session states | Deep | Medium | Shallow |
| Secrets at rest (§2) | Medium | Deep | Shallow | Shallow |
| Networking (§3) | Medium | Medium | Deep | Deep |
| FEC / RaptorQ (§4) | Shallow: what "sent" vs "delivered" means | Shallow | Deep | Medium |
| Desktop stack (§5) | Deep | Medium | Medium | Shallow |
| Mobile (§6) | Deep, once mobile starts | Shallow | Medium: background timers | None |
| Relay (§7) | Shallow | Medium | Medium | Deep |
