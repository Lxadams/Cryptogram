# E2E Messenger: Learning Curriculum

This is the technical study guide for the system as it was built (`main`, commit `52b49d8`, 20 October 2026). It started as the guide to the MVP plan in [doable-roadmap.md](doable-roadmap.md); where the built design differs from that plan, each section says so. The project spans Rust systems programming, a Leptos UI in a Tauri shell, error correction and cryptography, so this guide explains *what* you need to understand to work on it.

For how the pieces fit together, read [Logan-info.md](Logan-info.md) (a message's path, byte by byte), [Frontend-UI-info.md](Frontend-UI-info.md) (the app) and [doable-cryptographic-flow.md](doable-cryptographic-flow.md) (the crypto flow). What comes next is in [stage-3-roadmap.md](stage-3-roadmap.md).

---

## 1. Hybrid Cryptography & Key Exchange (Logan's Focus)

### Ed25519 & X25519
*   **Ed25519**: A digital signature algorithm used for long-term identity. Every KeyExchange, SessionEstablish, PQ inject and PQ inject request is signed with it. Your contact code (the QR code) carries your Ed25519 key, so whoever scans it can check everything you sign.
*   **X25519**: Elliptic Curve Diffie-Hellman. Allows two parties to combine their private keys with each other's public keys to arrive at a shared secret.

Each identity holds an Ed25519, an X25519 and an ML-KEM-768 key pair, plus a separate Ed25519 *token key* whose hash is the routing token (see §6).

### ML-KEM & Key Encapsulation
Post-quantum algorithms don't work like Diffie-Hellman. **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203; formerly Kyber) has one party generate a random secret and "encapsulate" it into a ciphertext using the other party's public key. The second party decapsulates it. The app uses ML-KEM-768 from `libcrux-ml-kem`, behind `client/src/pq.rs`.
*   **Learning Requirement**: Understand the KEM API flow (`KeyGen`, `Encapsulate`, `Decapsulate`).

### Hybrid Key Derivation (HKDF)
Because post-quantum algorithms are new, standards bodies recommend **hybrid cryptography**: combine them with a classical algorithm, so the result is only broken if both are.
*   **What's built**: The contact with the lower routing token sets up the session. It makes a fresh X25519 key, does a DH with the other side's X25519 key, encapsulates a fresh ML-KEM secret to their ML-KEM key, and sends both in a signed SessionEstablish (`0x04`). Each side runs **HKDF-SHA256** over the two shared secrets (info `"pqxdh-root-key"`) to get the session's **root key**.
*   **Learning Requirement**: Understand how to safely combine several shared secrets with HKDF. If a quantum computer breaks ML-KEM, the X25519 secret still protects the key, and the other way round.

---

## 2. The Ratchet: a Symmetric Hash Ratchet with PQ Refreshes (Logan's Focus)

The messaging engine that gives each message its own key. The plan was a Signal Double Ratchet; what's built is simpler (`SymmetricSessionState` in `client/src/lib.rs`).

*   **Per-message keys**: Each chain step derives a message key, `HMAC-SHA256(chain, "message-key")`, and the next chain key, `HMAC-SHA256(chain, "chain-key")`. One step per chunk of a message. Old chain keys are thrown away, so someone who steals today's state can't read yesterday's messages (forward secrecy). Each chunk is encrypted with XChaCha20-Poly1305 and a random 24-byte nonce.
*   **Sequence numbers**: Every chunk (`0x01`) carries an 8-byte `seq_no`, the sender's position in its chain.
*   **Out of order (the skip dictionary)**: UDP loses and reorders packets. When a chunk arrives ahead of the receive chain, the receiver steps forward to it and stores the keys it skipped in `skip_dict`, so the earlier chunks can still be decrypted when they turn up.
    *   **Memory bounds**: At most 100 steps ahead, and at most 500 stored keys, with the oldest dropped first. There is no time limit on a stored key.
    *   **Duplicates**: A chunk behind the chain with no stored key has already been read (or its key was dropped), and is ignored.
*   **PQ refreshes**: Every 5 ratchet steps (checked once per message), the sender encapsulates a fresh ML-KEM secret to the peer's long-term ML-KEM key, mixes it into its send chain with HKDF, and sends a signed **PQ inject** (`0x05`).
    *   **A signed position**: The inject names the position it applies at (`applies_at`), and the receiver mixes it in at exactly that point. Up to 32 can wait for their position.
    *   **It travels with its message**: The inject rides in the same FEC object as the message that triggered it, with a stronger failure target (1 in a million, against 1 in 10,000 for a message), as losing one stalls the chain.
    *   **Parked messages**: Messages that need an inject that hasn't arrived are parked (at most 100 per contact, for 7 days, saved with the session) and decrypted once it lands.
*   **Recovering a lost refresh**: The sender keeps its latest 20 signed injects. A receiver holding parked messages sends a signed **PQ inject request** (`0x08`) for the positions it's missing: after 3 s, then 6 s, 12 s and 24 s, then every 30 s. The sender resends those injects. Both sides need the current build.
*   **Repair session**: For anything else, such as a refresh older than the latest 20, the chat's ⋮ menu has **Repair session** (`repair <token>` in the CLI). It drops the session and sets up a fresh one, PQ keys and all, keeping the contact, their name and the chat history. It replaced the plan's "blunt force" session reset.

### Background: the Signal Double Ratchet
*   **Diffie-Hellman ratcheting**: The Double Ratchet sends a new ephemeral X25519 key as the conversation goes back and forth, and each new DH result moves the root chain on. Someone who steals today's keys loses access as soon as new keys are exchanged. That is **post-compromise security**.
*   **What the built design lacks**: PQ refreshes are encrypted to the peer's *long-term* ML-KEM key, so whoever steals that key can read every later refresh too. The hash ratchet gives forward secrecy, not post-compromise security. A ratchet that brings in fresh X25519 and ML-KEM keys is the planned fix (Stage 3 item 3.1).
*   **Learning Requirement**: Understand the difference between forward secrecy and post-compromise security, and which one each design gives.
*   **Known gaps**: Both directions' chains start from the same root key, and the `0x01` header isn't authenticated with its ciphertext (review C-1). The end-to-end seal around every chat symbol (`0x07`) covers for both for now. See [implementation-review.md](implementation-review.md).

---

## 3. Forward Error Correction & RaptorQ (Student 3)

Getting messages through heavy loss without waiting for end-to-end acknowledgments. The plan said 95% loss; the built system is designed and tested for **70% loss each way**.
*   **Erasure codes vs. ARQ**: Understand why reactive retransmission (waiting for an ACK from the other phone) fails under heavy loss. At 70% loss each way, a packet and its ACK both get through only 9% of the time.
*   **Rateless fountain codes (RaptorQ)**: Understand how RaptorQ takes a message sliced into $K$ source symbols and generates as many repair symbols as needed. A receiver rebuilds the message from almost *any* $K$ symbols, whichever packets were dropped. It's in `code/fec`.
*   **Sizing a burst**: Each message is sent as one burst, sized from the loss it's designed for and a target failure rate (`fec::packets_for`). A one-chunk message is 34 packets of 1024-byte symbols, or 55 with a PQ inject.
*   **Burst sending**: Symbols go out 10 ms apart (`BurstSender`), so a short spike of jamming only takes a few of them.
*   **What is acknowledged**: There are no end-to-end ACKs, but each hop has its own:
    *   **Relay to recipient**: The relay keeps each packet until the recipient acks it, resending after 2 s, 4 s, and so on up to 60 s apart.
    *   **Sender to relay**: The sender asks the relay which of its packets arrived, and shows **✓** once the relay has enough of them. The ✓ means "the relay has it", not "delivered".

---

## 4. Networking & Obfuscation (Student 3)

*   **Raw UDP, not QUIC**: QUIC was cut from the plan. The client opens a raw `tokio::net::UdpSocket` to the relay, on UDP port 443 in production. Port 443 makes the traffic look like QUIC at a glance, but it isn't QUIC: this is a weak disguise, so don't oversell it. A QUIC transport is parked on the `Logan/QUIC+CRT+Disguise` branch.
*   **Hop-by-hop link encryption**: Understand why every packet between phone and relay is wrapped in a second layer of encryption. Without it, anyone on the path could read the recipient's routing token and the FEC headers, which would identify the app as a messenger.
    *   **The handshake**: The client sends an ephemeral X25519 key. The relay answers with its own ephemeral key and a session ID it picks, signed with its Ed25519 key. The app only accepts the relay key it was set up with (the pinned key). HKDF over the DH result gives one key for each direction.
    *   **Every packet after it**: ChaCha20-Poly1305 (not XChaCha20-Poly1305 as planned: the packet number is the nonce, so no random 24-byte nonce is needed). The header (type, session ID, packet number) is authenticated too, and a replay window refuses any packet number seen before.
*   **Constant-rate tunnels (planned, not built)**: Understand traffic analysis. Today each message goes out as a burst, so anyone watching a link can see when and how much someone sends. The relay can make dummy packets, but nothing sends them yet.
    *   **The plan** (Stage 3 Phase 1): After the handshake, each end sends fixed-size cells on a random clock, waiting a random, exponentially distributed gap after each one, rather than exactly every 100 ms. An idle cell is all padding, so a busy link looks the same as a quiet one.
    *   **The cost**: About 417 MB a day each way at 4 cells a second. The original 100 ms clock would be about 1 GB. See the rate profiles in [stage-3-roadmap.md](stage-3-roadmap.md#rate-profiles).

---

## 5. The App: Leptos, Tauri and Android (Student 1)

The plan was a Kotlin Android app bridged to the Rust core with Mozilla's `uniffi-rs`. What's built is a **Leptos** UI (Rust compiled to WebAssembly) inside a **Tauri** shell, the same code on desktop and Android. The reasoning is in [tech-decision-leptos-client.md](tech-decision-leptos-client.md).
*   **Tauri commands as the bridge**: The WASM in the webview can't open sockets or files. It draws screens and calls named Tauri commands (24 of them) through `window.__TAURI__.core.invoke`, with JSON arguments and results. The native side owns the one `Client`, its UDP socket and three background loops: receive, a 500 ms tick and a 15 s keepalive. Nothing is pushed to the UI: it polls once a second. See [Frontend-UI-info.md](Frontend-UI-info.md#2-the-bridge-apirs--commandsrs).
*   **Android foreground service**: Android freezes or kills apps in the background to save battery. While someone is logged in, `MessageService` runs as a foreground service with an ongoing "Connected" notification, so Android keeps the process and its UDP socket alive. It runs no timer, as there's no metronome. In deep sleep Android may still pause the network; the relay holds messages until the phone wakes.
*   **Rust to Kotlin**: A Kotlin thread in `NativeBridge` blocks in the JNI call `nextEvent()` and hears from Rust when someone logs in or out, or a message arrives. It posts each event to the main thread, since only the main thread may touch the UI.
*   **QR code trust**: The contact code is `CG2:` followed by Base45 of the routing token (16 bytes) and the Ed25519 key (32 bytes): 72 characters, a 29×29 QR code. Both people add each other, usually by scanning each other's code (**Manual add** takes the same two values). The X25519 and ML-KEM keys come later, in a KeyExchange signed with the scanned key.
    *   **Drawing and scanning in the WASM**: The QR code is drawn with `qrcode`, and the scanner uses `getUserMedia` and `rqrr`, so there's no native scanner plugin.
    *   **An optional device scanner**: The webview's `BarcodeDetector` (Google's ML Kit on Android) can be turned on, but is off by default.

The Android build and its background behaviour are in [../code/frontend/ANDROID.md](../code/frontend/ANDROID.md).

---

## 6. The Blind Relay Server (Student 4)

The relay (`code/server`, on AWS EC2) routes messages without being able to read them.
*   **Token-based routing**: The server has no user IDs. A routing token is 16 bytes, the hash of the client's Ed25519 *token key*, not a random number. To claim its token, the client sends a **sync** signed by that key and bound to its link's keys. The relay then maps the token to that link and address, so only the token's owner can collect its packets. The client sends 3 syncs every 15 s, which keeps the mapping and its NAT open.
*   **Offline queuing**: Packets for a token wait in RAM, each with a 16-byte delivery ID, for up to 7 days. The relay resends each one until the recipient acks it.
    *   **No fetch request**: When the recipient syncs from a new address or link, or after more than 30 s of silence, the relay resends everything queued for it at once.
    *   **Nothing on disk**: The relay keeps no message on disk, and core dumps are off.
*   **Admission tags**: Contacts share an 8-byte tag derived from their two X25519 keys. Each client lists its contacts' tags in its sync (up to 64), and a sender attaches the tag to what it sends. Tagged packets share a 2 MiB queue per recipient. Everything else, such as contact requests from strangers, shares a 64 KiB queue that drops its oldest packets first, so strangers can't fill your queue.
*   **Bounded tables**: At most 100,000 links and 100,000 recipients' tags. Handshakes are rate-limited per address: a burst of 20, then one a second.
*   **What the server can see**: It never decrypts message content. It does see routing tokens, the sender's token on each chat symbol, the contents of contact requests (names and keys), and when and how much each link sends. Stage 3 plans fixes for each (items 2.1, 2.6 and Phase 1).

---

## 7. Stretch Goal: Ephemeral Multicast Group Chats

Not started. Group chats are still a stretch goal, and the Stage 3 roadmap defers them (it would look at MLS, RFC 9420). If the team gets to them, these are the ideas to understand for group chats over 1-on-1 channels:
*   **Signal Sender Keys**: Instead of a separate ratchet session per member of a group, a sender generates a single symmetric key and distributes it to group members over their existing 1-on-1 sessions.
*   **Server Fanout**: The server takes a single incoming datagram tagged with a "Multicast Token" and copies it into the queues of every recipient, saving the sender a lot of bandwidth.
