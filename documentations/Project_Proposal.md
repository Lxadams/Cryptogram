# E2E-Messenger: Project Proposal and Technical Specifications

**Prepared For:** Stuart Inglis
**Project:** Compx374 Industry Project
**Date:** July 2026

> [!NOTE]
> *This document and its proposed architecture are subject to change as the project evolves.*

---

## 1. Executive Summary

E2E-Messenger is a secure, extreme-loss tolerant tactical messenger designed as a Proof of Concept (PoC) for rugged operational environments. The system abandons traditional messaging paradigms (such as WebSockets, TCP, or central identity servers) in favor of a decentralized, metronomic, and rateless UDP approach. Built with a high-performance **Rust cryptography and networking core** accessed via a **Mobile UI (Android/Kotlin)**, this project demonstrates approaches to metadata obfuscation, network reliability, and Post-Quantum cryptography.

The architecture is explicitly designed to survive hostile network conditions—including up to **95% packet loss** and Deep Packet Inspection (DPI) censorship firewalls—without leaking metadata about who is communicating or when.

## 2. Project Objectives & Scope

This proposal outlines a scoped-down, realistic Proof of Concept (MVP) for a four-person engineering team. 

**Core Objectives:**
1. **Extreme Loss Tolerance:** Ensure reliable messaging over raw UDP on port 443, tolerating 95% packet loss without standard ACK-based retransmissions.
2. **Metadata Obfuscation:** Prevent traffic analysis and DPI fingerprinting through a Constant-Rate Tunnel (CRT) sending packets metronomically every 100ms.
3. **Decentralized Identity:** Establish trust strictly in-person via QR codes, eliminating central identity servers.
4. **Post-Quantum Resilience:** Utilize a Hybrid Post-Quantum Handshake (ML-KEM / Kyber + X25519) for the initial session establishment to protect against "Harvest Now, Decrypt Later" threats.

**Scope Reductions for MVP:**
- Focus strictly on 1-on-1 messaging (Ephemeral Multicast Group Chats are a stretch goal).
- Utilize standard Android Encrypted Shared Preferences instead of hardware-specific Samsung Knox APIs.
- Substitute complex stateful QUIC transport with raw UDP, maximizing bandwidth efficiency over highly degraded links like SATCOM.
- Utilize a RAM-only relay server without Proof-of-Work or NVMe disk spilling.

---

## 3. Technical Architecture & Specifications

### 3.1 Initial Handshake & Trust Establishment

Trust is established completely out-of-band to guarantee identity integrity. Users do not register accounts. Instead, they physically scan a peer's QR code containing their Ed25519, X25519, and ML-KEM-768 public keys. 

Once scanned, both devices derive a **16-byte Unidirectional Routing Token** to direct traffic via the relay server without exposing their identities.

![Initial Handshake Bootstrap](diagrams/Initial%20Handshake%20Bootstrap.png)

### 3.2 Server Link Handshake (WireGuard-Lite)

Before end-to-end sessions are established, the client securely connects to the AWS Relay Server upon app boot. Instead of a vulnerable Pre-Shared Key (PSK), the client performs an ephemeral **X25519** key exchange with the server's hardcoded static public key. This "WireGuard-Lite" handshake establishes a unique Link Master Key and a 4-byte Session ID, securing the outer layer of all UDP packets with XChaCha20-Poly1305.

### 3.3 Hybrid Post-Quantum Key Exchange (PQXDH)

To bootstrap a session, the first message utilizes a Hybrid Post-Quantum Key Exchange:
1. The client generates a random secret and encapsulates it against the peer's public **ML-KEM-768 (Kyber)** key.
2. The client performs a standard **X25519** Diffie-Hellman exchange.
3. Both secrets are combined using a Hybrid Key Derivation Function (**HKDF-SHA256**) to produce an unbreakable Master Key.

![Cryptographic Chain](diagrams/Cryptographic%20Chain.png)

### 3.4 End-to-End Encryption (The Double Ratchet)

Subsequent messages are secured using the standard **X25519 Double Ratchet Algorithm**, ensuring Perfect Forward Secrecy (PFS) on a per-message basis. Every message is encrypted with a unique Message Key derived from the previous state via a one-way KDF. 

**Resilience against Out-of-Order and Lost Packets:**
If packets are delayed, dropped, or arrive out-of-order, the Double Ratchet handles this gracefully. Skipped message keys are safely derived and temporarily stored in a "skipped key dictionary," allowing delayed messages to be decrypted when they finally arrive. If a device is fully offline, the Relay Server buffers these messages in a RAM queue until the device reconnects. 
If a message is permanently lost (e.g., beyond RaptorQ recovery), the session does not break. The DH ratchet self-heals as soon as the next message arrives with a new ephemeral public key, allowing the users to continue communicating seamlessly. To prevent memory exhaustion from these permanently lost keys, the ratchet enforces a strict limit (`MAX_SKIP = 500`) and a 5-minute Time-To-Live (TTL) for uncollected keys.

To achieve ongoing quantum resilience without complex asynchronous PQ ratcheting, a "Blunt Force" Cryptographic Session Reset is triggered either manually or every 100 messages, completely re-keying the session with fresh Kyber math.

![Double Ratchet Flow](diagrams/Double%20Rachet.png)
![Double Ratchet 3x Flow](diagrams/Double%20Rachet%203x%20Flow.png)

### 3.5 Extreme Loss Tolerance (RaptorQ FEC)

Standard TCP networks rely on Acknowledgments (ACKs) and retransmissions, failing critically when loss exceeds 50%. Our architecture replaces this with **RaptorQ**, a Forward Error Correction (FEC) fountain code. Encrypted payloads are padded, sliced into mathematical symbols, and continuously streamed. Receivers perfectly reconstruct messages by collecting any sufficient subset of these symbols.

### 3.6 Traffic Obfuscation & Metronomic Tunnel

To prevent observers from knowing when users are communicating, the client establishes a Constant-Rate Tunnel (CRT).
- A Rust timer loop runs in an Android Foreground Service, emitting exactly one packet every **100ms** (10 pkts/sec).
- **Dummy Traffic vs Continuous RaptorQ Emission:** Originally, the architecture called for emitting cryptographically secure random bytes (Dummy Packets) when idle to maintain the constant rate. However, a more optimal approach is to continuously emit **redundant RaptorQ repair symbols** for the most recent messages during idle periods instead of random noise. Since RaptorQ symbols are already wrapped in XChaCha20 link encryption, they appear mathematically identical to random noise to an outside observer. This approach maintains perfect metadata obfuscation while vastly increasing the probability of message delivery under extreme loss, at zero additional bandwidth cost.
- Traffic is sent over raw UDP wrapped in an outer layer of **XChaCha20-Poly1305** Link Encryption.

![Regular Use](diagrams/Regular%20Use.png)
![UDP Structure](diagrams/UDP%20Structure.png)

### 3.7 The Blind Relay Server & Offline Routing

The backend is a highly concurrent, RAM-only blind router. It maintains zero knowledge of user identities or E2E keys. Clients prepend their 16-byte Routing Tokens to packets. The Relay maps these tokens to an active IP address or stores them in a RAM offline queue if the recipient is disconnected. Cryptographic demultiplexing on the client-side allows devices to identify the sender using purely one-way routing tokens.

![Offline Flow](diagrams/Offline%20Flow.png)

---

## 4. Threat Model

To provide rigorous security guarantees, the architecture assumes a specific, highly capable adversary.

**In-Scope Adversaries (Defended Against):**
- **Passive Network Observers (ISPs, Telcos):** Cannot read metadata, traffic timing, or packet sizes due to the constant-rate tunnel and XChaCha20 padding.
- **Active Censorship Firewalls (DPI):** Cannot fingerprint the protocol or rely on TCP state disruption (RST injection) because the transport is raw, connectionless UDP.
- **Malicious/Compromised Relay Servers:** The AWS server operates blindly. It only sees ephemeral link keys and 16-byte routing tokens, possessing zero cryptographic capability to decrypt payloads or map IPs to permanent identities.
- **"Harvest Now, Decrypt Later" State Actors:** The initial PQXDH key exchange protects the session master key against future quantum decryption.

**Out-of-Scope (Not Defended Against):**
- **Endpoint Compromise:** If the Android OS is rooted, infected with malware, or physically confiscated while unlocked, the encryption provides no protection.
- **Hardware Side-Channels:** Acoustic, thermal, or electromagnetic emission analysis on the physical device is out of scope.

## 5. Resource Overhead & 24/7 Battery Optimization

A strict 100ms Constant-Rate Tunnel requires the mobile cellular radio to remain in its highest power state continuously, which is unsustainable for 24/7 background operation (similar to WhatsApp). To balance extreme metadata obfuscation with real-world battery constraints, the architecture utilizes **Adaptive Metronome Scaling**.

- **Active Mode (100ms ticks):** When the app is open, or a chat is actively receiving/sending, the tunnel operates at maximum frequency. At ~1KB per packet, this consumes ~10KB/s bandwidth, ensuring instant RaptorQ delivery and perfect metadata masking during conversations.
- **Standby Mode (5-second ticks):** When the app is backgrounded and idle for more than 3 minutes, the metronome scales down to a 5-second heartbeat. This precise interval allows modern LTE/5G cellular radios to drop into **Connected-DRX (Discontinuous Reception)** low-power states, drastically reducing battery drain while keeping the Relay Server offline queue synced.
- **Metadata Mitigation:** The 5-second polling interval means a new incoming message may be delayed by up to 5 seconds when asleep. Furthermore, the transition from Standby to Active mode leaks a minor metadata signal ("this user just became active"). To mitigate this, the client generates artificial Active Mode bursts periodically throughout the day—even when no messages are being sent—confusing traffic analyzers attempting to correlate wake-ups with actual human communication.

---

## 6. Specific Implementations & Division of Labor

The 4-person engineering team is divided into specialized roles to tackle the Rust-Kotlin boundary, post-quantum cryptography, and network operations.

### 6.1 Mobile UI & FFI Lead (Student 1)
- **Role:** Handles the Kotlin app, QR code CameraX integration, Android Foreground Services, and the Rust-to-Kotlin Foreign Function Interface (FFI).
- **Core Challenge:** Managing threading across the FFI boundary. The Rust metronome (`tokio`) runs independently of Android's main thread, necessitating strict `uniffi-rs` callback marshaling to safely update the UI (e.g., `StateFlow`) without crashing the view hierarchy.
- **Service Lifecycle:** Maintaining a resilient Foreground Service to prevent Android Doze mode from killing the 100ms Rust metronome.

### 6.2 Post-Quantum Crypto Lead (Logan)
- **Role:** Builds local key generation, Hybrid PQ Handshake, HKDF derivation, and the X25519 Double Ratchet.
- **Core Challenge:** Hardening the Double Ratchet against UDP loss (memory bounds) and implementing the "Blunt Force" Cryptographic Session Reset for PQ healing.

### 6.3 Transport & FEC Lead (Student 3)
- **Role:** Integrates the RaptorQ symbol encoding/decoding, Rust 100ms metronome, Dummy packet generation, and UDP reassembly.
- **Core Challenge:** Ensuring the 100ms tick remains constant and seamlessly wrapping/unwrapping RaptorQ symbols within XChaCha20 link encryption.

### 6.4 Server Lead (Student 4)
- **Role:** Develops the AWS Relay's asynchronous UDP routing dictionary and offline queues using `tokio` in Rust.
- **Core Challenge:** Implementing stateless DoS protection and ensuring rapid `HashMap` token lookups without memory allocation bottlenecks.

---

## 7. Project Roadmap

**Phase 1: Rust Core Bootstrapping & QR Exchange**
- Setup Android native and Rust cross-compilation toolchains.
- Define `uniffi-rs` interfaces and generate keypairs.
- Integrate CameraX for QR scanning and derive Shared Routing Tokens.

**Phase 2: Network Metronome & Double Ratchet**
- Implement the Double Ratchet state machine with UDP loss mitigations.
- Build the 100ms `tokio` metronome and XChaCha20 Link Handshake.
- Wrap the Rust core in an Android Foreground Service resilient to Doze mode.

**Phase 3: The Blind Relay Server**
- Deploy the asynchronous AWS Relay for UDP routing.
- Implement token-based RAM queuing for offline users.
- Wire offline queue sync into the client app lifecycle.

**Phase 4: Integration & Extreme Loss Testing**
- Connect the full pipeline: Input → Ratchet → RaptorQ → Metronome.
- Implement the "Session Reset" for PQ healing.
- Rehearse the live demo under simulated 90% artificial packet loss (e.g., via `tc netem`).

**Phase 5 (Stretch Goal): Ephemeral Multicast Group Chats**
- Distribute "Sender Keys" over established 1-on-1 ratchets.
- Inject `MULTICAST_BIND` control packets to route dynamic group fanouts via the Blind Relay.

---

## 8. Known Weaknesses & MVP Compromises

Given the constraints of the project timeframe, specific production features have been compromised:
- **Session Reset vs Asynchronous PQ Ratcheting:** Full PQ integration into the ratcheting engine is out-of-scope. Instead, the session resets entirely to establish fresh Kyber keys.
- **Multicast Bind Spoofing:** In the stretch goal, without Zero-Knowledge Proofs, an attacker guessing a group's Routing Token could potentially inject fake bind commands.

## 9. Conclusion

E2E-Messenger provides a pragmatic, forward-looking implementation of secure communication under extreme duress. By successfully combining Post-Quantum handshakes, Forward Error Correction, and rigorous metadata obfuscation into a cohesive Mobile-Rust architecture, this MVP will demonstrate a robust tactical messaging paradigm built for hostile environments.
