# E2E-Messenger: Project Proposal and Technical Specifications

**Prepared For:** Stuart Inglis
**Project:** Compx374 Industry Project
**Date:** July 2026

> [!NOTE]
> *This document and its proposed architecture are subject to change as the project evolves.*

---

## 1. Executive Summary

E2E-Messenger is a secure messaging Proof of Concept (PoC) designed for highly unreliable networks. It uses a decentralized, constant-rate UDP approach built with Rust and an Android UI. The project demonstrates metadata obfuscation, network reliability, and post-quantum cryptography.

The architecture is designed to function even with up to 95% packet loss and censorship firewalls, without leaking metadata about the users or their communication patterns.

## 2. Project Objectives & Scope

This proposal outlines a realistic Minimum Viable Product (MVP) for a four-person team. 

**Core Objectives:**
1. **Loss Tolerance:** Ensure reliable messaging over UDP, tolerating 95% packet loss without standard acknowledgment (ACK) based retransmissions.
2. **Metadata Obfuscation:** Prevent traffic analysis by sending packets at a constant rate.
3. **Decentralized Identity:** Establish trust in-person via QR codes, eliminating central servers.
4. **Post-Quantum Resilience:** Use a hybrid post-quantum handshake (ML-KEM / X25519) to protect against future decryption threats.

<<<<<<< HEAD
**MVP Scope:**
- 1-on-1 messaging only.
- Use standard Android Encrypted Shared Preferences.
- Use raw UDP transport for maximum bandwidth efficiency.
- Use a RAM-only relay server without permanent storage.
=======
**Scope Reductions for MVP:**
- Focus strictly on 1-on-1 messaging (Ephemeral Multicast Group Chats are a stretch goal).
- Utilize standard Android Encrypted Shared Preferences instead of hardware-specific Samsung Knox APIs.
- Substitute complex stateful QUIC transport with raw UDP, maximizing bandwidth efficiency over highly degraded links like SATCOM.
- Utilize a RAM-only relay server.
>>>>>>> acc30a9ba4920e7a6c80ec692d8e7d7df852bb5c

---

## 3. Technical Architecture & Specifications

### 3.1 Trust Establishment

Trust is established in-person. Users do not register accounts. Instead, they scan a peer's QR code containing their public keys. Both devices then derive a 16-byte Routing Token to direct traffic via the relay server without exposing their identities.

![Initial Handshake Bootstrap](diagrams/Initial%20Handshake%20Bootstrap.png)

### 3.2 Server Link Handshake

When the app starts, the client connects to the AWS Relay Server. It performs an X25519 key exchange with the server's static public key. This establishes a Link Master Key, securing all UDP packets with an outer layer of encryption (XChaCha20-Poly1305).

### 3.3 Post-Quantum Key Exchange

The first message uses a hybrid key exchange:
1. The client generates a random secret using the peer's ML-KEM-768 public key.
2. The client performs an X25519 Diffie-Hellman exchange.
3. Both secrets are combined using a Key Derivation Function to produce a Master Key.

![Cryptographic Chain](diagrams/Cryptographic%20Chain.png)

### 3.4 End-to-End Encryption

Subsequent messages use the X25519 Double Ratchet algorithm for Perfect Forward Secrecy. 

**Handling Packet Loss:**
If packets are lost or out of order, skipped keys are derived and stored temporarily, allowing delayed messages to be decrypted later. The Relay Server buffers messages for offline devices. If a message is permanently lost, the ratchet self-heals when the next message arrives. Uncollected keys are limited to 500 and expire after 5 minutes.

To maintain quantum resilience, a session reset is triggered manually or every 100 messages, establishing fresh keys.

![Double Ratchet Flow](diagrams/Double%20Rachet.png)
![Double Ratchet 3x Flow](diagrams/Double%20Rachet%203x%20Flow.png)

### 3.5 Loss Tolerance (Forward Error Correction)

Standard TCP fails when packet loss is high. Instead, we use RaptorQ Forward Error Correction (FEC). Encrypted messages are split into redundant symbols and continuously streamed. Receivers can reconstruct the message once they collect enough symbols, without needing to request retransmissions.

### 3.6 Traffic Obfuscation

To hide communication patterns, the client sends traffic at a constant rate.
- A background service sends exactly one packet every 100ms.
- **Continuous Data Emission:** During idle periods, the client continuously sends redundant RaptorQ symbols for the most recent messages instead of random noise. This appears as random noise to observers while increasing the chance of message delivery under heavy loss.
- Traffic is sent over raw UDP with link encryption.

![Regular Use](diagrams/Regular%20Use.png)
![UDP Structure](diagrams/UDP%20Structure.png)

### 3.7 The Blind Relay Server

<<<<<<< HEAD
The backend is a RAM-only router with no knowledge of user identities or encryption keys. Clients prepend their Routing Tokens to packets. The Relay maps these tokens to an IP address or stores them in a RAM queue if the recipient is offline. 
=======
The backend is a single instance, RAM-only blind router. It maintains zero knowledge of user identities or E2E keys. Clients prepend their 16-byte Routing Tokens to packets. The Relay maps these tokens to an IP address during an initial sync request, then stores forward requests in a queue to be sent repeatedly. Cryptographic demultiplexing on the client-side allows devices to identify the sender using purely one-way routing tokens.
>>>>>>> acc30a9ba4920e7a6c80ec692d8e7d7df852bb5c

![Offline Flow](diagrams/Offline%20Flow.png)

---

## 4. Threat Model

**Defended Against:**
- **Passive Network Observers:** Cannot read metadata or traffic timing due to the constant-rate tunnel.
- **Active Censorship Firewalls:** Cannot fingerprint the protocol due to raw UDP transport.
- **Compromised Relay Servers:** The server only sees link keys and routing tokens; it cannot decrypt payloads or identify users.
- **State Actors:** The initial key exchange protects against future quantum decryption.

**Not Defended Against:**
- **Endpoint Compromise:** Compromised OS, malware, or unlocked physical access.
- **Hardware Side-Channels:** Physical device emission analysis.

<<<<<<< HEAD
## 5. Battery Optimization & Metadata Leaks
=======
**Out-of-Scope (Not Defended Against):**
- **Endpoint Compromise:** If the Android OS is rooted, infected with malware, or physically confiscated while unlocked, the encryption provides no protection.
- **Hardware Side-Channels:** Acoustic, thermal, or electromagnetic emission analysis on the physical device is out of scope.
- **Malicious ISP**: Since packets are not routed through the Tor network, the ISP can still observe the source IP addresses and associate them with users.
>>>>>>> acc30a9ba4920e7a6c80ec692d8e7d7df852bb5c

A strict 100ms constant-rate tunnel drains the battery, making 24/7 background operation impractical. To balance privacy with battery life, we use two modes:

- **Active Mode (100ms interval):** Used when the app is open. It consumes ~10KB/s bandwidth, ensuring fast message delivery.
- **Standby Mode (5-second interval):** Used when the app is in the background. This allows the cellular radio to enter low-power states, saving battery.

**Addressing the Metadata Tradeoff:**
Using Standby Mode permanently is not an option because real-time chatting would be unacceptably slow (taking seconds to deliver a single message). However, switching to Active Mode only when communicating leaks metadata, revealing to an attacker when a user is chatting. 

To prevent this, the client periodically generates fake Active Mode bursts throughout the day when idle. This makes it impossible for an observer to distinguish real conversations from automated background bursts.

---

## 6. Division of Labor

The 4-person engineering team is divided into specialized roles.

<<<<<<< HEAD
### 6.1 Mobile UI & FFI Lead (Student 1)
- **Role:** Handles the Kotlin Android app, QR code integration, and the Rust-to-Kotlin interface.
- **Challenge:** Managing threading between Rust and Android to safely update the UI, and maintaining a resilient background service.
=======
### 6.1 Mobile UI & FFI Lead (Rowan)
- **Role:** Handles the Kotlin app, QR code CameraX integration, Android Foreground Services, and the Rust-to-Kotlin Foreign Function Interface (FFI).
- **Core Challenge:** Managing threading across the FFI boundary. The Rust metronome (`tokio`) runs independently of Android's main thread, necessitating strict `uniffi-rs` callback marshaling to safely update the UI (e.g., `StateFlow`) without crashing the view hierarchy.
- **Service Lifecycle:** Maintaining a resilient Foreground Service to prevent Android Doze mode from killing the 100ms Rust metronome.
>>>>>>> acc30a9ba4920e7a6c80ec692d8e7d7df852bb5c

### 6.2 Post-Quantum Crypto Lead (Logan)
- **Role:** Builds key generation, the hybrid handshake, and the Double Ratchet.
- **Challenge:** Handling packet loss in the Double Ratchet and implementing the session reset.

<<<<<<< HEAD
### 6.3 Transport & FEC Lead (Student 3)
- **Role:** Integrates RaptorQ encoding, the constant-rate tunnel, and UDP packet management.
- **Challenge:** Maintaining the constant sending rate and wrapping symbols in link encryption.

### 6.4 Server Lead (Student 4)
- **Role:** Develops the AWS Relay's UDP routing and offline queues in Rust.
- **Challenge:** Implementing DoS protection and ensuring fast token lookups.
=======
### 6.3 Transport & FEC Lead (Cameron)
- **Role:** Integrates the RaptorQ symbol encoding/decoding, Rust 100ms metronome, Dummy packet generation, and UDP reassembly.
- **Core Challenge:** Ensuring the 100ms tick remains constant and seamlessly wrapping/unwrapping RaptorQ symbols within XChaCha20 link encryption.

### 6.4 Server Lead (Khang)
- **Role:** Develops the AWS Relay's asynchronous UDP routing dictionary and offline queues using `tokio` in Rust.
- **Core Challenge:** Implementing stateless DoS protection and ensuring rapid `HashMap` token lookups without memory allocation bottlenecks.
>>>>>>> acc30a9ba4920e7a6c80ec692d8e7d7df852bb5c

---

## 7. Project Roadmap
**Phase 1: The Blind Relay Server**
- Handle incoming sync and forward requests
- Manage metadata and outbound message queue
- Broadcast packets to all known clients

<<<<<<< HEAD
**Phase 1: Core Bootstrapping & QR Exchange**
- Setup Android and Rust toolchains.
- Define interfaces and generate keypairs.
- Integrate QR scanning and derive Routing Tokens.

**Phase 2: Network & Double Ratchet**
- Implement the Double Ratchet with loss mitigations.
- Build the constant-rate tunnel and Link Handshake.
- Wrap the Rust core in an Android background service.

**Phase 3: Relay Server**
- Deploy the AWS Relay for UDP routing.
- Implement RAM queuing for offline users.
- Wire offline queue sync into the client app.

**Phase 4: Integration & Testing**
- Connect the full pipeline.
- Implement the session reset.
- Test under simulated 90% packet loss.
=======
**Phase 2: Rust Core Bootstrapping & QR Exchange**
- Setup Android native and Rust cross-compilation toolchains.
- Define `uniffi-rs` interfaces and generate keypairs.
- Integrate CameraX for QR scanning and derive Shared Routing Tokens.

**Phase 3: Network Metronome & Double Ratchet**
- Implement the Double Ratchet state machine with UDP loss mitigations.
- Build the 100ms `tokio` metronome and XChaCha20 Link Handshake.
- Wrap the Rust core in an Android Foreground Service resilient to Doze mode.

**Phase 4: Integration & Extreme Loss Testing**
- Connect the full pipeline: Input → Ratchet → RaptorQ → Metronome.
- Implement the "Session Reset" for PQ healing.
- Rehearse the live demo under simulated 90% artificial packet loss (e.g., via `tc netem`).
>>>>>>> acc30a9ba4920e7a6c80ec692d8e7d7df852bb5c

**Phase 5 (Stretch Goal): Group Chats**
- Distribute sender keys over established 1-on-1 ratchets.
- Route dynamic group messages via the Relay.

---

## 8. Known Weaknesses

- **Session Reset vs Asynchronous Ratcheting:** Full post-quantum integration into the ratcheting engine is out of scope. Instead, the session resets entirely to establish new keys.
- **Multicast Spoofing:** In the stretch goal, an attacker guessing a group's Routing Token could potentially inject fake bind commands.

## 9. Conclusion

E2E-Messenger provides a pragmatic implementation of secure communication under extreme network conditions. By combining post-quantum handshakes, Forward Error Correction, and constant-rate traffic into a Mobile-Rust architecture, this MVP demonstrates a robust messaging paradigm for hostile environments.
