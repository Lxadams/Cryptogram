# E2E-Messenger
**Compx374 Industry Project** 

## Project Overview

E2E-Messenger is a highly secure, extreme-loss tolerant tactical messenger designed as a Proof of Concept (PoC) for rugged operational environments. Built with a high-performance **Rust cryptography and networking core** accessed via a **Mobile UI (Android/Kotlin)**, this project demonstrates novel approaches to metadata obfuscation, network reliability without TCP, and Post-Quantum cryptography.

The architecture is explicitly designed to survive hostile network conditions, including **95% packet loss** and Deep Packet Inspection (DPI) censorship firewalls, without leaking metadata about who is communicating or when.

For the full implementation schedule, see the [doable-roadmap.md](doable-roadmap.md).

---

## How It Works: The Core Mechanics

Our architecture abandons traditional messaging paradigms (like WebSockets, TCP, or central identity servers) in favor of a decentralized, metronomic, and rateless UDP approach. Here is how the components interact:

### 1. Identity & Trust (QR Codes)
Users do not register accounts, usernames, or phone numbers. Trust is established completely out-of-band by physically scanning a QR code on a peer's device. This QR code contains the peer's public identity keys and establishes a shared "rendezvous token" used for routing.

### 2. Hybrid Post-Quantum Key Exchange (PQXDH)
To protect against future quantum computers harvesting encrypted data today ("Harvest Now, Decrypt Later"), the very first session handshake combines standard elliptic curve Diffie-Hellman (**X25519**) with the NIST-standardized Post-Quantum Key Encapsulation Mechanism, **ML-KEM-768 (Kyber)**. These secrets are merged using a Hybrid Key Derivation Function (HKDF) to establish an unbreakable Master Key. Ongoing sessions are kept secure against quantum threats via a "Blunt Force" Cryptographic Session Reset (triggered automatically every 100 messages or manually), which completely re-keys the session with fresh Kyber math.

### 3. End-to-End Encryption (The Double Ratchet)
Once the Master Key is established, ongoing messages are secured using the standard **X25519 Double Ratchet Algorithm**. This ensures *Perfect Forward Secrecy* on a strictly **per-message** basis. The keys are not rotated by time (e.g., day-by-day); instead, every single message is encrypted with a unique Message Key dynamically calculated from the previous message's key via a one-way Key Derivation Function (KDF). To prevent memory exhaustion under 95% packet loss, the ratchet is hardened with a strict `MAX_SKIP` limit and a 5-minute Time-To-Live (TTL) for uncollected skipped keys. Once a message is decrypted (or its key expires), that specific key is permanently destroyed.

### 4. Extreme Loss Tolerance (RaptorQ FEC)
Tactical networks (like jammed radios) drop packets constantly. Standard TCP networks rely on "ACKs" (acknowledgments) to trigger retransmissions, which fails completely if loss exceeds 50%.
Instead, our Rust core uses **RaptorQ**, a Forward Error Correction (FEC) fountain code. The messenger pads the encrypted text, slices it into mathematical symbols, and continuously streams redundant repair symbols. The receiver can perfectly reconstruct the message by collecting *any* subset of those symbols, eliminating the need for ACKs entirely.

### 5. Traffic Obfuscation (The Metronomic Tunnel)
To prevent a passive observer from knowing *when* you are talking or *how much* you are saying, the app establishes a **Constant-Rate Tunnel (CRT)**.
- A Rust timer loop runs in an Android Foreground Service, firing exactly one packet every **100ms** (10 pkts/sec).
- If the user isn't typing, the client generates cryptographically secure random bytes (Dummy Packets) and sends them anyway.
- For extreme deployment conditions (SATCOM, degraded 2G/3G), these packets are sent as **pure, raw UDP datagrams** (over port 443) wrapped in an outer layer of **XChaCha20-Poly1305** Link Encryption (secured statelessly via an ephemeral X25519 handshake against the server's pinned public key). This provides maximum bandwidth efficiency and reliability by eliminating connection handshakes and congestion control overhead, which would otherwise cripple performance under 95% packet loss.

### 6. The Blind Relay Server
The backend is a highly concurrent, RAM-only cloud server. It acts purely as a dumb router.
- It has zero knowledge of User IDs, passwords, or persistent accounts.
- Clients calculate ephemeral, 16-byte **Routing Tokens** and attach them to the front of their packets.
- When the Relay receives a packet, it reads the 16-byte token and immediately routes it to the IP address currently registered to that token, or stores it in a temporary offline RAM queue if the recipient is asleep. It employs strict stateless DoS protection, instantly dropping invalid tokens without memory allocation.

### 7. Stretch Goal: Ephemeral Multicast Group Chats
While the core architecture focuses on strict 1-on-1 privacy, the project includes a stretch goal to implement Ephemeral Multicast Group Chats. This involves generating "Signal Sender Keys" and securely distributing them over the 1-on-1 channels, allowing the server to dynamically fan-out a single message stream to multiple recipients simultaneously without knowing the group's persistent topology.

---

### Project Documentation
*   [Realistic Implementation Roadmap](doable-roadmap.md)
*   [Hybrid Crypto Rust Demo](hybrid_crypto_demo.rs)
*   [Original Master Architecture](ROADMAP.md)
*   [Prerequisite Learning Guide](LEARNING.md)
