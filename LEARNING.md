# E2E Messenger: MVP Learning Curriculum

This document serves as the technical study guide for implementing the MVP architecture defined in `doable-roadmap.md`. Because this project spans Rust systems programming, Mobile UI integration (FFI), advanced error correction, and cryptography, this guide explains *what* your team needs to understand to build the system successfully.

---

## 1. Hybrid Cryptography & Key Exchange (Logan's Focus)

### Ed25519 & X25519
*   **Ed25519**: A digital signature algorithm used for long-term identity. You use this to sign your keys so the other person knows it's really you.
*   **X25519**: Elliptic Curve Diffie-Hellman. Allows two parties to combine their private keys with each other's public keys to mathematically arrive at a shared secret.

### ML-KEM (Kyber) & Key Encapsulation
Post-Quantum algorithms do not work like Diffie-Hellman. **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism) requires one party to generate a random secret and "encapsulate" it into a ciphertext using the other party's public key. The second party decapsulates it. 
*   **Learning Requirement**: Understand the KEM API flow (`KeyGen`, `Encapsulate`, `Decapsulate`).

### Hybrid Key Derivation (HKDF)
Because post-quantum algorithms are novel, the NSA and industry standards mandate **Hybrid Cryptography**. 
*   **Learning Requirement**: Understand how to safely cascade multiple shared secrets. You must combine the classical X25519 secret and the ML-KEM secret using **HKDF-SHA256** (HMAC-based Extract-and-Expand Key Derivation Function) to produce a Master Key. If a quantum computer breaks ML-KEM in the future, your X25519 math still protects the key.

---

## 2. The Signal Double Ratchet Algorithm (Logan's Focus)

The core messaging engine that provides Perfect Forward Secrecy (PFS).
*   **Per-Message Symmetric Ratcheting**: Understand how Key Derivation Functions (KDFs) advance forward on *every single message*. A new Message Key is derived dynamically from the previous state, ensuring an attacker who steals today's key cannot read yesterday's messages.
*   **Diffie-Hellman Ratcheting**: Understand how sending a new ephemeral X25519 public key occasionally forces the root chain to rotate, guaranteeing that if an attacker steals today's key, they lose access as soon as you exchange new DH keys.
*   **Out-of-Order Execution**: UDP guarantees packet loss and reordering. You must understand how the Double Ratchet handles skipped messages (storing derived message keys in a dictionary for future late arrivals).

---

## 3. Forward Error Correction & RaptorQ (Student 3)

Tolerating 95% packet loss without Acknowledgment (ACK) packets requires completely abandoning standard TCP/ARQ logic.
*   **Erasure Codes vs. ARQ**: Understand why reactive retransmission (waiting for an ACK) completely fails when round-trip loss is 95%.
*   **Rateless Fountain Codes (RaptorQ)**: Understand how RaptorQ can take a file (or ciphertext) sliced into $K$ source symbols and generate a nearly infinite stream of mathematical repair symbols. A receiver can successfully reconstruct the entire original message by collecting *any* subset of symbols, regardless of which specific packets were dropped.

---

## 4. Networking & Obfuscation (Student 3)

*   **QUIC Datagrams (RFC 9221)**: You will be using a Rust crate like `quinn`. QUIC is HTTP/3. It runs over UDP but looks like standard HTTPS web traffic to Deep Packet Inspection (DPI) firewalls. You will use the "Unreliable Datagrams" feature of QUIC so packets aren't artificially held back by the library.
*   **Constant-Rate Tunnels (CRT)**: Understand traffic analysis. To hide metadata (who is talking and when), your app must fire a packet every 100ms exactly. If the user isn't typing, you send a Dummy Packet filled with cryptographic noise.
*   **Hop-by-Hop Link Encryption**: Understand why wrapping the outer payload in XChaCha20-Poly1305 is necessary. It ensures the DPI firewall cannot look inside your QUIC packets and see the RaptorQ headers, which would identify your app as a messenger.

---

## 5. Mobile & Rust FFI Integration (Student 1)

*   **Foreign Function Interfaces (FFI)**: You cannot easily write UDP sockets or RaptorQ math in standard Kotlin without massive performance hits. You must learn how to bridge a Rust Core library to an Android UI. Look deeply into **Mozilla's `uniffi-rs`**, which automatically generates the Kotlin bindings for your Rust code.
*   **Android Foreground Services**: Modern mobile operating systems (like Android Doze mode) will aggressively kill any background threads trying to fire a timer every 100ms to save battery. You must learn how to implement an Android Foreground Service with a persistent, sticky notification to tell the OS "Do not kill my Rust metronome."
*   **QR Code Trust**: Understand how to generate QR codes locally in Android that contain the Rust-generated public keys, and how to pass a scanned string back into Rust.

---

## 6. The Blind Relay Server (Student 4)

The AWS Relay must route messages without knowing who is talking, what they are saying, or when they are saying it.
*   **Token-Based Routing**: The server does not use User IDs. Understand how to use a basic `HashMap` in Rust/Go to map a 16-byte incoming Routing Token to a specific IP address and Port.
*   **Offline Queuing**: If a token isn't currently active (the user's app is closed), understand how to append the incoming packets to an array in RAM (`Vec` or slice) so the user can query and download them when they come back online.
*   **Zero-Knowledge Architecture**: Embrace the concept that the server is "dumb." It only sees encrypted noise and 16-byte tokens. It never decrypts the payload.

---

## 7. Stretch Goal: Ephemeral Multicast Group Chats

If your team reaches Phase 5, you will need to understand the cryptographic and networking extensions required for group chats over 1-on-1 channels.
*   **Signal Sender Keys**: Instead of doing a complex Double Ratchet for every member of a group, learn how a sender generates a single Symmetric Key and distributes it to group members via their existing 1-on-1 channels.
*   **Server Fanout**: Understand how the server can take a single incoming QUIC datagram tagged with a "Multicast Token" and physically duplicate it into the egress queues of multiple recipients, saving the sender massive amounts of bandwidth.
