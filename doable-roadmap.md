# E2E Messenger: Realistic Mobile MVP Roadmap (University Project Scope)

This document outlines a scoped-down, realistic Proof of Concept (PoC) roadmap suitable for a 4-person university engineering team completing a single-semester (12-16 week) final project. 

The goal of this roadmap is to prove the core, novel concepts of the architecture—Extreme Loss Tolerance, Metadata Obfuscation, QR-based identity, and **Post-Quantum Key Exchange**—while aggressively cutting the most complex production-level requirements (HTTP/3 Evasion, Samsung Knox Hardware bindings, and asynchronous PQ ratcheting) to make it achievable in Rust on mobile.

---

## 1. Scope Reductions (What We Cut)

*   **Cryptography (Simplified PQ):** Cut ML-DSA (Dilithium) signatures and the complex Asynchronous PQ Session Healing. **Target:** Use standard Ed25519 for identity signatures, but implement a **Hybrid Post-Quantum Handshake** using ML-KEM (Kyber) alongside X25519 strictly for the initial session establishment. The active Double Ratchet will remain purely classical (X25519).
*   **Networking:** Cut HTTP/3 (QUIC) encapsulation. **Target:** Send raw custom UDP datagrams over the network.
*   **Hardware APIs:** Cut Samsung Knox/TE integration. **Target:** Store the SQLite database and keys in standard Android Encrypted Shared Preferences or SQLCipher.
*   **Server Hardening:** Cut Proof-of-Work (PoW) and NVMe disk spilling. **Target:** A simple RAM-only relay that queues and routes packets based on tokens.
*   **Features:** Cut Group Chats (Ephemeral Multicast). **Target:** Strict 1-on-1 messaging.

---

## 2. Core MVP Architecture (Mobile + Rust + Simplified PQ)

The MVP will demonstrate a Mobile-to-Mobile messenger built with a Rust core, routing blindly through a cloud server. 

### A. The Mobile Client (Alice & Bob)
*   **Language & Stack:** 
    *   **Core Engine:** Rust (handles all crypto, RaptorQ, and networking). 
    *   **UI:** Kotlin (Android) or React Native.
    *   **Bridge:** Use Mozilla's `uniffi-rs` or `jni` to generate bindings.
*   **Key Exchange (QR Codes):** Users generate Ed25519/X25519 public keys and display them as a QR code using a standard Android library. Scanning the QR code establishes the long-term identity trust and shared rendezvous token.
*   **Hybrid PQ Session Bootstrapping:** The very first handshake message utilizes a Rust crate like `pqcrypto-kyber` to encapsulate an ML-KEM secret against the peer's public key. This secret is fed into the HKDF alongside the X25519 secrets to seed the initial Double Ratchet.
*   **E2E Encryption:** Basic X25519 Double Ratchet for ongoing messages (ignoring PQ session healing).
*   **Transport (RaptorQ):** Use a Rust FEC crate (e.g., `raptorq`) to slice encrypted messages into redundant symbols.
*   **The Metronome:** A background Rust thread running a `sleep(100ms)` loop. **Crucial Android Note:** The app *must* run as an Android "Foreground Service" with a persistent sticky notification to prevent Doze mode from killing the timer.

### B. The Server (Relay)
*   **Language:** Rust (`tokio`) or Go.
*   **Function:** A lightweight UDP server. Maintains a `HashMap` in memory linking `Routing Tokens` to `IP:Port` combinations or Offline Queues.
*   **Logic:** When a UDP packet arrives, the server reads the 16-byte token and either forwards it to the active IP or queues it in RAM.

---

## 3. Implementation Phases (12-Week Schedule)

### Phase 1: Rust Core, QR Integration, & PQ Bootstrapping (Weeks 1-4)
*   **Task 1.1 (Rust Crypto):** Build the local key generation functions (Ed25519 + X25519 + ML-KEM-768). Implement the Hybrid KDF that combines the classical DH and the Kyber KEM.
*   **Task 1.2 (Rust FEC):** Integrate the RaptorQ crate. Prove that you can take a buffer, split it into symbols, drop half, and successfully reassemble.
*   **Task 1.3 (Mobile UI):** Set up the Android app and `uniffi` bindings to call the Rust crypto library.
*   **Task 1.4 (Mobile UI):** Implement the Camera/QR scanner in Android to exchange the public Ed25519/X25519 keys.

### Phase 2: The Network Metronome & Double Ratchet (Weeks 5-7)
*   **Task 2.1 (Rust Crypto):** Implement the standard X25519 Double Ratchet state machine, seeded by the Master Key generated in Phase 1.
*   **Task 2.2 (Rust Transport):** Build the 100ms `tokio` metronome thread in the Rust core, emitting Dummy packets when idle.
*   **Task 2.3 (Mobile UI):** Wrap the Rust metronome execution in an Android **Foreground Service**. 

### Phase 3: The Blind Relay Server (Weeks 8-9)
*   **Task 3.1 (Server):** Build a basic asynchronous UDP server in Rust (`tokio`) or Go on AWS.
*   **Task 3.2 (Server):** Implement the RAM-only Routing Table and Offline Queuing logic.
*   **Task 3.3 (Rust Core):** Implement a fetch request in the client to ask the server for queued offline packets upon opening the app.

### Phase 4: Integration & Extreme Loss Testing (Weeks 10-12)
*   **Task 4.1 (Mobile UI):** Connect the Chat UI to the Rust backend (Type -> Ratchet Encrypt -> RaptorQ slice -> Metronome Transmit).
*   **Task 4.2 (Mobile UI):** Polish the UX from QR scanning to chat window.
*   **Task 4.3 (The Big Demo):** Demo two phones establishing a Hybrid Post-Quantum session and sending messages to each other over a network that is artificially dropping 90% of UDP packets.

---

## 4. Division of Labor (Suggested for 4 People)

*   **Student 1 (Mobile UI & FFI Lead):** Focuses on the Kotlin app, QR code camera integration, the `uniffi` bridge, and Android Foreground Services.
*   **Student 2 (Post-Quantum Crypto Lead):** Focuses on the Hybrid PQ Handshake (ML-KEM + X25519), HKDF derivation, and the X25519 Double Ratchet.
*   **Student 3 (Transport & FEC Lead):** Focuses on the RaptorQ symbol encoding/decoding, the Rust 100ms metronome, Dummy packet generation, and UDP reassembly.
*   **Student 4 (Server Lead):** Focuses on the AWS Relay, building the asynchronous UDP routing dictionary and offline queues.

## 5. Why This is the Right Balance

By keeping ML-KEM strictly in the initial handshake, you get to claim **"Post-Quantum Initial Key Exchange"** on your graduation resumes (which is highly sought after right now). However, by dropping the ML-DSA signatures and asynchronous PQ ratcheting, you avoid the nightmare of transmitting massive cryptographic structures continuously over a 95% loss UDP stream, making the project highly achievable.
