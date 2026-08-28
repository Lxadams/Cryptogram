# E2E-Messenger: Protocol Flow Diagrams

This document illustrates the core operational flows of the E2E-Messenger architecture as **currently implemented in the codebase**. It covers the initial physical and cryptographic handshake, active messaging using the Symmetric Hash Ratchet and PQ Injections, and the offline queuing mechanism.

## 1. Initial Handshake & Session Bootstrapping

This diagram shows how trust is established out-of-band via a Micro-QR code, followed by the Deferred Key Exchange which utilizes a Hybrid Post-Quantum Key Exchange to establish a Master Key.

```mermaid
sequenceDiagram
    participant A as Alice
    participant B as Bob
    participant S as Relay Server

    Note over A, B: Phase 1: Physical Trust Exchange
    A->>A: Generate Identity, DH, & Kyber Keys
    A->>B: Display QR Code (Routing Token + Ed25519 PubKey)
    B-->>A: Scan QR Code (Out-of-band)
    Note over A, B: Identity Trusted. 

    Note over B, S: Phase 2: Server Link Handshake
    B->>S: Link Handshake (Eph X25519 Pub + Ed25519 Sig)
    S->>S: Verify Client Signature & DH
    S->>B: Session ID + Server Ed25519 Sig (Mutual Auth)

    Note over A, B: Phase 3: Deferred Key Exchange & Session Boot
    B->>B: Sign KeyExchangePayload
    B->>S: Encrypted 0x02 to Alice's Routing Token
    S->>A: Forward Packet
    A->>A: Verify Bob's Sig against QR Code!
    A->>A: Sign KeyExchange Response
    A->>S: Encrypted 0x02 to Bob's Routing Token
    S->>B: Forward Packet
    B->>B: Verify Sig, TOFU Accept
    B->>B: Encapsulate Kyber + DH Handshake
    B->>B: Sign SessionEstablishPayload (0x04)
    B->>S: Encrypted 0x04 to Alice's Routing Token
    S->>A: Forward Packet
    A->>A: Decapsulate Kyber & DH
    Note over A, B: Derives identical Session Master Key! Secure E2E Session Established.
```

## 2. Active Messaging & PQ Ratcheting

This diagram illustrates the active messaging flow. Instead of a complex double ratchet, the current MVP uses a highly concurrent Bidirectional Symmetric Hash Ratchet, utilizing `SenderToken` for $O(1)$ lookups, and injecting fresh Post-Quantum entropy every 5 messages.

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Relay Server
    participant B as Bob

    Note over A, B: Secure E2E Session Established

    Note over A: Alice sends a message
    A->>A: Symmetric Hash Ratchet (Advance send_chain_key)
    A->>A: Encrypt Msg with XChaCha20-Poly1305 (Message Key)
    A->>S: Link-Encrypted [0x01 | SenderToken | SeqNo | Ciphertext]
    
    S->>B: Server forwards based on Target Routing Token
    
    B->>B: Lookup session via SenderToken in O(1) time
    B->>B: Symmetric Hash Ratchet (Advance recv_chain_key)
    B->>B: Decrypt Message
    B->>B: Permanently Destroy Message Key (Forward Secrecy)

    Note over A, B: After 5 messages, PQ Injection occurs
    A->>A: Encapsulate new secret against Bob's Kyber Key
    A->>A: Mix new PQ Secret into send_chain_key via HKDF
    A->>A: Sign PQInjectPayload
    A->>S: Link-Encrypted [0x05 | PQInjectPayload]
    S->>B: Forwards Packet
    B->>B: Verify Sig, Decapsulate Kyber
    B->>B: Mix new PQ Secret into recv_chain_key via HKDF
    Note over A, B: Chain Keys perfectly synchronized with refreshed Post-Quantum Secrecy!
```

## 3. Offline Queuing & Retrieval

This diagram shows how the stateless relay handles disconnected users. Because the server maps Routing Tokens directly to active IPs or RAM queues, it securely stores messages for offline peers without any persistent storage or user accounts.

```mermaid
sequenceDiagram
    participant A as Alice (Offline)
    participant S as Relay Server
    participant B as Bob (Online)

    Note over A: Alice's phone dies or loses service.
    
    B->>S: UDP Packet [Encrypted Message for Alice]
    Note over S: Server decrypts Link layer, reads target Routing Token.<br/>Alice's IP is not currently active.
    S->>S: Store packet in RAM Offline Queue for Token (Max 50)
    
    B->>S: UDP Packet [Encrypted Message for Alice]
    S->>S: Store packet in RAM Offline Queue for Token
    
    Note over A: Alice reconnects (App opens and binds IP)
    A->>S: Link Handshake & Initial Sync
    
    Note over S: Server flushes Token's RAM Queue
    S->>A: Queued UDP Packet 1
    S->>A: Queued UDP Packet 2
    
    A->>A: Reassemble & Decrypt
```
## 4. High-Level Topology (The 10,000-Foot View)

This diagram shows the broad network layout. It highlights that the server is completely untrusted and has no persistent database, while all sensitive cryptographic keys and session states remain strictly isolated on the local devices.

```mermaid
graph TD
    subgraph Client A [Alice's Device]
        AppA[Tauri Desktop App]
        StorageA[(Local Storage & Keys)]
        AppA --> StorageA
    end

    subgraph Server [Relay Server]
        direction TB
        Relay[Blind UDP Router]
        RAM[(Volatile RAM Queue)]
        Relay --- RAM
    end

    subgraph Client B [Bob's Device]
        AppB[Tauri Desktop App]
        StorageB[(Local Storage & Keys)]
        AppB --> StorageB
    end

    AppA <==>|Link Encrypted UDP| Relay
    Relay <==>|Link Encrypted UDP| AppB
    
    AppA -.->|Out-of-Band Micro-QR Scan| AppB
```

## 5. Component & Data Flow (The Tech Stack)

This diagram illustrates the internal architecture of the desktop client. It shows how the Leptos WebAssembly frontend communicates with the Rust core via Tauri's IPC bridge, and how the cryptographic engine manages the UDP network state.

```mermaid
graph TD
    subgraph Desktop Client [Tauri Application]
        
        subgraph Frontend [Webview]
            Leptos[Leptos UI / WASM]
        end

        subgraph Backend [Rust Core]
            TauriAPI[Tauri IPC Handlers]
            LibRS[lib.rs Cryptographic Core]
            Crypto[Kyber & XChaCha20 Engine]
            Net[UDP Socket Manager]
            Storage[(Local JSON State)]
        end
        
        Leptos <-->|JSON Commands| TauriAPI
        TauriAPI <--> LibRS
        LibRS <--> Crypto
        LibRS <--> Storage
        LibRS <--> Net
        
    end
    
    Net <-->|Raw UDP Packets| WAN((Internet / Relay))
```
