# E2E-Messenger: Protocol Flow Diagrams

This document illustrates the core operational flows of the E2E-Messenger architecture as **currently implemented in the codebase**. It covers the initial physical and cryptographic handshake, active messaging using the Symmetric Hash Ratchet and PQ Injections, and the offline queuing mechanism.

## 1. Initial Handshake & Session Bootstrapping

Trust is established out-of-band: both people scan each other's QR code. The Deferred Key Exchange then swaps the large keys over the relay, and a Hybrid Post-Quantum Key Exchange establishes a Master Key. Each side only takes in a KeyExchange from someone it added itself, checked against the key it scanned; one from anyone else is dropped and listed as a connection request. The contact with the lower routing token is the *establisher* and sends the SessionEstablish. The *responder* confirms it with a KeyExchange naming the session, and only then does the establisher use it. Below, Bob's token is the lower.

```mermaid
sequenceDiagram
    participant A as Alice
    participant B as Bob
    participant S as Relay Server

    Note over A, B: Phase 1: Physical Trust Exchange, both ways
    A->>A: Generate Identity, Token, DH, & ML-KEM Keys
    B->>B: Generate Identity, Token, DH, & ML-KEM Keys
    B-->>A: Alice scans Bob's QR Code (Routing Token + Ed25519 PubKey)
    A-->>B: Bob scans Alice's QR Code (Routing Token + Ed25519 PubKey)
    Note over A, B: Each has added the other, with the key they scanned.

    Note over B, S: Phase 2: Server Link Handshake (both clients)
    B->>S: Link Handshake (Eph X25519 Pub, padded)
    S->>S: DH, a link key per direction, pick a Session ID
    S->>B: Session ID + Eph X25519 Pub + Server Ed25519 Sig
    B->>S: Sync (signed by Bob's token key, proves he owns his Routing Token)
    S->>B: Sync Ack

    Note over A, B: Phase 3: Deferred Key Exchange & Session Boot (Bob establishes)
    B->>B: Sign KeyExchangePayload (0x02)
    B->>S: Encrypted 0x02 to Alice's Routing Token
    S->>A: Forward Packet
    A->>A: Bob is a contact she added. Verify his Sig against the key she scanned
    A->>A: Sign KeyExchange (has Bob's keys, asks for a session)
    A->>S: Encrypted 0x02 to Bob's Routing Token
    S->>B: Forward Packet
    B->>B: Alice is a contact he added. Verify her Sig against the key he scanned
    B->>B: Encapsulate ML-KEM + DH Handshake
    B->>B: Sign SessionEstablishPayload (0x04)
    B->>S: Encrypted 0x04 to Alice's Routing Token
    S->>A: Forward Packet
    A->>A: Verify Sig, Decapsulate ML-KEM & DH
    A->>A: Sign KeyExchange naming the session (confirms it)
    A->>S: Encrypted 0x02 to Bob's Routing Token
    S->>B: Forward Packet
    Note over A, B: Derives identical Session Master Key! Secure E2E Session Established once Bob has the confirmation.
```

## 2. Active Messaging & PQ Ratcheting

This diagram illustrates the active messaging flow. Instead of a double ratchet, the current MVP uses a Bidirectional Symmetric Hash Ratchet, utilizing `SenderToken` for $O(1)$ lookups, and injecting fresh Post-Quantum entropy every 5 ratchet steps. A message travels as a paced burst of sealed `0x07` RaptorQ symbols, sized to survive 70% loss. When a PQ inject is due, it rides inside the same burst as the message, not as a packet of its own, so the two arrive together or not at all. The relay keeps each packet until the recipient acks it. The sender's ✓ comes from the relay's receipts, not from the recipient.

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Relay Server
    participant B as Bob

    Note over A, B: Secure E2E Session Established

    Note over A: Alice sends a message
    A->>A: Pad & chunk, Symmetric Hash Ratchet (Advance send_chain_key per chunk)
    A->>A: Encrypt each chunk with XChaCha20-Poly1305 (Message Key) as 0x01
    opt Every 5th ratchet step, after the message's last chunk
        A->>A: Encapsulate new secret against Bob's ML-KEM Key
        A->>A: Mix new PQ Secret into send_chain_key via HKDF
        A->>A: Sign PQInjectPayload (0x05), bundled with the message
    end
    A->>A: RaptorQ-encode the bundle, seal each symbol as 0x07
    A->>S: Paced burst of link-encrypted 0x07 symbols, 10 ms apart
    S->>S: Queue each packet for Bob's Routing Token
    S->>B: Forward each packet
    B->>S: Ack (Delivery IDs)
    Note over S: A packet not acked is resent with backoff
    A->>S: Receipt request
    S->>A: Receipt (which of the burst's packets are queued)
    Note over A: ✓ once enough of the burst is at the relay to rebuild it

    B->>B: Open the seals, rebuild the bundle from enough symbols
    B->>B: Lookup session via SenderToken in O(1) time
    B->>B: Symmetric Hash Ratchet (Advance recv_chain_key), Decrypt chunks
    B->>B: Permanently Destroy Message Keys (Forward Secrecy)
    B->>B: Verify PQ inject Sig, Decapsulate ML-KEM, mix into recv_chain_key at applies_at
    Note over A, B: Chain Keys perfectly synchronized with refreshed Post-Quantum Secrecy!
```

### Recovering a Lost PQ Inject

If a burst carrying an inject is lost altogether, nothing after it decrypts. The receiver parks those messages and asks for the inject again with a signed `0x08` request; the sender keeps its latest 20 injects per session for this. A request signed on an older session (sent before a repair) is ignored. An inject older than the latest 20 can't be sent again: the session needs **Repair session**, which sets up a new one and keeps the contact and the chat history.

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Relay Server
    participant B as Bob

    Note over A, B: The burst carrying a PQ inject never arrives
    A->>S: Bursts of later messages
    S->>B: Forward
    B->>B: Can't decrypt yet, park them (up to 100, for 7 days)
    Note over B: After 3 s, then twice as long each time, up to every 30 s
    B->>S: Signed 0x08 request (from, through), 3 copies
    S->>A: Forward
    A->>A: Verify on this session, forget kept injects Bob already has
    A->>S: The kept 0x05 injects he's missing, bare, 3 copies each
    S->>B: Forward
    B->>B: Mix them in, parked messages decrypt
```

## 3. Offline Queuing & Retrieval

This diagram shows how the RAM-only relay handles disconnected users. Because the server maps Routing Tokens directly to the address each one has proven it's at, with a RAM queue behind it, it holds messages for offline peers without any persistent storage or user accounts. Every forwarded packet waits in the queue until the recipient acks it: up to 2 MiB per recipient for its contacts' packets (new ones refused once full) and 64 KiB for everyone else's, for up to 7 days. Unacked packets are resent with backoff, and at once (paced 5 ms apart) when the recipient syncs from a new address or link, or after more than 30 seconds of silence.

```mermaid
sequenceDiagram
    participant A as Alice (Offline)
    participant S as Relay Server
    participant B as Bob (Online)

    Note over A: Alice's phone dies or loses service.

    B->>S: UDP Packet [Encrypted Message for Alice]
    Note over S: Server decrypts Link layer, reads target Routing Token.
    S->>S: Queue packet in RAM for Alice's Token (contacts' packets up to 2 MiB)
    S--xA: Send to Alice's last address (lost)
    Note over S: Resent after 2 s, 4 s, 8 s, up to 60 s apart, until acked

    B->>S: UDP Packet [Encrypted Message for Alice]
    S->>S: Queue packet in RAM for Alice's Token

    Note over A: Alice reconnects (App opens, new address)
    A->>S: Link Handshake & Sync
    Note over S: Sync from a new address, so resend the queue at once, 5 ms apart
    S->>A: Queued UDP Packet 1
    S->>A: Queued UDP Packet 2
    A->>S: Ack (Delivery IDs)
    S->>S: Drop acked packets from the queue

    A->>A: Reassemble & Decrypt
```
## 4. High-Level Topology (The 10,000-Foot View)

This diagram shows the broad network layout. It highlights that the server is completely untrusted and has no persistent database, while all sensitive cryptographic keys and session states remain strictly isolated on the local devices. Each device runs the Cryptogram app: a Leptos UI in a Tauri shell, on desktop or Android.

```mermaid
graph TD
    subgraph Client A [Alice's Device]
        AppA["Cryptogram app (Tauri, desktop or Android)"]
        StorageA[(Encrypted Keys & History)]
        AppA --> StorageA
    end

    subgraph Server [Relay Server]
        direction TB
        Relay[Blind UDP Router]
        RAM[(Volatile RAM Queue)]
        Relay --- RAM
    end

    subgraph Client B [Bob's Device]
        AppB["Cryptogram app (Tauri, desktop or Android)"]
        StorageB[(Encrypted Keys & History)]
        AppB --> StorageB
    end

    AppA <==>|Link Encrypted UDP| Relay
    Relay <==>|Link Encrypted UDP| AppB
    
    AppA -.->|Out-of-Band QR Scan, each way| AppB
```

## 5. Component & Data Flow (The Tech Stack)

This diagram illustrates the internal architecture of the Cryptogram app. It shows how the Leptos WebAssembly frontend communicates with the Rust core via Tauri's IPC bridge, and how the cryptographic engine manages the UDP network state. State is kept in two SQLCipher databases, one for the identity and its sessions and one for the chat history, both keyed from the passcode. It's the same on Android, where the Tauri shell runs the same Rust backend behind the same webview UI.

```mermaid
graph TD
    subgraph App [Cryptogram App - Tauri on desktop or Android]
        
        subgraph Frontend [Webview]
            Leptos[Leptos UI / WASM]
        end

        subgraph Backend [Rust Core]
            TauriAPI[Tauri IPC Handlers]
            LibRS[lib.rs Cryptographic Core]
            Crypto[ML-KEM & XChaCha20 Engine]
            Net[UDP Socket Manager]
            Storage[("SQLCipher databases: identity state, chat history")]
        end
        
        Leptos <-->|JSON Commands| TauriAPI
        TauriAPI <--> LibRS
        LibRS <--> Crypto
        LibRS <--> Storage
        LibRS <--> Net
        
    end
    
    Net <-->|Raw UDP Packets| WAN((Internet / Relay))
```
