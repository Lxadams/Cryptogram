# E2E-Messenger: Protocol Flow Diagrams

This document illustrates the core operational flows of the E2E-Messenger architecture. It covers the initial physical and cryptographic handshake, the ongoing metronomic communication, and the offline queuing mechanism.

## 1. Initial Handshake & Session Bootstrapping

This diagram shows how trust is established out-of-band via QR code, followed by the first message that utilizes the Hybrid Post-Quantum Key Exchange to establish a Master Key.

```mermaid
sequenceDiagram
    participant A as Alice
    participant B as Bob
    participant S as Relay Server

    Note over A, B: Phase 1: Physical Trust Exchange
    A->>A: Generate Identity and DH Keys
    A->>B: Display QR Code
    B-->>A: Scan QR Code (Out-of-band)
    Note over A, B: Identity Trusted. Shared Routing Token derived.

    Note over B: Phase 2: Hybrid PQ Handshake
    B->>B: Generate Kyber Secret for Alice
    B->>B: Perform standard X25519 DH Exchange
    B->>B: HKDF(Kyber + X25519) = Session Master Key
    
    Note over B, S: Phase 3: Server Link Handshake (App Boot)
    B->>S: Link Handshake (Ephemeral X25519 PubKey)
    S->>B: 4-byte Session ID (Link Key Established)

    B->>B: Encrypt Msg 1 & Handshake with Master Key
    B->>B: Slice via RaptorQ & Apply XChaCha20 Link Encryption
    
    Note over B: 100ms Metronome Foreground Service Starts
    B->>S: UDP Packet (Session ID + Encrypted Payload)
    Note over S: Reads Session ID to find Link Key, decrypts to find Token.
    S->>A: Forwards Raw UDP Packet
    
    A->>A: Decrypt Link Encryption
    A->>A: Reassemble RaptorQ Symbols
    A->>A: Decrypt Kyber & DH Handshake
    A->>A: Derive identical Session Master Key
    Note over A, B: Secure Quantum-Resilient Session Established
```

## 2. Messaging Back & Forth (The Metronomic Tunnel)

This diagram illustrates the constant-rate tunnel. Packets are fired continuously every 100ms, effectively masking when real messages are being sent. It also shows how RaptorQ handles packet loss without requiring a traditional network "ACK".

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Relay Server
    participant B as Bob

    Note over A, B: Both clients running 100ms Metronome Timer
    
    Note over A, B: Scenario A: Idle (No users typing)
    A->>S: UDP Dummy (Session ID + Encrypted Noise)
    S->>B: Forwarded blindly
    B->>S: UDP Dummy (Session ID + Encrypted Noise)
    S->>A: Forwarded blindly
    Note over A, B: To an observer, the link looks like a constant static stream.

    Note over A, B: Scenario B: Alice sends a real message
    A->>A: Encrypt Msg via X25519 Double Ratchet (Unique Key)
    A->>A: Slice into 3 Redundant Symbols (RaptorQ)
    A->>S: Metronome Tick 1: UDP Packet (Session ID + Symbol 1)
    A->>S: Metronome Tick 2: UDP Packet (Session ID + Symbol 2)
    A->>S: Metronome Tick 3: UDP Packet (Session ID + Symbol 3)
    
    S->>B: Forwards Packet 1
    S-xB: Packet 2 DROPPED (Network Loss)
    S->>B: Forwards Packet 3
    
    B->>B: Reassemble message from any received subset (1 and 3)
    B->>B: Decrypt via Double Ratchet
    B->>B: Permanently Destroy Message Key (PFS)
    Note over A, B: No ACKs are sent or required. Seamless recovery.
```

## 3. Offline Queuing & Retrieval

This diagram shows how the stateless relay handles disconnected users. Because the server only maps Routing Tokens to IPs or RAM queues, it doesn't need to manage user accounts to buffer messages.

```mermaid
sequenceDiagram
    participant A as Alice (Offline)
    participant S as Relay Server
    participant B as Bob (Online)

    Note over A: Alice's phone dies or loses service.
    
    Note over B, S: Bob's Metronome continues firing at 100ms
    B->>S: UDP Packet (Session ID + Encrypted Dummy/Message)
    Note over S: Decrypts via Session ID, reads Token. Alice's IP not active.
    S->>S: Store packet in RAM Offline Queue for Token
    
    B->>S: UDP Packet (Session ID + Encrypted Dummy/Message)
    S->>S: Store packet in RAM Offline Queue for Token
    
    Note over A: Alice reconnects (App opens and binds IP)
    A->>S: Initial Sync: Fetch Queued Packets for Token
    
    Note over S: Server flushes Token's RAM Queue
    S->>A: Queued UDP Packet 1
    S->>A: Queued UDP Packet 2
    S->>A: Queued UDP Packet N
    
    A->>A: Reassemble & Decrypt
    A->>S: Alice's Metronome resumes (100ms ticks)
    S->>B: Forwarded Packet
```

You have identified the exact edge-cases that make blind routing tricky! To make this work securely without the server confusing the IPs, and without Alice getting Bob and Paul's messages mixed up, the system relies on Unidirectional Inbox Tokens and Cryptographic Demultiplexing.

Here is exactly how both of those problems are solved:

1. How does the server get the routing IDs without confusing Alice and Bob?
While the QR code scan establishes a "Shared Secret" between Alice and Bob, they do not actually use a single shared token to route traffic (otherwise, as you noted, the server wouldn't know which IP is the sender and which is the receiver).

Instead, they take that Shared Secret and feed it into a Key Derivation Function (KDF) to deterministically generate Two Unidirectional Routing Tokens:

Token A (Alice's Inbox): Used only for messages traveling from Bob to Alice.
Token B (Bob's Inbox): Used only for messages traveling from Alice to Bob.
How the Server routes:

Registration: Every 100ms, Alice's metronome sends a tiny "Keep-Alive" control packet to the Server. She puts Token A on the front of this packet. The Server reads it and updates its HashMap: Token A -> Alice's IP.
(Bob does the exact same thing with Token B, so the server maps Token B -> Bob's IP).
Sending a Message: When Bob wants to send a message to Alice, his app prepends Token A to the message packets.
The Server receives Bob's message, looks up Token A in the HashMap, and instantly forwards it to Alice's IP.
Because the tokens are strictly one-way (unidirectional), the Server never gets confused about whose IP belongs to which token.

2. How does Alice know a message is from Bob and not Paul?
This is solved by the fact that the Routing Tokens are strictly pairwise (unique to every specific conversation).

When Alice scans Bob's QR code, they generate Token A (Bob → Alice).
When Alice scans Paul's QR code, they generate a completely different shared secret, resulting in Token C (Paul → Alice).
The Demultiplexing Process (How Alice's App sorts it out): When a raw UDP packet arrives at Alice's phone, her app looks at the 16-byte Routing Token on the front of the packet.

If the packet has Token A, her app knows immediately: "This is from Bob. I need to use Bob's XChaCha20 link key to decrypt the outer layer, and Bob's Double Ratchet state to decrypt the message."
If the packet has Token C, her app knows: "This is from Paul. I must use Paul's keys."
If the packet has an unknown Token that Alice's app doesn't recognize, it is instantly dropped as cryptographic noise.
This concept is called Cryptographic Demultiplexing. Because Alice manages a unique "Inbox Token" for every single person she talks to, her app always knows exactly who sent the packet and which cryptographic keys are required to unlock it, all without the Server ever knowing who "Token A" or "Token C" belong to!