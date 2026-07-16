# E2E UDP Messenger: Implementation Roadmap

Rust implementation of an end-to-end encrypted messenger over UDP, with a later obfuscation layer for traffic correlation evasion. Sections marked as open decisions list tradeoffs rather than a single recommended path.

## Stack

Fixed:
- Language: Rust
- Async runtime: tokio
- Handshake framework: snow (Noise Protocol Framework)
- Fuzzing: cargo-fuzz
- Static analysis: clippy, cargo audit

Open, see Phase 0:
- Noise pattern (XX or IK)
- Identity key scheme (X25519 static key alone, or X25519 plus a separate Ed25519 signing key)
- AEAD cipher (ChaCha20-Poly1305 or AES-256-GCM)

---

## Phase 0: Design Decisions

These affect later phases. Listed as tradeoffs to decide before Phase 1 starts.

**Key distribution model**
- TOFU with manual fingerprint verification: no pre-shared setup, vulnerable to MITM until the fingerprint is verified out of band.
- Pre-shared / out-of-band contact exchange: stronger guarantee from first contact, requires an out-of-band channel before messaging starts.

**Noise pattern**
- Noise_XX: works for first contact with no prior key knowledge. 3-message handshake, 1.5 RTT. Both static keys are transmitted during the handshake, encrypted.
- Noise_IK: requires knowing the peer's static key ahead of time, tied to the key distribution model above. 2-message handshake, 1 RTT.

**Identity key scheme**
- X25519 static key used directly as identity, same model as WireGuard: one keypair, DH possession authenticates.
- X25519 static key plus separate Ed25519 signing key: two keypairs, signing capability independent of the session key. Useful for signed key updates or multi-device linking.

**AEAD cipher**
- ChaCha20-Poly1305: consistent performance without hardware acceleration, common on mobile, used by WireGuard and Signal.
- AES-256-GCM: faster on hardware with AES-NI, slower and harder to implement in constant time without it.

**Peer discovery / rendezvous**
- Signaling server: simpler to build. A central point that can observe connection metadata, who is contacting whom and when.
- DHT: no central point of observation, more complex to implement, slower and less reliable discovery.

**Threat model scope: IP-level correlation**
- Direct P2P: lowest latency, simplest. A network observer sees the two endpoints communicating even with content and timing obfuscated.
- Relay: hides endpoint correlation from a network observer. Adds latency, the relay becomes infrastructure to run and trust.

**Wire format**
Not a tradeoff, a planning step: reserve header fields for padding length and timing metadata now, even if unused until Phase 4. Avoids a breaking format change later regardless of which options above are chosen.

---

## Phase 1: Core Crypto Handshake

- Generate identity keys per the scheme chosen in Phase 0
- Integrate Noise Protocol via snow, using the pattern chosen in Phase 0
- Derive symmetric session keys from the handshake output
- Encrypt/decrypt messages with the AEAD cipher chosen in Phase 0

**Milestone:** two local processes complete a handshake and exchange an encrypted message via direct function call, no networking yet.

---

## Phase 2: UDP Transport

- Basic UDP socket send/receive with tokio::net::UdpSocket
- Design packet format with sequence numbers to handle loss, reordering, duplication
- Implement the peer discovery / rendezvous mechanism chosen in Phase 0
- Start fuzzing the packet parser as soon as it exists

**Reliability scope, open decision:**
- Handshake-only retransmission, message packets best-effort: matches common real-time messenger design (Signal, WhatsApp), lower complexity, lost messages are not automatically resent.
- Broader reliability layer for all packet types: guarantees delivery, more complexity, closer to reimplementing TCP semantics on top of UDP.

**Milestone:** two processes exchange encrypted messages over real UDP sockets on a network.

---

## Phase 3: Session and Message Layer

- Finalize wire format using the header fields reserved in Phase 0
- Implement replay protection, reject old or duplicate sequence numbers

**Forward secrecy mechanism, open decision:**
- Periodic re-handshake or rekey (snow's rekey, or a fresh handshake at intervals): simpler to implement, coarser-grained forward secrecy. Compromise of a session key exposes all messages since the last rekey.
- Full Double Ratchet: forward secrecy and break-in recovery per message, more implementation complexity and a larger surface for bugs.

**Private key storage, open decision:**
- OS keychain: stronger OS-level protection, separate platform-specific API for each target (Linux, macOS, Windows, mobile).
- Encrypted disk storage: portable across platforms, requires managing the encryption key for that storage separately.

**Milestone:** sustained conversation with key rotation, stable under packet loss and reordering.

---

## Phase 4: Obfuscation Layer

- Traffic shaping: constant-rate or randomized packet timing to defeat timing correlation
- Padding: pad packets to fixed sizes using the reserved header fields, so length doesn't leak content or type
- Cover traffic: dummy packets during idle periods
- If Phase 0 scoped IP-level correlation in scope, implement the relay here

**Protocol mimicry, open decision:**
- Include it: stronger blending into normal traffic (resembling QUIC or WebRTC), requires maintaining compatibility with the mimicked protocol's observable characteristics, adds implementation and maintenance burden.
- Skip it: less blending strength, less ongoing maintenance.

Reference designs: obfs4 (Tor pluggable transport), WireGuard obfuscation forks.

**Milestone:** measured packet timing and size distributions no longer correlate cleanly with message events.

---

## Phase 5: Hardening and Review

- Write a threat model document covering the decisions made in Phase 0: attacker capabilities, what's in scope
- Run clippy and cargo audit
- Continue fuzzing coverage across the full packet handling path
- Get external review before any real deployment
- No custom crypto primitives, audited libraries only

---

## Learning Checklist

**Cryptography**
- [ ] Asymmetric key exchange vs encryption (X25519 produces a shared secret, not ciphertext)
- [ ] AEAD ciphers: ChaCha20-Poly1305 vs AES-GCM, and the hardware acceleration tradeoff
- [ ] Ed25519 signatures, and when a separate signing identity is needed vs a DH static key alone
- [ ] Forward secrecy: periodic rekey vs full Double Ratchet
- [ ] Noise Protocol Framework spec, in particular XX vs IK

**Key management**
- [ ] Trust-on-first-use and fingerprint/safety-number verification
- [ ] Private key storage at rest: OS keychain vs encrypted storage

**Networking**
- [ ] UDP fundamentals: no ordering, no delivery guarantee, no congestion control
- [ ] NAT traversal: STUN/TURN, hole punching
- [ ] Peer discovery / rendezvous design: signaling server vs DHT
- [ ] QUIC's approach to reliability over UDP, as a reference design

**Traffic analysis and obfuscation**
- [ ] Traffic fingerprinting basics
- [ ] Tor pluggable transports (obfs4, meek) as case studies
- [ ] Limits of padding/timing defenses against a determined analyst
- [ ] IP-level correlation vs content/timing correlation, and why they need different defenses

**Rust specific**
- [ ] Ownership and borrowing
- [ ] tokio async runtime
- [ ] snow crate API, including transport mode and rekey

**Security engineering pitfalls**
- [ ] Nonce reuse with AEAD (breaks confidentiality)
- [ ] Timing side channels
- [ ] Unauthenticated ciphertext
- [ ] Review WireGuard and Signal design docs as examples
