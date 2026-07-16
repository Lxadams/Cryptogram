# E2E UDP Messenger: Learning Guide

Companion to ROADMAP.md. Goes through each item in the learning checklist with more depth than the roadmap's one-line summaries.

---

## 1. Cryptography

### Asymmetric key exchange vs encryption

X25519 is Diffie-Hellman over Curve25519. Each party has a private/public keypair. Combining your private key with their public key produces the same shared secret they get combining their private key with your public key. This shared secret is not ciphertext and is not sent over the network. It's derived locally by both sides, then fed into a key derivation function (typically HKDF) to produce the keys used for actual encryption.

The common confusion: conflating "asymmetric encryption" (RSA encrypting data directly with a public key) with "asymmetric key agreement" (X25519 deriving a shared secret that a symmetric cipher then uses). In this project, the message itself would be encrypted by a symmetric AEAD cipher using a key derived from the X25519 shared secret, not by X25519 directly.

### AEAD ciphers

AEAD (Authenticated Encryption with Associated Data) provides confidentiality and integrity together: encrypting produces ciphertext plus a tag, decrypting requires the same key and nonce and fails if either the ciphertext or the tag was altered.

ChaCha20-Poly1305 combines the ChaCha20 stream cipher with the Poly1305 MAC. Performance is consistent regardless of CPU features, since it doesn't depend on hardware acceleration.

AES-256-GCM uses AES in Galois/Counter Mode. On CPUs with AES-NI (most modern x86/ARM64 desktop and server chips) it's fast. Without AES-NI, software AES is slower and prone to timing side channels unless implemented carefully.

Both commonly use 96-bit nonces. In a protocol like this one, nonces are usually derived from the packet sequence number rather than generated randomly, since random 96-bit nonces carry a birthday-bound collision risk at high message volumes.

### Ed25519 signatures

Ed25519 is a deterministic signature scheme over edwards25519, a related but different curve form than X25519. Given a message and a private key it produces a signature; anyone with the public key can verify it. It is a separate capability from X25519 even though both are built on the same curve family.

This matters for the identity key scheme decision in Phase 0. Using only an X25519 static key (WireGuard's approach) means authentication comes from proving DH possession during the handshake itself, with no separate signing capability. Adding a separate Ed25519 keypair enables signing data outside the handshake: signed key rotation announcements, signed device-linking certificates for multi-device support, or a fingerprint independent of session key rotation. The cost is a second keypair to generate, store, and back up.

### Forward secrecy

If a key is compromised in the future, forward secrecy means past communications stay unreadable, because the keys that encrypted them were derived from ephemeral material that no longer exists.

Periodic rekey (via `snow`'s rekey function, or a fresh Noise handshake at intervals) rotates the session key on a schedule. If an attacker gets today's key, they read today's traffic within that window, not last week's. The exposure window is however long you wait between rekeys.

Double Ratchet (used by Signal) advances the key on every message, combining a symmetric-key ratchet with periodic Diffie-Hellman ratchet steps. This gives forward secrecy per message and break-in recovery: even if a key is compromised at message N, message N+1 uses key material from a new DH step, so the compromise doesn't persist. The cost is complexity: tracking skipped message keys for out-of-order delivery (which UDP guarantees you'll encounter), and managing ratchet state where a bug silently breaks the security property without necessarily crashing anything.

### Noise Protocol Framework

Noise is a framework for building handshake protocols from a small set of primitives (DH function, cipher, hash), instead of designing a handshake from scratch, which is where most homegrown crypto protocols go wrong. Each documented "pattern" specifies what messages are exchanged and in what order, with defined resulting security properties.

Noise_XX: `-> e`, `<- e, ee, s, es`, `-> s, se`, three messages. Works when neither party knows the other's static key in advance.

Noise_IK: responder's static key known out of band beforehand, then `-> e, es, s, ss`, `<- e, ee, se`, two messages. The initiator can encrypt its own static key to the responder in the first message, so a passive observer learns only that the responder is being contacted, not who's contacting them, until the responder decrypts message one. This is an anonymity property XX doesn't give as directly, worth weighing alongside round-trip count when deciding the Phase 0 tradeoff.

---

## 2. Key management

### TOFU and fingerprint verification

Trust On First Use accepts a peer's public key the first time it's seen and pins it, flagging any later change (the same model SSH uses for host keys). It protects against an attacker who wasn't present during the first exchange, not one who was.

Fingerprint or safety-number verification is the mitigation: derive a short, human-comparable representation of the public key (a number sequence or QR code, what Signal calls safety numbers) and have both users compare it out of band, in person or over a separate channel, to confirm no one substituted a key during the exchange. Worth deciding early whether the app surfaces this in the UI or treats it as a later addition, since it directly affects the strength of the key distribution claim.

### Private key storage at rest

If an attacker can read the key file directly, the handshake's security guarantees don't matter.

OS keychain APIs (Keychain on macOS, Credential Manager/DPAPI on Windows, Secret Service/libsecret on Linux, Keystore on Android, Keychain on iOS) hand storage off to the OS, usually tied to user login and, on mobile, to hardware-backed secure storage. The cost is a different API per platform, requiring an abstraction layer, and inconsistent availability across Linux distributions.

Encrypted disk storage (a key file encrypted with a key derived from a user password, via Argon2 for example) is portable and doesn't depend on OS features, but shifts the problem: now the encryption key protecting the identity key needs protecting too, usually by deriving it from something the user remembers, which makes password strength a dependency of the whole security story.

---

## 3. Networking

### UDP fundamentals

UDP is a thin wrapper over IP: an 8-byte header (source port, dest port, length, checksum) plus send/receive of individual datagrams. Three guarantees TCP provides are absent: no delivery guarantee (a datagram can simply never arrive), no ordering (later-sent datagrams can arrive first), no automatic retransmission or congestion control. This is why the wire format needs its own sequence numbers and reorder tolerance built in, features TCP provides for free at the cost of head-of-line blocking, which real-time messaging wants to avoid.

### NAT traversal

Most consumer devices sit behind NAT: the router rewrites private IPs to a shared public IP, and by default nothing outside can initiate a connection in, only responses to outbound traffic route back.

STUN (Session Traversal Utilities for NAT) is a protocol where a public server tells a client what public IP:port its own NAT mapped it to. When both peers exchange this info through a separate signaling channel, they can each send a UDP packet toward the other's public mapping at the same time, opening a temporary path through both NATs, since each router now sees outbound traffic matching what it's about to receive. This is hole punching. It doesn't work against all NAT types (symmetric NAT is the hard case), which is why TURN exists: a relay server that forwards traffic when hole punching fails, at the cost of bandwidth, latency, and the relay seeing that the two peers are communicating.

### Peer discovery / rendezvous

Separate from NAT traversal: how does a peer learn the other party's current public IP:port to attempt hole punching against in the first place? Some out-of-band channel handles that initial exchange.

A signaling server is the simple version: both peers connect to a known server and exchange current network info through it (and it can double as a TURN fallback if hole punching fails). The tradeoff is that server sees metadata about who's trying to reach whom.

A DHT (the same idea BitTorrent uses for trackerless discovery) removes the single central point but adds work: running and maintaining a working DHT implementation, with slower and less reliable discovery than a dedicated server.

### QUIC's approach to reliability over UDP

QUIC is worth reading even without adopting it, since it already solved reliable, ordered-per-stream, encrypted transport over UDP in production at scale (it's what HTTP/3 runs on). It multiplexes multiple independent streams over one UDP flow so loss on one stream doesn't block others, avoiding TCP's head-of-line blocking while keeping reliability. It does its own loss detection and retransmission using packet numbers that are monotonic and never reused, the same sequence number design this roadmap calls for. It also integrates the TLS 1.3 handshake into the transport handshake so encryption isn't bolted on afterward. Reading QUIC's loss detection and congestion control sections is a fast way to avoid known mistakes in custom retransmission logic.

---

## 4. Traffic analysis and obfuscation

### Traffic fingerprinting basics

Even with encrypted payloads, packet size, timing, and direction form a pattern often distinctive enough to identify what app or action is happening. This is website fingerprinting and traffic analysis research applied to encrypted channels, studied extensively against Tor, where researchers have shown they can identify which site is being visited from a Tor circuit using packet size and timing sequences alone, with high accuracy in controlled settings. For a messenger this means a text message, a typing indicator, and a media transfer each have their own fingerprint unless actively equalized, the reason Phase 4 exists.

### Tor pluggable transports as case studies

obfs4 wraps Tor traffic to look like uniformly random bytes, defeating deep packet inspection that looks for Tor's handshake signature, and adds authentication to the obfuscation layer itself so a censor can't probe the port to unmask it. meek instead tunnels traffic inside HTTPS requests to a large cloud provider (domain fronting), relying on the fact that blocking the front domain would collateral-damage the provider's other customers.

These represent two different obfuscation approaches: make traffic look like nothing, or make traffic look like something specific and expensive to block. The Phase 4 protocol mimicry decision is a choice between these approaches.

### Limits of padding/timing defenses

Padding to fixed sizes and adding timing jitter raise the cost of traffic analysis, but a resourced observer with visibility at both ends of a suspected conversation, or enough samples to train a classifier, can often still get statistically significant correlation on long-lived or repetitive conversations. This is an active research area, not a solved problem. Phase 4 raises the cost of correlation; it doesn't make correlation impossible.

Constant-rate transmission (a datagram every N milliseconds regardless of real data, padded with cover traffic) is the strongest defense against timing analysis specifically, at the cost of bandwidth and battery, which is why most systems apply it selectively instead of always-on.

### IP-level correlation vs content/timing correlation

Different attacker capabilities, different defenses. Conflating them creates a false sense of security.

Content/timing correlation is an observer watching one link and inferring what's being said or what type of action is happening from patterns in the encrypted stream. Padding and traffic shaping address this.

IP-level correlation is an observer, or someone with visibility at multiple points on the network such as an ISP or a broad-tap adversary, seeing that IP A and IP B are exchanging UDP packets at all, independent of packet contents. No amount of padding or timing jitter on a direct P2P link hides this. Only routing through an intermediary, a relay or a multi-hop network like Tor, changes what the observer can directly see. This is why the relay decision sits in Phase 0 separately from Phase 4's obfuscation techniques: they defend against different things.

---

## 5. Rust specific

### Ownership and borrowing

Rust's core guarantee, enforced at compile time with no runtime cost: each value has one owner, and when the owner goes out of scope the value is dropped. Values can be borrowed as one mutable reference or any number of immutable references at a time, never both at once.

For a crypto/networking project this matters concretely: key material wrapped in a type that's dropped, and made to zero its memory on drop via the `zeroize` crate, is guaranteed to be cleaned up when it goes out of scope without waiting on a garbage collector, so session keys don't linger in memory pages that could get paged to disk or read by another process after use. Work through a few small exercises before touching handshake code if this is unfamiliar. Mistakes here become compile errors, which is Rust's value proposition for this kind of code (a memory bug caught at compile time instead of a leaked key at runtime), but only if the errors are understood rather than worked around by adding `.clone()` everywhere.

### tokio async runtime

tokio provides a task scheduler, a reactor for OS I/O events, and timers, so UDP send/receive can be written as `async fn`s that yield while waiting on the network instead of blocking a thread.

Relevant pieces: `tokio::net::UdpSocket` for the socket itself; `tokio::time::sleep`/`interval` for the timing and jitter work in Phase 4; `tokio::select!` for waiting on multiple things at once, e.g. "receive a packet or a retransmission timer fires, whichever happens first", the shape of the handshake retry logic in Phase 2; `tokio::spawn` for running independent tasks, such as one per peer connection, concurrently.

Worth knowing the difference between `tokio::sync::Mutex` (async-aware, needed when holding the lock across an `.await`) and `std::sync::Mutex` (faster, use when not holding across an `.await`), a common source of confusion and occasional deadlocks in async Rust.

### snow crate API

`snow` implements the Noise Protocol Framework. A `HandshakeState` is built from a `Builder` configured with the chosen pattern string (e.g. `"Noise_IK_25519_ChaChaPoly_BLAKE2s"`), the local static keypair, and, for IK, the remote's known static public key. `write_message`/`read_message` are called alternately as handshake messages are exchanged.

Once complete, `into_transport_mode()` converts the `HandshakeState` into a `TransportState`, used afterward for message encryption via `write_message`/`read_message` again, now doing AEAD encrypt/decrypt of application data instead of handshake steps. `TransportState` tracks send/receive nonces as counters internally, matching the sequence-number-as-nonce approach from the AEAD section, and exposes a `rekey()` method for the periodic rekey approach in the Phase 3 forward secrecy decision, advancing the symmetric key without a full new handshake.

---

## 6. Security engineering pitfalls

### Nonce reuse with AEAD

The most damaging implementation mistake available in this project. AEAD ciphers require a unique nonce per encryption under a given key. Encrypting two different messages with the same key and nonce lets an attacker who intercepts both ciphertexts XOR them together and recover the XOR of the two plaintexts (for stream-cipher-based AEADs like ChaCha20-Poly1305), and depending on the cipher can sometimes recover the authentication key, breaking integrity for every subsequent message under that key.

This is why sequence-number-derived nonces, rather than random ones, are standard here: a monotonic counter can't repeat as long as it's enforced to never reset or overflow, never gets reused across a rekey without also resetting, and never lets two different connections share a key/counter pair. Any state restoration, such as crash recovery or process restart, that could replay an old counter value against the same key is a nonce reuse bug, worth an explicit test.

### Timing side channels

An operation whose execution time depends on secret data, a key or a plaintext byte, can leak that data to an attacker who can measure timing precisely enough, even over a network in some cases. Classic examples: comparing a computed MAC against a received one with a naive `==` that short-circuits on the first differing byte, leaking how many bytes matched, instead of a constant-time comparison; branching on a secret bit where the two branches take different amounts of time.

The libraries in this stack (`snow`, `dalek`, `chacha20poly1305`) are written to be constant-time in their core operations, a major reason to use audited libraries instead of writing crypto primitives by hand. Application-level code, comparisons of MACs, tokens, or derived values, can still introduce a side channel if a constant-time comparison function isn't used for anything secret-derived.

### Unauthenticated ciphertext

Encryption without authentication lets an attacker flip bits in ciphertext and have it decrypt to a modified, plausible plaintext without detection, or replay old ciphertext, or in some modes forge new ciphertext outright. AEAD's authentication half exists to prevent this, but only if the result is checked: every decrypt call needs its authentication result verified before the plaintext is used, and on failure the packet must be dropped rather than partially processed. A common bug is decrypting, then acting on part of the plaintext, such as parsing a header, before checking the auth tag, which reopens the exact hole AEAD closes. Verify first, use after.

### WireGuard and Signal design docs

Two of the most scrutinized real-world protocols doing pieces of what this project needs. WireGuard's whitepaper is short and readable, close to Noise_IK plus a specific set of primitives plus a minimal UDP wire format, close to a worked example of several Phase 0 decisions already discussed here. Signal's Double Ratchet and X3DH specs are the reference for the full Double Ratchet side of the Phase 3 forward secrecy tradeoff, worth reading in full before deciding to build it, since they make the actual bookkeeping (skipped-key storage, out-of-order handling) concrete rather than abstract.
