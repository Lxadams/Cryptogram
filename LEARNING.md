# E2E Tactical Messenger: Learning Curriculum

This document serves as the technical study guide and prerequisite learning curriculum for implementing the master architecture defined in `ROADMAP.md`. Because the system spans post-quantum cryptography, advanced erasure coding, low-level network obfuscation, and hardware-backed mobile security, this guide explains *what* you need to understand to build the system successfully.

---

## 1. Post-Quantum Cryptography & Hybrid Key Exchange

### ML-KEM (Kyber) vs. Diffie-Hellman
Traditional Diffie-Hellman (X25519) allows two parties to combine their private keys with each other's public keys to arrive at a shared secret mathmatically. Post-Quantum algorithms do not work this way. **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism) requires one party to encapsulate a randomly generated symmetric secret against the other party's public key, producing a ciphertext. The second party decapsulates this ciphertext to recover the secret. 
* **Learning Requirement**: Understand the KEM API flow (`KeyGen`, `Encapsulate`, `Decapsulate`) and how to safely bind KEM ciphertexts into protocol transcripts to prevent Key Compromise Impersonation (KCI).

### ML-DSA (Dilithium)
The post-quantum digital signature algorithm used to authenticate identity keys and prekey bundles.
* **Learning Requirement**: Understand the massive key size and signature size differences between Ed25519 (64-byte signatures) and ML-DSA-65 (3,300+ byte signatures), and why ML-DSA keys cannot be transmitted in every network packet due to MTU limitations.

### Hybrid Key Derivation (HKDF)
Because post-quantum algorithms are novel, the NSA (CSfC) and industry standards mandate **Hybrid Cryptography**. 
* **Learning Requirement**: Understand how to safely cascade multiple shared secrets. In this protocol, 4 classical X25519 secrets and 2 ML-KEM secrets are concatenated alongside the public transcripts and fed into **HKDF-SHA256** (HMAC-based Extract-and-Expand Key Derivation Function) to produce a Master Key that is secure as long as *at least one* of the underlying algorithms remains unbroken.

---

## 2. The Signal Double Ratchet Algorithm

The core messaging engine that provides Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS).
* **Root Chain & Message Chains**: Understand how KDFs advance forward on every message (Symmetric Ratchet) to ensure an attacker who steals today's key cannot read yesterday's messages.
* **Diffie-Hellman Ratcheting**: Understand how sending a new ephemeral public key with every message forces the Root Chain to rotate, guaranteeing that if an attacker steals today's key, they lose access as soon as the participants exchange new messages.
* **Out-of-Order Execution**: UDP guarantees packet loss and reordering. You must understand how the Double Ratchet handles skipped messages (storing derived message keys in a dictionary for future late arrivals) up to a `MAX_SKIP` limit.
* **Asynchronous PQ Healing**: Because ML-KEM ciphertexts are too large to append to every message, you must understand how to execute the standard classical Double Ratchet, while periodically sending out-of-band ML-KEM encapsulations (`PQ_REKEY`) to "heal" the root chain against quantum adversaries.

---

## 3. Forward Error Correction (FEC) & RaptorQ

Tolerating 95% packet loss without Acknowledgment (ACK) packets requires completely abandoning standard TCP/ARQ logic.
* **Erasure Codes vs. ARQ**: Understand why reactive retransmission fails when round-trip loss is 95%.
* **Rateless Fountain Codes (RaptorQ - RFC 6330)**: Understand how RaptorQ can take a file sliced into $K$ source symbols and generate an infinite stream of repair symbols. A receiver can successfully reconstruct the entire original message by collecting *any* $K + \epsilon$ symbols, regardless of which specific packets were dropped.
* **Interleaved Round-Robin Scheduling**: To prevent active typing from starving active block transmissions, you must understand how to interleave FEC block transmissions inside a fixed timer loop, streaming repair symbols during idle ticks.
* **Galois Fields (`GF(256)`)**: A conceptual understanding of how erasure coding matrix math works in finite fields will aid in debugging decoder failures.

---

## 4. Low-Level Networking & Censorship Evasion

* **MTU & IP Fragmentation**: Understand why the UDP packet size is strictly capped at **1350 bytes**. If a datagram exceeds the network path MTU (typically 1500 bytes), routers fragment it. If either fragment is lost, the whole packet is lost, squaring your effective packet loss rate and destroying the RaptorQ math.
* **Constant-Rate Tunnels (CRT)**: Understand traffic analysis and timing correlation. To hide metadata, the application must fire a packet every 100ms exactly, padding empty ticks with cryptographic noise (Dummy Packets).
* **HTTP/3 (QUIC) Datagrams (RFC 9221)**: Because sending raw, metronomic UDP packets looks highly anomalous to Deep Packet Inspection (DPI) firewalls, you must learn how to wrap raw UDP datagrams inside a QUIC connection (over port 443) to camouflage the traffic as standard web browsing.
* **Harmonic Signatures**: Understand that default QUIC implementations inject Keep-Alives and MTU probes. When overlaid on a 100ms CRT loop, these create harmonic timing frequencies. You must learn how to modify a QUIC stack to achieve total protocol silence.

---

## 5. Hardware Security & Mobile OS Internals

To meet tactical CSfC constraints, you must understand the Android/Samsung hardware boundaries.
* **Samsung Knox Vault (EAL5+)**: Understand the physical separation between the Application Processor (OS), the Trusted Execution Environment (TEE/TrustZone), and dedicated Secure Elements (SE).
* **Key Wrapping Architectures**: Because hardware APIs often lag behind cryptographic research (e.g., lack of ML-KEM support in Knox), you must learn how to generate software keys in volatile RAM, and use the hardware element to generate an AES Key Encryption Key (KEK) to securely "wrap" the software keys before saving them to disk.
* **Write-Ahead Logging (WAL)**: When you delete a one-time prekey from the hardware Keystore and update the Double Ratchet state in the SQLite database, you are updating two independent systems. If the phone crashes halfway, the session is permanently locked. You must understand Two-Phase Commits and WAL concepts to ensure atomicity.
* **Memory Hygiene**: Learn system calls and memory management techniques to prevent RAM scraping: `zeroize` traits in Rust to wipe buffers on drop, `mlock` to pin pages and prevent OS swapping to disk, and Android `onTrimMemory` lifecycle hooks.

---

## 6. Advanced Server Architecture (Blind Routing)

The AWS Relay must route messages without knowing who is talking, what they are saying, or when they are saying it.
* **Metronomic Decoupling**: If a server forwards a packet the millisecond it receives it, global adversaries can correlate the processing latency ($\Delta T$) to link Alice to Bob. You must understand how to buffer ingress traffic and only flush egress queues on globally aligned timer ticks.
* **Stateless Proof-of-Work (PoW)**: To prevent socket exhaustion DDoS attacks, you must learn how to issue stateless cryptographic challenges (e.g., $HMAC(ClientIP + DailySecret) = Cookie$), forcing the client to solve a CPU-bound hashcash puzzle before the server allocates any RAM.
* **Hash Ratcheting & Blind Queuing**: Understand how to use one-way hashing ($H(Token) \rightarrow R_0, H(R_0) \rightarrow R_1$) to create "Offline Rendezvous Tokens." This allows the server to queue data to a mailbox that constantly changes names, preventing the server from tracking long-term subscriptions.
* **Delete Tokens (Blinded GC)**: Learn how to shift deletion commands ($HMAC(SessionKey, BlockID)$) into the link-layer plaintext, allowing the relay to instantly purge RAM queues without needing to decrypt the E2E payload.
