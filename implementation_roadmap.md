# E2E Tactical Messenger: Detailed Implementation Roadmap

This roadmap breaks down the `ROADMAP.md` architecture into highly granular, sequential development tasks. It is designed to allow concurrent workstreams (e.g., Server vs. Client Cryptography) while ensuring dependencies between complex features (like RaptorQ and Double Ratchet state) are respected.

## Phase 1: Local Setup & Cryptographic Foundation
*This phase focuses entirely on local, offline client architecture and securing data-at-rest.*
- [ ] **1.1: Dependency Initialization**: Integrate cryptographic libraries (ML-DSA, ML-KEM, X25519, Ed25519, ChaCha20, HKDF).
- [ ] **1.2: Samsung Knox Bindings**: Implement hardware bindings to generate and store the 32-byte Master Seed inside the Secure Element.
- [ ] **1.3: Hardware Key Derivation**: Build the HKDF-SHA256 engine to derive classical keys ($IK_{sign}$, $IK_{dh}$) from the master seed.
- [ ] **1.4: PQ Wrapped Key Architecture**: Implement ML-DSA-65 and ML-KEM-768 key generation in software (RAM), explicitly wrapping them with a Knox Key Encryption Key (KEK) before storage.
- [ ] **1.5: Memory Hygiene Layer**: Implement strict memory zeroization (e.g., using `zeroize` traits) for all temporary RAM buffers holding decrypted keys.
- [ ] **1.6: Prekey Bundle Generation**: Generate classical and Post-Quantum One-Time Prekeys (PQOPKs). Sign the bundle using the ML-DSA-65 $IK_{sign}$ key.
- [ ] **1.7: SQLite / SQLCipher Setup**: Implement the encrypted local database to persist message history and the Double Ratchet state.
- [ ] **1.8: Knox DualDAR Integration**: Map the application's file system directory to utilize DualDAR double-encryption for the SQLCipher files.
- [ ] **1.9: QR Code Generator**: Build the out-of-band onboarding system (generates QR containing Public Keys, Bootstrap Nonce, and calculates local $\Delta t_{A-B}$ clock offset).

## Phase 2: Client Transport Layer (The CRT Engine)
*This phase builds the network primitives and the metronomic Constant-Rate Tunnel.*
- [ ] **2.1: UDP Datagram Structure**: Implement the fixed 1350-byte UDP packet serializer (16B Token, 24B Nonce, 1310B Link Ciphertext).
- [ ] **2.2: Link Encryption**: Implement hop-by-hop XChaCha20-Poly1305 encryption for the 1310B payload.
- [ ] **2.3: Link Key Rotation**: Implement inline X25519 ephemeral key swaps every 10 minutes to maintain link-layer Perfect Forward Secrecy.
- [ ] **2.4: Metronomic Ticker**: Create the core background thread that ticks exactly every 100ms, transmitting a packet regardless of user activity.
- [ ] **2.5: Transport Routing Flags**: Implement the 1-byte flag parser (`0x01 FORWARD`, `0x02 DROP`) inside the link plaintext.
- [ ] **2.6: Link-Encrypted NTP Queries**: Build `TIME_SYNC_REQ` / `TIME_SYNC_RESP` handling over the encrypted link to establish secure epochs.
- [ ] **2.7: Epoch Token Generator**: Implement the rotating routing token hash chain, initialized strictly using the out-of-band clock offset.

## Phase 3: AWS Relay Foundation (Blind Routing)
*This phase establishes the AWS Relay as a zero-knowledge packet router and offline buffer.*
- [ ] **3.1: Server OS Hardening**: Disable virtual memory swap (`swapoff`), configure `tmpfs` mounts for queues, and disable all stdout/file logging.
- [ ] **3.2: Noise XX Listener**: Implement the server-side Noise protocol handshake to establish link keys with connecting clients.
- [ ] **3.3: Proof-of-Work (PoW) Validator**: Implement stateless server cookie generation and CPU-bound PoW puzzle verification to prevent connection flooding.
- [ ] **3.4: Active Connection Table**: Build the fast, RAM-only hash map linking active `IP:Port` sockets to ephemeral Routing Tokens.
- [ ] **3.5: Prekey Directory**: Implement a queryable prekey database indexed strictly by the SHA-256 hash of the user's public identity key.
- [ ] **3.6: Metronomic Egress**: Decouple ingress processing from egress transmission. Buffer all outgoing packets and flush them strictly on the server's global 100ms grid ticks.

## Phase 4: Client Session & Core E2E Cryptography
*This phase binds the classical and post-quantum keys into a unified Double Ratchet session.*
- [ ] **4.1: Hybrid Post-Quantum X3DH**: Implement the handshake combining 4x X25519 DH operations with dual ML-KEM encapsulations.
- [ ] **4.2: Master Key Derivation**: Feed the DH secrets, ML-KEM secrets, and public parameter transcript into the HKDF session binder.
- [ ] **4.3: Double Ratchet State Machine**: Integrate the standard Double Ratchet to generate revolving message keys ($MK$).
- [ ] **4.4: Dual-Layer E2E Encryption**: Implement the dynamic Header Key (derived from Ratchet Root Key) to encrypt metadata, alongside the payload encryption.
- [ ] **4.5: Bootstrap Fallback**: Implement the deterministic Bootstrap Header Key used for the very first `HANDSHAKE` block before the Ratchet is initialized.
- [ ] **4.6: Session Healing Flags**: Implement state tracking for "Degraded PQ Forward Secrecy" when PQOPKs are depleted, triggering interactive upgrades upon connection.
- [ ] **4.7: Asynchronous PQ Ratchet**: Implement the out-of-band `PQ_REKEY` logic (transmitting new ML-KEM ciphertexts to heal Post-Compromise Security).
- [ ] **4.8: Constant Padding Math**: Implement automatic padding of all E2E plaintexts (text/commands) with secure random bytes to exactly 4880 bytes.
- [ ] **4.9: Keystore WAL**: Implement a Write-Ahead Log in SQLCipher to ensure the hardware deletion of a used PQOPK is strictly atomic with the Ratchet state save.

## Phase 5: Forward Error Correction (RaptorQ IPI) & Reliability
*This phase ensures the system can withstand 95% packet loss without acknowledgments.*
- [ ] **5.1: RaptorQ Integration**: Integrate a 2D File-Level RaptorQ encoder/decoder.
- [ ] **5.2: E2E Header Layout**: Structure the decrypted 17-byte metadata header (Pkt Type, Block ID, ESI, Symbol Count K).
- [ ] **5.3: Source Slicing**: Slice the 4880-byte padded ciphertext into exactly four (K=4) 1220-byte source symbols.
- [ ] **5.4: Interleaved Round-Robin Scheduler**: Build the sender logic that round-robins active transmission blocks during idle CRT ticks, injecting up to $N_{max} = 120$ repair symbols per block.
- [ ] **5.5: Decoder Constraints**: Implement memory protection on the receiver (max 3 concurrent decoding blocks, enforce a +/- 5 sliding sequence window).
- [ ] **5.6: Dynamic Eviction**: Implement the receiver block eviction timeout (60-second floor, scaling with interleave depth).
- [ ] **5.7: Extreme Loss Resync**: Implement the client logic to detect unrecoverable packet loss (ratchet break) and issue a `SESSION_RESYNC` handshake packet.

## Phase 6: Blind Deletion & Server Queue Management
*This phase protects the Relay from RAM exhaustion and enables privacy-preserving garbage collection.*
- [ ] **6.1: Delete Token Generation**: Implement client calculation of the blinded $K_{\text{delete}}$ token via HMAC-SHA256 of the session key.
- [ ] **6.2: Offline Rendezvous Tokens**: Implement the one-way hash chain ($R_n$) and client Look-Ahead queries for blind message retrieval.
- [ ] **6.3: Relay RAM Offline Queues**: Implement the server logic to route incoming packets with unrecognized tokens to temporary RAM buffers.
- [ ] **6.4: NVMe Spilling (Anti-DoS)**: Implement the 50MB per-$R_n$ quota on the Relay, forcing overflow data to be server-encrypted and spilled to NVMe to protect `tmpfs`.
- [ ] **6.5: Relay Blind Garbage Collection**: Program the relay to read the Delete Token from the inner transport layer and instantly `free()` the corresponding $R_n$ queue.
- [ ] **6.6: Relay Tombstone Cache**: Implement a 2-minute RAM cache of processed Delete Tokens. Drop any incoming active symbols matching a tombstoned token.
- [ ] **6.7: E2E Pings (Anti-Exhaustion)**: Implement client-side logic to detect 30 seconds of missing E2E pings, switching tunnel flags to `DROP` to halt server queuing.

## Phase 7: HTTP/3 Obfuscation (Censorship Evasion)
*This phase upgrades the transport layer to defeat Deep Packet Inspection.*
- [ ] **7.1: QUIC Client Wrapping**: Wrap the 1350-byte custom UDP packets natively inside standard HTTP/3 QUIC Datagram frames.
- [ ] **7.2: QUIC Server Listener**: Bind the AWS Relay to port 443 with valid TLS certificates to mimic standard HTTPS traffic.
- [ ] **7.3: Anti-Harmonic Scrubbing**: Modify the QUIC stack to strictly disable Keep-Alives, Flow Control updates, and MTU probes, leaving only the 100ms grid traffic.
- [ ] **7.4: Datagram Routing**: Connect the raw QUIC datagram ingress/egress directly to the CRT metronomic scheduler pipeline.

## Phase 8: Multicast Group Chat (Bandwidth Preservation)
*This phase allows group communication without violating the CRT 10-pkt/sec limit.*
- [ ] **8.1: Sender Key Protocol**: Implement the Signal Sender Key generation (Symmetric Chain + Signing Key).
- [ ] **8.2: Out-of-Band Key Distribution**: Implement the logic to distribute Sender Keys over existing 1-on-1 Double Ratchet channels.
- [ ] **8.3: MULTICAST_BIND Packets**: Build the link-encrypted control packet mapping an Ephemeral Multicast Token (EMT) to recipient routing tokens.
- [ ] **8.4: RaptorQ Bind Redundancy**: Inject redundant `MULTICAST_BIND` packets continually into the active RaptorQ streaming block.
- [ ] **8.5: Relay Multicast Fanout Engine**: Implement logic on the AWS Relay to cache binds for 30s and physically duplicate incoming EMT packets into individual recipient egress queues.
- [ ] **8.6: PCS Epoch Enforcement**: Program the client to destroy and rotate the Sender Key every 50 messages or immediately when a member leaves/goes offline.

## Phase 9: Tactical Cleanup & Defensive QA
*This phase ensures the system meets the rugged operational requirements of a tactical environment.*
- [ ] **9.1: Application Lifecycle Hooks**: Tie RAM zeroization and SQLCipher cache flushing strictly to Android/iOS `onStop` and `onTrimMemory` lifecycle events.
- [ ] **9.2: Memory Locking (`mlock`)**: Implement syscalls to lock sensitive cryptographic buffers in memory, preventing OS swap paging.
- [ ] **9.3: Background Catch-Up Verification**: Validate that extreme sequence skipping (e.g., `MAX_SKIP = 2000`) is executed on a background thread to prevent UI freezing.
- [ ] **9.4: Link Overlap Tolerance**: Verify the Relay correctly maintains a 5-second overlap window during Link Key rotations to handle UDP jitter without dropping packets.
- [ ] **9.5: 95% Loss Stress Test**: Conduct rigorous End-to-End stress tests simulating 95% packet loss on the network interface (using tools like `tc qdisc netem`) to validate the RaptorQ IPI math and decoder evictions.
