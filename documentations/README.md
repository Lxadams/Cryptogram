# E2E-Messenger
**Compx374 Industry Project** 

## Project Overview

E2E-Messenger is a highly secure, extreme-loss tolerant tactical messenger designed as a Proof of Concept (PoC) for rugged operational environments. Built with a high-performance **Rust cryptography and networking core** accessed via a **Mobile UI (Android/Kotlin)**, this project demonstrates novel approaches to metadata obfuscation, network reliability without TCP, and Post-Quantum cryptography.

The architecture is designed to survive hostile network conditions (heavy packet loss, jamming, and eventually Deep Packet Inspection censorship firewalls) while leaking as little metadata as it can about who is communicating, or when. What's built so far, and what isn't yet, is set out below and in the [Stage 3 roadmap](stage-3-roadmap.md).

For the full implementation schedule, see the [doable-roadmap.md](doable-roadmap.md). For what comes next (the constant-rate tunnel and hardening), see [stage-3-roadmap.md](stage-3-roadmap.md).

---

## How It Works: The Core Mechanics

Our architecture abandons traditional messaging paradigms (like WebSockets, TCP, or central identity servers) in favor of a decentralized, metronomic, and rateless UDP approach. Here is how the components interact:

### 1. Identity & Trust (QR Codes)
Users do not register accounts, usernames, or phone numbers. Trust is established completely out-of-band by physically scanning a QR code on a peer's device. The code holds the peer's routing token (where the relay delivers their messages) and their Ed25519 identity key, against which everything they later send is checked. Both people scan each other.

### 2. Hybrid Post-Quantum Key Exchange (PQXDH)
To protect against future quantum computers harvesting encrypted data today ("Harvest Now, Decrypt Later"), each session's handshake combines elliptic curve Diffie-Hellman (**X25519**) with the NIST-standardized Post-Quantum Key Encapsulation Mechanism, **ML-KEM-768** (FIPS 203). The two secrets are merged with HKDF into the session's root key, which stays safe unless both are broken.

Every five messages, the sender also mixes a fresh ML-KEM secret into its chain (a "PQ refresh"). These are encapsulated to the contact's long-term ML-KEM key. That keeps a session post-quantum, but doesn't heal it after a device is compromised: healing needs the ratchet planned in the roadmap (item 3.1).

### 3. End-to-End Encryption (Symmetric Hash Ratchet)
Once a session is established, messages are encrypted with a **symmetric hash ratchet**, not the Double Ratchet:
- **Forward secrecy, per message:** every message gets its own key, from a chain that only moves forward (HMAC-SHA256), so earlier messages' keys can't be recovered from the current state.
- **Out-of-order delivery:** a bounded skip dictionary holds at most 500 skipped keys, and nothing more than 100 messages ahead is accepted. Used keys are destroyed.
- **No healing yet:** without a Diffie-Hellman step, the ratchet doesn't recover from a compromise on its own (see the roadmap).

### 4. Extreme Loss Tolerance (RaptorQ FEC)
Tactical networks (like jammed radios) drop packets constantly. Standard TCP networks rely on "ACKs" (acknowledgments) to trigger retransmissions, which fails completely if loss exceeds 50%.

Instead, our Rust core uses **RaptorQ**, a Forward Error Correction (FEC) fountain code:
- **The burst:** the sender pads and encrypts the message, then sends it as a burst of symbols sized to survive **70% loss** on either side's link. That's the loss it's tested at, against the real relay.
- **Rebuilding:** the receiver rebuilds the message from any large enough subset of those symbols. There are no end-to-end ACKs.
- **Offline phones:** the relay keeps each packet until the recipient's client acknowledges it, so a phone that's offline or asleep still gets it later.

### 5. Traffic Obfuscation (Planned: the Constant-Rate Tunnel)
**The plan:** to stop a passive observer learning *when* you talk or *how much*, each end will send fixed-size cells at a constant, randomised rate, padding when there's nothing to say. That's Phase 1 of the [Stage 3 roadmap](stage-3-roadmap.md).

**Today:**
- **Visible patterns:** packets go out only when there's something to send, so timing and volume are visible.
- **Link encryption:** every packet is already encrypted after an X25519 handshake with the relay (whose public key is built into the app). It uses **ChaCha20-Poly1305**, with a key for each direction, and every packet is numbered so none can be replayed.
- **No disguise yet:** it's raw UDP on port 443, which doesn't yet look like any other protocol to DPI.

### 6. The Blind Relay Server
The backend is a RAM-only cloud server that acts as a router.
- **No accounts:** it has zero knowledge of User IDs, passwords, or persistent accounts.
- **Routing tokens:** each client has a 16-byte **Routing Token**, the hash of a key only that client holds. So when it tells the relay where it is (a signed "sync"), it can prove the token is its own.
- **Routing:** when the relay receives a packet, it reads the recipient's token. It forwards the packet to the address that token's owner has proven it's at, or keeps it in a RAM-only queue while they're offline, for up to 7 days.
- **Flood protection:** its tables are bounded, and handshakes are rate-limited per address, so floods can't exhaust it.
- **What it can see:** it never sees message contents. It does see which tokens talk to which, and when. Hiding that from the relay is later work (roadmap items 2.6 and 3.6).

### 7. Stretch Goal: Ephemeral Multicast Group Chats
While the core architecture focuses on strict 1-on-1 privacy, the project includes a stretch goal to implement Ephemeral Multicast Group Chats. This involves generating "Signal Sender Keys" and securely distributing them over the 1-on-1 channels, allowing the server to dynamically fan-out a single message stream to multiple recipients simultaneously without knowing the group's persistent topology.

---

### Project Documentation
*   [Realistic Implementation Roadmap](doable-roadmap.md)
*   [Stage 3 Roadmap: Constant-Rate Tunnel and Hardening](stage-3-roadmap.md)
*   [Cryptographic Flow, as Implemented](doable-cryptographic-flow.md)
*   [RaptorQ FEC Transport](raptorq-fec-transport.md)
*   [Prerequisite Learning Guide](LEARNING.md)
