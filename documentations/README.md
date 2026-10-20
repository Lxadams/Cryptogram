# E2E-Messenger
**Compx374 Industry Project** 

## Project Overview

E2E-Messenger is a highly secure, extreme-loss tolerant tactical messenger designed as a Proof of Concept (PoC) for rugged operational environments. Built with a high-performance **Rust cryptography and networking core** accessed via the **Cryptogram app** (a **Leptos UI in a Tauri shell**, on desktop and Android), this project demonstrates novel approaches to metadata obfuscation, network reliability without TCP, and Post-Quantum cryptography.

The architecture is designed to survive hostile network conditions (heavy packet loss, jamming, and eventually Deep Packet Inspection censorship firewalls) while leaking as little metadata as it can about who is communicating, or when. What's built so far, and what isn't yet, is set out below and in the [Stage 3 roadmap](stage-3-roadmap.md).

The original implementation schedule, the July plan, is in [doable-roadmap.md](doable-roadmap.md); the build has since moved on from it. For what comes next (the constant-rate tunnel and hardening), see [stage-3-roadmap.md](stage-3-roadmap.md).

---

## How It Works: The Core Mechanics

Our architecture abandons traditional messaging paradigms (like WebSockets, TCP, or central identity servers) in favor of an account-free, rateless UDP approach. Here is how the components interact:

### 1. Identity & Trust (QR Codes)
Users do not register accounts, usernames, or phone numbers. Trust is established completely out-of-band by physically scanning a QR code on a peer's device. The code holds the peer's routing token (where the relay delivers their messages) and their Ed25519 identity key, against which everything they later send is checked. Both people scan each other.

### 2. Hybrid Post-Quantum Key Exchange (PQXDH)
To protect against future quantum computers harvesting encrypted data today ("Harvest Now, Decrypt Later"), each session's handshake combines elliptic curve Diffie-Hellman (**X25519**) with the NIST-standardized Post-Quantum Key Encapsulation Mechanism, **ML-KEM-768** (FIPS 203). The two secrets are merged with HKDF into the session's root key, which stays safe unless both are broken.

Every five messages, the sender also mixes a fresh ML-KEM secret into its chain (a "PQ refresh"). These are encapsulated to the contact's long-term ML-KEM key. That keeps a session post-quantum, but doesn't heal it after a device is compromised: healing needs the ratchet planned in the roadmap (item 3.1). A refresh travels inside its message's burst; if that burst is lost, the receiver asks for it again with a signed request, and the sender, which keeps its latest 20, sends it again. Anything else that breaks a session is fixed with **Repair session**, which sets up a new one and keeps the contact and the chat history.

### 3. End-to-End Encryption (Symmetric Hash Ratchet)
Once a session is established, messages are encrypted with a **symmetric hash ratchet**, not the Double Ratchet:
- **Forward secrecy, per message:** every message gets its own key, from a chain that only moves forward (HMAC-SHA256), so earlier messages' keys can't be recovered from the current state.
- **Out-of-order delivery:** a bounded skip dictionary holds at most 500 skipped keys, and nothing more than 100 messages ahead is accepted. Used keys are destroyed.
- **In-order display:** messages are shown in the order they were sent. One that arrives ahead of an earlier one waits up to 10 seconds for it.
- **No healing yet:** without a Diffie-Hellman step, the ratchet doesn't recover from a compromise on its own (see the roadmap).

### 4. Extreme Loss Tolerance (RaptorQ FEC)
Tactical networks (like jammed radios) drop packets constantly. Standard TCP networks rely on "ACKs" (acknowledgments) to trigger retransmissions, which fails completely if loss exceeds 50%.

Instead, our Rust core uses **RaptorQ**, a Forward Error Correction (FEC) fountain code:
- **The burst:** the sender pads and encrypts the message, then sends it as a burst of symbols sized to survive **70% loss** on either side's link. That's the loss it's tested at, against the real relay.
- **Rebuilding:** the receiver rebuilds the message from any large enough subset of those symbols. There are no end-to-end ACKs.
- **Offline phones:** the relay keeps each packet until the recipient's client acknowledges it, so a phone that's offline or asleep still gets it later.
- **The ✓:** the sender asks the relay which of the burst's packets it holds (a receipt), and shows ✓ once there are enough to rebuild the message. If that doesn't happen within 30 seconds, it shows a red **!** with a retry button.
- **Contact setup:** a setup packet (KeyExchange or SessionEstablish) is a single packet, which can't be spread over FEC symbols. So to a contact who has added you back, each goes out as 3 copies, and an unanswered KeyExchange is sent again after 10 seconds, then less and less often.

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
*   [Realistic Implementation Roadmap](doable-roadmap.md): the original July plan, kept for reference
*   [Stage 3 Roadmap: Constant-Rate Tunnel and Hardening](stage-3-roadmap.md)
*   [Cryptographic Flow, as Implemented](doable-cryptographic-flow.md)
*   [Protocol Flow Diagrams](architecture-diagrams.md)
*   [How a Message Gets from Phone A to Phone B](Logan-info.md): a message's path, the ✓, and the packet formats
*   [How the Frontend / UI Works](Frontend-UI-info.md)
*   [RaptorQ FEC Transport](raptorq-fec-transport.md)
*   [Implementation Review](implementation-review.md) (5 October) and [Cryptographic Security Review](cryptographic_security_review.md) (July): dated reviews, many of whose findings have been fixed since
*   [Deploying the Relay to EC2](ec2-deployment.md) (through GitHub Actions) and [by Hand](ec2-manual-deploy.md)
*   [Tech Decision: Leptos Instead of Kotlin for the Client](tech-decision-leptos-client.md)
*   [Prerequisite Learning Guide](LEARNING.md)
