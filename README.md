# E2E-Messenger
Compx374 industry project 

## Project Summary

E2E-Messenger is a highly secure, post-quantum resilient, and extreme-loss tolerant tactical messenger designed for rugged operational environments. The architecture is engineered to provide absolute metadata privacy, censorship evasion, and reliable communication even under 95% network packet loss.

### Key Architectural Features:
* **Post-Quantum Cryptography:** Utilizes a Hybrid PQXDH handshake (ML-KEM-768 and X25519) and ML-DSA-65 signatures to provide robust Post-Quantum Forward Secrecy and Post-Compromise Security.
* **Constant-Rate Tunnel (CRT):** Defeats traffic analysis and metadata correlation via metronomic 100ms packet transmissions, ensuring a global passive adversary cannot distinguish between active communication and dummy traffic.
* **Extreme Loss Tolerance:** Employs Interleaved RaptorQ Forward Error Correction (FEC) to guarantee message delivery without relying on ACKs, tolerating up to 95% packet loss.
* **Censorship Evasion:** Encapsulates UDP datagrams within standard HTTP/3 (QUIC) frames to bypass Deep Packet Inspection (DPI) firewalls, appearing as normal HTTPS traffic.
* **Blind Routing & Garbage Collection:** Routes messages through an AWS Relay using rotating ephemeral tokens and blinded deletion tokens. The relay has zero knowledge of the sender, receiver, or message contents, and runs completely in volatile memory (`tmpfs`).
* **Tactical Hardware Integration:** Integrates tightly with Samsung Knox Vault for secure hardware storage of master seeds and classical identity keys, utilizing Knox DualDAR for data-at-rest encryption.
* **Ephemeral Multicast Routing:** Supports group chats using ephemeral multicast tokens and Signal Sender Keys to preserve bandwidth while avoiding persistent group topologies on the server.

For detailed architecture and phase-by-phase implementation plans, please refer to the [ROADMAP.md](ROADMAP.md) and [implementation_roadmap.md](implementation_roadmap.md).
