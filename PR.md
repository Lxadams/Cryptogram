Logan - Stage 3: disguised constant-rate transport (QUIC + CRT)

Full write-up, wire formats and measurements: [documentations/disguised-crt-transport.md](documentations/disguised-crt-transport.md).

### Changes in this PR:

**Move to QUIC**

1. **The link is QUIC on UDP 443** (`quinn` 0.11, rustls 0.23.45 with aws-lc-rs). Cells travel as QUIC datagrams (RFC 9221), with ALPN `h3`. The raw-UDP link layer is gone: its handshake, 4-byte session ID, link encryption, syncs, acks and dummy packets.
2. **The relay has a real certificate, and the app pins its key.**
   - **Production:** `TLS_CERT`/`TLS_KEY` (Let's Encrypt, renewed with `--reuse-key`).
   - **Locally:** a saved self-signed certificate.
   - **The pin:** `SERVER_PUBKEY` is now SHA-256 of the certificate's public key (`server --print-pubkey`). The app trusts that key and nothing else, whoever signed the certificate.
3. **What this fixes:**
   - **The identity key is no longer sent.** The client stays anonymous at the TLS level, which closes Stage 2's follow-up.
   - **No persistent session ID.** QUIC connection IDs rotate every 10 minutes and on a network change.
   - **Post-quantum key exchange.** The app offers only X25519MLKEM768, decrypted from the capture to confirm. Recorded traffic stays safe from a future quantum computer.
4. **QUIC doesn't slow down under loss.** A fixed-rate congestion controller never shrinks its window, so jamming can't throttle the stream.
5. **Probing gets a website.**
   - **The relay serves HTTP/3** (`h3`) to every connection.
   - **Cells need the app's access key.** A connection's datagrams are ignored, and it gets none back, until a cell carries a valid hello. The hello is an HMAC under the access key (`SERVER_ACCESS_KEY`, `server --print-access-key`), plus the Stage 2 token-ownership signature. Both are bound to a TLS exporter value, so a hello can't be replayed on another connection.
   - `SITE_DIR` serves your own pages.

**The constant-rate tunnel**

6. **New shared `code/cell` crate:**
   - 1,150-byte cells (sequence number, receipt, frames, padding)
   - receipt bookkeeping and a loss estimate
   - the Poisson clock
   - the hello
   - the QUIC settings
   - `CellTransport`
7. **Client send loop** (`client::link::RelayLink`): one cell per tick of a Poisson clock averaging **4 cells/s**, real or padding. It reconnects by itself and queues while down.
8. **The relay sets its own output timing.** Each link has its own Poisson clock, whatever is queued.
9. **Everything is in the stream.**
   - **Acks:** every cell carries a receipt for the other side's cells (highest seq plus a 64-bit bitmap), so acks are batched by construction.
   - **Contact requests go through FEC:** KeyExchange and SessionEstablish travel as FEC objects of plain symbols (new inner type `0x08`), so adding a contact survives loss too.
10. **FEC redundancy adapts to measured loss.**
    - **Measured, not assumed:** receipts tell the client exactly which symbols reached the relay.
    - **Each object's first round** is sized for the measured loss (a 99% chance of enough).
    - **Top-ups:** any shortfall is topped up with fresh repair symbols until the relay holds `K + h`.
    - **The relay's side:** it resends whatever the recipient's receipts show was lost.
    - **Cost:** a short message takes about 4 cells on a clean link and 9 at 50% loss, against the 34 the old fixed 70% budget spent everywhere.
11. **Every packet is the same size.** QUIC pads every packet after the handshake to 1,200 bytes (`pad_to_mtu`, MTU discovery off), ACK-only packets included.

**Everything else**

12. **No DNS lookup to see.** Ship the relay's IP in `SERVER_ADDR`, and nothing is looked up. A hostname is resolved over DNS-over-HTTPS (Cloudflare, then Quad9), never plaintext DNS. `SERVER_NAME` is the certificate's name, sent as SNI.
13. **Android:**
    - **Wake lock:** the foreground service holds a partial wake lock while someone is logged in.
    - **Battery optimisation:** the app asks once for the exemption. Doze ignores wake locks without it.
    - **Measuring:** new `./measure-battery.sh` measures the cost with Android's batterystats.
14. **Ready for a mixnet.** The cell stream is written against `CellTransport` ("send a cell / receive a cell"), and QUIC is just its implementation. The relay's link loop is generic too.
15. **Code moves:**
    - **The relay** is now a library plus a thin binary, so the client's tests run the real relay logic.
    - **`fec`:** gains `ObjectEncoder` (any symbol on demand), `symbols_needed` and `sends_for`.
    - **`Client`:** `create_fec_packets` became `create_message`. It returns an `Outgoing` object, as do contact requests and replies.
    - **Tauri:** the receive loop and the 15 s keepalive are replaced by the link's handler.
16. **Scripts and docs:**
    - **Scripts:** `runpeer.sh`, `runpeer-lan.sh`, `build-apk.sh` and `runserver-lan.sh` handle the access key.
    - **Docker:** Compose gives the relay a fixed IP for the CLI container, and the Dockerfiles copy `cell/`.
    - **CI:** `code/cell` joins the matrix.
    - **Deploy:** the workflow mounts the Let's Encrypt certificate when a `RELAY_DOMAIN` secret is set.
    - **Docs:** the server, frontend, ANDROID, EC2 and overview docs are updated.

### ⚠️ Wire format and deployment
Everything here is breaking. **Deploy the relay and update every client together.**
- **Old and new can't talk:** old clients can't reach a new relay, and new clients can't reach an old one.
- **Two keys per build:** every build needs `SERVER_PUBKEY` (now the key pin) and `SERVER_ACCESS_KEY`. A production build also needs `SERVER_NAME`, and `SERVER_ADDR` as an IP is best.
- **The pin changes once:** the relay's old Ed25519 identity (`server_identity.json`) is no longer used. The new values live in the same `/data` volume and stay stable from here on.
- **Production certificate** (`documentations/ec2-deployment.md`):
  1. Point a domain at the relay.
  2. Get a Let's Encrypt certificate with `--reuse-key`.
  3. Set the `RELAY_DOMAIN` secret.
- **Saved identities and chats carry over.** Old state files load, and their link fields are ignored.

### Testing
- **Unit and integration tests:** all passing; `fmt` and `clippy -D warnings` clean on every crate.

  | Crate | Tests |
  |---|---|
  | cell (new) | 16 |
  | fec | 28 |
  | server | 11, rewritten, over real QUIC in-process |
  | client | 125, including 9 new link tests |
  | Tauri | 13 |
  | frontend | 10 |

  - **Client link tests:** these run the real relay logic and the real client loop over in-memory lossy links, on a paused clock. They cover:
    - contacts added and 6 messages each way at **0, 10, 30, 50 and 70%** loss on one side
    - the same cell rate idle and busy, in both directions
    - adaptive redundancy (4 cells per message clean, 9 at 50%)
    - a link dropping mid-message
    - a delivery the app couldn't handle being delivered again
    - two apps talking over real QUIC
    - a wrong pin refused
    - a wrong access key never answered
  - **Server tests:**
    - a prober gets the website and no datagrams
    - forwarding, and forgetting delivered packets
    - resending a cell reported lost
    - offline queues, and a link that drops unconfirmed
    - a constant output rate
- **Real relay over real QUIC** (`lossy_link sweep`), Alice's link jammed in both directions:
  - **Every loss level 0–70%:** 5/5 messages each way at 0, 10, 20 … 70%, in 6–18 s per level, ratchets in step.
- **Capture of Alice's link:**
  - **One size:** after the handshake, every packet both ways is **1,200 bytes** (3,856 packets).
  - **Same rate idle or busy:** over 2-minute windows on the clean link, Alice sent **7.42 packets/s idle vs 7.41** while both users were sending; the relay sent 7.28 vs 7.55, within sampling noise.
  - **Decrypted ClientHello:** SNI, ALPN `h3`, TLS 1.3, X25519MLKEM768 only.
  - `CAPTURE=file.pcap` saves it for Wireshark.
- **Android emulator** (Android 15, x86_64):
  - **Builds:** the APK builds, so aws-lc and ML-KEM cross-compile for Android.
  - **Connects:** Connect reaches the relay over QUIC.
  - **Background:** the wake lock is held, and the exemption prompt puts the app on Doze's whitelist. The link stays up with the screen off in forced deep idle.
  - **Battery:** over 20 minutes, with the screen off in forced Doze:
    - the wake lock was held throughout and the link stayed up
    - the whole app (debug build, WebView included) used 3.4% of a core
    - the link alone, in an optimised build, uses 0.3% of a core on a desktop
    - the emulator's mAh figure comes from a placeholder power profile, so it means nothing
    - the radio, which dominates on a real phone, still needs measuring on one
- **Not tested yet:**
  - two real phones
  - battery on a real phone (the emulator's mAh figures come from a generic power profile)
  - a real domain and Let's Encrypt certificate
  - the desktop app clicked through
  - the Docker Compose CLI

### Follow-ups
- **TLS fingerprint.** rustls's ClientHello isn't a browser's: different extensions, no GREASE, and only the PQ group on offer. A JA4-style fingerprint can tell it apart.
- **Long-term shape.** Each packet looks ordinary, but a connection running all day at ~7 same-size packets a second each way doesn't look like browsing.
- **No TCP website.** Real sites also serve HTTPS over TCP. An `HTTPS` DNS record with `alpn="h3"` lets browsers find this one.
- **One access key for every copy of the app.** Extracting it from an APK lets a censor confirm a relay.
- **Data and battery.** About 8.9 KB/s each way (~770 MB/day) including QUIC's padded ACK-only packets, which quinn can't delay past the RTT. `CELLS_PER_SECOND` is the one knob.
- **The relay resends every symbol it got,** including ones beyond what the recipient needs.
- **The relay still sees who talks to whom.** That's for the mixnet stage.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
