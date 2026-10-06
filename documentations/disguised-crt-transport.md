# Stage 3: Disguised Constant-Rate Transport

Branch `Logan/QUIC+CRT+Disguise`, October 2026. Builds on the RaptorQ transport ([raptorq-fec-transport.md](raptorq-fec-transport.md)) and Stage 2 (signed syncs, no presence, the relay key shipped with the app).

## 1. Summary

**Goal:** someone watching the network, or probing the relay, can't tell when people are messaging, how much, or that this is a messenger at all. Messages must still get through when a jammer drops up to 70% of one side's packets.

**What was built:**
- **QUIC on UDP 443.** The raw-UDP link layer (own handshake, session ID, link encryption, sync and ack packets) is gone. Client and relay talk QUIC (`quinn`), with ALPN `h3`, and send everything as QUIC datagrams (RFC 9221).
- **Cells at a constant rate.** Everything either side sends is a 1,150-byte **cell**, about 4 per second each way, at random (Poisson) intervals, whether or not there's anything in it. Every QUIC packet after the handshake is padded to 1,200 bytes.
- **Real TLS, pinned.** The relay presents a real certificate for a real domain (Let's Encrypt). The app pins the certificate's key, offers only the hybrid **X25519 + ML-KEM-768** key exchange, and sends no client certificate.
- **A website for everyone else.** A connection that doesn't prove it has the app's access key gets an ordinary HTTP/3 website and never a datagram.
- **No backing off under loss.** A fixed-rate congestion controller stops QUIC slowing down when packets are lost, so jamming can't throttle the stream.
- **Everything in the stream.** Acknowledgements are receipts in every cell. Contact requests (KeyExchange, SessionEstablish) go through FEC like messages.
- **Redundancy that follows measured loss.** Receipts tell each sender exactly which of its cells arrived. An object's first round of symbols is sized for the measured loss, and any shortfall is topped up until the relay has enough. The relay resends what the recipient's receipts say didn't arrive.
- **No DNS leak.** The app ships with the relay's IP address; a hostname is looked up over DNS-over-HTTPS instead.
- **Android:** a partial wake lock, a one-time request for the battery-optimisation exemption, and `measure-battery.sh`.
- **Ready for a mixnet:** the cell stream is written against a `CellTransport` trait ("send a cell / receive a cell"), with QUIC as its one implementation.

**Verified:**

| Check | Result |
|---|---|
| Real relay over real QUIC, Alice's link jammed in both directions at 0, 10, 20 … 70% (`lossy_link sweep`) | **Every message, every level, both ways** (5 each way per level). Ratchets in step. |
| Same, in-process with simulated time (`client` link tests): contacts added *under* loss, then 6 messages each way | **All delivered at 0, 10, 30, 50, 70%** |
| Capture of Alice's link, after the handshake | **One packet size: 1,200 bytes**, both directions (3,856 packets) |
| Packet rate on the clean link, idle vs both users sending (2-minute windows) | Alice → relay **7.42 vs 7.41** packets/s; relay → Alice **7.28 vs 7.55** (sampling noise); same gap spread (CV 0.94 vs 0.94) |
| ClientHello, decrypted from the capture's Initial packets | SNI = relay's name, ALPN `h3`, TLS 1.3, group **X25519MLKEM768** only (1,216-byte key share) |
| Prober without the access key | Gets the website over HTTP/3; garbage, padding and a wrong-key hello get no datagram back |
| Cells per short message | **4.0** on a clean link, **9.0** at 50% loss (sending blind for 70% would be 34+) |
| Android emulator (x86_64): build, connect, wake lock, exemption, Doze | Connects to the relay over QUIC; wake lock held; whitelisted; stays connected in forced deep idle. Battery: §10. |
| Test suites | See §12. All pass; `fmt` and `clippy -D warnings` clean on every crate. |

## 2. Decisions

| Question | Decision | Why |
|---|---|---|
| Transport | QUIC (`quinn` 0.11, `quinn-proto` 0.11.19), datagrams for cells | Looks like HTTP/3; datagrams aren't retransmitted or ordered, which suits FEC |
| TLS provider | rustls 0.23.45 with aws-lc-rs | The provider with `X25519MLKEM768`. Builds without cmake, including for Android (checked) |
| Key exchange | App offers **only** X25519MLKEM768; relay prefers it, also accepts X25519/P-256/P-384 | The app can't be downgraded; browsers visiting the website still work |
| Relay authentication | Pin SHA-256 of the certificate's SubjectPublicKeyInfo (`SERVER_PUBKEY`); ignore chain, name and expiry | A compromised CA can't impersonate the relay; the cert can be renewed if the key is kept (`--reuse-key`) |
| Client authentication | None at the TLS level. First cells carry a **hello**: HMAC under the app's access key, plus a routing-token ownership signature, both bound to a TLS exporter value | The relay never sees the identity key (Stage 2 follow-up); probers without the key see only a website; a hello can't be replayed on another connection |
| Session identifier | QUIC connection IDs, rotated every 10 minutes and on migration | Replaces the 4-byte session ID that was in every packet in the clear |
| Cell size | 1,150 bytes | Fits a 1,200-byte QUIC packet (1,162 bytes of datagram room with 8-byte connection IDs), and one sealed FEC symbol (1,093 bytes) per cell |
| Packet size | Every 1-RTT packet padded to 1,200 bytes (`pad_to_mtu`), MTU discovery off | One size on the wire, ACK-only packets and loss probes included. 1,200 crosses every path, IPv6 tunnels too |
| Rate | 4 cells/s each way, exponential gaps (Poisson) | Rate from the stage plan. Random gaps avoid a fixed beat, and the schedule never looks at the queue |
| Congestion control | `FixedRate`: a constant 1 MiB window, never reduced | Loss mustn't slow the stream. The cell clock is the rate limiter |
| Reliability, uplink | FEC, first round sized by measured loss (99% chance of enough), then top-ups from receipts until the relay holds `K + h` symbols | Low latency, no blind 70% budget, and no message is stuck if loss rises mid-send |
| Reliability, downlink | The relay resends whatever the recipient's receipts show was lost | The relay can't re-encode sealed symbols; selective repeat on one hop is cheap |
| Acks | Receipt (highest seq + 64-bit bitmap) in every cell | Batched by construction, and inside the stream |
| Contact requests | FEC objects of plain symbols (new inner type `0x08`) | No session yet, so no seal key; the payloads inside are signed. Now they survive loss too |
| Relay address | Shipped in the app as an IP; a hostname goes over DNS-over-HTTPS (Cloudflare, then Quad9) | No plaintext DNS query saying who's being contacted |
| Android | Partial wake lock in the foreground service; ask once for the battery-optimisation exemption | Doze would otherwise freeze the stream, and its gaps would show |
| Mixnet | `CellTransport` trait in the shared `cell` crate | The cell stream doesn't know it runs over QUIC |

## 3. How a message travels now

```
CLIENT A                                   RELAY                                 CLIENT B
create_message                             (per link, Poisson clock, 4/s)
  ratchet-encrypt chunks (+ PQ inject)
  bundle -> FEC object -> Outgoing
link.send(Outgoing)
  every Poisson tick (4/s): one cell
    [seq | receipt | Forward{to: B, symbol}]   -> parse, record seq
      or [seq | receipt] if nothing's due      -> settle our cells from its receipt
                                               -> queue symbol for B
  receipts from the relay                      every tick: one cell to B
    -> which symbols arrived                     [seq | receipt | Deliver{symbol}]  -> handle (decode,
    -> loss estimate                             or padding                            decrypt, inbox)
    -> top up until relay has K+h                B's receipts: drop delivered,      -> record seq
                                                 resend lost                           (after handling)
```

Above the transport nothing changed: the ratchet, PQ injections, the seal, the FEC objects, and the signed contact requests are as before.

## 4. Wire formats

### 4.1 On the wire

QUIC v1, UDP 443. Handshake: the client's Initial packets (padded to 1,200 by QUIC) carry a ClientHello with SNI, ALPN `h3`, TLS 1.3 and an X25519MLKEM768 key share; the server's reply carries the hybrid ciphertext and its certificate. After that, every packet in both directions is a 1,200-byte short-header packet. Its contents (cells, ACK frames, the relay's HTTP/3 SETTINGS) are encrypted.

### 4.2 Cell (QUIC datagram payload, `code/cell/src/format.rs`)

```
[4 seq][4 receipt largest][8 receipt bitmap]      header, big-endian
([1 type][2 len][len bytes])*                     frames
[0x00 ...]                                        padding to 1,150 bytes
```

- `seq`: this side's cell number on this link, from 1.
- Receipt: the highest of the other side's `seq` received (0 = none yet), and a bitmap of the 64 before it (bit `i` = `largest - 1 - i` arrived). A cell more than 3 behind the newest one reported, but not reported itself, counts as lost.

| Frame | Type | Direction | Body |
|---|---|---|---|
| Hello | 1 | client → relay | access proof (32) ‖ routing token (16) ‖ token public key (32) ‖ signature (64) |
| Forward | 2 | client → relay | recipient token (16) ‖ payload (≤ 1,115) |
| Deliver | 3 | relay → client | payload (≤ 1,131) |

Unknown frame types are skipped, so either end can add one later.

### 4.3 Hello (`code/cell/src/proof.rs`)

```
binding      = TLS exporter("EXPORTER-e2e-messenger/link/v1", 32 bytes)   (both ends derive it)
access proof = HMAC-SHA256(access key, "e2e-messenger/access/v1" ‖ binding)
signature    = Ed25519(token key, "e2e-messenger/sync/v2" ‖ HKDF(binding, "sync-binding"))
routing token = SHA-256("e2e-messenger/routing-token/v1" ‖ token public key)[..16]   (unchanged)
```

The relay checks the access proof first, in constant time, and ignores a connection's datagrams until a hello passes. The client puts the hello in every cell until the relay's first cell arrives.

### 4.4 Payloads (what Forward and Deliver carry)

| Type | What | Size |
|---|---|---|
| `0x07` | Sealed FEC symbol of a chat object (unchanged) | 1,093 |
| `0x08` **new** | Contact-request symbol: `[0x08 ‖ sender token (16) ‖ FEC packet]`. The object is one bundled KeyExchange (`0x02`) or SessionEstablish (`0x04`) from that sender. | ≤ 1,053 |

Bare `0x01`/`0x02`/`0x04`/`0x05` are still accepted by `handle_incoming_packet` (tests use them), but front ends only send `0x07` and `0x08`.

### 4.5 Removed

The relay handshake (types 0, 2), link-encrypted data (1), acks (3) and syncs (4); the 4-byte session ID; delivery IDs; dummy packets with inner type `0x00`; the client's `server_addr`, `link_master_key` and `session_id` (old state files still load: the fields are ignored); `BurstSender`/`send_burst`; the 15 s keepalive.

## 5. What each party can see

| | Before (raw UDP) | After |
|---|---|---|
| **On-path observer** | UDP 443 that isn't QUIC; a fixed 4-byte session ID in every packet; packet timing and count per message (bursts) | QUIC with ALPN `h3` and the relay's domain in SNI; one packet size; ~7.4 packets/s each way whether idle or busy; connection IDs that rotate |
| | The client's identity key in the handshake, in the clear | Nothing about the user |
| | Ephemeral X25519 only: recorded traffic falls to a future quantum computer | X25519 + ML-KEM-768 |
| | DNS query for the relay's name (if a name was used) | None (IP shipped), or DNS-over-HTTPS |
| **Active prober** | A UDP service answering a specific handshake | An HTTP/3 website with a valid certificate. Datagrams without a valid hello get nothing back |
| **Relay** | Client identity key, routing tokens, who sends to whom, timing | Routing tokens, who sends to whom, timing. No identity key |

The relay still learns the social graph; hiding it from the relay is the mixnet stage's job.

## 6. Rate and redundancy

**The clock.** Each end sends a cell, then waits an exponentially distributed gap (mean 250 ms), drawn from the OS RNG. It never looks at the queue. After a stall (busy runtime, phone waking), the next gap is measured from when the cell actually went, so a stall delays the stream rather than releasing a burst.

**The client's queue** (`code/client/src/link.rs`, `SendQueue`) holds objects oldest first. For each tick it picks the oldest object for which

```
symbols in flight  <  sends_for(needed - confirmed, loss, 1%)
```

and sends that object's next symbol (each one new: source symbols, then repair symbols at ever-higher indices). `needed` is `K + h` with `h` from the decode target (1 for messages, 2 for PQ-carrying messages and contact requests). `sends_for` is the smallest number of sends with a 99% chance of at least that many arriving. Receipts move symbols from in flight to confirmed or lost. An object leaves the queue once the relay has confirmed `needed` symbols. If the link drops, everything in flight counts as lost and is topped up on the next link.

**The loss estimate** (`cell::LossEstimate`) is the larger of a fast average (last ~8 cells) and a slow one (last ~64), starting at 30%. It's clamped to 5–95% for planning, so a perfectly clean link still gets one spare symbol.

**The relay** keeps each queued payload until a receipt shows its cell arrived. A lost cell's payload goes back in line (oldest first); so does anything in flight on a link that closes.

**Costs.** At 4 cells/s plus QUIC's ACK-only packets (also padded), each direction carries about 7.4 packets/s × 1,200 B ≈ **8.9 KB/s, ~770 MB a day**, whatever the user does. That's the price of the rate the stage plan chose; `CELLS_PER_SECOND` is one constant. A short message takes about 4 cells on a clean link (~1 s), 9 at 50% loss.

## 7. QUIC settings (`code/cell/src/quic.rs`, both ends)

| Setting | Value |
|---|---|
| `initial_mtu` = `min_mtu` | 1,200; MTU discovery off |
| `pad_to_mtu` | on: every 1-RTT packet padded to 1,200 bytes, ACK-only packets and loss probes included |
| Congestion controller | `FixedRate`: window 1 MiB, never reduced |
| Connection IDs | 8 bytes, retired every 10 minutes (`RandomConnectionIdGenerator::set_lifetime`) |
| Idle timeout | 30 s (cells keep it busy; no keep-alives) |
| ALPN | `h3` |

**ACK-only packets.** QUIC acknowledges datagrams. With cells ~250 ms apart, most ACKs can't ride on an outgoing cell, so each side sends ~3.4 ACK-only packets a second. They're padded like everything else and their timing follows the other side's (constant-rate) cells, so they reveal nothing, but they nearly double the packet count. The ACK-frequency extension can't help: quinn caps a requested ACK delay at the RTT.

## 8. Relay (`code/server`)

| | Before | After |
|---|---|---|
| Listener | UDP socket | `quinn` endpoint (and HTTP/3 via `h3`/`h3-quinn` for the website) |
| Identity | Ed25519 key in `server_identity.json` | TLS certificate: `TLS_CERT`/`TLS_KEY` (Let's Encrypt) or a saved self-signed one; access key in `relay_access_key` |
| Who a token's packets go to | Last address that synced it | The link that proved it owns it (a newer link takes over and the old one is closed) |
| Output | On arrival, 5 ms pacing, resend with backoff 2–60 s | Each link's own Poisson clock, a cell every ~250 ms, real or padding |
| Delivery confirmation | Delivery-ID acks | Cell receipts |
| Resends | Timer backoff | When a receipt shows the cell was lost, or the link closed unconfirmed |
| Unauthenticated connections | n/a | Website only, datagrams ignored |
| Code | one binary | library (`link`, `stores`, `site`, `tls`) + thin binary, so the client's tests can run the real relay logic |

`--print-pubkey` now prints the key pin; `--print-access-key` is new. Nothing listens on TCP.

## 9. Client and front ends

- **`code/cell` (new crate):** cells and frames, receipts and the loss estimate, the Poisson clock, the hello, the QUIC settings and `CellTransport`. Shared by client and relay.
- **`code/fec`:** `ObjectEncoder` (hands out any symbol index on demand, for top-ups), `symbols_needed`, `sends_for`.
- **`client::transport`:** `Outgoing`, an FEC object that produces symbols on demand, sealed (`0x07`) or plain (`0x08`). `FecReceiver` reassembles contact requests too.
- **`client::link` (new):** `RelayConfig` (IP as is, or DNS-over-HTTPS), `RelayLink` (connects, says hello, runs the cell stream, reconnects with backoff 1–30 s, queues while down), the pinned-key verifier, `Handler`.
- **`Client`:** `create_message` → `Outgoing` (was `create_fec_packets`); `add_contact`, `create_kx_request` and `handle_incoming_packet` return `Outgoing` replies; no link state. A delivery whose handler returns `None` isn't acknowledged, so the relay delivers it again.
- **CLI:** `client <pin>` with `SERVER_ACCESS_KEY` (and `SERVER_ADDR`, `SERVER_NAME`) set.
- **Tauri:** `bootstrap` starts a `RelayLink` and waits up to 20 s for it; the receive loop and 15 s keepalive are replaced by the link's handler; Android's "app resumed" now means "reconnect now if down". `send_message` queues: it no longer fails because the network is down.

## 10. Android

- `MessageService` holds a `PARTIAL_WAKE_LOCK` (`e2e-messenger:relay-link`) for as long as it runs, i.e. while someone is logged in. Without a timeout, deliberately: the stream has no natural end, and logging out releases it.
- On the first login after install, the app asks to be exempted from battery optimisation (`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`); the answer is remembered and not asked again. Without it, Doze cuts the app's network access while the phone is idle, wake lock or not.
- Manifest: `WAKE_LOCK`, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`.

**Checked on the emulator** (Android 15, x86_64, `./build-apk.sh --emulator`): the APK builds (aws-lc and ML-KEM cross-compile for Android), Connect reaches the relay over QUIC, the service runs in the foreground holding the wake lock, the exemption prompt appears and "Allow" puts the app on Doze's whitelist, and the link stays up with the screen off in forced deep idle.

**Battery** (`./measure-battery.sh`), on the emulator: 20 minutes logged in, with the screen off and the device forced into deep idle.

| | Result |
|---|---|
| Wake lock | Held the whole 20 minutes |
| Link | Stayed up throughout (the relay never saw it close) |
| CPU, whole app (debug APK, WebView included) | 40 s in 20 minutes (19 s user, 21 s system): **3.4% of one core** |
| CPU, the link alone (CLI, optimised build, desktop CPU, idle) | 0.18 s a minute: **0.3% of a core** |
| Estimated drain | 0.04 mAh: meaningless, from the emulator's placeholder power profile |

So the cells themselves cost little CPU; the debug build and the WebView account for most of the app's share. What the emulator can't show is the radio: a packet every ~70 ms in each direction never lets a phone's cellular or Wi-Fi radio drop into its idle states, and on a real phone that's most of the cost. **Measuring that needs a real phone** (`./measure-battery.sh 60` over USB, and `--baseline 60` logged out to compare); it hasn't been done yet.

## 11. Deployment

1. **Domain:** an `A` record for the relay's name (e.g. `relay.example.com`) → its Elastic IP.
2. **Certificate:** Let's Encrypt with `--reuse-key` (DNS challenge, or open TCP 80 only while issuing); mount `/etc/letsencrypt` and set `TLS_CERT`/`TLS_KEY`. The deploy workflow does this when the `RELAY_DOMAIN` secret is set.
3. **Security group:** UDP 443 in. No TCP.
4. **Build the app with:** `SERVER_ADDR=<IP>:443`, `SERVER_NAME=relay.example.com`, `SERVER_PUBKEY` (`server --print-pubkey`), `SERVER_ACCESS_KEY` (`server --print-access-key`).

Step by step: [ec2-deployment.md](ec2-deployment.md). Local testing is unchanged (`./runserver.sh`, `./runpeer.sh`, `./build-apk.sh`); the scripts now fetch the access key too.

**Breaking:** the relay and every client must be updated together. Old clients can't reach a new relay, and vice versa.

## 12. Testing

| Crate | Tests | New or rewritten |
|---|---|---|
| `code/cell` (new) | 16 | all: framing, malformed cells, receipts, loss estimate, Poisson gaps and rate, hello (access, replay on another connection, someone else's token) |
| `code/fec` | 28 | 3: overhead and `symbols_needed`, `sends_for`, top-up symbols decode |
| `code/server` | 11 | all, over real QUIC in-process: website for a prober (and no datagrams), forwarding and forgetting delivered packets, resending a lost cell, offline queue and a link dropping unconfirmed, constant output rate busy or idle; queue unit tests |
| `code/client` | 125 | link (9): 0–70% loss end to end with contacts added under loss, constant rate idle vs busy, adaptive redundancy, reconnect mid-message, unacknowledged redelivery, two apps over real QUIC, wrong pin refused, wrong access key never answered, address parsing. Transport: contacts over a lossy link, contact-request objects only carry the sender's request, top-ups. |
| `code/frontend/src-tauri` | 13 | (one removed: the relay address is no longer saved state) |
| `code/frontend` | 10 | unchanged |

The link tests run the real relay logic (`server::link`) and the real client loop over in-memory links that drop a set fraction of cells, on Tokio's paused clock, so ten simulated minutes take about a second, deterministically, in CI.

**Real network:** `cargo run --example lossy_link -- <pin> <access key> sweep alice 5` (relay running) connects two clients through lossy proxies, measures a clean-link capture (idle, then both sending), then runs every loss level. `CAPTURE=file.pcap` saves Alice's side for Wireshark; `CAPTURE_SECS` sets the idle and busy spells.

| Loss on Alice's link (both directions) | Alice → Bob | Bob → Alice | Time for 5 + 5 |
|---|---|---|---|
| 0% | 5/5 | 5/5 | 6 s |
| 10% | 5/5 | 5/5 | 8 s |
| 20% | 5/5 | 5/5 | 7 s |
| 30% | 5/5 | 5/5 | 7 s |
| 40% | 5/5 | 5/5 | 9 s |
| 50% | 5/5 | 5/5 | 12 s |
| 60% | 5/5 | 5/5 | 14 s |
| 70% | 5/5 | 5/5 | 18 s |

## 13. Known limitations and follow-ups

1. **TLS fingerprint.** rustls's ClientHello differs from a browser's (extension set and order, no GREASE), and offering X25519MLKEM768 *alone* is unusual: browsers also offer X25519. A JA4-style fingerprint can tell it from Chrome. Mimicking a browser's ClientHello isn't possible with rustls today.
2. **Long-term shape.** Each packet looks ordinary, but a connection that runs all day at ~7 same-size packets a second each way doesn't look like browsing. Hiding *that* needs cover in real traffic (or the mixnet).
3. **No TCP website.** Real sites serve HTTPS over TCP and advertise HTTP/3 with Alt-Svc; this relay is HTTP/3 only (an `HTTPS` DNS record with `alpn="h3"` lets browsers find it). Serving the same site on TCP 443 would close the gap, at the cost of the TCP surface Stage 2 removed.
4. **One access key for every copy of the app.** Extracting it from the APK lets a censor confirm a relay. Per-user or per-invite credentials would fix that.
5. **Data and battery.** ~770 MB a day each way, and the radio never idles. Fewer cells per second cut both at the price of latency; it's one constant.
6. **The relay resends every symbol it got,** including ones beyond what the recipient needs. With both links lossy that's wasted downlink cells.
7. **A link's first seconds:** until receipts arrive, sizing assumes 30% loss (top-ups correct it). The QUIC handshake itself is retransmitted by QUIC's own timers, so under heavy jamming connecting takes longer (the tests add contacts under loss but connect the link first).
8. **The certificate's expiry is ignored by the app** (it trusts the pinned key). An expired certificate would still show to visitors, so renewals matter. A key change means rebuilding every app.
9. **DNS-over-HTTPS** tells Cloudflare or Quad9 the relay's name; shipping the IP avoids even that.
10. **Still only relay-to-recipient reliability.** A message is lost if the relay restarts with it queued (RAM only), as before.
11. **`lossy_link` is still manual** (needs a running relay), but the link tests cover the same ground in CI with the real relay logic.

## 14. Tuning knobs

| Constant | Where | Default |
|---|---|---|
| `CELLS_PER_SECOND` | `cell/src/pace.rs` | 4 |
| `CELL_LEN` | `cell/src/format.rs` | 1,150 |
| `MTU` | `cell/src/quic.rs` | 1,200 |
| `CID_LIFETIME`, `IDLE_TIMEOUT`, `FIXED_WINDOW` | same | 10 min, 30 s, 1 MiB |
| Loss estimate prior and weights | `cell/src/window.rs` | 30%; 1/8 and 1/64 |
| `ROUND_SHORTFALL`, `MIN/MAX_PLANNED_LOSS` | `client/src/link.rs` | 1%; 5% / 95% |
| `CONNECT_TIMEOUT`, `HELLO_TIMEOUT`, retry backoff | same | 30 s, 30 s, 1–30 s |
| `MESSAGE/PQ_MESSAGE/CONTROL_MAX_FAILURE` | `client/src/transport.rs` | 1e-4 / 1e-6 / 1e-6 |
| `MESSAGE_TTL`, `MAX_QUEUED_BYTES_PER_TOKEN` | `server/src/link.rs`, `stores.rs` | 7 days, 2 MiB |
