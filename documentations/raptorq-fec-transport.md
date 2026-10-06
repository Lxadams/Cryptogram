# RaptorQ FEC Transport: Change Write-up

Branch `claude/raptorq-e2e-integration-2c36af`, 5 October 2026. Companion document: [implementation-review.md](implementation-review.md), a review of the whole system as it now stands.

## 1. Summary

**Goal:** Client A can send and Client B can receive while the jammed side's link loses up to **70% of all packets**. This must work with no ACKs, no retransmission and no change to the trust model.

**What was built:**
- **Burst sending.** Every chat message now travels as a burst of RaptorQ (RFC 6330) forward-error-correction symbols. The receiver rebuilds the message from *any* sufficient subset of them.
- **End-to-end sealing.** Each symbol is sealed with a key only the two clients hold, so the relay forwards opaque packets and can't reassemble anything.
- **PQ injections bundled with their message.** The ratchet's post-quantum injection (every 5th message) now travels inside the same burst as its message. Previously one lost or reordered injection packet desynchronised a session permanently; now the pair arrive together or not at all.
- **PQ injections name their chain position** (`applies_at`, from the message-padding PR #35). The receiver mixes each one in at exactly that point however early or late it arrives, and ignores copies. Its signature also covers a session binding, so it can't be replayed into a later session.
- **Fixed-size packets** (also PR #35). Every chat chunk is padded to a 1,024-byte block, so every FEC symbol is full size and every datagram is 1,154 bytes whatever the message length. Long messages (up to 16,176 bytes) are split into chunks, all carried in one burst.
- **Pacing.** Bursts are paced 10 ms per packet, one burst at a time in send order, so a short jamming spike can't take a whole message. The relay forwards a packet the moment it arrives and paces each recipient's backlog at 5 ms per packet, so it never re-bunches bursts.

**Verified:**

| Check | Result |
|---|---|
| 1,000 messages in-process, 70.2% measured packet loss, bursts reordered | **1000/1000 delivered**, ratchets in step after 200 PQ injections |
| Real relay over real UDP, sender jammed at 70% | **40/40** (70.9% of packets dropped) |
| Real relay over real UDP, receiver jammed at 70% | **40/40** (69.8% dropped) |
| Real relay, one side jammed at **80%** (beyond the target) | **30/30** each way |
| Real relay, **both** sides jammed at 70% (≈91% end to end, well beyond the target) | 28/30 and 26/30. Degrades gracefully and the session survives. |
| Test suites, all crates | **163 tests, all passing** (client 114, relay 10, fec 25, Tauri 14), `fmt` and `clippy -D warnings` clean |

## 2. Decisions

| Question | Decision | Why |
|---|---|---|
| Loss model | 70% on the jammed side's link only: the sender's uplink or the receiver's downlink. The non-jammed side is clean. | Models jamming of one party. End to end, each packet survives with probability 0.3. |
| Where FEC runs | **End to end**, client to client | Only the clients may repair their messages. The relay is just a relay. |
| What the relay sees | Each symbol sealed with a per-contact key | The relay can't group symbols into messages, let alone rebuild one |
| Sending style | **Burst** (SATCOM-like): all of a message's symbols go out at send time, paced 10 ms apart | Low latency at this loss level. A constant-rate tunnel would need 2–8 s per short message at a 100 ms tick. Left for later; the FEC layer doesn't depend on the scheduler. |
| Delivery target | 99.99% per message. 99.9999% for messages carrying a PQ injection, since losing one of those used to desync the session. | Agreed trade-off between reliability and airtime |
| In scope | Chat messages (0x01) and PQ injections (0x05) | Contacts are added face to face via QR codes, and that handshake isn't digital in the lossy setting |
| Out of scope | Relay handshake, sync/keepalive, KeyExchange (0x02), SessionEstablish (0x04), presence (0x06) | Assumed done on a clean link, as agreed |
| Packet format | One new inner payload type, `0x07`. (`0x01` padding and `0x05`'s `applies_at` came with PR #35.) | "Don't change the packet structure too much" |

## 3. How a message travels now

```
SEND (Client A)
  plaintext
    -> split into chunks, pad each to 1,024 B (PR #35)
    -> symmetric-ratchet encrypt each chunk   (one 0x01 payload per chunk)
    -> every 5th step: + PQ injection         (0x05 payload, with `applies_at`)
    -> bundle: [2-byte len | payload]...      (one FEC "object")
    -> RaptorQ encode into N symbols          (N from fec::packets_for)
    -> seal each symbol end to end            (XChaCha20-Poly1305, per-contact key)
    -> link-encrypt each, as before           (unchanged)
    -> BurstSender: one packet every 10 ms, one burst at a time

RELAY (unchanged logic)
  link-decrypt -> read recipient token -> queue -> re-encrypt for recipient
  (forwarded on arrival, backlogs paced 5 ms/packet, queue cap 2 MiB per recipient,
   each packet kept until the recipient acks it)

RECEIVE (Client B)
  link-decrypt (unchanged) -> inner type 0x07
    -> look up the session by sender token -> open the seal
    -> fec::Reassembler: once any ~K symbols are in, the object is rebuilt
    -> unbundle -> each 0x01 / 0x05 part goes through the existing handlers
    -> a message that arrived ahead of its PQ injection is held, then
       retried once the injection lands
```

Everything above the transport is unchanged: the ratchet, the PQ maths, the signatures, the link layer and the relay's routing.

## 4. Packet formats

### 4.1 Layering on the wire

The outer (link) layer is unchanged:

```
UDP payload (client -> relay):
[0x01 TYPE_DATA | 4 session id | 24 nonce | XChaCha20-Poly1305_link( 16 recipient token | inner ) | 16 tag]
```

New inner payload `0x07` is a sealed FEC symbol:

```
[0x07 | 16 sender token | 24 nonce | XChaCha20-Poly1305_seal( FEC packet ) | 16 tag]

seal key = HKDF-SHA256(salt = "e2e-messenger-v1", ikm = session root key, info = "fec-symbol-seal")
AAD      = 0x07 || sender token || recipient token
```

FEC packet (`code/fec`), all fields big-endian:

```
[4 object id | 4 object length | 4 symbol id | symbol (T bytes)]

T (symbol size) = object length rounded up to a multiple of 8, capped at 1024.
                  Derived from the length on both sides, never sent.
symbol id       = 0..K-1 for source symbols, K.. for repair symbols (RFC 6330 ESI, 24-bit).
object id       = the message's sequence number (unique within a session;
                  the receiver keeps each session's ids apart).
```

FEC object (bundle):

```
( [2 len | 0x01 chunk payload] )+ ( [2 len | 0x05 PQ injection payload] )?
```

### 4.2 Sizes

| | Bytes |
|---|---|
| Overhead per packet: link 61 + seal envelope 57 + FEC header 12 | **130** |
| Every datagram (T = 1024) | **1,154**: inside a 1,200-byte safe MTU and the relay's 2,048-byte buffer |

Since chunks are padded (PR #35), the smallest bundle is 1,091 bytes, so the symbol size is always the 1,024-byte cap. Packet size no longer reveals message length; the number of packets reveals the chunk count (1,011 bytes per chunk). Short messages cost more airtime than before padding (34 packets instead of 27).

### 4.3 What the relay can see, before and after

| | Before | After (FEC path) |
|---|---|---|
| Message plaintext | No | No |
| Sender token | Yes (inside 0x01) | Yes (needed to pick the seal key) |
| Sequence number, nonce, ratchet ciphertext | Yes | **No** (sealed) |
| Which packets belong to the same message | Trivially (one packet = one message) | **No** from contents. Inferable from timing. |
| PQ injection packets | Distinguishable (fixed 1,193 bytes) | Not by content. Bursts every 5th message are larger. |
| Reassembling a message | n/a | **Impossible**: no seal key |

The seal's AAD binds the sender *and* recipient tokens. The relay therefore can't relabel a symbol as coming from another contact, redirect it to someone else, or bounce a client's own symbols back at it. That last case is the reflection problem in the legacy path, which is being fixed separately.

## 5. Redundancy (sizing)

`fec::packets_for(object_len, loss, max_failure)` picks the smallest burst size N for which the decode-failure probability is at most `max_failure`:

- Each packet survives independently with probability `1 - loss`. The binomial distribution is computed in log space so large bursts can't underflow.
- With fewer than K symbols, decoding always fails.
- With K + h symbols it fails with probability `10^-(2h+2)`. That's RFC 6330's quoted 1e-2 / 1e-4 / 1e-6 for h = 0, 1, 2, continued at the same rate. Real GF(256) decoding does slightly better, so the model is conservative.

Packets per message at 70% loss:

| Message (padded chunks) | K | **99.99%** (messages) | K with PQ | **99.9999%** (PQ-carrying) |
|---|---|---|---|---|
| 1 chunk (≤ 1,011 B, most chat) | 2 | **34** | 3 | **55** |
| 4 chunks (≤ 4 KB) | 5 | **53** | 6 | 74 |
| 8 chunks (≤ 8 KB) | 9 | **74** | 10 | 97 |
| 16 chunks (max, 16,176 B) | 18 | **117** | 19 | 143 |

A typical short message costs about 39 KB on the wire (34 × 1,154 B). Before padding it was 27 packets of ~250 B, about 7 KB. That's the price of hiding message length.

**A bug that measurement caught:** the first version of the model held failure flat at 1e-6 once K + 2 symbols arrived. That made a 1e-6 target reachable only through float rounding, so PQ-carrying bursts were **~155 packets instead of 48**. The 1,000-message pass-rate test exposed it: 52,600 packets where ~31,000 were expected. It was fixed, with a regression test (`stricter_targets_cost_a_few_more_packets_not_many`).

## 6. Keeping the PQ ratchet in step under loss

Every 5th message, the sender mixes fresh Kyber entropy into its sending chain. The receiver must mix the same secret into its receiving chain at *exactly* the same position. Previously the injection (0x05) was a separate datagram, so under loss:

1. **Injection lost:** every later message failed to decrypt. The session was dead with no recovery.
2. **Injection arrived before its message:** mixed in at the wrong chain position. Same outcome.
3. **A later message arrived before the injection:** that message was dropped.

FEC alone doesn't fix this. Two objects sent back to back can finish decoding in either order, so FEC makes case 3 more likely. The fixes:

- **Bundling** fixes 1 and 2. The injection travels inside the same FEC object as its message, sized to 99.9999%. They arrive together, in order, or not at all. ([transport.rs](../code/client/src/transport.rs) `encode_message`)
- **Chain positions** (`applies_at`, PR #35) make the order of injections irrelevant. One for a position the receive chain hasn't reached is held (`recv_pq_injects`, persisted) and mixed in when the chain gets there. A copy of one already taken in is ignored. No timestamp check applies to 0x05, so one queued at the relay for longer than 5 minutes still lands. ([lib.rs](../code/client/src/lib.rs): `accept_pq_inject`, `try_decrypt`)
- **Holding and retrying** fixes 3. A 0x01 message that arrived *sealed* (so its sender is proven), fails to decrypt, and has a sequence number at or ahead of the receive chain is held in `FecReceiver`. Once an injection lands or an earlier message decrypts, everything held for that peer is retried in sequence order. Held messages are capped at 32 per peer (the furthest-ahead dropped first) and expire 60 s after they were *first* held. Bare 0x01 datagrams, which anyone can forge, are never held. ([lib.rs](../code/client/src/lib.rs): `receive_message`, `retry_deferred`)

Residual risk: if an *entire* PQ-carrying burst is lost (≤ 1 in 10⁶ per injection at the design loss), the session still desyncs, and there's no automatic recovery yet. See §11 and the review.

## 7. Pacing

Packets go out every `FEC_PACKET_SPACING` (10 ms). After a stall the interval carries on at that spacing rather than catching up, so it never sends a run of packets unpaced. A 27-packet message takes ~0.27 s. Spreading packets in time keeps losses close to independent under bursty jamming: one 50 ms spike costs about 5 packets, not the whole message. It also avoids overflowing the receiver's socket buffer.

Front ends send through `BurstSender`, a task per socket that sends bursts one at a time in the order queued. One message's burst never interleaves with the next, so the receiver finishes them in send order. `send` resolves once a burst's first packet is out and fails if it couldn't be sent at all (for example, the network is down), so the UI can report it. The client lock isn't held while a burst drains, because the receive loop needs that lock.

The relay previously flushed its queues once per second, which collapsed any pacing into one line-rate blast. Now its outbound task wakes the moment a packet is queued or a recipient syncs, and sends each recipient at most one packet every 5 ms. A live burst passes straight through with its spacing intact, and a backlog is spread out instead of overflowing the recipient's socket buffer.

## 8. Relay changes (`code/server`)

| Change | Before | After | Why |
|---|---|---|---|
| Outbound scheduling | Poll every 1 s, drain everything | **Woken on arrival** (`Notify`); at most one packet per recipient every `RELAY_PACKET_SPACING` (5 ms) | Preserve burst pacing, pace backlogs, no idle polling, no added latency |
| Per-recipient queue cap | 50 packets, oldest evicted | **2 MiB** (`MAX_QUEUED_BYTES_PER_TOKEN`), new packets refused once full | Evicting the oldest cut the front off queued bursts, and losing an older PQ-carrying message makes every later one undecryptable |
| Send error during a flush | Aborted the rest of the already-drained batch (lost) | Logged, skipped, continues | Each forwarded symbol counts |
| Per-packet logging | `info!` × 3 per packet | `debug!` | A message is tens to hundreds of packets; blocking stdout slowed the receive loop |
| Delivery (PR #36) | Sent once to the recipient's last known address, then dropped | **Kept until acked**: each packet carries a delivery ID the recipient echoes in an ack (type 3). Resent 2 s, 4 s… up to 60 s apart within the same 5 ms pacing, and at once when the recipient syncs from a new address or after 30 s of silence. Kept up to 7 days | A phone that's asleep, frozen or just restarted otherwise loses everything sent to it. The client skips resends it has already handled |
| Presence pings (PR #36) | Queued like messages | Sent once, only to an online recipient | They're useless late, and would fill an offline recipient's queue |
| Link lifetime (PR #36) | 1 h from the handshake | 7 days from its **last use** | Clients never redo the handshake, so a link must outlast a phone asleep overnight (R-3 in implementation-review.md) |

The relay learned nothing about FEC or crypto. It still forwards opaque inner payloads by recipient token.

## 9. Client and front-end changes

- **New: `fec` crate** ([code/fec/src/lib.rs](../code/fec/src/lib.rs)). It's pure: no sockets, no crypto.
  - `encode`, `packets_for`, `symbol_size_for`, `source_symbols_for`.
  - `Reassembler<S>`: any order, duplicates OK, each object returned exactly once. Memory is bounded per source and overall, partial objects expire after 120 s, and finished ids are remembered for 600 s so stragglers are ignored.
  - Every header field is validated before it reaches `raptorq`, so malformed input returns an error instead of panicking.
- **New: `transport` module** ([code/client/src/transport.rs](../code/client/src/transport.rs)): bundling, seal and open, burst encoding, `FecReceiver` (per-session seal ciphers, reassembler, held messages), `send_burst`, `BurstSender`, and the tuning constants.
- **`Client`** ([lib.rs](../code/client/src/lib.rs)):
  - New `create_fec_packets(target, plaintext)`. It checks the size *before* touching the ratchet.
  - `create_encrypted_packet` (single datagrams, injection sent separately) is now test-only. Both share the private `encrypt_message_payloads`.
  - New `0x07` receive branch. Bundled parts are accepted only as 0x01/0x05, and only on the sealing peer's own behalf, so a bundle can't carry a KeyExchange that would re-key the session.
  - Messages are held and retried around PQ injections (§6).
  - New transient field `fec_rx`, never persisted.
- **CLI** ([main.rs](../code/client/src/main.rs)): `msg` queues its burst on a `BurstSender` and reports if it couldn't be sent.
- **Desktop app** ([commands.rs](../code/frontend/src-tauri/src/commands.rs)): `send_message` builds the burst under the lock, releases it, and queues it on the runtime's `BurstSender`. It returns the chat-history id as before, or an error if the burst couldn't leave the machine.

**Compatibility:** both peers need this build. Old builds ignore 0x07. The receive side still accepts bare 0x01/0x05 datagrams (PR #35's format), and a test mixes both paths in one conversation.

## 10. Build, CI and Docker

- New crate `code/fec` (dependency: `raptorq = "2.0.1"`, pure Rust). Added to the CI matrix.
- `code/client` depends on it via `path = "../fec"`. Lockfiles for `client` and `src-tauri` gained only the two new crates.
- `code/client/Dockerfile` and `code/frontend/Dockerfile` now copy `fec/` (it's a path dependency).
- **Windows developers:** the client's SQLCipher builds OpenSSL from source, which needs a native Windows Perl. Git-Bash's Perl fails. Install Strawberry Perl (`winget install StrawberryPerl.StrawberryPerl`) and put `C:\Strawberry\perl\bin` first on `PATH` for the first build. Visual Studio's `nmake` is picked up automatically.

## 11. Testing

### 11.1 Results

| Crate | Before | After | New | Status |
|---|---|---|---|---|
| `code/fec` | — | 25 | 25 | all pass |
| `code/client` | 64 | 81 | 17 | all pass |
| `code/server` | 6 | 8 | 2 | all pass |
| `code/frontend/src-tauri` | 14 | 14 | 0 (compiles with the `send_message` change) | all pass |
| `code/frontend` | 6 | 6 | 0 | all pass |
| **Total** | **90** | **134** | **44** | **all pass** |

All pre-existing tests were run first, unchanged. One server test had pinned the old queue cap of 50 and now uses the constant.

### 11.2 New tests

**`fec` crate (25):**
- Round trips at every size boundary.
- Decoding from repair symbols only, and never from fewer than K symbols.
- Order and duplicates don't matter.
- **Survives 70% random loss** (1,000 objects).
- Survives 30/50/70/80/90% loss when sized for it.
- A 64 KB object survives 70% loss.
- Bursty (Gilbert–Elliott) loss averaging 70%.
- The sizing model agrees with measured failure rates, and pins the table in §5.
- Stricter targets cost a few packets more, not several times as many (regression).
- The failure model is monotonic and bounded.
- Documented wire layout and systematic symbols.
- Malformed packets are rejected without panicking.
- Interleaved sources and objects.
- Memory bounds (per source and overall), expiry of partial and completed objects, and the too-many-symbols cut-off.
- Many objects streamed back to back and replayed each arrive exactly once.

**`client` transport (17):**
- **Both directions at 70% loss with reordering**, with 8 PQ injections each way.
- **1,000-message delivery rate** (prints the measured rate).
- **A message that overtakes its PQ injection is recovered.**
- Stale messages are never held.
- Symbols are opaque to the relay and bound to their sender.
- The seal is bound to key, sender and recipient, and rejects reflection, relabelling, redirection, truncation and tampering.
- PQ-carrying bursts get extra redundancy, but not a multiple.
- Every datagram is the same size (≤ 1,200 bytes) whatever the message length.
- Held-message queue bounds and expiry.
- Bundles may only carry the sealing peer's own 0x01/0x05. A smuggled KeyExchange can't re-key the session.
- Malformed FEC payloads are dropped and the session carries on.
- Duplicated bursts deliver once.
- Old and new send paths interoperate, including PQ injections on both.
- Oversized messages are refused before touching the ratchet.
- `send_burst` delivers in order, and really spreads packets out in time.

**`server` (2):**
- A 300-packet burst to an online recipient is delivered whole and in order.
- The full forwarding path: dequeue, re-encrypt under the recipient's link key, send over real UDP. The original security review had flagged this path as never tested.

### 11.3 Real-network check (`lossy_link`)

[`code/client/examples/lossy_link.rs`](../code/client/examples/lossy_link.rs) runs two real clients against the **real relay** over **real UDP**. Each client sits behind a small proxy that can drop packets. Contacts connect on a clean link, then the chosen side is jammed:

```bash
# terminal 1 (relay; note its "Server Static Pubkey")
cd code/server && cargo run

# terminal 2
cd code/client && cargo run --example lossy_link -- <relay pubkey hex> 0.7 alice 40
#   args: <pubkey> [loss=0.7] [jammed=alice|bob|both|none] [messages=30]
```

With `jammed=alice`, Alice→Bob exercises a jammed **sender** and Bob→Alice a jammed **receiver**. The run exits non-zero unless every message arrived and both ratchets are in step. It's suitable for rehearsing the demo.

| Run | Alice→Bob | Bob→Alice | Ratchets |
|---|---|---|---|
| Alice jammed, 70% | 40/40 (885/1,248 packets dropped) | 40/40 (871/1,248 dropped) | in step |
| Bob jammed, 80% | 30/30 | 30/30 | in step |
| Both jammed, 70% each (~91% end to end) | 28/30 | 26/30 | in step |

## 12. Tuning knobs

| Constant | Where | Default |
|---|---|---|
| `FEC_DESIGN_LOSS` | `client/src/transport.rs` | 0.7 |
| `MESSAGE_MAX_FAILURE` / `PQ_MESSAGE_MAX_FAILURE` | same | 1e-4 / 1e-6 |
| `FEC_PACKET_SPACING` | same | 10 ms |
| `MAX_MESSAGE_LEN` (chunk limit, PR #35) | `client/src/chunks.rs` | 16,176 bytes |
| `DEFER_TTL` / `MAX_DEFERRED_PER_PEER` | same | 60 s / 32 |
| `MAX_SYMBOL_SIZE`, `MAX_OBJECT_LEN` | `fec/src/lib.rs` | 1,024 B / 64 KiB |
| `fec::Limits` (pending/completed bounds and TTLs) | same | 128 / 32 per source / 120 s; 4,096 / 600 s |
| `RELAY_PACKET_SPACING` | `server/src/main.rs` | 5 ms |
| `MAX_QUEUED_BYTES_PER_TOKEN` | `server/src/stores.rs` | 2 MiB |

To cover both sides being jammed at 70% (91% end to end), set `FEC_DESIGN_LOSS = 0.91`. A short message then costs ~99 packets.

## 13. Known limitations and follow-ups

1. **Residual PQ desync.** If a whole PQ-carrying burst is lost (≤ 10⁻⁶ per injection), the session breaks with no recovery. A resync/"session reset" message (roadmap Task 4.1b) would close this.
2. ~~**PQ injections older than 5 minutes are rejected.**~~ Fixed: 0x05 is exempt from the freshness window, and its signed chain position rules out replays instead (review finding **C-4**).
3. **Fixed redundancy.** Every message pays for 70% loss even on a clean link (27× packets for a short message). Loss feedback from the receiver could adapt it.
4. **Traffic analysis.** Bursts reveal send times, the chunk count (burst length), and which messages carry a PQ injection (larger burst). Padding is per chunk now, so packet size reveals nothing. The constant-rate tunnel mode would hide the rest.
5. **Not FEC-protected (by agreement):** relay handshake, sync/keepalive, KeyExchange, SessionEstablish, presence. The jammed client's presence dot will flicker, and a jammed client can't (re)connect to the relay.
6. **Seal key is static per session.** It's derived from the root key, so a root-key compromise exposes the envelopes. The messages inside remain protected by the ratchet.
7. **No automated multi-process test in CI.** `lossy_link` is manual because it needs a running relay.
