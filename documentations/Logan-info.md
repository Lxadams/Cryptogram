# How a message gets from Phone A to Phone B

What happens to a chat message from the moment you press Send on Phone A until it shows up on Phone B. Covers:

1. [The end-to-end path](#1-the-end-to-end-path-a--relay--b), step by step
2. [The ✓ / ! status marks](#2-the-tick-mark--and-)
3. [How out-of-order, lost and duplicate packets are handled](#3-out-of-order-lost-and-duplicate-packets) at every layer
4. [The packet structure](#4-packet-structure), byte by byte

Everything here is from the code as of `main` (commit `52b49d8`, 20 October 2026). File references are relative to `code/`.

---

## The big picture in one paragraph

Phone A splits the message into chunks, pads each chunk to 1024 bytes, and encrypts each one with the next key from its ratchet (`0x01` payloads). It bundles those chunks into one **RaptorQ FEC object** and encodes that into a burst of 34+ symbols, sized so the message survives losing 70% of the packets. Each symbol is sealed end to end (`0x07`), wrapped in the **link layer** (ChaCha20-Poly1305 between phone and relay), and sent 10 ms apart. The **relay** can't read any of it. It opens the link layer, reads the recipient's routing token, queues the packet, and forwards it to Phone B on B's own link, resending until B **acks** each packet. Phone B rebuilds the FEC object from *any* K symbols, decrypts the chunks, reassembles the message, and puts it back in send order before showing it. Meanwhile Phone A keeps asking the relay "which of my packets do you have?" and shows **✓** once the relay has enough of them to rebuild the message. If a whole burst carrying a PQ inject is lost, Phone B asks Phone A for the inject again (§3.10).

```
 Phone A                         Relay (server)                        Phone B
 ───────                         ──────────────                        ───────
 text
  │ chunks::split + padding::pad
  │ ratchet-encrypt each chunk  (0x01)
  │ bundle [+ PQ inject 0x05]  → FEC object
  │ RaptorQ encode → N symbols
  │ seal each symbol E2E        (0x07)
  │ link-seal, paced lane
  │ BurstSender: 1 pkt / 10 ms
  ├──────── TYPE_ADMITTED_DATA ──────▶ open link pkt
  │                                    enqueue for B's token
  │                                    record_queued (for receipts)
  │                                    take_due: 1 pkt / 5 ms per recipient
  │                                    re-seal on B's link ──── TYPE_DATA ────▶ open link pkt
  │                                                                           dedupe delivery ID
  │                                                                           open 0x07 seal
  │                                                                           FEC reassemble (any K)
  │                                                                           unbundle → 0x01 / 0x05
  │                                                                           ratchet decrypt + unpad
  │                                                                           chunk reassembly
  │                                                                           DeliveryOrder (reorder)
  │                                                                           → inbox → UI (1 s poll)
  │                                    remove from queue ◀──── TYPE_ACK ──────┤ (one per packet)
  │  every 2 s (3 copies)
  ├──────── TYPE_RECEIPT_REQUEST ────▶
  ◀──────── TYPE_RECEIPT (×3) ─────────┤ bitmap of paced-lane pkts queued
  │ ≥ K of this burst's packets queued?  → ✓
  │ 30 s and still not?                  → !
```

---

## 1. The end-to-end path (A → relay → B)

### 1.0 Before any message: link + session setup (one-time)

Two separate "connections" have to exist before a chat message can flow:

| What | Between | Set up by | Code |
|---|---|---|---|
| **Link** | each phone ↔ relay | X25519 handshake (`TYPE_HANDSHAKE_INIT` / `RESP`), relay signs with its pinned Ed25519 key. Gives a random 4-byte **session ID** and two ChaCha20-Poly1305 keys (one per direction). Then the phone sends a signed **`Sync`** proving it owns its routing token and registering one **admission tag** per contact. | `relay-link/src/lib.rs`, `perform_handshake` in `client/src/lib.rs`, `handle_request` in `server/src/main.rs` |
| **E2E session** | Phone A ↔ Phone B | Both people add each other. KeyExchange (`0x02`) both ways, then the establisher (the lower routing token) sends SessionEstablish (`0x04`), and the responder confirms with a KeyExchange naming the session. Hybrid PQXDH: X25519 + ML-KEM-768 → `root_key`. Both chain keys start at `root_key`. A lost setup packet is covered by copies and resends (§3.11). | `handle_key_exchange`, `handle_session_establish` in `client/src/lib.rs` |

The relay only learns "routing token T lives on link S at address X". It never sees the E2E keys.

If a session breaks for good, **Repair session** (the chat's ⋮ menu, `Client::repair_session`) drops it and sends a KeyExchange with a new add ID, as removing and re-adding the contact would. The other side drops its copy, and the two set up a fresh session. The contact, their name and the chat history stay.

Background loops in the app (`frontend/src-tauri/src/commands.rs`):

| Loop | Period | Job |
|---|---|---|
| `spawn_receive_loop` | on every UDP packet | `Client::handle_relay_packet`, then send whatever it returns (acks, replies, resent PQ injects) |
| `spawn_tick_loop` | **500 ms** | `release_held_messages()` (reorder timeouts) + `receipt_requests()` (✓ machinery, and loss probes while the network stats are watched) + `pq_inject_requests()` (asks for a missing PQ inject, §3.10) |
| `spawn_keepalive_loop` | **15 s** | `keepalive()`: 3 signed syncs (keeps NAT mapping + relay record alive), KeyExchange resends; re-handshakes after 2 min of silence from the relay |
| Leptos `refresh` (UI) | **1 s** | `list_contacts`, `connection_requests`, `poll_inbox`, `sent_message_updates`, and `network_stats` while **Network stats** is on and the app is on screen |

Every packet to and from the relay goes through `client/src/netsim.rs`, which counts packets and can drop a set share of them each way to simulate loss on the device (off by default). The CLI runs the same keepalive and tick loops (`client/src/main.rs`).

### 1.1 Phone A: press Send

`ChatPanel::send_now` (`frontend/src/app.rs`) → Tauri `send_message` (`commands.rs`) → `Client::create_fec_packets` (`client/src/lib.rs`).

**Step 1: split into chunks** (`client/src/chunks.rs`)
- Each chunk gets an 11-byte header: `kind | 8-byte random msg id | index | count`.
- 1011 bytes of text per chunk, **max 16 chunks** (16,176 bytes). Longer messages are rejected *before* the ratchet moves.

**Step 2: pad each chunk** (`client/src/padding.rs`)
- `[2-byte len | chunk | zeros]` → always exactly **1024 bytes**, so packet size never leaks message length.

**Step 3: ratchet-encrypt each chunk** (`encrypt_message_payloads`)
- For each chunk: `message_key = HMAC(chain_key, "message-key")`, `chain_key = HMAC(chain_key, "chain-key")` (`chain_step`).
- XChaCha20-Poly1305 with a random 24-byte nonce → a **`0x01` payload** carrying the sender token and **`seq_no` = `send_count`**. `send_count` increments per *chunk*, not per message.
- **PQ inject:** if this message's chunks took `send_count` past a multiple of `PQ_INJECT_INTERVAL` (5), encapsulate a fresh ML-KEM secret to the peer, mix it into the send chain, and emit a signed **`0x05` PQ inject** carrying `applies_at = send_count`. The signed inject is also kept with the session (`sent_pq_injects`, the latest 20), in case Phone B asks for it again (§3.10).
- State is saved and the message is written to chat history (status column = `Sending`).

**Step 4: bundle + FEC encode** (`client/src/transport.rs::encode_message`, `fec/src/lib.rs`)
- Bundle = `[len|0x01 chunk]...[len|0x05 inject]`, all in one FEC object. **The inject always travels with its message:** they arrive together or not at all.
- `object_id = seq_no of the last chunk` (unique per session).
- `fec::packets_for(len, loss=0.7, max_failure)` picks the burst size: target failure is 1e-4 for a normal message (34 packets for a one-chunk message, 55 for one carrying a PQ inject; the "27" in `transport.rs`'s comment is stale), and **1e-6** if it carries a PQ inject, because losing an inject desyncs the ratchet.
- Symbol size is 1024 bytes for any real message (a one-chunk object is 1091 bytes, so K = 2 source symbols plus repair symbols).

**Step 5: seal each symbol end to end** (`seal_symbols`)
- Key = `HKDF(root_key, "fec-symbol-seal")`; AAD = `0x07 || sender || target`. So the relay can't tell which packets belong to the same message, and can't redirect or relabel them.

**Step 6: link-wrap in the paced lane** (`wrap_data` → `relay_link::data_packet`)
- `TYPE_ADMITTED_DATA` (with the admission tag B registered for A) or `TYPE_DATA` if there's no tag.
- Numbered in the **paced lane** (top bit of the packet number set). The first packet number is remembered for the ✓ check (`track_sent`, §2).

**Step 7: send the burst** (`transport::BurstSender`)
- `send_message` queues the burst **while still holding the client lock**, so bursts leave in the same order they were numbered.
- A single task sends bursts one after another (never interleaved), **one packet every 10 ms** (`FEC_PACKET_SPACING`), so a short jamming spike only takes a few packets.
- `send_message` returns once the first packet is out. The UI shows the message with status `Sending` (a small spinner).

### 1.2 The relay (`server/src/main.rs`, `server/src/stores.rs`)

**Receive** (`handle_request`):
1. `Tables::open` looks up the link by session ID, authenticates with ChaCha20-Poly1305, and checks the **replay window** (1024 per lane). Forged, replayed, or wrong-link packets are refused.
2. `parse_data` → recipient token, optional admission tag, inner payload (opaque).
3. `enqueue_message`:
   - The packet goes into B's queue with a fresh random **16-byte delivery ID**, TTL **7 days**.
   - A packet whose admission tag is one B registered counts against B's **2 MiB contacts queue**. Anything else (strangers, contact requests) shares a **64 KiB** queue that evicts its oldest entries first.
   - When the contacts queue is full, new packets are **refused, not evicted** (evicting would cut the front off queued messages and could drop a PQ inject).
4. If queued: `record_queued(session, packet_number)` sets the bit in that link's **receipt bitmap**. A packet that was dropped for a full queue is never counted, so A can't get a ✓ for something the relay threw away.

**Forward** (`spawn_outbound_task` → `send_due_packets` → `Tables::take_due`):
- The task wakes on a `Notify` whenever something is queued or a recipient syncs, otherwise sleeps until the next slot is due.
- **At most one packet per recipient every 5 ms** (`RELAY_PACKET_SPACING`, half the client's 10 ms). A live burst passes straight through; a backlog (B coming back online) gets paced instead of blasted.
- Sends the **oldest due** packet first, so a backlog goes out in order.
- Each send is **re-sealed on B's link** with a fresh packet number, including resends: `TYPE_DATA` = `delivery_id || inner`.
- The packet **stays queued** and its next resend is scheduled: **2 s, 4 s, 8 s, … capped at 60 s** (`resend_delay`).
- B is "offline" if there's no metadata entry for the token. Packets just wait (up to 7 days).
- **Wake-up resend:** if B syncs from a new address, on a new link, or after more than 30 s of silence, every queued packet's backoff is reset to "now" (`update_metadata`).

**Ack** (`TYPE_ACK`): B sends `own_token || delivery_ids`. The relay only accepts it from B's *current* link session (so nobody else can delete B's mail), then drops those packets from the queue.

### 1.3 Phone B: receive

`spawn_receive_loop` → `Client::handle_relay_packet` (`client/src/lib.rs`):

1. `release_held_messages()`: every incoming packet is also a chance to flush timed-out reorder holds (§3).
2. `link.open(packet)`: authenticate + replay window. Updates `last_heard` (link liveness).
3. Dispatch on link type: `TYPE_RECEIPT` (handled for A's ✓ side), `TYPE_SYNC_ACK`, `TYPE_PATH_CHALLENGE`, or `TYPE_DATA`.
4. For `TYPE_DATA`: split off the delivery ID. **Dedupe** with `RecentDeliveries` (last 4096 IDs); a resent copy isn't processed again.
5. `handle_incoming_packet(inner)` → **`0x07` branch**:
   - Look up the session for the sender token and **open the seal** with the session's FEC seal key. Failures are dropped silently (strangers can't get further).
   - `fec_rx.reassemble`: feed the symbol into RaptorQ. **Any K symbols in any order** rebuild the object; until then, nothing happens.
   - `unbundle` → for each part: `0x01` → `receive_message`, `0x05` → PQ inject handling.
6. `receive_message`:
   - `try_decrypt(seq_no)`: fast-forward the receive chain (up to 100 ahead), store skipped keys in `skip_dict`, and mix in any pending PQ inject at its exact position.
   - If it can't decrypt yet (a PQ inject it depends on hasn't landed), **park it** (§3.7). While anything is parked, the tick loop asks Phone A for the missing inject (§3.10).
   - `unpad` → `Reassembler::accept` (chunk reassembly) → `DeliveryOrder::accept` (send-order) → `deliver()` → chat history + `inbox`.
7. The **ack** for this packet's delivery ID is appended to the replies, *after* the packet is handled and saved, and after anything handling it queued to send (resent PQ injects, §3.10). A crash in between means a resend, not a lost message.
8. The UI's 1 s `poll_inbox` picks up the message; Android gets a notification via `background::message_received`.

---

## 2. The tick mark (✓ and !)

### What the ✓ means

> **✓ = "the relay has enough of this message's packets that Phone B will (≈99%) be able to rebuild it."**

It is **not** "delivered to Phone B" and **not** "read". The tooltip in `app.rs` says *"The relay has it"*. There is currently **no end-to-end delivery or read receipt** from B back to A.

`!` = the relay didn't confirm within 30 s (*"It didn't get to the relay."*). A retry button sits next to it: `retry_message` sends the text again as a new message at the bottom, and deletes the failed one from the history. If the first try reached Phone B after all, B gets it twice.

### Why it's done with receipts instead of acks

The relay never acks individual data packets from the sender. A burst is 34+ packets at 70% loss, and acking each one would double the traffic. Instead the relay keeps a **bitmap of which paced-lane packet numbers it queued** for each link, and the client asks for it.

### Step by step (`client/src/confirmations.rs`, `client/src/lib.rs`)

1. **Track** (`create_fec_packets` → `track_sent`): records an `Unconfirmed`:
   - `session`: the link session ID it went out on
   - `first`: first paced-lane packet number of the burst; `packets`: burst length
   - `needed`: `transport::symbols_needed` = **K source symbols** (any K is enough for RaptorQ to decode ~99% of the time). It used to be K+1, but that made the ✓ wait or time out on messages that had actually arrived.
   - `history_id`: chat-history row, which is set to `Sending`
2. **First ask** is scheduled at `sent_at + burst_time (10 ms × packets) + 500 ms`.
3. **Tick loop (500 ms)** calls `receipt_requests()`:
   - `expire()`: anything older than **`CONFIRM_TIMEOUT` = 30 s** → `settle(Failed)`.
   - If a request is due: send **3 copies** of `TYPE_RECEIPT_REQUEST` (empty, Direct lane) and schedule the next one **2 s** later. Repeats while anything is unconfirmed.
4. **Relay** (`TYPE_RECEIPT_REQUEST`): only answers if the request came from the link's verified address, then sends `TYPE_RECEIPT` (the bitmap: `next` + 1024 bits) **3 times** (`REPLY_COPIES`).
5. **Phone A** (`handle_relay_packet`, `TYPE_RECEIPT`): `confirmations.confirmed_by(session, receipt)`. For each pending message on *this* link, it counts how many of `first..first+packets` the bitmap shows as taken in. If that's ≥ `needed`, it calls `settle(Sent)`.
6. `settle` writes the status to the chat-history DB (`status` column: 1 Sending, 2 Sent, 3 Failed) and pushes `(history_id, status)` onto `send_updates` (capped at 256).
7. **UI** (1 s `refresh`): `sent_message_updates` drains them, finds the message by id, and sets `status` → the `<For>` is keyed on `(id, status)`, so it re-renders with ✓ or `!`.
   - **Race:** a short message can be confirmed before `send_message` has even returned. Those updates go into `early_updates`, and `send_now` picks the status up from there when it adds the message.

### Edge cases worth knowing

- **App killed mid-send:** on restart, `ChatHistory::open` turns every `Sending` row into `Failed` (`history.rs`).
- **Link changes mid-send** (re-handshake after a sleep, NAT rebinding → new link): receipts from the new link don't count for messages sent on the old one (`m.session == session`). Those messages will show `!` after 30 s even if B got them.
- **Bounded:** at most 256 unconfirmed messages tracked; the oldest is failed beyond that.
- **Why 30 s / 2 s / 3 copies:** at 70% loss each way, one round of requests gets an answer about half the time, so 15 rounds almost always do (comment in `confirmations.rs`).

---

## 3. Out-of-order, lost and duplicate packets

UDP gives no ordering or delivery guarantee, and the system is designed for **70% loss with reordering**. Each layer handles its own part:

| # | Layer | Problem it handles | Mechanism | Limits | Code |
|---|---|---|---|---|---|
| 3.1 | Sender | Bursts interleaving / leaving out of numbering order | `BurstSender`: one task, one burst at a time, in queue order; queued under the client lock | n/a | `transport.rs` |
| 3.2 | Link layer (both ends) | Reordered packets on the wire; replays | Per-lane sliding **replay window** (RFC 6479). Any packet up to 1024 behind the newest is accepted once; duplicates or older ones are refused. Two lanes (Direct / Paced) so a long paced burst can't push control packets out of the window. | 1024 per lane | `relay_link::ReplayWindow` |
| 3.3 | Relay | Loss relay → B; B offline | Queue + **resend until acked** (2→4→8…60 s backoff), immediate resend when B wakes or moves; per-recipient FIFO paced 5 ms | 7-day TTL, 2 MiB/token | `stores.rs` |
| 3.4 | Phone B, transport | Duplicate deliveries (lost acks → resends) | `RecentDeliveries` drops repeat delivery IDs before processing (important: a resent KeyExchange would otherwise restart the session) | last 4096 IDs | `deliveries.rs` |
| 3.5 | Phone B, FEC | Lost and reordered symbols | RaptorQ: **any K symbols in any order**. Stragglers for an already-completed object are ignored (completed set). Per-session epoch so a new session's object IDs don't collide. | completed set 4096 / 600 s | `fec/src/lib.rs`, `FecReceiver` |
| 3.6 | Phone B, ratchet | Messages arriving with a gap in seq numbers | `try_decrypt` fast-forwards the chain and stores skipped keys in **`skip_dict`**, so the earlier message can still decrypt when it arrives. Old seq with no stored key = duplicate → silently ignored. | ≤100 ahead; skip_dict ≤500 | `SymmetricSessionState::try_decrypt` |
| 3.7 | Phone B, PQ ratchet | PQ inject arriving before/after the messages around it | Inject carries **`applies_at`**. If the chain isn't there yet it's stored in `recv_pq_injects.pending` and mixed in exactly when the chain reaches that position. Messages encrypted *after* an inject that hasn't arrived are **parked** (`ParkedPayloads`, saved to disk) and retried (`retry_deferred`) once it lands. Only FEC-sealed payloads are parked (the seal proves the sender), so strangers can't fill the queue. | 32 pending injects; 100 parked/peer, 7-day TTL | `accept_pq_inject`, `transport.rs` |
| 3.8 | Phone B, chunks | Chunks of a multi-chunk message arriving in any order | `Reassembler` keyed by `(sender, msg_id)`, slots by index, ignores repeats | 300 s timeout, 4 incomplete/sender | `chunks.rs` |
| 3.9 | Phone B, delivery order | Whole messages completing out of send order (one lost more symbols and waited for a resend) | **`DeliveryOrder`** (below) | 10 s wait, 64 held | `ordering.rs` |
| 3.10 | Phone B ↔ Phone A, PQ recovery | A whole burst carrying a PQ inject lost, so every later message is parked for an inject nobody would send again | B asks for it with a signed **`0x08`** request; A resends it (below) | A keeps the latest 20 per session | `pq_inject_requests`, the `0x08` branch in `client/src/lib.rs` |
| 3.11 | Both, contact setup | A lost KeyExchange or SessionEstablish (single packets, so no FEC) | To a contact who has added us, each goes out **3 times** (`SETUP_COPIES`), each sealed on its own; to anyone else, once. An unanswered KeyExchange is resent after **10 s**, then twice as long each time | 8 resends; any progress or a new link starts the count again | `setup_resends`, `take_extra_packets` |

### 3.9 `DeliveryOrder`: putting messages back in send order

Every chunk carries its ratchet position (`seq_no`), so a completed message knows its span `first..=last` (`first = seq_no − chunk_index`). Per session:

- `next` = ratchet position of the first chunk of the next message to show.
- `accept(first, last, text)`:
  - `first == next` → show it, advance `next = last + 1`, then release any held messages that now follow on.
  - `first > next` → **hold** it in a `BTreeMap` keyed by `first`, timestamped.
  - `first < next` → its wait already ran out and later messages went first. Show it now anyway ("late is better than never").
- **`release_due`** (called on every relay packet and every 500 ms tick): any held message that has waited **`REORDER_WAIT` = 10 s** gives up on the gap in front of it, and it plus everything before it is released in order. 10 s covers the relay's first two resends (at 2 s and 6 s), which is when nearly every missing message turns up.
- `pass_over`: a position that decrypted but was dropped (bad padding, bad chunk) takes its place in the order empty, so it doesn't block later messages.
- Over **64** held, the oldest gap is abandoned (a contact can't make B hold unbounded data).
- The state is **saved with the session**: a held message has already used its ratchet key, so it must survive an app restart.

### Example: message 2 overtakes message 1

```
A sends m1 (seq 0) and m2 (seq 1), two bursts, back to back.
70% loss: m1 loses too many symbols; m2 gets K through.

B: m2 FEC completes → decrypt seq 1 (seq 0's key goes to skip_dict)
   DeliveryOrder: first=1 > next=0 → HOLD m2
relay resends m1's un-acked symbols at +2 s
B: m1 FEC completes → decrypt seq 0 using skip_dict key
   DeliveryOrder: first=0 == next → show m1, then release m2
UI shows: m1, m2   ✓

If m1 never comes: after 10 s, release_due shows m2.
If m1 turns up later after all, it's shown when it arrives (out of order).
```

### 3.10 Recovering a lost PQ inject

An inject travels once, in the burst of the message that triggered it, and Phone A mixes it into its send chain straight away. If that whole burst is lost, every later message from A fails to decrypt and is parked (§3.7) for an inject nobody would send again. So:

- **A keeps its injects:** the latest 20 per session (`KEPT_PQ_INJECTS`, enough to cover the 100 messages the receive chain looks ahead), as the signed `0x05` payloads, saved with the session. They hold only the ML-KEM ciphertext and a signature, nothing secret.
- **B asks again:** while it's holding messages for a missing inject, it sends a **`0x08` PQ inject request** for positions `from` (its receive position) through `through` (the furthest message held). First after 3 s, as an inject is often just behind, then after 6 s, 12 s and 24 s, and every 30 s after that until the messages decrypt. Each request goes 3 times, in the Direct lane.
- **A resends:** it drops the kept injects before `from` (B has those), and sends the ones up to `through` as plain `0x05` packets in the Direct lane, 3 copies each, answering each contact at most once a second.
- **Old sessions:** the request is signed with the session binding, as an inject is, so one from before a repair doesn't verify and is ignored (logged as a note, not an alert).
- **Too old:** if A no longer has the inject, it logs that the session needs repairing.

Once the inject lands, `retry_deferred` decrypts the parked messages and `DeliveryOrder` shows them in order. Both sides need a build with `0x08`: an older client ignores the request.

---

## 4. Packet structure

Packets are layered like an onion. From the outside in:

```
UDP datagram
└─ Link packet (phone ↔ relay)                 relay-link/src/lib.rs
   └─ Link plaintext: routing info              [recipient | tag] or [delivery id]
      └─ Inner payload (phone ↔ phone, opaque to relay)
         ├─ 0x07 sealed FEC symbol              client/src/transport.rs
         │  └─ FEC packet                       fec/src/lib.rs
         │     └─ (part of) FEC object = bundle
         │        ├─ 0x01 chat chunk payload    client/src/lib.rs
         │        │  └─ padded block            client/src/padding.rs
         │        │     └─ chunk                client/src/chunks.rs
         │        └─ 0x05 PQ inject (optional)  client/src/packets.rs
         ├─ 0x02 KeyExchange
         ├─ 0x04 SessionEstablish
         ├─ 0x05 PQ inject, on its own (only when resent, §3.10)
         ├─ 0x08 PQ inject request                client/src/packets.rs
         └─ 0x00 dummy (cover traffic, currently off)
```

All integers are big-endian.

### 4.1 Handshake packets (plain, before a link exists)

```
HANDSHAKE_INIT (320 bytes, padded so 3 reply copies never exceed it: no amplification)
  [0x00 | client ephemeral X25519 pub (32) | zero padding (287)]

HANDSHAKE_RESP (101 bytes)
  [0x02 | session id (4) | relay ephemeral X25519 pub (32) | Ed25519 sig (64)]
  sig covers: "e2e-messenger/handshake/v2" || client eph || relay eph || session id
```

### 4.2 Link packet (everything after the handshake)

```
┌────────┬──────────────┬──────────────────┬───────────────────────────────────┐
│ type 1 │ session id 4 │ packet number 8  │ ChaCha20-Poly1305(plaintext) + 16 │
└────────┴──────────────┴──────────────────┴───────────────────────────────────┘
 \_____________ header, in clear, authenticated as AAD ______/
```
- **Packet number** = the AEAD nonce. **Top bit = lane** (0 Direct, 1 Paced); the rest is the position in that lane.
- Separate key per direction (`to_relay`, `to_client`) so packets can't be reflected back.
- Overhead: 13 header + 16 tag = **29 bytes**.

| Type | Value | Direction | Plaintext |
|---|---|---|---|
| `TYPE_DATA` | 1 | phone → relay | `recipient token (16) \| inner` |
| `TYPE_ADMITTED_DATA` | 5 | phone → relay | `recipient token (16) \| admission tag (8) \| inner` |
| `TYPE_DATA` | 1 | relay → phone | `delivery id (16) \| inner` (all-zero id = no ack needed) |
| `TYPE_ACK` | 3 | phone → relay | `own token (16) \| delivery id (16) × n` |
| `TYPE_SYNC` | 4 | phone → relay | `token (16) \| token pub key (32) \| sig (64) \| admission tag (8) × ≤64` |
| `TYPE_SYNC_ACK` | 8 | relay → phone | packet number of the sync (8) |
| `TYPE_PATH_CHALLENGE` | 6 | relay → phone | challenge (16) |
| `TYPE_PATH_RESPONSE` | 7 | phone → relay | same challenge (16) |
| `TYPE_RECEIPT_REQUEST` | 9 | phone → relay | empty |
| `TYPE_RECEIPT` | 10 | relay → phone | `next (8) \| 16 × u64 bitmap` = 136 bytes |

### 4.3 Inner payloads (end to end; the relay just forwards bytes)

Every inner payload starts with a type byte, then the **sender's routing token**.

#### `0x07`: sealed FEC symbol (what chat messages actually travel as)
```
┌──────┬────────────────┬──────────┬─────────────────────────────────────────┐
│ 0x07 │ sender token16 │ nonce 24 │ XChaCha20-Poly1305(FEC packet) + 16 tag │
└──────┴────────────────┴──────────┴─────────────────────────────────────────┘
key = HKDF(root_key, "fec-symbol-seal");  AAD = 0x07 || sender || target
size = 1 + 16 + 24 + (12 + 1024) + 16 = 1093 bytes  (CHAT_INNER_PAYLOAD_LEN)
```

#### FEC packet (inside the seal)
```
[object id 4 | object length 4 | symbol id 4 | symbol (≤1024)]
object id = seq_no of the message's last chunk
```

#### FEC object = bundle
```
[len 2 | 0x01 chunk payload] [len 2 | 0x01 chunk payload] ... [len 2 | 0x05 PQ inject]?
```

#### `0x01`: ratchet-encrypted chat chunk (1089 bytes)
```
┌──────┬────────────────┬──────────┬──────────┬───────────────────────────────────────┐
│ 0x01 │ sender token16 │ seq_no 8 │ nonce 24 │ XChaCha20-Poly1305(padded block) + 16 │
└──────┴────────────────┴──────────┴──────────┴───────────────────────────────────────┘
key = this seq_no's message key from the symmetric hash ratchet
```

#### Padded block (1024 bytes, inside the `0x01` ciphertext)
```
[payload length 2 | chunk | zero bytes up to 1024]
```

#### Chunk (inside the padded block)
```
[kind 0x01 | message id 8 (random) | index 1 | count 1 | text bytes ≤1011]
```

#### Signed control payloads (`client/src/packets.rs`)
All share `[sender token 16 | target token 16 | timestamp 8 | … | Ed25519 sig 64]`, signed over everything before the signature.

| Type | Total body | Body fields |
|---|---|---|
| `0x02` KeyExchange | 1393 | Ed25519 pub 32, X25519 pub 32, ML-KEM pub 1184, display name 32, flags 1, add id 4, session add id 4 |
| `0x04` SessionEstablish | 1232 | ML-KEM ciphertext 1088, ephemeral X25519 pub 32, establisher add id 4, responder add id 4 |
| `0x05` PQ inject | 1200 | `applies_at` 8, ML-KEM ciphertext 1088. Its signature also covers a session binding that isn't sent, so it can't be replayed into a later session |
| `0x08` PQ inject request | 120 | `from` 8, `through` 8. Its signature covers the label `pq-inject-request`, everything before the signature, and the session binding, so it only verifies on the session it was made for |

`0x02` and `0x04` go as single `TYPE_(ADMITTED_)DATA` packets in the **Direct** lane, not FEC: a one-packet message can't be spread over symbols, so copies are its redundancy (§3.11). `0x05` travels *inside* an FEC bundle with its message, and on its own only when resent (§3.10). `0x08` is a single Direct-lane packet, sent 3 times. `0x03` and `0x06` are unused (`0x06` was a presence ping, since removed).

### 4.4 Sizes on the wire for a chat symbol

| Hop | Size |
|---|---|
| Phone → relay (`TYPE_ADMITTED_DATA`) | 13 + 16 recipient + 8 tag + 1093 inner + 16 tag = **1146 bytes** |
| Relay → phone (`TYPE_DATA`) | 13 + 16 delivery id + 1093 inner + 16 tag = **1138 bytes** |

Both are under the 1232-byte IPv6-safe UDP payload, so no IP fragmentation. Every chat packet is the same size whatever the message length.

---

## 5. Things I noticed while tracing this (possible follow-ups)

1. **✓ is relay-receipt, not delivery.** If the team expects WhatsApp-style ✓✓ (delivered) or blue ticks (read), that needs a new E2E receipt message from B → A. Nothing like that exists yet.
2. **Possible restart-loss window.** `handle_relay_packet` **acks every forwarded packet right after handling it**, including symbols of an object that isn't complete yet, and `FecReceiver` isn't saved. So if Phone B restarts mid-reassembly, the symbols it already acked won't be resent, and the message is only recovered if the remaining un-acked symbols are enough on their own. (`FecReceiver`'s doc comment used to claim the opposite; it now says this.) Worth deciding whether that's acceptable.
3. **Link change during a send → false `!`.** Confirmations are tied to the link session ID, so a re-handshake within 30 s of sending marks the message failed even if the relay had it.
4. **Only the latest 20 PQ injects can be resent.** One missing from further back still needs a repair, though the receive chain can't get that far ahead anyway. And a session out of step for some other reason keeps sending a `0x08` every 30 s while it holds messages, until it's repaired.
