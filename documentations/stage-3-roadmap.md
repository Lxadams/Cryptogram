# Stage 3 Roadmap: Constant-Rate Tunnel and Hardening

What comes after Stage 2 (the Bug Fixes PR, issue #40). It keeps the raw UDP link: the QUIC transport on `Logan/QUIC+CRT+Disguise` is parked for now. The goals are the project's: stop MITM attacks, hide metadata (who talks to whom, when, and how much), survive heavy loss and jamming, and limit what a captured phone or relay gives away.

Items are ordered by how much they buy for the effort. The constant-rate tunnel is the exception: it's the priority, so it starts straight away, alongside the quick wins.

- **Effort** is for one person: XS under half a day, S 1–2 days, M 3–5 days, L 2–3 weeks, XL a month or more.
- **Reward** is how much an item does for the goals above.

## Where Stage 2 leaves us

- **Done:** relay-chosen session IDs, a key per direction, numbered packets that can't be replayed, path challenges, signed syncs, admission tags and bounded relay tables. Clients reconnect by themselves, and contact setup can't stall.
- **Not yet:**
  - **No cover traffic.** The relay's dummy packets exist but nothing sends them, so anyone watching sees when and how much people message.
  - **Readable contact requests.** The relay can read every KeyExchange.
  - **Guessable passcodes.** A captured phone's passcode can be guessed offline.
- **Since then:** PR #43 (`Logan/PQ-Inject-Fixes`, merged 20 October 2026) added:
  - **Lost PQ refresh recovery.** A receiver holding messages it can't decrypt asks for the missing refreshes with a signed PQ inject request (`0x08`), and the sender resends them from its latest 20.
  - **Repair session.** A ⋮ menu item in the chat (and `repair <token>` in the CLI) that sets up a fresh session with a contact, keeping their name and the chat history.
  - **Setup copies.** KeyExchange and SessionEstablish go out 3 times to a contact who has added you, and an unanswered KeyExchange is first resent after 10 s, not 30 s.
  - **Simulated loss and network stats.** A loss percentage each way, set in the app, and a **Network stats** setting (off by default) that shows packets, loss each way and resends.
  - **An unstable-network warning** when the measured loss reaches 90% either way.
  - **Retrying a failed message** from its red **!**.

## At a glance

| Order | Item | Area | Effort | Reward |
|---|---|---|---|---|
| 0.1 | Retry and repeat the handshake | Transport, Relay | S | High |
| 0.2 | Block screenshots (`FLAG_SECURE`) | Mobile | XS | Medium |
| 0.3 | Notifications without names | Mobile | XS | Medium |
| 0.4 | Make the README match the code | All | XS | Medium |
| 0.5 | Relay hygiene: key file permissions, non-root, no core dumps | Relay | XS | Medium |
| 0.6 | ML-KEM (FIPS 203) instead of round-3 Kyber | Crypto | S | Medium |
| 0.7 | Dependency checks in CI | Ops | S | Medium |
| 0.8 | Handshake rate limit per address | Relay | S | Medium |
| 0.9 | Stronger passcode hashing | Crypto | XS | Low–Medium |
| 0.10 | No Google Play services by default | Mobile | XS | Low–Medium |
| **1** | **Constant-rate tunnel over UDP** | Transport, Relay, Mobile | L, for two people | High |
| 2.1 | Seal contact requests to the recipient | Crypto | S–M | High |
| 2.2 | Duress passcode, wipe after failed logins | Mobile | S–M | Medium–High |
| 2.3 | Disappearing messages | Client, Mobile | S–M | Medium |
| 2.4 | Hardware-backed vault key | Mobile | M–L | High |
| 2.5 | Rotating link IDs, hidden packet numbers | Transport, Relay | M | Medium |
| 2.6 | Per-pair IDs instead of sender tokens | Crypto | M | Medium |
| 3.1 | Post-compromise security: a DH + ML-KEM ratchet | Crypto | L | High |
| 3.2 | Several relays under one offline root key | Relay, Client | L | High |
| 3.3 | Multipath: cellular, Wi-Fi and satcom at once | Transport | L | High |
| 3.4 | Identity rotation and revocation | Crypto | M | Medium |
| 3.5 | Narrowband profile for radio links | Transport | M–L | Medium |
| 3.6 | Two-hop relaying | Relay | XL | High |

## Phase 0: quick wins (week 1)

**Status:** done on `Logan/Bug-Fixes` (8 October 2026), apart from pinning the toolchain (0.7). Screenshot blocking (0.2) was later taken out again, in PR #43. Each item ends with what was built, where that differs from the plan.

### 0.1 Retry and repeat the handshake

**The problem:** `perform_handshake` sends one init and gives up after 5 s. At 70% loss each way that fails 91% of the time, and the user has to press Connect again.

**The fix:**
- **Client:** send the init three times, about 200 ms apart, and keep retrying for a minute.
- **Relay:** answer every copy, three times over. Reuse the reply for an init it saw in the last few seconds (keyed by the client's ephemeral key), so the copies don't open extra links.

**The result:** at 70% loss, a connect attempt succeeds about half the time instead of 9% of it.

- **Where:** `perform_handshake` (`code/client/src/lib.rs`), `handle_request` (`code/server/src/main.rs`).
- **Done when:** `lossy_link` connects at 70% loss.
- **Done:**
  - **As planned:** the client retries for a minute. The relay reuses its reply for as long as the link it opened is waiting for a sync (a minute).
  - **Reconnecting:** a client now reconnects after two minutes without hearing from the relay, not after one unanswered sync, which heavy loss alone often caused.
  - **Result:** `lossy_link` connects through 70% loss, in 0.4 to 6.4 s in the runs so far.

### 0.2 Block screenshots

Set `FLAG_SECURE` in `MainActivity.onCreate`. That blocks screenshots and screen recording, and blanks the app's thumbnail in recent apps.

**Done, then removed.** It was set on `Logan/Bug-Fixes`, and PR #43 took it out of `MainActivity` so a phone can be mirrored to a laptop (with scrcpy, say) for demos. Screenshots, screen recordings and the recent-apps thumbnail all show the app again.

**Still to do:** turn it back on for release builds, or make it a setting.

### 0.3 Notifications without names

New-message notifications say "From <name>" on the lock screen (`message_notification_text`). Show just "New message" by default, and make showing names a setting.

**Done:**
- **The setting:** "Say who each message is from in notifications", under **Settings** in the section after the contact list, adds "From <name>". It's off by default, and saved with the identity.
- **Where it shows:** only on Android, the one platform that posts notifications.

### 0.4 Make the README match the code

**What it claimed:** `documentations/README.md` described a Double Ratchet, ML-KEM, a session reset every 100 messages and a 100 ms metronome.

**What was built** (8 October): a symmetric hash ratchet with PQ refreshes, round-3 Kyber (ML-KEM since, see 0.6), no session reset (a manual Repair session since PR #43), and no cover traffic yet.

**Why it matters:** a security reviewer who spots one overclaim stops trusting the rest. Say what's built, and link this roadmap for what isn't.

**Done.**

### 0.5 Relay hygiene

- **Key file permissions:** write `server_identity.json` with mode 0600. `fs::write` uses the default, which is usually world-readable.
- **Non-root:** run the container as a non-root user (`USER` in `code/server/Dockerfile`) with a read-only root filesystem (`--read-only` in `deploy.yml`).
- **No core dumps:** turn them off (`--ulimit core=0`), so a crash can't write queued messages or the relay key to disk. The relay is meant to keep everything in RAM.

**Done:** all three. The relay also turns core dumps off itself at startup, for when it's run outside Docker. On Linux, it also stops other processes run by its user from reading its memory.

### 0.6 ML-KEM instead of round-3 Kyber

- **The problem:** `pqcrypto-kyber 0.8` is Kyber as it stood in round 3, not the standard (ML-KEM, FIPS 203). Any government evaluation will ask for FIPS 203.
- **The fix:** switch to `ml-kem` (RustCrypto) or `pqcrypto-mlkem`.
- **What changes on the wire:** ML-KEM-768's keys and ciphertexts are the same sizes, so no packet changes size. The two don't interoperate, though, so clients update together, as with Stage 2.

**Done:**
- **The library:** `libcrux-ml-kem`, Cryspen's formally verified implementation, behind `code/client/src/pq.rs`.
- **Why not `pqcrypto-mlkem`:** it's flagged unmaintained (RUSTSEC-2026-0161).
- **Saved identities:** ones with Kyber keys load as ML-KEM keys, as the layouts match.

### 0.7 Dependency checks in CI

Add `cargo deny check` (advisories, licences, banned and duplicate crates) and `cargo audit` to `pr_build.yml`. Pin the toolchain in `rust-toolchain.toml`.

**Done:**
- **The check:** `pr_build.yml` runs `cargo deny check` for every crate, with the rules in `code/deny.toml`.
- **No `cargo audit`:** cargo-deny reads the same RustSec database, so it would add nothing.
- **Duplicate crates are allowed:** Tauri brings in dozens, which would bury anything that matters.

**Not done:** the toolchain pin. The Docker image (`rust:1-slim`), CI and the Android build would all have to follow it, so it waits until a new Rust release actually breaks a build.

### 0.8 Handshake rate limit

Each handshake costs the relay a key agreement and a signature, and anyone can send them. Stage 2 bounds the memory this takes, but not the CPU. Add a token bucket per source address (or per /24), so no one sender can take up the relay's CPU.

**Done:**
- **The limit:** per address, with an IPv6 address counted by its /64: a burst of 20, then one a second.
- **What's free:** copies of an init already answered don't count.
- **What's left:** someone spoofing many addresses still gets through. A stateless cookie, as QUIC's Retry does, would stop that.

### 0.9 Stronger passcode hashing

- **The problem:** the vault key comes from Argon2id with 19 MiB and two passes. On a seized phone, a short passcode falls quickly to offline guessing.
- **The fix:** raise the cost, to 64 MiB and three passes say, after timing it on the slowest phone you support. The parameters are stored with each hash, so existing identities still unlock.
- **It's a stopgap:** 2.4 is the real fix.

**Done:** 64 MiB and three passes, about 0.1 s per login on a laptop. **Still to do:** time it on the slowest phone you support.

### 0.10 No Google Play services by default

On Android, the QR scanner's `BarcodeDetector` is Google's ML Kit, running through Play services. Turn it off by default and keep `rqrr`. A setting can turn it back on for anyone who wants its better scanning.

**Done:** the scanner uses `rqrr` alone unless "Also use this device's own scanner" is ticked. The choice is remembered on that device.

## Phase 1: the constant-rate tunnel

**What it buys:**
- **Hidden timing and volume:** someone watching a link sees the same packets at the same rate whether anyone is messaging or not, so they can't tell when people talk, or how much.
- **Sturdier delivery:** receipts drive resends and how much redundancy each message gets.
- **No lost messages on reconnect:** messages wait in a queue across reconnects.

**What it doesn't:**
- **It isn't a disguise.** Constant-rate encrypted UDP on port 443 can still be recognised for what it is. Hiding that is the disguise stage (QUIC), which is deferred.
- **Nothing here is wasted later.** Everything sits behind a "send a cell / receive a cell" interface, so QUIC, or later a mixnet, can carry the same cells.

### Design

It's ported from the QUIC branch, without QUIC: `code/cell`, `client/src/link.rs`, `server/src/link.rs`, and the `ObjectEncoder` in `fec`.

- **Cells.** After the handshake, everything either side sends is one fixed-size cell: 1,150 bytes inside the link packet, for a 1,179-byte UDP payload.
  - **Layout:** `[receipt: newest seen + 64-bit bitmap][frames][padding]`.
  - **Frames:** Forward and Deliver (payloads), Sync (the token proof and admission tags), PathChallenge and PathResponse.
  - **One type, one size:** the link packet's number doubles as the cell's sequence number, so every packet after the handshake looks the same.
- **The clock.** Each end sends a cell, then waits a random (exponentially distributed) gap, whatever is queued. An idle cell is all padding. After a stall, the next gap counts from when the cell actually went, so a stall can't release a burst.
- **Receipts.** Every cell says which of the other side's cells arrived. That replaces:
  - delivery IDs and acks;
  - sync acks: a link whose receipts stop is gone, so the client reconnects;
  - the relay's resend timer: it resends whatever a receipt shows was lost.
- **Adaptive redundancy.** The client sends each message's FEC symbols from a queue, one symbol per cell. The first round is sized from the measured loss, and it tops up until the relay confirms enough. No more blind 70% budget on every message.
- **Contact requests through FEC** (inner type `0x09`; `0x08` is now the PQ inject request). The setup then survives the same loss as messages, and a request can grow past one packet (see 2.1).
- **Queued while down.** Messages sent while the link is down wait, and go out once it's back.

**What goes:**
- `BurstSender`, and the paced lane of packet numbers
- delivery IDs, acks and sync acks
- receipt requests (the ✓) and the loss probes behind the network stats: every cell's receipt replaces both
- setup copies (KeyExchange and SessionEstablish sent 3 times): contact requests through FEC replace them
- the relay's `take_due` pacing and 2–60 s resend backoff
- the 15 s keepalive (the clock keeps the NAT mapping open)

**What stays:** the handshake, the keys, packet numbers and the replay window, path challenges, the token proof, admission tags, and the relay's caps.

### Rate profiles

Cover traffic costs data and battery, because the radio never gets to idle. Make the rate a per-device setting that changes rarely: a change in rate is itself something an observer can see.

| Profile | Cells/s each way | Data a day, each way | Short message, clean link |
|---|---|---|---|
| Low | 1 | ~104 MB | ~4 s |
| Standard | 4 | ~417 MB | ~1 s |
| Radio silence | none while idle | only what's sent | once a session opens |

**Compared with other rates:** the original roadmap's 100 ms metronome (`doable-roadmap.md`) would be about 1 GB a day each way. The QUIC branch measured about 770 MB at 4 cells/s, because QUIC's ACK-only packets nearly double its packet count. Over raw UDP, receipts ride inside the cells instead.

**Radio silence** is for when transmitting at all is the risk. Nothing goes out until the user sends a message or checks for new ones. Then the tunnel runs at a constant rate for a fixed time, and goes quiet again. The relay holds messages in between, for up to 7 days.

### Milestones

| | Milestone | Area | Effort |
|---|---|---|---|
| 1.1 | Cell format, receipts, loss estimate and Poisson clock in `relay-link`. Port the branch's `format.rs`, `window.rs` and `pace.rs` (about 750 lines), leaving out QUIC and its hello. | Transport | M |
| 1.2 | Relay: a clock per link, one cell per tick (a queued payload or padding). Resend what receipts show was lost; a link is alive while its receipts keep coming. | Relay | M |
| 1.3 | Client: a send loop on the clock, and a symbol queue with top-ups (`ObjectEncoder`, `sends_for`). Queue while down, reconnect when receipts stop, and remove what cells replace. | Transport | L |
| 1.4 | Contact requests as FEC objects (`0x09`) | Transport | S |
| 1.5 | Rate profiles, and a setting for them in the app | Transport, Mobile | S |
| 1.6 | Android: a wake lock and the battery-optimisation exemption (from the branch). Measure battery on a real phone, for each profile. | Mobile | S |
| 1.7 | Tests: in-memory lossy links on Tokio's paused clock (port the branch's `link/tests.rs`), a `lossy_link` loss sweep, and a packet capture | All | M |

Two people (Transport and Relay) can work on 1.1–1.3 in parallel once the cell format is agreed: about three weeks. It's another flag day: the relay and every client update together.

### Done when

- A packet capture of a client's link shows one packet size, at the same rate, whether it's idle, busy or adding a contact.
- Every message gets through at 0–70% loss, in both directions, including contacts added under loss.
- A relay restart, or a phone changing networks mid-message, loses nothing.
- Battery drain has been measured on a real phone for each profile, and the default profile chosen from that.

## Phase 2: common-sense hardening

### 2.1 Seal contact requests to the recipient

**The problem:** the relay can read every KeyExchange: names, identity keys and add IDs.

**The fix:** encrypt each one to the recipient's Ed25519 key from their QR code, converted to X25519, with a fresh ephemeral key. libsodium and age do the same conversion, and `ed25519-dalek` has it. Nothing changes in the QR code.

**Why it waits for Phase 1:** the request grows by about 48 bytes, past what fits in one unfragmented packet, so it needs contact requests sent through FEC (`0x09`, 1.4).

**Effort:** S–M. **Reward:** high.

### 2.2 Duress passcode and failed-login wipe

- **Duress passcode:** a second passcode that opens an empty identity, or wipes the real one.
- **Failed-login wipe:** an opt-in wipe after N wrong passcodes.

**Effort:** S–M. **Reward:** medium–high.

### 2.3 Disappearing messages

A retention time per contact for local history, enforced by a purge when the app opens and periodically after. It's local only, so it needs no protocol change.

**Effort:** S–M. **Reward:** medium.

### 2.4 Hardware-backed vault key

Wrap the Argon2-derived vault key with an Android Keystore key (StrongBox where the phone has it) that requires the user's authentication. Guessing the passcode then needs the phone's secure hardware, which limits the rate of guesses, instead of a GPU.

**Effort:** M–L. **Reward:** high.

### 2.5 Rotating link IDs, hidden packet numbers

**The problem:** the session ID and packet number are in the clear. An observer can follow one link across time and network changes, and count its packets.

**The fix:**
- **Rotating IDs:** rotate the session ID each epoch. Both ends derive the next one from the link keys, and the relay accepts the current and the previous one.
- **Hidden numbers:** mask the packet number, as QUIC's header protection does.

It's easier after Phase 1.

**Effort:** M. **Reward:** medium.

### 2.6 Per-pair IDs instead of sender tokens

**The problem:** every chat symbol carries the sender's token, readable by the relay.

**The fix:** replace it with a per-pair ID, derived from the session's root key, that rotates each epoch. A seized relay's queues then no longer show who wrote to whom.

**The limit:** a live relay still sees which link sent each cell. Senders are only fully hidden with two-hop relaying (3.6).

**Effort:** M. **Reward:** medium.

## Phase 3: bigger steps

- **3.1 Post-compromise security.**
  - **The problem:** PQ refreshes are encrypted to the peer's long-term ML-KEM key, so a captured phone exposes all of its future traffic too.
  - **The fix:** replace them with a ratchet that brings in fresh X25519 and ML-KEM keys as the conversation goes back and forth. A session then heals once the attacker loses access.
  - **Effort:** L. **Reward:** high.
- **3.2 Several relays under one offline root key.**
  - **The problem:** one relay is one place to block or seize.
  - **The fix:** sign relay keys with an offline root key that the app pins. Hand out relay addresses the way Tor hands out bridges, in QR codes for instance.
  - **Effort:** L. **Reward:** high.
- **3.3 Multipath.**
  - **The fix:** send cells over every network the device has: cellular, Wi-Fi and satcom. A jammer hits one band, and FEC symbols can arrive by any path.
  - **Needs:** Phase 1.
  - **Effort:** L. **Reward:** high.
- **3.4 Identity rotation and revocation.**
  - **The problem:** a lost phone's identity can't be revoked today; each contact removes it by hand.
  - **The fix:** a signed key change, confirmed by a fresh scan.
  - **Effort:** M. **Reward:** medium.
- **3.5 Narrowband profile.**
  - **The problem:** at 2.4 kbps (HF radio), one 1,179-byte cell takes 4 s to send.
  - **The fix:** a profile with small cells (around 256 bytes) and a slower clock, for radio links.
  - **Needs:** Phase 1.
  - **Effort:** M–L. **Reward:** medium.
- **3.6 Two-hop relaying.**
  - **The fix:** an entry relay that sees your address, and an exit relay that sees your mailbox; neither sees both.
  - **Why it matters:** it's the step that actually hides the social graph from relays, and the start of a mixnet.
  - **Effort:** XL. **Reward:** high.

## Deferred

- **QUIC and the disguise.** That's the HTTP/3 look, the decoy website and a TCP fallback, parked on `Logan/QUIC+CRT+Disguise`. Phase 1 keeps the cell interface, so QUIC can come back as another way to carry cells.
- **A mixnet.**
- **Group messaging** (MLS, RFC 9420).
- **A CNSA 2.0 suite for classified use:** ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384.

## Suggested split

- **Transport lead:** 0.1 (client side), 1.1, 1.3, 1.4 and 1.5, then 2.5 and 3.3.
- **Relay lead:** 0.1 (relay side), 0.5, 0.8 and 1.2, then 3.2.
- **Crypto lead:** 0.6, 0.9, 2.1 and 2.6, then 3.1 and 3.4.
- **Mobile lead:** 0.2, 0.3, 0.10, 1.5 (the setting), 1.6, 2.2, 2.3 and 2.4.
- **Everyone:** 0.4, 0.7 and 1.7.
