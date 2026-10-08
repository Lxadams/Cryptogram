Logan - Bug Fixes: close the Stage 2 holes, contact adding and QR scanning, Stage 3 quick wins

Closes issue: #40

### Summary
- **Contacts need both sides to add each other.** A stranger's KeyExchange is dropped, and the setup ends on one session however the messages cross, get lost or arrive late.
- **The link to the relay is authenticated end to end.**
  - **Session IDs:** the relay picks them.
  - **Packets:** numbered and never accepted twice, with a key per direction and an authenticated header.
  - **Syncs:** prove token ownership.
  - **Moving a link:** a path challenge proves the new address first.
  - **Relay tables:** each one is capped.
- **Clients survive a bad network.**
  - **Handshakes:** retried and repeated.
  - **Reconnecting:** automatic after two minutes of silence.
  - **Contact setup:** resent with backoff.
  - **Messages:** shown in the order they were sent, and kept while they wait for a PQ refresh.
- **Sent messages show ✓ or !,** for whether the relay confirmed it has them.
- **Phase 0 of the [Stage 3 roadmap](documentations/stage-3-roadmap.md),** apart from the toolchain pin: ML-KEM-768, stronger Argon2id, `FLAG_SECURE`, notifications without names, relay hygiene, a handshake rate limit, `cargo deny` in CI, and Google's scanner opt-in.

### What changed

**Contact setup** (`code/client/src/lib.rs`)
- **Add each other.** Both people add each other by scanning or pasting (`Client::add_contact`), and a KeyExchange from anyone else is dropped before it touches contact state. Adding your own code is refused.
- **One establisher.** The contact with the lower routing token sends the SessionEstablish.
  - **Re-offers:** each time it's asked, it offers the same session, re-signed, until the responder confirms it.
  - **Sending:** nothing goes out on a session until it's confirmed.
- **Add IDs.** Each fresh add gets an ID from a counter that only goes up, and every KeyExchange and SessionEstablish carries the IDs. Messages from before a removal are then recognisably stale. This replaces `awaiting_session_est` and `seen_session_keys`.
- **The setup can't stall.**
  - **Late KeyExchanges:** taken in however late, but the name in one over 5 minutes old is ignored.
  - **Resends:** a KeyExchange is resent after 30 s, then twice as long each time, up to 8 times. The count restarts when the contact replies, or after a reconnect.
  - **Stale SessionEstablish:** answered with a fresh request.
  - **Restarting:** adding again restarts the setup from either side.
- **Saving:**
  - **Contacts:** added contacts are saved straight away.
  - **Sessions:** a session that couldn't be saved is neither offered nor confirmed.
- **Presence is gone:** the ping loop, `PresencePayload` (0x06), the online dots, and Android's `appVisible` bridge.
- **The UI:**
  - **Contact status:** goes pending → connecting → connected.
  - **Connection requests:** someone not in your contacts gets a pop-up, showing only their token prefix.
  - **Limits:** at most 8 new requests per 10 minutes, held in memory only.
  - **Dismissing:** "Not now" hides that person for a day, and closing the pop-up hides it until the app restarts.
  - **Muting:** requests can be muted, and the setting is saved.

**Relay link** (new crate `code/relay-link`, shared by client and relay)
- **Handshake.**
  - **The init:** the client's ephemeral X25519 key, padded to 320 bytes. It no longer carries the client's identity key.
  - **The reply:** signed, carrying the session ID the relay picked, and sent 3 times. The 3 copies together are smaller than the init.
  - **Repeats:** a repeated init from the same address gets the same reply. A copy from any other address is refused, so a spoofed init can't hand someone a link aimed at a victim. A handshake never replaces a live link.
  - **Rate limit:** a burst of 20 per address, then one a second. An IPv6 address counts by its /64, and IPv4-mapped addresses count as IPv4.
- **Packets:** `[type | session ID | 8-byte packet number | ChaCha20-Poly1305]`, with the header as associated data.
  - **Keys:** one per direction.
  - **Replays:** each lane has a 1,024-packet replay window. Message bursts get their own paced lane, so packets sent while a burst goes out don't push it out of the window.
- **Syncs (`TYPE_SYNC`):** carry `token | token_pub | signature | admission tags`.
  - **The token:** `SHA-256(label ‖ token_pub)[..16]`, from its own Ed25519 key.
  - **The signature:** covers a value derived from the link key.
  - **One token per link:** a sync on a new link retires the token's previous one.
- **Path validation:** a sync from a new address only gets a `TYPE_PATH_CHALLENGE`. The link moves once the HMAC'd answer comes back from there.
- **Admission tags:** contacts derive a per-direction 8-byte tag (`TYPE_ADMITTED_DATA`, up to 64 registered per sync).
  - **Strangers:** untagged packets share a 64 KiB queue per recipient, so someone with only your QR code can't fill the 2 MiB queue your contacts use.
- **Bounds:**
  - **Links:** at most 100k. One with no sync goes after 1 minute, and a synced one after an hour idle.
  - **Admission tags:** kept for at most 100k recipients.
  - **Tagless queues:** 64 MiB shared between them.
- **Liveness:** `TYPE_SYNC_ACK`. Clients sync 3 times every 15 s, and redo the handshake on the same socket after two minutes without hearing from the relay, or after a long sleep. Sleep is measured by the wall clock, as `Instant` stops while a phone sleeps. The CLI runs the same keepalive.
- **Receipts:** `TYPE_RECEIPT_REQUEST` and `TYPE_RECEIPT` (`client/src/confirmations.rs`). The client asks every 2 s while anything is unconfirmed. The relay answers only to the link's own address, listing the paced-lane packets it actually queued, so a packet dropped because the queue was full doesn't count.
  - **✓:** once the relay has a message's source symbols.
  - **!:** after 30 s without that.
  - **Saved:** statuses go in the chat history. A message still unconfirmed when the app closes is marked failed.
- **Relay hosting:**
  - **Key:** the plain-HTTP `GET /pubkey` endpoint and TOFU pinning are gone. The relay key is baked into each build (`SERVER_PUBKEY`), so the relay no longer listens on TCP.
  - **Logs:** no tokens or addresses, and refused packets are logged at debug level only.
  - **Hardening:** the identity file is 0600, and an existing one is tightened to 0600 on load. Core dumps are off. The container runs as non-root with a read-only filesystem.

**Delivery under loss**
- **In order** (`client/src/ordering.rs`): chunks carry their ratchet positions, so a message that overtakes an earlier one is held until that one arrives.
  - **The limit:** a missing message holds the rest up for at most 10 s (`REORDER_WAIT`).
  - **Saving:** held messages are saved with the session, and handed over if the session is replaced.
- **Parked for a PQ refresh:** messages that arrive before their PQ refresh now wait up to 7 days (up to 100 per contact), saved with the session, instead of being dropped after 60 s.

**Crypto**
- **ML-KEM-768** (`libcrux-ml-kem`, behind `client/src/pq.rs`) replaces round-3 Kyber. The sizes are the same, and saved keys load as ML-KEM keys.
- **Argon2id at 64 MiB and 3 passes,** up from 19 MiB and 2. Existing hashes keep their stored parameters.

**App and Android**
- **QR codes:** contact codes are `CG2:` + Base45, at error correction L, for a 29×29 code (from 37×37) that scans from further away. A v1 code gets an "older version" message.
- **The scanner:**
  - **Capture:** asks for 1080p with autofocus, and decodes at 1280px.
  - **Decoders:** `rqrr`, capped at a quarter of the UI thread. The device's own `BarcodeDetector` (Play services' ML Kit on Android) is opt-in.
  - **Closing:** stops the camera, even mid-start.
- **Screenshots:** blocked with `FLAG_SECURE`, which also covers your own QR code.
- **Notifications:** say "New message" unless "Say who each message is from" is on.
- **Message times:** shown on every message.
- **New Tauri commands:** `connection_requests`, `set_connection_requests_muted`, `dismiss_connection_request`, `notification_settings` and `set_notify_with_names`.

**Tooling**
- **New scripts:**
  - `build-apk.sh`: a LAN debug APK with this machine's relay address and key baked in. `--emulator` adds x86_64.
  - `run-emulator.sh`: creates and boots a Pixel 6 AVD with the webcam as its camera, then installs and opens the app.
  - `runserver-lan-lossy.sh` and `server/examples/lossy_proxy.rs`: the LAN relay behind a proxy that drops 70% of packets each way. Port 4431 skips the loss, and typing a new value changes it.
- **`server --print-pubkey`:** never creates a key, and fails with directions when there isn't one.
- **Updated scripts:** `runpeer*.sh` fill in the local relay's key, and `install-apk.sh` uses WSL's own adb for the emulator.
- **CI:** `cargo deny check` runs on every crate (`code/deny.toml`), and CI and the Dockerfiles include `relay-link`.
- **Docker:** the builders are pinned to `rust:1-slim-bookworm`, to match the bookworm runtime's glibc. The client image also installs `make` and `perl`, for the vendored OpenSSL.
- **Scripts:** they now print their own errors when an APK, an NDK or adb is missing. Before, `set -e` exited silently.
- **Docs:**
  - The README now says what's actually built.
  - Also updated: the relay README, ANDROID.md, the crypto flow and the EC2 guides.

### ⚠️ Breaking: deploy the relay and update every client together
- **Wire format:** everything above in `relay-link` is new. Some packets also changed size or format:
  - **KeyExchange:** 1,393 bytes, up from 1,384.
  - **SessionEstablish:** 1,232 bytes, up from 1,224.
  - **Chat FEC symbols:** 1,146 bytes.
  - **KeyExchange to a contact:** 1,447 bytes, within PPPoE's 1,464 (both sizes pinned by tests).
  - **QR codes:** now `CG2:`. Old and new builds can't read each other's codes.
  - **ML-KEM:** keys and ciphertexts keep their sizes, but old and new clients derive different secrets, so they can't set up a session.
- **Everyone re-adds their contacts.** An old identity gets a new, provable routing token on first load, and its old contacts are removed, with a warning in the log.
- **Every build needs `SERVER_PUBKEY`:**
  - **Local:** `runpeer.sh`, `runpeer-lan.sh --mobile` and `build-apk.sh` set it.
  - **Production:** ANDROID.md step 6.
  - **Between deploys:** the key persists in the `server_identity` volume.
- **EC2:** the inbound TCP 443 rule can be deleted.

### Testing
- **Checks:** fmt, `clippy --all-targets -D warnings` and the unit tests pass on every crate. The frontend is also checked for WASM.

  | Crate | Tests |
  |---|---|
  | relay-link | 13 |
  | fec | 25 |
  | Relay | 49 |
  | Client | 168 |
  | Tauri backend | 15 |
  | Frontend | 10 |

  The tests cover:
  - **Contact setup:** every scan order, crossed and late messages, re-adds and lost confirmations.
  - **Link security:** every replay and path attack above.
  - **Relay caps.**
  - **Delivery:** ordering, parking and confirmations, each surviving a restart.
  - **Code sizes:** QR and packet sizes are pinned.
- **End to end, over real UDP against the real relay:**
  - **`lossy_link`, 70% loss on one side:**
    - **Connecting:** the jammed side connects in 0.4–6.4 s.
    - **Messages:** 30/30 each way, in order.
  - **`lossy_link`, 75% on both sides:** 30/30 each way, in order, with 35 overtakes held back.
  - **`lossy_link`, 80% on both sides:** fails. 3 of 60 never arrive (see Follow-ups).
  - **Two CLI clients through the lossy proxy:**
    - **Confirmations:** ✓ at 0%, and 10/10 confirmed at 70% on both. A message fails after 31 s at 100%.
    - **Relay restart:** both clients reconnect by themselves in about 2 minutes, and messaging resumes.
  - **A temporary attacker harness:** a replayed sync from another address only gets a challenge. The victim keeps receiving, and follows its own move to a new socket.
- **Android:** cross-compiles for arm64, and the Kotlin compiles.
- **Not yet tested:**
  - an APK on the emulator or a phone since the review fixes, and the two-phone test (include adding someone who's offline, and a relay restart)
  - on a real phone: notifications, the screenshot block, and the camera changes
  - the desktop app by hand
  - the Docker images

### Follow-ups
- **Past 75% loss on both sides, messages go missing.** Nothing resends a message end to end. Roadmap 1.3 (receipts and top-ups) fixes this.
- **Messages sent while the link is down are lost** (up to about 2¼ minutes after a relay restart). The Phase 1 tunnel queues them.
- **Handshakes from spoofed addresses still cost the relay CPU,** and a full link table locks out new clients. The fix is a stateless cookie, as QUIC's Retry does.
- **Contacts are trusted with your queue:**
  - A malicious contact can fill your contacts' queue.
  - Contacts past the 64 registered share the queue for strangers.
- **Junk can fill the shared 64 MiB tagless budget** for up to 7 days.
- **Tagged queues have no overall cap.** One throwaway token per link, each with a 2 MiB queue, adds up to 100k × 2 MiB.
- **The handshake rate limiter stops limiting** once it tracks 65,536 sources. An IPv6 /48 can keep it that way for minutes.
- **Parked retries save the whole state once per payload.** That's about 100 saves of the full state per retry at the cap: slow, but correct.
- **A `server_identity` volume made by an old root-run container, with no identity file in it,** leaves the non-root relay unable to create one.
- **Packet numbers are in the clear.** Roadmap 2.5 hides them.
- **Connection requests:**
  - No Android notification is posted for them.
  - The requester's token isn't proven; the scan is the trust step.
- **Production:**
  - ANDROID.md still has a TODO for the production relay address and key.
  - Release signing is still to do.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
