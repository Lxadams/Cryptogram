Logan - Bug Fixes: close the open holes, plus easier contact adding and QR scanning

Closes issue: #40

### Changes in this PR:

**Stage 2: closing the open holes**

1. **Contact requests are accepted only from scanned contacts.** The "auto-accepting for demo" path is gone. A KeyExchange from someone you haven't added is dropped before it touches any contact state, so knowing your token is no longer enough to open a session with you. Both people now add each other (by scanning, or by pasting token + key), through a new `Client::add_contact`.
   - **Why the handshake changed too.** Once both sides scan, both send a KeyExchange, and they can cross. Under the old flow each side would then create its own session and accept the other's, leaving them on different sessions. There was also a second problem: whoever scans first has their KeyExchange dropped, so the other side would never get their Kyber key, and PQ injections in that direction would silently stop.
   - **The fix:**
     - **One establisher.** The contact with the lower routing token always sends the SessionEstablish, and one from the other side is dropped.
     - **A "have your keys" flag.** The KeyExchange gains a 1-byte `has_peer_keys` flag ("I already have your KeyExchange"). A contact without your keys gets yours again. The establisher sends SessionEstablish only once the other side has its keys.
     - **Ask once.** The responder asks for a session once (`awaiting_session_est`), so crossing KeyExchanges produce one SessionEstablish, not two.
   - Removing a contact and adding them back still works, from either side.
2. **Presence is removed entirely:**
   - the ping loop (`spawn_presence_loop`) and `PresencePayload` (`0x06`)
   - the relay's queue for presence pings (`enqueue_ephemeral`)
   - `Client::is_online`, `last_seen`, and the online dots in the UI
   - Android's `appVisible` bridge, which existed only to pause pings off screen. This replaces #36's "presence pings pause while the app is off screen".
3. **Syncs prove token ownership.**
   - **Before:** anyone with a link session could sync any routing token. Tokens are in QR codes, so someone could have a victim's queued messages sent to themselves, and ack them away so the victim never got them.
   - **Token:** the routing token is now the hash of a per-token Ed25519 key, `SHA-256("e2e-messenger/routing-token/v1" ‖ token_pub)[..16]`, kept separate from the identity key.
   - **New sync packet:** a sync is a new link packet type, `TYPE_SYNC` (4), carrying `token | token_pub | signature`. The signature covers a value derived from the link key, so a signed sync is useless on any other link.
   - **Relay checks:** the relay checks that the token is the hash of the key and verifies the signature with `verify_strict`.
   - **Old syncs rejected:** an empty `TYPE_DATA` packet, the old unsigned sync, is now rejected.
   - **Acks:** "acks only count from the token's current session" now actually means the owner.
4. **The relay's key ships with the app.**
   - **Endpoint removed:** the plain-HTTP `GET /pubkey` endpoint is removed. Whoever answered first on the network path could swap the key, and anyone probing could identify the server. The relay no longer listens on TCP at all, and `axum` is gone.
   - **No more trust-on-first-use:** the pinning that worked around this (`known_relays.json`, `reqwest`) is removed too.
   - **Where the key comes from now:** the app takes the key from `SERVER_PUBKEY`, set at launch or baked in at build time like `SERVER_ADDR` (`relay_pubkey_hex` in `commands.rs`).
   - **Script support:** the relay has a new `--print-pubkey` flag. `runpeer.sh` and `runpeer-lan.sh` use it to fill the key in for a relay on the same machine, and `runserver-lan.sh` prints it for other machines.
   - **TCP 443 removed** from the server's Dockerfile, `docker-compose.yml`, the deploy workflow and the EC2 docs.
5. **No tokens or IP addresses in relay logs.** "Request handling error from {addr}", "Queue full for token…" and the debug lines for received, sent, synced, forwarded and acked packets no longer name an address or token.

**Adding contacts: from the first two-phone test**

Two phones connected fine, but adding a contact looked broken: one side showed "pending" and the other showed nothing. That was the intended behaviour from item 1, just invisible.

6. **Pending hint and connection-request pop-up.**
   - **Pending hint:** a pending contact now shows "Waiting for them to scan your code", in the list and in its chat.
   - **Pop-up:** when someone who isn't a contact tries to connect, a pop-up says "Someone (a1b2c3d4...) wants to connect with you", with **Scan their code** and **Not now**. Scanning them back is what accepts. There's still no accept-without-scanning button, which would bring back what item 1 removed.
   - **Bounded and unverified:** the client remembers only the token and time of recent requests (at most 8, for 10 minutes, in memory only). The pop-up shows only the token prefix, never the name they sent, since nothing in it is verified until the scan.
   - **New Tauri commands:** `connection_requests` and `dismiss_connection_request`.
7. **QR codes that scan from further away.**
   - **Smaller code:** contact codes are now `CG2:` plus the token and key packed with Base45 (RFC 9285), at error correction L. That makes a 29×29 code, down from 37×37, so each square is about 22% bigger. The "Your QR code" dialog is also wider (520px, up from 380).
   - **Old codes:** a v1 code gets a clear "from an older version of the app" message.
   - **Scanner:**
     - asks for up to 1080p with continuous autofocus (left alone, Android WebViews tend to pick 640×480)
     - decodes at 1280px wide, up from 640
     - uses the WebView's `BarcodeDetector` where there is one
   - **`rqrr` still runs on every frame.** On the emulator the built-in detector exists but returns nothing, because Google Play services can't download its barcode module, and it gives no error. Decoding a 1280×720 frame with `rqrr` takes about 11 ms natively.

**Tooling and docs**

8. **`build-apk.sh`** builds a debug APK for LAN testing with this machine's IP and the local relay's key baked in. It finds the JDK, SDK and NDK if they aren't set, and handles the ranlib workaround. `--emulator` adds x86_64 code, so one APK runs on phones and the emulator.
9. **`run-emulator.sh`** creates a Pixel 6 emulator (`e2e-test`, Android 15, 2 GB of RAM, webcam as the back camera) on first run, then boots it, installs the newest APK and opens the app. This makes it possible to test with one phone.
10. **Docs:** the frontend README (relay key, and the add-each-other steps), ANDROID.md (relay key at build time, first run, presence bullet removed), the relay's README (signed sync, no presence queue) and the EC2 deploy guides (no TCP 443, how clients get the key).

### ⚠️ Wire format and deployment
Everything here is breaking. **Deploy the relay and update every client together.**
- **Wire format changes:**
  - **Syncs:** the new `TYPE_SYNC` (4) replaces the empty `TYPE_DATA` sync. An older client's syncs are rejected, so the relay never sends it anything.
  - **KeyExchange:** now 1385 bytes, up from 1384, because of the `has_peer_keys` byte.
  - **Presence:** `PresencePayload` (`0x06`) no longer exists.
  - **Contact QR codes:** now `CG2:`. Old and new builds can't read each other's codes.
- **Everyone has to re-add their contacts.** An identity saved before this change has a random routing token it can't prove to the relay. So on first load it gets a new token derived from a fresh token key, with a warning in the log. Its old contacts stop working, and their chat history is left with no way to view it.
- **Every build needs `SERVER_PUBKEY`.** Without it, Connect fails with an error explaining what's missing.
  - Desktop: `runpeer.sh` sets it for a local relay.
  - Phones: `build-apk.sh` and `runpeer-lan.sh --mobile` set it.
  - Production builds need the deployed relay's key (ANDROID.md, step 6).
  - The relay's identity persists in the `server_identity` volume, so the key doesn't change between deploys.
- **EC2:** the inbound TCP 443 rule in the security group can be deleted by hand.
- **New files need adding:** `build-apk.sh` and `run-emulator.sh` are new and untracked, so `git add` them.

### Testing
- **Unit tests:** all passing, and clippy is clean on every crate (frontend native and WASM).
  - **Relay: 18.** New:
    - a sync for someone else's token is rejected, whether claimed with your own key or with the victim's public key and a forged signature
    - a sync signed for another link is rejected
    - an empty data packet is no longer a sync
  - **Client: 119.** New:
    - each scan order: establisher first, responder first, both before either hears back
    - re-adding a removed contact, from either side
    - a stranger's KeyExchange leaves no contact state
    - a SessionEstablish from the responder is dropped
    - the sync proves token ownership
    - an old identity migrates to a provable token
    - connection requests are listed, dismissed and cleared on add
    - tampered or misaddressed requests are never noted
  - **Tauri backend: 14.** The trust-on-first-use pinning tests are removed with the feature.
  - **Frontend: 10.** New: RFC 9285's Base45 examples, round trips, damaged codes, the old-version message, the code's size pinned at 29×29, and `rqrr` reading back what's drawn.
  - **Repeat runs:** roles depend on random tokens, so the handshake tests were run 25 times with no failures.
- **End to end, with the real relay and two CLI clients:** 18 checks, run 5 times, with each side taking the establisher role in different runs.
  - `--print-pubkey` works, and nothing listens on TCP
  - a one-sided request is ignored
  - the session comes up once both sides add each other
  - messages get through both ways, including a 3,000-character one that crosses a PQ refresh
  - the relay log has no client addresses or routing tokens, and no request errors
- **`lossy_link` at 70% loss on both sides:** 5/5 messages each way, with both ratchets in step.
- **Android:**
  - The APK builds for arm64 and x86_64 (which also compiles the Kotlin change).
  - The app installs and runs on the emulator, and its WebView offers `BarcodeDetector` with QR support.
  - Two phones both connected to the relay. That test showed the silent one-sided request and led to item 6.
- **Not tested yet:**
  - the full two-phone handshake with the new pop-up
  - the camera changes (resolution, autofocus, the Samsung's `BarcodeDetector`) on a real phone
  - Connect from the emulator to the relay
  - clicking through the desktop app

### Follow-ups
- **A rare session mismatch.** Re-adding the same contact twice in quick succession, or both people re-adding each other at once after one removed the other, can produce two SessionEstablishes. If packet loss then reorders them, the two sides end up on different sessions. Removing and re-adding the contact fixes it.
- **A slow SessionEstablish is dropped (this was already the case).** One held at the relay for more than 5 minutes fails the timestamp check. Re-adding the contact recovers.
- **The pop-up needs the app open.** No Android notification is posted for connection requests.
- **The requester's token isn't proven to the receiver.** The pop-up only prompts a scan, and the scan is the trust step.
- **The token key doesn't hide who you are from the relay yet.** The relay still sees each client's identity Ed25519 key in the link handshake, so it can link a token to an identity. This matters if we move to per-contact tokens.
- **Link packets have no replay protection.** A captured sync replayed from another address redirects that token's deliveries until the owner's next keepalive (15 s). The packets stay queued and can't be read or acked, so the effect is a delay.
- **Production setup.** ANDROID.md still has a TODO for the production relay address, and now its key too. Release signing is also still to do.
- **Emulator scanning.** The emulator's camera is the laptop webcam, usually fixed-focus. Scanning a phone's code with it is hard; the phone scanning the emulator's screen works better.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
