Logan - Bug Fixes: close the open holes, plus easier contact adding and QR scanning

Closes issue: #40

### Fixes from review

**Contacts**
- **A stuck setup can always be restarted.**
  - **What changed:** the establisher now offers the session it already has, re-signed, each time it's asked, instead of making a new one. That was the real cause of the stuck setup.
  - **What it replaces:** the `awaiting_session_est` workaround is gone, and the responder simply asks whenever it has no session.
  - **The result:** adding a contact again restarts the setup from either side.
- **A session isn't used until both sides have it.** The responder confirms the session it took in, and the establisher holds off sending until then. A lost confirmation is recovered by adding the contact again from either side, or by any message on the session.
- **Add IDs tell old messages from new.**
  - **What they are:** whenever a client adds a contact from scratch, it gives them a new add ID from a counter that only goes up.
  - **Where they go:** every KeyExchange and SessionEstablish carries them, so a message from before either side last removed the other is recognisably stale.
  - **What they replace:** the `seen_session_keys` cache, which would also have blocked the establisher's re-offer.
- **Adding a contact is saved straight away.** An app closed before the other side adds back no longer forgets it added them, so their request isn't taken for a stranger's.
- **Upgraded identities lose their old contacts.** Before, they stayed showing as connected. Those sessions can't work once the routing token changes, so they're removed, with a warning in the log.
- **A stale SessionEstablish now recovers by itself.** One held at the relay past the 5-minute window (while offline, say) is answered with a fresh request, and the establisher offers the same session again.

**Relay security**
- **Session IDs are the relay's to give.**
  - **The handshake:** the relay picks an unused random ID and signs it into its handshake reply.
  - **No takeovers:** a handshake never replaces a live link. Seeing a session ID on the wire no longer lets anyone take that link over or delete its messages.
- **A sync only counts from the link's proven address.**
  - **The challenge:** a sync from any other address gets a path challenge sent there, sealed with the link key. The link moves only once the answer comes back over the link from that address.
  - **No relay state:** challenges are HMACs, so the relay doesn't have to remember them.
  - **Replays:** a recorded sync replayed from elsewhere moves nothing. A token syncing on a new link also retires its old link, so a replayed sync from the old link can't move it back.
- **Contacts get their own queue.**
  - **The tags:** each pair of contacts derives an 8-byte tag per direction from their static X25519 keys.
  - **Registering:** a client registers its contacts' tags in its sync (up to 64). Contacts put them on their packets, using the new `TYPE_ADMITTED_DATA`.
  - **The queues:** once a recipient has registered tags, packets without one share a separate 64 KiB queue, oldest out first. So someone who only has your QR code can't fill the 2 MiB your contacts' messages wait in.
- **Connection requests are limited, and can be muted.**
  - **Limit:** at most 8 new requests are listed per 10 minutes, however many identities they come from. Dismissed ones count towards it.
  - **"Not now":** hides that person for a day.
  - **"Mute connection requests":** stops the pop-ups until you unmute in the contact list. The setting is saved.
- **Link packets authenticate their type and session ID** (as AEAD associated data), so a packet can't be relabelled as another type or moved to another link.

**Scripts and app**
- **`runserver-lan.sh`** prints commands that work on this machine (no address, so the key is read locally) and on others (with the key).
- **`install-apk.sh` on WSL** uses WSL's own adb whenever it can see the device, which is the case for an emulator from `run-emulator.sh`. A USB phone still goes through Windows' adb.
- **`server --print-pubkey`** never creates a key. With no identity yet, it explains what to do and fails, so `build-apk.sh` and the `runpeer` scripts stop instead of building in a key no relay has.
- **QR scanner:**
  - **Closed while starting:** it no longer leaves the camera on. It used to touch the closed dialog's state and panic before stopping the camera.
  - **Closed during setup:** it no longer starts its scanning timer.
  - **Decode cost:** `rqrr` is held to a quarter of the UI thread. After a decode that took `t`, the next one starts no sooner than `4t` after the last one started.

**Cleanups**
- **New `code/relay-link` crate.** Packet types and layouts, the handshake, link sealing and the sync proof are now shared by client and relay, instead of copied into each. CI and the Dockerfiles include it. A test also pins the client's chat packet size to the relay's dummy-packet size.
- **Bounded test helper.** The helper that generated identities until one had a lower token, which could take any number of tries, now swaps identities instead.

### Fixes from the second review

**Relay**
- **An old link can't take its token back.**
  - **The hole:** a sync on a new link only retired the old link while the token's metadata (1,000 s) still pointed at it. A phone offline longer than that, then relaunched, left its old link alive for days. A captured sync from the old link, replayed from its address, then moved the token back and deleted the live link, cutting the phone off until it restarted.
  - **The fix:** the relay keeps the link each token was last synced on, so a sync on a new link retires the old one however long ago it was last used.
- **Link packets are numbered, and each number is taken in once.**
  - **The format:** the 24-byte random nonce is replaced by an 8-byte packet number, which is also the nonce (now ChaCha20-Poly1305). Each end keeps a 1,024-packet window per lane for reordering. Packets are 16 bytes smaller.
  - **Lanes:** a client numbers message bursts apart from everything else. Bursts are sealed at once but paced out over seconds, so acks and syncs sent meanwhile would otherwise push them out of the window. A burst is queued before the client's lock is released, so bursts leave in the order they were numbered.
  - **What it closes:** a copy of any packet, replayed from anywhere, is refused. That covers the path-validation hole (bounce the relay's challenge to the real client, then replay its answer from your own address to move its link there), the follow-up about replayed data packets filling a queue, and replayed syncs.
- **Each direction has its own key.** A packet the relay forwarded used to authenticate if bounced back to it, and was queued for a "recipient" that was really its delivery ID. It's refused now.
- **The relay's tables are bounded.**
  - **One token per link:** a link carries one token for good. Before, one link could sync any number of made-up tokens, each leaving admission tags behind for 7 days.
  - **Link lifetimes:** a link nobody syncs on goes after a minute. A synced one goes after an hour idle, down from 7 days, now that clients reconnect by themselves.
  - **Caps:** at most 100,000 links (handshakes past that are refused) and 100,000 recipients' admission tags (past that, a new recipient's packets share one queue, as before tags).
  - **Tagless queues:** recipients without tags (not synced since the relay started, or tokens nobody owns) share 64 MiB of queue between them, so made-up tokens can't take the relay's memory. The sweep logs a warning while any of these is full.
- **The handshake no longer identifies the client.** The init carried the client's Ed25519 identity key and a signature, which proved nothing (the relay accepted any key) and let the relay tie a token to an identity. It's now the ephemeral key padded with zeros, so the init stays bigger than the reply, and a handshake with someone else's address can't make the relay an amplifier.
- **Refused packets are logged at debug level,** not as errors. Anyone can send junk to UDP 443.

**Clients**
- **They reconnect by themselves.**
  - **How:** a client sends three syncs every 15 s, and the relay acks each one three times (new `TYPE_SYNC_ACK`). A client that hasn't heard from the relay for two minutes, or straight away after a long sleep, does the handshake again on the same socket. It checks the reply against the pinned relay key, syncs on the new link, and resends any KeyExchanges still pending. Heavy loss alone rarely looks like a dead link: at 70% loss each way, two silent minutes happen about one time in 200.
  - **The result:** a relay restart (every deploy), or a link that expired while the phone slept, no longer cuts everyone off until they restart the app.
  - **The CLI** now runs the same keepalive. It had none, so its NAT mapping lapsed.
- **Contact setup can't stall.**
  - **Late KeyExchanges:** a contact's KeyExchange is taken in however long it waited at the relay, since add IDs already tell an old one from a current one. Only the name in it is ignored when it's over 5 minutes old, as they may have renamed themselves. Before, if the second person added the first while the first was offline, their KeyExchange was dropped as stale, and both sides showed "Waiting for them to scan your code" forever.
  - **Late requests:** a stranger's connection request is listed however long it waited.
  - **Resends:** until a contact is connected, the client sends its KeyExchange again: after 30 s, then twice as long each time, up to 8 times. The count starts again when the contact replies, and resends go out straight away after reconnecting. Each step of the setup was a single UDP packet to the relay, which nothing resent.
  - **"Connecting":** a contact who has added you back now shows "connecting" while the session is set up, instead of "Waiting for them to scan your code".
- **Adding your own code is refused.** It started a KeyExchange loop with yourself through the relay that never ended. Packets claiming to come from you are dropped too.
- **Nothing is promised to a contact that couldn't be saved.** An establisher doesn't offer a session it couldn't save, and a responder neither takes one in nor confirms it (it rolls back). Before, a failed save after confirming could leave the two sides on different sessions after a restart.
- **Closing the connection-request pop-up** (the X, a click outside it, or Escape) only hides that request until the app restarts. "Not now" still hides that person for a day, as before. A stray tap used to count as "Not now".

### Changes in this PR:

**Stage 2: closing the open holes**

1. **Contact requests are accepted only from scanned contacts.** The "auto-accepting for demo" path is gone. A KeyExchange from someone you haven't added is dropped before it touches any contact state, so knowing your token is no longer enough to open a session with you. Both people now add each other (by scanning, or by pasting token + key), through a new `Client::add_contact`.
   - **Why the handshake changed too.** Once both sides scan, both send a KeyExchange, and they can cross. Under the old flow each side would then create its own session and accept the other's, leaving them on different sessions. There was also a second problem: whoever scans first has their KeyExchange dropped, so the other side would never get their Kyber key, and PQ injections in that direction would silently stop.
   - **The fix:**
     - **One establisher.** The contact with the lower routing token always sends the SessionEstablish, and one from the other side is dropped.
     - **A "have your keys" flag.** The KeyExchange says whether the sender already has the target's keys. A contact without your keys gets yours again. The establisher offers a session only once the other side has its keys and asks for one.
     - **One session on offer.** The establisher offers the session it has again (re-signed) whenever it's asked, until the responder confirms it, so crossing or repeated KeyExchanges end on one session (see "Fixes from review").
   - Removing a contact and adding them back works from either side, and so does adding them again to restart a stuck setup.
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
   - **Session IDs and replays:** see "Fixes from review". The relay picks session IDs, and a sync only counts from the link's proven address.
4. **The relay's key ships with the app.**
   - **Endpoint removed:** the plain-HTTP `GET /pubkey` endpoint is removed. Whoever answered first on the network path could swap the key, and anyone probing could identify the server. The relay no longer listens on TCP at all, and `axum` is gone.
   - **No more trust-on-first-use:** the pinning that worked around this (`known_relays.json`, `reqwest`) is removed too.
   - **Where the key comes from now:** the app takes the key from `SERVER_PUBKEY`, set at launch or baked in at build time like `SERVER_ADDR` (`relay_pubkey_hex` in `commands.rs`).
   - **Script support:** the relay has a new `--print-pubkey` flag, which never creates a key. `runpeer.sh` and `runpeer-lan.sh` use it to fill the key in for a relay on the same machine, and `runserver-lan.sh` prints it for other machines.
   - **TCP 443 removed** from the server's Dockerfile, `docker-compose.yml`, the deploy workflow and the EC2 docs.
5. **No tokens or IP addresses in relay logs.** "Request handling error from {addr}", "Queue full for token…" and the debug lines for received, sent, synced, forwarded and acked packets no longer name an address or token.

**Adding contacts: from the first two-phone test**

Two phones connected fine, but adding a contact looked broken: one side showed "pending" and the other showed nothing. That was the intended behaviour from item 1, just invisible.

6. **Pending hint and connection-request pop-up.**
   - **Pending hint:** a pending contact now shows "Waiting for them to scan your code", in the list and in its chat.
   - **Pop-up:** when someone who isn't a contact tries to connect, a pop-up says "Someone (a1b2c3d4...) wants to connect with you", with **Scan their code** and **Not now**. Scanning them back is what accepts. There's still no accept-without-scanning button, which would bring back what item 1 removed.
   - **Bounded and unverified:**
     - **What's kept:** only the token and time of recent requests, at most 8 new ones per 10 minutes, in memory only.
     - **Controls:** "Not now" hides someone for a day, and requests can be muted (saved).
     - **What's shown:** only the token prefix, never the name they sent, since nothing in it is verified until the scan.
   - **New Tauri commands:** `connection_requests` (tokens and whether muted), `set_connection_requests_muted` and `dismiss_connection_request`.
7. **QR codes that scan from further away.**
   - **Smaller code:** contact codes are now `CG2:` plus the token and key packed with Base45 (RFC 9285), at error correction L. That makes a 29×29 code, down from 37×37, so each square is about 22% bigger. The "Your QR code" dialog is also wider (520px, up from 380).
   - **Old codes:** a v1 code gets a clear "from an older version of the app" message.
   - **Scanner:**
     - asks for up to 1080p with continuous autofocus (left alone, Android WebViews tend to pick 640×480)
     - decodes at 1280px wide, up from 640
     - uses the WebView's `BarcodeDetector` where there is one
   - **`rqrr` runs too, whenever its share of the UI thread allows (at most a quarter).**
     - **Why not leave it to the built-in detector:** on the emulator it exists but returns nothing, because Google Play services can't download its barcode module, and it gives no error.
     - **Its cost:** decoding a 1280×720 frame with `rqrr` takes about 11 ms natively, and more in a phone's WebView.

**Tooling and docs**

8. **`build-apk.sh`** builds a debug APK for LAN testing with this machine's IP and the local relay's key baked in. It finds the JDK, SDK and NDK if they aren't set, and handles the ranlib workaround. `--emulator` adds x86_64 code, so one APK runs on phones and the emulator.
9. **`run-emulator.sh`** creates a Pixel 6 emulator (`e2e-test`, Android 15, 2 GB of RAM, webcam as the back camera) on first run, then boots it, installs the newest APK and opens the app. This makes it possible to test with one phone.
10. **Docs:** the frontend README (relay key, and the add-each-other steps), ANDROID.md (relay key at build time, first run, presence bullet removed), the relay's README (signed sync, no presence queue) and the EC2 deploy guides (no TCP 443, how clients get the key).

### ⚠️ Wire format and deployment
Everything here is breaking. **Deploy the relay and update every client together.**
- **Wire format changes** (all defined in `code/relay-link`, apart from the E2E payloads):
  - **Handshake:** the init is the client's ephemeral X25519 key padded with zeros to 320 bytes: no session ID, identity key or signature. The reply carries the session ID the relay picked, and its signature covers it. The relay sends it three times (`REPLY_COPIES`), which together are still smaller than the init.
  - **Keys:** the link has one key per direction, from HKDF labels `e2e-messenger/link/v2/to-relay` and `.../to-client`.
  - **Link packets:** `[type | session ID | 8-byte packet number | ChaCha20-Poly1305]`. The packet number is the nonce and replaces the 24-byte random one. The whole header is authenticated as AEAD associated data.
  - **Syncs:** the new `TYPE_SYNC` (4) replaces the empty `TYPE_DATA` sync. It carries `token | token_pub | signature | admission tags`. An older client's syncs are rejected, so the relay never sends it anything.
  - **New packet types:** `TYPE_ADMITTED_DATA` (5), `TYPE_PATH_CHALLENGE` (6), `TYPE_PATH_RESPONSE` (7) and `TYPE_SYNC_ACK` (8).
  - **KeyExchange:** now 1393 bytes, up from 1384. It gains a flags byte ("have your keys", "have a session"), the sender's add ID, and the add ID its session was made for.
  - **SessionEstablish:** now 1232 bytes, up from 1224, carrying the two add IDs it was made for.
  - **Packet sizes:** chat packets to a contact (FEC symbols) are 1,146 bytes, with their admission tag, and KeyExchanges to a contact are 1,447 (1,439 before the tag is known), inside a PPPoE link's 1,464. Both are pinned by tests.
  - **Presence:** `PresencePayload` (`0x06`) no longer exists.
  - **Contact QR codes:** now `CG2:`. Old and new builds can't read each other's codes.
- **Everyone has to re-add their contacts.** An identity saved before this change has a random routing token it can't prove to the relay. So on first load it gets a new token derived from a fresh token key, and its old contacts are removed, since they could only reach the old token. The log says so. Their chat history is left with no way to view it.
- **Every build needs `SERVER_PUBKEY`.** Without it, Connect fails with an error explaining what's missing.
  - Desktop: `runpeer.sh` sets it for a local relay.
  - Phones: `build-apk.sh` and `runpeer-lan.sh --mobile` set it.
  - Production builds need the deployed relay's key (ANDROID.md, step 6).
  - The relay's identity persists in the `server_identity` volume, so the key doesn't change between deploys.
- **EC2:** the inbound TCP 443 rule in the security group can be deleted by hand.
- **New files need adding:** `build-apk.sh`, `run-emulator.sh` and `code/relay-link/` are new, so `git add` them.

### Testing
- **Unit tests:** all passing. `fmt`, and `clippy -D warnings` on all targets, are clean on every crate, with the frontend checked both native and for WASM.

  | Crate | Tests |
  |---|---|
  | relay-link (new) | 11 |
  | Relay | 40 |
  | Client | 141 |
  | Tauri backend | 14 |
  | Frontend | 10 |

  - **From the second review** (each fails without its fix):
    - relay: an old link can't reclaim its token after the token's metadata expired; a link syncs one token; replayed syncs and data packets are refused from any address; a replayed path response can't move a link; a forwarded packet bounced back is refused; handshakes are refused while the link table is full; the admission table is capped; tagless queues share a budget; links nobody syncs on expire in a minute
    - relay-link: each direction has its own key; a packet is taken in once; lanes are windowed apart; the replay window's edges; the handshake init's padding
    - client: adding your own code is refused; a late KeyExchange from a contact still carries the setup on, without its name; the setup completes when the second KeyExchange arrives late, or when the whole first round is lost; late connection requests are listed; resends back off, stop, and restart on progress; contact status goes pending, connecting, connected; unsaved sessions are neither offered nor taken in; unacked syncs lead to a new handshake that only the pinned relay can answer, then a sync and resends on the new link; unanswered handshakes are retried
  - **relay-link:**
    - a sealed packet opens only as sealed, with its type, session ID and packet number tamper-proof
    - the handshake gives both ends one key, and its reply fits only its own handshake, relay and session ID
    - a sync proves ownership on one link only
    - admission tags are bounded
  - **Relay:**
    - a sync for someone else's token is rejected, whether claimed with your own key or with the victim's public key and a forged signature
    - a sync signed for another link is rejected
    - an empty data packet is no longer a sync
    - a handshake, even a replayed one, never takes over a live link, and every link gets its own session ID
    - a sync replayed from another address only gets a challenge
    - a link moves only when it answers from its new address, not from a third one
    - challenges expire, and are bound to their link and address
    - an old link's sync can't move a token back
    - flooding a token can't block its contacts' messages; without tags everything shares one queue; tags outlast the recipient's metadata
    - `--print-pubkey`'s lookup creates nothing
  - **Client:**
    - each scan order: establisher first, responder first, both before either hears back
    - a stuck setup restarted by adding again, from either side
    - a lost confirmation recovered by adding again from either side, or by a message
    - a repeated request gets the same session, whichever offer arrives first
    - both re-adding at once after a removal, delivered newest or oldest first, once or twice each: one session every time
    - messages from before a re-add are ignored
    - a stale offer is answered with a fresh request
    - adding a contact is saved straight away
    - re-adding a removed contact, from either side
    - a stranger's KeyExchange leaves no contact state
    - connection requests are listed, limited, dismissed for a day, muted (saved), and cleared on add
    - admission tags are shared per direction, registered in the sync, put on packets to contacts, and dropped when a contact is removed
    - the handshake takes the relay's session ID and refuses an impostor's reply
    - path challenges are answered
    - an old identity migrates to a provable token and loses its contacts
  - **Tauri backend: 14.** The trust-on-first-use pinning tests are removed with the feature.
  - **Frontend: 10:**
    - RFC 9285's Base45 examples, round trips and damaged codes
    - the old-version message
    - the code's size pinned at 29×29
    - `rqrr` reading back what's drawn
- **End to end, against the real relay over real UDP:**
  - **`lossy_link` at 70% loss, re-run after the second review's fixes:** 10/10 messages each way with Alice's link jammed, and again with Bob's, with both ratchets in step.
  - **Relay restart, with two CLI clients (a temporary harness, not committed):** they connect and message, adding your own code is refused, then the relay is restarted. Both notice their syncs going unacked, redo the handshake by themselves, and messages flow both ways again.
  - **A temporary harness (not committed):**
    - an attacker's handshake gets its own session
    - Bob's sync replayed from the attacker's address only gets a challenge
    - Bob keeps receiving, and none of his packets reach the attacker
    - when Bob moves to a new socket, he answers the challenge and his messages follow him
  - **`--print-pubkey` with no identity:** fails with directions and creates nothing.
- **`install-apk.sh`, with fake `adb` binaries simulating WSL:** the emulator goes through WSL's adb, and a USB phone through Windows'.
- **Not re-run since the review fixes:**
  - the Android builds and emulator runs
  - the two-phone test (worth including adding someone while they're offline, and a relay restart)
- **Not tested yet:**
  - the full two-phone handshake with the new pop-up
  - the camera changes (resolution, autofocus, the Samsung's `BarcodeDetector`, the decode cap) on a real phone
  - Connect from the emulator to the relay
  - clicking through the desktop app
  - the Docker images

### Follow-ups
- **The pop-up needs the app open.** No Android notification is posted for connection requests.
- **The requester's token isn't proven to the receiver.** The pop-up only prompts a scan, and the scan is the trust step.
- **Contacts are trusted with your queue.** A contact's tag only proves they're a contact, so a malicious contact can still fill your contacts' queue. Contacts beyond the 64 a sync registers share the small queue for strangers.
- **Handshakes still cost the relay CPU.** Each is a DH and a signature for an unauthenticated packet. The caps keep memory bounded, but a flood can still use CPU, and while the link table is full, new clients can't connect. A stateless cookie, as QUIC's Retry does, or a per-address rate limit would close it.
- **Messages sent while a link is down are lost.** That's from the relay going away until the client notices, about 25 s at most. Nothing resends a message end to end.
- **Junk can fill the tagless budget.** Once the shared 64 MiB is full, packets for recipients who haven't synced since the relay restarted are refused until it expires, which can take up to 7 days.
- **Packet numbers are in the clear,** so someone watching a link can count its packets (WireGuard's counters are too). QUIC's header protection hides them.
- **The QUIC branch** replaces this link layer, so the link-layer fixes here are moot there. The client-side ones (the setup, resends, your own code, saving) need porting.
- **Production setup.** ANDROID.md still has a TODO for the production relay address, and now its key too. Release signing is also still to do.
- **Emulator scanning.** The emulator's camera is the laptop webcam, usually fixed-focus. Scanning a phone's code with it is hard; the phone scanning the emulator's screen works better.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
