Logan - Android app, reliable background delivery and a responsive UI

Closes issue: #36

### Changes in this PR:

**Android app**
1. **Android project and build guide.** `code/frontend/src-tauri/gen/android/` is committed, and `code/frontend/ANDROID.md` covers toolchain setup through to installing on a phone. Android apps can't be launched with environment variables, so the relay address is baked in at build time (`SERVER_ADDR`, read with `option_env!` in `server_addr_raw`).
2. **Receiving in the background.** While someone is logged in, a foreground service (`MessageService.kt`) keeps the process from being frozen, so the UDP socket keeps receiving. Android shows an ongoing "Connected" notification while it runs. A message that arrives while the app is off screen shows a notification that names the sender but never the text.
   - The bridge between Kotlin and Rust (`NativeBridge.kt` ↔ `src-tauri/src/background.rs`) works by having a Kotlin thread block in a native `nextEvent()` call.
   - It goes that way round because Tauri's own Rust-to-Kotlin plugin calls `expect` an activity to exist. They would panic once the app has been swiped away.
3. **Swiping the app away.** While logged in, the app keeps running instead of exiting. Previously tao called `process::exit` when the last window closed. On reopen, the window is rebuilt from `tauri.conf.json` and the frontend picks up the session again through a new `current_session` command, so you go straight back to your chats.
4. **Presence pings pause while the app is off screen.** This saves battery, because each ping wakes the radio. Contacts see you as offline until you reopen the app, but messages still arrive. The keepalive also syncs immediately when the app comes back on screen.
5. **Session handling.**
   - Android's standard library has no file locking, so the session lock now accepts `Unsupported`.
   - `login` ends any existing session first.
   - `bootstrap` stops the previous connection's background loops.
   - `delete_identity` refuses to delete the identity that's logged in.
6. **Manifest.**
   - Cloud backup and device transfer are switched off (`allowBackup="false"` and `data_extraction_rules.xml`), so identities never leave the phone.
   - Adds the camera, notification and foreground-service permissions.
   - Drops the template's Android TV launcher entry.
   - `MainActivity` pads the app clear of the status bar, navigation bar and keyboard. Android 15+ forces edge-to-edge, and older WebViews report the CSS safe-area insets as zero, so this is done natively.

**Relay and client: messages survive a recipient that's offline or asleep**

7. **Delivery receipts at the relay.**
   - **Before:** the relay sent each queued packet once to the recipient's last known address, then deleted it. Anything sent to a phone that had gone to sleep, or whose app had just been killed, was lost. Presence pings, which every contact sends every 20 seconds, were also queued like messages:
     - Before #32, they pushed real messages out of the old 50-packet queue after about 17 minutes offline.
     - Under #32's 2 MiB cap, which refuses new packets once full, they would eventually lock real messages out instead.
   - **Now:** each forwarded packet carries a delivery ID in the envelope's 16-byte prefix. The recipient confirms it with a new `TYPE_ACK` (3) packet. Until then the relay resends it with backoff (2s, 4s, 8s… up to 60s), and immediately when the recipient syncs from a new address or after more than 30 seconds of silence. Resends go through #32's 5 ms per-recipient pacing like everything else.
   - Packets are kept for up to 7 days, within #32's 2 MiB cap per recipient.
   - Presence pings (inner type `0x06`) are sent once, and only to recipients that are online.
   - An ack only counts if it comes from the recipient's current link session.
   - **Links stay alive while in use.** Every authentic packet refreshes its link's expiry, which is now 7 days after last use. Before, it was 1 hour after the handshake (finding R-3 in `implementation-review.md`), so a long-running app went deaf after an hour. Now a phone that slept overnight wakes up to a working link.
8. **Client side.** A new `Client::handle_relay_packet` opens a packet, handles it, then sends the ack. The ack goes after the packet is handled, so a crash in between causes a resend rather than a lost message. Recent delivery IDs are remembered so a resend is acked again but never handled twice, since a resent KeyExchange would restart the session. The CLI, the Tauri app and #32's `lossy_link` example all use it.

**Frontend layout**

9. **The app fits the window at any size.** Long content scrolls inside its own panel, so the header and message box stay in view. This fixes the default 800×600 window, where the message box was pushed off-screen and couldn't be reached.
   - **Under 720px wide** (phones and narrow windows), the main screen shows one column: the contact list, or the open chat with a "← Contacts" button.
   - **Identity card:** now a single row, with the token and key folded under "Show token and key".
   - **Login, create identity and connect screens:** a centred column at most 440px wide.
   - **Contact rows:** stay on one line, and long names are cut off with "…".
   - **Touch screens:** bigger tap targets.
   - **Scrollbars:** match the theme.

**Docs and tooling**

10. **Docs.** ANDROID.md (including the "Receiving in the background" section), a link from the README, and updates for delivery receipts in `doable-cryptographic-flow.md`, `raptorq-fec-transport.md` and the relay's README.
11. **`runpeer.sh`.** It now strips the environment that VS Code's snap leaks into its terminal. That environment crashed the WebKitGTK window and moved identity storage under `~/snap`.

### Merged with main (#32, RaptorQ FEC)
`main` is merged into this branch, so this builds on #32. The relay keeps #32's design:
- forwarding on arrival
- 5 ms pacing per recipient
- a 2 MiB queue cap that refuses new packets once full

The one change is that packets stay in that queue until they're acked. `take_due` now releases the oldest packet that's due (new, or its resend time reached) without removing it.

#32's tests are adapted to match. A backlog still goes out whole, in order and one packet per pacing slot, and the packets then stay queued until acked.

FEC and acks work at different layers:
- **FEC** rebuilds a message from whichever symbols arrive.
- **Acks** make the relay keep trying until the recipient actually has the packets, which FEC can't do for a phone that's asleep or offline.

### ⚠️ Wire format and deployment
- **New relay packet type:** acks (type 3). The 16-byte prefix on forwarded packets now holds the delivery ID instead of zeros.
- **Older clients:** they ignore the delivery ID, but never send acks, so the relay keeps resending to them (at most every 60 seconds, for up to 7 days). Deploy the relay and update all clients together.
- **Android build:** needs `RANLIB_aarch64_linux_android` set, or OpenSSL's build fails (ANDROID.md, step 4).

### Testing
- **Unit tests:** all passing, and clippy is clean on all three.
  - **Relay: 17.** 7 are new: resend backoff, acks only from the recipient's session, resend after silence or an address change, presence pings sent once and never queued for an offline recipient, link kept alive by use, and the backoff cap. #32's pacing and forwarding tests are adapted to ack-based retention.
  - **Client: 117.** 3 are new: ack and resend handling, no ack for relay dummy packets, and delivery-ID memory.
  - **Tauri backend: 14.**
- **End to end, through the merged relay over real UDP:**
  - **`lossy_link` at 70% loss** on the jammed side: 20/20 messages delivered each way, with both ratchets in step.
  - **Recipient restarted:** Bob's CLI is killed while the relay still has his address. Alice messages him, Bob restarts from his saved state, and the message arrives. Against `main`'s relay, the same test loses it.
- **APK:** the debug build for arm64 builds without warnings.
- **On a Galaxy S23+** (debug build, relay on a PC on the same Wi-Fi, before merging `main`):
  - Added a contact by QR code and received messages.
  - Confirmed the foreground service is running (`dumpsys`).
  - Swiped the app away and reopened it twice. Each time the window was rebuilt, in the same process, with the session intact (logcat).
  - Presence pings paused on Home and resumed on reopen (logcat).
- **Layout:** screenshots in headless Firefox at 384×832, 640×480, 800×600 and 1280×800 against a mocked backend, then installed on the S23+.
- **Not tested yet:**
  - Seeing the new-message notification on a locked phone.
  - The battery impact.
  - A release (signed) build.

### Follow-ups
- Fill in the production relay address in ANDROID.md (still a TODO).
- **Process death:** if Android kills the app, nothing is received until you log in again. Logging in needs the passcode, so it can't happen automatically; the relay holds messages for up to 7 days.
- **Deep sleep:** in Doze, Android can delay delivery until the phone wakes. Push notifications via Firebase Cloud Messaging would avoid this, but Google would see when messages arrive.
- **UI decisions:**
  - Should the token and key show by default on wide windows?
  - Should the "ESTABLISHED" pill be dropped? The online dot already marks established contacts, and the pill is what cuts off long names in the sidebar.
- Set up signing for release builds.
- **Ack overhead under heavy loss.** At 70% loss, acks get lost too, so the relay resends symbols FEC had already made unnecessary. In the `lossy_link` run, Bob sent 764 packets to Alice and 1944 reached her jammed link. Acking once per decoded message, covering all its symbols, would cut this.
- **No handshake after a relay restart.** Clients never redo the handshake, so after a relay restart (or a link left unused for 7 days) you still need to log out and back in. This is what remains of R-3.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
