Logan - PQ Inject Fixes: recover lost PQ injects, repair sessions, loss testing and network stats, chat UI, Cryptogram branding

Closes issue: #

### Summary
- **A lost PQ inject no longer breaks a session for good.** The receiver asks for it again and the sender resends it, so the held messages decrypt. Before, one lost burst left one direction of the chat dead until both people re-added each other.
- **"Repair session"** sets up a fresh session with a contact without removing them, for anything recovery can't fix.
- **Contact setup and repair hold up at heavy loss.** Setup packets go out 3 times, and are resent after 10 s instead of 30 s. At 70% loss each way, a repair took 30–71 s. Before, it took 251 s once and didn't finish within 5 minutes three times out of four.
- **Loss can be simulated on the device itself,** with a percentage each way, so testing no longer needs a lossy relay.
- **Network stats and an unstable-network warning,** behind a **Network stats** setting that's off by default, as measuring sends extra packets:
  - **Network fold:** the relay's status, packet counts, loss each way over the last 10 s, and retransmissions.
  - **Warning:** a thin amber bar while 90% or more is being lost either way.
- **Chat UI:**
  - **New messages:** counts next to each contact, newest conversation first.
  - **Header:** a ⋮ menu, with the contact's name centred.
  - **Main screen:** a **+** by "Contacts" for adding people, settings in their own section after the contacts, and a sun or moon for the theme.
  - **Sending:** a spinner while a message sends, and a retry button next to a **!**.
  - **QR codes:** they open and close around a scan.
  - **Android back:** closes what's on top instead of leaving the app.
  - **Keyboard:** the newest message stays in view when it opens.
- **Branding:**
  - **Name:** the app is now called Cryptogram.
  - **Look:** the new palette, and the logo as the app icon.
  - **Start page:** a "Sign in" page before login.
  - **Connect:** waits at least 2 s.
- **Screen capture is allowed again** (no `FLAG_SECURE`), so a phone can be mirrored to a laptop for demos.
- **Tooling:**
  - **`-ip`, `-p` and `-pk`:** `build-apk.sh` and `runpeer.sh` take them to point at any relay.
  - **logcat:** debug Android builds send the client's log output there.
  - **CLI:** a `repair` command.

### What changed

**Lost PQ injects** (`code/client/src/lib.rs`, `packets.rs`, `storage.rs`, `transport.rs`)
- **The bug:** a PQ inject travels once, in the burst of the message that triggered it, and the sender mixes it into its send chain straight away. If that whole burst was lost, every later message failed to decrypt and was held for an inject nobody would send again. Reproduced on a phone and the emulator at 100% sending loss.
- **The sender keeps its injects:** the latest 20 per session (`KEPT_PQ_INJECTS`, covering the 100 messages the receive chain looks ahead), as the signed 0x05 payloads, saved with the session (`SymmetricSessionState::sent_pq_injects`). They hold only the Kyber ciphertext and signature, nothing secret.
- **The receiver asks again** (`Client::pq_inject_requests`): while it's holding messages for a missing inject, it sends a new `PQInjectRequestPayload` (0x08) for the positions it needs.
  - **Timing:** first after 3 s, as an inject is often just behind, then after 6 s, 12 s, and every 30 s until the messages decrypt.
  - **Signing:** signed with a label and the session binding, so it only verifies on the session it was made for.
  - **Copies:** 3 of each request.
- **The sender resends** the injects in the asked-for range as direct packets, 3 copies each, through a new outbox that `handle_relay_packet` sends after its reply.
  - **Pruning:** it drops the injects the request shows the receiver already has.
  - **Rate limit:** at most one answer per contact per second.
  - **Older sessions:** a request signed on an older session is ignored. Most often it was sent before a repair, so it's logged as a note, not an alert.
- **Front ends:** the Tauri tick loop and the CLI send the requests twice a second, along with receipt requests.

**Repair session** (`Client::repair_session`, `repair_session` command)
- **What it does:** drops the session and sends a KeyExchange with a new add ID, the way removing and re-adding someone would. The other side drops its copy when that arrives, and the two set up a fresh session, PQ keys and all.
- **What stays:** the contact, their name and the chat history.
- **Where:** either side can repair, from the chat's ⋮ menu. It's hidden while a contact is pending. The CLI has `repair <token>` too.

**Contact setup at heavy loss** (`code/client/src/lib.rs`)
- **Why copies, not FEC:** messages already go out as FEC bursts. A KeyExchange or SessionEstablish is a single packet, though, so it can't be spread over symbols, and copies are its redundancy.
- **Copies:** setup packets to a contact who has added us go out 3 times (`SETUP_COPIES`), each sealed on its own. At 70% loss on the uplink, one copy reaches the relay 30% of the time, and three 66%. The relay then resends what it has until the contact acks it.
- **First requests:** to someone who hasn't added us yet (no admission tag), a setup packet goes just once. Those share a small queue at the relay with everyone else's first requests.
- **Sooner resends:** an unanswered KeyExchange is first resent after 10 s instead of 30 s, then twice as long each time, as before. A repair at heavy loss takes several steps, so each one waiting 30 s added up.
- **Sending the copies:** `Client::take_extra_packets` hands over the extra copies, and front ends send them after what `add_contact` and `repair_session` return. `keepalive` and the relay handshake return them with their own packets.
- **Measured** through the lossy proxy, at 70% loss each way:

  | | Repair | First contact setup |
  |---|---|---|
  | Before | 251 s, then 3 runs not done in 5 minutes | not done in 5 minutes |
  | After | 42, 30, 63 and 71 s | 41–233 s |

**Simulated loss** (new `code/client/src/netsim.rs`)
- **Two percentages:** outgoing and incoming, set under "Simulated loss" at the bottom of the Network fold (`simulated_loss`, `set_simulated_loss` commands).
- **Coverage:** every send to and receive from the relay goes through it: message bursts, keepalives, receipts, acks, contact requests and the relay handshake.
- **Defaults:** off (0%) by default, and reset when the app closes.

**Network stats** (`netsim.rs`, `Client::retransmissions`, `network_stats` command, `NetworkStats`)
- **Where:** a "Network" fold in the settings section after the contacts, updated every second.
- **The setting:** a **Network stats** checkbox under Settings, off by default and saved per device (`localStorage`).
  - **Off:** the main screen doesn't ask for the stats, so the client sends no probes and there's no warning. The Network fold says the stats are off, and still has the simulated loss.
  - **On:** stats and the warning, with the probes below.
- **What it shows:**
  - **The relay:** its address and status. It's connected if heard from in the last 40 s, quiet if not, or reconnecting.
  - **Packets:** sent and received since the app started, with any dropped by the simulated loss (`netsim::packet_counts`).
  - **Loss:** each way, over the last 10 s (see below).
  - **Retransmissions since login:** contact-setup resends, reconnects, PQ refreshes asked for and resent, messages retried, and deliveries received twice.

**Loss estimate and unstable-network warning** (new `code/client/src/link_quality.rs`)
- **What it measures from:** the relay answers every sync and receipt request with 3 copies of one packet, and numbers everything it sends in order. So the answers it sent are the ones that arrived plus the gaps in the numbering.
- **The estimate,** over the last 10 s, giving each answer 250 ms to arrive:
  - **Receiving loss:** the copies that arrived, out of 3 per answer sent.
  - **Sending loss:** the answers sent, out of the requests sent.
- **Replays count too:** the copies are the same packet, so the link turns copies 2 and 3 away as replays. It does that only after authenticating them, so they're still counted.
- **Probes:** while the stats are polled, the client sends 8 receipt requests a second, so 10 s holds enough to measure. That's about 4 KB/s.
  - **Background:** none while the app is in the background or the screen is off (`document.hidden`).
  - **Why that check is needed:** the web view keeps the page's timers running in the background. Before the check, a phone with the app in the background went on probing at the same rate: about 7 requests a second up, and 21 answers down.
- **The warning** (`NetworkWarning`):
  - **What:** a thin amber bar across the top of the main screen, above the chat on a phone too.
  - **When:** shown once either way reaches 90%, and kept until it's below 88%, so it doesn't flicker.
  - **What it says:** how much is lost and which way, or that nothing came back from the relay at all.
- **Measured on real UDP** through the lossy proxy:

  | Loss each way | Read as (sending / receiving, mean) | Warning on |
  |---|---|---|
  | 50% | 52% / 51% | never |
  | 70% | 67% / 64% | never |
  | 85% | 86% / 85% | 60% of the time |

  - **Step response:** after a step up to 85%, the warning came on about 16 s later. After a step back down, it cleared within a second.
  - **How these were worked out:** the runs were recorded with the warning at 80%. The "Warning on" figures apply the 90%/88% thresholds to the same recorded estimates.
  - **Not measured:** loss of 90% or more each way.

**Chat UI** (`code/frontend/src/app.rs`, `style.css`)
- **New-message counts:**
  - **Badge:** a small square next to a contact's name counts the messages that arrived while their chat wasn't open. Opening the chat clears it.
  - **Back button:** shows the total, since on a phone the list is hidden while a chat is open.
  - **Restarts:** counts live in the frontend only, so they start again at zero after a restart.
- **Newest conversation first:** `list_contacts` reports each contact's latest message time, sent or received (`ContactDto::last_message_ms`, from the new `ChatHistory::latest_per_contact`), so the order survives a restart. Contacts with no messages follow, by name.
- **Chat header:**
  - **Title:** the contact's name, centred, instead of "Chat with *name*".
  - **Menu:** a ⋮ button holds "Repair session" (a reusable `Menu`, built like `Modal`).
  - **Back button:** just ←.
- **Sending:**
  - **Spinner:** a small spinner shows while a message sends. ✓ and **!** are unchanged.
  - **Retry:** a retry button sits next to a **!**. `retry_message` sends the text again as a new message at the bottom, and deletes the failed one from the history (`ChatHistory::message`, `ChatHistory::delete`). If the first try reached the contact after all, they get it twice.
- **QR codes** (new `QrCodeModal`, owned by `MainScreen`):
  - **They scanned you first:** scanning their code closes yours.
  - **You scanned first:** scanning someone who hasn't scanned you yet opens your code, which closes once they have (their status leaves "pending").
- **Android back** (`MainActivity.kt`, new `code/frontend/src/back_button.rs`): `MainActivity` asks the page about every back press (`window.__cryptogramBack()`). The page closes the top layer over the contact list (a chat, your QR code, the scanner, the Manual add dialog) and says so. With none open, back goes on to Android's default, which puts the app in the background.
  - **Why not history:** each layer first got a web view history entry, which Tauri goes back through. But Chromium marks an entry for the back button to skip when the page adds the next one without a tap, as when your QR code opened by itself after a scan. The web view then said it couldn't go back, so back left the app from an open chat. Seen on a phone: back exited with the chat's entry at index 1 of 2.
  - **Why not Tauri's back-button listener:** Tauri attaches its back handling to the first activity only. Closing the app while it keeps running in the background (for notifications) destroys that activity, and reopening makes a new one. Back then left the app from anywhere until a force stop. `MainActivity` attaches its handler to every activity.
  - **Order:** back closes the scanner or Manual add, then the QR code, then the chat, and only then leaves the app.
- **Keyboard:** opening it shrinks the web view, and the transcript's scroll position counts from the top, so the newest messages slipped out of sight. The transcript now stays at the newest message through a resize if it was there.

**Branding** (`code/frontend/branding/`, `style.css`, `app.rs`)
- **Name:** "Cryptogram" in the window title, the header and the Android launcher (`productName`, `strings.xml`).
  - **Unchanged:** the app identifier, the Android package and the crate names, so the new build installs over the old one and keeps its data.
- **Palette:** the colour tokens come from `#164858`, `#EFFBF2`, `#1F8A70` and `#02141A`, plus shades mixed from them, with a new `--info`. Dark mode uses `#02141A` behind panels shaded from `#164858`. Light mode uses `#EFFBF2` behind white panels.
- **App icon:** made from `logo-app-icon.svg`, with an adaptive icon on Android (a foreground and a background).
  - **Sources:** they're in `code/frontend/branding/`.
  - **Regenerating:** run `cargo tauri icon ../branding/icon.json` from `src-tauri`.
- **Start page** (`WelcomeScreen`):
  - **What's on it:** the large logo, in the version for the theme, the name and **Sign in**, which goes to the Login page.
  - **Who sees it:** someone already signed in goes straight to their contacts.
  - **Getting back to it:** log out, or Android back from Login or Create Identity.
- **Connect:** the main screen appears no sooner than 2 s after **Connect** is clicked (`CONNECT_MIN_WAIT`), however fast the relay answers. Errors show straight away.
- **Main screen layout:**
  - **Identity card:** just your name, at the top. Its **Present QR code** button is gone, as **Show QR code** under the **+** does the same.
  - **Adding contacts:** a **+** at the far right of the "Contacts" heading opens a menu with **Show QR code**, **Scan QR code** and **Manual add**. **Manual add** opens a dialog for the token and key. Android's back button closes it, like the scanner.
  - **Empty list:** says to tap **+**, in place of the old "Add contact" section.
  - **Settings section:** after the contacts, scrolling with them, with two folds:
    - **Settings:** the "Show token and key" fold, and the notification setting on Android.
    - **Network:** the stats and the simulated loss together.
  - **Theme toggle:** a sun in dark mode and a moon in light mode, for the mode it switches to, in place of the "Light mode" / "Dark mode" text.
- **Small fixes:**
  - The notification setting's checkbox is no longer full width.

**Tooling**
- **`build-apk.sh -ip <ip> -p <port> -pk <hex>`** builds for any relay, such as the deployed one. `-pk` is required with `-ip`. With no flags it builds for the local relay, as before.
- **`runpeer.sh`** takes the same flags for desktop peers.
  - **Priority:** the flags win over `SERVER_ADDR`/`SERVER_PUBKEY`, which still work, so `runpeer-lan.sh` is unchanged.
  - **Per peer:** each peer can use a different relay.
  - **Output:** it prints the relay it uses.
- **Screen capture:** `FLAG_SECURE` is gone from `MainActivity`, so the app shows in screenshots, recordings and mirroring tools such as scrcpy, and in the recent-apps thumbnail. It was there to keep chats and QR codes off other screens.
- **logcat:** debug Android builds send stdout and stderr to logcat under the tag `E2E` (`adb logcat -s E2E`), so the client's reports can be watched on a phone. Release builds don't, as the client also prints messages as they arrive.
- **CLI `repair <token>`:** does what the app's "Repair session" does. It was used to time repairs through the lossy proxy.
- **Docs:**
  - **`Frontend-UI-info.md`:** the start page, chat header, back behaviour, the main screen's layout and + menu, network stats and the warning, how loss is estimated, the palette and the icon sources.
  - **`code/README.md`:** the CLI `repair` command.
  - **`code/frontend/README.md` and `ANDROID.md`:** the 10 s resend and setup copies, and adding contacts from the **+**.

### Compatibility
- **No relay changes:** the relay doesn't need redeploying.
- **Installing over the old app:** the new name and icon install over the old build, as the app identifier is unchanged.
- **Mixed builds:** an old client ignores the new 0x08 request, so recovering a lost inject needs both sides on this build. Repair works with any build.
- **Saved state:** sessions gain `sent_pq_injects`. Older saved state loads without it.
- **Sessions already broken:** a session broken before this build can't recover by itself, because the old build didn't keep its injects. Repair it once.
- **`build-apk.sh`:** `RELAY_PORT=…` is gone. Use `-p`.

### Testing
- **Checks:** fmt, `clippy --all-targets -D warnings` and the unit tests pass on every crate. The frontend is also checked for WASM, and the Tauri backend for Android (arm64).

  | Crate | Tests |
  |---|---|
  | relay-link | 13 |
  | fec | 25 |
  | Relay | 49 |
  | Client | 189 (21 new) |
  | Tauri backend | 15 |
  | Frontend | 10 |

  The new tests cover:
  - **Recovery:** a lost inject recovered after its first request is lost too.
  - **Restart:** the sender restarting between the first resend and the second.
  - **Kept injects:** bounded and pruned.
  - **Other sessions:** a request from another session is ignored.
  - **The request:** its format and session binding.
  - **Repair:** from either side, and refused for a non-contact.
  - **Contact order:** the latest-message query.
  - **Simulated loss:** 0% never drops a packet, and 100% always does.
  - **Setup copies:** only to contacts who have added us, each sealed on its own.
  - **The loss estimate** (8 tests): loss each way, from copies, gaps and requests; nothing back; too little to tell; only the last 10 s counting; probing only while watched; the 90%/88% warning thresholds.
  - **Measuring the link:** the relay's sync acks, replayed copies included, feed the estimate.
  - **Retry:** looking up and deleting one message in the history.

  The save/load round trip now includes the kept injects. Counters for retransmissions are checked in the existing PQ recovery and relay packet tests.
- **On devices, a phone and the emulator through the deployed relay:**
  - **The bug:** reproduced. 5 messages failed at 100% sending loss, including the one carrying the inject, and every later message was held.
  - **Recovery:** with this build, a lost inject was recovered twice without a repair. The receiver asked about 3 s after the next message arrived, the sender resent it, and the message appeared.
  - **Repair session:** pressed twice on the phone, both times on a session broken before the fix. Messages got through again after each.
  - **Old requests:** requests from before a repair were refused, as they should be.
- **Android back, on the phone** (driven over adb, with Chrome DevTools to read the web view):
  - **The history bug:** caught in the act. A chat was open with its entry at index 1 of 2, and back still went to the home screen.
  - **Layers:** with the back-button listener build, back closed a chat, then a QR code opened over a chat, one at a time, and only then left the app. Each was opened without a tap, which is what had marked entries to skip before. They were also tried by hand.
  - **A recreated activity** (the final build): changing the font scale makes Android recreate the activity in the same process, as closing and reopening the app does while it runs in the background. On the new activity, back from Login returned to the start page and the app stayed open. Back from the start page left the app, as it should.
- **The Network stats setting, on the phone:** counted over adb. Each count is a `network_stats` call, which starts up to 5 s of probing itself (about 40 packets up), so a 60 s window with nothing else going on reads about 45.

  | State | Sent | Received |
  |---|---|---|
  | Off (the default), app open | 48 in 60 s | 144 |
  | On, app open | 7.1/s | 21.3/s |
  | On, app in the background | 45 in 60 s | 135 |
  | On, back in the foreground | 7.1/s | 21.4/s |
  | Off again | 46 in 60 s | 138 |

  - **Off:** the fold said the stats are off, with no stats or warning. Turning it on brought them back, and the choice was saved.
  - **Background:** the page reported itself hidden.
- **Through the lossy proxy, on this PC:** the repair and contact-setup times, and the loss estimate's readings, in the tables above.
- **In a browser:** these were rendered in headless Firefox with a mocked backend:
  - **Screens:** the start page and the chat screen, in both themes.
  - **The warning bar.**
  - **The new main screen layout:** the + menu, the Manual add dialog, an empty contact list, and the settings section with every fold open, at desktop and phone widths.
- **Commits:** each of the 21 code commits builds and lints on its own.
- **Not yet tested:**
  - on a device: the ⋮ menu and centred title, new-message counts and ordering, the QR code popups, the keyboard fix, network stats and the warning, the spinner and retry, the new name, icon and start page, and the main screen's new layout
  - Android back on the final build after closing and reopening the app, from a chat or a QR code: only Login was tried on a recreated activity
  - the desktop app by hand
  - `runpeer.sh -ip …` beyond its argument handling, which was checked with a stub `cargo`
  - mirroring the phone with scrcpy now that `FLAG_SECURE` is gone

### Follow-ups
- **Older injects:** only the latest 20 are kept, so one missing from further back still needs a repair. The receive chain couldn't get that far ahead anyway.
- **Requests while held:** a session out of step for some other reason keeps sending a request every 30 s while it holds messages. Repair stops it.
- **Unread counts:** not saved, so they reset when the app restarts.
- **Connection request pop-up:** Android back doesn't close it.
- **Loss pattern:** simulated loss drops packets independently at random, with no bursts.
- **Loss estimate:**
  - **Only while watched:** it's measured only while **Network stats** is on and the app is on screen, so there's no estimate for when the app was in the background.
  - **Near the threshold:** 10 s of samples is noisy, so between about 85% and 90% loss the warning can come and go.
- **Retrying a message:** if the first try reached the contact after all, they get it twice.
- **The old name:** the identifier, Android package, crate names and saved-theme key still say e2e-messenger. Changing the identifier would make it a separate app, without the old one's data.
- **A stale comment:** `chunks.rs` says the relay keeps at most 50 packets per recipient. It's actually 2 MiB (`MAX_QUEUED_BYTES_PER_TOKEN`).
- **Screen capture:** consider turning `FLAG_SECURE` back on for release builds, or making it a setting.
- **Group chats:** designed (relay fan-out to a conversation token, with Sender Keys) but not started.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
