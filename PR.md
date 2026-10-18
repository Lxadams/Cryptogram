Logan - PQ Inject Fixes: recover lost PQ injects, repair sessions, on-device loss testing, chat UI

Closes issue: #

### Summary
- **A lost PQ inject no longer breaks a session for good.** The receiver asks for it again and the sender resends it, so the held messages decrypt. Before, one lost burst left one direction of the chat dead until both people re-added each other.
- **"Repair session"** sets up a fresh session with a contact without removing them, for anything recovery can't fix.
- **Loss can be simulated on the device itself,** with a percentage each way, so testing no longer needs a lossy relay.
- **Chat UI:**
  - **New messages:** counts next to each contact, newest conversation first.
  - **Header:** a ⋮ menu, with the contact's name centred.
  - **QR codes:** they open and close around a scan.
  - **Android back:** closes what's on top instead of leaving the app.
  - **Keyboard:** the newest message stays in view when it opens.
- **Screen capture is allowed again** (no `FLAG_SECURE`), so a phone can be mirrored to a laptop for demos.
- **Tooling:** `build-apk.sh` and `runpeer.sh` take `-ip`, `-p` and `-pk` to point at any relay, and debug Android builds send the client's log output to logcat.

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
- **Where:** either side can repair, from the chat's ⋮ menu. It's hidden while a contact is pending.

**Simulated loss** (new `code/client/src/netsim.rs`)
- **Two percentages:** outgoing and incoming, set under "Simulated network loss" on the identity card (`simulated_loss`, `set_simulated_loss` commands).
- **Coverage:** every send to and receive from the relay goes through it: message bursts, keepalives, receipts, acks, contact requests and the relay handshake.
- **Defaults:** off (0%) by default, and reset when the app closes.

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
- **QR codes** (new `QrCodeModal`, owned by `MainScreen`):
  - **They scanned you first:** scanning their code closes yours.
  - **You scanned first:** scanning someone who hasn't scanned you yet opens your code, which closes once they have (their status leaves "pending").
- **Android back:** each layer over the contact list (a chat, your QR code, the scanner) gets a browser-history entry, and Tauri goes back in the web view's history before leaving the app.
  - **Order:** back closes the scanner, then the QR code, then the chat, and only then leaves the app.
  - **Other ways of closing:** closing a layer some other way (X, ←, a scan) takes its entry back off.
- **Keyboard:** opening it shrinks the web view, and the transcript's scroll position counts from the top, so the newest messages slipped out of sight. The transcript now stays at the newest message through a resize if it was there.

**Tooling**
- **`build-apk.sh -ip <ip> -p <port> -pk <hex>`** builds for any relay, such as the deployed one. `-pk` is required with `-ip`. With no flags it builds for the local relay, as before.
- **`runpeer.sh`** takes the same flags for desktop peers.
  - **Priority:** the flags win over `SERVER_ADDR`/`SERVER_PUBKEY`, which still work, so `runpeer-lan.sh` is unchanged.
  - **Per peer:** each peer can use a different relay.
  - **Output:** it prints the relay it uses.
- **Screen capture:** `FLAG_SECURE` is gone from `MainActivity`, so the app shows in screenshots, recordings and mirroring tools such as scrcpy, and in the recent-apps thumbnail. It was there to keep chats and QR codes off other screens.
- **logcat:** debug Android builds send stdout and stderr to logcat under the tag `E2E` (`adb logcat -s E2E`), so the client's reports can be watched on a phone. Release builds don't, as the client also prints messages as they arrive.
- **Docs:** `Frontend-UI-info.md` describes the new chat header and back behaviour.

### Compatibility
- **No relay changes:** the relay doesn't need redeploying.
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
  | Client | 177 (9 new) |
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

  The save/load round trip now includes the kept injects.
- **On devices, a phone and the emulator through the deployed relay:**
  - **The bug:** reproduced. 5 messages failed at 100% sending loss, including the one carrying the inject, and every later message was held.
  - **Recovery:** with this build, a lost inject was recovered twice without a repair. The receiver asked about 3 s after the next message arrived, the sender resent it, and the message appeared.
  - **Repair session:** pressed twice on the phone, both times on a session broken before the fix. Messages got through again after each.
  - **Old requests:** requests from before a repair were refused, as they should be.
- **Commits:** each of the 11 builds and lints on its own.
- **Not yet tested:**
  - on a device: the ⋮ menu and centred title, new-message counts and ordering, the QR code popups, Android back, and the keyboard fix (all in the latest APK, which built)
  - the desktop app by hand
  - `runpeer.sh -ip …` beyond its argument handling, which was checked with a stub `cargo`
  - mirroring the phone with scrcpy now that `FLAG_SECURE` is gone

### Follow-ups
- **Older injects:** only the latest 20 are kept, so one missing from further back still needs a repair. The receive chain couldn't get that far ahead anyway.
- **Requests while held:** a session out of step for some other reason keeps sending a request every 30 s while it holds messages. Repair stops it.
- **Unread counts:** not saved, so they reset when the app restarts.
- **Connection request pop-up:** Android back doesn't close it.
- **Loss pattern:** simulated loss drops packets independently at random, with no bursts.
- **A stale comment:** `chunks.rs` says the relay keeps at most 50 packets per recipient. It's actually 2 MiB (`MAX_QUEUED_BYTES_PER_TOKEN`).
- **Screen capture:** consider turning `FLAG_SECURE` back on for release builds, or making it a setting.
- **Group chats:** designed (relay fan-out to a conversation token, with Sender Keys) but not started.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
