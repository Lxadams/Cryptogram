Khang - RaptorQ FEC transport: messaging survives 70% packet loss

Closes issue: #

### Changes in this PR:
1. **FEC transport:** each message travels as a burst of RaptorQ (RFC 6330) symbols, and the receiver rebuilds it from any large enough subset. All of a message's padded chunks and its PQ refresh (if one is due) go into one FEC object. A burst is sized so that at 70% packet loss a message fails 1 time in 10,000, or 1 in 1,000,000 if it carries a PQ refresh. There's no ACK or resend. Code is in the new `code/fec` crate and `client/src/transport.rs`, and symbols travel as a new inner type, `0x07`.
2. **End-to-end sealed symbols:** each symbol is encrypted with a key derived from the session's root key, bound to both the sender and recipient tokens. The relay forwards opaque packets: it can't tell which symbols belong to one message, rebuild one, or relabel or redirect a symbol.
3. **Messages that overtake their PQ refresh are held** (sealed ones only, 32 per contact, for 60 s) and retried in order once the refresh lands. #35's `applies_at` already handles refreshes arriving out of order; this covers the other case, a message arriving before the refresh it needs.
4. **Ordered, paced sending:** `BurstSender` sends one packet every 10 ms and one burst at a time, in send order. A short jamming spike then only costs a few packets of a message, and messages arrive in the order they were sent. `send_message` now returns an error if the burst couldn't leave the machine at all.
5. **Relay:**
   - Forwards each packet as soon as it arrives, instead of polling.
   - Paces each recipient's backlog at one packet every 5 ms, so a client coming back online isn't flooded.
   - Caps each recipient's queue at 2 MiB, refusing new packets rather than evicting old ones. Evicting old ones would cut queued messages short and could drop a PQ refresh.
   - Logs individual packets at debug level only.
   - Dummy packets are resized to 1154 bytes to match FEC packets, and are still switched off.
6. `create_encrypted_packets` is now test-only; the CLI and Tauri `send_message` use `create_fec_packets`.
7. Added the `lossy_link` example, which runs two clients through the real relay with a lossy proxy. Added `documentations/raptorq-fec-transport.md` and `documentations/implementation-review.md`, plus unit tests. Passing: client 114, relay 10, fec 25, Tauri backend 14. `fmt` and `clippy -D warnings` are clean.

### Results
- In-process: 1,000 messages through 70% loss with shuffled bursts, all delivered, and the ratchets still in step after 200 PQ refreshes.
- Real relay over UDP: 40/40 delivered with the sender jammed at 70%, and 40/40 with the receiver jammed. At 80% loss on one side, 30/30 each way. These numbers are from before the review fixes and the #35 merge; `lossy_link` hasn't been re-run since.

### ⚠️ Breaking wire format
Chat now travels only as `0x07` FEC packets, so both clients must run this version. Saved state from #35 still loads.

### ⚠️ Airtime cost
#35's padding makes every FEC symbol full size, so a short message is 34 packets × 1154 bytes, about 39 KB on the wire. Before the merge it was about 7 KB (27 smaller packets). Packet size no longer reveals message length, but on a metered satellite link this is about 5× the cost per message.

### Follow-ups
- Losing an entire burst that carries a PQ refresh (about 1 in 1,000,000 at 70% loss) still breaks the session. Recovering needs a session-reset message (review finding C-5).
- Make redundancy adapt to actual loss, so messages on a clean link don't pay for 70% loss.
- Burst length still reveals a message's chunk count, and which messages carry a PQ refresh.
- The relay handshake, key exchange and presence pings aren't FEC-protected, as agreed; they still need a clean link.
- `lossy_link` needs a running relay, so it isn't in CI.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
