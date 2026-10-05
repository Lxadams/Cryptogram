Khang - Fixed-size message packets, long-message chunking and reliable PQ refreshes

Closes issue: #

### Changes in this PR:
1. **Message padding:** every chat packet is now exactly 1150 bytes, so the relay and network observers can no longer read message length. Plaintext is padded to a 1024-byte block (`[u16 length | data | zeros]`) inside the E2E encryption (`client/src/padding.rs`).
2. **Long-message chunking:** messages up to 16,176 bytes are split into ≤16 chunks, each sent as its own ratcheted packet and reassembled on receipt in any order (`client/src/chunks.rs`). Anything longer is rejected with an error in the chat panel, and the draft text is restored so it isn't lost. Before this, messages over ~1,900 bytes were silently dropped because they overflowed the relay's 2 KB receive buffer.
3. **PQ refresh ordering:** the `0x05` refresh now carries the step it applies at (`applies_at`), and the receiver mixes it in at exactly that step, so it can arrive early, late or more than once. Before, a refresh that overtook the previous message, or got lost, broke the session permanently. So did one queued at the relay for over 5 minutes, because of the timestamp check. The signature also covers a binding derived from the session's root key, so a refresh can't be replayed into a later session with the same contact.
4. **Relay dummy packets** are now 1150 bytes and framed like forwarded chat packets (inner type `0x00`, which clients ignore). Dummy sending is still switched off, as it has been since `185758d`. @Lxadams, was that intentional?
5. `create_encrypted_packet` is renamed `create_encrypted_packets` and returns every chunk packet plus the refresh; the CLI and Tauri `send_message` send them all. Duplicate chat and refresh packets are now ignored quietly, so every packet is safe to resend.
6. Updated `documentations/doable-cryptographic-flow.md` and added unit tests. Passing: client 92, server 7, Tauri backend 14.

### ⚠️ Breaking wire format
The chat and PQ refresh packet formats changed, so all clients must run this version to talk to each other. Existing saved state still loads.

### Follow-ups
- Nothing resends packets yet. Until something does, a lost chunk loses its whole message, and a lost PQ refresh still breaks the session.
- Decide whether to turn relay dummy packets back on.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
