# E2E-Messenger Implementation Review

5 October 2026, branch `claude/raptorq-e2e-integration-2c36af` (main at `17f1a92` plus the RaptorQ FEC transport).

**Scope:** relay server, client core, cryptography, post-quantum protocol, FEC transport, packet structure, front ends, build/CI, tests and docs.

**Method:**
- Read all source in `code/`.
- Ran every crate's test suite (134 tests, all passing).
- Ran the real relay and two clients over real UDP with injected packet loss (`code/client/examples/lossy_link.rs`).

This builds on [cryptographic_security_review.md](cryptographic_security_review.md), whose still-open items are re-checked against the current code. For the FEC work itself, see [raptorq-fec-transport.md](raptorq-fec-transport.md).

**Severity scale:**

| Severity | Meaning |
|---|---|
| **Critical** | Breaks confidentiality or authenticity |
| **High** | An outsider or the relay can break delivery or sessions, or a core goal fails |
| **Medium** | Weakens a security property or fails under realistic conditions |
| **Low** | Hardening |
| **Info** | Observation |

## Status, 20 October 2026

Checked against `main` at `52b49d8`. The findings below are as written on 5 October. This table says where each one stands now.

- **Fixed:** the problem is gone.
- **Mitigated:** the risk is smaller, but the cause is still there.
- **Open:** unchanged.
- **Obsolete:** the code it was about is gone.
- **Still true:** an Info observation that still holds.

**C-1 never landed.** The fix described as "in progress in a separate task" (§1, §6, §13) was not merged. Both chains still start at the root key, and the `0x01` header still isn't bound as AAD. Other changes mitigate it (see the table), but it isn't fixed.

| Finding | Severity | Status | How, or where |
|---|---|---|---|
| R-1 Any client can register any routing token | High | Fixed | A routing token is now the hash of an Ed25519 token key (`routing_token_for`). A sync is signed by that key and bound to the link's keys. |
| R-2 Any client can overwrite a session's link key | High | Fixed | The relay picks session IDs. |
| R-3 Links expire after 1 h, never re-established | High | Fixed | Expiry is refreshed on use (1 h after last use). Clients re-handshake after 2 min of silence from the relay. Packets stay queued until acked. |
| R-4 Resources are unbounded | Medium | Fixed | Caps on links, admission tags and queues, a 64 MiB shared budget, and a handshake rate limit per address. Still open: spoofed source addresses get past the per-address limit (a stateless cookie would close this). |
| R-5 The relay logs metadata | Medium | Fixed | Only startup lines at info. Refused packets at debug. |
| R-6 Single-shot handshake | Medium | Fixed | Init and reply each sent 3 times. Retries for up to 60 s. Copies of one init get the same reply and link. |
| R-7 Dummy traffic disabled | Low | Open | Dummy packets exist but nothing sends them. Planned for Stage 3 Phase 1 ([stage-3-roadmap.md](stage-3-roadmap.md)). |
| R-8 Relay identity key in plaintext JSON | Low | Fixed | `server_identity.json` is written with mode 0600. |
| R-9 Not mutual authentication | Info | Obsolete | The handshake no longer carries a client key. A client proves its token with the signed sync. |
| L-1 CLI stores secrets in plaintext | Medium | Open | The CLI's state (`client_state.json`, or `E2E_STATE_FILE`) is still plaintext JSON. The app encrypts at rest. |
| L-2 CLI never re-syncs | Medium | Fixed | The CLI has the same 15 s keepalive and 500 ms tick as the app. |
| L-3 Plaintext printed to stdout | Low | Open | Still prints `>> [From …]: text`. On Android debug builds that reaches logcat (tag `E2E`). |
| L-4 Every send rewrites the whole state | Info | Open | Unchanged. |
| C-1 Both ratchet directions start from the same key | High | Mitigated | Not fixed (see above). Chat only travels inside `0x07` seals, whose AAD binds sender and recipient. A bundle only accepts the sealing peer's own `0x01`/`0x05`. A packet claiming to be from yourself is dropped. |
| C-2 Initial forward secrecy depends on long-term keys | Medium | Open | No prekeys yet. |
| C-3 PQ injections reuse the static KEM key, one direction only | Medium | Open | Stage 3 item 3.1. |
| C-4 Late PQ injections rejected | High | Fixed | `0x05` carries its chain position (`applies_at`). No freshness check applies to it. |
| C-5 No recovery from a desynced session | Medium | Fixed | **Repair session** (the app's ⋮ menu, CLI `repair <token>`) sets up a fresh session and keeps the contact and history. For the common cause, a lost PQ injection, the receiver asks again with a signed `0x08` request. |
| C-6 KeyExchange from strangers auto-accepted | Medium | Fixed | Both people must add each other. A KeyExchange from someone you haven't added is dropped and shown as a connection request. |
| C-7 Root key not bound to the transcript | Low | Open | Still HKDF over the two shared secrets only, info `pqxdh-root-key`. |
| C-8 Replay caches cleared wholesale | Low | Obsolete | Both caches are gone. Add IDs (a counter that only goes up) replaced `seen_session_keys`. |
| C-9 Presence pings can be replayed | Low | Obsolete | Presence (`0x06`) was removed. |
| C-10 Login/storage cryptography is sound | Info | Still true | Argon2id is now 64 MiB, 3 passes. Identities created before keep their old cost (19 MiB, 2 passes). |
| P-1 Pre-standard Kyber, not ML-KEM | Low | Fixed | ML-KEM-768 (`libcrux-ml-kem`, behind `client/src/pq.rs`). |
| F-1 Residual PQ desync | Medium | Fixed | A receiver with parked messages sends a signed `0x08` request, and the sender resends from its latest 20 injections. An older loss needs **Repair session**. |
| F-2 Fixed redundancy | Low | Open | Every message is still sized for 70% loss. |
| F-3 Traffic analysis | Low | Open | Packets are padded to fixed sizes. Timing and burst length still show. |
| F-4 Seal key static per session | Low | Open | Unchanged. |
| F-5 Random 32-bit object IDs | Low | Fixed | The object ID is the last chunk's `seq_no`, kept apart per session. |
| F-6 Designed for one jammed side | Info | Still true | Still designed for 70% loss. |
| W-1 KeyExchange datagram too big for small MTUs | Low | Open | 1,447 bytes with an admission tag, 1,439 without: still over 1,280. Setup copies help with loss, not fragmentation. |
| W-2 Sizes and timing leak | Low | Mitigated | Padding fixes the sizes. Timing and burst length still show (F-3). |
| W-3 Session IDs and type byte in clear | Info | Still true | Session IDs are now chosen by the relay. |
| A-1 `"csp": null` | Low | Open | Unchanged. |
| A-2 Inbox polled, not pushed | Info | Still true | The main screen still polls every 1 s. |
| B-1 No Cargo workspace | Low | Open | Each crate still has its own lockfile. |
| B-2 Windows builds need Strawberry Perl | Info | Still true | The client still builds SQLCipher with vendored OpenSSL. The Linux client image installs `make` and `perl` for the same reason. |
| B-3 `runchecks.sh` checks only the server, and rewrites | Low | Open | Unchanged. |
| B-4 Dockerfiles build release binaries per crate | Info | Still true | The client image copies `fec` and `relay-link`, the relay image `relay-link`. The relay binds `0.0.0.0:443/udp` and runs as its own unprivileged user. `deploy.yml` runs it read-only, with no capabilities. |

Also since 5 October:
- CI also runs `cargo deny check` for each crate, and covers `code/relay-link`.
- Tests now total 301, all passing: relay-link 13, fec 25, relay 49, client 189, src-tauri 15, frontend 10.
- §3's wire reference and §11's test table describe the 5 October code. For what changed in the link layer, see [Since this write-up](raptorq-fec-transport.md#since-this-write-up) in the FEC write-up.

## 1. Executive summary

The cryptographic core is in good shape for a proof of concept:
- Hybrid X25519 + Kyber768 session setup.
- Ed25519-signed control messages with target binding and freshness checks.
- A bounded skip-dictionary ratchet, and Argon2id + SQLCipher at rest on the desktop app.

The code is careful, readable and well tested (134 tests).

The weakest area is **the relay's link and routing layer**. Anyone with a link session can claim any routing token, overwrite any session's link key, or exhaust memory. Every link also silently expires after one hour with no re-handshake. None of this exposes message content, which stays end-to-end encrypted, but it does let an outsider or a misbehaving relay redirect or blackhole traffic. Under the extreme-loss goal, one protocol issue matters most: **PQ injections are rejected after 5 minutes (C-4)**, so a recipient who was offline or jammed loses the session.

**Top priorities, in order:**

| # | Finding | Severity | Status, 20 October |
|---|---|---|---|
| 1 | R-1 Any client can register any routing token (traffic hijack) | High | Fixed |
| 2 | R-2 Any client can overwrite any session's link key | High | Fixed |
| 3 | R-3 Links expire after 1 h with no re-handshake. Queued messages for that client are then dropped. | High | Fixed |
| 4 | C-4 Late PQ injections are rejected, which permanently desyncs the session (**fixed**: chain position replaces the freshness check) | High (for the loss goal) | Fixed |
| 5 | C-1 Both ratchet directions start from the same chain key (reflection) | High, **fix in progress in a separate task** | Mitigated. The fix never landed. |
| 6 | C-6 KeyExchange from strangers is auto-accepted, contradicting the mutual-QR trust model | Medium | Fixed |
| 7 | R-5 The relay logs who talks to whom | Medium | Fixed |

## 2. Architecture at a glance

```
 Client A ──UDP──► Relay (RAM-only, blind) ──UDP──► Client B
   │ link layer: XChaCha20-Poly1305, key from an ephemeral X25519 handshake
   │             with the relay (relay signs with its pinned Ed25519 key)
   │ E2E layer:  hybrid PQXDH-style setup (X25519 + Kyber768), then a
   │             symmetric hash ratchet with a Kyber injection every 5 messages
   │ FEC layer:  RaptorQ bursts, each symbol sealed end to end (new)
```

| Component | Path | Role |
|---|---|---|
| Relay | `code/server` | Link handshakes, routing-token → address table, per-token queue, forwarding |
| Client core | `code/client` (lib + CLI bin) | Identity, link layer, E2E protocol, ratchet, storage, FEC transport |
| FEC | `code/fec` | Pure RaptorQ encode/reassemble (new) |
| Desktop app | `code/frontend/src-tauri` | Tauri shell: login/identities, background loops, commands |
| Web UI | `code/frontend` | Leptos/WASM UI, contact QR codes |

## 3. Packet structure: full wire reference

### 3.1 Outer layer (client ↔ relay)

| Type | Direction | Layout | Bytes |
|---|---|---|---|
| `0x00` HANDSHAKE_INIT | client → relay | type 1 · session id 4 · client ephemeral X25519 32 · client Ed25519 pub 32 · Ed25519 sig over the ephemeral 64 | 133 |
| `0x02` HANDSHAKE_RESP | relay → client | type 1 · session id 4 · relay ephemeral X25519 32 · relay Ed25519 sig over (client eph ‖ relay eph) 64 | 101 |
| `0x01` DATA | both | type 1 · session id 4 · nonce 24 · XChaCha20-Poly1305(recipient token 16 ‖ inner) · tag 16 | 61 + inner |

- A **sync** is a DATA packet whose inner payload is empty (61 bytes). It registers "this token lives at this address".
- Relay → client DATA carries an all-zero token.

### 3.2 Inner layer (end to end)

Fields in brackets are the payload signed by the sender's Ed25519 key.

| Type | Layout | Bytes | Wire total |
|---|---|---|---|
| `0x01` Msg | sender token 16 · seq 8 · nonce 24 · XChaCha20-Poly1305(plaintext) + 16 | 65 + text | 126 + text |
| `0x02` KeyExchange | [sender 16 · target 16 · timestamp 8 · Ed25519 32 · X25519 32 · Kyber768 pk 1,184 · name 32] · sig 64 | 1,385 | **1,446** |
| `0x04` SessionEstablish | [sender · target · ts · Kyber ct 1,088 · ephemeral X25519 32] · sig 64 | 1,225 | 1,286 |
| `0x05` PQInject | [sender · target · ts · Kyber ct 1,088] · sig 64 | 1,193 | 1,254 |
| `0x06` Presence | [sender · target · ts] · sig 64 | 105 | 166 |
| `0x07` FEC symbol (new) | sender 16 · nonce 24 · XChaCha20-Poly1305(FEC header 12 · symbol T) + 16 | 69 + T | ≤ 1,154 |

`0x03` is unused. Layouts are pinned by tests (`payload_sizes_match_the_wire_format`, `key_exchange_bytes_match_the_original_layout`, `packets_have_the_documented_layout`).

### 3.3 Key derivations

All HKDFs are HKDF-SHA256 with salt `"e2e-messenger-v1"`.

| Key | Derivation |
|---|---|
| Link key | HKDF(DH(client eph, relay eph), info `wireguard-lite-link`) |
| Session root key | HKDF(X25519(initiator eph, responder **static**) ‖ Kyber768 shared secret, info `pqxdh-root-key`) |
| Message key / next chain key | HMAC-SHA256(chain key, `message-key` / `chain-key`) |
| PQ injection | chain key ← HKDF(chain key ‖ Kyber shared secret, info `pq-ratchet-inject`) |
| FEC seal key (new) | HKDF(root key, info `fec-symbol-seal`) |
| Login | Argon2id(passcode, 16-byte salt; 19 MiB, t=2, p=1) → HKDF labels `login-verifier/v1` and `vault-key/v1` |
| At rest | SQLCipher raw key = vault key (identity store and chat history) |

### 3.4 Packet-structure findings

- **W-1 (Low): the KeyExchange datagram is 1,446 bytes.** It fits a 1,500-byte Ethernet MTU but not paths with smaller MTUs (IPv6 minimum 1,280, VPNs, some cellular/SATCOM links), where it fragments. A lost fragment loses the whole packet, and it isn't FEC-protected. Splitting it, or sending it through the FEC path (now a small change), would fix this.
- **W-2 (Low): sizes and timing leak.** Legacy packets reveal exact ciphertext length. FEC packets reveal length to within 8 bytes, and bursts reveal send times and every 5th (PQ-carrying) message. Pad to a few size buckets if the metadata claims matter.
- **W-3 (Info):** session ids (4 bytes, client-chosen) and the type byte are in clear by design. Everything else is under the link AEAD.

## 4. Relay server (`code/server`)

**Strengths:**
- Small and readable.
- Every forwarded packet is re-encrypted per recipient.
- RAM-only queues with TTLs.
- Persisted Ed25519 identity that clients pin.
- Malformed input is rejected without panics.
- Forwarding is woken on arrival and paced per recipient (5 ms/packet). The new test covers the full re-encrypt-and-send path, which had been flagged as untested.

**Findings:**

**R-1 (High): any client can register any routing token.** A sync (empty DATA) maps the token inside it to the sender's address and session with no proof of ownership (`handle_request`, `update_metadata`). Routing tokens are not secret: they're in every contact QR code and visible to the relay. An attacker with any link session can:
- redirect a victim's incoming traffic to themselves, including flushing the victim's offline queue to them;
- blackhole it.

Content stays E2E-encrypted, so this is a delivery attack, not a confidentiality one. **Fix:** bind each token to the Ed25519 key that first registered it (the handshake already carries the client's key), and require that key's signature on syncs.

**R-2 (High): any client can overwrite any session's link key.** `register_link` replaces whatever is stored under a session id. Session ids are in clear in every packet. A handshake reusing a victim's id silently re-keys their link: the victim's packets fail the MAC, and forwards to the victim are encrypted under the attacker's key. **Fix:** refuse to replace a live session id unless the same client Ed25519 key signs the new handshake, or have the relay assign session ids.

**R-3 (High): links expire after one hour and are never re-established.** A link's expiry is fixed at handshake time (`register_link`, +3,600 s) and is not refreshed by traffic. The sweep then deletes it, and neither the CLI nor the desktop app re-handshakes. Every client therefore stops sending and receiving about 60–62 minutes after login. Worse, `prepare_outbound_messages` drains a recipient's queue *before* looking up their link key, so messages queued for an expired link are **dropped**. **Fix:** refresh expiry on use, let clients re-handshake when their packets go unanswered, and look up the link before draining.

**R-4 (Medium): resources are unbounded.**
- No global cap on links, metadata entries or queues, and no rate limiting.
- Each handshake costs an Ed25519 verification plus an X25519 operation.
- Per-token queues are capped, at 2 MiB after the FEC change (was 50 packets), refusing new packets once full. There's no cap on the number of tokens, so memory grows with every random token an attacker queues for.

**Fix:** a global byte budget, per-source rate limits, and cheap pre-checks before signature verification.

**R-5 (Medium): the relay logs metadata.** At `INFO` it logs every packet's source `IP:port`, plus the routing token of every sync and forward. A seized or compromised relay therefore yields a time-stamped who-talks-to-whom record. That contradicts the zero-knowledge / metadata-obfuscation claims. **Fix:** log at `DEBUG` without tokens or addresses.

**R-6 (Medium): the handshake is single-shot and not idempotent.** Clients make one attempt with a 5 s timeout. At 70% loss on the jammed side that succeeds about 9% of the time. The relay generates a fresh key per init, so repeated inits re-key the link and break retries (scoped out for this phase).

**R-7 (Low): dummy traffic is disabled.** `dummy_targets` is always empty, so the cover-traffic path is dead code, contrary to the README.

**R-8 (Low): the relay's identity key is stored as plaintext JSON** (`server_identity.json`). Acceptable for a PoC. Restrict file permissions in deployment.

**R-9 (Info):** the relay authenticates itself (its signature over both ephemerals). The client's signature is checked only against the key the client itself supplies, so the relay admits anyone. That's fine for an open relay, but then it's not "mutual authentication" as the server README says.

## 5. Client core (`code/client`)

**Strengths:**
- One library shared by the CLI and the desktop app.
- Strict, length-checked parsers built around a single `signed_bytes()` per payload, which prevents layout drift.
- Constant-time token comparison for target binding.
- Bounded replay and pending-contact structures.
- Clear error and alert paths.
- Encrypted-at-rest identity and history on the desktop app, with a careful one-time migration from plaintext.

**Findings:**

**L-1 (Medium): the CLI still stores every secret in plaintext** (`client_state.json`): identity keys, root and chain keys, and skipped message keys. The desktop app fixed this with SQLCipher; the CLI never attaches an `IdentityStateStore`. (Original review #1, still open for the CLI.)

**L-2 (Medium): the CLI never re-syncs.** Only the desktop app has the 15 s keepalive. The relay's metadata TTL is 1,000 s, so a CLI peer stops receiving after about 17–19 minutes. Its messages queue at the relay until they expire.

**L-3 (Low): message plaintext is printed to stdout** (`>> [From …]: <text>` in `handle_incoming_packet`). In the desktop app that goes to the launching terminal and any captured output. Gate it behind a debug flag.

**L-4 (Info): every send and receive rewrites the whole state** (`save()` serialises all sessions, keys and skip dictionaries). That's fine at PoC scale but O(state) per message.

## 6. Cryptography

**Strengths:**
- Standard, well-reviewed primitives: X25519, Ed25519, XChaCha20-Poly1305 with random 192-bit nonces, HKDF/HMAC-SHA256, Argon2id.
- Domain-separated HKDF labels everywhere.
- Signed control messages bound to sender, target and timestamp.
- Hybrid classical + post-quantum session secret: breaking it requires breaking both.
- SessionEstablish replay cache, now inserted only *after* signature verification (original review #7, fixed).

**Findings:**

**C-1 (High): both ratchet directions start from the same chain key.** `SymmetricSessionState::from_root_key` sets `send_chain_key = recv_chain_key = root_key` on both peers. Until the first PQ injection, message key *n* is the same in both directions. Message headers (sender token, seq) are also not AEAD-authenticated. Together these let the relay rewrite the sender token of Alice's message and bounce it back to Alice, who decrypts her own message as if from Bob. **Status: a fix is in progress in a separate task:** split directional chains via HKDF and bind the header as AAD. The new FEC path is already immune, because its seal binds sender and recipient.

**C-2 (Medium): the initial handshake's forward secrecy depends on long-term keys.** The responder contributes only its *static* X25519 and *static* Kyber keys. Anyone who later steals Bob's long-term secrets and recorded the SessionEstablish can recompute the root key of every session Bob accepted. Signal's PQXDH avoids this with signed (and one-time) prekeys. (Related to original review #8.)

**C-3 (Medium): PQ injections reuse the static Kyber key and are one-directional.** Every injection encapsulates to the peer's long-term Kyber key, so compromising that key compromises every injection. Only the sender's chain is refreshed, and a peer who rarely sends rarely refreshes. (Original review #6 and #9, still open.)

**C-4 (High for the loss goal): late PQ injections are rejected, permanently desyncing the session.** Like every signed control payload, `0x05` must be within ±300 s of the receiver's clock (`accepts_payload`). The relay holds queued packets for up to 1,000 s, and jammed or offline recipients are exactly the ones whose packets arrive late. Consider a PQ-carrying message that reaches Bob more than 5 minutes after it was sent:
- the message decrypts;
- the injection is dropped as stale;
- every later message from that peer fails, for good.

The same happens with clock skew over 5 minutes, which is plausible on isolated networks without NTP. **Fix:** the injection's position in the chain and its replay cache already prevent replay, so drop the freshness check for `0x05` (or widen it beyond the relay TTL). Alternatively, carry the KEM ciphertext inside the ratchet-encrypted message itself.

**C-5 (Medium): no recovery from a desynced session.** Whatever the cause (C-4, a lost PQ burst, a corrupted state file), the only remedy is removing and re-adding the contact. A signed "session reset" control message (roadmap Task 4.1b) would let the two clients re-establish a session in the background.

**C-6 (Medium): KeyExchange from strangers is auto-accepted.** A KeyExchange from a token not in `pending_contacts` is accepted, logged as "Auto-accepting for demo", answered, and leads to a full session. Anyone who knows your routing token (it's in your QR code) can therefore become a contact and message you, without you having scanned *their* code. The intended model is that both parties show QR codes to each other. **Fix:** only answer KeyExchanges from tokens whose key you've scanned, or surface them as pending requests that need explicit acceptance.

**C-7 (Low): the root key isn't bound to the transcript.** `hybrid_root_key` hashes only the two shared secrets. Adding both identity keys and the handshake transcript to the HKDF info is a cheap hardening against unknown-key-share style issues.

**C-8 (Low): replay caches are cleared wholesale.** `seen_session_keys` and `pq_inject_replay_cache` are emptied entirely when they pass 1,000 entries, which briefly reopens the replay window. Evict the oldest entries instead.

**C-9 (Low): presence pings can be replayed for 5 minutes.** They're signed and timestamped but not replay-cached, so the relay can replay a ping to show a contact as online when they aren't.

**C-10 (Info): login/storage cryptography is sound.**
- Argon2id parameters match OWASP's baseline.
- The verifier and vault key are independent HKDF expansions.
- The passcode is zeroized.
- The vault key's `Debug` output is redacted.
- Deleting an identity without its passcode is a deliberate recovery path.

## 7. Post-quantum implementation

| Aspect | Current state | Assessment |
|---|---|---|
| Algorithm | `pqcrypto-kyber` 0.8.1 → PQClean `kyber768` | **P-1 (Low):** this is pre-standard CRYSTALS-Kyber, not FIPS 203 **ML-KEM**, which the docs claim and which ships separately as `pqcrypto-mlkem`. Swapping is mechanical (same sizes and API shape), but it changes the wire format. |
| Initial session | X25519(eph, static) + Kyber768 encapsulation → one HKDF | Correct hybrid combiner. Forward-secrecy limits per C-2. |
| Continuous PQ | Kyber encapsulation to the peer's static key every 5 sent messages, mixed into the send chain | Works and is tested. Limits per C-3. |
| Under loss | **Previously fragile:** a lost or reordered injection killed the session. **Now** bundled atomically with its message in one FEC object at 99.9999%, with late-arriving messages held and retried. | Fixed in this branch, apart from C-4/C-5 |
| Ordering | The injection applies at chain position `send_count` (after message *n*) | Correct on both sides, verified across 200 injections under 70% loss |
| Key sizes | Public key 1,184, ciphertext 1,088, secret key 2,400 bytes | Dominates control-packet sizes (W-1) |

## 8. FEC transport (new in this branch)

**Strengths:**
- Pure, separately tested crate.
- Validates headers before they reach `raptorq`.
- Bounded memory on the receive side.
- Sealed end to end, so the relay can't group or rebuild symbols.
- Sizing model checked against measurement (it caught its own bug).
- Pacing preserved through the relay.
- Interoperates with the legacy single-datagram path.

Measured:
- 1000/1000 messages delivered at 70.2% loss in-process.
- 40/40 each way over real UDP with the sender or the receiver jammed.
- 30/30 at 80% loss.
- About 90% delivered with both sides jammed (~91% end to end).

**Self-review findings:**

**F-1 (Medium): residual PQ desync.** Losing an entire PQ-carrying burst (≤ 10⁻⁶ per injection at 70% loss) still desyncs the session. Fix with C-5.

**F-2 (Low): fixed redundancy.** Every message pays for 70% loss even on a clean link (about 27 packets, ~6–8 KB, for a short message). Receiver loss reports could adapt it.

**F-3 (Low): traffic analysis.** See W-2. A constant-rate tunnel mode would hide timing at the cost of latency.

**F-4 (Low): the seal key is static per session.** A root-key compromise exposes symbol envelopes, but the messages inside remain ratchet-protected. Ratcheting the seal key per PQ epoch would restore forward secrecy at this layer.

**F-5 (Low): random 32-bit object ids.** A collision with a recently finished object (remembered for 10 min) silently drops the new message. The probability is about (objects in the window) / 2³². Negligible at chat volumes; widen to 64 bits if volume grows.

**F-6 (Info): designed for one jammed side.** Both sides jammed at 70% (≈91%) degrades to ~90% delivery. Setting `FEC_DESIGN_LOSS = 0.91` covers it, at ~99 packets per short message.

## 9. Front ends

**CLI (`code/client/src/main.rs`):** a minimal REPL (`connect`, `msg`). It now sends FEC bursts on a background task. Issues: L-1 and L-2. It also has no presence and no contact names.

**Desktop app (`code/frontend/src-tauri`):** clean separation between the UI and the shared `Client`.
- Path-safe pseudonym sanitising.
- OS-level advisory session locks (no stale-lock problem).
- Encrypted identity and history.
- Background receive, keepalive and presence loops, aborted on logout.
- `send_message` now sends bursts without holding the runtime lock.

Findings:
- **A-1 (Low):** `tauri.conf.json` sets `"csp": null` together with `withGlobalTauri: true`. Leptos escapes rendered text, so XSS is unlikely, but a CSP is cheap defence in depth for an app whose webview can call every command.
- **A-2 (Info):** the inbox is polled rather than pushed. That's fine at this scale.

**Web UI (`code/frontend`):**
- The contact QR code is `cryptogram:v1:<token hex>:<ed25519 hex>`: versioned, prefix-checked and strictly validated.
- QR decode and encode are pure Rust compiled to WASM.

No issues found. Note that the QR code contains the routing token, which makes R-1 and C-6 practical for anyone who sees your code.

## 10. Build, CI and deployment

- CI runs `fmt --check`, `clippy -D warnings`, build and test for each crate, now including `code/fec`.
- **B-1 (Low):** there's no workspace. Each crate has its own lockfile and target directory, so dependency versions can drift (they're currently aligned) and builds are duplicated. A Cargo workspace would share both.
- **B-2 (Info):** Windows builds of the client need Strawberry Perl for vendored OpenSSL (via SQLCipher). See the FEC write-up §10.
- **B-3 (Low):** `runchecks.sh` only checks `code/server` and runs `cargo fmt` (rewriting files) rather than `--check`.
- **B-4 (Info):** the Dockerfiles build release binaries per crate and now include `fec`. The relay container binds `0.0.0.0:443/udp`.

## 11. Testing

| Crate | Tests | Notes |
|---|---|---|
| `fec` | 25 | Loss at 30–90%, bursty loss, model-versus-measurement, wire layout, bounds, malformed input |
| `client` | 81 | 64 protocol/crypto/storage tests plus 17 transport tests (70% loss end to end, 1,000-message rate, PQ reordering, seal binding, hostile bundles) |
| `server` | 8 | Handshake, sync/forward, offline queue and bounds, TTL sweep, full re-encrypt-and-send path, burst not truncated |
| `src-tauri` | 14 | Login/identity lifecycle, migration, locking |
| `frontend` | 6 | Contact code, QR round trip |

Gaps:
- No automated multi-process test in CI: `lossy_link` needs a running relay.
- No tests for R-1, R-2 or R-3 (the behaviours themselves are the problem).
- No fuzzing of the packet parsers (they're length-checked, but cheap to fuzz).
- No test for C-4 (late PQ injection).
- No tests for the desktop app's network commands.

## 12. Documentation versus code

| Docs say | Code does |
|---|---|
| Survives **95%** loss (README) | Designed and verified for 70% on one hop. Both hops at 70% (91%) degrades to ~90% delivery. 95% would need `FEC_DESIGN_LOSS = 0.95`, at ~200 packets per message. |
| RaptorQ FEC | **Now implemented** (this branch) |
| 100 ms metronome / constant-rate traffic, dummy packets | Burst sending was chosen. The relay's dummy traffic is disabled (R-7). |
| ML-KEM | Pre-standard Kyber768 (P-1) |
| "Double Ratchet" (architecture diagrams) | Symmetric hash ratchet plus PQ injection. No DH ratchet. |
| Per-conversation inbox tokens | One routing token per identity |
| "Mutual authentication" of client and relay | The relay authenticates itself. The client signs with a self-supplied key (R-9). |
| Relay has zero knowledge of who talks to whom | It logs source addresses and tokens (R-5) |

## 13. Prioritised recommendations

1. ~~**Relay routing integrity (R-1, R-2):** bind tokens and session ids to the client's Ed25519 key. This is small, relay-side work plus a signature on syncs.~~ Fixed: a token is the hash of a token key, syncs are signed by it, and the relay picks session IDs.
2. ~~**Link lifetime (R-3):** refresh expiry on use, re-handshake from clients, and stop dropping drained messages.~~ Fixed: expiry is refreshed on use, clients re-handshake, and packets stay queued until acked.
3. ~~**Late PQ injections (C-4):** exempt `0x05` from the 5-minute freshness window. Without this, offline or jammed recipients lose sessions.~~ Fixed: `0x05` carries its chain position and has no freshness check.
4. **Finish C-1** (in progress in a separate task). Not done: mitigated only (see the status table).
5. ~~**Session reset (C-5 / F-1):** one signed control message that lets two clients recover any desync without re-scanning QR codes.~~ Fixed: **Repair session**, and `0x08` requests for a lost PQ injection.
6. ~~**Contact acceptance (C-6):** answer KeyExchanges only from scanned contacts.~~ Fixed: both people add each other, and strangers show as connection requests.
7. ~~**Relay hygiene (R-4, R-5):** a global memory budget, rate limits, metadata-free logs.~~ Fixed: caps, a global budget, a handshake rate limit, and only startup lines at info. A stateless cookie against spoofed addresses is still open.
8. **CLI parity (L-1, L-2):** encrypted state and a keepalive. Partly done: the CLI has the keepalive, but its state is still plaintext.
9. **Standards and hardening (P-1, C-2, C-3, C-7):** move to ML-KEM, add prekeys, rotate the KEM key, bind the transcript. Partly done: ML-KEM-768 is in. Prekeys, KEM rotation and transcript binding are not.
10. ~~**Loss coverage beyond messaging:** FEC or repetition for the handshake, sync and presence, once those are in scope.~~ Fixed by repetition: the handshake init and reply go 3 times with retries, syncs 3 times, and setup packets 3 times to a contact who has added you, with a 10 s first resend. Presence was removed.
