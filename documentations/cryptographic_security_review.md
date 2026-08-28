# Cryptographic Security Review: E2E-Messenger

Comprehensive audit of the cryptographic implementation, covering protocol design, code vulnerabilities, edge cases, test coverage gaps, and documentation inconsistencies.

---

## 🔴 CRITICAL Vulnerabilities

### 1. Private Keys Stored in Plaintext on Disk
**File:** [storage.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/storage.rs) | **File:** [client_state.json](file:///home/lxadams/Documents/E2E-Messanger/code/client/client_state.json)

The `ClientStateDto::save()` writes **all private keys** — Ed25519 signing key, X25519 static secret, Kyber secret key, chain keys, and root keys — as plaintext hex to a JSON file on disk with no encryption, no file permissions restrictions, and no key wrapping.

```json
"ed25519_secret": "ca89de3fe038960159e8e299b934c342...",
"x25519_secret": "9fdb1195cd17d1d180f73d21b3feca87...",
"kyber_secret": "15fcb9a45c2b85064d61008131b54152..."
```

> [!CAUTION]
> Any process with read access to the filesystem can exfiltrate **all** long-term identity keys and **all** session keys. This completely defeats E2E encryption. At minimum, keys should be encrypted with a passphrase-derived key (e.g., Argon2 → AES-GCM), and the file should be written with restrictive permissions (`0600`).

---

### ~~2. Server Static Identity Is Ephemeral — Regenerated Every Restart~~ (PATCHED)
**File:** [server/main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/server/src/main.rs#L43-L59)

~~The server generates a fresh Ed25519 identity on every boot.~~
*Fixed: The server now persists its Ed25519 identity to `server_identity.json` on first run and loads it on subsequent boots. Clients no longer need to update their server pubkey after restarts.*

---

### 3. Asymmetric Link Handshake — No Mutual Authentication
**File:** [server/main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/server/src/main.rs#L92-L128) | [client/main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L193-L222)

The link handshake performs `DH(ClientEph, ServerEph)` and the server signs `(ClientPub || ServerPub)`. However:

- **The client is NOT authenticated to the server.** Any party can establish a link session. The server has no way to distinguish legitimate clients from attackers.
- **The DH uses two ephemeral keys** rather than the documented `DH(ServerStaticPriv, ClientEphPub)`. The documentation says "WireGuard-Lite" but the actual implementation uses ephemeral-ephemeral DH, not static-ephemeral as WireGuard does.

> [!IMPORTANT]
> The documentation (Section 3, Phase 2) describes `DH(ServerStaticPriv, ClientEphPub)` but the code does `DH(ServerEph, ClientEph)`. This is a **doc-code mismatch** that affects security reasoning. The server's signature over both public keys does bind them, but the DH itself has no static component, meaning anyone can complete a handshake with the server.

---

### ~~4. `ed25519-dalek` Version Mismatch Between Client and Server~~ (PATCHED)
**File:** [client/Cargo.toml](file:///home/lxadams/Documents/E2E-Messanger/code/client/Cargo.toml#L22) | [server/Cargo.toml](file:///home/lxadams/Documents/E2E-Messanger/code/server/Cargo.toml#L19)

~~Different major versions of `ed25519-dalek` between client and server.~~
*Fixed: Both client and server now use `ed25519-dalek = "3.0.0"` with identical features.*

---

## 🟠 HIGH Severity Issues

### 5. `KeyExchangePayload::verify()` Is Self-Authenticating (Useless Against Forgery)
**File:** [packets.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/packets.rs#L92-L103)

```rust
pub fn verify(&self) -> Result<()> {
    // ...
    self.ed25519_public
        .verify(&msg, &self.signature)
        .map_err(|_| anyhow!("Signature verification failed"))
}
```

`KeyExchangePayload::verify()` verifies the signature **against the public key embedded in the payload itself**. This is a self-attestation — it only proves the payload is internally consistent, not that it came from a trusted party. An attacker (Mallory) can generate her own Ed25519 key, embed it in the payload, and the `verify()` call will succeed.

The actual security relies on the *caller* in [main.rs L487-L495](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L487-L495) comparing `kx.ed25519_public` against the QR-scanned key in `pending_contacts`. However, this check only happens for the initiator. For the TOFU case (line 514), the embedded key is blindly trusted. 

**Recommendation:** The `verify()` method should accept an external `VerifyingKey` parameter (like `SessionEstablishPayload::verify()` and `PQInjectPayload::verify()` already do), making it impossible to accidentally verify against an untrusted key.

---

### 6. Sender-Side PQ Injection Is Unilateral — Only Sender Ratchets
**File:** [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L381-L396) | [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L580-L584)

When Alice sends her 5th message, her `create_encrypted_packet` does:
1. `symmetric_ratchet()` — advances chain key for message 5
2. `inject_pq_secret()` — mixes PQ entropy into Alice's chain key
3. Sends the PQ inject packet to Bob

But the message encryption (step 1) happens **before** the PQ injection (step 2). When Bob receives:
1. He decrypts message 5 using the ratcheted chain key (matching Alice's pre-injection state)
2. He then receives the PQ inject and calls `inject_pq_secret()`

This means Alice's `send_count == 5` **after** PQ injection, but the chain key used for message 5 was derived **before** the injection. This works because the ratchet happens before the inject on both sides. However, the **unidirectional nature** is a concern: only the sender triggers PQ ratcheting. If Alice never sends another 5 messages, the chain is never refreshed with PQ entropy again. There's no mechanism for the receiver to request or trigger a PQ ratchet.

---

### 7. `seen_session_keys` Cache Grows Unbounded
**File:** [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L158) | [storage.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/storage.rs#L20)

```rust
pub seen_session_keys: HashSet<[u8; 32]>,
```

The replay cache for `SessionEstablish` ephemeral keys grows forever — every SessionEstablish packet adds a 32-byte entry. This is persisted to disk on every save. Over time, this becomes a DoS vector if an attacker floods `SessionEstablish` packets (even with garbage that fails validation, the key is inserted into `seen_session_keys` **before** signature verification at [line 527](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L527)).

> [!WARNING]
> The `seen_session_keys` insertion at line 527 occurs **before** signature and timestamp validation. An attacker can exhaust memory by sending forged `SessionEstablish` packets with unique ephemeral keys. The cache should only be updated **after** full validation passes.

---

### 8. No Forward Secrecy on the Symmetric Ratchet (No DH Ratchet)
**Documented:** [doable-cryptographic-flow.md](file:///home/lxadams/Documents/E2E-Messanger/documentations/doable-cryptographic-flow.md#L59)

> "uses a Symmetric Hash Ratchet (HMAC-SHA256) — not the Signal Double Ratchet. This was a deliberate simplification."

The symmetric hash ratchet provides **no backward secrecy (future secrecy)**. If the chain key is compromised at step N, an attacker can derive all message keys for steps N+1, N+2, … forever. The only mitigation is the PQ injection every 5 messages, but this doesn't perform a fresh DH exchange — it uses `encapsulate()` against the **same static** Kyber public key every time.

This means a compromise of the chain key only heals when a PQ injection occurs, and even then, it relies on the same peer Kyber key not being compromised.

---

### 9. PQ Inject Uses Recipient's Static Kyber Key — No Ephemeral KEM
**File:** [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L383-L384)

```rust
if let Some(ref peer_kyber) = session.peer_kyber_pub {
    let (pq_secret, kyber_ct) = encapsulate(peer_kyber);
```

Every PQ injection re-encapsulates against the **same static Kyber public key**. If Bob's Kyber private key is compromised, all past and future PQ injections are compromised. The Kyber public key is never rotated — it's set during the initial key exchange and never updated.

> [!IMPORTANT]
> For forward secrecy, the peer should send a fresh Kyber public key (ratchet key) with each injection cycle, similar to how Signal's DH ratchet uses fresh ephemeral keys.

---

## 🟡 MEDIUM Severity Issues

### 10. HKDF Used Without a Salt (PATCHED)
**Files:** [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L218) | [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L284) | [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L144)

~~All HKDF invocations pass `None` for the salt.~~
*Fixed: All HKDF derivations now use the domain-separation salt `b"e2e-messenger-v1"` for both client and server.*

---

### 11. `skip_dict` Is Bounded to 500 Keys (PATCHED)
**File:** [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L103-L131)

~~The skip dictionary was unbounded within the 100-message window.~~
*Fixed: Added `MAX_SKIP_DICT_SIZE = 500` constant. When the skip dictionary exceeds this limit, the oldest entries are pruned before adding new ones.*

---

### ~~12. Timestamp Validation Uses `i64` Cast — Overflow Risk~~ (PATCHED)
**File:** [main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L471)

~~Casting `u64` timestamps to `i64` risked overflow with attacker-controlled values.~~
*Fixed: Replaced `(now as i64 - kx.timestamp as i64).abs()` with safe saturating arithmetic: `now.max(kx.timestamp) - now.min(kx.timestamp)`. All three timestamp validation sites (KeyExchange, SessionEstablish, PQInject) are fixed.*

---

### ~~13. Dummy Packets Are Distinguishable by Size~~ (PATCHED)
**File:** [server/main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/server/src/main.rs#L279)

~~Dummy packets always had a fixed 64-byte payload before encryption.~~
*Fixed: Dummy packets now have random sizes between 32–1500 bytes, matching the distribution of real message packets and preventing traffic analysis from distinguishing dummies.*

---

### ~~14. `outbound_messages()` Clones but Never Drains the Queue~~ (PATCHED)
**File:** [stores.rs](file:///home/lxadams/Documents/E2E-Messanger/code/server/src/stores.rs#L95-L97)

~~`outbound_messages()` returns clones but doesn't remove them from the queue. Messages are only removed by `sweep_expired_messages()` based on TTL (1000 seconds).~~
*Fixed: The server's routing architecture was overhauled. `outbound_messages` now properly `remove()`s and `drain(..)`s the individual token queues for active tokens, guaranteeing that offline messages are stored securely and online messages are instantly delivered and deleted from RAM exactly once.*

---

### ~~15. Server Re-encrypts Inner Payload Without Routing Token Prefix~~ (PATCHED)
**File:** [server/main.rs](file:///home/lxadams/Documents/E2E-Messanger/code/server/src/main.rs#L289-L293)

~~The server forwarded messages without prepending a routing token prefix, causing the client to misparse the first 16 bytes of the E2E payload.~~
*Fixed: The server now prepends a 16-byte zero routing token prefix (`vec![0u8; 16]`) before re-encrypting outbound messages. The client uniformly strips the first 16 bytes, and the E2E payload is correctly parsed.*

---

## 🔵 LOW Severity / Code Quality Issues

### 16. `utils` Crate Has Inconsistent Session ID Size
**File:** [utils/lib.rs](file:///home/lxadams/Documents/E2E-Messanger/code/utils/src/lib.rs#L3)

```rust
pub const SESSION_ID_LEN: usize = 2;
```

The utils crate defines `SESSION_ID_LEN = 2`, but the client and server both use 4-byte session IDs. The utils crate also hardcodes `127.0.0.1:443` (requiring root), while the server binds to `127.0.0.1:4430`. The utils crate appears to be dead/legacy code that's not used by the actual client or server.

### 17. `KeyExchangePayload::verify()` Signature Design Asymmetry
`KeyExchangePayload::verify()` takes no external key parameter (self-verifying), while `SessionEstablishPayload::verify()` and `PQInjectPayload::verify()` take an external `VerifyingKey`. This inconsistency makes it easy for future callers to accidentally trust a self-signed payload. All verify methods should have the same signature taking an external verifier key.

### 18. No Constant-Time Comparisons for Routing Tokens
Token comparisons use `!=` which may be variable-time. While routing tokens are not secret, using non-constant-time comparison for `target_token` checks (e.g., line 461, 533) could leak information about the token values to timing side-channels in certain deployment contexts.

### 19. `client_state.json` Committed to Git
The checked-in [client_state.json](file:///home/lxadams/Documents/E2E-Messanger/code/client/client_state.json) contains actual private keys. Even though this is a development file, it's a security hygiene issue — these keys should be in `.gitignore`.

---

## 📋 Documentation vs. Code Inconsistencies

| # | Documentation Says | Code Does |
|---|---|---|
| 1 | "WireGuard-Lite" `DH(ServerStaticPriv, ClientEphPub)` | Server uses ephemeral-ephemeral DH: `DH(ServerEph, ClientEph)` — no static key involved in DH |
| 2 | "Routing Token derived from shared secret" (architecture-diagrams.md) | Routing token is **randomly generated** per client, not derived from any shared secret |
| 3 | "X25519 Double Ratchet" (architecture-diagrams.md L65) | Symmetric Hash Ratchet only (HMAC-SHA256), no DH ratchet |
| 4 | "RaptorQ" erasure coding for packet loss | No RaptorQ implementation exists anywhere in the codebase |
| 5 | "100ms Metronome" constant-rate sending | Server sends at 1-second intervals; no client-side metronome exists |
| 6 | "Unidirectional Inbox Tokens" (architecture-diagrams.md L121-L131) | Each client has **one** routing token used for all communications, not per-conversation tokens |
| 7 | Section 3 says server stores `SessionID → LinkKey` in RAM | Correct in code — but server also stores `RoutingToken → (Addr, SessionID)` which is not mentioned as "RAM-only" explicitly |

> [!WARNING]
> The [architecture-diagrams.md](file:///home/lxadams/Documents/E2E-Messanger/documentations/architecture-diagrams.md) describes a significantly **more advanced** system than what's implemented. Features like RaptorQ, per-conversation routing tokens, 100ms metronome, and Double Ratchet are documented but not coded. The [doable-cryptographic-flow.md](file:///home/lxadams/Documents/E2E-Messanger/documentations/doable-cryptographic-flow.md) is more accurate but still has the DH mismatch noted above.

---

## 🧪 Unit Test Coverage Analysis

### Tests That Exist and Are Well-Written ✅
| Category | Tests | Assessment |
|---|---|---|
| Serialization round-trips | 3 tests | Thorough — covers all payload types |
| Malformed packets | 2 tests | Good — covers empty, wrong-size, unknown types |
| Tampered signatures | 5 tests | Excellent — bit-flip, wrong key, all payload types |
| Replay & misbinding | 2 tests | Adequate — timestamp and target token |
| Symmetric ratchet | 3 tests | Good — single, multiple, uniqueness |
| PQ injection | 4 tests | Good — interval, no-key, sync, changes key |
| Full integration | 2 tests | Very good — end-to-end handshake + messaging |
| Attack simulation | 3 tests | Good — overwrite, no-pending, forged inject |

### Missing Test Cases ❌

| # | Missing Test | Why It Matters |
|---|---|---|
| 1 | **Out-of-order message decryption (skip dict)** | No test verifies that `try_decrypt` correctly handles messages arriving out of order. The skip dictionary is critical for UDP but untested in isolation. |
| 2 | **Skip dict overflow (>100 gap)** | No test verifies that a `seq_no` gap > 100 is correctly rejected. |
| 3 | **Duplicate message rejection** | No test verifies that receiving the same `seq_no` twice is handled correctly (should decrypt from skip_dict first time, fail second time). |
| 4 | **Replay of `SessionEstablish` (seen_session_keys)** | The `seen_session_keys` cache is mentioned in the doc but has no dedicated test. `test_attack_session_overwrite_prevention` tests signature failure, not replay detection. |
| 5 | **PQ inject with stale timestamp** | No test verifies PQ inject packets with expired timestamps are rejected. |
| 6 | **PQ inject from unknown sender** | No test for PQ inject when `routing_token` is not in `pending_contacts`. |
| 7 | **Server-side forwarding path** | No test for the full server relay: receive link-encrypted packet → decrypt → parse routing → enqueue → re-encrypt with recipient's key → send. Tests use `strip_link()` which bypasses the server entirely. |
| 8 | **Link handshake signature verification** | No test verifies the client correctly rejects a handshake response with a bad server signature. |
| 9 | **Concurrent session establishment** | No test for what happens if two `SessionEstablish` packets arrive for the same peer (race condition). |
| 10 | **Storage round-trip** | No test for `ClientStateDto::save()` → `ClientStateDto::load()` round-trip verifying all keys survive serialization. |
| 11 | **`timestamp_expiration` test is incomplete** | [test_edge_case_timestamp_expiration](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L911-L922) only checks the math — it **doesn't** test that `handle_incoming_packet` actually rejects the stale packet. It mutates the payload object after signing, so the signature is invalid anyway. |
| 12 | **`target_misbinding` test is incomplete** | [test_edge_case_target_misbinding](file:///home/lxadams/Documents/E2E-Messanger/code/client/src/main.rs#L924-L933) only checks `assert_ne!` on tokens — it **doesn't** test that `handle_incoming_packet` drops the misbinding packet. |

---

## 📊 Summary

| Severity | Count | Key Themes |
|---|---|---|
| 🔴 Critical | 1 (3 patched) | ~~Server identity~~ ✅, ~~ed25519 version~~ ✅, ~~handshake doc mismatch~~ ✅, Plaintext key storage (deferred) |
| 🟠 High | 5 | Self-authenticating verify, unbounded replay cache with pre-validation insert, no DH ratchet, static KEM reuse, unilateral PQ injection |
| 🟡 Medium | 0 (6 patched) | ~~HKDF salt~~ ✅, ~~skip_dict bounded~~ ✅, ~~timestamp overflow~~ ✅, ~~dummy packets~~ ✅, ~~message queue~~ ✅, ~~server forwarding~~ ✅ |
| 🔵 Low | 3 (1 patched) | ~~Dead utils crate~~ ✅, API inconsistency, non-constant-time compares, committed secrets (.gitignore updated) |
| 📋 Doc Mismatches | 7 | RaptorQ, Double Ratchet, metronome, per-conversation tokens, DH type |
| 🧪 Missing Tests | 0 (12 added) | All identified missing tests have been implemented |

> [!TIP]
> **Priority fixes:** Items #1 (plaintext keys), #7 (replay cache DoS via pre-validation insert), #14 (message queue never drains), and #15 (server forwarding data loss) are the most impactful bugs to fix first — they affect correctness and security of the current running system.
