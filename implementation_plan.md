# Implementation Plan: E2E Cryptographic Hardening (Phase 5)

## Status, 20 October 2026

This is the July 2026 plan, kept as a record of what was planned. All four items were built, some of them differently. The design as it is now is in [documentations/Logan-info.md](documentations/Logan-info.md) and [documentations/doable-cryptographic-flow.md](documentations/doable-cryptographic-flow.md).

| Item | Status | What was built |
|---|---|---|
| 1. Persistent storage | Done, differently in the app | **The CLI** saves its state as planned, to `client_state.json` (or the file `E2E_STATE_FILE` names), in plaintext, so the warning below still applies to it. **The app** doesn't use JSON: each identity's state and chat history are SQLCipher databases (`client_state.sqlite`, `chat_history.sqlite`), keyed by a vault key derived from the passcode with Argon2id. The PQ keys are ML-KEM-768 now, not `pqcrypto_kyber`. `client_state.json` isn't tracked by git. |
| 2. Relay authentication and replay | Done, with changes | **As planned:** the relay signs the handshake with its Ed25519 key, which the client pins (the CLI takes it as its argument), and the link key comes from an ephemeral-ephemeral X25519 DH. **Changed:** the relay picks the session ID, so the client's init carries only its ephemeral key, and the signature covers the session ID too. There's a key per direction, and numbered packets with a replay window, so link packets can't be replayed either. The client isn't identified in the handshake: its signed sync proves it owns its routing token. |
| 3. Session replay cache | Built, then replaced | `seen_session_keys` was built as planned, then replaced by **add IDs**. Each side numbers every time it adds the other, from a counter that only goes up, and both numbers travel in every KeyExchange and SessionEstablish. A replayed SessionEstablish names a session that exists already or an older one, and changes nothing. |
| 4. Skip dictionary | Done | An 8-byte `seq_no`, `recv_count` and `skip_dict`, as planned. A chunk can be up to 100 ahead, and at most 500 skipped keys are kept (not 1000), the oldest dropped first. The `0x01` header also carries the sender's routing token: `[0x01 \| sender token 16 \| seq_no 8 \| nonce 24 \| ciphertext]`. |

The verification plan's tests exist for items 1, 2 and 4. The replay-cache test went with the cache; add IDs have their own tests.

---

This plan addresses the four specific security and reliability requirements identified in the cryptographic review.

## Proposed Changes

### 1. Persistent Key & State Storage (Client)
- **Goal**: Maintain identities and active sessions across restarts.
- **Approach**: 
  - Add `serde` and `serde_json` to `code/client/Cargo.toml`.
  - Create `code/client/src/storage.rs` with custom serialization wrappers (since cryptographic types like `pqcrypto_kyber::PublicKey` don't implement `Serialize` by default).
  - Save `Client` state (Identity, `pending_contacts`, `e2e_sessions`, `peer_kyber_keys`) to a local `client_state.json` file in the current working directory upon any state change (e.g., establishing a session, ratcheting).
  - Load from `client_state.json` on startup if it exists, otherwise generate a new identity.

### 2. Server Identity Authentication & Replay Prevention
- **Goal**: Authenticate the server and prevent link-layer replay attacks (DoS/Blackhole).
- **Approach**: Upgrade the link layer to a fully interactive, authenticated handshake.
  - **Server Side**: Give the server an `Ed25519` identity key pair (generated on startup or loaded from disk).
  - **Handshake Flow**:
    1. Client -> Server: `[TYPE_HANDSHAKE_INIT | SessionID | ClientEphPub]`
    2. Server -> Client: `[TYPE_HANDSHAKE_RESP | SessionID | ServerEphPub | Ed25519_Signature(ClientEphPub || ServerEphPub)]`
  - **Client Side**: Client verifies the signature using the server's pinned `Ed25519` public key (passed via CLI instead of the X25519 key). Link key becomes `HKDF(DH(ClientEphPriv, ServerEphPub))`.
  - **Benefit**: Replaying a handshake is impossible because the client generates a fresh ephemeral key every boot, and the server signs it live.

### 3. Session Replay Cache
- **Goal**: Prevent the "Session Reset DoS" attack.
- **Approach**:
  - Add `seen_session_keys: HashSet<[u8; 32]>` to the `Client` struct.
  - When receiving a `SessionEstablishPayload` (0x04), verify if `eph_x25519_pub.as_bytes()` is in the set.
  - If it is, drop the packet (it's a replay). If not, add it and process the establishment.

### 4. Symmetric Ratchet Skip Dictionary (Out-of-Order Handling)
- **Goal**: Mitigate session death upon missed UDP messages.
- **Approach**:
  - **Header Update**: Add an 8-byte `sequence_number` to the E2E message packet structure: `[0x01 | 8-byte SeqNo | 24-byte Nonce | E2E Ciphertext]`.
  - **State Update**: Add `recv_count: u64` and `skip_dict: HashMap<u64, [u8; 32]>` to `SymmetricSessionState`.
  - **Logic**: 
    - If `SeqNo == recv_count`, ratchet normally.
    - If `SeqNo > recv_count`, ratchet forward `SeqNo - recv_count` times, storing all skipped Message Keys in `skip_dict`. (Max skip limit: e.g., 1000 messages to prevent OOM attacks).
    - If `SeqNo < recv_count`, look for the key in `skip_dict`. Use it and remove it.

## User Review Required

> [!WARNING]
> **State Storage Limitations**: For the MVP, `client_state.json` will store private keys (Ed25519, X25519, Kyber) in **plaintext** (hex/base64 encoded) on the local disk. In a production mobile app, this must be securely wrapped via iOS Secure Enclave / Android Keystore. Is a plaintext JSON file acceptable for this phase?

> [!IMPORTANT]
> **Server Handshake Change**: The CLI arguments will change. You will need to start the client with the server's `Ed25519` public key instead of its `X25519` key.

## Verification Plan

### Automated Tests
1. **Storage Tests**: Serialize a fully populated `Client` state to disk, deserialize it, and verify keys and ratchet states match perfectly.
2. **Handshake Tests**: Write a test verifying that `TYPE_HANDSHAKE_RESP` with a bad signature is rejected by the client.
3. **Replay Cache Tests**: Write a test attempting to process the exact same `SessionEstablish` payload twice; assert the second attempt is rejected.
4. **Skip Dictionary Tests**: Write a test where Alice sends messages 1, 2, 3, 4. Bob receives 1, 4, 3 (2 is dropped). Assert Bob can successfully decrypt all received messages and the sessions remain fully in sync.
