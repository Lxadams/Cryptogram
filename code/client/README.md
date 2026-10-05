# client: protocol library and CLI

This crate holds the whole E2E-Messenger client protocol: identities, the relay link handshake, the deferred key exchange with hybrid PQXDH, the hash ratchet with PQ injection, presence pings, and encrypted local storage. It builds two targets:

- **a library** (`src/lib.rs`), used by the desktop app's Tauri shell ([`code/frontend/src-tauri`](../frontend/src-tauri));
- **a CLI** (`src/main.rs`), a small terminal REPL for testing without the GUI.

There's one implementation of the protocol, and both front ends call it unchanged. The protocol is explained in [cryptography.md](../../documentations/cryptography.md) and the wire format in [architecture.md §4](../../documentations/architecture.md#4-wire-format).

## Modules

| File | Contents |
|---|---|
| `src/lib.rs` | `Client` (the protocol state machine), `UserIdentity`, `SymmetricSessionState` (the ratchet), `perform_handshake`, passcode hashing and vault-key derivation, and hex parsers. Also holds most of the unit tests. |
| `src/packets.rs` | The signed payloads: `KeyExchangePayload` (`0x02`), `SessionEstablishPayload` (`0x04`), `PQInjectPayload` (`0x05`) and `PresencePayload` (`0x06`), with their wire layouts |
| `src/storage.rs` | `ClientStateDto` (serialisable state; saved as plaintext JSON by the CLI) and `IdentityStateStore` (the same state as one row in a SQLCipher database, used by the desktop app) |
| `src/history.rs` | `ChatHistory`: the SQLCipher `messages` table, for appending, reading recent messages, and deleting a contact |
| `src/main.rs` | The CLI |

## Using the library

A front end supplies a UDP socket and a receive loop. Everything else is a call on `Client`:

```rust
let mut client = Client::new(server_addr);              // or ClientStateDto::load / IdentityStateStore::load
perform_handshake(&mut client, &socket, &relay_pubkey).await?;   // link handshake + sync

// Receive loop
let (len, _) = socket.recv_from(&mut buf).await?;
if let Some(inner) = client.open_link_packet(&buf[..len]) {
    if let Ok(Some(reply)) = client.handle_incoming_packet(&inner) {
        socket.send_to(&reply, client.server_addr).await?;     // e.g. an automatic KeyExchange reply
    }
}

// Add a contact (token + Ed25519 key from their contact code)
client.pending_contacts.insert(token, their_ed25519);
socket.send_to(&client.create_kx_request(token), client.server_addr).await?;

// Send a message (every 5th send also returns a PQInject packet to send)
let (msg, pq_inject) = client.create_encrypted_packet(token, b"hello")?;
```

| API | Purpose |
|---|---|
| `drain_inbox()` | Decrypted incoming messages as `(sender token, plaintext, history row id)` |
| `generate_sync_packet()` | Keepalive or re-announce to the relay |
| `generate_presence_packet(token)` | Signed online ping for one contact |
| `is_online(token, freshness)` | Whether we've heard from that contact within `freshness` |
| `history_for_contact(token, limit)` | Recent messages from the attached `ChatHistory` |
| `forget_contact(token)` | Remove a contact's session, keys, name and history locally |
| `save()` | Save to `identity_store` if one is attached, otherwise to plaintext JSON at `state_path` |
| `hash_passcode`, `verify_passcode`, `derive_vault_key` | Argon2id login verifier and SQLCipher vault key |
| `parse_routing_token`, `parse_verifying_key` | Validate user-supplied hex |

`history` and `identity_store` are optional. If they aren't attached, as in the CLI, nothing is recorded to history and `save()` falls back to plaintext JSON.

## CLI

```bash
cd code/client
cargo run -- <relay Ed25519 pubkey hex>
```

| Environment variable | Default | Meaning |
|---|---|---|
| `SERVER_ADDR` | `127.0.0.1:4430` | Relay address. Host names are resolved, so `server:443` works inside Docker Compose. |
| `E2E_STATE_FILE` | `client_state.json` (working directory) | Where identity and session state are saved, as **plaintext** JSON |

On start it loads the state file, or creates a new identity if there isn't one. It then does the link handshake and prints its routing token and Ed25519 key, which is what another peer needs to add it. Commands:

```
connect <routing_token_hex> <ed25519_pub_hex>   # add a contact and send a KeyExchange
msg <routing_token_hex> <text...>               # send an E2E message (needs an established session)
```

Incoming messages and protocol events are printed as they arrive. Requests from unknown peers are accepted automatically (trust on first use), with a `[SECURITY WARNING]` line.

Compared with the desktop app, the CLI has no chat history, no encrypted storage, no display name, and doesn't send keepalive or presence. Behind a NAT it can stop receiving after a minute or so of silence. To run it in Docker, see [deployment.md](../../documentations/deployment.md#client).

## Constants

| Constant | Value | Where |
|---|---|---|
| PQ injection interval | every 5 sent messages | `PQ_INJECT_INTERVAL` |
| Out-of-order window | 100 messages ahead | `SymmetricSessionState::try_decrypt` |
| Skipped-key limit | 500 keys | `MAX_SKIP_DICT_SIZE` |
| Timestamp tolerance | ±300 s | `MAX_TIMESTAMP_DRIFT` |
| Relay handshake timeout | 5 s | `HANDSHAKE_TIMEOUT` |
| Pending contact cap | 50 (new requests dropped beyond that) | `handle_incoming_packet` (0x02) |
| Replay cache cap | 1000 entries, then cleared | `seen_session_keys`, `pq_inject_replay_cache` |
| Argon2id | m = 19456 KiB, t = 2, p = 1, 16-byte salt | `ARGON2_*` |
| HKDF salt | `e2e-messenger-v1` | `HKDF_SALT` |

## Building and testing

```bash
cargo build
cargo test        # 64 tests
cargo fmt --check && cargo clippy -- -D warnings   # what CI runs
```

`rusqlite` is built with `bundled-sqlcipher-vendored-openssl`, so the first build compiles OpenSSL from source. That needs **Perl** and **make**:

- **Linux:** usually already installed.
- **Windows:** Strawberry Perl (Git Bash's Perl isn't enough) plus `nmake` from the Visual Studio Build Tools.

The first build takes several minutes, up to about 20 on Windows. The tests are listed by area in [cryptography.md §10](../../documentations/cryptography.md#10-tests).
