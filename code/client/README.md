# client

The protocol core: identities, contacts, sessions, encryption and the link
to the relay. It's a library shared by two front ends, so both run the same
code:

- **The CLI** in this crate (`src/main.rs`), a terminal peer for testing.
- **The app** (`code/frontend/src-tauri`), which keeps one `Client` alive
  behind the UI.

For how a message travels from one phone to another, and the packet
formats, see [Logan-info.md](../../documentations/Logan-info.md).

## Modules

| File | What it does |
|---|---|
| `lib.rs` | `Client`: identities, contacts and sessions (PQXDH setup, the symmetric ratchet, PQ refreshes), the link to the relay (handshake, syncs, keepalive), receipts, and the passcode's Argon2id hash and vault key. |
| `main.rs` | The CLI: arguments, the stdin commands, and the receive, keepalive and tick loops. |
| `packets.rs` | The signed payloads (KeyExchange, SessionEstablish, PQ inject, PQ inject request). Each one's layout and signature come from one `signed_bytes()`. |
| `pq.rs` | ML-KEM-768, Cryspen's `libcrux-ml-kem` behind a small interface of fixed-size byte arrays. |
| `transport.rs` | The FEC transport: a message, with any PQ inject, sent as a burst of sealed RaptorQ symbols, and rebuilt from whichever arrive. Holds messages that arrive before the PQ inject they need. |
| `chunks.rs` | Splits a message into chunks that each fit one padded block, and puts them back together. |
| `padding.rs` | Pads every chunk to the same size inside the encryption, so a message's length doesn't show on the wire. |
| `ordering.rs` | Hands each contact's messages over in the order they were sent, waiting up to 10 s for a missing one. |
| `confirmations.rs` | Asks the relay which of our messages it has, for the ✓ and the red **!**. |
| `deliveries.rs` | Remembers the relay's delivery IDs, so a packet resent after a lost ack is handled once. |
| `link_quality.rs` | Estimates the loss each way from the relay's answers, for network stats and the unstable-network warning. |
| `netsim.rs` | Simulated packet loss each way, for testing on one device, and packet counts. |
| `history.rs` | Chat history in SQLCipher (`chat_history.sqlite`), keyed by the vault key. The app uses it; the CLI doesn't. |
| `storage.rs` | Saving and loading a `Client`: `ClientStateDto` (the JSON form, which the CLI writes as it is) and `IdentityStateStore` (the app's SQLCipher `client_state.sqlite`). |
| `test_support.rs` | Helpers for the unit tests. |

## Running the CLI

Start a relay first (`./runserver.sh` from the repo root). It prints its
`Server Static Pubkey` at startup, and the client needs it to check the
relay. Then, from this directory:

```
cargo run -- <relay pubkey hex>
```

- **Relay address:** `SERVER_ADDR`, default `127.0.0.1:4430`. A hostname
  works too (e.g. `server:443` in Docker Compose).
- **On start** it does the link handshake and prints your routing token
  and Ed25519 key, which another peer needs to add you.
- **Commands**, typed in once it's running:
  ```
  connect <routing_token_hex> <ed25519_pub_hex>
  msg <routing_token_hex> <message text...>
  repair <routing_token_hex>
  ```
  `connect` adds a contact. Both people have to add each other before a
  session is set up. `repair` sets up a new session with a contact whose
  session has broken, as the app's **Repair session** does.
- **Received messages** print as `>> [From <first 4 bytes of their token>]: text`.
- It has the same 15 s keepalive and 500 ms tick as the app.

The CLI's state, keys included, is **plaintext JSON** in
`client_state.json` in the current directory, or wherever
`E2E_STATE_FILE` points. Only the app encrypts its state at rest. To run
two CLI peers from one directory, give each its own `E2E_STATE_FILE`.
`client_state.json` is ignored by git.

To run it in Docker instead, see [`code/README.md`](../README.md).

## The `lossy_link` example

A check of the FEC transport over the real relay and real UDP: two
clients, Alice and Bob, in one process, each behind a small proxy that can
drop packets.

```
cargo run --example lossy_link -- <relay pubkey hex> [loss] [jammed] [messages]
```

| Argument | Meaning | Default |
|---|---|---|
| `loss` | Fraction of packets the jammed side drops, both ways | `0.7` |
| `jammed` | `alice`, `bob`, `both` or `none` | `alice` |
| `messages` | Messages sent each way | `30` |

It needs the relay running; `SERVER_ADDR` overrides its address. It exits
non-zero unless every message arrived, in the order it was sent, and both
ratchets stayed in step.

## Tests

```
cargo test
```

The first build is slow: SQLCipher compiles its own OpenSSL, which needs
`perl` and `make`. Argon2id is built optimised even in debug builds (see
`Cargo.toml`), so tests that log in don't take seconds each.
