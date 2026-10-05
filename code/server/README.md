# server: the blind UDP relay

A single-binary Tokio UDP server. It does the link handshake with each client, maps routing tokens to client addresses, and forwards packets that are end-to-end encrypted, re-encrypting each one for the recipient's link. All routing state is kept in RAM. The relay never holds end-to-end keys and can't read message text.

The overall design is in [architecture.md](../../documentations/architecture.md) and the link handshake in [cryptography.md §3](../../documentations/cryptography.md#3-relay-link-handshake).

## Running

```bash
./runserver.sh                 # from the repo root (Linux): build, setcap, run
cd code/server && cargo run    # any platform
```

On boot it prints the relay's public key. Clients need it to authenticate the relay:

```
UDP server listening on 127.0.0.1:4430
Server Static Pubkey: <64 hex chars>
```

For Docker and EC2, see [deployment.md](../../documentations/deployment.md).

| Setting | Default | Notes |
|---|---|---|
| `BIND_ADDR` env var | `127.0.0.1:4430` | The Docker image sets `0.0.0.0:443` |
| `server_identity.json` | in the working directory | Ed25519 secret key, plaintext hex. Created on first run and reused after that. Delete it to rotate the identity; every client then needs the new pubkey. In Docker it's on the `/data` volume. |
| Log level | `info`, fixed in code | `RUST_LOG` has no effect |

`runserver.sh` runs `setcap cap_net_bind_service`, which needs `sudo`, so the binary could bind port 443 without root. With the default port 4430 this isn't needed.

## State (`src/stores.rs`)

| Table | Key → value | Lifetime |
|---|---|---|
| `active_links` | session ID → link key | 1 hour after the handshake |
| `metadata` | routing token → (client address, session ID) | 1000 s, refreshed by every sync packet |
| `message_queues` | routing token → FIFO of inner payloads | Up to 50 per token (oldest dropped). Each entry expires after 1000 s. |

## Protocol

```
on packet:
    0x00 handshake (133 bytes):
        verify the client's Ed25519 signature over its ephemeral X25519 key
        DH(relay_eph, client_eph) → HKDF-SHA256(salt "e2e-messenger-v1", info "wireguard-lite-link") → link key
        sign (client_eph_pub ‖ relay_eph_pub) with the relay's Ed25519 identity
        active_links[session_id] = link key
        reply 0x02 (session_id, relay_eph_pub, signature)

    0x01 data:
        look up the link key by session_id (unknown → drop)
        decrypt with XChaCha20-Poly1305 (bad MAC → drop)
        token = first 16 bytes, inner = the rest
        if inner is empty:   sync    → metadata[token] = (source address, session_id)
        else:                forward → append inner to message_queues[token]

    anything else: drop

every 1 s (outbound task):
    for each token with a metadata entry: take its whole queue
        for each payload: encrypt (16 zero bytes ‖ payload) with the recipient's link key
                          send 0x01 (recipient session_id, nonce, ciphertext) to the recipient's address

every 120 s (sweeper):
    drop expired links, metadata entries and queued messages
```

Every forwarded packet goes through the queue, including packets for online recipients, so delivery takes up to about 1 s. `send_outbound_messages` has a code path for sending encrypted dummy packets of random size (32–1500 bytes), but `prepare_outbound_messages` never picks any targets, so **no dummy traffic is sent**.

## Known limitations

- **No client authorisation.** Any keypair can complete a handshake.
- **Session-ID takeover.** A handshake that reuses an existing session ID replaces that link key, which disconnects the original client.
- **Number of queues isn't capped.** A connected client can create a queue for any number of tokens, limited only by the 1000 s TTL.
- **2048-byte receive buffer.** Larger datagrams (chat messages over about 1.9 KB of text) are dropped.
- **One global `Mutex`** around all the tables.
- **Logs at `info` include routing tokens and client addresses** for every packet.

These are also tracked in [cryptography.md §9](../../documentations/cryptography.md#9-open-issues).

## Tests

```bash
cargo test        # 6 tests in src/main.rs
```

| Test | Checks |
|---|---|
| `test_sync_then_forward` | Handshake, then sync, then forward; the packet lands in the outbound queue |
| `test_edge_case_invalid_handshake` | Empty and wrong-length handshakes are rejected |
| `test_edge_case_handshake_mutual_auth_failure` | A corrupted client signature is rejected |
| `test_edge_case_offline_queuing_and_sync` | A packet for an offline token waits in the queue and is released after that token syncs |
| `test_edge_case_offline_queue_dos_bounds` | 55 packets to one token leave the newest 50 |
| `test_edge_case_offline_queue_ttl_expiry` | The sweeper removes expired entries |

`../../runchecks.sh` runs `cargo clippy` and `cargo fmt` on this crate.
