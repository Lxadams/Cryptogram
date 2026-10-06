# Relay

A QUIC server on UDP 443 that forwards fixed-size cells between clients.
Design and measurements: [documentations/disguised-crt-transport.md](../../documentations/disguised-crt-transport.md).

To anyone on the network it's an HTTP/3 website with a real certificate. A
client running the app opens a link by proving it has the app's access key
and owns its routing token; from then on the relay sends it a cell about
4 times a second, real or padding, and forwards what it sends to whoever owns
the routing token it names.

## Keys

All kept in the working directory (`/data` in Docker), made on first run:

| File | What | Clients get it from |
|---|---|---|
| `relay_cert.pem`, `relay_key.pem` | Self-signed TLS certificate and its key, for testing. Ignored when `TLS_CERT` and `TLS_KEY` point at a real certificate (production). | — |
| (the key above, or `TLS_KEY`) | What clients pin: SHA-256 of the certificate's public key | `server --print-pubkey`, and logged at startup as "Server Static Pubkey" → `SERVER_PUBKEY` |
| `relay_access_key` | Every copy of the app proves it has this. Or set `SERVER_ACCESS_KEY`. | `server --print-access-key` → `SERVER_ACCESS_KEY` |

The app ships with both rather than asking the relay. Renewing a real
certificate must keep its key (certbot's `--reuse-key`), or every app stops
trusting the relay.

## Settings

| Variable | Default | |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:4430` | `0.0.0.0:443` in Docker |
| `TLS_CERT`, `TLS_KEY` | (self-signed) | PEM files: certificate chain, private key |
| `SERVER_NAME` | `localhost` | Names on the self-signed certificate (comma-separated) |
| `SERVER_ACCESS_KEY` | (`relay_access_key`) | 64 hex characters |
| `SITE_DIR` | (built-in page) | Static files for the website |

## Tables (RAM only)
- Link owners: routing token → the link (connection) that proved it owns it.
- Queues: per routing token, packets waiting for its owner, each either
  waiting to be sent or in flight on a link. At most `MAX_QUEUED_BYTES_PER_TOKEN`
  (2 MiB) per token; once full, new packets are refused (older ones kept).
  Kept until delivered, or 7 days.

## Protocol
```
on_connection(conn):
    Serve HTTP/3 on its streams, for as long as it's open (the website).
    Read its datagrams; ignore every one until a cell carries a hello that
    checks out (see code/cell/src/proof.rs):
        an HMAC under the access key, and
        a routing token that's the hash of a key whose signature covers a
        value exported from this connection's TLS session.
    A connection without one never gets a datagram back.
    Then: bind the token to this link (a previous link for it is closed and
    its unconfirmed packets go to this one), and run the link.

link sender, forever, on a Poisson clock averaging 4 cells/s:
    Build a cell: our next sequence number, a receipt for the client's cells,
    and the oldest packet for this token that isn't in flight, if any.
    Remember which packet the cell carried. Send it as a QUIC datagram.

link receiver, for each cell from the client:
    Record its sequence number (for our receipts).
    Settle our cells its receipt covers: a packet whose cell arrived leaves
    the queue; one whose cell was lost is due to be sent again.
    Queue each forwarded payload for the routing token it names.

link closed:
    Unbind the token; anything sent on this link that no receipt settled
    is due again, for the token's next link.

sweep (every 120 s): drop expired packets.
```

QUIC settings (both ends, see `code/cell/src/quic.rs`): every packet after the
handshake padded to 1,200 bytes, a congestion controller that never slows down
under loss, connection IDs rotated every 10 minutes, ALPN `h3`, TLS 1.3 with
X25519MLKEM768 preferred (the app offers nothing else; browsers can still use
X25519).

## Other implementation details
- Knows nothing of user IDs or E2E keys, and sees only opaque payloads.
- Logs no client addresses or routing tokens.
- `cargo test` runs the relay in-process over real QUIC: the website a
  visitor without the access key sees, forwarding, resending lost cells,
  queues for offline recipients, and the constant output rate.
