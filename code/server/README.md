## Tables
- Metadata: (routing_token, incoming IP, incoming port, expiry_timestamp)
- Message Queue: (routing_token, payload, expiry_timestamp)

Storage-engine agnostic: for now using in-memory hashmaps; Redis can be considered for later if needed.

## Server Identity
The server persists its Ed25519 identity to `server_identity.json` on first run. On subsequent boots, the same key is loaded automatically — clients do not need to update their server pubkey after restarts.

## Protocol
```
on_request(request):
    If a 'Handshake' request is received:
        Verify client's Ed25519 signature over ephemeral X25519 key (mutual auth).
        Perform DH(ServerEph, ClientEph), derive link key via HKDF-SHA256.
        Sign (ClientPub || ServerPub) with server Ed25519 identity.
        Return handshake response.
    If a 'Sync' request is received (empty inner payload after link decryption):
        Update the 'Metadata' table with (routing_token, incoming IP, incoming port, expiry_timestamp).
        Flush any queued offline messages for this token to the outbound queue.
    If a 'Forward' request is received:
        Add (routing_token, payload, expiry_timestamp) to the message queue.
        Queue is bounded to 50 messages per token (oldest evicted).
    Otherwise, discard the request.

send_outbound_messages():
    For all routing tokens with active metadata AND queued messages:
        Re-encrypt payload with recipient's link key (XChaCha20-Poly1305).
        Prepend a 16-byte dummy routing token prefix so client can strip uniformly.
        Send UDP packet to recipient's IP + port.
    For all active metadata entries NOT sent real messages:
        Send a dummy UDP packet the same size and framing as a forwarded chat
        message (1150 bytes), inner type 0x00, which clients ignore.
        (Currently disabled: prepare_outbound_messages selects no dummy targets.)

sweep_expired_messages():
    For all entries in the message queue that have expired:
        Delete the entry

sweep_metadata():
    For all entries in the Metadata table that have expired:
        Delete the entry

sweep_active_links():
    For all link keys that have expired (1 hour TTL):
        Delete the entry

main():
    Load or generate server Ed25519 identity.
    Launch a thread that calls send_outbound_messages() every 1 second.
    Launch a thread that calls sweep tasks every 120 seconds.
```

## Other implementation details
- Listens on `127.0.0.1:4430` by default (localhost, for development without `sudo`). Override with the `BIND_ADDR` env var — the Docker image sets `BIND_ADDR=0.0.0.0:443`.
- Server has zero knowledge of user IDs or E2E keys
- All message payloads are stored encrypted in RAM only