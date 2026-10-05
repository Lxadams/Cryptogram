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
        Queue is bounded to MAX_QUEUED_BYTES_PER_TOKEN (2 MiB) per token; once full, new packets are refused (older ones kept) — clients send each message as a burst of FEC packets.
        Wake the outbound task.
    Otherwise, discard the request.

send_due_packets():
    For each routing token with queued packets AND active metadata, whose pacing slot is due:
        Take ONE packet; next slot for this token is RELAY_PACKET_SPACING (5 ms) later.
        Re-encrypt payload with recipient's link key (XChaCha20-Poly1305).
        Prepend a 16-byte dummy routing token prefix so client can strip uniformly.
        Send UDP packet to recipient's IP + port.
    Return when the next slot falls due (if anything is still queued for an online token).

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
    Launch a task that calls send_due_packets(), then sleeps until the next slot or until woken by a new packet/sync (so live FEC bursts pass straight through and backlogs are paced).
    Launch a thread that calls sweep tasks every 120 seconds.
```

## Other implementation details
- Listens on `127.0.0.1:4430` by default (localhost, for development without `sudo`). Override with the `BIND_ADDR` env var — the Docker image sets `BIND_ADDR=0.0.0.0:443`.
- Server has zero knowledge of user IDs or E2E keys
- All message payloads are stored encrypted in RAM only