## Tables
- Metadata: (routing_token, incoming IP, incoming port, expiry_timestamp)
- Message Queue: (routing_token, delivery_id, payload, expiry_timestamp, next resend)

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
    Any link-encrypted request ('Sync', 'Forward', 'Ack') refreshes its link's expiry.
    If a 'Sync' request is received (type 4: routing token + token public key + signature):
        Reject it unless the token is the hash of the public key and the signature, by
        that key, covers a value derived from this link's key (so only the token's
        owner can sync it, and only on its own link).
        Update the 'Metadata' table with (routing_token, incoming IP, incoming port, expiry_timestamp).
        If the address changed, or this token was silent for over 30 s (asleep), make
        everything still queued for it due now, so it's resent straight away.
        Wake the outbound task.
    If a 'Forward' request is received (type 1, with a non-empty inner payload):
        Add it to the message queue with a random 16-byte delivery ID,
        kept until acknowledged or expired (7 days).
        Queue is bounded to MAX_QUEUED_BYTES_PER_TOKEN (2 MiB) per token; once full, new packets are refused (older ones kept) — clients send each message as a burst of FEC packets.
        Wake the outbound task.
    If an 'Ack' request is received (type 3: own routing token + delivery IDs):
        If it comes from the token's current link session, drop those packets from its queue.
    Otherwise, discard the request.

send_due_packets():
    For each routing token with queued packets AND active metadata, whose pacing slot is due:
        Take the oldest ONE packet that's due (new, or its resend backoff passed);
        next slot for this token is RELAY_PACKET_SPACING (5 ms) later.
        It stays queued until acked; its next resend is 2 s later, doubling to at most 60 s.
        Re-encrypt payload with recipient's link key (XChaCha20-Poly1305).
        Prepend the 16-byte delivery ID, which the client echoes back in its ack.
        Send UDP packet to recipient's IP + port.
    Return when the next slot or resend falls due (if anything is still queued for an online token).
    (Cover traffic: dummy_packet() builds a packet the same size and framing as a
    forwarded FEC chat packet (1154 bytes), inner type 0x00, which clients ignore.
    Currently disabled: nothing sends them.)

sweep_expired_messages():
    For all entries in the message queue that have expired:
        Delete the entry

sweep_metadata():
    For all entries in the Metadata table that have expired:
        Delete the entry

sweep_active_links():
    For all link keys that have expired (7 days since last use):
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