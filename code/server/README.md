## Tables
- Links: (session_id, link key, the address the link has proven it's at, the token last synced on it, expiry)
- Metadata: (routing_token, incoming IP, incoming port, link session, expiry_timestamp)
- Message Queue: (routing_token, delivery_id, payload, admitted?, expiry_timestamp, next resend)
- Admission: (routing_token, the admission tags its contacts put on their packets, expiry)

Storage-engine agnostic: for now using in-memory hashmaps; Redis can be considered for later if needed.

## Server Identity
The server persists its Ed25519 identity to `server_identity.json` on first run. On subsequent boots, the same key is loaded automatically — clients do not need to update their server pubkey after restarts.

`server --print-pubkey` prints the key and exits. It never creates an identity: if there's none in the current directory yet, it says so and exits with an error, rather than making up a key no running relay has (which would be baked into every client built with it). Start the relay once to create one.

The packet formats, the handshake and the sync proof live in `code/relay-link`, which the client builds on too.

## Protocol
```
on_request(request):
    If a 'Handshake' request is received (type 0: client ephemeral X25519 + Ed25519 key + signature):
        Verify client's Ed25519 signature over ephemeral X25519 key (mutual auth).
        Perform DH(ServerEph, ClientEph), derive link key via HKDF-SHA256.
        Give the link a random session ID no live link has, and remember the address
        the handshake came from: the link's packets go there and nowhere else. (The
        session ID is in the clear on every packet, so it's the relay's to pick: nobody
        who sees one can take that link over by handshaking with it.)
        Sign (label || ClientPub || ServerPub || SessionId) with server Ed25519 identity.
        Return handshake response (type 2: session ID + server ephemeral + signature).
    Every other request is a link packet: [type | session ID | nonce | AEAD], with the
    type and session ID authenticated too. Any one refreshes its link's expiry.
    If a 'Sync' request is received (type 4: routing token + token public key + signature
    + up to 64 8-byte admission tags):
        Reject it unless the token is the hash of the public key and the signature, by
        that key, covers a value derived from this link's key (so only the token's
        owner can sync it, and only on its own link).
        If it came from an address other than the link's, don't believe it yet (it may
        be a copy someone captured and replayed from elsewhere): reply with a path
        challenge (type 6) to that address, sealed with the link key, and change nothing.
        Otherwise:
        If the token was on another link before, delete that link, so nothing from it
        (a replayed sync, say) can move the token back.
        Update the 'Metadata' table with (routing_token, incoming IP, incoming port, expiry_timestamp).
        If the address changed, or this token was silent for over 30 s (asleep), make
        everything still queued for it due now, so it's resent straight away.
        Replace the token's admission tags (kept 7 days, so they still protect it offline).
        Wake the outbound task.
    If a 'Path Response' request is received (type 7: the challenge, echoed):
        If it answers a challenge for this link at the address it came from (from the
        last 10-20 s), the link has moved there: send it everything there from now on,
        resending whatever it hasn't acked. Challenges are HMACs under a key the relay
        keeps in memory, so it doesn't have to remember the ones it sent.
    If a 'Forward' request is received (type 1, or type 5 with an admission tag, with a
    non-empty inner payload):
        Add it to the message queue with a random 16-byte delivery ID,
        kept until acknowledged or expired (7 days).
        Once the recipient has registered admission tags, a packet carrying one of them
        is from a contact; anything else isn't, and only gets a separate
        MAX_UNADMITTED_BYTES_PER_TOKEN (64 KiB) per token, oldest evicted first, so
        anyone who only knows the token (it's in the recipient's QR code) can't fill
        the queue its contacts' messages wait in.
        The contacts' queue is bounded to MAX_QUEUED_BYTES_PER_TOKEN (2 MiB) per token
        (everything shares it before the recipient registers tags); once full, new
        packets are refused (older ones kept) — clients send each message as a burst of
        FEC packets.
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
    For all entries in the Metadata and Admission tables that have expired:
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