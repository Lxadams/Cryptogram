## Tables
- Links: (session_id, a link key per direction, the packet numbers sent and taken in, the address the link has proven it's at, the one token synced on it, expiry)
- Token links: (routing_token, the session_id of the link it was last synced on)
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
    If a 'Handshake' request is received (type 0: client ephemeral X25519, then zero
    padding, so the request is bigger than its reply and the relay is never an amplifier):
        Perform DH(ServerEph, ClientEph), derive a link key for each direction via
        HKDF-SHA256. (The handshake doesn't say who the client is: its sync proves that.)
        If the link table is full (MAX_LINKS, 100,000), refuse it.
        Give the link a random session ID no live link has, and remember the address
        the handshake came from: the link's packets go there and nowhere else. (The
        session ID is in the clear on every packet, so it's the relay's to pick: nobody
        who sees one can take that link over by handshaking with it.)
        Sign (label || ClientPub || ServerPub || SessionId) with server Ed25519 identity.
        Return handshake response (type 2: session ID + server ephemeral + signature).
    Every other request is a link packet: [type | session ID | packet number | AEAD],
    sealed with the client-to-relay key, the whole header authenticated too. Refuse it
    unless it's for a link we have, authenticates, and has a packet number not taken in
    before (within a 1024-packet window per lane, for reordering). So a copy of any
    packet, replayed from anywhere, is refused, and one the relay sent (sealed with the
    other key) can't be bounced back to it. Any packet taken in refreshes its link's
    expiry: an hour once a token has synced on it, a minute until then.
    If a 'Sync' request is received (type 4: routing token + token public key + signature
    + up to 64 8-byte admission tags):
        Reject it unless the token is the hash of the public key and the signature, by
        that key, covers a value derived from this link's keys (so only the token's
        owner can sync it, and only on its own link).
        If it came from an address other than the link's (its NAT mapping changed, say),
        don't believe it yet: reply with a path challenge (type 6) to that address,
        sealed with the link key, and change nothing.
        Otherwise:
        Reject it if the link already carries another token: a link carries one token
        for good, so one link can't register any number of made-up tokens.
        If the token was on another link before, delete that link, however long ago it
        was last used, so nothing from it (a replayed sync, say) can move the token back.
        Update the 'Metadata' table with (routing_token, incoming IP, incoming port, expiry_timestamp).
        If the address changed, or this token was silent for over 30 s (asleep), make
        everything still queued for it due now, so it's resent straight away.
        Replace the token's admission tags (kept 7 days, so they still protect it
        offline), unless it has none yet and the table is full (MAX_ADMISSION_ENTRIES,
        100,000): then its packets share one queue, as before tags existed.
        Reply with a sync ack (type 8: the sync's packet number), so the client knows
        its link is still here. A client whose syncs stop being acked (the relay
        restarted, or its link expired) does the handshake again.
        Wake the outbound task.
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
        FEC packets. Recipients without tags (not synced since the relay started, or
        tokens nobody owns) also share MAX_UNREGISTERED_QUEUED_BYTES (64 MiB) between
        them, so made-up tokens can't take the relay's memory.
        Wake the outbound task.
    If an 'Ack' request is received (type 3: own routing token + delivery IDs):
        If it comes from the token's current link session, drop those packets from its queue.
    Otherwise, discard the request.

send_due_packets():
    For each routing token with queued packets AND active metadata, whose pacing slot is due:
        Take the oldest ONE packet that's due (new, or its resend backoff passed);
        next slot for this token is RELAY_PACKET_SPACING (5 ms) later.
        It stays queued until acked; its next resend is 2 s later, doubling to at most 60 s.
        Prepend the 16-byte delivery ID, which the client echoes back in its ack, and
        seal it on the recipient's link (ChaCha20-Poly1305, relay-to-client key, the
        link's next packet number: every resend is sealed afresh).
        Send UDP packet to recipient's IP + port.
    Return when the next slot or resend falls due (if anything is still queued for an online token).
    (Cover traffic: dummy_packet() builds a packet the same size and framing as a
    forwarded FEC chat packet (1138 bytes), inner type 0x00, which clients ignore.
    Currently disabled: nothing sends them.)

sweep_expired_messages():
    For all entries in the message queue that have expired:
        Delete the entry
    Recount the bytes queued for recipients without tags.

sweep_metadata():
    For all entries in the Metadata and Admission tables that have expired:
        Delete the entry

sweep_active_links():
    For all links that have expired (an hour since last use, or a minute if no token
    ever synced on it):
        Delete the entry, and its token's entry in 'Token links'
    If the link, admission or tagless-queue limits are full, log a warning: someone may
    be flooding the relay.

main():
    Load or generate server Ed25519 identity.
    Launch a task that calls send_due_packets(), then sleeps until the next slot or until woken by a new packet/sync (so live FEC bursts pass straight through and backlogs are paced).
    Launch a thread that calls sweep tasks every 120 seconds.
```

## Other implementation details
- Listens on `127.0.0.1:4430` by default (localhost, for development without `sudo`). Override with the `BIND_ADDR` env var — the Docker image sets `BIND_ADDR=0.0.0.0:443`.
- Server has zero knowledge of user IDs or E2E keys
- Refused packets (unknown links, forgeries, replays, malformed or rejected requests) are only logged at debug level, as anyone can send junk
- All message payloads are stored encrypted in RAM only