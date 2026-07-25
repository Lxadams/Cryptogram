## Tables
- Metadata: (sender_session_id, incoming IP, incoming port, expiry_timestamp)
- Outbound Queue: (receiver_session_id, payload, expiry_timestamp)

Storage-engine agnostic: for now lets go with in-memory hashmaps; Redis can be considered for later if needed


## Protocol
```
on_request(request):
    If a 'Sync' request is received:
        Update the 'Metadata' table with (sender_session_id, incoming IP, incoming port, expiry_timestamp).
    If a 'Forward' request is received:
        Add (receiver_session_id, payload, expiry_timestamp) to the 'Outbound Queue'.
    Otherwise, discard the request.

send_outbound_messages():
    Call sweep_metadata()
    Call sweep_expired_messages()

    For all entries in 'Outbound Queue' as entry:
        Get metadata of entry.receiver_session_id from 'Metadata', discards if failed
        Send UDP packet to IP + port with entry.payload
    For all entries in 'Metadata' not sent in the loop above:
        Send dummy UDP packet to IP + port

sweep_expired_messages():
    For all entries in the 'Outbound Queue' table that have expired:
        Delete the entry

sweep_metadata():
    For all entries in the 'Metadata table' that have expired:
        Delete the entry

main():
    Launch a thread that calls send_outbound_messages() every N seconds.
```