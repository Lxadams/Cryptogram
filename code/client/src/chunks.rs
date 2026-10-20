// Splits a chat message into chunks that each fit one padded block (see
// `padding`), and reassembles them on the receiving side. Every chunk is
// sent as its own ordinary E2E chat message — ratcheted, padded and
// encrypted — so a long message is just several same-size packets on the
// wire, and the chunk header below is only ever visible to the peer.
//
// Each chunk (the payload `padding::pad` wraps) is:
//
//   [kind u8 | 8-byte message id | index u8 | count u8 | data...]
//
// Every message carries the header, even a single-chunk one (`count == 1`),
// so there's only one format to parse.

use crate::RoutingToken;
use crate::padding;
use anyhow::{Result, anyhow};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const KIND_TEXT: u8 = 0x01;
const HEADER_LEN: usize = 1 + 8 + 1 + 1;
/// Message bytes carried per chunk.
pub const CHUNK_DATA_LEN: usize = padding::MAX_PAYLOAD_LEN - HEADER_LEN;
/// Kept small on purpose: the relay queues at most 2 MiB of contacts'
/// packets per recipient (refusing new ones once full), the receiving
/// ratchet only accepts messages up to 100 steps ahead, and losing any one
/// chunk loses the whole message.
pub const MAX_CHUNKS: usize = 16;
/// Longest message, in UTF-8 bytes, that can be sent.
pub const MAX_MESSAGE_LEN: usize = CHUNK_DATA_LEN * MAX_CHUNKS;
/// How long an incomplete message waits for its missing chunks. Chunks are
/// sent back to back, and a relay holding them for an offline recipient
/// delivers them together, so this only needs to outlast a slow network.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(300);
/// Most incomplete messages kept per sender; the oldest is dropped to make
/// room, so a buggy or malicious contact can't grow this without bound.
const MAX_PENDING_PER_SENDER: usize = 4;

type MessageId = [u8; 8];

/// Splits `message` into chunk payloads, in order, or errors if it's longer
/// than `MAX_MESSAGE_LEN`. The error text is shown to the user as-is.
pub fn split(message: &[u8]) -> Result<Vec<Vec<u8>>> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(anyhow!(
            "Message is too long: {} bytes (limit is {MAX_MESSAGE_LEN}). \
             Emoji and non-Latin characters take up to 4 bytes each.",
            message.len()
        ));
    }
    let mut msg_id = [0u8; 8];
    OsRng.fill_bytes(&mut msg_id);
    // `chunks` yields nothing for an empty slice, but an empty message is
    // still sent, as one empty chunk.
    let pieces: Vec<&[u8]> = if message.is_empty() {
        vec![message]
    } else {
        message.chunks(CHUNK_DATA_LEN).collect()
    };
    let count = pieces.len() as u8;
    Ok(pieces
        .into_iter()
        .enumerate()
        .map(|(index, data)| {
            let mut chunk = Vec::with_capacity(HEADER_LEN + data.len());
            chunk.push(KIND_TEXT);
            chunk.extend_from_slice(&msg_id);
            chunk.push(index as u8);
            chunk.push(count);
            chunk.extend_from_slice(data);
            chunk
        })
        .collect())
}

struct Chunk<'a> {
    msg_id: MessageId,
    index: usize,
    count: usize,
    data: &'a [u8],
}

/// Which chunk of its message `chunk` is: `(index, count)`.
pub fn position(chunk: &[u8]) -> Result<(usize, usize)> {
    let chunk = parse(chunk)?;
    Ok((chunk.index, chunk.count))
}

fn parse(chunk: &[u8]) -> Result<Chunk<'_>> {
    if chunk.len() < HEADER_LEN {
        return Err(anyhow!("Chunk is shorter than its header"));
    }
    if chunk[0] != KIND_TEXT {
        return Err(anyhow!("Unknown chunk kind {:#04x}", chunk[0]));
    }
    let index = chunk[9] as usize;
    let count = chunk[10] as usize;
    if count == 0 || count > MAX_CHUNKS || index >= count {
        return Err(anyhow!("Chunk {index} of {count} is out of range"));
    }
    Ok(Chunk {
        msg_id: chunk[1..9].try_into().unwrap(),
        index,
        count,
        data: &chunk[HEADER_LEN..],
    })
}

struct Partial {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    first_seen: Instant,
}

/// Incoming chunks of messages that haven't fully arrived yet. In memory
/// only, like `Client::inbox` — the ratchet state is saved after every
/// chunk, so chunks received before a restart can't be decrypted again and
/// their message is simply lost.
#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<(RoutingToken, MessageId), Partial>,
}

impl Reassembler {
    /// Feeds one decrypted, unpadded chunk from `sender`. Returns the whole
    /// message once its last missing chunk arrives, `None` while it's still
    /// waiting on others.
    pub fn accept(&mut self, sender: RoutingToken, chunk: &[u8]) -> Result<Option<Vec<u8>>> {
        self.accept_at(sender, chunk, Instant::now())
    }

    fn accept_at(
        &mut self,
        sender: RoutingToken,
        chunk: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>> {
        let chunk = parse(chunk)?;
        if chunk.count == 1 {
            return Ok(Some(chunk.data.to_vec()));
        }

        self.expire(now);
        let key = (sender, chunk.msg_id);
        if !self.pending.contains_key(&key) {
            self.make_room_for(sender);
            self.pending.insert(
                key,
                Partial {
                    chunks: vec![None; chunk.count],
                    received: 0,
                    first_seen: now,
                },
            );
        }

        let partial = self.pending.get_mut(&key).unwrap();
        if partial.chunks.len() != chunk.count {
            return Err(anyhow!(
                "Chunk says its message has {} chunks, earlier ones said {}",
                chunk.count,
                partial.chunks.len()
            ));
        }
        // A repeat of a chunk we already hold is ignored (the ratchet
        // rejects replays anyway, so this is belt and braces).
        let slot = &mut partial.chunks[chunk.index];
        if slot.is_none() {
            *slot = Some(chunk.data.to_vec());
            partial.received += 1;
        }
        if partial.received < chunk.count {
            return Ok(None);
        }

        // Every slot is filled by now, so flattening skips nothing.
        let partial = self.pending.remove(&key).unwrap();
        Ok(Some(
            partial.chunks.into_iter().flatten().flatten().collect(),
        ))
    }

    /// Drops every incomplete message from `sender` (e.g. when the contact
    /// is removed).
    pub fn forget(&mut self, sender: &RoutingToken) {
        self.pending.retain(|(s, _), _| s != sender);
    }

    fn expire(&mut self, now: Instant) {
        self.pending.retain(|(sender, _), partial| {
            let keep = now.duration_since(partial.first_seen) < REASSEMBLY_TIMEOUT;
            if !keep {
                println!(
                    ">> Dropped incomplete message from {}: {} of {} chunks arrived.",
                    hex::encode(&sender[0..4]),
                    partial.received,
                    partial.chunks.len()
                );
            }
            keep
        });
    }

    fn make_room_for(&mut self, sender: RoutingToken) {
        let from_sender = self.pending.iter().filter(|((s, _), _)| *s == sender);
        if from_sender.clone().count() < MAX_PENDING_PER_SENDER {
            return;
        }
        let oldest = *from_sender
            .min_by_key(|(_, partial)| partial.first_seen)
            .unwrap()
            .0;
        self.pending.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: RoutingToken = [0xAA; 16];
    const BOB: RoutingToken = [0xBB; 16];

    /// Feeds `chunks` to a fresh reassembler in the given order, asserting
    /// nothing comes out until the last one.
    fn reassemble(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut r = Reassembler::default();
        let (last, rest) = chunks.split_last().unwrap();
        for chunk in rest {
            assert_eq!(r.accept(ALICE, chunk).unwrap(), None);
        }
        r.accept(ALICE, last)
            .unwrap()
            .expect("last chunk completes it")
    }

    #[test]
    fn test_split_chunk_counts_at_boundaries() {
        let cases = [
            (0, 1),
            (1, 1),
            (CHUNK_DATA_LEN, 1),
            (CHUNK_DATA_LEN + 1, 2),
            (MAX_MESSAGE_LEN, MAX_CHUNKS),
        ];
        for (len, expected_chunks) in cases {
            let chunks = split(&vec![b'x'; len]).unwrap();
            assert_eq!(chunks.len(), expected_chunks, "message of {len} bytes");
            for chunk in &chunks {
                assert!(chunk.len() <= padding::MAX_PAYLOAD_LEN);
            }
        }
    }

    #[test]
    fn test_split_rejects_message_over_limit() {
        let err = split(&vec![b'x'; MAX_MESSAGE_LEN + 1]).unwrap_err();
        assert!(err.to_string().contains("too long"), "{err}");
    }

    #[test]
    fn test_roundtrip_in_order_and_reversed() {
        let message: Vec<u8> = (0..MAX_MESSAGE_LEN).map(|i| i as u8).collect();
        let mut chunks = split(&message).unwrap();
        assert_eq!(reassemble(&chunks), message);
        chunks.reverse();
        assert_eq!(reassemble(&chunks), message);
    }

    #[test]
    fn test_roundtrip_multibyte_char_across_boundary() {
        // Puts a 4-byte emoji across the first chunk boundary.
        let message = format!("{}👋 hi", "x".repeat(CHUNK_DATA_LEN - 2));
        let chunks = split(message.as_bytes()).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(reassemble(&chunks), message.as_bytes());
    }

    #[test]
    fn test_empty_and_single_chunk_messages_complete_immediately() {
        let mut r = Reassembler::default();
        for message in [&b""[..], b"hi"] {
            let chunks = split(message).unwrap();
            assert_eq!(r.accept(ALICE, &chunks[0]).unwrap().unwrap(), message);
        }
        assert!(r.pending.is_empty());
    }

    #[test]
    fn test_duplicate_chunk_is_ignored() {
        let message = vec![b'x'; CHUNK_DATA_LEN * 3];
        let chunks = split(&message).unwrap();
        let mut r = Reassembler::default();
        assert_eq!(r.accept(ALICE, &chunks[0]).unwrap(), None);
        assert_eq!(r.accept(ALICE, &chunks[0]).unwrap(), None);
        assert_eq!(r.accept(ALICE, &chunks[1]).unwrap(), None);
        assert_eq!(r.accept(ALICE, &chunks[2]).unwrap().unwrap(), message);
    }

    #[test]
    fn test_same_message_id_from_different_senders_does_not_mix() {
        let chunks = split(&vec![b'x'; CHUNK_DATA_LEN * 2]).unwrap();
        let mut r = Reassembler::default();
        assert_eq!(r.accept(ALICE, &chunks[0]).unwrap(), None);
        assert_eq!(r.accept(BOB, &chunks[1]).unwrap(), None);
    }

    #[test]
    fn test_parse_rejects_malformed_headers() {
        let mut r = Reassembler::default();
        let valid = split(&vec![b'x'; CHUNK_DATA_LEN * 2]).unwrap().remove(0);

        assert!(
            r.accept(ALICE, &valid[..HEADER_LEN - 1]).is_err(),
            "too short"
        );
        let mut bad = valid.clone();
        bad[0] = 0x7F;
        assert!(r.accept(ALICE, &bad).is_err(), "unknown kind");
        let mut bad = valid.clone();
        bad[10] = 0;
        assert!(r.accept(ALICE, &bad).is_err(), "count of zero");
        let mut bad = valid.clone();
        bad[10] = MAX_CHUNKS as u8 + 1;
        assert!(r.accept(ALICE, &bad).is_err(), "count over the limit");
        let mut bad = valid.clone();
        bad[9] = 2;
        assert!(r.accept(ALICE, &bad).is_err(), "index past the count");
    }

    #[test]
    fn test_inconsistent_count_rejected() {
        let chunks = split(&vec![b'x'; CHUNK_DATA_LEN * 3]).unwrap();
        let mut r = Reassembler::default();
        assert_eq!(r.accept(ALICE, &chunks[0]).unwrap(), None);
        let mut bad = chunks[1].clone();
        bad[10] = 2;
        assert!(r.accept(ALICE, &bad).is_err());
    }

    #[test]
    fn test_incomplete_message_expires() {
        let chunks = split(&vec![b'x'; CHUNK_DATA_LEN * 2]).unwrap();
        let mut r = Reassembler::default();
        let start = Instant::now();
        assert_eq!(r.accept_at(ALICE, &chunks[0], start).unwrap(), None);

        // The missing half turns up too late: the first half is gone, so
        // this starts (and waits on) a fresh incomplete message instead.
        let late = start + REASSEMBLY_TIMEOUT;
        assert_eq!(r.accept_at(ALICE, &chunks[1], late).unwrap(), None);
        assert_eq!(r.pending.len(), 1);
    }

    #[test]
    fn test_pending_per_sender_is_capped_dropping_oldest() {
        let mut r = Reassembler::default();
        let start = Instant::now();
        let messages: Vec<Vec<Vec<u8>>> = (0..=MAX_PENDING_PER_SENDER)
            .map(|_| split(&vec![b'x'; CHUNK_DATA_LEN * 2]).unwrap())
            .collect();
        for (i, chunks) in messages.iter().enumerate() {
            let at = start + Duration::from_secs(i as u64);
            assert_eq!(r.accept_at(ALICE, &chunks[0], at).unwrap(), None);
        }
        assert_eq!(r.pending.len(), MAX_PENDING_PER_SENDER);

        // The oldest was dropped, so its second half can't complete it...
        let at = start + Duration::from_secs(60);
        assert_eq!(r.accept_at(ALICE, &messages[0][1], at).unwrap(), None);
        // ...but the newest is still there.
        let newest = messages.last().unwrap();
        assert!(r.accept_at(ALICE, &newest[1], at).unwrap().is_some());

        // Another sender's messages don't count against Alice's cap.
        let bob_chunks = split(&vec![b'x'; CHUNK_DATA_LEN * 2]).unwrap();
        r.accept_at(BOB, &bob_chunks[0], at).unwrap();
        assert!(r.pending.keys().any(|(s, _)| *s == BOB));
    }

    #[test]
    fn test_forget_drops_only_that_sender() {
        let chunks = split(&vec![b'x'; CHUNK_DATA_LEN * 2]).unwrap();
        let mut r = Reassembler::default();
        r.accept(ALICE, &chunks[0]).unwrap();
        r.accept(BOB, &chunks[0]).unwrap();
        r.forget(&ALICE);
        assert!(r.pending.keys().all(|(s, _)| *s == BOB));
        assert_eq!(r.pending.len(), 1);
    }
}
