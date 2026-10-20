//! Forward error correction for E2E-Messenger's transport.
//!
//! A message (an "object": any byte buffer up to `MAX_OBJECT_LEN`) is
//! RaptorQ-encoded (RFC 6330) into `K` source symbols plus as many repair
//! symbols as the caller asks for. The receiver rebuilds the object from
//! *any* `K` (or very slightly more) of them, in any order — so a burst of
//! `N` packets survives losing up to roughly `N - K` of them, with no ACKs
//! or retransmission. That's the whole loss-tolerance story: the sender
//! decides up front how much redundancy the link needs (`packets_for`) and
//! fires the lot.
//!
//! This crate is deliberately pure — no sockets, no crypto — so it can be
//! tested in isolation and shared by anything that needs it. Each packet it
//! produces is
//!
//!   [4-byte object id | 4-byte object length | 4-byte symbol id | symbol]
//!
//! (all big-endian). The client seals every one of these end to end before
//! it touches the network (see `code/client`), so a relay only ever forwards
//! opaque bytes and can't reassemble anything.

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation, PayloadId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Object id + object length + symbol id.
pub const HEADER_LEN: usize = 12;
/// Largest symbol (and so the largest payload a single packet carries).
/// Sized so a symbol plus every layer of overhead around it stays well
/// inside a ~1200-byte UDP datagram, which crosses real networks unfragmented.
pub const MAX_SYMBOL_SIZE: usize = 1024;
/// Largest object this crate will encode or reassemble. Bounds both the
/// receiver's memory per object and the decode cost (at most 64 source
/// symbols per object).
pub const MAX_OBJECT_LEN: usize = 64 * 1024;
/// Hard ceiling on packets per object, whatever `packets_for` is asked for.
pub const MAX_PACKETS_PER_OBJECT: u32 = 4096;
/// RFC 6330 symbol alignment; every symbol size is a multiple of this.
const ALIGNMENT: usize = 8;
/// RFC 6330 encoding symbol ids are 24 bits on the wire.
const MAX_SYMBOL_ID: u32 = (1 << 24) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecError {
    /// Empty objects carry nothing and RaptorQ can't encode them.
    EmptyObject,
    /// Object length is over `MAX_OBJECT_LEN` (or zero, on receipt).
    ObjectTooLarge,
    /// `encode` was asked for more than `MAX_PACKETS_PER_OBJECT` packets.
    TooManyPackets,
    /// Packet is shorter than its header.
    Truncated,
    /// Symbol id is outside RFC 6330's 24-bit range.
    BadSymbolId,
    /// Symbol length doesn't match what the object length implies.
    BadSymbolSize,
    /// Packet disagrees with earlier packets of the same object about the
    /// object's length.
    InconsistentLength,
    /// An object received far more symbols than decoding it could need
    /// without completing; it was dropped.
    TooManySymbols,
}

impl fmt::Display for FecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::EmptyObject => "cannot FEC-encode an empty object",
            Self::ObjectTooLarge => "object length is zero or exceeds MAX_OBJECT_LEN",
            Self::TooManyPackets => "more packets requested than MAX_PACKETS_PER_OBJECT",
            Self::Truncated => "FEC packet is shorter than its header",
            Self::BadSymbolId => "FEC symbol id is out of range",
            Self::BadSymbolSize => "FEC symbol size doesn't match the object length",
            Self::InconsistentLength => "FEC packets disagree about their object's length",
            Self::TooManySymbols => "FEC object received too many symbols without decoding",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for FecError {}

/// Symbol size used for an object of `object_len` bytes: the object rounded
/// up to the alignment, capped at `MAX_SYMBOL_SIZE`. Small objects (most
/// chat messages) therefore travel as a single small symbol instead of being
/// padded out to a full kilobyte in every packet. Both ends derive it from
/// the object length, so it never needs to be sent.
pub fn symbol_size_for(object_len: usize) -> usize {
    object_len
        .div_ceil(ALIGNMENT)
        .saturating_mul(ALIGNMENT)
        .clamp(ALIGNMENT, MAX_SYMBOL_SIZE)
}

/// Number of source symbols (`K`) an object of `object_len` bytes splits into.
pub fn source_symbols_for(object_len: usize) -> u32 {
    object_len.div_ceil(symbol_size_for(object_len)) as u32
}

fn check_object_len(object_len: usize) -> Result<(), FecError> {
    match object_len {
        0 => Err(FecError::EmptyObject),
        n if n > MAX_OBJECT_LEN => Err(FecError::ObjectTooLarge),
        _ => Ok(()),
    }
}

/// One source block, one sub-block: objects are small enough that RFC 6330's
/// partitioning machinery would only add parameters to agree on.
fn transmission_info(object_len: usize) -> ObjectTransmissionInformation {
    ObjectTransmissionInformation::new(
        object_len as u64,
        symbol_size_for(object_len) as u16,
        1,
        1,
        ALIGNMENT as u8,
    )
}

/// Probability that an object of `k` source symbols fails to decode when
/// `n` packets are sent and each survives independently with probability
/// `survive`. Decoding certainly fails with fewer than `k` symbols; with
/// `k + h` it fails with probability about `10^-(2h + 2)` — RFC 6330's
/// stated bounds of 1e-2, 1e-4 and 1e-6 for h = 0, 1, 2, continued at the
/// same rate of ~100x per extra symbol (GF(256) decoding actually does a
/// little better). It must keep falling rather than flatten out at 1e-6:
/// a floor there would make a 1e-6 target reachable only through float
/// rounding, at several times the packets really needed.
fn failure_probability(k: u32, n: u32, survive: f64) -> f64 {
    let fail_with_overhead = |overhead: i64| {
        if overhead < 0 {
            1.0
        } else {
            10f64.powi(-2 * (overhead as i32 + 1))
        }
    };
    if survive >= 1.0 {
        return fail_with_overhead(n as i64 - k as i64);
    }
    // Binomial pmf in log space so long bursts at heavy loss don't
    // underflow (0.3^4096 is well below f64's range).
    let (ln_survive, ln_lost) = (survive.ln(), (1.0 - survive).ln());
    let mut ln_pmf = n as f64 * ln_lost; // P(0 received)
    let mut failure = 0.0;
    for r in 0..=n {
        failure += ln_pmf.exp() * fail_with_overhead(r as i64 - k as i64);
        if r < n {
            ln_pmf += ((n - r) as f64 / (r + 1) as f64).ln() + ln_survive - ln_lost;
        }
    }
    // Clamped because the log-space terms can sum a hair over 1 right next
    // to certain failure.
    failure.min(1.0)
}

/// How many packets to send for an object of `object_len` bytes so it is
/// rebuilt with probability at least `1 - max_failure`, when each packet is
/// independently lost with probability `loss`. Never fewer than the object's
/// source symbol count, never more than `MAX_PACKETS_PER_OBJECT`.
pub fn packets_for(object_len: usize, loss: f64, max_failure: f64) -> u32 {
    let k = source_symbols_for(object_len.max(1));
    let survive = 1.0 - loss.clamp(0.0, 0.999);
    (k..=MAX_PACKETS_PER_OBJECT)
        .find(|&n| failure_probability(k, n, survive) <= max_failure)
        .unwrap_or(MAX_PACKETS_PER_OBJECT)
}

/// Encode `object` into `packets` FEC packets (or the object's source symbol
/// count, if that's more): the `K` source symbols first, then repair symbols.
/// `object_id` must be unique among the sender's recent objects to the same
/// receiver. The client uses the ratchet position of the message's last
/// chunk, which is unique within a session.
pub fn encode(object_id: u32, object: &[u8], packets: u32) -> Result<Vec<Vec<u8>>, FecError> {
    check_object_len(object.len())?;
    if packets > MAX_PACKETS_PER_OBJECT {
        return Err(FecError::TooManyPackets);
    }
    let k = source_symbols_for(object.len());
    let encoder = Encoder::new(object, transmission_info(object.len()));
    let block = &encoder.get_block_encoders()[0];
    let mut symbols = block.source_packets();
    symbols.extend(block.repair_packets(0, packets.saturating_sub(k)));

    let header_prefix = {
        let mut prefix = [0u8; 8];
        prefix[..4].copy_from_slice(&object_id.to_be_bytes());
        prefix[4..].copy_from_slice(&(object.len() as u32).to_be_bytes());
        prefix
    };
    Ok(symbols
        .into_iter()
        .map(|symbol| {
            let (payload_id, data) = symbol.split();
            let mut packet = Vec::with_capacity(HEADER_LEN + data.len());
            packet.extend_from_slice(&header_prefix);
            packet.extend_from_slice(&payload_id.encoding_symbol_id().to_be_bytes());
            packet.extend_from_slice(&data);
            packet
        })
        .collect())
}

struct Header {
    object_id: u32,
    object_len: usize,
    symbol_id: u32,
}

/// Validates everything `raptorq` would otherwise `assert!` on, so no packet
/// off the network can panic the decoder.
fn parse(packet: &[u8]) -> Result<(Header, &[u8]), FecError> {
    if packet.len() < HEADER_LEN {
        return Err(FecError::Truncated);
    }
    let field = |i: usize| u32::from_be_bytes(packet[i..i + 4].try_into().unwrap());
    let header = Header {
        object_id: field(0),
        object_len: field(4) as usize,
        symbol_id: field(8),
    };
    if header.object_len == 0 || header.object_len > MAX_OBJECT_LEN {
        return Err(FecError::ObjectTooLarge);
    }
    if header.symbol_id > MAX_SYMBOL_ID {
        return Err(FecError::BadSymbolId);
    }
    let symbol = &packet[HEADER_LEN..];
    if symbol.len() != symbol_size_for(header.object_len) {
        return Err(FecError::BadSymbolSize);
    }
    Ok((header, symbol))
}

/// Memory bounds for a `Reassembler`. Objects that never gather enough
/// symbols (the sender's whole burst was jammed) would otherwise pile up
/// forever; these caps decide what gets dropped first.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Partially received objects held at once, across all sources.
    pub max_pending: usize,
    /// Partially received objects held at once from a single source.
    pub max_pending_per_source: usize,
    /// How long a partially received object waits for more symbols.
    pub pending_ttl: Duration,
    /// Finished objects remembered so their straggling symbols are ignored
    /// instead of decoding the same object twice.
    pub max_completed: usize,
    /// How long a finished object is remembered.
    pub completed_ttl: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_pending: 128,
            max_pending_per_source: 32,
            pending_ttl: Duration::from_secs(120),
            max_completed: 4096,
            completed_ttl: Duration::from_secs(600),
        }
    }
}

struct Pending {
    decoder: Decoder,
    object_len: usize,
    first_seen: Instant,
    received: u32,
}

/// Collects FEC packets from any number of sources and hands back each
/// object exactly once, as soon as enough of its symbols have arrived.
/// `S` identifies a sender (the client uses the peer's routing token);
/// object ids only need to be unique per sender.
pub struct Reassembler<S> {
    limits: Limits,
    pending: HashMap<(S, u32), Pending>,
    completed: HashSet<(S, u32)>,
    completed_order: VecDeque<((S, u32), Instant)>,
}

impl<S: Copy + Eq + Hash> Default for Reassembler<S> {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl<S: Copy + Eq + Hash> Reassembler<S> {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            pending: HashMap::new(),
            completed: HashSet::new(),
            completed_order: VecDeque::new(),
        }
    }

    /// Feed one FEC packet from `source`. Returns the rebuilt object the
    /// first time enough symbols have arrived, `None` while it's still
    /// incomplete (or for stragglers of an object already returned), and an
    /// error for packets that are malformed or inconsistent.
    pub fn ingest(
        &mut self,
        source: S,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, FecError> {
        let (header, symbol) = parse(packet)?;
        let key = (source, header.object_id);
        if self.completed.contains(&key) {
            return Ok(None);
        }
        if !self.pending.contains_key(&key) {
            self.make_room(source, now);
            self.pending.insert(
                key,
                Pending {
                    decoder: Decoder::new(transmission_info(header.object_len)),
                    object_len: header.object_len,
                    first_seen: now,
                    received: 0,
                },
            );
        }
        let entry = self.pending.get_mut(&key).expect("inserted above");
        if entry.object_len != header.object_len {
            return Err(FecError::InconsistentLength);
        }
        entry.received += 1;
        // A healthy object decodes within K + 2 distinct symbols; allow a
        // generous margin for duplicates before deciding it never will.
        let k = source_symbols_for(entry.object_len);
        if entry.received > 4 * k + 64 {
            self.pending.remove(&key);
            return Err(FecError::TooManySymbols);
        }
        let packet = EncodingPacket::new(PayloadId::new(0, header.symbol_id), symbol.to_vec());
        match entry.decoder.decode(packet) {
            Some(object) => {
                self.pending.remove(&key);
                self.remember_completed(key, now);
                Ok(Some(object))
            }
            None => Ok(None),
        }
    }

    /// Partially received objects currently held.
    pub fn pending_objects(&self) -> usize {
        self.pending.len()
    }

    /// Drop pending objects that waited too long, then evict the oldest
    /// pending objects until there's room for one more from `source`.
    fn make_room(&mut self, source: S, now: Instant) {
        let ttl = self.limits.pending_ttl;
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.first_seen) < ttl);

        let from_source = self.pending.keys().filter(|(s, _)| *s == source).count();
        if from_source >= self.limits.max_pending_per_source {
            self.evict_oldest(|(s, _)| *s == source);
        }
        if self.pending.len() >= self.limits.max_pending {
            self.evict_oldest(|_| true);
        }
    }

    fn evict_oldest(&mut self, matches: impl Fn(&(S, u32)) -> bool) {
        let oldest = self
            .pending
            .iter()
            .filter(|(key, _)| matches(key))
            .min_by_key(|(_, p)| p.first_seen)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.pending.remove(&key);
        }
    }

    fn remember_completed(&mut self, key: (S, u32), now: Instant) {
        self.completed.insert(key);
        self.completed_order.push_back((key, now));
        while let Some(&(old_key, finished)) = self.completed_order.front() {
            let expired = now.saturating_duration_since(finished) >= self.limits.completed_ttl;
            if !expired && self.completed_order.len() <= self.limits.max_completed {
                break;
            }
            self.completed_order.pop_front();
            self.completed.remove(&old_key);
        }
    }
}

/// Test helpers, also used by the `client` crate's tests (via the
/// `test-util` feature).
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    /// SplitMix64 — a tiny seeded PRNG so every loss pattern is
    /// reproducible without pulling in a `rand` dependency.
    pub struct Rng(pub u64);

    impl Rng {
        pub fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// Uniform in [0, 1).
        pub fn unit(&mut self) -> f64 {
            (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
        }

        pub fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }

        pub fn shuffle<T>(&mut self, items: &mut [T]) {
            for i in (1..items.len()).rev() {
                items.swap(i, self.below(i + 1));
            }
        }

        pub fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next_u64() as u8).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::Rng;
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    /// Feed `packets` to a fresh reassembler; return the object if it decodes.
    fn reassemble(packets: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut rx = Reassembler::default();
        let t = now();
        let mut result = None;
        for packet in packets {
            if let Some(object) = rx.ingest(1u8, packet, t).unwrap() {
                assert!(result.is_none(), "object returned twice");
                result = Some(object);
            }
        }
        result
    }

    #[test]
    fn symbol_size_rule() {
        assert_eq!((symbol_size_for(1), source_symbols_for(1)), (8, 1));
        assert_eq!((symbol_size_for(100), source_symbols_for(100)), (104, 1));
        assert_eq!((symbol_size_for(1024), source_symbols_for(1024)), (1024, 1));
        assert_eq!((symbol_size_for(1025), source_symbols_for(1025)), (1024, 2));
        assert_eq!(source_symbols_for(MAX_OBJECT_LEN), 64);
    }

    #[test]
    fn roundtrip_without_loss_at_every_size_boundary() {
        let mut rng = Rng(1);
        for len in [
            1,
            7,
            8,
            9,
            100,
            1023,
            1024,
            1025,
            4096,
            10_000,
            MAX_OBJECT_LEN,
        ] {
            let object = rng.bytes(len);
            // Exactly the source symbols, no repair at all.
            let packets = encode(7, &object, 0).unwrap();
            assert_eq!(packets.len() as u32, source_symbols_for(len));
            assert_eq!(
                reassemble(&packets).as_deref(),
                Some(&object[..]),
                "len {len}"
            );
        }
    }

    #[test]
    fn encode_rejects_empty_oversized_and_absurd_requests() {
        assert_eq!(encode(1, &[], 10), Err(FecError::EmptyObject));
        assert_eq!(
            encode(1, &vec![0; MAX_OBJECT_LEN + 1], 10),
            Err(FecError::ObjectTooLarge)
        );
        assert_eq!(
            encode(1, b"hi", MAX_PACKETS_PER_OBJECT + 1),
            Err(FecError::TooManyPackets)
        );
    }

    #[test]
    fn decodes_from_repair_symbols_alone() {
        let object = Rng(2).bytes(5000);
        let k = source_symbols_for(object.len()) as usize;
        let packets = encode(3, &object, 3 * k as u32).unwrap();
        // Every source symbol lost; only repair symbols arrive.
        assert_eq!(reassemble(&packets[k..]).as_deref(), Some(&object[..]));
    }

    #[test]
    fn fewer_than_k_symbols_never_decode() {
        let object = Rng(3).bytes(4000);
        let k = source_symbols_for(object.len()) as usize;
        let packets = encode(3, &object, 40).unwrap();
        assert_eq!(reassemble(&packets[packets.len() - (k - 1)..]), None);
    }

    #[test]
    fn order_and_duplicates_dont_matter() {
        let mut rng = Rng(4);
        let object = rng.bytes(3000);
        let mut packets = encode(9, &object, 20).unwrap();
        let copies = packets.clone();
        packets.extend(copies);
        rng.shuffle(&mut packets);
        // `reassemble` asserts the object comes back exactly once, despite
        // every symbol arriving twice and stragglers after completion.
        assert_eq!(reassemble(&packets).as_deref(), Some(&object[..]));
    }

    /// The headline property: sized by `packets_for` for 70% loss, objects
    /// survive 70% independent packet loss at (better than) the target rate.
    #[test]
    fn survives_70_percent_random_loss() {
        let mut rng = Rng(5);
        let trials = 1000;
        let mut failures = 0;
        for trial in 0..trials {
            let len = 50 + (trial * 37) % 4000;
            let object = rng.bytes(len);
            let n = packets_for(len, 0.7, 1e-4);
            let mut packets = encode(trial as u32, &object, n).unwrap();
            packets.retain(|_| rng.unit() >= 0.7);
            rng.shuffle(&mut packets);
            match reassemble(&packets) {
                Some(rebuilt) => assert_eq!(rebuilt, object),
                None => failures += 1,
            }
        }
        // Expected failures: 1000 * 1e-4 = 0.1.
        assert!(failures <= 1, "{failures} of {trials} objects lost");
    }

    /// Same channel without the redundancy: confirms the test above is
    /// actually exercising the code rather than an easy channel.
    #[test]
    fn without_redundancy_70_percent_loss_is_fatal() {
        let mut rng = Rng(6);
        let mut delivered = 0;
        for trial in 0..200 {
            let object = rng.bytes(500);
            let mut packets = encode(trial, &object, 0).unwrap();
            packets.retain(|_| rng.unit() >= 0.7);
            delivered += reassemble(&packets).is_some() as u32;
        }
        assert!(delivered < 100, "{delivered} of 200 delivered with no FEC");
    }

    /// The analytic model behind `packets_for` should be honest: at a loose
    /// 1% target (so failures are frequent enough to count), the measured
    /// failure rate must not be meaningfully worse than promised.
    #[test]
    fn redundancy_model_matches_measured_failure_rate() {
        let mut rng = Rng(7);
        for len in [200, 4000] {
            let n = packets_for(len, 0.7, 1e-2);
            let trials = 3000;
            let mut failures = 0;
            for trial in 0..trials {
                let object = rng.bytes(len);
                let mut packets = encode(trial, &object, n).unwrap();
                packets.retain(|_| rng.unit() >= 0.7);
                failures += reassemble(&packets).is_none() as u32;
            }
            let rate = failures as f64 / trials as f64;
            assert!(rate <= 0.02, "len {len}: {rate} measured vs 0.01 promised");
        }
    }

    /// Jamming tends to come in bursts rather than independent drops. A
    /// two-state (Gilbert-Elliott) channel averaging the same 70% loss, with
    /// bad spells ~5 packets long, is harsher than independent loss at the
    /// same sizing — this pins how much, so the margin is a known quantity
    /// (and why the sender spreads its burst out in time).
    #[test]
    fn bursty_loss_at_the_same_average_rate() {
        let mut rng = Rng(8);
        // Bad spells lose everything, good spells lose 10%. Leaving bad with
        // p = 0.2 (mean spell 5 packets) and good with p = 0.4 spends 2/3 of
        // the time bad: 2/3 * 100% + 1/3 * 10% = 70% average loss.
        let (leave_bad, leave_good, good_loss) = (0.2, 0.4, 0.1);
        let trials = 1000;
        let mut failures = 0;
        let mut bad = false;
        let mut lost = 0usize;
        let mut sent = 0usize;
        for trial in 0..trials {
            let object = rng.bytes(300);
            let n = packets_for(300, 0.7, 1e-4);
            let mut packets = encode(trial, &object, n).unwrap();
            packets.retain(|_| {
                bad = if bad {
                    rng.unit() >= leave_bad
                } else {
                    rng.unit() < leave_good
                };
                let drop = bad || rng.unit() < good_loss;
                sent += 1;
                lost += drop as usize;
                !drop
            });
            failures += reassemble(&packets).is_none() as u32;
        }
        let average_loss = lost as f64 / sent as f64;
        assert!((0.65..0.75).contains(&average_loss), "{average_loss}");
        assert!(failures <= 10, "{failures} of {trials} lost to bursts");
    }

    #[test]
    fn packets_for_matches_the_published_table() {
        // 70% loss; K = 1, 2 and 4 source symbols.
        assert_eq!(packets_for(100, 0.7, 1e-3), 20);
        assert_eq!(packets_for(100, 0.7, 1e-4), 27);
        assert_eq!(packets_for(2000, 0.7, 1e-3), 27);
        assert_eq!(packets_for(2000, 0.7, 1e-4), 34);
        assert_eq!(packets_for(4000, 0.7, 1e-3), 39);
        assert_eq!(packets_for(4000, 0.7, 1e-4), 47);
        // No loss: K + 2 symbols already meets RFC 6330's 1e-6 bound.
        assert_eq!(packets_for(100, 0.0, 1e-6), 3);
        // More loss never needs fewer packets.
        let mut last = 0;
        for tenth in 0..10 {
            let n = packets_for(1500, tenth as f64 / 10.0, 1e-4);
            assert!(n >= last);
            last = n;
        }
        // Total loss is capped rather than looping forever.
        assert_eq!(packets_for(100, 1.0, 1e-9), MAX_PACKETS_PER_OBJECT);
    }

    #[test]
    fn interleaved_objects_from_several_sources() {
        let mut rng = Rng(9);
        let mut rx = Reassembler::default();
        let t = now();
        // Two sources reuse the same object id: they must not collide.
        let a = rng.bytes(2500);
        let b = rng.bytes(700);
        let mut stream: Vec<(u8, Vec<u8>)> = encode(42, &a, 10)
            .unwrap()
            .into_iter()
            .map(|p| (1, p))
            .chain(encode(42, &b, 10).unwrap().into_iter().map(|p| (2, p)))
            .collect();
        rng.shuffle(&mut stream);
        let mut got = HashMap::new();
        for (source, packet) in &stream {
            if let Some(object) = rx.ingest(*source, packet, t).unwrap() {
                assert!(got.insert(*source, object).is_none());
            }
        }
        assert_eq!(got.get(&1), Some(&a));
        assert_eq!(got.get(&2), Some(&b));
        assert_eq!(rx.pending_objects(), 0);
    }

    #[test]
    fn malformed_packets_are_rejected_not_panicked_on() {
        let mut rx = Reassembler::default();
        let t = now();
        let good = encode(5, &[1u8; 100], 3).unwrap();
        let tweak = |at: usize, value: u32| {
            let mut p = good[0].clone();
            p[at..at + 4].copy_from_slice(&value.to_be_bytes());
            p
        };

        assert_eq!(rx.ingest(0u8, &good[0][..11], t), Err(FecError::Truncated));
        assert_eq!(
            rx.ingest(0u8, &tweak(4, 0), t),
            Err(FecError::ObjectTooLarge)
        );
        let too_big = MAX_OBJECT_LEN as u32 + 1;
        assert_eq!(
            rx.ingest(0u8, &tweak(4, too_big), t),
            Err(FecError::ObjectTooLarge)
        );
        assert_eq!(
            rx.ingest(0u8, &tweak(8, 1 << 24), t),
            Err(FecError::BadSymbolId)
        );
        let mut short_symbol = good[0].clone();
        short_symbol.pop();
        assert_eq!(
            rx.ingest(0u8, &short_symbol, t),
            Err(FecError::BadSymbolSize)
        );
        // Same object id, a different (but self-consistent) length. The
        // first object needs two symbols, so it's still pending, not done.
        let two_symbols = encode(6, &[1u8; 2000], 0).unwrap();
        assert_eq!(rx.ingest(0u8, &two_symbols[0], t), Ok(None));
        let other_len = encode(6, &[1u8; 50], 3).unwrap();
        assert_eq!(
            rx.ingest(0u8, &other_len[1], t),
            Err(FecError::InconsistentLength)
        );
    }

    #[test]
    fn an_object_that_never_decodes_is_dropped_after_too_many_symbols() {
        let mut rx = Reassembler::default();
        let t = now();
        let packets = encode(5, &Rng(10).bytes(3000), 0).unwrap();
        // Only one distinct symbol of a K = 3 object, resent forever.
        let mut outcome = Ok(None);
        for _ in 0..200 {
            outcome = rx.ingest(0u8, &packets[0], t);
            if outcome.is_err() {
                break;
            }
        }
        assert_eq!(outcome, Err(FecError::TooManySymbols));
        assert_eq!(rx.pending_objects(), 0);
    }

    #[test]
    fn pending_objects_are_bounded_per_source_and_overall() {
        let limits = Limits {
            max_pending: 6,
            max_pending_per_source: 4,
            ..Limits::default()
        };
        let mut rx = Reassembler::new(limits);
        let t = now();
        // Half of a K = 2 object each: never completes on its own.
        let half = |id: u32| encode(id, &[3u8; 2000], 0).unwrap().remove(0);

        for id in 0..10 {
            rx.ingest(1u8, &half(id), t + Duration::from_millis(id as u64))
                .unwrap();
        }
        assert_eq!(rx.pending_objects(), 4, "per-source cap");
        for id in 0..10 {
            rx.ingest(2u8, &half(id), t + Duration::from_millis(100 + id as u64))
                .unwrap();
        }
        assert_eq!(rx.pending_objects(), 6, "overall cap");

        // The survivors are the newest: finishing object 9 from source 2
        // still works, finishing object 0 from source 1 (evicted) doesn't.
        let rest = |id: u32| encode(id, &[3u8; 2000], 0).unwrap().remove(1);
        let later = t + Duration::from_secs(1);
        assert!(rx.ingest(2u8, &rest(9), later).unwrap().is_some());
        assert!(rx.ingest(1u8, &rest(0), later).unwrap().is_none());
    }

    #[test]
    fn stale_partial_objects_expire() {
        let limits = Limits {
            pending_ttl: Duration::from_secs(10),
            ..Limits::default()
        };
        let mut rx = Reassembler::new(limits);
        let t = now();
        let packets = encode(1, &[4u8; 2000], 0).unwrap();
        rx.ingest(0u8, &packets[0], t).unwrap();
        // A different object arriving much later sweeps the stale one out...
        let other = encode(2, &[4u8; 2000], 0).unwrap();
        rx.ingest(0u8, &other[0], t + Duration::from_secs(11))
            .unwrap();
        assert_eq!(rx.pending_objects(), 1);
        // ...so the stale object's second half no longer completes it.
        let late = rx.ingest(0u8, &packets[1], t + Duration::from_secs(12));
        assert_eq!(late, Ok(None));
    }

    #[test]
    fn completed_objects_are_forgotten_eventually() {
        let limits = Limits {
            max_completed: 2,
            ..Limits::default()
        };
        let mut rx = Reassembler::new(limits);
        let t = now();
        let object = |id: u32| encode(id, &[id as u8 + 1; 64], 2).unwrap();
        for id in 0..3 {
            assert!(rx.ingest(0u8, &object(id)[0], t).unwrap().is_some());
        }
        // Object 0 fell out of the 2-entry completed set; 1 and 2 didn't.
        assert!(rx.ingest(0u8, &object(0)[1], t).unwrap().is_some());
        assert!(rx.ingest(0u8, &object(2)[1], t).unwrap().is_none());
    }

    /// Pins the wire layout described in the module docs, and that the code
    /// is systematic: the first K symbols are the object itself.
    #[test]
    fn packets_have_the_documented_layout() {
        let object = Rng(11).bytes(2500);
        let packets = encode(0xDEAD_BEEF, &object, 7).unwrap();
        assert_eq!(packets.len(), 7);
        let symbol_size = symbol_size_for(object.len());
        for (i, packet) in packets.iter().enumerate() {
            assert_eq!(packet.len(), HEADER_LEN + symbol_size);
            assert_eq!(packet[0..4], 0xDEAD_BEEFu32.to_be_bytes());
            assert_eq!(packet[4..8], 2500u32.to_be_bytes());
            // Source symbols are ids 0..K, repair symbols carry on from K.
            assert_eq!(packet[8..12], (i as u32).to_be_bytes());
        }
        let k = source_symbols_for(object.len()) as usize;
        let mut joined: Vec<u8> = packets[..k]
            .iter()
            .flat_map(|p| p[HEADER_LEN..].to_vec())
            .collect();
        assert!(
            joined[object.len()..].iter().all(|&b| b == 0),
            "zero padded"
        );
        joined.truncate(object.len());
        assert_eq!(joined, object);
    }

    #[test]
    fn encode_never_emits_fewer_than_k_packets() {
        for len in [1, 1500, 9000] {
            let k = source_symbols_for(len);
            for asked in [0, 1, k.saturating_sub(1)] {
                let packets = encode(1, &vec![9u8; len], asked).unwrap();
                assert_eq!(packets.len() as u32, k, "len {len}, asked {asked}");
            }
        }
    }

    /// Sized for whatever loss it's told to expect, the code delivers —
    /// not just at the 70% design point.
    #[test]
    fn survives_heavy_loss_at_every_design_point() {
        let mut rng = Rng(12);
        for loss in [0.3, 0.5, 0.7, 0.8, 0.9] {
            let trials = 300;
            let mut failures = 0;
            for trial in 0..trials {
                let len = 40 + (trial * 53) % 3000;
                let object = rng.bytes(len);
                let n = packets_for(len, loss, 1e-4);
                let mut packets = encode(trial as u32, &object, n).unwrap();
                packets.retain(|_| rng.unit() >= loss);
                rng.shuffle(&mut packets);
                match reassemble(&packets) {
                    Some(rebuilt) => assert_eq!(rebuilt, object),
                    None => failures += 1,
                }
            }
            assert!(failures <= 1, "loss {loss}: {failures} of {trials} lost");
        }
    }

    #[test]
    fn largest_object_survives_70_percent_loss() {
        let mut rng = Rng(13);
        let object = rng.bytes(MAX_OBJECT_LEN);
        let n = packets_for(MAX_OBJECT_LEN, 0.7, 1e-4);
        for trial in 0..10 {
            let mut packets = encode(trial, &object, n).unwrap();
            packets.retain(|_| rng.unit() >= 0.7);
            rng.shuffle(&mut packets);
            assert_eq!(reassemble(&packets).as_deref(), Some(&object[..]));
        }
    }

    #[test]
    fn completed_objects_expire_after_their_ttl() {
        let limits = Limits {
            completed_ttl: Duration::from_secs(10),
            ..Limits::default()
        };
        let mut rx = Reassembler::new(limits);
        let t = now();
        let a = encode(1, b"first object", 3).unwrap();
        let b = encode(2, b"second object", 3).unwrap();
        assert!(rx.ingest(0u8, &a[0], t).unwrap().is_some());
        // A straggler inside the TTL is ignored...
        assert!(
            rx.ingest(0u8, &a[1], t + Duration::from_secs(5))
                .unwrap()
                .is_none()
        );
        // ...but once another completion sweeps it out, the id is free again.
        let later = t + Duration::from_secs(11);
        assert!(rx.ingest(0u8, &b[0], later).unwrap().is_some());
        assert!(rx.ingest(0u8, &a[2], later).unwrap().is_some());
    }

    /// Regression: a one-in-a-million target (what the client uses for
    /// messages carrying a PQ inject) costs a few more packets than
    /// one-in-ten-thousand — not several times as many, which is what a
    /// model that flattened out at 1e-6 produced.
    #[test]
    fn stricter_targets_cost_a_few_more_packets_not_many() {
        for len in [100, 1300, 4000, 20_000] {
            let normal = packets_for(len, 0.7, 1e-4);
            let strict = packets_for(len, 0.7, 1e-6);
            assert!(strict > normal, "len {len}");
            assert!(strict < 2 * normal, "len {len}: {strict} vs {normal}");
        }
        // The model keeps improving past RFC 6330's last quoted bound.
        let deep = failure_probability(1, 80, 0.3);
        assert!(deep > 0.0 && deep < 1e-9, "{deep}");
    }

    #[test]
    fn failure_model_only_improves_with_more_packets() {
        for k in [1, 2, 8, 64] {
            let mut last = f64::INFINITY;
            for n in k..k + 120 {
                let p = failure_probability(k, n, 0.3);
                // Up to float rounding: right next to certain failure the
                // values are 1 - 1e-14-ish and differ only in the last bits.
                assert!(p <= last + 1e-12, "k {k}, n {n}: {p} > {last}");
                assert!((0.0..=1.0).contains(&p), "k {k}, n {n}: p = {p:e}");
                last = p;
            }
        }
        // Fewer received symbols than K can never decode.
        assert_eq!(failure_probability(4, 3, 1.0), 1.0);
    }

    /// A receiver that's offline gets the relay's whole queue at once —
    /// many objects' symbols back to back, plus later duplicates. Every
    /// object must come out exactly once.
    #[test]
    fn many_objects_streamed_back_to_back_each_arrive_once() {
        let mut rng = Rng(14);
        let mut rx = Reassembler::default();
        let t = now();
        let objects: Vec<Vec<u8>> = (0..20).map(|i| rng.bytes(100 + i * 150)).collect();
        let mut stream: Vec<Vec<u8>> = Vec::new();
        for (id, object) in objects.iter().enumerate() {
            let n = packets_for(object.len(), 0.7, 1e-4);
            stream.extend(encode(id as u32, object, n).unwrap());
        }
        let replay = stream.clone();
        stream.extend(replay);
        let mut got = HashMap::new();
        for packet in &stream {
            if let Some(object) = rx.ingest(7u8, packet, t).unwrap() {
                let id = u32::from_be_bytes(packet[..4].try_into().unwrap());
                assert!(got.insert(id, object).is_none(), "object {id} twice");
            }
        }
        assert_eq!(got.len(), objects.len());
        for (id, object) in objects.iter().enumerate() {
            assert_eq!(&got[&(id as u32)], object);
        }
        assert_eq!(rx.pending_objects(), 0);
    }
}
