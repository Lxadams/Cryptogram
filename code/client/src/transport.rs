//! FEC transport: everything a client sends a contact travels as a RaptorQ
//! object (see the `fec` crate), so it survives heavy packet loss. Each
//! object goes out as however many symbols the link needs (see `link`),
//! and the recipient rebuilds it from any `K` (or a few more) of them.
//!
//! Chat (`Client::create_message`): the message's ratchet-encrypted chunks
//! (0x01, each padded to a fixed size), plus the PQ inject (0x05) that
//! follows them when one is due, are bundled into one object, and every
//! symbol is sealed end to end:
//!
//!   [0x07 | 16-byte sender token | 24-byte nonce | XChaCha20-Poly1305(symbol)]
//!
//! The seal key is derived from the pair's session root key, so only the two
//! clients can open a symbol. The relay forwards opaque packets: it can't
//! tell which ones belong to the same message, let alone rebuild one.
//!
//! Contact requests (KeyExchange 0x02, SessionEstablish 0x04) come before
//! there's a session, so there's no seal key yet. Their symbols travel
//! plain, and the payloads inside are signed:
//!
//!   [0x08 | 16-byte sender token | symbol]
//!
//! Bundling the PQ inject with its message is what keeps the ratchet in step
//! under loss: the two arrive together or not at all, and in order. A later
//! message that overtakes the bundle (its own object finished decoding
//! first) is parked in `FecReceiver` and retried once the inject lands; the
//! inject itself names the chain position it applies at, so it's mixed in
//! at exactly that point however early or late it arrives. Only sealed
//! messages are parked: the seal proves the sender, so strangers can't fill
//! the queue.

use crate::{HKDF_SALT, RoutingToken};
use anyhow::Result;
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::time::{Duration, Instant};

/// Chance a chat message may fail to decode even once the recipient has
/// all the symbols the relay accepted: 1 in 10,000.
const MESSAGE_MAX_FAILURE: f64 = 1e-4;
/// Stricter target for a message carrying a PQ inject: losing one of those
/// desyncs the ratchet for good, not just one message.
const PQ_MESSAGE_MAX_FAILURE: f64 = 1e-6;
/// Contact requests: losing a SessionEstablish leaves the pair stuck until
/// one of them adds the other again, so these get the strict target too.
const CONTROL_MAX_FAILURE: f64 = 1e-6;

/// How long, and how many, messages are parked per peer waiting for a PQ
/// inject they were encrypted after.
const DEFER_TTL: Duration = Duration::from_secs(60);
const MAX_DEFERRED_PER_PEER: usize = 32;

const NONCE_LEN: usize = 24;

/// Inner type of a sealed chat symbol.
pub(crate) const SEALED_SYMBOL: u8 = 0x07;
/// Inner type of a plain contact-request symbol.
pub(crate) const CONTROL_SYMBOL: u8 = 0x08;

fn seal_cipher(root_key: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), root_key)
        .expand(b"fec-symbol-seal", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    XChaCha20Poly1305::new(Key::from_slice(&key))
}

/// Binds a sealed symbol to its sender and recipient, so the relay can't
/// relabel or redirect it.
fn seal_aad(sender: &RoutingToken, target: &RoutingToken) -> [u8; 33] {
    let mut aad = [0u8; 33];
    aad[0] = SEALED_SYMBOL;
    aad[1..17].copy_from_slice(sender);
    aad[17..].copy_from_slice(target);
    aad
}

/// Length-prefix each payload (2-byte big-endian length) into one FEC object.
fn bundle(parts: &[&[u8]]) -> Vec<u8> {
    let mut object = Vec::with_capacity(parts.iter().map(|p| 2 + p.len()).sum());
    for part in parts {
        object.extend_from_slice(&(part.len() as u16).to_be_bytes());
        object.extend_from_slice(part);
    }
    object
}

/// Inverse of `bundle`; `None` if the object isn't a well-formed bundle.
pub(crate) fn unbundle(mut object: &[u8]) -> Option<Vec<&[u8]>> {
    let mut parts = Vec::new();
    while !object.is_empty() {
        let len = u16::from_be_bytes(object.get(..2)?.try_into().ok()?) as usize;
        parts.push(object.get(2..2 + len)?);
        object = &object[2 + len..];
    }
    Some(parts)
}

/// How an object's symbols are wrapped for the relay.
enum Envelope {
    /// Chat: sealed under the pair's session (0x07).
    Sealed {
        sender: RoutingToken,
        cipher: XChaCha20Poly1305,
        aad: [u8; 33],
    },
    /// Contact requests: no session yet (0x08).
    Plain { sender: RoutingToken },
}

impl Envelope {
    fn wrap(&self, symbol: &[u8]) -> Vec<u8> {
        match self {
            Envelope::Sealed {
                sender,
                cipher,
                aad,
            } => seal_symbol(cipher, aad, sender, symbol),
            Envelope::Plain { sender } => {
                let mut inner = Vec::with_capacity(1 + 16 + symbol.len());
                inner.push(CONTROL_SYMBOL);
                inner.extend_from_slice(sender);
                inner.extend_from_slice(symbol);
                inner
            }
        }
    }
}

/// One object on its way to a contact: a message, or a contact request.
/// It hands out a fresh symbol each time it's asked (`next_payload`), as
/// many as it takes. The link sends a first round sized for the loss it
/// measures and tops up any shortfall, until the relay holds `needed` of
/// them.
pub struct Outgoing {
    target: RoutingToken,
    /// Type of the first payload bundled inside (0x01, 0x02 or 0x04).
    kind: u8,
    encoder: fec::ObjectEncoder,
    envelope: Envelope,
    next_index: u32,
    object_len: usize,
    max_failure: f64,
}

impl fmt::Debug for Outgoing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outgoing")
            .field("kind", &self.kind)
            .field("needed", &self.needed())
            .field("sent", &self.next_index)
            .finish_non_exhaustive()
    }
}

impl Outgoing {
    fn new(
        target: RoutingToken,
        object_id: u32,
        parts: &[&[u8]],
        envelope: Envelope,
        max_failure: f64,
    ) -> Result<Self> {
        let object = bundle(parts);
        Ok(Self {
            target,
            kind: parts.first().and_then(|p| p.first()).copied().unwrap_or(0),
            encoder: fec::ObjectEncoder::new(object_id, &object)?,
            envelope,
            next_index: 0,
            object_len: object.len(),
            max_failure,
        })
    }

    /// Whose routing token the relay should forward this to.
    pub fn target(&self) -> RoutingToken {
        self.target
    }

    /// How many distinct symbols the recipient needs for this to decode
    /// with the target probability.
    pub fn needed(&self) -> u32 {
        fec::symbols_needed(self.object_len, self.max_failure)
    }

    /// The next symbol, ready to forward (each one different), or `None`
    /// once `fec::MAX_PACKETS_PER_OBJECT` have been handed out.
    pub fn next_payload(&mut self) -> Option<Vec<u8>> {
        let symbol = self.encoder.packet(self.next_index).ok()?;
        self.next_index += 1;
        Some(self.envelope.wrap(&symbol))
    }

    /// Type of the payload inside (0x01 chat, 0x02 KeyExchange, 0x04
    /// SessionEstablish).
    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// The next `n` symbols.
    #[cfg(test)]
    pub(crate) fn take(&mut self, n: u32) -> Vec<Vec<u8>> {
        (0..n).filter_map(|_| self.next_payload()).collect()
    }

    /// Enough symbols, sent once with no feedback, that the object still
    /// decodes with its target probability after losing `loss` of them:
    /// what a sender that never hears back would have to send.
    #[cfg(test)]
    pub(crate) fn burst(&mut self, loss: f64) -> Vec<Vec<u8>> {
        self.take(fec::packets_for(self.object_len, loss, self.max_failure))
    }
}

/// Bundle a message's ratchet-encrypted chunks (and the PQ inject that
/// follows them, if any) into FEC object `object_id`, sealed for `target`.
pub(crate) fn encode_message(
    root_key: &[u8; 32],
    sender: &RoutingToken,
    target: &RoutingToken,
    object_id: u32,
    chunks: &[Vec<u8>],
    pq_inject: Option<&[u8]>,
) -> Result<Outgoing> {
    let mut parts: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    parts.extend(pq_inject);
    let max_failure = match pq_inject {
        Some(_) => PQ_MESSAGE_MAX_FAILURE,
        None => MESSAGE_MAX_FAILURE,
    };
    let envelope = Envelope::Sealed {
        sender: *sender,
        cipher: seal_cipher(root_key),
        aad: seal_aad(sender, target),
    };
    Outgoing::new(*target, object_id, &parts, envelope, max_failure)
}

/// A contact request (`payload` is a whole 0x02 or 0x04 inner payload) as
/// an FEC object of plain symbols.
pub(crate) fn encode_control(
    sender: &RoutingToken,
    target: &RoutingToken,
    payload: &[u8],
) -> Result<Outgoing> {
    // No session numbering to borrow ids from: a random id, which only
    // has to differ from this sender's other recent requests to `target`.
    let object_id = OsRng.next_u32();
    let envelope = Envelope::Plain { sender: *sender };
    Outgoing::new(
        *target,
        object_id,
        &[payload],
        envelope,
        CONTROL_MAX_FAILURE,
    )
}

/// Seal one FEC symbol end to end: a 0x07 inner payload.
fn seal_symbol(
    cipher: &XChaCha20Poly1305,
    aad: &[u8; 33],
    sender: &RoutingToken,
    symbol: &[u8],
) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: symbol,
                aad: aad.as_slice(),
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers");
    let mut inner = Vec::with_capacity(1 + 16 + NONCE_LEN + sealed.len());
    inner.push(SEALED_SYMBOL);
    inner.extend_from_slice(sender);
    inner.extend_from_slice(&nonce);
    inner.extend_from_slice(&sealed);
    inner
}

/// Open a sealed symbol (`sealed` = nonce || ciphertext, i.e. the 0x07
/// payload after its sender token). `None` unless it was sealed by
/// `sender` for `target` with this session's seal cipher.
fn open_symbol(
    cipher: &XChaCha20Poly1305,
    sender: &RoutingToken,
    target: &RoutingToken,
    sealed: &[u8],
) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &seal_aad(sender, target),
            },
        )
        .ok()
}

/// Receive-side FEC state: per-session seal ciphers, half-rebuilt objects,
/// and chat messages parked because they arrived ahead of the PQ inject
/// they were encrypted after. Transient — never persisted (a restart just
/// drops anything in flight).
#[derive(Default)]
pub struct FecReceiver {
    /// Keyed by (sender, session epoch): object ids are per-session seq
    /// numbers, so a re-established session's ids mustn't hit the previous
    /// session's, still remembered as completed.
    reassembler: fec::Reassembler<(RoutingToken, u64)>,
    /// Contact requests, keyed by the sender they claim. Anyone can send
    /// these, so the reassembler's bounds are what keep a flood in check.
    control: fec::Reassembler<RoutingToken>,
    peers: HashMap<RoutingToken, PeerSeal>,
    next_epoch: u64,
    /// Parked 0x01 payloads per sender, keyed by seq number.
    deferred: HashMap<RoutingToken, BTreeMap<u64, (Instant, Vec<u8>)>>,
}

/// A peer's symbol-opening cipher, derived once per session rather than
/// once per symbol, and the epoch that session's objects reassemble under.
struct PeerSeal {
    root_key: [u8; 32],
    cipher: XChaCha20Poly1305,
    epoch: u64,
}

impl FecReceiver {
    /// Open a sealed symbol from `sender` (see `open_symbol`) under the
    /// session `root_key` belongs to. A session not seen before gets a fresh
    /// cipher and reassembly epoch, and anything still parked from the
    /// sender's previous session is dropped (it can't decrypt any more).
    pub(crate) fn open(
        &mut self,
        root_key: &[u8; 32],
        sender: &RoutingToken,
        target: &RoutingToken,
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        if self
            .peers
            .get(sender)
            .is_none_or(|peer| peer.root_key != *root_key)
        {
            self.next_epoch += 1;
            self.peers.insert(
                *sender,
                PeerSeal {
                    root_key: *root_key,
                    cipher: seal_cipher(root_key),
                    epoch: self.next_epoch,
                },
            );
            self.deferred.remove(sender);
        }
        open_symbol(&self.peers[sender].cipher, sender, target, sealed)
    }

    /// Feed a symbol `open` returned to the reassembler: the rebuilt object
    /// the first time enough of its symbols have arrived.
    pub(crate) fn reassemble(
        &mut self,
        sender: RoutingToken,
        symbol: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, fec::FecError> {
        let epoch = self.peers.get(&sender).map_or(0, |peer| peer.epoch);
        self.reassembler.ingest((sender, epoch), symbol, now)
    }

    /// `reassemble` for a contact request's plain symbol.
    pub(crate) fn reassemble_control(
        &mut self,
        sender: RoutingToken,
        symbol: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, fec::FecError> {
        self.control.ingest(sender, symbol, now)
    }

    /// Park the undecryptable 0x01 message `seq` from `sender` for a later
    /// retry. `parked_at` is when it was first parked: re-parking after a
    /// failed retry keeps it, so a message can't outlive `DEFER_TTL`.
    pub(crate) fn defer(
        &mut self,
        sender: RoutingToken,
        seq: u64,
        payload: Vec<u8>,
        parked_at: Instant,
        now: Instant,
    ) {
        let fresh = |parked: &Instant| now.saturating_duration_since(*parked) < DEFER_TTL;
        if !fresh(&parked_at) {
            return;
        }
        let queue = self.deferred.entry(sender).or_default();
        queue.retain(|_, (parked, _)| fresh(parked));
        queue.entry(seq).or_insert((parked_at, payload));
        // Over the cap, drop the furthest-ahead message: lower seq numbers
        // are the ones the next PQ inject unblocks first.
        if queue.len() > MAX_DEFERRED_PER_PEER {
            queue.pop_last();
        }
    }

    /// Everything still fresh that's parked for `sender`, in seq order, as
    /// (parked_at, payload).
    pub(crate) fn take_deferred(
        &mut self,
        sender: &RoutingToken,
        now: Instant,
    ) -> Vec<(Instant, Vec<u8>)> {
        self.deferred
            .remove(sender)
            .into_iter()
            .flatten()
            .map(|(_, entry)| entry)
            .filter(|(parked, _)| now.saturating_duration_since(*parked) < DEFER_TTL)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn deferred_count(&self, sender: &RoutingToken) -> usize {
        self.deferred.get(sender).map_or(0, BTreeMap::len)
    }

    #[cfg(test)]
    pub(crate) fn pending_objects(&self) -> usize {
        self.reassembler.pending_objects()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        Rng, cleanup, connect, connected_pair, inbox_texts, new_client, session,
    };
    use crate::{Client, MAX_MESSAGE_LEN};

    /// The loss the tests below throw at a link with no feedback, and size
    /// one-shot bursts for: a jammed side losing 70% of packets.
    const TEST_LOSS: f64 = 0.7;

    fn seal_symbols(
        root_key: &[u8; 32],
        sender: &RoutingToken,
        target: &RoutingToken,
        symbols: &[Vec<u8>],
    ) -> Vec<Vec<u8>> {
        let (cipher, aad) = (seal_cipher(root_key), seal_aad(sender, target));
        symbols
            .iter()
            .map(|symbol| seal_symbol(&cipher, &aad, sender, symbol))
            .collect()
    }

    /// Each message's symbols, just enough of them (no loss expected).
    fn bursts(from: &mut Client, to: &Client, count: usize) -> Vec<Vec<Vec<u8>>> {
        (0..count)
            .map(|i| {
                let mut out = from
                    .create_message(to.identity.routing_token, format!("m{i}").as_bytes())
                    .unwrap();
                out.take(out.needed())
            })
            .collect()
    }

    fn deliver_all(to: &mut Client, burst: &[Vec<u8>]) {
        for inner in burst {
            to.handle_incoming_packet(inner).unwrap();
        }
    }

    #[test]
    fn bundle_roundtrip_and_malformed_bundles() {
        let parts: [&[u8]; 3] = [b"first", b"", b"third part"];
        let object = bundle(&parts);
        assert_eq!(unbundle(&object).unwrap(), parts);
        assert!(unbundle(&object[..object.len() - 1]).is_none());
        assert!(unbundle(&[0x00]).is_none());
        assert_eq!(unbundle(&[]).unwrap().len(), 0);
    }

    /// `rounds` messages from `sender` to `receiver` through a link that
    /// drops `TEST_LOSS` of packets, each sent as a one-shot burst sized for
    /// that. Bursts of three neighbouring messages are in flight together
    /// and shuffled, so later messages regularly finish decoding before
    /// earlier ones.
    fn chat_over_lossy_link(sender: &mut Client, receiver: &mut Client, rng: &mut Rng) {
        let rounds = 40;
        let mut in_flight: Vec<Vec<u8>> = Vec::new();
        let mut sent = Vec::new();
        for i in 0..rounds {
            let text = format!(
                "message {i} to {}",
                hex::encode(receiver.identity.routing_token)
            );
            let mut out = sender
                .create_message(receiver.identity.routing_token, text.as_bytes())
                .unwrap();
            in_flight.extend(out.burst(TEST_LOSS));
            sent.push(text);
            if i % 3 == 2 || i == rounds - 1 {
                in_flight.retain(|_| rng.unit() >= TEST_LOSS);
                rng.shuffle(&mut in_flight);
                for inner in in_flight.drain(..) {
                    receiver.handle_incoming_packet(&inner).unwrap();
                }
            }
        }
        let mut got = inbox_texts(receiver);
        got.sort();
        sent.sort();
        assert_eq!(got, sent, "every message delivered exactly once");
        assert_eq!(
            session(sender, receiver).send_chain_key,
            session(receiver, sender).recv_chain_key,
            "ratchets still in step after {} PQ injections",
            rounds / 5
        );
    }

    /// Both directions chatting through a link that drops 70% of packets
    /// and reorders what's left — including every 5th message's PQ ratchet
    /// injection — with every message delivered and both ratchets still in
    /// step.
    #[test]
    fn conversation_survives_70_percent_loss_and_reordering() {
        let (mut alice, mut bob) = connected_pair();
        let mut rng = Rng(70);
        chat_over_lossy_link(&mut alice, &mut bob, &mut rng);
        chat_over_lossy_link(&mut bob, &mut alice, &mut rng);
        cleanup(&[&alice, &bob]);
    }

    /// Contact requests go through FEC too: two people can add each other
    /// over a link losing 70% of packets, both ways.
    #[test]
    fn contacts_connect_over_a_lossy_link() {
        let (mut alice, mut bob) = (new_client(), new_client());
        let mut rng = Rng(8);
        let mut lossy = |to: &mut Client, mut out: Outgoing| -> Option<Outgoing> {
            let mut reply = None;
            for inner in out.burst(TEST_LOSS) {
                if rng.unit() >= TEST_LOSS
                    && let Some(r) = to.handle_incoming_packet(&inner).unwrap()
                {
                    reply = Some(r);
                }
            }
            reply
        };
        let early = alice.add_contact(bob.identity.routing_token, bob.identity.ed25519_public);
        assert!(lossy(&mut bob, early).is_none(), "not added back yet");
        let mut next = Some(alice.identity.routing_token)
            .map(|token| bob.add_contact(token, alice.identity.ed25519_public));
        let mut to_alice = true;
        while let Some(out) = next.take() {
            next = match to_alice {
                true => lossy(&mut alice, out),
                false => lossy(&mut bob, out),
            };
            to_alice = !to_alice;
        }
        assert_eq!(
            session(&alice, &bob).root_key,
            session(&bob, &alice).root_key
        );
        cleanup(&[&alice, &bob]);
    }

    /// The specific race bundling alone doesn't fix: message 5 is encrypted
    /// *after* the PQ inject carried with message 4, and its object finishes
    /// decoding first. It must be parked and delivered once the inject
    /// lands, not dropped.
    #[test]
    fn message_overtaking_its_pq_inject_is_recovered() {
        let (mut alice, mut bob) = connected_pair();
        let bursts = bursts(&mut alice, &bob, 6);

        for i in [0, 1, 2, 3, 5] {
            deliver_all(&mut bob, &bursts[i]);
        }
        assert_eq!(inbox_texts(&mut bob), ["m0", "m1", "m2", "m3"]);
        assert_eq!(bob.fec_rx.deferred_count(&alice.identity.routing_token), 1);

        // Message 4 + its PQ inject arrive last: 4 decrypts, the inject
        // lands, and the parked message 5 goes through right after.
        deliver_all(&mut bob, &bursts[4]);
        assert_eq!(inbox_texts(&mut bob), ["m4", "m5"]);
        assert_eq!(bob.fec_rx.deferred_count(&alice.identity.routing_token), 0);
        assert_eq!(
            session(&alice, &bob).send_chain_key,
            session(&bob, &alice).recv_chain_key
        );
        cleanup(&[&alice, &bob]);
    }

    /// The race the review found: a later PQ inject (message 9's) finishes
    /// decoding before an earlier one (message 4's). Each must land at its
    /// own chain position, not wherever the chain happens to be, or the
    /// session is corrupted for good.
    #[test]
    fn pq_injects_arriving_out_of_order_land_at_their_own_positions() {
        let (mut alice, mut bob) = connected_pair();
        let bursts = bursts(&mut alice, &bob, 11);

        for i in [0, 1, 2, 3, 5, 6, 7, 8, 9] {
            deliver_all(&mut bob, &bursts[i]);
        }
        assert_eq!(inbox_texts(&mut bob), ["m0", "m1", "m2", "m3"]);
        assert_eq!(bob.fec_rx.deferred_count(&alice.identity.routing_token), 5);
        assert!(
            session(&bob, &alice)
                .recv_pq_injects
                .pending
                .contains_key(&10)
        );

        deliver_all(&mut bob, &bursts[4]);
        assert_eq!(inbox_texts(&mut bob), ["m4", "m5", "m6", "m7", "m8", "m9"]);
        deliver_all(&mut bob, &bursts[10]);
        assert_eq!(inbox_texts(&mut bob), ["m10"]);
        assert_eq!(
            session(&alice, &bob).send_chain_key,
            session(&bob, &alice).recv_chain_key
        );
        cleanup(&[&alice, &bob]);
    }

    /// A bare 0x01 is unauthenticated until it decrypts, so one that can't
    /// is never held: forged ones can't push genuine parked messages out.
    #[test]
    fn forged_bare_messages_are_never_parked() {
        let (mut alice, mut bob) = connected_pair();
        let alice_token = alice.identity.routing_token;
        let bursts = bursts(&mut alice, &bob, 6);
        for i in [0, 1, 2, 3, 5] {
            deliver_all(&mut bob, &bursts[i]);
        }
        assert_eq!(bob.fec_rx.deferred_count(&alice_token), 1);

        for seq in 0..2 * MAX_DEFERRED_PER_PEER as u64 {
            let mut forged = vec![0x01];
            forged.extend_from_slice(&alice_token);
            forged.extend_from_slice(&(5 + seq).to_be_bytes());
            forged.extend_from_slice(&[0u8; 24 + 32]);
            bob.handle_incoming_packet(&forged).unwrap();
        }
        assert_eq!(bob.fec_rx.deferred_count(&alice_token), 1);

        deliver_all(&mut bob, &bursts[4]);
        assert_eq!(inbox_texts(&mut bob), ["m0", "m1", "m2", "m3", "m4", "m5"]);
        cleanup(&[&alice, &bob]);
    }

    /// A sealed re-delivery of an already-read message (a straggler, or
    /// the relay replaying it under a new object) can never succeed later,
    /// so it must not sit in the deferred queue.
    #[test]
    fn stale_messages_are_not_parked() {
        let (mut alice, mut bob) = connected_pair();
        let (alice_token, bob_token) = (alice.identity.routing_token, bob.identity.routing_token);
        let (msgs, _) = alice.create_encrypted_packets(bob_token, b"once").unwrap();
        bob.handle_incoming_packet(&msgs[0]).unwrap();
        let root = session(&bob, &alice).root_key;
        for object_id in [100, 101] {
            let mut out = encode_message(
                &root,
                &alice_token,
                &bob_token,
                object_id,
                std::slice::from_ref(&msgs[0]),
                None,
            )
            .unwrap();
            let needed = out.needed();
            deliver_all(&mut bob, &out.take(needed));
        }
        assert_eq!(inbox_texts(&mut bob), ["once"]);
        assert_eq!(bob.fec_rx.deferred_count(&alice_token), 0);
        cleanup(&[&alice, &bob]);
    }

    /// Object ids are per-session seq numbers, so a re-established session
    /// reuses ids the previous one already completed — which must not be
    /// mistaken for stragglers.
    #[test]
    fn reestablished_session_reuses_object_ids_cleanly() {
        let (mut alice, mut bob) = connected_pair();
        for burst in bursts(&mut alice, &bob, 3) {
            deliver_all(&mut bob, &burst);
        }
        assert_eq!(inbox_texts(&mut bob), ["m0", "m1", "m2"]);

        alice.forget_contact(bob.identity.routing_token);
        bob.forget_contact(alice.identity.routing_token);
        connect(&mut alice, &mut bob);
        assert_eq!(session(&alice, &bob).send_count, 0);
        for burst in bursts(&mut alice, &bob, 3) {
            deliver_all(&mut bob, &burst);
        }
        assert_eq!(inbox_texts(&mut bob), ["m0", "m1", "m2"]);
        cleanup(&[&alice, &bob]);
    }

    /// Only the two ends of the session can do anything with a symbol: the
    /// relay sees no plaintext, and a symbol relabelled as coming from
    /// another contact, tampered with, or sent by a stranger goes nowhere.
    #[test]
    fn symbols_are_opaque_and_bound_to_their_sender() {
        let (mut alice, mut bob) = connected_pair();
        // Bob's second contact, so relabelling has a real session to hit.
        let mut carol = new_client();
        connect(&mut carol, &mut bob);

        let secret = b"meet at the north gate";
        let mut out = alice
            .create_message(bob.identity.routing_token, secret)
            .unwrap();
        let burst = out.take(out.needed());

        for inner in &burst {
            assert_eq!(inner[0], SEALED_SYMBOL);
            assert!(!inner.windows(secret.len()).any(|w| w == secret));
            // No E2E message header visible either: just the sender token.
            assert!(
                !inner
                    .windows(16)
                    .skip(17)
                    .any(|w| w == alice.identity.routing_token)
            );
        }

        // Relabelled as Carol's, tampered, or from a stranger: nothing.
        let stranger = Client::new();
        for inner in &burst {
            let mut relabelled = inner.clone();
            relabelled[1..17].copy_from_slice(&carol.identity.routing_token);
            bob.handle_incoming_packet(&relabelled).unwrap();

            let mut tampered = inner.clone();
            *tampered.last_mut().unwrap() ^= 1;
            bob.handle_incoming_packet(&tampered).unwrap();

            let mut foreign = inner.clone();
            foreign[1..17].copy_from_slice(&stranger.identity.routing_token);
            bob.handle_incoming_packet(&foreign).unwrap();
        }
        assert!(bob.drain_inbox().is_empty());
        assert_eq!(bob.fec_rx.pending_objects(), 0);

        // The genuine symbols still work afterwards.
        deliver_all(&mut bob, &burst);
        assert_eq!(inbox_texts(&mut bob), ["meet at the north gate"]);
        cleanup(&[&alice, &bob, &carol]);
    }

    #[test]
    fn oversized_messages_are_refused_before_touching_the_ratchet() {
        let (mut alice, bob) = connected_pair();
        let before = session(&alice, &bob).send_count;
        let huge = vec![b'x'; MAX_MESSAGE_LEN + 1];
        assert!(
            alice
                .create_message(bob.identity.routing_token, &huge)
                .is_err()
        );
        assert_eq!(session(&alice, &bob).send_count, before);
        cleanup(&[&alice, &bob]);
    }

    /// A symbol only opens for the exact (session key, sender, recipient) it
    /// was sealed for — which also makes FEC traffic immune to the relay
    /// bouncing a client's own packets back at it.
    #[test]
    fn sealed_symbols_are_bound_to_key_sender_and_recipient() {
        let root = [1u8; 32];
        let (a, b, c) = ([0xA; 16], [0xB; 16], [0xC; 16]);
        let message = b"\x01not really a message".to_vec();
        let inner = encode_message(&root, &a, &b, 0, &[message], None)
            .unwrap()
            .next_payload()
            .unwrap();
        assert_eq!(&inner[..17], [&[SEALED_SYMBOL][..], &a].concat());
        let sealed = &inner[17..];

        let open = |key: &[u8; 32], sender, target, sealed: &[u8]| {
            open_symbol(&seal_cipher(key), sender, target, sealed)
        };
        let symbol = open(&root, &a, &b, sealed).expect("intended recipient opens it");
        assert_eq!(symbol.len(), fec::HEADER_LEN + fec::symbol_size_for(2 + 21));
        assert!(open(&[2u8; 32], &a, &b, sealed).is_none(), "other key");
        assert!(open(&root, &b, &a, sealed).is_none(), "reflected");
        assert!(open(&root, &c, &b, sealed).is_none(), "relabelled");
        assert!(open(&root, &a, &c, sealed).is_none(), "redirected");
        assert!(open(&root, &a, &b, &sealed[..23]).is_none(), "truncated");
        let mut bad_nonce = sealed.to_vec();
        bad_nonce[0] ^= 1;
        assert!(open(&root, &a, &b, &bad_nonce).is_none(), "tampered");
    }

    /// A message carrying a PQ inject needs one more symbol at the far end
    /// (a 1-in-a-million decode target instead of 1 in 10,000), not a
    /// multiple of what a plain one needs.
    #[test]
    fn pq_carrying_messages_need_one_more_symbol() {
        let (root, a, b) = ([3u8; 32], [0xA; 16], [0xB; 16]);
        let message = vec![0x01; 1089];
        let pq = vec![0x05; 1193];
        let chunks = std::slice::from_ref(&message);
        let plain = encode_message(&root, &a, &b, 0, chunks, None).unwrap();
        let with_pq = encode_message(&root, &a, &b, 1, chunks, Some(&pq)).unwrap();
        assert_eq!(plain.needed(), 2 + 1, "K = 2, plus 1 for 1e-4");
        assert_eq!(with_pq.needed(), 3 + 2, "K = 3, plus 2 for 1e-6");

        // And through the client: every 5th message (the one carrying the
        // PQ inject) needs more; the rest are identical.
        let (mut alice, bob) = connected_pair();
        let needed: Vec<u32> = (0..10)
            .map(|_| {
                alice
                    .create_message(bob.identity.routing_token, b"same length")
                    .unwrap()
                    .needed()
            })
            .collect();
        for (i, &n) in needed.iter().enumerate() {
            if i % 5 == 4 {
                assert!(n > needed[0], "message {i}: {n} vs {}", needed[0]);
            } else {
                assert_eq!(n, needed[0], "message {i}");
            }
        }
        cleanup(&[&alice, &bob]);
    }

    /// Every payload a client forwards is the same size whatever the
    /// message length (chunks are padded, so every symbol is full-size),
    /// contact requests included, and fits in one cell.
    #[test]
    fn every_payload_is_one_fixed_size_and_fits_a_cell() {
        let (mut alice, bob) = connected_pair();
        let mut sizes = Vec::new();
        for len in [1, 100, 1000, 3000, 10_000, MAX_MESSAGE_LEN] {
            let mut out = alice
                .create_message(bob.identity.routing_token, &vec![b'x'; len])
                .unwrap();
            sizes.extend(out.take(out.needed() + 3).iter().map(Vec::len));
        }
        assert!(sizes.iter().all(|&size| size == sizes[0]), "{sizes:?}");
        let mut kx = alice.create_kx_request(bob.identity.routing_token);
        let control: Vec<usize> = kx.take(kx.needed()).iter().map(Vec::len).collect();
        assert!(control.iter().all(|&size| size <= sizes[0]), "{control:?}");
        assert!(
            sizes[0] <= cell::format::MAX_FORWARD_PAYLOAD,
            "{}",
            sizes[0]
        );
        cleanup(&[&alice, &bob]);
    }

    #[test]
    fn deferred_queue_is_bounded_per_peer_ordered_and_expires() {
        let mut rx = FecReceiver::default();
        let t = Instant::now();
        let (peer, other) = ([7u8; 16], [8u8; 16]);
        for seq in (0..40u64).rev() {
            rx.defer(peer, seq, vec![seq as u8], t, t);
        }
        assert_eq!(rx.deferred_count(&peer), MAX_DEFERRED_PER_PEER);
        let taken: Vec<Vec<u8>> = rx
            .take_deferred(&peer, t)
            .into_iter()
            .map(|(_, p)| p)
            .collect();
        // The furthest-ahead were dropped to make room; seq order on the way out.
        let expected: Vec<Vec<u8>> = (0..MAX_DEFERRED_PER_PEER as u8).map(|i| vec![i]).collect();
        assert_eq!(taken, expected);
        assert_eq!(rx.deferred_count(&peer), 0);

        rx.defer(peer, 1, vec![1], t, t);
        rx.defer(other, 2, vec![2], t, t);
        assert!(rx.take_deferred(&peer, t + DEFER_TTL).is_empty(), "expired");
        assert_eq!(
            rx.take_deferred(&other, t),
            [(t, vec![2])],
            "peers independent"
        );

        // Re-parking after a failed retry keeps the original park time, so
        // retries can't keep a message alive past DEFER_TTL.
        let later = t + DEFER_TTL / 2;
        rx.defer(peer, 3, vec![3], t, later);
        let (parked_at, payload) = rx.take_deferred(&peer, later).remove(0);
        rx.defer(peer, 3, payload, parked_at, t + DEFER_TTL);
        assert_eq!(rx.deferred_count(&peer), 0);
    }

    /// A sealed object may only carry what `create_message` bundles — a
    /// message and its PQ inject — on the sealing peer's own behalf. Anything
    /// else inside (another contact's message, a KeyExchange that would
    /// re-key the session, a nested symbol) is ignored.
    #[test]
    fn bundles_only_carry_the_sealing_peers_own_messages() {
        let (alice, mut bob) = connected_pair();
        let mut carol = new_client();
        connect(&mut carol, &mut bob);
        let (alice_token, bob_token) = (alice.identity.routing_token, bob.identity.routing_token);
        let root_before = session(&bob, &alice).root_key;

        let (carols_msgs, _) = carol
            .create_encrypted_packets(bob_token, b"from carol")
            .unwrap();
        let alices_kx = alice.kx_payload(bob_token);
        let nested = encode_message(&root_before, &alice_token, &bob_token, 0, &[vec![1]], None)
            .unwrap()
            .next_payload()
            .unwrap();
        let object = bundle(&[&carols_msgs[0], &alices_kx, &nested]);
        let symbols = fec::encode(1, &object, 0).unwrap();
        for inner in seal_symbols(&root_before, &alice_token, &bob_token, &symbols) {
            assert!(bob.handle_incoming_packet(&inner).unwrap().is_none());
        }
        assert!(bob.drain_inbox().is_empty());
        assert_eq!(bob.fec_rx.deferred_count(&carol.identity.routing_token), 0);
        assert_eq!(session(&bob, &alice).root_key, root_before, "not re-keyed");
        cleanup(&[&alice, &bob, &carol]);
    }

    /// A contact request's object carries one KeyExchange or
    /// SessionEstablish, from the sender its symbols name. Chat inside one,
    /// or a request on someone else's behalf, is ignored.
    #[test]
    fn contact_request_objects_only_carry_the_senders_requests() {
        let (mut alice, mut bob) = connected_pair();
        let carol = new_client();
        let (alice_token, bob_token) = (alice.identity.routing_token, bob.identity.routing_token);
        let (msgs, _) = alice
            .create_encrypted_packets(bob_token, b"smuggled")
            .unwrap();
        let carols_kx = carol.kx_payload(bob_token);
        for payload in [&msgs[0], &carols_kx] {
            let mut out = encode_control(&alice_token, &bob_token, payload).unwrap();
            let needed = out.needed();
            for inner in out.take(needed) {
                assert!(bob.handle_incoming_packet(&inner).unwrap().is_none());
            }
        }
        assert!(bob.drain_inbox().is_empty());
        assert!(bob.connection_requests().is_empty(), "carol's wasn't noted");
        cleanup(&[&alice, &bob]);
    }

    #[test]
    fn malformed_fec_payloads_are_dropped_and_the_session_carries_on() {
        let (mut alice, mut bob) = connected_pair();
        let (alice_token, bob_token) = (alice.identity.routing_token, bob.identity.routing_token);
        let root = session(&bob, &alice).root_key;

        // Too short to hold a sender token at all.
        assert!(bob.handle_incoming_packet(&[0x07, 1, 2, 3]).is_err());
        assert!(bob.handle_incoming_packet(&[0x08, 1, 2, 3]).is_err());
        // A known sender with nothing after the token.
        for kind in [SEALED_SYMBOL, CONTROL_SYMBOL] {
            let mut empty = vec![kind];
            empty.extend_from_slice(&alice_token);
            assert!(bob.handle_incoming_packet(&empty).unwrap().is_none());
        }
        // Validly sealed, but not a well-formed bundle inside.
        let symbols = fec::encode(9, &[0xFF, 0xFF, 1, 2], 0).unwrap();
        for inner in seal_symbols(&root, &alice_token, &bob_token, &symbols) {
            assert!(bob.handle_incoming_packet(&inner).unwrap().is_none());
        }
        // Validly sealed garbage that isn't even an FEC packet.
        for inner in seal_symbols(&root, &alice_token, &bob_token, &[vec![0u8; 5]]) {
            assert!(bob.handle_incoming_packet(&inner).unwrap().is_none());
        }
        assert!(bob.drain_inbox().is_empty());

        let mut out = alice.create_message(bob_token, b"still works").unwrap();
        deliver_all(&mut bob, &out.take(out.needed()));
        assert_eq!(inbox_texts(&mut bob), ["still works"]);
        cleanup(&[&alice, &bob]);
    }

    /// A relay (or network) that duplicates packets mustn't duplicate
    /// messages.
    #[test]
    fn duplicated_symbols_deliver_once() {
        let (mut alice, mut bob) = connected_pair();
        let mut out = alice
            .create_message(bob.identity.routing_token, b"once only")
            .unwrap();
        let burst = out.take(out.needed());
        for _ in 0..3 {
            deliver_all(&mut bob, &burst);
        }
        assert_eq!(inbox_texts(&mut bob), ["once only"]);
        cleanup(&[&alice, &bob]);
    }

    /// Topping up: symbols handed out later than the first round are new
    /// ones, so a recipient who got too few of the first can finish from
    /// the rest.
    #[test]
    fn a_short_first_round_is_completed_by_later_symbols() {
        let (mut alice, mut bob) = connected_pair();
        let mut out = alice
            .create_message(bob.identity.routing_token, b"topped up")
            .unwrap();
        let first = out.take(out.needed());
        // Only one of the first round arrives.
        deliver_all(&mut bob, &first[..1]);
        assert!(bob.drain_inbox().is_empty());
        let more = out.take(out.needed());
        deliver_all(&mut bob, &more);
        assert_eq!(inbox_texts(&mut bob), ["topped up"]);
        cleanup(&[&alice, &bob]);
    }

    /// The old one-datagram path still works alongside the FEC one, in the
    /// same conversation — including a PQ inject sent each way.
    #[test]
    fn single_datagram_and_fec_sends_interoperate() {
        let (mut alice, mut bob) = connected_pair();
        let bob_token = bob.identity.routing_token;
        for i in 0..12 {
            let text = format!("m{i}");
            if i % 2 == 0 {
                let (msgs, pq) = alice
                    .create_encrypted_packets(bob_token, text.as_bytes())
                    .unwrap();
                for packet in msgs.iter().chain(&pq) {
                    bob.handle_incoming_packet(packet).unwrap();
                }
            } else {
                let mut out = alice.create_message(bob_token, text.as_bytes()).unwrap();
                deliver_all(&mut bob, &out.take(out.needed()));
            }
        }
        let expected: Vec<String> = (0..12).map(|i| format!("m{i}")).collect();
        assert_eq!(inbox_texts(&mut bob), expected);
        assert_eq!(
            session(&alice, &bob).send_chain_key,
            session(&bob, &alice).recv_chain_key
        );
        cleanup(&[&alice, &bob]);
    }

    /// The pass rate with no feedback at all: 1,000 messages through a link
    /// dropping 70% of packets, each sent as one burst sized for that,
    /// neighbouring bursts shuffled together. Sized for 1-in-10,000 loss per
    /// message (1-in-a-million for the 200 carrying PQ injects), so all
    /// 1,000 are expected; at most one is tolerated.
    #[test]
    fn delivery_rate_over_1000_messages_at_70_percent_loss() {
        let (mut alice, mut bob) = connected_pair();
        let bob_token = bob.identity.routing_token;
        let mut rng = Rng(1000);
        let total = 1000;
        let (mut sent_packets, mut surviving) = (0, 0);
        let mut in_flight: Vec<Vec<u8>> = Vec::new();
        for i in 0..total {
            let burst = alice
                .create_message(bob_token, format!("msg {i}").as_bytes())
                .unwrap()
                .burst(TEST_LOSS);
            sent_packets += burst.len();
            in_flight.extend(burst);
            if i % 4 == 3 || i == total - 1 {
                in_flight.retain(|_| rng.unit() >= TEST_LOSS);
                surviving += in_flight.len();
                rng.shuffle(&mut in_flight);
                for inner in in_flight.drain(..) {
                    bob.handle_incoming_packet(&inner).unwrap();
                }
            }
        }
        let delivered = bob.drain_inbox().len();
        println!(
            "delivered {delivered}/{total} ({:.2}%) at 70% loss: {sent_packets} packets sent, {surviving} survived ({:.1}% lost)",
            100.0 * delivered as f64 / total as f64,
            100.0 * (sent_packets - surviving) as f64 / sent_packets as f64,
        );
        assert!(delivered >= total - 1, "only {delivered}/{total} delivered");
        assert_eq!(
            session(&alice, &bob).send_chain_key,
            session(&bob, &alice).recv_chain_key,
            "ratchets in step after 200 PQ injections"
        );
        cleanup(&[&alice, &bob]);
    }
}
