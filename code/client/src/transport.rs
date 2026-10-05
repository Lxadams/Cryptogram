//! FEC transport: carries E2E messages as bursts of RaptorQ symbols (see the
//! `fec` crate) so they survive heavy packet loss with no ACKs or resends.
//!
//! Send side (`Client::create_fec_packets`): the message's ratchet-encrypted
//! chunks (0x01, each padded to a fixed size) — plus, when due, the PQ inject
//! (0x05) that follows them — are bundled into one FEC object, encoded into
//! enough symbols to survive `FEC_DESIGN_LOSS`, and every symbol is sealed
//! end to end before the usual link encryption:
//!
//!   [0x07 | 16-byte sender token | 24-byte nonce | XChaCha20-Poly1305(symbol)]
//!
//! The seal key is derived from the pair's session root key, so only the two
//! clients can open a symbol. The relay forwards opaque packets: it can't
//! tell which ones belong to the same message, let alone rebuild one.
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
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Interval, MissedTickBehavior};

/// Packet loss each burst is sized to survive: the jammed side's link (the
/// sender's uplink or the receiver's downlink) dropping 70% of packets.
const FEC_DESIGN_LOSS: f64 = 0.7;
/// Chance a chat message may fail to arrive at `FEC_DESIGN_LOSS`: 1 in
/// 10,000 (27 packets for a short message).
const MESSAGE_MAX_FAILURE: f64 = 1e-4;
/// Stricter target for a message carrying a PQ inject: losing one of those
/// desyncs the ratchet for good, not just one message.
const PQ_MESSAGE_MAX_FAILURE: f64 = 1e-6;
/// Gap between consecutive packets of a burst (see `send_burst`).
const FEC_PACKET_SPACING: Duration = Duration::from_millis(10);

/// How long, and how many, messages are parked per peer waiting for a PQ
/// inject they were encrypted after.
const DEFER_TTL: Duration = Duration::from_secs(60);
const MAX_DEFERRED_PER_PEER: usize = 32;

const NONCE_LEN: usize = 24;

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
    aad[0] = 0x07;
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

/// Bundle a message's ratchet-encrypted chunks (and the PQ inject that
/// follows them, if any) into FEC object `object_id`, encode it for
/// `FEC_DESIGN_LOSS`, and seal every symbol for `target`. Returns 0x07 inner
/// payloads, not yet link-encrypted.
pub(crate) fn encode_message(
    root_key: &[u8; 32],
    sender: &RoutingToken,
    target: &RoutingToken,
    object_id: u32,
    chunks: &[Vec<u8>],
    pq_inject: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>> {
    let mut parts: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    parts.extend(pq_inject);
    let max_failure = match pq_inject {
        Some(_) => PQ_MESSAGE_MAX_FAILURE,
        None => MESSAGE_MAX_FAILURE,
    };
    let object = bundle(&parts);
    let packets = fec::packets_for(object.len(), FEC_DESIGN_LOSS, max_failure);
    let symbols = fec::encode(object_id, &object, packets)?;
    Ok(seal_symbols(root_key, sender, target, &symbols))
}

/// Seal FEC symbols end to end: one 0x07 inner payload per symbol.
fn seal_symbols(
    root_key: &[u8; 32],
    sender: &RoutingToken,
    target: &RoutingToken,
    symbols: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let cipher = seal_cipher(root_key);
    let aad = seal_aad(sender, target);
    symbols
        .iter()
        .map(|symbol| {
            let mut nonce = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce);
            let sealed = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: symbol,
                        aad: &aad,
                    },
                )
                .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers");
            let mut inner = Vec::with_capacity(1 + 16 + NONCE_LEN + sealed.len());
            inner.push(0x07);
            inner.extend_from_slice(sender);
            inner.extend_from_slice(&nonce);
            inner.extend_from_slice(&sealed);
            inner
        })
        .collect()
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

/// Ticks every `FEC_PACKET_SPACING`. After a stall (a busy runtime, a slow
/// disk write) it carries on at the normal spacing instead of firing the
/// missed ticks back to back, which would send a run of packets unpaced.
fn pacer() -> Interval {
    let mut ticker = tokio::time::interval(FEC_PACKET_SPACING);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker
}

/// Send each packet on its own `ticker` tick. A failed send is skipped
/// rather than aborting the rest: a lost packet is exactly what the
/// redundancy is for.
async fn send_paced(
    ticker: &mut Interval,
    socket: &UdpSocket,
    addr: SocketAddr,
    packets: &[Vec<u8>],
) {
    for packet in packets {
        ticker.tick().await; // the first tick after idling is immediate
        let _ = socket.send_to(packet, addr).await;
    }
}

/// Transmit one message's FEC packets at a steady `FEC_PACKET_SPACING`, so
/// a short jamming spike can only take a few of them — the code tolerates
/// losing most of a burst, just not all of it at once. Fails, abandoning
/// the burst, only if its first packet can't be sent: then nothing is
/// getting out. Front ends use `BurstSender`, which also keeps bursts in
/// order.
pub async fn send_burst(
    socket: &UdpSocket,
    addr: SocketAddr,
    packets: &[Vec<u8>],
) -> io::Result<()> {
    let Some((first, rest)) = packets.split_first() else {
        return Ok(());
    };
    let mut ticker = pacer();
    ticker.tick().await;
    socket.send_to(first, addr).await?;
    send_paced(&mut ticker, socket, addr, rest).await;
    Ok(())
}

type BurstJob = (Vec<Vec<u8>>, oneshot::Sender<io::Result<()>>);

/// Sends bursts (see `send_burst`) one at a time, in the order they were
/// queued, on a task of its own: one message's burst never interleaves with
/// the next one's, so the receiver finishes rebuilding them in send order,
/// and the spacing holds across back-to-back bursts too. Cheap to clone;
/// the task ends once every clone is dropped and the queue has drained.
#[derive(Clone)]
pub struct BurstSender(mpsc::UnboundedSender<BurstJob>);

impl BurstSender {
    /// Start the sending task for `socket` → `addr`. Must be called from
    /// within a Tokio runtime.
    pub fn spawn(socket: Arc<UdpSocket>, addr: SocketAddr) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<BurstJob>();
        tokio::spawn(async move {
            let mut ticker = pacer();
            while let Some((packets, first_sent)) = rx.recv().await {
                let Some((first, rest)) = packets.split_first() else {
                    let _ = first_sent.send(Ok(()));
                    continue;
                };
                ticker.tick().await;
                let result = socket.send_to(first, addr).await.map(drop);
                let failed = result.is_err();
                let _ = first_sent.send(result);
                if !failed {
                    send_paced(&mut ticker, &socket, addr, rest).await;
                }
            }
        });
        Self(tx)
    }

    /// Queue one message's burst behind any still going out. Resolves once
    /// its first packet has been sent — `Err` if it couldn't be, in which
    /// case none of it leaves this machine — while the rest is paced out in
    /// the background.
    pub async fn send(&self, packets: Vec<Vec<u8>>) -> io::Result<()> {
        let stopped = || io::Error::other("burst sender task has stopped");
        let (tx, rx) = oneshot::channel();
        self.0.send((packets, tx)).map_err(|_| stopped())?;
        rx.await.map_err(|_| stopped())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        Rng, cleanup, connect, connected_pair, inbox_texts, new_client, relay, session,
    };
    use crate::{Client, MAX_MESSAGE_LEN};

    /// Each message's burst, as the relay hands it to the recipient.
    fn bursts(from: &mut Client, to: &Client, count: usize) -> Vec<Vec<Vec<u8>>> {
        (0..count)
            .map(|i| {
                from.create_fec_packets(to.identity.routing_token, format!("m{i}").as_bytes())
                    .unwrap()
                    .iter()
                    .map(|p| relay(p, from))
                    .collect()
            })
            .collect()
    }

    fn deliver(to: &mut Client, burst: &[Vec<u8>]) {
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
    /// drops `FEC_DESIGN_LOSS` of packets. Bursts of three neighbouring
    /// messages are in flight together and shuffled, so later messages
    /// regularly finish decoding before earlier ones.
    fn chat_over_lossy_link(sender: &mut Client, receiver: &mut Client, rng: &mut Rng) {
        let rounds = 40;
        let mut in_flight: Vec<Vec<u8>> = Vec::new();
        let mut sent = Vec::new();
        for i in 0..rounds {
            let text = format!(
                "message {i} to {}",
                hex::encode(receiver.identity.routing_token)
            );
            let burst = sender
                .create_fec_packets(receiver.identity.routing_token, text.as_bytes())
                .unwrap();
            in_flight.extend(burst.iter().map(|p| relay(p, sender)));
            sent.push(text);
            if i % 3 == 2 || i == rounds - 1 {
                in_flight.retain(|_| rng.unit() >= FEC_DESIGN_LOSS);
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

    /// The end goal: both directions chatting through a link that drops
    /// 70% of packets and reorders what's left — including every 5th
    /// message's PQ ratchet injection — with every message delivered and
    /// both ratchets still in step.
    #[test]
    fn conversation_survives_70_percent_loss_and_reordering() {
        let (mut alice, mut bob) = connected_pair();
        let mut rng = Rng(70);
        chat_over_lossy_link(&mut alice, &mut bob, &mut rng);
        chat_over_lossy_link(&mut bob, &mut alice, &mut rng);
        cleanup(&[&alice, &bob]);
    }

    /// The specific race bundling alone doesn't fix: message 5 is encrypted
    /// *after* the PQ inject carried with message 4, and its burst finishes
    /// decoding first. It must be parked and delivered once the inject
    /// lands, not dropped.
    #[test]
    fn message_overtaking_its_pq_inject_is_recovered() {
        let (mut alice, mut bob) = connected_pair();
        let bursts = bursts(&mut alice, &bob, 6);

        for i in [0, 1, 2, 3, 5] {
            deliver(&mut bob, &bursts[i]);
        }
        assert_eq!(inbox_texts(&mut bob), ["m0", "m1", "m2", "m3"]);
        assert_eq!(bob.fec_rx.deferred_count(&alice.identity.routing_token), 1);

        // Message 4 + its PQ inject arrive last: 4 decrypts, the inject
        // lands, and the parked message 5 goes through right after.
        deliver(&mut bob, &bursts[4]);
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
            deliver(&mut bob, &bursts[i]);
        }
        assert_eq!(inbox_texts(&mut bob), ["m0", "m1", "m2", "m3"]);
        assert_eq!(bob.fec_rx.deferred_count(&alice.identity.routing_token), 5);
        assert!(
            session(&bob, &alice)
                .recv_pq_injects
                .pending
                .contains_key(&10)
        );

        deliver(&mut bob, &bursts[4]);
        assert_eq!(inbox_texts(&mut bob), ["m4", "m5", "m6", "m7", "m8", "m9"]);
        deliver(&mut bob, &bursts[10]);
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
            deliver(&mut bob, &bursts[i]);
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

        deliver(&mut bob, &bursts[4]);
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
        let inner = relay(&msgs[0], &alice);
        bob.handle_incoming_packet(&inner).unwrap();
        let root = session(&bob, &alice).root_key;
        for object_id in [100, 101] {
            let burst = encode_message(
                &root,
                &alice_token,
                &bob_token,
                object_id,
                std::slice::from_ref(&inner),
                None,
            );
            deliver(&mut bob, &burst.unwrap());
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
            deliver(&mut bob, &burst);
        }
        assert_eq!(inbox_texts(&mut bob), ["m0", "m1", "m2"]);

        alice.forget_contact(bob.identity.routing_token);
        bob.forget_contact(alice.identity.routing_token);
        connect(&mut alice, &mut bob);
        assert_eq!(session(&alice, &bob).send_count, 0);
        for burst in bursts(&mut alice, &bob, 3) {
            deliver(&mut bob, &burst);
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
        let burst: Vec<Vec<u8>> = alice
            .create_fec_packets(bob.identity.routing_token, secret)
            .unwrap()
            .iter()
            .map(|p| relay(p, &alice))
            .collect();

        for inner in &burst {
            assert_eq!(inner[0], 0x07);
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
        let stranger = Client::new("127.0.0.1:4430".parse().unwrap());
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

        // The genuine burst still works afterwards.
        for inner in &burst {
            bob.handle_incoming_packet(inner).unwrap();
        }
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
                .create_fec_packets(bob.identity.routing_token, &huge)
                .is_err()
        );
        assert_eq!(session(&alice, &bob).send_count, before);
        cleanup(&[&alice, &bob]);
    }

    #[tokio::test]
    async fn send_burst_delivers_every_packet_in_order() {
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packets: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 100]).collect();
        send_burst(&tx, rx.local_addr().unwrap(), &packets)
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        for expected in &packets {
            let (len, _) = rx.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], &expected[..]);
        }
    }

    /// The pacing is real: a burst takes about (packets - 1) spacings, so a
    /// short jamming spike can't take the whole thing.
    #[tokio::test]
    async fn send_burst_spreads_packets_out_in_time() {
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packets: Vec<Vec<u8>> = (0..11u8).map(|i| vec![i; 64]).collect();
        let started = Instant::now();
        send_burst(&tx, rx.local_addr().unwrap(), &packets)
            .await
            .unwrap();
        let spread = started.elapsed();
        assert!(
            spread >= FEC_PACKET_SPACING * 9,
            "11 packets went out in {spread:?}"
        );
    }

    /// A symbol only opens for the exact (session key, sender, recipient) it
    /// was sealed for — which also makes FEC traffic immune to the relay
    /// bouncing a client's own packets back at it.
    #[test]
    fn sealed_symbols_are_bound_to_key_sender_and_recipient() {
        let root = [1u8; 32];
        let (a, b, c) = ([0xA; 16], [0xB; 16], [0xC; 16]);
        let message = b"\x01not really a message".to_vec();
        let inner = encode_message(&root, &a, &b, 0, &[message], None).unwrap();
        assert_eq!(&inner[0][..17], [&[0x07][..], &a].concat());
        let sealed = &inner[0][17..];

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

    #[test]
    fn pq_carrying_bursts_get_extra_redundancy() {
        let (root, a, b) = ([3u8; 32], [0xA; 16], [0xB; 16]);
        let message = vec![0x01; 200];
        let pq = vec![0x05; 1193];
        let chunks = std::slice::from_ref(&message);
        let plain = encode_message(&root, &a, &b, 0, chunks, None).unwrap();
        let with_pq = encode_message(&root, &a, &b, 1, chunks, Some(&pq)).unwrap();
        assert_eq!(
            plain.len() as u32,
            fec::packets_for(2 + message.len(), FEC_DESIGN_LOSS, MESSAGE_MAX_FAILURE)
        );
        assert_eq!(
            with_pq.len() as u32,
            fec::packets_for(
                4 + message.len() + pq.len(),
                FEC_DESIGN_LOSS,
                PQ_MESSAGE_MAX_FAILURE
            )
        );
        assert!(with_pq.len() > plain.len());
        // A few packets more than the normal target for the same object,
        // not a multiple of it.
        let normal_for_same_object = fec::packets_for(
            4 + message.len() + pq.len(),
            FEC_DESIGN_LOSS,
            MESSAGE_MAX_FAILURE,
        );
        assert!(with_pq.len() < 2 * normal_for_same_object as usize);

        // And through the client: every 5th message (the one carrying the
        // PQ inject) goes out as a bigger burst; the rest are identical.
        let (mut alice, bob) = connected_pair();
        let sizes: Vec<usize> = (0..10)
            .map(|_| {
                alice
                    .create_fec_packets(bob.identity.routing_token, b"same length")
                    .unwrap()
                    .len()
            })
            .collect();
        for (i, &n) in sizes.iter().enumerate() {
            if i % 5 == 4 {
                assert!(n > sizes[0], "message {i}: {n} vs {}", sizes[0]);
            } else {
                assert_eq!(n, sizes[0], "message {i}");
            }
        }
        cleanup(&[&alice, &bob]);
    }

    /// Every datagram is the same size whatever the message length (chunks
    /// are padded, so every symbol is full-size), and stays inside ~1200
    /// bytes: it crosses real networks unfragmented, well inside the relay's
    /// 2048-byte receive buffer.
    #[test]
    fn every_packet_is_one_fixed_size_datagram() {
        let (mut alice, bob) = connected_pair();
        let mut sizes = Vec::new();
        for len in [1, 100, 1000, 3000, 10_000, MAX_MESSAGE_LEN] {
            let burst = alice
                .create_fec_packets(bob.identity.routing_token, &vec![b'x'; len])
                .unwrap();
            sizes.extend(burst.iter().map(Vec::len));
        }
        assert!(sizes.iter().all(|&size| size == sizes[0]), "{sizes:?}");
        assert!(sizes[0] <= 1200, "{}-byte datagrams", sizes[0]);
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

    /// Bursts queued back to back go out whole and in order, never
    /// interleaved, with the spacing kept across the boundary.
    #[tokio::test]
    async fn burst_sender_keeps_bursts_in_order() {
        let tx = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = BurstSender::spawn(tx, rx.local_addr().unwrap());
        let first: Vec<Vec<u8>> = (0..5u8).map(|i| vec![1, i]).collect();
        let second: Vec<Vec<u8>> = (0..5u8).map(|i| vec![2, i]).collect();
        let started = Instant::now();
        let (a, b) = tokio::join!(sender.send(first.clone()), sender.send(second.clone()));
        a.unwrap();
        b.unwrap();
        let mut buf = [0u8; 16];
        for expected in first.iter().chain(&second) {
            let (len, _) = rx.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], &expected[..]);
        }
        assert!(started.elapsed() >= FEC_PACKET_SPACING * 9);
    }

    /// If the first packet can't leave this machine, the caller is told.
    #[tokio::test]
    async fn burst_sender_reports_a_burst_that_cannot_be_sent() {
        let tx = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // An IPv6 destination from an IPv4 socket: every send fails.
        let sender = BurstSender::spawn(tx, "[::1]:9".parse().unwrap());
        assert!(sender.send(vec![vec![0u8; 8]; 3]).await.is_err());
        assert!(sender.send(Vec::new()).await.is_ok(), "task still running");
    }

    /// A sealed object may only carry what `create_fec_packets` bundles — a
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
        let carols_msg = relay(&carols_msgs[0], &carol);
        let alices_kx = relay(&alice.create_kx_request(bob_token), &alice);
        let nested = encode_message(&root_before, &alice_token, &bob_token, 0, &[vec![1]], None)
            .unwrap()
            .remove(0);
        let object = bundle(&[&carols_msg, &alices_kx, &nested]);
        let symbols = fec::encode(1, &object, 0).unwrap();
        for inner in seal_symbols(&root_before, &alice_token, &bob_token, &symbols) {
            assert_eq!(bob.handle_incoming_packet(&inner).unwrap(), None);
        }
        assert!(bob.drain_inbox().is_empty());
        assert_eq!(bob.fec_rx.deferred_count(&carol.identity.routing_token), 0);
        assert_eq!(session(&bob, &alice).root_key, root_before, "not re-keyed");
        cleanup(&[&alice, &bob, &carol]);
    }

    #[test]
    fn malformed_fec_payloads_are_dropped_and_the_session_carries_on() {
        let (mut alice, mut bob) = connected_pair();
        let (alice_token, bob_token) = (alice.identity.routing_token, bob.identity.routing_token);
        let root = session(&bob, &alice).root_key;

        // Too short to hold a sender token at all.
        assert!(bob.handle_incoming_packet(&[0x07, 1, 2, 3]).is_err());
        // A known sender with nothing sealed after the token.
        let mut empty = vec![0x07];
        empty.extend_from_slice(&alice_token);
        assert_eq!(bob.handle_incoming_packet(&empty).unwrap(), None);
        // Validly sealed, but not a well-formed bundle inside.
        let symbols = fec::encode(9, &[0xFF, 0xFF, 1, 2], 0).unwrap();
        for inner in seal_symbols(&root, &alice_token, &bob_token, &symbols) {
            assert_eq!(bob.handle_incoming_packet(&inner).unwrap(), None);
        }
        // Validly sealed garbage that isn't even an FEC packet.
        for inner in seal_symbols(&root, &alice_token, &bob_token, &[vec![0u8; 5]]) {
            assert_eq!(bob.handle_incoming_packet(&inner).unwrap(), None);
        }
        assert!(bob.drain_inbox().is_empty());

        for p in alice.create_fec_packets(bob_token, b"still works").unwrap() {
            bob.handle_incoming_packet(&relay(&p, &alice)).unwrap();
        }
        assert_eq!(inbox_texts(&mut bob), ["still works"]);
        cleanup(&[&alice, &bob]);
    }

    /// A relay (or network) that duplicates packets mustn't duplicate
    /// messages.
    #[test]
    fn duplicated_bursts_deliver_once() {
        let (mut alice, mut bob) = connected_pair();
        let burst: Vec<Vec<u8>> = alice
            .create_fec_packets(bob.identity.routing_token, b"once only")
            .unwrap()
            .iter()
            .map(|p| relay(p, &alice))
            .collect();
        for _ in 0..3 {
            for inner in &burst {
                bob.handle_incoming_packet(inner).unwrap();
            }
        }
        assert_eq!(inbox_texts(&mut bob), ["once only"]);
        cleanup(&[&alice, &bob]);
    }

    /// The old one-datagram path still works alongside the new one, in the
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
                    bob.handle_incoming_packet(&relay(packet, &alice)).unwrap();
                }
            } else {
                for p in alice
                    .create_fec_packets(bob_token, text.as_bytes())
                    .unwrap()
                {
                    bob.handle_incoming_packet(&relay(&p, &alice)).unwrap();
                }
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

    /// The pass rate: 1,000 messages through a link dropping 70% of
    /// packets, neighbouring bursts shuffled together. Sized for 1-in-10,000
    /// loss per message (1-in-a-million for the 200 carrying PQ injects), so
    /// all 1,000 are expected; at most one is tolerated.
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
                .create_fec_packets(bob_token, format!("msg {i}").as_bytes())
                .unwrap();
            sent_packets += burst.len();
            in_flight.extend(burst.iter().map(|p| relay(p, &alice)));
            if i % 4 == 3 || i == total - 1 {
                in_flight.retain(|_| rng.unit() >= FEC_DESIGN_LOSS);
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
