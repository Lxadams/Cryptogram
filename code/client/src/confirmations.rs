// Whether the relay has the messages we send.
//
// A message goes out as a burst of FEC symbols, with consecutive packet
// numbers in the link's paced lane. The relay doesn't answer them, so the
// client asks it which it has taken in (`TYPE_RECEIPT_REQUEST`, sent
// `REQUEST_COPIES` times, every `REQUEST_INTERVAL` while anything's
// unconfirmed). The relay's receipt, sent several times too, says packet by
// packet.
//
// A message is sent once the relay has `needed` of its symbols: one more
// than its source symbols, enough for the recipient to rebuild it all but
// certainly (it fails 1 time in 10,000, the rate bursts are sized for). The
// relay then delivers it, resending until the recipient has it. A message
// not confirmed within `CONFIRM_TIMEOUT` has failed: too little of it got
// to the relay, or the link went down first.

use relay_link::{PacketNumber, Receipt, SessionId};
use std::time::{Duration, Instant};

/// Copies of each receipt request: one alone would rarely get through heavy
/// loss.
pub const REQUEST_COPIES: usize = 3;
/// How often to ask while anything is unconfirmed.
pub const REQUEST_INTERVAL: Duration = Duration::from_secs(2);
/// How long after a burst's last packet should have gone out to first ask.
const FIRST_REQUEST_AFTER: Duration = Duration::from_millis(500);
/// How long a message has to be confirmed. At 70% loss each way, one round
/// of requests gets an answer about half the time, so 15 rounds almost
/// always do.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);
/// Most messages tracked at once. Past this, the oldest is given up on.
const MAX_UNCONFIRMED: usize = 256;

/// A message we sent that the relay hasn't confirmed yet.
#[derive(Debug, Clone)]
pub struct Unconfirmed {
    /// The link it went out on: a receipt from any other says nothing
    /// about it.
    pub session: SessionId,
    /// Its first packet's number, in the paced lane.
    pub first: PacketNumber,
    pub packets: u64,
    /// How many of its packets the relay needs.
    pub needed: u64,
    pub sent_at: Instant,
    /// Its row in the chat history, if there is one.
    pub history_id: Option<i64>,
    /// The start of its text, for the CLI to say which message it means.
    pub preview: String,
}

#[derive(Default)]
pub struct Confirmations {
    pub(crate) pending: Vec<Unconfirmed>,
    /// When to next ask the relay, while anything's pending.
    pub(crate) next_request: Option<Instant>,
}

impl Confirmations {
    /// Track `message`, whose burst takes `burst_time` to go out. Returns
    /// the oldest one, given up on, if there are now too many.
    pub fn track(&mut self, message: Unconfirmed, burst_time: Duration) -> Option<Unconfirmed> {
        let first_ask = message.sent_at + burst_time + FIRST_REQUEST_AFTER;
        self.next_request = Some(self.next_request.map_or(first_ask, |at| at.min(first_ask)));
        self.pending.push(message);
        (self.pending.len() > MAX_UNCONFIRMED).then(|| self.pending.remove(0))
    }

    /// The messages that have run out of time to be confirmed.
    pub fn expire(&mut self, now: Instant) -> Vec<Unconfirmed> {
        let (expired, pending) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|m| now.duration_since(m.sent_at) >= CONFIRM_TIMEOUT);
        self.pending = pending;
        self.stop_asking_if_done();
        expired
    }

    /// Whether to ask the relay now. If so, the next time is set.
    pub fn request_due(&mut self, now: Instant) -> bool {
        match self.next_request {
            Some(at) if now >= at && !self.pending.is_empty() => {
                self.next_request = Some(now + REQUEST_INTERVAL);
                true
            }
            _ => false,
        }
    }

    /// The messages a receipt from link `session` shows the relay has
    /// enough of.
    pub fn confirmed_by(&mut self, session: SessionId, receipt: &Receipt) -> Vec<Unconfirmed> {
        let (confirmed, pending) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|m| {
                m.session == session
                    && (0..m.packets)
                        .filter(|&i| receipt.taken_in(m.first + i) == Some(true))
                        .count() as u64
                        >= m.needed
            });
        self.pending = pending;
        self.stop_asking_if_done();
        confirmed
    }

    fn stop_asking_if_done(&mut self) {
        if self.pending.is_empty() {
            self.next_request = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_link::{LinkEnd, LinkKeys, Side, TYPE_DATA};

    /// A client's end of a link, and the relay's.
    fn link() -> (LinkEnd, LinkEnd) {
        let keys = LinkKeys {
            to_relay: [1; 32],
            to_client: [2; 32],
        };
        (
            LinkEnd::new(Side::Client, keys, [3; 4]),
            LinkEnd::new(Side::Relay, keys, [3; 4]),
        )
    }

    /// A message of `packets` packets sent on `client`, needing `needed`.
    fn send(
        client: &mut LinkEnd,
        packets: u64,
        needed: u64,
        at: Instant,
    ) -> (Unconfirmed, Vec<Vec<u8>>) {
        let first = client.next_packet_number(relay_link::Lane::Paced);
        let burst = (0..packets)
            .map(|_| client.seal(relay_link::Lane::Paced, TYPE_DATA, b"symbol"))
            .collect();
        let message = Unconfirmed {
            session: client.session_id(),
            first,
            packets,
            needed,
            sent_at: at,
            history_id: Some(1),
            preview: "hi".into(),
        };
        (message, burst)
    }

    #[test]
    fn a_message_is_confirmed_once_the_relay_has_enough_of_it() {
        let (mut client, mut relay) = link();
        let now = Instant::now();
        let mut confirmations = Confirmations::default();
        let (message, burst) = send(&mut client, 10, 4, now);
        confirmations.track(message, Duration::ZERO);

        for packet in &burst[..3] {
            relay.open(packet).unwrap();
        }
        let receipt = relay.paced_receipt();
        assert!(confirmations.confirmed_by([3; 4], &receipt).is_empty());

        relay.open(&burst[9]).unwrap();
        let receipt = relay.paced_receipt();
        assert!(
            confirmations.confirmed_by([9; 4], &receipt).is_empty(),
            "a receipt from another link says nothing"
        );
        let confirmed = confirmations.confirmed_by([3; 4], &receipt);
        assert_eq!(confirmed.len(), 1);
        assert!(confirmations.pending.is_empty());
        assert!(!confirmations.request_due(now + CONFIRM_TIMEOUT));
    }

    #[test]
    fn requests_go_out_once_the_burst_has_and_then_every_interval() {
        let (mut client, _) = link();
        let now = Instant::now();
        let mut confirmations = Confirmations::default();
        assert!(!confirmations.request_due(now), "nothing to ask about");
        let (message, _) = send(&mut client, 10, 4, now);
        confirmations.track(message, Duration::from_millis(100));

        let first_ask = now + Duration::from_millis(100) + FIRST_REQUEST_AFTER;
        assert!(!confirmations.request_due(first_ask - Duration::from_millis(1)));
        assert!(confirmations.request_due(first_ask));
        assert!(!confirmations.request_due(first_ask + REQUEST_INTERVAL / 2));
        assert!(confirmations.request_due(first_ask + REQUEST_INTERVAL));
    }

    #[test]
    fn a_message_not_confirmed_in_time_has_failed() {
        let (mut client, _) = link();
        let now = Instant::now();
        let mut confirmations = Confirmations::default();
        let (early, _) = send(&mut client, 10, 4, now);
        let (later, _) = send(&mut client, 10, 4, now + Duration::from_secs(5));
        confirmations.track(early, Duration::ZERO);
        confirmations.track(later, Duration::ZERO);

        assert!(
            confirmations
                .expire(now + CONFIRM_TIMEOUT - Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(confirmations.expire(now + CONFIRM_TIMEOUT).len(), 1);
        assert_eq!(confirmations.pending.len(), 1);
        assert_eq!(
            confirmations
                .expire(now + Duration::from_secs(5) + CONFIRM_TIMEOUT)
                .len(),
            1
        );
        assert!(!confirmations.request_due(now + Duration::from_secs(60)));
    }

    #[test]
    fn tracking_is_bounded() {
        let (mut client, _) = link();
        let now = Instant::now();
        let mut confirmations = Confirmations::default();
        for _ in 0..MAX_UNCONFIRMED {
            let (message, _) = send(&mut client, 1, 1, now);
            assert!(confirmations.track(message, Duration::ZERO).is_none());
        }
        let (message, _) = send(&mut client, 1, 1, now);
        assert!(confirmations.track(message, Duration::ZERO).is_some());
        assert_eq!(confirmations.pending.len(), MAX_UNCONFIRMED);
    }
}
