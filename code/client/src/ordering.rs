// Hands each contact's messages over in the order they were sent.
//
// Under loss, messages finish arriving out of order. A message that lost
// more of its FEC symbols waits for the relay's resends (2 s later, then
// 4 s, 8 s and so on), while the one after it may get through at once.
// Every chunk carries its position in the sender's ratchet, so a message
// that turns up before an earlier one is held until that one arrives.
//
// One that never arrives (lost for good, or never sent because the
// sender's app died) holds the rest up for at most `REORDER_WAIT`. After
// that, what's held goes out, and if the missing message turns up after
// all, it goes out when it does.
//
// The state lives in each session (`SymmetricSessionState::delivery`), so
// it starts afresh with every new session, and it's saved with the session:
// a held message has already used up its ratchet key, so it can't be lost
// to the app closing.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Longest a message waits for an earlier one. Long enough for the relay's
/// first two resends of a missing message (2 s and 6 s after it was first
/// sent), which is when nearly every missing one turns up.
pub const REORDER_WAIT: Duration = Duration::from_secs(10);
/// Most messages held per session. Past this, the oldest gap is given up
/// on, so a contact can't make us hold any number of messages.
const MAX_HELD: usize = 64;

/// Where a session's incoming messages are, in the order they were sent.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DeliveryOrder {
    /// Ratchet position of the first chunk of the next message to hand
    /// over.
    pub next: u64,
    /// Complete messages waiting for an earlier one, by the ratchet
    /// position of their first chunk.
    pub held: BTreeMap<u64, HeldMessage>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HeldMessage {
    /// Ratchet position of the message's last chunk.
    pub last: u64,
    /// `None` for a position that held nothing to hand over (see
    /// `DeliveryOrder::pass_over`).
    pub text: Option<Vec<u8>>,
    /// When it was held, in Unix milliseconds: a wall clock, not an
    /// `Instant`, as it's saved with the session.
    pub held_at_ms: u64,
}

/// The time now, in Unix milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl DeliveryOrder {
    /// Delivery for a session that was saved before messages were ordered:
    /// everything it had received was handed over as it arrived, so the
    /// next message to hand over is the next one it receives.
    pub fn starting_at(next: u64) -> Self {
        Self {
            next,
            held: BTreeMap::new(),
        }
    }

    /// Take in a complete message whose chunks had ratchet positions
    /// `first..=last`. Returns the messages that can go out now, in the
    /// order they were sent: none if it's waiting for an earlier one.
    pub fn accept(&mut self, first: u64, last: u64, text: Vec<u8>, now_ms: u64) -> Vec<Vec<u8>> {
        self.take_in(first, last, Some(text), now_ms)
    }

    /// Ratchet positions `first..=last` held nothing to hand over: a
    /// payload that decrypted but was dropped. The messages after it
    /// mustn't wait for it, so it takes its place in the order, empty.
    /// Returns the messages that can go out now.
    pub fn pass_over(&mut self, first: u64, last: u64, now_ms: u64) -> Vec<Vec<u8>> {
        self.take_in(first, last, None, now_ms)
    }

    fn take_in(
        &mut self,
        first: u64,
        last: u64,
        text: Option<Vec<u8>>,
        now_ms: u64,
    ) -> Vec<Vec<u8>> {
        if first < self.next {
            // Its turn has passed: the wait for it ran out. Late is better
            // than never. If it runs on past `next`, those positions are
            // its own, so nothing after it may wait for them.
            let mut out: Vec<Vec<u8>> = text.into_iter().collect();
            if last >= self.next {
                self.next = last + 1;
                out.extend(self.release_ready());
            }
            return out;
        }
        if first > self.next {
            self.held.insert(
                first,
                HeldMessage {
                    last,
                    text,
                    held_at_ms: now_ms,
                },
            );
            if self.held.len() > MAX_HELD {
                let oldest_gap_ends_at = *self.held.keys().next().unwrap();
                return self.release_through(oldest_gap_ends_at);
            }
            return Vec::new();
        }
        self.next = last + 1;
        let mut out: Vec<Vec<u8>> = text.into_iter().collect();
        out.extend(self.release_ready());
        out
    }

    /// Give up on whatever is missing in front of any message held for
    /// `REORDER_WAIT`: hand over everything held up to it, in order, then
    /// anything that follows on from those.
    pub fn release_due(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let wait = REORDER_WAIT.as_millis() as u64;
        // The last message (in sent order) that has waited long enough.
        let due = self
            .held
            .iter()
            .rev()
            .find(|(_, held)| now_ms.saturating_sub(held.held_at_ms) >= wait)
            .map(|(&first, _)| first);
        match due {
            Some(first) => self.release_through(first),
            None => Vec::new(),
        }
    }

    /// Hand over everything held, in order, whatever is missing in front of
    /// it: for a session that's being dropped, whose held messages couldn't
    /// be had again.
    pub fn release_all(&mut self) -> Vec<Vec<u8>> {
        self.release_through(u64::MAX)
    }

    /// Hand over every held message up to the one starting at `first`, and
    /// the run that follows on from it.
    fn release_through(&mut self, first: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(entry) = self.held.first_entry() {
            if *entry.key() > first {
                break;
            }
            let held = entry.remove();
            self.next = self.next.max(held.last + 1);
            out.extend(held.text);
        }
        out.extend(self.release_ready());
        out
    }

    /// The held messages whose turn has come, now that `next` has moved.
    fn release_ready(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(entry) = self.held.first_entry() {
            if *entry.key() > self.next {
                break;
            }
            let held = entry.remove();
            self.next = self.next.max(held.last + 1);
            out.extend(held.text);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAIT: u64 = REORDER_WAIT.as_millis() as u64;

    fn texts(out: Vec<Vec<u8>>) -> Vec<String> {
        out.into_iter()
            .map(|t| String::from_utf8(t).unwrap())
            .collect()
    }

    #[test]
    fn messages_in_order_go_straight_out() {
        let mut order = DeliveryOrder::default();
        assert_eq!(texts(order.accept(0, 0, b"a".to_vec(), 0)), ["a"]);
        assert_eq!(texts(order.accept(1, 3, b"b".to_vec(), 0)), ["b"]);
        assert_eq!(texts(order.accept(4, 4, b"c".to_vec(), 0)), ["c"]);
        assert_eq!(order.next, 5);
        assert!(order.held.is_empty());
    }

    #[test]
    fn a_message_ahead_waits_for_the_ones_before_it() {
        let mut order = DeliveryOrder::default();
        assert!(order.accept(2, 2, b"c".to_vec(), 0).is_empty());
        assert!(order.accept(1, 1, b"b".to_vec(), 0).is_empty());
        assert_eq!(texts(order.accept(0, 0, b"a".to_vec(), 0)), ["a", "b", "c"]);
        assert_eq!(order.next, 3);
        assert!(order.held.is_empty());
    }

    #[test]
    fn a_message_that_never_comes_holds_the_rest_up_for_the_wait_only() {
        let mut order = DeliveryOrder::default();
        assert!(order.accept(1, 1, b"b".to_vec(), 1000).is_empty());
        assert!(order.accept(3, 3, b"d".to_vec(), 2000).is_empty());
        assert!(order.release_due(1000 + WAIT - 1).is_empty());
        // "b" has waited long enough; "d" goes too, though it hasn't, as
        // only a message missing in front of it is holding it.
        assert!(order.accept(2, 2, b"c".to_vec(), 3000).is_empty());
        assert_eq!(texts(order.release_due(1000 + WAIT)), ["b", "c", "d"]);
        assert_eq!(order.next, 4);

        // The missing one turning up late still goes out.
        assert_eq!(texts(order.accept(0, 0, b"a".to_vec(), 9999)), ["a"]);
        assert_eq!(order.next, 4);
    }

    #[test]
    fn the_wait_runs_out_message_by_message() {
        let mut order = DeliveryOrder::default();
        assert!(order.accept(1, 1, b"b".to_vec(), 0).is_empty());
        assert!(order.accept(3, 3, b"d".to_vec(), 5000).is_empty());
        // Only "b" is due. "d" is still waiting for the missing message
        // between them.
        assert_eq!(texts(order.release_due(WAIT)), ["b"]);
        assert_eq!(order.next, 2);
        assert_eq!(texts(order.accept(2, 2, b"c".to_vec(), WAIT)), ["c", "d"]);
    }

    #[test]
    fn a_dropped_message_holds_nothing_up() {
        let mut order = DeliveryOrder::default();
        assert!(order.pass_over(0, 0, 0).is_empty());
        assert_eq!(texts(order.accept(1, 1, b"b".to_vec(), 0)), ["b"]);

        // Dropped ahead of its turn, it waits its turn, then goes quietly.
        assert!(order.pass_over(3, 3, 0).is_empty());
        assert!(order.accept(4, 4, b"e".to_vec(), 0).is_empty());
        assert_eq!(texts(order.accept(2, 2, b"c".to_vec(), 0)), ["c", "e"]);
        assert_eq!(order.next, 5);
    }

    #[test]
    fn a_late_message_running_past_next_holds_nothing_up() {
        let mut order = DeliveryOrder::default();
        // A chunk at 0 was dropped on its own, so `next` is 1, inside the
        // message that turns up at 0..=2.
        assert!(order.pass_over(0, 0, 0).is_empty());
        assert!(order.accept(3, 3, b"d".to_vec(), 0).is_empty());
        assert_eq!(texts(order.accept(0, 2, b"abc".to_vec(), 0)), ["abc", "d"]);
        assert_eq!(order.next, 4);
    }

    #[test]
    fn a_dropped_session_hands_over_everything_held() {
        let mut order = DeliveryOrder::default();
        assert!(order.accept(3, 3, b"d".to_vec(), 0).is_empty());
        assert!(order.pass_over(2, 2, 0).is_empty());
        assert!(order.accept(1, 1, b"b".to_vec(), 0).is_empty());
        assert_eq!(texts(order.release_all()), ["b", "d"]);
        assert!(order.held.is_empty());
    }

    #[test]
    fn holding_is_bounded() {
        let mut order = DeliveryOrder::default();
        let mut out = Vec::new();
        for first in 1..=MAX_HELD as u64 + 1 {
            out.extend(order.accept(first, first, first.to_string().into_bytes(), 0));
        }
        // Past the limit, the gap at 0 is given up on and everything goes.
        assert_eq!(out.len(), MAX_HELD + 1);
        assert_eq!(texts(out)[0], "1");
        assert!(order.held.is_empty());
    }

    #[test]
    fn a_session_saved_before_ordering_starts_at_its_next_message() {
        let mut order = DeliveryOrder::starting_at(7);
        assert_eq!(texts(order.accept(7, 7, b"x".to_vec(), 0)), ["x"]);
        assert_eq!(order.next, 8);
    }
}
