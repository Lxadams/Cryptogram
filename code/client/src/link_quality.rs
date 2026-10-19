//! How much of our traffic with the relay is being lost right now, each
//! way, over the last `WINDOW` (10 s). The relay answers every sync and
//! every receipt request we send it with `REPLY_COPIES` copies of one
//! packet (the same packet: the copies after the first are replays, which
//! the link turns away but which still prove they arrived), and everything
//! it sends us on a link is numbered in order. So over the window:
//!
//! - The answers it sent are the ones that arrived plus the gaps in the
//!   numbering (packets all of whose copies were lost, taken to be answers,
//!   as nearly everything it sends us is).
//! - **Receiving:** the copies that arrived, out of `REPLY_COPIES` for each
//!   answer it sent, give its packets' delivery rate.
//! - **Sending:** the answers it sent, out of the requests we sent, give
//!   ours: it answers every request that reaches it.
//!
//! At heavy loss only a few answers come back in 10 s, so while a front end
//! is watching (see `LinkQuality::unstable`) the client probes with a
//! receipt request every `PROBE_INTERVAL` that nothing else has asked the
//! relay anything (see `LinkQuality::probes_due`): enough samples that the
//! estimate is steady enough to warn by. At 70% each way, a probe a second
//! left the warning on a third of the time; eight a second, simulated, 7%.
//! Unwatched, it adds nothing.
//!
//! Packets dropped by the simulated loss (see `netsim`) count like any
//! others: to the client they're lost either way.

use crate::SessionId;
use relay_link::{PacketNumber, REPLY_COPIES};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The span the estimate covers.
const WINDOW: Duration = Duration::from_secs(10);
/// About how long an answer takes to come back: the requests counted are
/// the window's, this much earlier, so that they line up with the answers
/// that arrived in it.
const ANSWER_DELAY: Duration = Duration::from_millis(250);
/// Too few requests in the window to say anything from.
const MIN_REQUESTS: usize = 3;
/// How often to probe, while watched, when nothing else has asked the relay
/// anything (eight a second: about 4 KB/s with their answers, mostly the
/// receipts), the most probes owed at once (four, for a front end asking
/// every 500 ms), and how long after the last look it stops.
const PROBE_INTERVAL: Duration = Duration::from_millis(125);
const MAX_PROBES_AT_ONCE: u32 = 4;
const WATCHED_FOR: Duration = Duration::from_secs(5);
/// Loss in either direction at which the network counts as unstable, and
/// below which it counts as stable again: a little apart, so an estimate
/// wobbling around one threshold doesn't flip the warning on and off, but
/// not far, or noise at 70% (which isn't unstable) would keep it on.
const UNSTABLE_LOSS: f64 = 0.8;
const STABLE_AGAIN_LOSS: f64 = 0.78;

/// The estimated share of packets lost each way, from 0 to 1.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Loss {
    /// Ours, on the way to the relay.
    pub sending: f64,
    /// The relay's, on the way to us.
    pub receiving: f64,
    /// Nothing came back at all in the window, though we kept asking: both
    /// are then 1, as there's nothing to tell them apart by.
    pub nothing_back: bool,
}

/// A packet from the relay: which link and number, when its first copy
/// arrived, whether it answers a request, and how many copies have arrived.
struct Incoming {
    session: SessionId,
    number: PacketNumber,
    at: Instant,
    answer: bool,
    copies: u32,
}

/// The requests we've sent the relay and what came back, over the last two
/// windows (the earlier one for where the numbering stood when this one
/// began).
#[derive(Default)]
pub struct LinkQuality {
    /// When each request (a sync or a receipt request) went out.
    requests: VecDeque<Instant>,
    incoming: VecDeque<Incoming>,
    last_request: Option<Instant>,
    last_watched: Option<Instant>,
    unstable: bool,
}

impl LinkQuality {
    /// We've sent the relay a request it answers (a sync or a receipt
    /// request).
    pub(crate) fn request_sent(&mut self, now: Instant) {
        self.requests.push_back(now);
        self.last_request = Some(now);
        self.forget_before(now);
    }

    /// A copy of a packet from the relay has arrived on link `session`,
    /// numbered `number`: the first, or (for an answer, which the relay
    /// sends several times) a replay of it. `answer` if it answers a
    /// request (a sync ack or a receipt).
    pub(crate) fn received(
        &mut self,
        now: Instant,
        session: SessionId,
        number: PacketNumber,
        answer: bool,
    ) {
        match self
            .incoming
            .iter_mut()
            .find(|p| p.session == session && p.number == number)
        {
            Some(packet) => packet.copies += 1,
            None => self.incoming.push_back(Incoming {
                session,
                number,
                at: now,
                answer,
                copies: 1,
            }),
        }
        self.forget_before(now);
    }

    /// How many receipt requests to send the relay just to measure by: one
    /// per `PROBE_INTERVAL` that nothing has asked it anything (up to
    /// `MAX_PROBES_AT_ONCE`), while someone is watching; otherwise none.
    pub(crate) fn probes_due(&self, now: Instant) -> u32 {
        let watched = self
            .last_watched
            .is_some_and(|at| now.duration_since(at) < WATCHED_FOR);
        if !watched {
            return 0;
        }
        match self.last_request {
            None => MAX_PROBES_AT_ONCE,
            Some(at) => {
                let owed = now.duration_since(at).as_millis() / PROBE_INTERVAL.as_millis();
                (owed as u32).min(MAX_PROBES_AT_ONCE)
            }
        }
    }

    /// The loss each way over the last `WINDOW`, or `None` when too few
    /// requests went out to tell.
    pub fn estimate(&self, now: Instant) -> Option<Loss> {
        let start = now.checked_sub(WINDOW)?;
        let requests = self
            .requests
            .iter()
            .filter(|&&at| at + ANSWER_DELAY >= start && at + ANSWER_DELAY <= now)
            .count();
        if requests < MIN_REQUESTS {
            return None;
        }
        let (answers_sent, copies) = self.answers_since(start);
        if answers_sent == 0 {
            return Some(Loss {
                sending: 1.0,
                receiving: 1.0,
                nothing_back: true,
            });
        }
        let down = (f64::from(copies) / (answers_sent * REPLY_COPIES as u64) as f64).min(1.0);
        let up = (answers_sent as f64 / requests as f64).min(1.0);
        Some(Loss {
            sending: 1.0 - up,
            receiving: 1.0 - down,
            nothing_back: false,
        })
    }

    /// How many answers the relay sent since `start`, those that arrived
    /// and the gaps in its numbering, and how many copies of them arrived.
    fn answers_since(&self, start: Instant) -> (u64, u32) {
        let (mut sent, mut copies) = (0u64, 0u32);
        let mut links: Vec<SessionId> = Vec::new();
        for packet in &self.incoming {
            if packet.at >= start && !links.contains(&packet.session) {
                links.push(packet.session);
            }
        }
        for link in links {
            let on_link = |in_window: bool| {
                self.incoming
                    .iter()
                    .filter(move |p| p.session == link && (p.at >= start) == in_window)
            };
            let Some(top) = on_link(true).map(|p| p.number).max() else {
                continue;
            };
            let first = on_link(true).map(|p| p.number).min().unwrap_or(top);
            // From the last number before the window, or else the first in it.
            let numbered = match on_link(false).map(|p| p.number).max() {
                Some(before) if before < top => top - before,
                _ => top - first + 1,
            };
            let arrived = on_link(true).count() as u64;
            let answers = on_link(true).filter(|p| p.answer).count() as u64;
            sent += answers + numbered.saturating_sub(arrived);
            copies += on_link(true)
                .filter(|p| p.answer)
                .map(|p| p.copies.min(REPLY_COPIES as u32))
                .sum::<u32>();
        }
        (sent, copies)
    }

    /// Whether the network is unstable: loss either way has reached
    /// `UNSTABLE_LOSS`, and hasn't since dropped below `STABLE_AGAIN_LOSS`.
    /// Asking counts as watching, which keeps the probes going (see
    /// `probes_due`).
    pub fn unstable(&mut self, now: Instant) -> bool {
        self.last_watched = Some(now);
        if let Some(loss) = self.estimate(now) {
            let worst = loss.sending.max(loss.receiving);
            if worst >= UNSTABLE_LOSS {
                self.unstable = true;
            } else if worst < STABLE_AGAIN_LOSS {
                self.unstable = false;
            }
        }
        self.unstable
    }

    /// Drop what's older than two windows: the earlier one is only needed
    /// for where the numbering stood when the current one began.
    fn forget_before(&mut self, now: Instant) {
        let Some(cutoff) = now.checked_sub(2 * WINDOW) else {
            return;
        };
        while self.requests.front().is_some_and(|&at| at < cutoff) {
            self.requests.pop_front();
        }
        while self.incoming.front().is_some_and(|p| p.at < cutoff) {
            self.incoming.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: SessionId = [1, 2, 3, 4];

    /// One request a second for a window and a bit, each answered with
    /// `REPLY_COPIES` copies of one packet: the request gets through if
    /// `up(i)`, and `copies_back(i)` of its answer's copies get here.
    /// Returns the quality and the time it ends.
    fn exchange(
        up: impl Fn(u64) -> bool,
        copies_back: impl Fn(u64) -> u32,
    ) -> (LinkQuality, Instant) {
        let start = Instant::now();
        let mut quality = LinkQuality::default();
        let seconds = WINDOW.as_secs() + 2;
        // The relay numbers its answers in order, as it sends them.
        let mut number = 0;
        for i in 0..seconds {
            let at = start + Duration::from_secs(i);
            quality.request_sent(at);
            if up(i) {
                for _ in 0..copies_back(i) {
                    quality.received(at + Duration::from_millis(100), LINK, number, true);
                }
                number += 1;
            }
        }
        (quality, start + Duration::from_secs(seconds))
    }

    const ALL: u32 = REPLY_COPIES as u32;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 0.06
    }

    #[test]
    fn no_loss_is_none_either_way() {
        let (quality, now) = exchange(|_| true, |_| ALL);
        let loss = quality.estimate(now).unwrap();
        assert!(
            close(loss.sending, 0.0) && close(loss.receiving, 0.0),
            "{loss:?}"
        );
    }

    #[test]
    fn loss_on_the_way_down_is_told_from_the_copies_and_gaps() {
        // Every request answered, but only one copy in three gets back.
        let (quality, now) = exchange(|_| true, |_| 1);
        let loss = quality.estimate(now).unwrap();
        assert!(close(loss.sending, 0.0), "{loss:?}");
        assert!(close(loss.receiving, 2.0 / 3.0), "{loss:?}");

        // Every copy of every other answer lost: the gaps say so.
        let (quality, now) = exchange(|_| true, |i| if i % 2 == 0 { ALL } else { 0 });
        let loss = quality.estimate(now).unwrap();
        assert!(close(loss.sending, 0.0), "{loss:?}");
        assert!(close(loss.receiving, 0.5), "{loss:?}");
    }

    /// The false alarm a copies-only estimate gave on a real link at 50%:
    /// a couple of answers back, with one copy each, said everything was
    /// being lost on the way down. Counted out of what the relay sent, it's
    /// two-thirds, not all.
    #[test]
    fn a_few_single_copies_are_not_total_loss() {
        let (quality, now) = exchange(|i| i % 4 == 0, |_| 1);
        let loss = quality.estimate(now).unwrap();
        assert!(close(loss.receiving, 2.0 / 3.0), "{loss:?}");
    }

    #[test]
    fn loss_on_the_way_up_is_told_from_the_requests_answered() {
        // Four requests in five lost; every copy of the rest's answers back.
        let (quality, now) = exchange(|i| i % 5 == 0, |_| ALL);
        let loss = quality.estimate(now).unwrap();
        assert!(close(loss.receiving, 0.0), "{loss:?}");
        assert!(close(loss.sending, 0.8), "{loss:?}");
    }

    #[test]
    fn nothing_back_is_said_so_and_too_little_is_no_estimate() {
        let (quality, now) = exchange(|_| false, |_| 0);
        assert_eq!(
            quality.estimate(now),
            Some(Loss {
                sending: 1.0,
                receiving: 1.0,
                nothing_back: true,
            })
        );
        let mut few = LinkQuality::default();
        let start = Instant::now();
        few.request_sent(start);
        assert_eq!(few.estimate(start + WINDOW), None);
    }

    /// Only the last `WINDOW` counts: total loss a minute ago doesn't.
    #[test]
    fn only_the_last_ten_seconds_count() {
        let (mut quality, now) = exchange(|_| false, |_| 0);
        let later = now + 6 * WINDOW;
        for i in 0..WINDOW.as_secs() {
            let at = later - WINDOW + Duration::from_secs(i);
            quality.request_sent(at);
            for _ in 0..ALL {
                quality.received(at, LINK, 1000 + i, true);
            }
        }
        let loss = quality.estimate(later).unwrap();
        assert!(
            close(loss.sending, 0.0) && close(loss.receiving, 0.0),
            "{loss:?}"
        );
    }

    #[test]
    fn probes_only_while_watched_and_quiet() {
        let start = Instant::now();
        let mut quality = LinkQuality::default();
        assert_eq!(quality.probes_due(start), 0, "nobody's watching");
        quality.unstable(start);
        assert_eq!(quality.probes_due(start), MAX_PROBES_AT_ONCE);
        quality.request_sent(start);
        assert_eq!(
            quality.probes_due(start + PROBE_INTERVAL / 2),
            0,
            "just asked"
        );
        assert_eq!(quality.probes_due(start + PROBE_INTERVAL), 1);
        assert_eq!(
            quality.probes_due(start + 10 * PROBE_INTERVAL),
            MAX_PROBES_AT_ONCE
        );
        assert_eq!(
            quality.probes_due(start + WATCHED_FOR),
            0,
            "stopped watching"
        );
    }

    #[test]
    fn unstable_comes_on_at_80_percent_and_goes_off_below_78() {
        let (mut fine, now) = exchange(|_| true, |_| ALL);
        assert!(!fine.unstable(now));
        // 9 requests in 10 lost on the way up.
        let (mut lossy, now) = exchange(|i| i % 10 == 0, |_| ALL);
        assert!(lossy.unstable(now));
        // 1 in 2 lost: below 78%, so off.
        lossy.incoming = exchange(|i| i % 2 == 0, |_| ALL).0.incoming;
        assert!(!lossy.unstable(now));
    }
}
