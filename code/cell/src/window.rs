//! Receipt bookkeeping for one link.
//!
//! The receiving side records which of the other side's cells arrived
//! (`ReceiveWindow`) and puts a `Receipt` in every cell it sends. The
//! sending side matches receipts against what it sent (`SendWindow`): each
//! cell it sent is resolved as delivered or lost, along with whatever it
//! carried, and the outcomes feed a running loss estimate. Nothing is
//! retransmitted at this layer; what to do about a lost cell is up to the
//! caller (the client sends more FEC symbols, the relay resends).

use crate::format::Receipt;
use std::collections::BTreeMap;

/// A cell this far behind the newest one reported, but not reported
/// itself, counts as lost. QUIC datagrams can be reordered a little; a cell
/// reported received after it was counted lost is simply received twice
/// downstream, which every user of these copes with.
const REORDER_THRESHOLD: u32 = 3;

/// Bits in a receipt's bitmap: how far back a receipt can report on.
const WINDOW: u32 = 64;

/// The other side's cells we've received, as reported in our receipts.
#[derive(Debug, Default, Clone)]
pub struct ReceiveWindow {
    receipt: Receipt,
}

impl ReceiveWindow {
    /// Record that the other side's cell `seq` arrived. Returns `false` for
    /// a duplicate, or a cell too old for the receipt to cover.
    pub fn record(&mut self, seq: u32) -> bool {
        let Receipt { largest, bitmap } = &mut self.receipt;
        if seq == 0 {
            return false;
        }
        if seq > *largest {
            let shift = seq - *largest;
            // The previous largest becomes bit `shift - 1`, unless this is
            // the first cell (largest 0 marks "nothing yet").
            let previous = match *largest {
                0 => 0,
                _ => 1u64.checked_shl(shift - 1).unwrap_or(0),
            };
            *bitmap = bitmap.checked_shl(shift).unwrap_or(0) | previous;
            *largest = seq;
            return true;
        }
        if seq == *largest {
            return false;
        }
        let bit = *largest - 1 - seq;
        if bit >= WINDOW || *bitmap & (1 << bit) != 0 {
            return false;
        }
        *bitmap |= 1 << bit;
        true
    }

    /// The receipt to put in our next cell.
    pub fn receipt(&self) -> Receipt {
        self.receipt
    }
}

/// What a receipt settled: the tags of cells now known to have arrived,
/// and of cells now counted as lost.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved<T> {
    pub delivered: Vec<T>,
    pub lost: Vec<T>,
}

impl<T> Default for Resolved<T> {
    fn default() -> Self {
        Self {
            delivered: Vec::new(),
            lost: Vec::new(),
        }
    }
}

/// Our cells on one link that the other side hasn't reported on yet, each
/// with an optional tag saying what it carried.
pub struct SendWindow<T> {
    next_seq: u32,
    outstanding: BTreeMap<u32, Option<T>>,
    loss: LossEstimate,
}

impl<T> Default for SendWindow<T> {
    fn default() -> Self {
        Self::new(LossEstimate::default())
    }
}

impl<T> SendWindow<T> {
    /// Start a link's numbering at 1, carrying over what an earlier link
    /// learned about loss.
    pub fn new(loss: LossEstimate) -> Self {
        Self {
            next_seq: 1,
            outstanding: BTreeMap::new(),
            loss,
        }
    }

    /// Number the next cell and remember what it carries until a receipt
    /// settles it.
    pub fn send(&mut self, tag: Option<T>) -> u32 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.outstanding.insert(seq, tag);
        seq
    }

    /// Settle every outstanding cell `receipt` reports on.
    pub fn on_receipt(&mut self, receipt: Receipt) -> Resolved<T> {
        let mut resolved = Resolved::default();
        if receipt.largest == 0 || receipt.largest >= self.next_seq {
            return resolved; // nothing received yet, or not a receipt for our cells
        }
        let settled: Vec<(u32, bool)> = self
            .outstanding
            .range(..=receipt.largest)
            .filter_map(|(&seq, _)| {
                let behind = receipt.largest - seq;
                if behind == 0 {
                    return Some((seq, true));
                }
                let bit = behind - 1;
                if bit < WINDOW && receipt.bitmap & (1 << bit) != 0 {
                    Some((seq, true))
                } else if behind > REORDER_THRESHOLD {
                    Some((seq, false))
                } else {
                    None // might still turn up
                }
            })
            .collect();
        for (seq, arrived) in settled {
            let tag = self.outstanding.remove(&seq).flatten();
            self.loss.update(!arrived);
            if let Some(tag) = tag {
                match arrived {
                    true => resolved.delivered.push(tag),
                    false => resolved.lost.push(tag),
                }
            }
        }
        resolved
    }

    /// The link is gone: everything still outstanding never got a receipt,
    /// so whatever it carried has to be treated as lost.
    pub fn drain(&mut self) -> Vec<T> {
        std::mem::take(&mut self.outstanding)
            .into_values()
            .flatten()
            .collect()
    }

    /// Estimated fraction of our cells this link loses.
    pub fn loss(&self) -> &LossEstimate {
        &self.loss
    }
}

/// Running estimate of how many cells a link loses. Quick to rise when
/// jamming starts (an average over the last few cells) and slow to fall
/// when it stops (an average over the last few dozen), so senders err on
/// the side of extra redundancy.
#[derive(Debug, Clone, Copy)]
pub struct LossEstimate {
    fast: f64,
    slow: f64,
    samples: u64,
}

/// Assumed before a link has reported anything.
const PRIOR_LOSS: f64 = 0.3;
const FAST_WEIGHT: f64 = 1.0 / 8.0;
const SLOW_WEIGHT: f64 = 1.0 / 64.0;

impl Default for LossEstimate {
    fn default() -> Self {
        Self {
            fast: PRIOR_LOSS,
            slow: PRIOR_LOSS,
            samples: 0,
        }
    }
}

impl LossEstimate {
    pub fn update(&mut self, lost: bool) {
        let x = if lost { 1.0 } else { 0.0 };
        self.fast += FAST_WEIGHT * (x - self.fast);
        self.slow += SLOW_WEIGHT * (x - self.slow);
        self.samples += 1;
    }

    /// The fraction of cells to plan for losing.
    pub fn value(&self) -> f64 {
        self.fast.max(self.slow)
    }

    /// How many cells this estimate is based on.
    pub fn samples(&self) -> u64 {
        self.samples
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt_after(seqs: &[u32]) -> Receipt {
        let mut rx = ReceiveWindow::default();
        for &seq in seqs {
            rx.record(seq);
        }
        rx.receipt()
    }

    #[test]
    fn receive_window_tracks_arrivals_and_rejects_repeats() {
        let mut rx = ReceiveWindow::default();
        assert_eq!(rx.receipt(), Receipt::default());
        assert!(!rx.record(0), "seq 0 is never sent");
        assert!(rx.record(1));
        assert_eq!(
            rx.receipt(),
            Receipt {
                largest: 1,
                bitmap: 0
            }
        );
        assert!(rx.record(4));
        assert_eq!(rx.receipt().bitmap, 0b100, "1 is 3 behind 4");
        assert!(rx.record(3), "late but in the window");
        assert_eq!(rx.receipt().bitmap, 0b101);
        assert!(!rx.record(3) && !rx.record(4), "duplicates");
        assert!(rx.record(100));
        assert_eq!(rx.receipt().bitmap, 0, "everything earlier fell out");
        assert!(!rx.record(20), "too old to report on");
        assert!(rx.record(36));
        assert_eq!(rx.receipt().bitmap, 1 << 63);
    }

    #[test]
    fn receipts_settle_cells_as_delivered_or_lost() {
        let mut tx = SendWindow::default();
        let seqs: Vec<u32> = (0..10).map(|i| tx.send(Some(i))).collect();
        assert_eq!(seqs, (1..=10).collect::<Vec<_>>());

        // 1..=10 sent; 2 and 6 lost, 7 and 9 not reported yet.
        let resolved = tx.on_receipt(receipt_after(&[1, 3, 4, 5, 8, 10]));
        assert_eq!(resolved.delivered, [0, 2, 3, 4, 7, 9]);
        assert_eq!(resolved.lost, [1, 5], "2 and 6 are more than 3 behind");
        // 7 and 9 are within 3 of 10: they may still arrive, and 9 does.
        let resolved = tx.on_receipt(receipt_after(&[1, 3, 4, 5, 8, 9, 10]));
        assert_eq!(resolved.delivered, [8]);
        assert!(resolved.lost.is_empty());
        // A newer cell pushes 7 more than 3 behind.
        tx.send(Some(10));
        let resolved = tx.on_receipt(receipt_after(&[1, 3, 4, 5, 8, 9, 10, 11]));
        assert_eq!((resolved.delivered, resolved.lost), (vec![10], vec![6]));
        assert!(tx.on_receipt(receipt_after(&[10])).delivered.is_empty());
        assert!(tx.drain().is_empty(), "all settled");
    }

    #[test]
    fn a_receipt_far_ahead_settles_old_cells_as_lost() {
        let mut tx = SendWindow::default();
        for i in 0..100 {
            tx.send(Some(i));
        }
        let resolved = tx.on_receipt(receipt_after(&[100]));
        assert_eq!(resolved.delivered, [99]);
        assert_eq!(resolved.lost.len(), 96, "everything over 3 behind");
        assert_eq!(tx.drain(), [96, 97, 98]);
    }

    #[test]
    fn receipts_for_cells_never_sent_are_ignored() {
        let mut tx = SendWindow::<u8>::default();
        tx.send(None);
        let bogus = Receipt {
            largest: 500,
            bitmap: u64::MAX,
        };
        assert_eq!(tx.on_receipt(bogus), Resolved::default());
        assert_eq!(tx.loss().samples(), 0);
    }

    #[test]
    fn loss_estimate_rises_fast_and_falls_slowly() {
        let mut est = LossEstimate::default();
        assert_eq!(est.value(), PRIOR_LOSS);
        for _ in 0..50 {
            est.update(false);
        }
        assert!(est.value() < 0.15, "clean link: {}", est.value());
        for _ in 0..12 {
            est.update(true);
        }
        assert!(
            est.value() > 0.7,
            "jamming noticed within 3 s: {}",
            est.value()
        );
        for _ in 0..12 {
            est.update(false);
        }
        assert!(
            est.value() > 0.15,
            "but not forgotten as fast: {}",
            est.value()
        );
    }

    /// Cells lost at a steady rate: the estimate settles near it, a little
    /// high rather than low.
    #[test]
    fn loss_estimate_tracks_a_steady_rate() {
        let mut tx = SendWindow::default();
        let mut rx = ReceiveWindow::default();
        let mut x = 7u64;
        for _ in 0..2000 {
            let seq = tx.send(Some(()));
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            if (x >> 33) % 10 >= 7 {
                rx.record(seq);
            }
            tx.on_receipt(rx.receipt());
        }
        let loss = tx.loss().value();
        assert!((0.65..0.9).contains(&loss), "{loss}");
    }
}
