// Remembers which relay deliveries we've already handled. The relay resends
// a forwarded packet until we acknowledge it (see `Client::handle_relay_packet`),
// so a lost ack means the same packet arrives again. Handling it twice is
// mostly harmless (chat and PQ refresh duplicates are ignored), but a resent
// KeyExchange would restart the session, so repeats are skipped here, by the
// relay's delivery ID, before they reach `handle_incoming_packet`.

use crate::DeliveryId;
use std::collections::{HashSet, VecDeque};

/// How many delivery IDs to remember. Resends of one packet arrive within
/// minutes, long before this many newer packets could push it out.
const CAPACITY: usize = 4096;

#[derive(Default)]
pub struct RecentDeliveries {
    order: VecDeque<DeliveryId>,
    seen: HashSet<DeliveryId>,
}

impl RecentDeliveries {
    /// Records `id` and returns whether this is the first time we've seen it.
    pub fn first_time(&mut self, id: DeliveryId) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > CAPACITY
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_is_detected_and_memory_is_bounded() {
        let mut recent = RecentDeliveries::default();
        assert!(recent.first_time([1; 16]));
        assert!(!recent.first_time([1; 16]));

        for i in 0..CAPACITY as u32 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id[15] = 0xFF;
            recent.first_time(id);
        }
        assert_eq!(recent.order.len(), CAPACITY);
        assert_eq!(recent.seen.len(), CAPACITY);
        assert!(recent.first_time([1; 16]), "oldest ID was forgotten");
    }
}
