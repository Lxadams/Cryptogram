use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

pub type RoutingToken = cell::RoutingToken;
/// Identifies one client connection (a "link") for as long as it lasts.
pub type LinkId = u64;
/// The relay's own number for a queued packet, never sent anywhere: cell
/// receipts say which cells arrived, and each cell carried at most one
/// packet.
pub type PacketId = u64;

/// Payload bytes held per recipient token. Clients send each message as a
/// handful of FEC packets (about 1 KB each), so this holds a couple of
/// thousand of them for an offline recipient. Bounded so one token can't
/// eat the relay's RAM.
pub const MAX_QUEUED_BYTES_PER_TOKEN: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QueuedPacket {
    pub id: PacketId,
    pub payload: Vec<u8>,
    pub expiry: Instant,
    /// The link it's been sent on and not yet settled by a receipt from.
    /// `None` means it's due to be sent (again).
    sent_on: Option<LinkId>,
}

#[derive(Default)]
struct TokenQueue {
    packets: VecDeque<QueuedPacket>,
    bytes: usize,
}

/// Packets waiting for each recipient, and which link (if any) each
/// recipient is on right now.
///
/// A packet stays queued until a receipt from its recipient shows the cell
/// carrying it arrived. A receipt showing it was lost puts it back in line,
/// and so does its link closing before any receipt said either way: the
/// relay's half of each link is plain selective-repeat retransmission,
/// while the client end-to-end FEC covers its own uplink.
#[derive(Default)]
pub struct Tables {
    owners: HashMap<RoutingToken, LinkId>,
    queues: HashMap<RoutingToken, TokenQueue>,
    next_packet_id: PacketId,
}

impl Tables {
    pub fn new() -> Self {
        Self::default()
    }

    /// `link` proved it owns `token`, so the token's packets go there from
    /// now on. Returns the link that had it before, if a different one: its
    /// unsettled packets are back in line for the new link.
    pub fn bind(&mut self, token: RoutingToken, link: LinkId) -> Option<LinkId> {
        let previous = self.owners.insert(token, link).filter(|&old| old != link);
        if let Some(old) = previous {
            self.requeue_link(&token, old);
        }
        previous
    }

    /// `link` closed. If it still served `token`, nobody does now; anything
    /// it was sent and never settled goes back in line for the next link.
    pub fn unbind(&mut self, token: &RoutingToken, link: LinkId) {
        if self.owners.get(token) == Some(&link) {
            self.owners.remove(token);
        }
        self.requeue_link(token, link);
    }

    fn requeue_link(&mut self, token: &RoutingToken, link: LinkId) {
        if let Some(queue) = self.queues.get_mut(token) {
            for packet in &mut queue.packets {
                if packet.sent_on == Some(link) {
                    packet.sent_on = None;
                }
            }
        }
    }

    /// Queue `payload` for whoever owns `receiver_token`, now or later.
    /// Once the token's queue is full, new packets are refused rather than
    /// old ones evicted: evicting would keep cutting the front off queued
    /// messages, and losing an older one that carries a PQ ratchet update
    /// leaves later ones undecryptable anyway. Returns its id, or `None` if
    /// it was refused.
    pub fn enqueue(
        &mut self,
        receiver_token: RoutingToken,
        payload: Vec<u8>,
        ttl: Duration,
    ) -> Option<PacketId> {
        let queue = self.queues.entry(receiver_token).or_default();
        if queue.bytes + payload.len() > MAX_QUEUED_BYTES_PER_TOKEN {
            return None;
        }
        let id = self.next_packet_id;
        self.next_packet_id += 1;
        queue.bytes += payload.len();
        queue.packets.push_back(QueuedPacket {
            id,
            payload,
            expiry: Instant::now() + ttl,
            sent_on: None,
        });
        Some(id)
    }

    /// The next packet for `link` to send `token`, oldest first, if `link`
    /// is the token's current link and anything is due. It's marked as sent
    /// on `link` until `delivered` or `lost` settles it.
    pub fn next_for(&mut self, token: &RoutingToken, link: LinkId) -> Option<(PacketId, Vec<u8>)> {
        if self.owners.get(token) != Some(&link) {
            return None;
        }
        let now = Instant::now();
        let packet = self
            .queues
            .get_mut(token)?
            .packets
            .iter_mut()
            .find(|p| p.sent_on.is_none() && p.expiry > now)?;
        packet.sent_on = Some(link);
        Some((packet.id, packet.payload.clone()))
    }

    /// The recipient got these: they leave the queue.
    pub fn delivered(&mut self, token: &RoutingToken, ids: &[PacketId]) -> usize {
        let Some(queue) = self.queues.get_mut(token) else {
            return 0;
        };
        let before = queue.packets.len();
        queue.packets.retain(|p| !ids.contains(&p.id));
        queue.bytes = queue.packets.iter().map(|p| p.payload.len()).sum();
        let removed = before - queue.packets.len();
        if queue.packets.is_empty() {
            self.queues.remove(token);
        }
        removed
    }

    /// The cells carrying these, sent on `link`, were lost: send them again.
    pub fn lost(&mut self, token: &RoutingToken, link: LinkId, ids: &[PacketId]) {
        if let Some(queue) = self.queues.get_mut(token) {
            for packet in &mut queue.packets {
                if packet.sent_on == Some(link) && ids.contains(&packet.id) {
                    packet.sent_on = None;
                }
            }
        }
    }

    pub fn sweep_expired_messages(&mut self) {
        let now = Instant::now();
        for queue in self.queues.values_mut() {
            queue.packets.retain(|p| p.expiry > now);
            queue.bytes = queue.packets.iter().map(|p| p.payload.len()).sum();
        }
        self.queues.retain(|_, queue| !queue.packets.is_empty());
    }

    /// No token is bound to any link.
    pub fn is_empty_of_links(&self) -> bool {
        self.owners.is_empty()
    }

    pub fn owner(&self, token: &RoutingToken) -> Option<LinkId> {
        self.owners.get(token).copied()
    }

    pub fn get_queued_packets(&self, token: &RoutingToken) -> Option<&VecDeque<QueuedPacket>> {
        self.queues
            .get(token)
            .map(|queue| &queue.packets)
            .filter(|packets| !packets.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: RoutingToken = [0xCC; 16];
    const TTL: Duration = Duration::from_secs(60);

    fn queued(tables: &Tables) -> usize {
        tables.get_queued_packets(&TOKEN).map_or(0, |q| q.len())
    }

    #[test]
    fn packets_go_out_oldest_first_and_once_until_settled() {
        let mut tables = Tables::new();
        let a = tables.enqueue(TOKEN, b"a".to_vec(), TTL).unwrap();
        let b = tables.enqueue(TOKEN, b"b".to_vec(), TTL).unwrap();
        assert!(tables.next_for(&TOKEN, 1).is_none(), "nobody's link yet");

        tables.bind(TOKEN, 1);
        assert_eq!(tables.next_for(&TOKEN, 1), Some((a, b"a".to_vec())));
        assert_eq!(tables.next_for(&TOKEN, 1), Some((b, b"b".to_vec())));
        assert!(tables.next_for(&TOKEN, 1).is_none(), "both in flight");
        assert!(
            tables.next_for(&TOKEN, 2).is_none(),
            "not this token's link"
        );
        assert_eq!(queued(&tables), 2, "kept until a receipt settles them");
    }

    #[test]
    fn receipts_remove_delivered_packets_and_resend_lost_ones() {
        let mut tables = Tables::new();
        tables.bind(TOKEN, 1);
        let a = tables.enqueue(TOKEN, b"a".to_vec(), TTL).unwrap();
        let b = tables.enqueue(TOKEN, b"b".to_vec(), TTL).unwrap();
        tables.next_for(&TOKEN, 1);
        tables.next_for(&TOKEN, 1);

        assert_eq!(tables.delivered(&TOKEN, &[b]), 1);
        tables.lost(&TOKEN, 1, &[a]);
        assert_eq!(
            tables.next_for(&TOKEN, 1),
            Some((a, b"a".to_vec())),
            "resent"
        );
        assert_eq!(tables.delivered(&TOKEN, &[a]), 1);
        assert_eq!(queued(&tables), 0);
        assert!(tables.queues.is_empty(), "empty queues are dropped");
    }

    /// A phone that drops off mid-delivery gets everything that wasn't
    /// confirmed on its next link, and a lost-receipt report from the old
    /// link can't disturb the new one.
    #[test]
    fn a_closed_link_hands_its_unsettled_packets_to_the_next() {
        let mut tables = Tables::new();
        tables.bind(TOKEN, 1);
        let a = tables.enqueue(TOKEN, b"a".to_vec(), TTL).unwrap();
        tables.next_for(&TOKEN, 1);
        tables.unbind(&TOKEN, 1);
        assert_eq!(tables.owner(&TOKEN), None);
        assert!(tables.next_for(&TOKEN, 1).is_none());

        tables.bind(TOKEN, 2);
        assert_eq!(tables.next_for(&TOKEN, 2), Some((a, b"a".to_vec())));
        tables.lost(&TOKEN, 1, &[a]);
        assert!(tables.next_for(&TOKEN, 2).is_none(), "still in flight on 2");
    }

    #[test]
    fn a_newer_link_takes_the_token_over() {
        let mut tables = Tables::new();
        tables.bind(TOKEN, 1);
        let a = tables.enqueue(TOKEN, b"a".to_vec(), TTL).unwrap();
        tables.next_for(&TOKEN, 1);
        assert_eq!(tables.bind(TOKEN, 2), Some(1));
        assert_eq!(tables.bind(TOKEN, 2), None, "rebinding the same link");
        assert_eq!(tables.next_for(&TOKEN, 2), Some((a, b"a".to_vec())));
        // The old link closing later doesn't unbind the new one.
        tables.unbind(&TOKEN, 1);
        assert_eq!(tables.owner(&TOKEN), Some(2));
    }

    #[test]
    fn queues_are_bounded_by_bytes_and_keep_the_oldest() {
        let mut tables = Tables::new();
        let packet = vec![0xAB; 1000];
        let fits = MAX_QUEUED_BYTES_PER_TOKEN / packet.len();
        for _ in 0..fits {
            assert!(tables.enqueue(TOKEN, packet.clone(), TTL).is_some());
        }
        assert!(tables.enqueue(TOKEN, packet.clone(), TTL).is_none(), "full");
        assert_eq!(queued(&tables), fits);
        assert_eq!(tables.get_queued_packets(&TOKEN).unwrap()[0].id, 0);
        assert!(
            tables.enqueue([0xDD; 16], packet, TTL).is_some(),
            "per token"
        );
    }

    #[test]
    fn expired_packets_are_neither_sent_nor_kept() {
        let mut tables = Tables::new();
        tables.bind(TOKEN, 1);
        tables.enqueue(TOKEN, b"old".to_vec(), Duration::ZERO);
        let fresh = tables.enqueue(TOKEN, b"new".to_vec(), TTL).unwrap();
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(tables.next_for(&TOKEN, 1), Some((fresh, b"new".to_vec())));
        tables.sweep_expired_messages();
        assert_eq!(queued(&tables), 1);
    }
}
