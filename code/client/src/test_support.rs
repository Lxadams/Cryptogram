//! Helpers shared by the unit-test modules (`lib.rs`, `transport`).

use crate::{Client, SymmetricSessionState};
use std::net::SocketAddr;

pub(crate) use fec::test_util::Rng;

/// What the relay does to a client's packet before forwarding it: strip
/// the sender's link layer, the routing token and any admission tag,
/// leaving the inner payload (the recipient's own link layer is re-added
/// and removed symmetrically, so tests skip it).
pub(crate) fn strip_link(packet: &[u8], link_key: &[u8; 32]) -> Vec<u8> {
    let (packet_type, _) = relay_link::header(packet).unwrap();
    let plaintext = relay_link::open(link_key, packet).unwrap();
    let (_, _, inner) = relay_link::parse_data(packet_type, &plaintext).unwrap();
    inner.to_vec()
}

/// `strip_link` for a packet `sender` just produced.
pub(crate) fn relay(packet: &[u8], sender: &Client) -> Vec<u8> {
    strip_link(packet, &sender.link_master_key)
}

/// A fresh client whose persistence points at a scratch path.
pub(crate) fn new_client() -> Client {
    let addr: SocketAddr = "127.0.0.1:4430".parse().unwrap();
    let mut client = Client::new(addr);
    client.state_path = std::env::temp_dir()
        .join(format!(
            "e2e-test-{}.json",
            hex::encode(client.identity.routing_token)
        ))
        .to_string_lossy()
        .into_owned();
    client
}

/// Deliver `packet` from `sender` to `receiver` on a clean link, then each
/// reply the other way, until one side has nothing to send. Returns the
/// type byte of every packet delivered, in order.
pub(crate) fn exchange(sender: &mut Client, receiver: &mut Client, mut packet: Vec<u8>) -> Vec<u8> {
    let mut kinds = Vec::new();
    let (mut from, mut to) = (sender, receiver);
    loop {
        let inner = relay(&packet, from);
        kinds.push(inner[0]);
        assert!(kinds.len() <= 8, "handshake didn't settle: {kinds:x?}");
        match to.handle_incoming_packet(&inner).unwrap() {
            Some(reply) => packet = reply,
            None => return kinds,
        }
        std::mem::swap(&mut from, &mut to);
    }
}

/// Establish an E2E session the way two people do: `initiator` adds
/// `responder` first (so `responder`, not having added it back yet, drops
/// its KeyExchange), then `responder` adds `initiator`, and their replies go
/// back and forth on a clean link until neither has anything left to send.
pub(crate) fn connect(initiator: &mut Client, responder: &mut Client) {
    let early = initiator.add_contact(
        responder.identity.routing_token,
        responder.identity.ed25519_public,
    );
    assert_eq!(
        exchange(initiator, responder, early),
        [0x02],
        "not added back yet, so dropped"
    );
    let kx = responder.add_contact(
        initiator.identity.routing_token,
        initiator.identity.ed25519_public,
    );
    exchange(responder, initiator, kx);
    assert_eq!(
        session(initiator, responder).root_key,
        session(responder, initiator).root_key,
        "both ends must share one session"
    );
    assert!(initiator.is_connected(&responder.identity.routing_token));
    assert!(responder.is_connected(&initiator.identity.routing_token));
}

/// Two fresh clients, ordered so the first sends the SessionEstablish
/// (it has the lower routing token).
pub(crate) fn establisher_and_responder() -> (Client, Client) {
    let (a, b) = (new_client(), new_client());
    if a.identity.routing_token < b.identity.routing_token {
        (a, b)
    } else {
        (b, a)
    }
}

/// Two fresh clients with an E2E session between them.
pub(crate) fn connected_pair() -> (Client, Client) {
    let (mut alice, mut bob) = (new_client(), new_client());
    connect(&mut alice, &mut bob);
    (alice, bob)
}

pub(crate) fn session<'a>(of: &'a Client, with: &Client) -> &'a SymmetricSessionState {
    &of.e2e_sessions[&with.identity.routing_token]
}

pub(crate) fn inbox_texts(client: &mut Client) -> Vec<String> {
    client
        .drain_inbox()
        .into_iter()
        .map(|(_, pt, _)| String::from_utf8(pt).unwrap())
        .collect()
}

/// Remove the clients' scratch state files.
pub(crate) fn cleanup(clients: &[&Client]) {
    for c in clients {
        let _ = std::fs::remove_file(&c.state_path);
    }
}
