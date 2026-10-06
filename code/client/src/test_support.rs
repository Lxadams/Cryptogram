//! Helpers shared by the unit-test modules (`lib.rs`, `transport`, `link`).

use crate::{Client, Outgoing, SymmetricSessionState};

pub(crate) use fec::test_util::Rng;

/// A fresh client whose persistence points at a scratch path.
pub(crate) fn new_client() -> Client {
    let mut client = Client::new();
    client.state_path = std::env::temp_dir()
        .join(format!(
            "e2e-test-{}.json",
            hex::encode(client.identity.routing_token)
        ))
        .to_string_lossy()
        .into_owned();
    client
}

/// Hand `to` just enough of `out`'s symbols to rebuild it, as the relay
/// would over a clean link. Returns `to`'s reply, if it has one.
pub(crate) fn deliver(to: &mut Client, mut out: Outgoing) -> Option<Outgoing> {
    let mut reply = None;
    for payload in out.take(out.needed()) {
        if let Some(r) = to.handle_incoming_packet(&payload).unwrap() {
            assert!(reply.is_none(), "one reply per object");
            reply = Some(r);
        }
    }
    reply
}

/// The bare 0x02/0x04 payload a contact-request object carries: what its
/// symbols rebuild.
pub(crate) fn control_payload(mut out: Outgoing) -> Vec<u8> {
    let mut rx = fec::Reassembler::default();
    for symbol in out.take(out.needed()) {
        assert_eq!(symbol[0], crate::transport::CONTROL_SYMBOL);
        if let Some(object) = rx
            .ingest(0u8, &symbol[17..], std::time::Instant::now())
            .unwrap()
        {
            return crate::transport::unbundle(&object).unwrap()[0].to_vec();
        }
    }
    panic!("the object didn't rebuild from its own symbols");
}

/// Deliver `out` from `sender` to `receiver` on a clean link, then each
/// reply the other way, until one side has nothing to send. Returns the
/// type of every payload delivered (0x02 KeyExchange, 0x04
/// SessionEstablish), in order.
pub(crate) fn exchange(sender: &mut Client, receiver: &mut Client, mut out: Outgoing) -> Vec<u8> {
    let mut kinds = Vec::new();
    let (mut from, mut to) = (sender, receiver);
    loop {
        kinds.push(out.kind());
        assert!(kinds.len() <= 8, "handshake didn't settle: {kinds:x?}");
        match deliver(to, out) {
            Some(reply) => out = reply,
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
