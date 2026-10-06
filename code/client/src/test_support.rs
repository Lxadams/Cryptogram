//! Helpers shared by the unit-test modules (`lib.rs`, `transport`).

use crate::{Client, SymmetricSessionState};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use std::net::SocketAddr;

pub(crate) use fec::test_util::Rng;

/// What the relay does to a client's packet before forwarding it: strip
/// the sender's link layer and the routing token, leaving the inner payload
/// (the recipient's own link layer is re-added and removed symmetrically,
/// so tests skip it).
pub(crate) fn strip_link(packet: &[u8], link_key: &[u8; 32]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(link_key));
    let inner = cipher
        .decrypt(XNonce::from_slice(&packet[5..29]), &packet[29..])
        .unwrap();
    inner[16..].to_vec()
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

/// Establish an E2E session (KeyExchange → reply → SessionEstablish,
/// exactly as over the wire) on a clean link.
pub(crate) fn connect(initiator: &mut Client, responder: &mut Client) {
    initiator.pending_contacts.insert(
        responder.identity.routing_token,
        responder.identity.ed25519_public,
    );
    let kx = initiator.create_kx_request(responder.identity.routing_token);
    let reply = responder
        .handle_incoming_packet(&relay(&kx, initiator))
        .unwrap()
        .unwrap();
    let est = initiator
        .handle_incoming_packet(&relay(&reply, responder))
        .unwrap()
        .unwrap();
    responder
        .handle_incoming_packet(&relay(&est, initiator))
        .unwrap();
    assert!(
        responder
            .e2e_sessions
            .contains_key(&initiator.identity.routing_token)
    );
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
