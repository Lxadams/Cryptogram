//! The cell stream end to end: real clients, the real relay logic
//! (`server::link`), and in-memory links that lose a set fraction of cells,
//! on Tokio's paused clock so minutes of 4-cells-a-second traffic run in
//! moments.

use super::*;
use crate::test_support::{cleanup, new_client};
use fec::test_util::Rng;
use server::link::{Relay, run_link};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

/// One end of an in-memory link. Each cell sent through it is lost with
/// the link's current loss rate, and every cell sent is logged (when, and
/// whether it carried a frame) as a capture would see it.
struct LossyEnd {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    loss: Arc<AtomicU64>,
    rng: Mutex<Rng>,
    log: Arc<Mutex<Vec<(Instant, bool)>>>,
    /// Set when the link is cut: both ends then fail, as a dead QUIC
    /// connection does.
    cut: watch::Receiver<bool>,
}

impl CellTransport for LossyEnd {
    fn send_cell(&self, cell: Vec<u8>) -> io::Result<()> {
        if *self.cut.borrow() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        assert_eq!(cell.len(), CELL_LEN, "every cell is the same size");
        let carries = !cell::parse(&cell).unwrap().frames.is_empty();
        self.log.lock().unwrap().push((Instant::now(), carries));
        let loss = f64::from_bits(self.loss.load(Ordering::Relaxed));
        if self.rng.lock().unwrap().unit() >= loss && self.tx.send(cell).is_err() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }

    async fn recv_cell(&self) -> io::Result<Vec<u8>> {
        let mut cut = self.cut.clone();
        let mut rx = self.rx.lock().await;
        tokio::select! {
            cell = rx.recv() => cell.ok_or_else(|| io::ErrorKind::BrokenPipe.into()),
            _ = cut.wait_for(|cut| *cut) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

/// A client's link to the relay: (client end, relay end), both losing
/// `loss` of what they send, as when the client's side is jammed, and
/// what cuts it.
fn lossy_link(loss: &Arc<AtomicU64>, seed: u64) -> (LossyEnd, LossyEnd, watch::Sender<bool>) {
    let (to_relay, from_client) = mpsc::unbounded_channel();
    let (to_client, from_relay) = mpsc::unbounded_channel();
    let (cut, cut_rx) = watch::channel(false);
    let end = |tx, rx, seed| LossyEnd {
        tx,
        rx: tokio::sync::Mutex::new(rx),
        loss: Arc::clone(loss),
        rng: Mutex::new(Rng(seed)),
        log: Arc::default(),
        cut: cut_rx.clone(),
    };
    (
        end(to_relay, from_relay, seed),
        end(to_client, from_client, seed ^ 0xFFFF),
        cut,
    )
}

fn set_loss(loss: &AtomicU64, value: f64) {
    loss.store(value.to_bits(), Ordering::Relaxed);
}

/// A client on the relay, running the real cell loop.
struct Peer {
    client: Arc<tokio::sync::Mutex<Client>>,
    shared: Arc<Shared>,
    loss: Arc<AtomicU64>,
    /// What the client sent, and what the relay sent it.
    sent: Arc<Mutex<Vec<(Instant, bool)>>>,
    received: Arc<Mutex<Vec<(Instant, bool)>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    cut: Option<watch::Sender<bool>>,
    token: RoutingToken,
}

impl Peer {
    fn shared() -> Arc<Shared> {
        Arc::new(Shared {
            queue: Mutex::default(),
            loss: Mutex::default(),
            status: watch::Sender::new(LinkStatus::Connecting),
            reconnect: Notify::new(),
        })
    }

    fn join(relay: &Arc<Relay>, seed: u64) -> Self {
        let client = new_client();
        let token = client.identity.routing_token;
        let mut peer = Self {
            client: Arc::new(tokio::sync::Mutex::new(client)),
            shared: Self::shared(),
            loss: Arc::default(),
            sent: Arc::default(),
            received: Arc::default(),
            tasks: Vec::new(),
            cut: None,
            token,
        };
        peer.start(relay, seed);
        peer
    }

    /// Start a fresh link to the relay, keeping what's queued. The previous
    /// link, if any, is cut first, and both its ends wind down the way they
    /// do when a real connection dies.
    async fn connect(&mut self, relay: &Arc<Relay>, seed: u64) {
        if let Some(cut) = self.cut.take() {
            cut.send_replace(true);
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        self.start(relay, seed);
    }

    fn start(&mut self, relay: &Arc<Relay>, seed: u64) {
        let (client_end, relay_end, cut) = lossy_link(&self.loss, seed);
        self.cut = Some(cut);
        self.sent = Arc::clone(&client_end.log);
        self.received = Arc::clone(&relay_end.log);
        let (shared, handler) = (
            Arc::clone(&self.shared),
            client_handler(Arc::clone(&self.client)),
        );
        self.tasks.push(tokio::spawn(async move {
            run_cells(&client_end, &shared, None, &handler).await;
        }));
        let (relay, token) = (Arc::clone(relay), self.token);
        self.tasks.push(tokio::spawn(async move {
            let _ = run_link(relay, Arc::new(relay_end), token, 0, Box::new(|| {})).await;
        }));
    }

    fn send(&self, out: Outgoing) {
        self.shared.queue.lock().unwrap().push(out);
    }

    async fn add(&self, other: &Peer) {
        let other_key = other.client.lock().await.identity.ed25519_public;
        let kx = self.client.lock().await.add_contact(other.token, other_key);
        self.send(kx);
    }

    async fn has_session_with(&self, other: &Peer) -> bool {
        self.client
            .lock()
            .await
            .e2e_sessions
            .contains_key(&other.token)
    }

    async fn message(&self, to: &Peer, text: &str) {
        let out = self
            .client
            .lock()
            .await
            .create_message(to.token, text.as_bytes())
            .unwrap();
        self.send(out);
    }

    async fn inbox(&self) -> Vec<String> {
        self.client
            .lock()
            .await
            .drain_inbox()
            .into_iter()
            .map(|(_, text, _)| String::from_utf8(text).unwrap())
            .collect()
    }

    async fn cleanup(&self) {
        cleanup(&[&*self.client.lock().await]);
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Wait (in simulated time) for `done`, checking once a second, for up to
/// `limit`.
async fn within(limit: Duration, mut done: impl AsyncFnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done().await {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}

/// Alice and Bob add each other and swap `count` messages each way,
/// with Alice's link losing `loss` of cells in both directions throughout
/// (contact requests included). Returns (seconds to connect, seconds for
/// the messages).
async fn chat_with_alice_jammed(loss: f64, count: usize) -> (u64, u64) {
    let relay = Arc::new(Relay::new([0; 32]));
    let alice = Peer::join(&relay, 1);
    let bob = Peer::join(&relay, 2);
    set_loss(&alice.loss, loss);

    let start = Instant::now();
    alice.add(&bob).await;
    bob.add(&alice).await;
    let connected = within(Duration::from_secs(600), async || {
        alice.has_session_with(&bob).await && bob.has_session_with(&alice).await
    })
    .await;
    assert!(connected, "contacts didn't connect at {loss} loss");
    let connect_secs = start.elapsed().as_secs();

    let start = Instant::now();
    for i in 0..count {
        alice.message(&bob, &format!("to bob {i}")).await;
        bob.message(&alice, &format!("to alice {i}")).await;
    }
    let (mut to_bob, mut to_alice) = (Vec::new(), Vec::new());
    within(Duration::from_secs(1800), async || {
        to_bob.extend(bob.inbox().await);
        to_alice.extend(alice.inbox().await);
        to_bob.len() >= count && to_alice.len() >= count
    })
    .await;
    to_bob.sort();
    to_alice.sort();
    let mut expect_bob: Vec<String> = (0..count).map(|i| format!("to bob {i}")).collect();
    let mut expect_alice: Vec<String> = (0..count).map(|i| format!("to alice {i}")).collect();
    expect_bob.sort();
    expect_alice.sort();
    assert_eq!(to_bob, expect_bob, "alice -> bob at {loss} loss");
    assert_eq!(to_alice, expect_alice, "bob -> alice at {loss} loss");
    {
        let (a, b) = (alice.client.lock().await, bob.client.lock().await);
        let (ab, ba) = (&a.e2e_sessions[&bob.token], &b.e2e_sessions[&alice.token]);
        assert_eq!(ab.send_chain_key, ba.recv_chain_key, "ratchets in step");
        assert_eq!(ba.send_chain_key, ab.recv_chain_key, "ratchets in step");
    }
    alice.cleanup().await;
    bob.cleanup().await;
    (connect_secs, start.elapsed().as_secs())
}

/// The done criterion: everything gets through, contact requests
/// included, from a clean link up to one losing 70% of cells each way,
/// with 6 messages each way so a PQ ratchet refresh rides along too.
#[tokio::test(start_paused = true)]
async fn everything_gets_through_from_0_to_70_percent_loss() {
    for loss in [0.0, 0.1, 0.3, 0.5, 0.7] {
        let (connect, chat) = chat_with_alice_jammed(loss, 6).await;
        println!(
            "{:.0}% loss: connected in {connect}s, 12 messages in {chat}s",
            loss * 100.0
        );
    }
}

/// What an observer counts: cells leave at the same average rate whether
/// the user is idle or sending, in both directions, and every one is the
/// same size (`LossyEnd` checks that).
#[tokio::test(start_paused = true)]
async fn cells_flow_at_the_same_rate_idle_or_busy() {
    let relay = Arc::new(Relay::new([0; 32]));
    let alice = Peer::join(&relay, 3);
    let bob = Peer::join(&relay, 4);
    alice.add(&bob).await;
    bob.add(&alice).await;
    assert!(
        within(Duration::from_secs(120), async || alice
            .has_session_with(&bob)
            .await
            && bob.has_session_with(&alice).await)
        .await
    );

    let rate = |log: &Mutex<Vec<(Instant, bool)>>, from: Instant, to: Instant| {
        let log = log.lock().unwrap();
        let cells = log.iter().filter(|(at, _)| (from..to).contains(at)).count();
        let busy = log
            .iter()
            .filter(|(at, carries)| (from..to).contains(at) && *carries)
            .count();
        (cells as f64 / (to - from).as_secs_f64(), busy)
    };
    // The relay still has spare symbols of the contact requests to deliver
    // for a few seconds after both ends are connected.
    tokio::time::sleep(Duration::from_secs(30)).await;
    let idle_from = Instant::now();
    tokio::time::sleep(Duration::from_secs(300)).await;
    let busy_from = Instant::now();
    for i in 0..60 {
        alice.message(&bob, &format!("busy {i}")).await;
    }
    tokio::time::sleep(Duration::from_secs(300)).await;
    let end = Instant::now();

    for (what, log) in [("alice sent", &alice.sent), ("bob received", &bob.received)] {
        let (idle, idle_busy) = rate(log, idle_from, busy_from);
        let (busy, busy_cells) = rate(log, busy_from, end);
        println!(
            "{what}: idle {idle:.2} cells/s, busy {busy:.2} cells/s ({busy_cells} carrying data)"
        );
        assert_eq!(idle_busy, 0, "{what}: nothing to carry while idle");
        assert!(busy_cells > 100, "{what}: {busy_cells} cells carried data");
        for rate in [idle, busy] {
            assert!(
                (3.6..4.4).contains(&rate),
                "{what}: idle {idle}, busy {busy}"
            );
        }
    }
    assert_eq!(bob.inbox().await.len(), 60);
    alice.cleanup().await;
    bob.cleanup().await;
}

/// Redundancy follows measured loss: on a clean link a message costs about
/// as many cells as the recipient needs symbols; on a lossy one, more, but
/// nowhere near a fixed 70%-loss budget on a clean link.
#[tokio::test(start_paused = true)]
async fn redundancy_adapts_to_measured_loss() {
    let mut cells_per_message = Vec::new();
    for loss in [0.0, 0.5] {
        let relay = Arc::new(Relay::new([0; 32]));
        let alice = Peer::join(&relay, 5);
        let bob = Peer::join(&relay, 6);
        alice.add(&bob).await;
        bob.add(&alice).await;
        assert!(
            within(Duration::from_secs(300), async || alice
                .has_session_with(&bob)
                .await
                && bob.has_session_with(&alice).await)
            .await
        );
        set_loss(&alice.loss, loss);
        // Let the estimate settle on the new loss rate first.
        tokio::time::sleep(Duration::from_secs(60)).await;
        let from = Instant::now();
        let messages = 20;
        for i in 0..messages {
            alice.message(&bob, &format!("m{i}")).await;
        }
        let mut got = 0;
        assert!(
            within(Duration::from_secs(1200), async || {
                got += bob.inbox().await.len();
                got == messages
            })
            .await
        );
        let carried = alice
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, carries)| *at >= from && *carries)
            .count();
        cells_per_message.push(carried as f64 / messages as f64);
        alice.cleanup().await;
        bob.cleanup().await;
    }
    println!(
        "cells per message: clean {:.1}, 50% loss {:.1}",
        cells_per_message[0], cells_per_message[1]
    );
    // A short message needs 3 symbols (4 with a PQ refresh), plus a spare.
    assert!(
        cells_per_message[0] < 6.0,
        "clean: {}",
        cells_per_message[0]
    );
    assert!(
        cells_per_message[1] > 1.5 * cells_per_message[0],
        "{cells_per_message:?}"
    );
    // Sending blind for 70% loss would cost 34+ per message.
    assert!(cells_per_message[1] < 20.0, "{cells_per_message:?}");
}

/// A link that drops mid-message: whatever wasn't confirmed is sent again
/// on the next link, from both ends, and the message arrives once.
#[tokio::test(start_paused = true)]
async fn a_dropped_link_picks_up_where_it_left_off() {
    let relay = Arc::new(Relay::new([0; 32]));
    let mut alice = Peer::join(&relay, 7);
    let mut bob = Peer::join(&relay, 8);
    alice.add(&bob).await;
    bob.add(&alice).await;
    assert!(
        within(Duration::from_secs(120), async || alice
            .has_session_with(&bob)
            .await
            && bob.has_session_with(&alice).await)
        .await
    );

    // Both links go dark right after the message is queued.
    set_loss(&alice.loss, 1.0);
    set_loss(&bob.loss, 1.0);
    alice.message(&bob, "across a reconnect").await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(bob.inbox().await.is_empty());

    // New, working links, as after a network change.
    set_loss(&alice.loss, 0.0);
    set_loss(&bob.loss, 0.0);
    alice.connect(&relay, 9).await;
    bob.connect(&relay, 10).await;
    let mut got = Vec::new();
    assert!(
        within(Duration::from_secs(120), async || {
            got.extend(bob.inbox().await);
            !got.is_empty()
        })
        .await
    );
    tokio::time::sleep(Duration::from_secs(30)).await;
    got.extend(bob.inbox().await);
    assert_eq!(got, ["across a reconnect"]);
    alice.cleanup().await;
    bob.cleanup().await;
}

/// A delivery the front end couldn't handle (its handler returned `None`)
/// isn't acknowledged, so the relay delivers it again.
#[tokio::test(start_paused = true)]
async fn an_unhandled_delivery_is_delivered_again() {
    let relay = Arc::new(Relay::new([0; 32]));
    let (alice_end, alice_relay_end, _alice_cut) = lossy_link(&Arc::default(), 11);
    let (bob_end, bob_relay_end, _bob_cut) = lossy_link(&Arc::default(), 12);
    let bob_token = [0xB; 16];
    for (token, end) in [([0xA; 16], alice_relay_end), (bob_token, bob_relay_end)] {
        let relay = Arc::clone(&relay);
        tokio::spawn(async move {
            let _ = run_link(relay, Arc::new(end), token, 0, Box::new(|| {})).await;
        });
    }
    // Bob's front end is "busy" for the first delivery, and takes the rest.
    let refused: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
    let handled: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let handler: Handler = {
        let (refused, handled) = (Arc::clone(&refused), Arc::clone(&handled));
        Arc::new(move |payload| {
            let (refused, handled) = (Arc::clone(&refused), Arc::clone(&handled));
            Box::pin(async move {
                let mut refused = refused.lock().unwrap();
                if refused.is_none() {
                    *refused = Some(payload);
                    return None;
                }
                handled.lock().unwrap().push(payload);
                Some(Vec::new())
            })
        })
    };
    let ignore: Handler = Arc::new(|_| Box::pin(async { Some(Vec::new()) }));
    let (alice_shared, bob_shared) = (Peer::shared(), Peer::shared());
    {
        let shared = Arc::clone(&alice_shared);
        tokio::spawn(async move { run_cells(&alice_end, &shared, None, &ignore).await });
        let shared = Arc::clone(&bob_shared);
        tokio::spawn(async move { run_cells(&bob_end, &shared, None, &handler).await });
    }
    let kx = new_client().create_kx_request(bob_token);
    alice_shared.queue.lock().unwrap().push(kx);
    tokio::time::sleep(Duration::from_secs(60)).await;

    let refused = refused
        .lock()
        .unwrap()
        .clone()
        .expect("something was delivered");
    assert!(
        handled.lock().unwrap().contains(&refused),
        "delivered again after being refused"
    );
}

// ---------------------------------------------------------------------
// Over real QUIC on localhost, against the real relay endpoint.
// ---------------------------------------------------------------------

const ACCESS: AccessKey = [0x42; 32];

/// A relay on a random local port: its address and key pin.
async fn real_relay() -> (SocketAddr, [u8; 32]) {
    let identity = server::tls::self_signed(vec!["localhost".into()]).unwrap();
    let pin = identity.pin;
    let endpoint = server::bind_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server::tls::server_config(identity).unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::run(
        endpoint,
        Arc::new(Relay::new(ACCESS)),
        server::site::Site::load().unwrap(),
    ));
    (addr, pin)
}

fn real_config(addr: SocketAddr, key_pin: [u8; 32], access_key: AccessKey) -> RelayConfig {
    RelayConfig {
        addr,
        server_name: "localhost".into(),
        key_pin,
        access_key,
    }
}

struct RealPeer {
    client: Arc<tokio::sync::Mutex<Client>>,
    link: RelayLink,
    token: RoutingToken,
}

impl RealPeer {
    async fn start(config: RelayConfig) -> Self {
        let client = new_client();
        let (token, secret) = (
            client.identity.routing_token,
            client.identity.token_secret.clone(),
        );
        let client = Arc::new(tokio::sync::Mutex::new(client));
        let link = RelayLink::start(config, secret, client_handler(Arc::clone(&client))).unwrap();
        Self {
            client,
            link,
            token,
        }
    }
}

/// The whole stack: QUIC with the pinned key and the post-quantum key
/// exchange, the hello, contact requests and a message each way.
#[tokio::test]
async fn two_apps_talk_through_a_real_relay() {
    let (addr, pin) = real_relay().await;
    let alice = RealPeer::start(real_config(addr, pin, ACCESS)).await;
    let bob = RealPeer::start(real_config(addr, pin, ACCESS)).await;
    alice
        .link
        .wait_until_up(Duration::from_secs(10))
        .await
        .unwrap();
    bob.link
        .wait_until_up(Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(alice.link.status(), LinkStatus::Up);

    for (me, them) in [(&alice, &bob), (&bob, &alice)] {
        let key = them.client.lock().await.identity.ed25519_public;
        let kx = me.client.lock().await.add_contact(them.token, key);
        me.link.send(kx);
    }
    let up = within(Duration::from_secs(30), async || {
        alice
            .client
            .lock()
            .await
            .e2e_sessions
            .contains_key(&bob.token)
            && bob
                .client
                .lock()
                .await
                .e2e_sessions
                .contains_key(&alice.token)
    })
    .await;
    assert!(up, "contacts connected over QUIC");

    for (me, them, text) in [(&alice, &bob, "hi bob"), (&bob, &alice, "hi alice")] {
        let out = me
            .client
            .lock()
            .await
            .create_message(them.token, text.as_bytes())
            .unwrap();
        me.link.send(out);
    }
    let mut got = Vec::new();
    let delivered = within(Duration::from_secs(30), async || {
        for peer in [&alice, &bob] {
            got.extend(
                peer.client
                    .lock()
                    .await
                    .drain_inbox()
                    .into_iter()
                    .map(|(_, text, _)| String::from_utf8(text).unwrap()),
            );
        }
        got.len() == 2
    })
    .await;
    got.sort();
    assert!(delivered, "{got:?}");
    assert_eq!(got, ["hi alice", "hi bob"]);
    cleanup(&[&*alice.client.lock().await, &*bob.client.lock().await]);
}

/// A relay that can't prove it holds the pinned key is refused during the
/// TLS handshake, whatever its certificate says.
#[tokio::test]
async fn a_relay_without_the_pinned_key_is_refused() {
    let (addr, pin) = real_relay().await;
    let mut wrong = pin;
    wrong[0] ^= 1;
    let peer = RealPeer::start(real_config(addr, wrong, ACCESS)).await;
    let err = peer
        .link
        .wait_until_up(Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("handshake"), "{err}");
    cleanup(&[&*peer.client.lock().await]);
}

/// Without the right access key the relay never answers the hello: to it,
/// this is just someone visiting the website.
#[tokio::test]
async fn without_the_access_key_the_relay_never_answers() {
    let (addr, pin) = real_relay().await;
    let peer = RealPeer::start(real_config(addr, pin, [0u8; 32])).await;
    assert!(
        peer.link
            .wait_until_up(Duration::from_secs(3))
            .await
            .is_err()
    );
    assert_eq!(peer.link.status(), LinkStatus::Connecting);
    cleanup(&[&*peer.client.lock().await]);
}

#[tokio::test]
async fn relay_addresses_are_used_as_is_and_settings_are_checked() {
    let pin = hex::encode([1u8; 32]);
    let config = RelayConfig::from_settings("203.0.113.7:443", None, &pin, &pin)
        .await
        .unwrap();
    assert_eq!(config.addr, "203.0.113.7:443".parse().unwrap());
    assert_eq!(config.server_name, "203.0.113.7", "no name, no SNI");
    let config = RelayConfig::from_settings("[2001:db8::1]:443", Some("relay.example"), &pin, &pin)
        .await
        .unwrap();
    assert_eq!(config.addr, "[2001:db8::1]:443".parse().unwrap());
    assert_eq!(config.server_name, "relay.example");
    assert!(
        RelayConfig::from_settings("203.0.113.7", None, &pin, &pin)
            .await
            .is_err(),
        "needs a port"
    );
    assert!(
        RelayConfig::from_settings("203.0.113.7:443", None, "beef", &pin)
            .await
            .is_err(),
        "a short pin"
    );
}
