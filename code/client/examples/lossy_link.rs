//! Real-network check of the FEC transport: two clients (Alice and Bob,
//! in this one process) talk through the real relay over real UDP. Each
//! client sits behind a tiny proxy that can drop packets. The jammed peer's
//! proxy loses `loss` of everything it carries in both directions while
//! that peer connects to the relay (the handshake), and again once their
//! E2E session is up — so Alice -> Bob exercises a jammed sender and
//! Bob -> Alice a jammed receiver (with the default `jammed=alice`).
//!
//!   cargo run --example lossy_link -- <relay_pubkey_hex> [loss] [jammed] [messages]
//!
//!   loss      fraction of packets the jammed side drops (default 0.7)
//!   jammed    alice | bob | both | none (default alice)
//!   messages  messages sent in each direction (default 30)
//!
//! Needs the relay running (./runserver.sh, or `cargo run` in code/server);
//! SERVER_ADDR overrides its address (default 127.0.0.1:4430). Exits
//! non-zero unless every message arrived, in the order it was sent, and
//! both ratchets stayed in step.

use anyhow::{Result, anyhow, bail};
use client::{Client, RoutingToken, parse_verifying_key, perform_handshake, send_burst};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// A UDP hop between one client and the relay that drops packets with a
/// probability that can be switched on mid-run.
struct LossyProxy {
    /// Where the client sends (the client's `server_addr`).
    addr: SocketAddr,
    /// Drop probability, stored as `f64` bits.
    loss: Arc<AtomicU64>,
    dropped: Arc<AtomicUsize>,
    carried: Arc<AtomicUsize>,
}

impl LossyProxy {
    async fn start(relay: SocketAddr) -> Result<Self> {
        let client_side = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let relay_side = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let proxy = Self {
            addr: client_side.local_addr()?,
            loss: Arc::new(AtomicU64::new(0f64.to_bits())),
            dropped: Arc::new(AtomicUsize::new(0)),
            carried: Arc::new(AtomicUsize::new(0)),
        };
        let client_addr = Arc::new(Mutex::new(None::<SocketAddr>));

        // client -> relay
        let (from, to, seen) = (client_side.clone(), relay_side.clone(), client_addr.clone());
        let (loss, dropped, carried) = proxy.counters();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, src)) = from.recv_from(&mut buf).await {
                *seen.lock().await = Some(src);
                if passes(&loss, &dropped, &carried) {
                    let _ = to.send_to(&buf[..len], relay).await;
                }
            }
        });
        // relay -> client
        let (from, to, seen) = (relay_side, client_side, client_addr);
        let (loss, dropped, carried) = proxy.counters();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, _)) = from.recv_from(&mut buf).await {
                let Some(client) = *seen.lock().await else {
                    continue;
                };
                if passes(&loss, &dropped, &carried) {
                    let _ = to.send_to(&buf[..len], client).await;
                }
            }
        });
        Ok(proxy)
    }

    fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        (
            self.loss.clone(),
            self.dropped.clone(),
            self.carried.clone(),
        )
    }

    fn jam(&self, loss: f64) {
        self.loss.store(loss.to_bits(), Ordering::Relaxed);
    }

    /// (dropped, carried) since the last call.
    fn take_counts(&self) -> (usize, usize) {
        (
            self.dropped.swap(0, Ordering::Relaxed),
            self.carried.swap(0, Ordering::Relaxed),
        )
    }
}

fn passes(loss: &AtomicU64, dropped: &AtomicUsize, carried: &AtomicUsize) -> bool {
    let p = f64::from_bits(loss.load(Ordering::Relaxed));
    let roll = (OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
    if roll < p {
        dropped.fetch_add(1, Ordering::Relaxed);
        false
    } else {
        carried.fetch_add(1, Ordering::Relaxed);
        true
    }
}

struct Peer {
    client: Arc<Mutex<Client>>,
    socket: Arc<UdpSocket>,
    proxy: LossyProxy,
    token: RoutingToken,
    ed25519: VerifyingKey,
}

impl Peer {
    /// A client behind a proxy of its own, connected to the relay through
    /// `connect_loss` loss each way.
    async fn start(
        name: &str,
        relay: SocketAddr,
        relay_pub: &VerifyingKey,
        connect_loss: f64,
    ) -> Result<Self> {
        let proxy = LossyProxy::start(relay).await?;
        let mut client = Client::new(proxy.addr);
        client.local_name = name.to_string();
        client.state_path = std::env::temp_dir()
            .join(format!("lossy-link-{name}-{}.json", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        proxy.jam(connect_loss);
        let started = Instant::now();
        perform_handshake(&mut client, &socket, relay_pub).await?;
        let (dropped, carried) = proxy.take_counts();
        println!(
            "{name}: connected in {:.1}s through {:.0}% loss ({dropped}/{} packets dropped)",
            started.elapsed().as_secs_f64(),
            connect_loss * 100.0,
            dropped + carried,
        );
        proxy.jam(0.0);
        // The syncs `perform_handshake` ends with may have been lost too,
        // leaving the relay not knowing where we are. The app's next
        // keepalive tick syncs again; this is that tick, on a clean link.
        for packet in client.keepalive() {
            socket.send_to(&packet, proxy.addr).await?;
        }
        let (token, ed25519) = (
            client.identity.routing_token,
            client.identity.ed25519_public,
        );
        let client = Arc::new(Mutex::new(client));

        // Receive loop, exactly like the CLI's.
        let (rx_socket, rx_client) = (socket.clone(), client.clone());
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, _)) = rx_socket.recv_from(&mut buf).await {
                let mut c = rx_client.lock().await;
                for packet in c.handle_relay_packet(&buf[..len]) {
                    let _ = rx_socket.send_to(&packet, c.server_addr).await;
                }
            }
        });
        Ok(Self {
            client,
            socket,
            proxy,
            token,
            ed25519,
        })
    }

    async fn has_session_with(&self, other: &Peer) -> bool {
        self.client.lock().await.is_connected(&other.token)
    }
}

/// How long after the last burst `one_way` waits for everything to arrive.
/// The relay sends each recipient's packets 5 ms apart, so 30 messages'
/// symbols take about 6 s to leave it, and it resends anything not acked:
/// 2 s later, then backing off.
const DELIVERY_DEADLINE: Duration = Duration::from_secs(60);

/// Send `count` messages from `from` to `to` as paced FEC bursts, then wait
/// until they've all arrived, or `DELIVERY_DEADLINE` passes. Returns how
/// many arrived, and whether in the order they were sent.
async fn one_way(from: &Peer, to: &Peer, count: usize, label: &str) -> Result<(usize, bool)> {
    let _ = to.client.lock().await.drain_inbox(); // start from an empty inbox
    from.proxy.take_counts();
    to.proxy.take_counts();

    let mut sent = Vec::new();
    for i in 0..count {
        let text = format!("{label} #{i}");
        let packets = {
            let mut c = from.client.lock().await;
            c.create_fec_packets(to.token, text.as_bytes())?
        };
        let server_addr = from.proxy.addr;
        send_burst(&from.socket, server_addr, &packets).await?;
        sent.push(text);
    }

    let last_sent = Instant::now();
    let mut got: Vec<String> = Vec::new();
    while sent.iter().any(|s| !got.contains(s)) && last_sent.elapsed() < DELIVERY_DEADLINE {
        tokio::time::sleep(Duration::from_millis(100)).await;
        got.extend(
            to.client
                .lock()
                .await
                .drain_inbox()
                .into_iter()
                .map(|m| String::from_utf8_lossy(&m.text).into_owned()),
        );
    }
    let waited = last_sent.elapsed();
    let delivered = sent.iter().filter(|s| got.contains(*s)).count();
    // In order if each message arrived after every one sent before it.
    let in_order = got
        .iter()
        .filter_map(|text| sent.iter().position(|s| s == text))
        .is_sorted();

    let (a_dropped, a_carried) = from.proxy.take_counts();
    let (b_dropped, b_carried) = to.proxy.take_counts();
    let pct = |d: usize, c: usize| 100.0 * d as f64 / (d + c).max(1) as f64;
    println!(
        "{label}: {delivered}/{count} delivered{}, {:.1}s after the last was sent | sender's link dropped {a_dropped}/{} ({:.1}%), receiver's link dropped {b_dropped}/{} ({:.1}%)",
        if in_order {
            " in order"
        } else {
            " OUT OF ORDER"
        },
        waited.as_secs_f64(),
        a_dropped + a_carried,
        pct(a_dropped, a_carried),
        b_dropped + b_carried,
        pct(b_dropped, b_carried),
    );
    Ok((delivered, in_order))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let relay_pub = parse_verifying_key(args.get(1).ok_or_else(|| {
        anyhow!("usage: lossy_link <relay_pubkey_hex> [loss] [jammed] [messages]")
    })?)?;
    let loss: f64 = args.get(2).map_or(Ok(0.7), |s| s.parse())?;
    let jammed = args.get(3).map_or("alice", String::as_str).to_string();
    let messages: usize = args.get(4).map_or(Ok(30), |s| s.parse())?;
    let relay_raw = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:4430".into());
    let relay: SocketAddr = tokio::net::lookup_host(&relay_raw)
        .await?
        .next()
        .ok_or_else(|| anyhow!("can't resolve {relay_raw}"))?;

    let loss_for = |peer: &str| {
        if jammed == peer || jammed == "both" {
            loss
        } else {
            0.0
        }
    };
    let (alice_loss, bob_loss) = (loss_for("alice"), loss_for("bob"));
    let alice = Peer::start("alice", relay, &relay_pub, alice_loss).await?;
    let bob = Peer::start("bob", relay, &relay_pub, bob_loss).await?;

    // Contact exchange on a clean link (QR codes in the real app; out of
    // scope for the lossy part). Each adds the other.
    for (me, them) in [(&alice, &bob), (&bob, &alice)] {
        let kx = me
            .client
            .lock()
            .await
            .add_contact(them.token, them.ed25519)?;
        me.socket.send_to(&kx, me.proxy.addr).await?;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while !(alice.has_session_with(&bob).await && bob.has_session_with(&alice).await) {
        if Instant::now() > deadline {
            bail!("E2E session didn't come up on a clean link — is the relay running?");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!(
        "Session up. Jamming: {jammed} at {:.0}% loss, {messages} messages each way.",
        loss * 100.0
    );

    alice.proxy.jam(alice_loss);
    bob.proxy.jam(bob_loss);

    let (to_bob, bob_in_order) = one_way(&alice, &bob, messages, "alice->bob").await?;
    let (to_alice, alice_in_order) = one_way(&bob, &alice, messages, "bob->alice").await?;

    let (a, b) = (alice.client.lock().await, bob.client.lock().await);
    let in_step = a.e2e_sessions[&bob.token].send_chain_key
        == b.e2e_sessions[&alice.token].recv_chain_key
        && b.e2e_sessions[&alice.token].send_chain_key == a.e2e_sessions[&bob.token].recv_chain_key;
    println!("Ratchets in step: {in_step}");
    for c in [&*a, &*b] {
        let _ = std::fs::remove_file(&c.state_path);
    }
    if to_bob == messages && to_alice == messages && bob_in_order && alice_in_order && in_step {
        println!("PASS");
        Ok(())
    } else {
        bail!("FAIL")
    }
}
