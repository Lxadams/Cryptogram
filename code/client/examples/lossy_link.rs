//! Real-network check of the link: two clients (Alice and Bob, in this one
//! process) talk through the real relay over real QUIC. Each client sits
//! behind a small UDP proxy that can drop packets, and that records every
//! datagram it carries, which is what anyone watching that client's network
//! would capture.
//!
//!   cargo run --example lossy_link -- <relay_pubkey_hex> <access_key_hex> [loss|sweep] [jammed] [messages]
//!
//!   loss      fraction of packets the jammed side drops (default 0.7), or
//!             `sweep` to run 0%, 10%, ... 70% in turn
//!   jammed    alice | bob | both | none (default alice)
//!   messages  messages sent in each direction at each loss level (default 10)
//!
//! Needs the relay running (./runserver.sh, or `cargo run` in code/server;
//! `server --print-pubkey` and `--print-access-key` print the two keys).
//! SERVER_ADDR overrides its address (default 127.0.0.1:4430). Set CAPTURE
//! to a file name to also save Alice's side as a pcap file for Wireshark,
//! and CAPTURE_SECS to how long the capture's idle and busy spells last
//! (default 20; longer gives steadier rates).
//!
//! Contacts connect on a clean link, then the jammed side's proxy drops
//! `loss` of everything it carries in both directions, so Alice -> Bob is a
//! jammed sender and Bob -> Alice a jammed receiver (with `jammed=alice`).
//! At the end it reports, from Alice's capture, the sizes of the QUIC
//! packets after the handshake and the packet rate while idle and while
//! sending. Exits non-zero unless every message arrived, both ratchets
//! stayed in step and every post-handshake packet was the same size.

use anyhow::{Result, anyhow, bail};
use client::{
    Client, RoutingToken,
    link::{RelayConfig, RelayLink, client_handler},
};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::UdpSocket;

/// One datagram the proxy carried (or dropped).
#[derive(Clone)]
struct Captured {
    at: Instant,
    wall: SystemTime,
    to_relay: bool,
    bytes: Vec<u8>,
    dropped: bool,
}

impl Captured {
    /// QUIC long header (handshake) rather than short header (1-RTT).
    fn long_header(&self) -> bool {
        self.bytes[0] & 0x80 != 0
    }
}

/// A UDP hop between one client and the relay that drops packets with a
/// probability that can be changed mid-run, and records everything.
struct LossyProxy {
    /// Where the client sends (its relay address).
    addr: SocketAddr,
    relay: SocketAddr,
    /// Drop probability, stored as `f64` bits.
    loss: Arc<AtomicU64>,
    capture: Arc<Mutex<Vec<Captured>>>,
    /// Kept for the pcap: the client's address as the proxy sees it.
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl LossyProxy {
    async fn start(relay: SocketAddr) -> Result<Self> {
        let client_side = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let relay_side = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let proxy = Self {
            addr: client_side.local_addr()?,
            relay,
            loss: Arc::new(AtomicU64::new(0f64.to_bits())),
            capture: Arc::default(),
            client_addr: Arc::default(),
        };
        for to_relay in [true, false] {
            let (from, to) = match to_relay {
                true => (client_side.clone(), relay_side.clone()),
                false => (relay_side.clone(), client_side.clone()),
            };
            let (loss, capture, client_addr) = (
                proxy.loss.clone(),
                proxy.capture.clone(),
                proxy.client_addr.clone(),
            );
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok((len, src)) = from.recv_from(&mut buf).await {
                    let dest = if to_relay {
                        *client_addr.lock().unwrap() = Some(src);
                        relay
                    } else {
                        match *client_addr.lock().unwrap() {
                            Some(client) => client,
                            None => continue,
                        }
                    };
                    let p = f64::from_bits(loss.load(Ordering::Relaxed));
                    let dropped = unit() < p;
                    capture.lock().unwrap().push(Captured {
                        at: Instant::now(),
                        wall: SystemTime::now(),
                        to_relay,
                        bytes: buf[..len].to_vec(),
                        dropped,
                    });
                    if !dropped {
                        let _ = to.send_to(&buf[..len], dest).await;
                    }
                }
            });
        }
        Ok(proxy)
    }

    fn jam(&self, loss: f64) {
        self.loss.store(loss.to_bits(), Ordering::Relaxed);
    }

    /// (dropped, carried) since `since`.
    fn counts(&self, since: Instant) -> (usize, usize) {
        let capture = self.capture.lock().unwrap();
        let recent = capture.iter().filter(|c| c.at >= since);
        let dropped = recent.clone().filter(|c| c.dropped).count();
        (dropped, recent.count() - dropped)
    }
}

fn unit() -> f64 {
    (OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

struct Peer {
    client: Arc<tokio::sync::Mutex<Client>>,
    link: RelayLink,
    proxy: LossyProxy,
    token: RoutingToken,
    ed25519: VerifyingKey,
}

impl Peer {
    async fn start(name: &str, relay: SocketAddr, pin: &str, access: &str) -> Result<Self> {
        let proxy = LossyProxy::start(relay).await?;
        let mut client = Client::new();
        client.local_name = name.to_string();
        client.state_path = std::env::temp_dir()
            .join(format!("lossy-link-{name}-{}.json", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let (token, ed25519, secret) = (
            client.identity.routing_token,
            client.identity.ed25519_public,
            client.identity.token_secret.clone(),
        );
        let server_name = std::env::var("SERVER_NAME").unwrap_or_else(|_| "localhost".into());
        let config =
            RelayConfig::from_settings(&proxy.addr.to_string(), Some(&server_name), pin, access)
                .await?;
        let client = Arc::new(tokio::sync::Mutex::new(client));
        let link = RelayLink::start(config, secret, client_handler(client.clone()))?;
        link.wait_until_up(Duration::from_secs(15)).await?;
        Ok(Self {
            client,
            link,
            proxy,
            token,
            ed25519,
        })
    }

    async fn has_session_with(&self, other: &Peer) -> bool {
        self.client
            .lock()
            .await
            .e2e_sessions
            .contains_key(&other.token)
    }

    async fn inbox(&self) -> Vec<String> {
        self.client
            .lock()
            .await
            .drain_inbox()
            .into_iter()
            .map(|(_, pt, _)| String::from_utf8_lossy(&pt).into_owned())
            .collect()
    }
}

/// Send `count` messages each way at once, and wait for them. Returns how
/// many arrived in each direction.
async fn exchange(alice: &Peer, bob: &Peer, count: usize, label: &str) -> Result<(usize, usize)> {
    let since = Instant::now();
    let _ = (alice.inbox().await, bob.inbox().await);
    for i in 0..count {
        for (from, to, dir) in [(alice, bob, "a->b"), (bob, alice, "b->a")] {
            let text = format!("{label} {dir} #{i}");
            let message = from
                .client
                .lock()
                .await
                .create_message(to.token, text.as_bytes())?;
            from.link.send(message);
        }
    }
    // Plenty, at 4 cells a second: the heaviest case (70% loss each way
    // on one side) takes a few cells per message per percent of loss.
    let deadline = Instant::now() + Duration::from_secs(60 + 15 * count as u64);
    let (mut to_bob, mut to_alice) = (Vec::new(), Vec::new());
    while Instant::now() < deadline && (to_bob.len() < count || to_alice.len() < count) {
        tokio::time::sleep(Duration::from_millis(250)).await;
        to_bob.extend(bob.inbox().await);
        to_alice.extend(alice.inbox().await);
    }
    let (a_dropped, a_carried) = alice.proxy.counts(since);
    let (b_dropped, b_carried) = bob.proxy.counts(since);
    let pct = |d: usize, c: usize| 100.0 * d as f64 / (d + c).max(1) as f64;
    println!(
        "{label}: alice->bob {}/{count}, bob->alice {}/{count} in {:.0}s | alice's link dropped {:.1}%, bob's {:.1}%",
        to_bob.len(),
        to_alice.len(),
        since.elapsed().as_secs_f64(),
        pct(a_dropped, a_carried),
        pct(b_dropped, b_carried),
    );
    Ok((to_bob.len(), to_alice.len()))
}

/// What an observer of Alice's link saw, per direction: QUIC long-header
/// (handshake) packets, the sizes of the rest, and the packet rate on the
/// clean link while idle and while both sides were sending. Returns
/// whether every post-handshake packet was the same size.
fn report_capture(
    capture: &[Captured],
    idle: (Instant, Instant),
    busy: (Instant, Instant),
) -> bool {
    let mut one_size = true;
    for to_relay in [true, false] {
        let dir: Vec<&Captured> = capture.iter().filter(|c| c.to_relay == to_relay).collect();
        let handshake = dir.iter().filter(|c| c.long_header()).count();
        let mut sizes: BTreeMap<usize, usize> = BTreeMap::new();
        for c in dir.iter().filter(|c| !c.long_header()) {
            *sizes.entry(c.bytes.len()).or_default() += 1;
        }
        let rate = |(from, to): (Instant, Instant)| {
            let gaps: Vec<f64> = dir
                .iter()
                .filter(|c| c.at >= from && c.at < to)
                .map(|c| c.at)
                .collect::<Vec<_>>()
                .windows(2)
                .map(|w| (w[1] - w[0]).as_secs_f64())
                .collect();
            let per_sec = (gaps.len() + 1) as f64 / (to - from).as_secs_f64();
            let mean = gaps.iter().sum::<f64>() / gaps.len().max(1) as f64;
            let sd = (gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>()
                / gaps.len().max(1) as f64)
                .sqrt();
            (per_sec, sd / mean.max(1e-9))
        };
        let (idle_rate, idle_cv) = rate(idle);
        let (busy_rate, busy_cv) = rate(busy);
        println!(
            "  {}: {} packets, {handshake} handshake (long header); after it, sizes {:?}",
            if to_relay {
                "alice -> relay"
            } else {
                "relay -> alice"
            },
            dir.len(),
            sizes,
        );
        println!(
            "    clean link: idle {idle_rate:.2} packets/s (gap CV {idle_cv:.2}), sending {busy_rate:.2} packets/s (gap CV {busy_cv:.2})"
        );
        one_size &= sizes.len() == 1;
    }
    one_size
}

/// Alice's side as a pcap file (IPv4/UDP, the real ports, 127.0.0.1), for
/// Wireshark: it decodes the QUIC handshake's ClientHello (SNI, ALPN `h3`,
/// key exchange groups), and shows the rest as protected 1-RTT packets.
fn write_pcap(
    path: &str,
    capture: &[Captured],
    client: SocketAddr,
    relay: SocketAddr,
) -> Result<()> {
    let mut out = Vec::new();
    // Global header: magic, v2.4, zone 0, sigfigs 0, snaplen, LINKTYPE_IPV4.
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&228u32.to_le_bytes());
    for c in capture.iter().filter(|c| !c.dropped) {
        let (src, dst) = if c.to_relay {
            (client, relay)
        } else {
            (relay, client)
        };
        let since_epoch = c.wall.duration_since(SystemTime::UNIX_EPOCH)?;
        let total = 20 + 8 + c.bytes.len();
        out.extend_from_slice(&(since_epoch.as_secs() as u32).to_le_bytes());
        out.extend_from_slice(&since_epoch.subsec_micros().to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        // IPv4 header (no options, checksum left 0), then UDP (checksum 0).
        out.extend_from_slice(&[
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            17,
            0,
            0,
        ]);
        out.extend_from_slice(&[127, 0, 0, 1, 127, 0, 0, 1]);
        out.extend_from_slice(&src.port().to_be_bytes());
        out.extend_from_slice(&dst.port().to_be_bytes());
        out.extend_from_slice(&((8 + c.bytes.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&c.bytes);
    }
    std::fs::write(path, out)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage =
        "usage: lossy_link <relay_pubkey_hex> <access_key_hex> [loss|sweep] [jammed] [messages]";
    let pin = args.get(1).ok_or_else(|| anyhow!(usage))?;
    let access = args.get(2).ok_or_else(|| anyhow!(usage))?;
    let levels: Vec<f64> = match args.get(3).map(String::as_str) {
        Some("sweep") => (0..=7).map(|i| i as f64 / 10.0).collect(),
        other => vec![other.map_or(Ok(0.7), str::parse)?],
    };
    let jammed = args.get(4).map_or("alice", String::as_str).to_string();
    let messages: usize = args.get(5).map_or(Ok(10), |s| s.parse())?;
    let relay_raw = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:4430".into());
    let relay: SocketAddr = relay_raw
        .parse()
        .map_err(|_| anyhow!("SERVER_ADDR must be an ip:port here ({relay_raw})"))?;

    let alice = Peer::start("alice", relay, pin, access).await?;
    let bob = Peer::start("bob", relay, pin, access).await?;

    // Contact exchange on a clean link. Each adds the other.
    for (me, them) in [(&alice, &bob), (&bob, &alice)] {
        let kx = me.client.lock().await.add_contact(them.token, them.ed25519);
        me.link.send(kx);
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(alice.has_session_with(&bob).await && bob.has_session_with(&alice).await) {
        if Instant::now() > deadline {
            bail!("E2E session didn't come up on a clean link");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // For the capture, on the clean link: a quiet spell, then both sides
    // sending for about as long (a message a second each way keeps the
    // cells busy). An observer should see no difference.
    let spell: u64 = std::env::var("CAPTURE_SECS").map_or(Ok(20), |s| s.parse())?;
    println!("Session up. Idle for {spell}s, then sending on the clean link, for the capture.");
    tokio::time::sleep(Duration::from_secs(5)).await;
    let idle_from = Instant::now();
    tokio::time::sleep(Duration::from_secs(spell)).await;
    let idle = (idle_from, Instant::now());
    let busy_from = Instant::now();
    let busy_count = spell as usize;
    let (to_bob, to_alice) = exchange(&alice, &bob, busy_count, "clean, both sending").await?;
    let busy = (busy_from, Instant::now());
    let mut all_arrived = to_bob == busy_count && to_alice == busy_count;

    println!("Now {messages} messages each way per loss level, jamming {jammed}.");
    for loss in levels {
        if matches!(jammed.as_str(), "alice" | "both") {
            alice.proxy.jam(loss);
        }
        if matches!(jammed.as_str(), "bob" | "both") {
            bob.proxy.jam(loss);
        }
        let label = format!("{:.0}% loss", loss * 100.0);
        let (to_bob, to_alice) = exchange(&alice, &bob, messages, &label).await?;
        all_arrived &= to_bob == messages && to_alice == messages;
    }
    alice.proxy.jam(0.0);
    bob.proxy.jam(0.0);

    let in_step = {
        let (a, b) = (alice.client.lock().await, bob.client.lock().await);
        let (ab, ba) = (&a.e2e_sessions[&bob.token], &b.e2e_sessions[&alice.token]);
        ab.send_chain_key == ba.recv_chain_key && ba.send_chain_key == ab.recv_chain_key
    };
    println!("Ratchets in step: {in_step}");

    let capture = alice.proxy.capture.lock().unwrap().clone();
    println!("Alice's link, as a capture there would show it:");
    let one_size = report_capture(&capture, idle, busy);
    if let Ok(path) = std::env::var("CAPTURE") {
        let client = alice
            .proxy
            .client_addr
            .lock()
            .unwrap()
            .unwrap_or(alice.proxy.addr);
        write_pcap(&path, &capture, client, alice.proxy.relay)?;
        println!("Wrote {path}");
    }

    for peer in [&alice, &bob] {
        let _ = std::fs::remove_file(&peer.client.lock().await.state_path);
    }
    if all_arrived && in_step && one_size {
        println!("PASS");
        Ok(())
    } else {
        bail!("FAIL")
    }
}
