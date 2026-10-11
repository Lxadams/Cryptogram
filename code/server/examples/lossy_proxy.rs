//! A UDP proxy that loses packets, for trying the app over a bad network.
//! `runserver-lan-lossy.sh` runs it in front of the relay:
//!
//!   cargo run --example lossy_proxy -- <listen addr> <relay addr> [loss] [report secs]
//!
//! Each packet, either way, is dropped with probability `loss` (default
//! 0.7), independently of the others. Typing a new loss and Enter changes
//! it at once: 0 to add contacts on a clean link, say, then 0.7 again.
//!
//! Every `report secs` (default 1) that packets flowed, it prints how many
//! got through and how many it dropped, each way.
//!
//! Each client gets a socket of its own towards the relay, as behind a NAT,
//! so the relay can still tell clients apart. They all come from this
//! machine, though, so they share the relay's per-address handshake limit.
//! A client's socket closes after `IDLE_TIMEOUT` without a packet from the
//! relay. Its next packet then comes from a new port, which the relay sees
//! as the client moving.

use anyhow::{Context, Result, ensure};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Each client's socket towards the relay, by the client's address.
type Clients = Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>>;

/// The chance of dropping each packet, as `f64` bits, so it can change
/// while packets flow.
struct Loss(AtomicU64);

impl Loss {
    fn new(loss: f64) -> Self {
        Self(AtomicU64::new(loss.to_bits()))
    }

    fn get(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }

    fn set(&self, loss: f64) {
        self.0.store(loss.to_bits(), Ordering::Relaxed);
    }
}

/// Packets carried and dropped in one direction, since the proxy started.
#[derive(Default)]
struct Counts {
    carried: AtomicU64,
    dropped: AtomicU64,
}

impl Counts {
    /// Whether to drop the next packet, counting it either way.
    fn drop_next(&self, loss: &Loss) -> bool {
        // Uniform in [0, 1): the top 53 bits, as many as an f64 holds.
        let sample = (OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        let drop = sample < loss.get();
        let count = if drop { &self.dropped } else { &self.carried };
        count.fetch_add(1, Ordering::Relaxed);
        drop
    }

    fn tally(&self) -> Tally {
        Tally {
            carried: self.carried.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

/// A snapshot of `Counts`, or the difference between two.
#[derive(Clone, Copy, PartialEq)]
struct Tally {
    carried: u64,
    dropped: u64,
}

impl Tally {
    fn since(self, earlier: Tally) -> Tally {
        Tally {
            carried: self.carried - earlier.carried,
            dropped: self.dropped - earlier.dropped,
        }
    }

    fn dropped_percent(self) -> f64 {
        100.0 * self.dropped as f64 / (self.carried + self.dropped).max(1) as f64
    }
}

impl std::fmt::Display for Tally {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} through, {} dropped ({:.0}%)",
            self.carried,
            self.dropped,
            self.dropped_percent()
        )
    }
}

/// A loss typed in, as a fraction from 0 to 1.
fn parse_loss(s: &str) -> Result<f64> {
    let loss: f64 = s
        .trim()
        .parse()
        .context("loss is a fraction, from 0 to 1")?;
    ensure!(
        (0.0..=1.0).contains(&loss),
        "loss is a fraction, from 0 to 1"
    );
    Ok(loss)
}

#[tokio::main]
async fn main() -> Result<()> {
    let usage = "usage: lossy_proxy <listen addr> <relay addr> [loss] [report secs]";
    let args: Vec<String> = std::env::args().collect();
    let listen: SocketAddr = args.get(1).context(usage)?.parse()?;
    let relay: SocketAddr = args.get(2).context(usage)?.parse()?;
    let loss = Arc::new(Loss::new(args.get(3).map_or(Ok(0.7), |s| parse_loss(s))?));
    let report_secs: f64 = args.get(4).map_or(Ok(1.0), |s| s.parse())?;
    ensure!(
        report_secs > 0.0,
        "report secs is how often to print a summary, over 0"
    );
    let report_every = Duration::from_secs_f64(report_secs);

    let public = Arc::new(
        UdpSocket::bind(listen)
            .await
            .with_context(|| format!("can't listen on {listen} (is a relay already running?)"))?,
    );
    let clients: Clients = Default::default();
    let to_relay = Arc::new(Counts::default());
    let to_clients = Arc::new(Counts::default());
    println!(
        "[lossy proxy] {listen} -> {relay}, dropping {:.0}% of packets each way. Type a new loss (0 to 1) and Enter to change it.",
        loss.get() * 100.0
    );

    // A thread, not a task: a blocking read of stdin can't be cancelled,
    // so as a task it would hold up the runtime's shutdown.
    std::thread::spawn({
        let loss = loss.clone();
        move || {
            for line in std::io::stdin().lines() {
                let Ok(line) = line else { break };
                match parse_loss(&line) {
                    Ok(new) => {
                        loss.set(new);
                        println!(
                            "[lossy proxy] now dropping {:.0}% of packets each way",
                            new * 100.0
                        );
                    }
                    Err(e) => println!("[lossy proxy] {e}: 0.7 is 70%, 0 is none"),
                }
            }
        }
    });

    tokio::spawn({
        let (clients, to_relay, to_clients) =
            (clients.clone(), to_relay.clone(), to_clients.clone());
        async move {
            let mut ticks = tokio::time::interval(report_every);
            ticks.tick().await;
            let mut last = (to_relay.tally(), to_clients.tally());
            loop {
                ticks.tick().await;
                let now = (to_relay.tally(), to_clients.tally());
                // Quiet intervals say nothing, so an idle proxy doesn't
                // scroll the relay's own output away.
                if now == last {
                    continue;
                }
                println!(
                    "[lossy proxy] last {report_secs}s: to the relay {} | to clients {} | since start {:.0}% and {:.0}% dropped | clients: {}",
                    now.0.since(last.0),
                    now.1.since(last.1),
                    now.0.dropped_percent(),
                    now.1.dropped_percent(),
                    clients.lock().unwrap().len(),
                );
                last = now;
            }
        }
    });

    let mut buf = vec![0u8; 65536];
    loop {
        // An error here is an ICMP "port unreachable" from a client that
        // went away, say: nothing to do with anyone else's packets.
        let Ok((len, client)) = public.recv_from(&mut buf).await else {
            continue;
        };
        let existing = clients.lock().unwrap().get(&client).cloned();
        let upstream = match existing {
            Some(upstream) => upstream,
            None => {
                let local: SocketAddr = if relay.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                }
                .parse()?;
                let upstream = Arc::new(UdpSocket::bind(local).await?);
                upstream.connect(relay).await?;
                clients.lock().unwrap().insert(client, upstream.clone());
                tokio::spawn(relay_to_client(
                    upstream.clone(),
                    client,
                    public.clone(),
                    clients.clone(),
                    to_clients.clone(),
                    loss.clone(),
                ));
                upstream
            }
        };
        if !to_relay.drop_next(&loss) {
            let _ = upstream.send(&buf[..len]).await;
        }
    }
}

/// Carry what the relay sends `client`, until it's sent nothing for
/// `IDLE_TIMEOUT`.
async fn relay_to_client(
    upstream: Arc<UdpSocket>,
    client: SocketAddr,
    public: Arc<UdpSocket>,
    clients: Clients,
    counts: Arc<Counts>,
    loss: Arc<Loss>,
) {
    let mut buf = vec![0u8; 65536];
    // An error is an ICMP "port unreachable": the relay isn't running.
    while let Ok(received) = tokio::time::timeout(IDLE_TIMEOUT, upstream.recv(&mut buf)).await {
        if let Ok(len) = received
            && !counts.drop_next(&loss)
        {
            let _ = public.send_to(&buf[..len], client).await;
        }
    }
    clients.lock().unwrap().remove(&client);
}
