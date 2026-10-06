//! The client's link to the relay: a QUIC connection that looks like HTTP/3,
//! carrying a constant-rate stream of cells (see the `cell` crate).
//!
//! - **Who we talk to.** The relay is pinned by its key (`SERVER_PUBKEY`,
//!   see `cell::quic::key_pin`), whoever signed its certificate. TLS offers
//!   only the hybrid X25519MLKEM768 key exchange, so recorded traffic stays
//!   safe from a future quantum computer. Its address is shipped with the app
//!   or looked up over DNS-over-HTTPS, never in a plaintext DNS query.
//! - **Who we are.** Nobody, at the TLS level: no client certificate. The
//!   first cells carry a hello proving we're the app and own our routing
//!   token (see `cell::proof`).
//! - **When we send.** One cell per tick of a Poisson clock, averaging
//!   `cell::pace::CELLS_PER_SECOND`, whatever there is to send. A cell
//!   carries one FEC symbol of the oldest object still short of symbols, or
//!   nothing.
//! - **How much we send.** Every cell from the relay carries a receipt for
//!   ours, so we know which symbols reached it and how lossy our uplink is.
//!   Each object's first round is sized for the measured loss
//!   (`fec::sends_for`), and any shortfall is topped up with fresh symbols
//!   until the relay holds the `Outgoing::needed` the recipient must get.
//!   The relay then delivers every one of them, resending whatever our
//!   receipts say didn't arrive. Lossy links cost more cells, clean ones few.
//!
//! The cell stream runs over anything implementing `CellTransport` (QUIC
//! today), so a mixnet can replace it later.

use crate::{Client, Outgoing, RoutingToken};
use anyhow::{Context, Result, anyhow};
use cell::{
    CELL_LEN, CellBuilder, CellTransport, Frame, LossEstimate, ReceiveWindow, SendWindow,
    pace::PoissonClock,
    proof::{AccessKey, HELLO_LEN},
};
use ed25519_dalek::SigningKey;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::{
    self, CertificateError, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::{Notify, watch};
use tokio::time::Instant;

/// Each object's first round of symbols aims for this chance of falling
/// short; receipts show any shortfall and it's topped up.
const ROUND_SHORTFALL: f64 = 1e-2;
/// Loss rates planned for are kept in this range: a link that has lost
/// nothing lately still gets a spare symbol, and one losing everything
/// isn't sent hundreds per object.
const MIN_PLANNED_LOSS: f64 = 0.05;
const MAX_PLANNED_LOSS: f64 = 0.95;

/// How long the QUIC handshake may take. Generous: under heavy loss its
/// packets need resending too.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the relay may take to answer our hello. A relay that never
/// does has refused it: most likely a wrong `SERVER_ACCESS_KEY`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);
/// Waits between reconnection attempts: doubling from the first to the
/// second, and starting over once a link has come up.
const FIRST_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);

/// Where the relay is and how to recognise it.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub addr: SocketAddr,
    /// The name its certificate is for, sent in the TLS handshake as any
    /// HTTPS client would (an IP address sends none).
    pub server_name: String,
    /// The relay's key pin (`SERVER_PUBKEY`): see `cell::quic::key_pin`.
    pub key_pin: [u8; 32],
    /// What every copy of the app proves it has (`SERVER_ACCESS_KEY`).
    pub access_key: AccessKey,
}

impl RelayConfig {
    /// From the settings front ends are built or launched with.
    ///
    /// `addr` is `ip:port`, used as is (ship the relay's address in the app
    /// and nothing is looked up at all), or `host:port`, resolved over
    /// DNS-over-HTTPS. `server_name` defaults to `addr`'s host.
    pub async fn from_settings(
        addr: &str,
        server_name: Option<&str>,
        key_pin_hex: &str,
        access_key_hex: &str,
    ) -> Result<Self> {
        let parse_hex = |hex_str: &str, what: &str| -> Result<[u8; 32]> {
            let mut out = [0u8; 32];
            hex::decode_to_slice(hex_str.trim(), &mut out)
                .map_err(|_| anyhow!("{what} must be 64 hex characters"))?;
            Ok(out)
        };
        let (host, port) = split_host_port(addr)?;
        Ok(Self {
            addr: resolve(host, port).await?,
            server_name: server_name.unwrap_or(host).to_string(),
            key_pin: parse_hex(key_pin_hex, "SERVER_PUBKEY")?,
            access_key: parse_hex(access_key_hex, "SERVER_ACCESS_KEY")?,
        })
    }
}

fn split_host_port(addr: &str) -> Result<(&str, u16)> {
    let (host, port) = addr
        .trim()
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("The relay address {addr:?} needs a port (host:port)"))?;
    let port = port
        .parse()
        .map_err(|_| anyhow!("Bad port in relay address {addr:?}"))?;
    // [v6]:port
    Ok((host.trim_start_matches('[').trim_end_matches(']'), port))
}

/// An IP address as is; a name over DNS-over-HTTPS (Cloudflare, then
/// Quad9), so no plaintext DNS query tells the network who we're
/// contacting. The hosts file is checked first, which sends nothing.
async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    use hickory_resolver::{
        Resolver,
        config::{NameServerConfigGroup, ResolveHosts, ResolverConfig},
        name_server::TokioConnectionProvider,
    };
    install_crypto_provider();
    let mut servers = NameServerConfigGroup::cloudflare_https();
    servers.merge(NameServerConfigGroup::quad9_https());
    let config = ResolverConfig::from_parts(None, vec![], servers);
    let mut builder = Resolver::builder_with_config(config, TokioConnectionProvider::default());
    builder.options_mut().use_hosts_file = ResolveHosts::Always;
    let lookup = builder.build().lookup_ip(host).await.with_context(|| {
        format!("Couldn't look up the relay's address ({host}) over DNS-over-HTTPS")
    })?;
    let ip = lookup
        .iter()
        .next()
        .ok_or_else(|| anyhow!("The relay's name ({host}) has no address"))?;
    Ok(SocketAddr::new(ip, port))
}

/// rustls needs one process-wide crypto provider for anything that doesn't
/// name its own (the DNS-over-HTTPS client). aws-lc-rs, as everywhere else.
fn install_crypto_provider() {
    let _ = aws_lc_rs::default_provider().install_default();
}

/// Trusts exactly one key: the pinned one. Certificate chains, names and
/// expiry dates are ignored; what counts is that the relay proves (with the
/// handshake signature rustls checks below) that it holds the pinned key.
#[derive(Debug)]
struct PinnedKey {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = cell::quic::key_pin(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if bool::from(pin.ct_eq(&self.pin)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC is TLS 1.3 only.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// QUIC client settings: TLS 1.3 with only the post-quantum hybrid key
/// exchange on offer, the pinned relay key, ALPN h3, no client certificate.
fn quic_client_config(key_pin: [u8; 32]) -> Result<quinn::ClientConfig> {
    let provider = Arc::new(CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    });
    let verifier = PinnedKey {
        pin: key_pin,
        provider: Arc::clone(&provider),
    };
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![cell::quic::ALPN.to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(Arc::new(cell::quic::transport_config()));
    Ok(config)
}

/// Handles one payload the relay delivered (`Client::handle_incoming_packet`
/// under whatever lock the front end keeps its `Client` in). Returns the
/// replies to send, or `None` if it couldn't be handled right now, in which
/// case the cell isn't acknowledged and the relay delivers it again.
pub type Handler = Arc<
    dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Option<Vec<Outgoing>>> + Send>> + Send + Sync,
>;

/// A `Handler` for a `Client` kept in an `Arc<tokio::sync::Mutex<_>>`.
pub fn client_handler(client: Arc<tokio::sync::Mutex<Client>>) -> Handler {
    Arc::new(move |payload| {
        let client = Arc::clone(&client);
        Box::pin(async move {
            let reply = client.lock().await.handle_incoming_packet(&payload);
            Some(reply.ok().flatten().into_iter().collect())
        })
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkStatus {
    /// Connecting, or waiting for the relay to answer our hello.
    Connecting,
    /// The relay accepted our hello; cells are flowing both ways.
    Up,
    /// The last attempt failed, with why; another follows shortly.
    Down(String),
}

/// What the link knows about how it's doing, for front ends to show.
#[derive(Clone, Copy, Debug)]
pub struct LinkStats {
    /// Estimated fraction of our cells that don't reach the relay.
    pub uplink_loss: f64,
    /// Objects (messages, contact requests) still being sent.
    pub queued: usize,
}

/// An object being sent, and how its symbols have fared so far.
struct Tracked {
    id: u64,
    out: Outgoing,
    /// Symbols the relay is known to have.
    confirmed: u32,
    /// Symbols sent that no receipt has settled yet.
    in_flight: u32,
}

/// Everything waiting to go out, oldest first.
#[derive(Default)]
struct SendQueue {
    objects: VecDeque<Tracked>,
    next_id: u64,
}

impl SendQueue {
    fn push(&mut self, out: Outgoing) {
        self.next_id += 1;
        self.objects.push_back(Tracked {
            id: self.next_id,
            out,
            confirmed: 0,
            in_flight: 0,
        });
    }

    /// The next symbol to send: from the oldest object whose symbols in
    /// flight, at `loss`, are unlikely to make up what the relay still
    /// needs. Returns the object's id, its recipient and the symbol.
    fn next_symbol(&mut self, loss: f64) -> Option<(u64, RoutingToken, Vec<u8>)> {
        let loss = loss.clamp(MIN_PLANNED_LOSS, MAX_PLANNED_LOSS);
        let mut exhausted = None;
        let mut next = None;
        for (index, tracked) in self.objects.iter_mut().enumerate() {
            let missing = tracked.out.needed().saturating_sub(tracked.confirmed);
            if tracked.in_flight >= fec::sends_for(missing, loss, ROUND_SHORTFALL) {
                continue;
            }
            match tracked.out.next_payload() {
                Some(payload) => {
                    tracked.in_flight += 1;
                    next = Some((tracked.id, tracked.out.target(), payload));
                }
                None => exhausted = Some(index),
            }
            break;
        }
        if let Some(index) = exhausted {
            tracing::warn!("Gave up on a message: the link lost too much of it");
            self.objects.remove(index);
        }
        next
    }

    /// Receipts settled these symbols: `delivered` reached the relay,
    /// `lost` didn't. Objects the relay now has enough of are done.
    fn settle(&mut self, delivered: &[u64], lost: &[u64]) {
        for tracked in &mut self.objects {
            let arrived = delivered.iter().filter(|&&id| id == tracked.id).count() as u32;
            let missed = lost.iter().filter(|&&id| id == tracked.id).count() as u32;
            tracked.confirmed += arrived;
            tracked.in_flight = tracked.in_flight.saturating_sub(arrived + missed);
        }
        self.objects
            .retain(|tracked| tracked.confirmed < tracked.out.needed());
    }
}

struct Shared {
    queue: Mutex<SendQueue>,
    /// What the last link learned about loss, for the next one to start
    /// from.
    loss: Mutex<LossEstimate>,
    status: watch::Sender<LinkStatus>,
    reconnect: Notify,
}

/// The link to the relay. Starts connecting as soon as it's made, keeps
/// reconnecting whenever the connection drops, and sends whatever it's
/// given over the constant-rate cell stream. Dropping it closes the link.
pub struct RelayLink {
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl RelayLink {
    /// Start linking to the relay as the owner of `token_secret`'s routing
    /// token, handing everything the relay delivers to `handler`. Must be
    /// called from within a Tokio runtime.
    pub fn start(config: RelayConfig, token_secret: SigningKey, handler: Handler) -> Result<Self> {
        let bind: SocketAddr = match config.addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let mut endpoint = quinn::Endpoint::new(
            cell::quic::endpoint_config(),
            None,
            std::net::UdpSocket::bind(bind)?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(quic_client_config(config.key_pin)?);
        let shared = Arc::new(Shared {
            queue: Mutex::default(),
            loss: Mutex::default(),
            status: watch::Sender::new(LinkStatus::Connecting),
            reconnect: Notify::new(),
        });
        let task = tokio::spawn(supervise(
            endpoint,
            config,
            token_secret,
            Arc::clone(&shared),
            handler,
        ));
        Ok(Self { shared, task })
    }

    /// Queue `out` for sending. It goes out whether or not the link is up
    /// right now: anything queued waits for the next connection.
    pub fn send(&self, out: Outgoing) {
        self.shared.queue.lock().unwrap().push(out);
    }

    pub fn status(&self) -> LinkStatus {
        self.shared.status.borrow().clone()
    }

    /// Wait until the relay has accepted our hello, or fail with why not.
    pub async fn wait_until_up(&self, timeout: Duration) -> Result<()> {
        self.watch().until_up(timeout).await
    }

    /// A handle that follows this link's status, for waiting on it without
    /// holding on to the link (or whatever lock it's kept under).
    pub fn watch(&self) -> LinkWatch {
        LinkWatch(self.shared.status.subscribe())
    }

    /// Skip any wait before the next connection attempt (the app came back
    /// to the foreground, say). Does nothing while the link is up.
    pub fn reconnect_now(&self) {
        self.shared.reconnect.notify_one();
    }

    pub fn stats(&self) -> LinkStats {
        LinkStats {
            uplink_loss: self.shared.loss.lock().unwrap().value(),
            queued: self.shared.queue.lock().unwrap().objects.len(),
        }
    }
}

impl Drop for RelayLink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Follows a `RelayLink`'s status (see `RelayLink::watch`).
pub struct LinkWatch(watch::Receiver<LinkStatus>);

impl LinkWatch {
    /// Wait until the relay has accepted our hello, or fail with why not.
    pub async fn until_up(self, timeout: Duration) -> Result<()> {
        let mut status = self.0;
        let mut last_error = None;
        let up = tokio::time::timeout(timeout, async {
            loop {
                match status.borrow_and_update().clone() {
                    LinkStatus::Up => return,
                    LinkStatus::Down(e) => last_error = Some(e),
                    LinkStatus::Connecting => {}
                }
                if status.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        })
        .await;
        up.map_err(|_| match last_error {
            Some(e) => anyhow!("Couldn't reach the relay: {e}"),
            None => anyhow!(
                "No answer from the relay within {}s. Check its address and that it's running.",
                timeout.as_secs()
            ),
        })
    }
}

/// Connect, run the link until it drops, wait, and go again, forever.
async fn supervise(
    endpoint: quinn::Endpoint,
    config: RelayConfig,
    token_secret: SigningKey,
    shared: Arc<Shared>,
    handler: Handler,
) {
    let mut retry = FIRST_RETRY;
    loop {
        shared.status.send_replace(LinkStatus::Connecting);
        match connect_and_run(&endpoint, &config, &token_secret, &shared, &handler).await {
            Ok(()) => retry = FIRST_RETRY,
            Err(e) => {
                tracing::warn!("Relay link: {e:#}");
                shared
                    .status
                    .send_replace(LinkStatus::Down(format!("{e:#}")));
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(retry) => {}
            _ = shared.reconnect.notified() => {}
        }
        retry = (retry * 2).min(MAX_RETRY);
    }
}

/// One connection, from handshake to close. `Ok` if it came up and later
/// dropped (so retrying can start over at once), `Err` if it never came up.
async fn connect_and_run(
    endpoint: &quinn::Endpoint,
    config: &RelayConfig,
    token_secret: &SigningKey,
    shared: &Shared,
    handler: &Handler,
) -> Result<()> {
    let connecting = endpoint.connect(config.addr, &config.server_name)?;
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            anyhow!(
                "no QUIC handshake with {} within {}s",
                config.addr,
                CONNECT_TIMEOUT.as_secs()
            )
        })?
        .context("QUIC handshake failed (is SERVER_PUBKEY this relay's key?)")?;
    if connection.max_datagram_size().unwrap_or(0) < CELL_LEN {
        connection.close(0u32.into(), b"");
        return Err(anyhow!("the path can't carry {CELL_LEN}-byte cells"));
    }
    let binding = cell::quic::link_binding(&connection)?;
    let hello = cell::proof::hello(&config.access_key, token_secret, &binding);
    let result = run_cells(&connection, shared, Some(hello), handler).await;
    connection.close(0u32.into(), b"");
    match result {
        LinkEnd::Dropped(e) => {
            tracing::info!("Relay link dropped: {e}");
            Ok(())
        }
        LinkEnd::NeverUp(e) => Err(e),
    }
}

/// Per-link state: our cells' receipts, and theirs.
struct LinkState {
    tx: SendWindow<u64>,
    rx: ReceiveWindow,
    /// Sent in every cell until the relay's first cell shows it accepted it.
    hello: Option<[u8; HELLO_LEN]>,
}

enum LinkEnd {
    /// It came up, then the transport failed.
    Dropped(io::Error),
    /// It never came up.
    NeverUp(anyhow::Error),
}

/// Run the cell stream over `transport` until it fails: send a cell on
/// every tick of the Poisson clock, and handle every cell that arrives.
/// `hello` goes in each cell until the other end answers; with `None` the
/// link counts as up at once.
async fn run_cells<T: CellTransport>(
    transport: &T,
    shared: &Shared,
    hello: Option<[u8; HELLO_LEN]>,
    handler: &Handler,
) -> LinkEnd {
    let started = Instant::now();
    if hello.is_none() {
        shared.status.send_replace(LinkStatus::Up);
    }
    let link = Mutex::new(LinkState {
        tx: SendWindow::new(*shared.loss.lock().unwrap()),
        rx: ReceiveWindow::default(),
        hello,
    });
    let is_up = || link.lock().unwrap().hello.is_none();

    let send = async {
        let mut clock = PoissonClock::new();
        loop {
            clock.tick().await;
            let cell = next_cell(&link, shared);
            if let Err(e) = transport.send_cell(cell) {
                return e;
            }
            if !is_up() && started.elapsed() > HELLO_TIMEOUT {
                return io::Error::new(io::ErrorKind::TimedOut, "hello timeout");
            }
        }
    };
    let receive = async {
        loop {
            match transport.recv_cell().await {
                Ok(cell) => handle_cell(&cell, &link, shared, handler).await,
                Err(e) => return e,
            }
        }
    };
    let error = tokio::select! {
        e = send => e,
        e = receive => e,
    };

    // Whatever no receipt settled has to count as lost.
    let mut link = link.into_inner().unwrap();
    let unsettled = link.tx.drain();
    shared.queue.lock().unwrap().settle(&[], &unsettled);
    *shared.loss.lock().unwrap() = *link.tx.loss();
    if link.hello.is_none() {
        LinkEnd::Dropped(error)
    } else if error.kind() == io::ErrorKind::TimedOut {
        LinkEnd::NeverUp(anyhow!(
            "the relay didn't answer our hello within {}s (is SERVER_ACCESS_KEY this relay's?)",
            HELLO_TIMEOUT.as_secs()
        ))
    } else {
        LinkEnd::NeverUp(anyhow!(
            "the link failed before the relay answered: {error}"
        ))
    }
}

/// The cell for this tick: our hello while the relay hasn't answered it,
/// otherwise the next symbol due (if any), plus a receipt either way.
fn next_cell(link: &Mutex<LinkState>, shared: &Shared) -> Vec<u8> {
    let mut link = link.lock().unwrap();
    let receipt = link.rx.receipt();
    if let Some(hello) = link.hello {
        let seq = link.tx.send(None);
        let mut cell = CellBuilder::new(seq, receipt);
        cell.push(&Frame::Hello(&hello));
        return cell.finish();
    }
    let loss = link.tx.loss().value();
    let next = shared.queue.lock().unwrap().next_symbol(loss);
    let seq = link.tx.send(next.as_ref().map(|(id, _, _)| *id));
    let mut cell = CellBuilder::new(seq, receipt);
    if let Some((_, to, payload)) = &next {
        cell.push(&Frame::Forward { to: *to, payload });
    }
    cell.finish()
}

async fn handle_cell(cell: &[u8], link: &Mutex<LinkState>, shared: &Shared, handler: &Handler) {
    let Ok(parsed) = cell::parse(cell) else {
        tracing::debug!("Dropped a malformed cell from the relay");
        return;
    };
    {
        let mut link = link.lock().unwrap();
        // The relay sends nothing until it has accepted our hello.
        if link.hello.take().is_some() {
            shared.status.send_replace(LinkStatus::Up);
            tracing::info!("Relay link up");
        }
        let settled = link.tx.on_receipt(parsed.receipt);
        shared
            .queue
            .lock()
            .unwrap()
            .settle(&settled.delivered, &settled.lost);
        *shared.loss.lock().unwrap() = *link.tx.loss();
    }
    let mut handled = true;
    for frame in parsed.frames {
        if let Frame::Deliver(payload) = frame {
            match handler(payload.to_vec()).await {
                Some(replies) => {
                    let mut queue = shared.queue.lock().unwrap();
                    for reply in replies {
                        queue.push(reply);
                    }
                }
                None => handled = false,
            }
        }
    }
    // Only acknowledged once handled (and saved), so a crash in between
    // means the relay delivers it again rather than it being lost.
    if handled {
        link.lock().unwrap().rx.record(parsed.seq);
    }
}

#[cfg(test)]
mod tests;
