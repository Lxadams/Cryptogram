//! The QUIC settings both ends run cells over, and `CellTransport`.
//!
//! What they're for:
//! - **One packet size.** Every 1-RTT packet, ACK-only ones and loss probes
//!   included, is padded to `MTU` (`pad_to_mtu`), with path MTU discovery
//!   off so the size never changes. Only the handshake differs, as in any
//!   QUIC connection.
//! - **No backing off under loss.** QUIC's congestion control halves its
//!   sending rate when it sees loss, so jamming a link would throttle it.
//!   Cells are already sent at a fixed low rate (see `pace`), so `FixedRate`
//!   never reduces its window: the rate is whatever the cell clock says.
//! - **Rotating connection IDs** (`endpoint_config`): each end retires its
//!   connection IDs every `CID_LIFETIME`, and QUIC switches to fresh ones on
//!   a network change, so there's no long-lived identifier on the wire.
//! - **Looks like HTTP/3**: ALPN `h3` on UDP 443.

use bytes::Bytes;
use quinn::congestion::{Controller, ControllerFactory};
use quinn::rustls::pki_types::CertificateDer;
use quinn::{Connection, EndpointConfig, IdleTimeout, TransportConfig};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// ALPN both ends offer: the same as any HTTP/3 client and server.
pub const ALPN: &[u8] = b"h3";

/// Every QUIC packet after the handshake is exactly this many bytes: QUIC's
/// minimum, which crosses any path (IPv6 tunnels included) unfragmented.
pub const MTU: u16 = 1200;

/// TLS exporter label for the value a hello is bound to (see `proof`).
const EXPORTER_LABEL: &[u8] = b"EXPORTER-e2e-messenger/link/v1";

/// How long each connection ID is used before both ends move to a new one.
const CID_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Length of the connection IDs each end issues (quinn's default, and
/// what browsers use).
const CID_LEN: usize = 8;

/// A link that hears nothing at all for this long is dead. Cells arrive
/// about 4 times a second, so even at 90% loss that's dozens of chances.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Bytes `FixedRate` lets be in flight. Far above what cells need (about
/// 5 KB/s); it only exists so a stalled path can't buffer without bound.
const FIXED_WINDOW: u64 = 1 << 20;

/// A congestion controller that never slows down: loss doesn't shrink the
/// window. The cell clock, not QUIC, decides the sending rate.
#[derive(Debug, Clone, Copy)]
pub struct FixedRate;

impl Controller for FixedRate {
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _persistent: bool,
        _lost: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        FIXED_WINDOW
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(*self)
    }

    fn initial_window(&self) -> u64 {
        FIXED_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

struct FixedRateFactory;

impl ControllerFactory for FixedRateFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(FixedRate)
    }
}

/// Transport settings for both the client's and the relay's connections.
pub fn transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config
        .initial_mtu(MTU)
        .min_mtu(MTU)
        .mtu_discovery_config(None)
        .pad_to_mtu(true)
        .congestion_controller_factory(Arc::new(FixedRateFactory))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(IDLE_TIMEOUT).expect("well within QUIC's limit"),
        ))
        // Cells keep the connection busy; no separate keep-alives.
        .keep_alive_interval(None);
    config
}

/// Endpoint settings for both ends: rotating connection IDs.
pub fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.cid_generator(|| {
        let mut generator = quinn_proto::RandomConnectionIdGenerator::new(CID_LEN);
        generator.set_lifetime(CID_LIFETIME);
        Box::new(generator)
    });
    config
}

/// The value both ends of `connection` derive from its TLS session, which a
/// hello is bound to (see `proof`).
pub fn link_binding(connection: &Connection) -> io::Result<[u8; 32]> {
    let mut binding = [0u8; 32];
    connection
        .export_keying_material(&mut binding, EXPORTER_LABEL, b"")
        .map_err(|_| io::Error::other("TLS exporter unavailable"))?;
    Ok(binding)
}

/// The relay's key pin: SHA-256 of its certificate's SubjectPublicKeyInfo.
/// The app ships with it (`SERVER_PUBKEY`) and trusts only a certificate
/// for that key, whoever signed it. Pinning the key rather than the
/// certificate lets the relay renew its certificate, as long as it keeps
/// the key (certbot's `--reuse-key`).
pub fn key_pin(certificate: &CertificateDer<'_>) -> io::Result<[u8; 32]> {
    let parsed = webpki::EndEntityCert::try_from(certificate)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad certificate: {e}")))?;
    Ok(Sha256::digest(parsed.subject_public_key_info().as_ref()).into())
}

/// Something that carries cells to the other end of a link and back: the
/// only thing the cell scheduling above it needs. QUIC datagrams today; a
/// mixnet client could implement it later without changing anything above.
pub trait CellTransport: Send + Sync + 'static {
    /// Hand one cell to the network. Doesn't wait: a cell that can't be
    /// sent right now is dropped, like any lost packet.
    fn send_cell(&self, cell: Vec<u8>) -> io::Result<()>;

    /// Wait for the next cell from the other end. An error means the link
    /// is gone.
    fn recv_cell(&self) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

impl CellTransport for Connection {
    fn send_cell(&self, cell: Vec<u8>) -> io::Result<()> {
        self.send_datagram(Bytes::from(cell))
            .map_err(io::Error::other)
    }

    async fn recv_cell(&self) -> io::Result<Vec<u8>> {
        self.read_datagram()
            .await
            .map(|datagram| datagram.to_vec())
            .map_err(io::Error::other)
    }
}
