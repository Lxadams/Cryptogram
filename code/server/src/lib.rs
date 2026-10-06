//! The relay: a QUIC server on UDP 443 that forwards cells between clients.
//!
//! To anyone on the network it's an HTTP/3 website with a real certificate
//! (see `site` and `tls`). A client running the app proves it has the app's
//! access key and owns a routing token in the first cells it sends (see
//! `link`); from then on each side sends the other cells at a constant
//! Poisson rate, real or padding, and the relay queues what one user
//! forwards until the recipient's link confirms it arrived.
//!
//! It never sees plaintext (clients encrypt end to end), keeps nothing on
//! disk but its own keys, and logs no addresses or routing tokens.

use anyhow::Result;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::debug;

pub mod link;
pub mod site;
pub mod stores;
pub mod tls;

use link::Relay;
use site::Site;

const SWEEPING_TASK_INTERVAL: Duration = Duration::from_secs(120);

pub fn bind_endpoint(addr: SocketAddr, config: quinn::ServerConfig) -> Result<quinn::Endpoint> {
    let socket = std::net::UdpSocket::bind(addr)?;
    Ok(quinn::Endpoint::new(
        cell::quic::endpoint_config(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?)
}

/// Accept connections until the endpoint closes. Each one is served the
/// website, and becomes a link if it says hello.
pub async fn run(endpoint: quinn::Endpoint, relay: Arc<Relay>, site: Site) {
    while let Some(incoming) = endpoint.accept().await {
        let (relay, site) = (Arc::clone(&relay), site.clone());
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else {
                return;
            };
            tokio::spawn(site::serve(connection.clone(), site));
            if let Err(e) = link::serve(relay, connection).await {
                debug!("Connection ended: {e}");
            }
        });
    }
}

pub fn spawn_sweeping_task(relay: Arc<Relay>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEPING_TASK_INTERVAL).await;
            relay.tables.lock().unwrap().sweep_expired_messages();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf;
    use cell::{
        CELL_LEN, CellBuilder, CellTransport, Frame, ParsedCell, ReceiveWindow, parse,
        proof::{AccessKey, hello, routing_token_for},
        quic::link_binding,
    };
    use ed25519_dalek::SigningKey;
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::rustls::{
        self, DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, aws_lc_rs},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    use rand_core::{OsRng, RngCore};
    use std::time::Instant;
    use stores::RoutingToken;

    const ACCESS: AccessKey = [0x5A; 32];

    struct TestRelay {
        addr: SocketAddr,
        relay: Arc<Relay>,
    }

    async fn start_relay() -> TestRelay {
        let identity = tls::self_signed(vec!["localhost".into()]).unwrap();
        let endpoint = bind_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            tls::server_config(identity).unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let relay = Arc::new(Relay::new(ACCESS));
        tokio::spawn(run(endpoint, Arc::clone(&relay), Site::load().unwrap()));
        TestRelay { addr, relay }
    }

    /// Accepts any certificate: these tests are about the relay, not the
    /// app's key pinning (tested in the client crate).
    #[derive(Debug)]
    struct AnyCertificate(Arc<CryptoProvider>);

    impl ServerCertVerifier for AnyCertificate {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
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
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// A QUIC connection to the relay, offering only the post-quantum
    /// hybrid key exchange, as the app does.
    async fn connect(addr: SocketAddr) -> quinn::Connection {
        let provider = Arc::new(CryptoProvider {
            kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
            ..aws_lc_rs::default_provider()
        });
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        tls.alpn_protocols = vec![cell::quic::ALPN.to_vec()];
        let mut config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
        config.transport_config(Arc::new(cell::quic::transport_config()));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config);
        endpoint.connect(addr, "localhost").unwrap().await.unwrap()
    }

    fn signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    /// A stand-in for the app's end of a link, sending cells by hand.
    struct TestApp {
        connection: quinn::Connection,
        token: RoutingToken,
        rx: ReceiveWindow,
        next_seq: u32,
    }

    impl TestApp {
        /// Connect and say hello with `access`.
        async fn join(relay: &TestRelay, access: &AccessKey) -> Self {
            let connection = connect(relay.addr).await;
            let key = signing_key();
            let binding = link_binding(&connection).unwrap();
            let mut app = Self {
                connection,
                token: routing_token_for(&key.verifying_key()),
                rx: ReceiveWindow::default(),
                next_seq: 1,
            };
            let hello = hello(access, &key, &binding);
            app.send(&[Frame::Hello(&hello)]);
            app
        }

        fn send(&mut self, frames: &[Frame]) {
            let mut cell = CellBuilder::new(self.next_seq, self.rx.receipt());
            self.next_seq += 1;
            for frame in frames {
                assert!(cell.push(frame));
            }
            self.connection.send_cell(cell.finish()).unwrap();
        }

        /// The next cell from the relay, recorded in our receipts unless
        /// `drop` says to act as if it was lost.
        async fn recv(&mut self, drop: bool) -> Vec<u8> {
            let cell = tokio::time::timeout(Duration::from_secs(5), self.connection.recv_cell())
                .await
                .expect("the relay sends cells constantly")
                .unwrap();
            assert_eq!(cell.len(), CELL_LEN);
            if !drop {
                self.rx.record(parse(&cell).unwrap().seq);
            }
            cell
        }

        /// Receive until a cell delivers something; returns the payload.
        async fn next_delivery(&mut self) -> Vec<u8> {
            for _ in 0..100 {
                let cell = self.recv(false).await;
                if let Some(payload) = delivered(&parse(&cell).unwrap()) {
                    return payload;
                }
            }
            panic!("nothing delivered");
        }
    }

    fn delivered(cell: &ParsedCell) -> Option<Vec<u8>> {
        cell.frames.iter().find_map(|frame| match frame {
            Frame::Deliver(payload) => Some(payload.to_vec()),
            _ => None,
        })
    }

    fn queued(relay: &TestRelay, token: &RoutingToken) -> usize {
        relay
            .relay
            .tables
            .lock()
            .unwrap()
            .get_queued_packets(token)
            .map_or(0, |q| q.len())
    }

    /// Anyone who connects without the app's access key, a censor probing
    /// the address for instance, gets an ordinary website, and no cells
    /// whatever datagrams they send.
    #[tokio::test]
    async fn without_the_access_key_it_is_just_a_website() {
        let relay = start_relay().await;
        let connection = connect(relay.addr).await;

        let (mut driver, mut requests) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
        let mut fetch = async |path: &str| {
            let request = http::Request::get(format!("https://localhost{path}"))
                .body(())
                .unwrap();
            let mut stream = requests.send_request(request).await.unwrap();
            stream.finish().await.unwrap();
            let response = stream.recv_response().await.unwrap();
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            (response.status(), String::from_utf8(body).unwrap())
        };
        let (status, page) = fetch("/").await;
        assert_eq!(status, http::StatusCode::OK);
        assert!(page.contains("<title>Field Notes</title>"), "{page}");
        assert_eq!(fetch("/admin").await.0, http::StatusCode::NOT_FOUND);

        // Datagrams that aren't a valid hello (garbage, an all-padding
        // cell, a hello with the wrong access key) get nothing back.
        connection.send_cell(vec![0xEE; 100]).unwrap();
        connection
            .send_cell(CellBuilder::new(1, Default::default()).finish())
            .unwrap();
        let wrong = hello(
            &[0u8; 32],
            &signing_key(),
            &link_binding(&connection).unwrap(),
        );
        let mut cell = CellBuilder::new(2, Default::default());
        cell.push(&Frame::Hello(&wrong));
        connection.send_cell(cell.finish()).unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), connection.recv_cell()).await;
        assert!(reply.is_err(), "no cells for a connection without access");
        assert!(relay.relay.tables.lock().unwrap().is_empty_of_links());
    }

    /// The relay passes a payload from one user to another, and drops it
    /// from its queue once the recipient's receipt shows it arrived.
    #[tokio::test]
    async fn forwards_between_users_and_forgets_what_was_delivered() {
        let relay = start_relay().await;
        let mut alice = TestApp::join(&relay, &ACCESS).await;
        let mut bob = TestApp::join(&relay, &ACCESS).await;
        alice.recv(false).await; // the relay answers once it has the hello
        bob.recv(false).await;

        alice.send(&[Frame::Forward {
            to: bob.token,
            payload: b"hello bob",
        }]);
        assert_eq!(bob.next_delivery().await, b"hello bob");
        assert_eq!(queued(&relay, &bob.token), 1, "until a receipt says so");
        bob.send(&[]);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(queued(&relay, &bob.token), 0);
    }

    /// A cell the recipient reports lost is sent again, in a new cell.
    #[tokio::test]
    async fn a_cell_reported_lost_is_resent() {
        let relay = start_relay().await;
        let mut alice = TestApp::join(&relay, &ACCESS).await;
        let mut bob = TestApp::join(&relay, &ACCESS).await;
        alice.recv(false).await;
        bob.recv(false).await;

        alice.send(&[Frame::Forward {
            to: bob.token,
            payload: b"jammed",
        }]);
        // Bob "loses" the cell with the payload, and the next few.
        loop {
            let cell = bob.recv(true).await;
            if delivered(&parse(&cell).unwrap()).is_some() {
                break;
            }
        }
        for _ in 0..4 {
            bob.recv(false).await;
        }
        // His receipt shows the gap; the relay sends it again.
        bob.send(&[]);
        assert_eq!(bob.next_delivery().await, b"jammed");
    }

    /// Packets for someone offline wait for them, and whatever a link
    /// didn't confirm before closing goes to their next one.
    #[tokio::test]
    async fn offline_recipients_get_their_queue_when_they_connect() {
        let relay = start_relay().await;
        let mut alice = TestApp::join(&relay, &ACCESS).await;
        alice.recv(false).await;
        let carol_key = signing_key();
        let carol_token = routing_token_for(&carol_key.verifying_key());
        alice.send(&[Frame::Forward {
            to: carol_token,
            payload: b"while you were out",
        }]);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(queued(&relay, &carol_token), 1);

        // Carol connects, gets it, but drops off before sending a receipt.
        let join_as = async |key: &SigningKey| {
            let connection = connect(relay.addr).await;
            let binding = link_binding(&connection).unwrap();
            let mut app = TestApp {
                connection,
                token: routing_token_for(&key.verifying_key()),
                rx: ReceiveWindow::default(),
                next_seq: 1,
            };
            let hello = hello(&ACCESS, key, &binding);
            app.send(&[Frame::Hello(&hello)]);
            app
        };
        let mut carol = join_as(&carol_key).await;
        assert_eq!(carol.next_delivery().await, b"while you were out");
        carol.connection.close(0u32.into(), b"");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(queued(&relay, &carol_token), 1, "never confirmed");

        let mut carol = join_as(&carol_key).await;
        assert_eq!(carol.next_delivery().await, b"while you were out");
    }

    /// The relay's cells come at the same average rate, all the same size,
    /// whether or not it has anything to send.
    #[tokio::test]
    async fn the_relay_sends_at_a_constant_rate_busy_or_idle() {
        let relay = start_relay().await;
        let mut alice = TestApp::join(&relay, &ACCESS).await;
        let mut bob = TestApp::join(&relay, &ACCESS).await;
        bob.recv(false).await;
        alice.recv(false).await;

        let count_for = async |bob: &mut TestApp, secs: u64| {
            let (start, mut cells, mut busy) = (Instant::now(), 0, 0);
            while start.elapsed() < Duration::from_secs(secs) {
                let cell = bob.recv(false).await;
                cells += 1;
                busy += delivered(&parse(&cell).unwrap()).is_some() as usize;
            }
            (cells as f64 / secs as f64, busy)
        };
        let (idle_rate, idle_busy) = count_for(&mut bob, 5).await;
        for i in 0..40u8 {
            alice.send(&[Frame::Forward {
                to: bob.token,
                payload: &[i; 1000],
            }]);
        }
        let (busy_rate, busy) = count_for(&mut bob, 5).await;
        assert_eq!(idle_busy, 0);
        assert!(busy >= 10, "carrying data: {busy}");
        for rate in [idle_rate, busy_rate] {
            assert!(
                (2.0..6.5).contains(&rate),
                "idle {idle_rate}/s, busy {busy_rate}/s"
            );
        }
    }
}
