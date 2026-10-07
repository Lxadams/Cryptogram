use anyhow::{Result, anyhow};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use relay_link::{
    CHAT_INNER_PAYLOAD_LEN, Challenge, DeliveryId, SessionId, Sync, TYPE_ACK, TYPE_ADMITTED_DATA,
    TYPE_DATA, TYPE_HANDSHAKE_INIT, TYPE_PATH_CHALLENGE, TYPE_PATH_RESPONSE, TYPE_SYNC,
};
use sha2::Sha256;
use std::{
    fs, io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, sync::Notify};
use tracing::{debug, error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
mod stores;

use crate::stores::Tables;

const METADATA_TTL: Duration = Duration::from_secs(1000);
// How long a packet waits for an offline recipient to come back and
// acknowledge it. Long enough to cover a phone that's been off for a while.
const MESSAGE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
// Minimum gap between packets the relay sends one recipient. Half a
// client's FEC burst spacing (10ms): a live burst passes straight through
// with the spacing it arrived with — even two peers sending at once keep
// up — while a backlog (a recipient coming back online) is spread out
// instead of blasted at line rate, which would overflow their socket
// buffer and hand a jamming spike whole messages at a time.
const RELAY_PACKET_SPACING: Duration = Duration::from_millis(5);
const SWEEPING_TASK_INTERVAL: Duration = Duration::from_secs(120);

// Path challenges are answerable for this long (see `path_challenge`):
// an answer is checked against this window's challenge and the previous
// one's, so 10 to 20 seconds.
const CHALLENGE_WINDOW_SECS: u64 = 10;

// Inner type byte of a dummy packet, which the client ignores (the `0x00`
// arm in `Client::handle_incoming_packet`).
const INNER_TYPE_DUMMY: u8 = 0x00;

// The relay's Ed25519 identity, relative to where it runs (code/server
// locally, /data in Docker).
const IDENTITY_FILE: &str = "server_identity.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct ServerIdentityDto {
    ed25519_secret: String,
}

/// The relay's static Ed25519 identity from `path`, or `None` if there
/// isn't one there yet.
fn load_identity(path: &str) -> Result<Option<SigningKey>> {
    let json = match fs::read_to_string(path) {
        Ok(json) => json,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let dto: ServerIdentityDto = serde_json::from_str(&json)?;
    let mut sec_bytes = [0u8; 32];
    hex::decode_to_slice(&dto.ed25519_secret, &mut sec_bytes)?;
    Ok(Some(SigningKey::from_bytes(&sec_bytes)))
}

/// Load the relay's static Ed25519 identity from `path`, or generate one
/// and save it there if there isn't one yet.
fn load_or_create_identity(path: &str) -> Result<SigningKey> {
    if let Some(identity) = load_identity(path)? {
        return Ok(identity);
    }
    info!("No existing server identity found. Generating new Ed25519 keypair...");
    let mut identity_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut identity_bytes);
    let dto = ServerIdentityDto {
        ed25519_secret: hex::encode(identity_bytes),
    };
    fs::write(path, serde_json::to_string_pretty(&dto)?)?;
    Ok(SigningKey::from_bytes(&identity_bytes))
}

/// The relay's secrets: its identity, which clients pin, and the key its
/// path challenges are made with (see `path_challenge`), which lives only as
/// long as the process.
struct RelayKeys {
    identity: SigningKey,
    challenge: [u8; 32],
}

impl RelayKeys {
    fn new(identity: SigningKey) -> Self {
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        Self {
            identity,
            challenge,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // `--print-pubkey` prints the identity pubkey (hex) and exits, so build
    // scripts can bake it into clients: they ship with it instead of asking
    // the relay (see `relay_pubkey` in code/frontend/src-tauri/src/commands.rs).
    // It never creates an identity: a key made up here would be one no
    // running relay has, and every client built with it would be refused.
    // No logging then, so stdout is just the key.
    if std::env::args().nth(1).as_deref() == Some("--print-pubkey") {
        let Some(identity) = load_identity(IDENTITY_FILE)? else {
            let dir = std::env::current_dir()?;
            eprintln!(
                "error: no relay identity in {}. A relay makes one the first time it starts \
                 (./runserver.sh or ./runserver-lan.sh). For a relay running anywhere else \
                 (Docker, EC2), use the \"Server Static Pubkey\" it prints at startup.",
                dir.join(IDENTITY_FILE).display()
            );
            std::process::exit(1);
        };
        println!("{}", hex::encode(identity.verifying_key().as_bytes()));
        return Ok(());
    }
    tracing_subscriber::fmt().with_env_filter("info").init();

    let keys = RelayKeys::new(load_or_create_identity(IDENTITY_FILE)?);
    let server_pub_hex = hex::encode(keys.identity.verifying_key().as_bytes());

    let mut buffer = [0u8; 2048];

    // Defaults to 127.0.0.1:4430 for local testing without sudo.
    // Override with BIND_ADDR (e.g. "0.0.0.0:443" when running in Docker).
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:4430".to_string());
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
    info!("UDP server listening on {}", socket.local_addr()?);
    info!("Server Static Pubkey: {}", server_pub_hex);

    let tables = Arc::new(Mutex::new(Tables::new()));
    // Wakes the outbound task the moment something may be ready to forward
    // (a packet queued, a recipient synced), instead of it polling.
    let outbound_wake = Arc::new(Notify::new());

    spawn_outbound_task(
        Arc::clone(&tables),
        Arc::clone(&socket),
        Arc::clone(&outbound_wake),
    );
    spawn_sweeping_task(Arc::clone(&tables));

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, addr)) => {
                // Per-packet logging is debug-only: a message is tens to
                // hundreds of packets, and this loop must keep draining.
                // Logs never name a client's address or routing token.
                debug!("Received {} bytes", len);
                if let Err(e) = match handle_request(&tables, &keys, addr, &buffer[..len]) {
                    Ok(Some(resp)) => {
                        if let Err(send_err) = socket.send_to(&resp, addr).await {
                            error!("Failed to send response: {}", send_err);
                        }
                        Ok(())
                    }
                    Ok(None) => {
                        outbound_wake.notify_one();
                        Ok(())
                    }
                    Err(e) => Err(e),
                } {
                    error!("Request handling error: {}", e);
                }
            }
            Err(e) => {
                error!("Receive error: {}", e);
            }
        }
    }
}

/// Handle one packet from `socket_address`. Returns the reply to send back
/// there, if any: a handshake reply, or a path challenge.
fn handle_request(
    tables: &Arc<Mutex<Tables>>,
    keys: &RelayKeys,
    socket_address: SocketAddr,
    payload: &[u8],
) -> Result<Option<Vec<u8>>> {
    let Some(&packet_type) = payload.first() else {
        return Err(anyhow!("Empty payload"));
    };
    if packet_type == TYPE_HANDSHAKE_INIT {
        let client_ephemeral = relay_link::parse_handshake_init(payload)
            .map_err(|e| anyhow!("Invalid handshake: {e}"))?;
        let relay_secret = EphemeralSecret::random_from_rng(OsRng);
        let relay_ephemeral = X25519PublicKey::from(&relay_secret);
        let link_key =
            relay_link::derive_link_key(relay_secret.diffie_hellman(&client_ephemeral).as_bytes());
        let session_id = tables
            .lock()
            .unwrap()
            .register_link(link_key, socket_address);
        info!("Registered a new link");
        return Ok(Some(relay_link::handshake_resp(
            &keys.identity,
            &client_ephemeral,
            &relay_ephemeral,
            &session_id,
        )));
    }

    let (session_id, link_key, plaintext) = open_link_payload(tables, payload)?;
    match packet_type {
        TYPE_DATA | TYPE_ADMITTED_DATA => {
            let (recipient, tag, inner) = relay_link::parse_data(packet_type, &plaintext)
                .ok_or_else(|| anyhow!("Decrypted payload too small for routing token"))?;
            if inner.is_empty() {
                return Err(anyhow!("Data packet with nothing to forward"));
            }
            debug!("Forward request");
            let mut tables = tables.lock().unwrap();
            if tables
                .enqueue_message(recipient, inner.to_vec(), MESSAGE_TTL, tag)
                .is_none()
            {
                warn!("A recipient's queue is full; dropped a packet");
            }
        }
        TYPE_SYNC => {
            let sync = Sync::from_bytes(&plaintext).map_err(|e| anyhow!("Malformed sync: {e}"))?;
            sync.verify(&link_key)
                .map_err(|e| anyhow!("Rejected sync: {e}"))?;
            let mut tables = tables.lock().unwrap();
            if tables.link_addr(&session_id) != Some(socket_address) {
                // From an address the link hasn't shown it's at: maybe its
                // NAT mapping changed, maybe someone is replaying a copy of
                // its sync from somewhere else. Nothing moves until a
                // challenge sent there comes back over the link.
                debug!("Sync from a new address; challenging it");
                let challenge =
                    path_challenge(&keys.challenge, &session_id, &socket_address, unix_secs());
                return Ok(Some(relay_link::seal(
                    &link_key,
                    TYPE_PATH_CHALLENGE,
                    &session_id,
                    &challenge,
                )));
            }
            debug!("Sync request");
            tables.apply_sync(sync.token, session_id, sync.admission, METADATA_TTL);
        }
        TYPE_PATH_RESPONSE => {
            let challenge = relay_link::parse_challenge(&plaintext)
                .ok_or_else(|| anyhow!("Malformed path response"))?;
            if !answers_path_challenge(
                &keys.challenge,
                &session_id,
                &socket_address,
                &challenge,
                unix_secs(),
            ) {
                return Err(anyhow!("Path response doesn't answer a challenge"));
            }
            debug!("Link moved to a new address");
            tables
                .lock()
                .unwrap()
                .move_link(&session_id, socket_address, METADATA_TTL);
        }
        TYPE_ACK => {
            let (routing_token, ids) =
                relay_link::parse_ack(&plaintext).ok_or_else(|| anyhow!("Malformed ack"))?;
            let removed = tables
                .lock()
                .unwrap()
                .acknowledge(&routing_token, &session_id, ids);
            debug!("Ack: {} delivered", removed);
        }
        _ => return Err(anyhow!("Unknown packet type")),
    }
    Ok(None)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The challenge for link `session_id` at `addr`, in the time window `now`
/// falls in: an HMAC under the relay's challenge key, so the relay can check
/// an answer without remembering what it sent, and nobody else can make
/// one. It goes out sealed with the link's key, and only counts when it
/// comes back over that link from that same address, so it proves the
/// link's client really is there.
fn path_challenge(
    key: &[u8; 32],
    session_id: &SessionId,
    addr: &SocketAddr,
    now: u64,
) -> Challenge {
    challenge_mac(key, session_id, addr, now / CHALLENGE_WINDOW_SECS)
        .finalize()
        .into_bytes()[..16]
        .try_into()
        .unwrap()
}

/// Whether `challenge` is link `session_id`'s challenge at `addr` from this
/// time window or the one before.
fn answers_path_challenge(
    key: &[u8; 32],
    session_id: &SessionId,
    addr: &SocketAddr,
    challenge: &Challenge,
    now: u64,
) -> bool {
    let window = now / CHALLENGE_WINDOW_SECS;
    [window, window.saturating_sub(1)].iter().any(|&window| {
        challenge_mac(key, session_id, addr, window)
            .verify_truncated_left(challenge)
            .is_ok()
    })
}

fn challenge_mac(
    key: &[u8; 32],
    session_id: &SessionId,
    addr: &SocketAddr,
    window: u64,
) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(session_id);
    match addr.ip() {
        IpAddr::V4(ip) => mac.update(&ip.to_ipv6_mapped().octets()),
        IpAddr::V6(ip) => mac.update(&ip.octets()),
    }
    mac.update(&addr.port().to_be_bytes());
    mac.update(&window.to_be_bytes());
    mac
}

/// Decrypt a link packet: [1 byte type] [4 byte SessionId] [24 byte Nonce]
/// [Ciphertext...]. Returns its session ID, link key and plaintext.
fn open_link_payload(
    tables: &Arc<Mutex<Tables>>,
    payload: &[u8],
) -> Result<(SessionId, [u8; 32], Vec<u8>)> {
    let (_, session_id) =
        relay_link::header(payload).ok_or_else(|| anyhow!("Data packet too small"))?;
    let link_key = *tables
        .lock()
        .unwrap()
        .get_link_key(&session_id)
        .ok_or_else(|| anyhow!("Unknown Session ID"))?;
    let plaintext = relay_link::open(&link_key, payload)
        .ok_or_else(|| anyhow!("Invalid link encryption MAC"))?;
    // Authentic traffic on this link, so keep it.
    tables.lock().unwrap().touch_link(&session_id);
    Ok((session_id, link_key, plaintext))
}

fn spawn_outbound_task(tables: Arc<Mutex<Tables>>, socket: Arc<UdpSocket>, wake: Arc<Notify>) {
    tokio::spawn(async move {
        loop {
            let next_due = send_due_packets(&tables, &socket).await;
            // Sleep until the next pacing slot, or until something new
            // arrives (`notify_one` keeps a wake-up that lands mid-send).
            match next_due {
                Some(at) => tokio::select! {
                    _ = tokio::time::sleep_until(at.into()) => {}
                    _ = wake.notified() => {}
                },
                None => wake.notified().await,
            }
        }
    });
}

fn spawn_sweeping_task(tables: Arc<Mutex<Tables>>) {
    tokio::spawn(async move {
        loop {
            {
                let mut tables = tables.lock().unwrap();
                tables.sweep_active_links();
                tables.sweep_metadata();
                tables.sweep_expired_messages();
            }
            tokio::time::sleep(SWEEPING_TASK_INTERVAL).await;
        }
    });
}

/// Link-encrypt `inner_payload` for the recipient behind `session_id`,
/// behind a 16-byte prefix holding its delivery ID, which the client echoes
/// back in its ack (all zeros for a dummy packet, which needs no ack). Real
/// forwarded messages and dummy packets both go through this, so they're
/// framed identically on the wire.
fn wrap_for_recipient(
    link_key: &[u8; 32],
    session_id: &SessionId,
    delivery_id: &DeliveryId,
    inner_payload: &[u8],
) -> Vec<u8> {
    relay_link::forwarded_packet(link_key, session_id, delivery_id, inner_payload)
}

/// A dummy packet for the recipient behind `session_id`: the same size and
/// framing as a forwarded chat packet, with an inner type the client drops.
/// Cover traffic is switched off for now (nothing sends these), but this
/// keeps them ready to match real traffic when it's turned back on.
#[allow(dead_code)]
fn dummy_packet(link_key: &[u8; 32], session_id: &SessionId) -> Vec<u8> {
    let mut inner = vec![0u8; CHAT_INNER_PAYLOAD_LEN];
    inner[0] = INNER_TYPE_DUMMY;
    wrap_for_recipient(link_key, session_id, &[0u8; 16], &inner)
}

/// Forward every packet whose recipient's pacing slot is due (see
/// `Tables::take_due`), re-encrypted under the recipient's link key.
/// Returns when the next slot falls due, if anything is still waiting.
async fn send_due_packets(tables: &Mutex<Tables>, socket: &UdpSocket) -> Option<Instant> {
    let (due, next_due) = {
        let mut tables = tables.lock().unwrap();
        let (due, next_due) = tables.take_due(Instant::now(), RELAY_PACKET_SPACING);
        let due: Vec<_> = due
            .into_iter()
            .filter_map(|packet| Some((*tables.get_link_key(&packet.session_id)?, packet)))
            .collect();
        (due, next_due)
    };
    for (link_key, due) in due {
        let packet = wrap_for_recipient(&link_key, &due.session_id, &due.id, &due.payload);
        // Stays queued until acknowledged, so a failed send is resent like
        // a lost one.
        match socket.send_to(&packet, due.addr).await {
            Ok(_) => debug!("Sent {} bytes (re-encrypted)", packet.len()),
            Err(e) => error!("Failed to forward {} bytes: {}", packet.len(), e),
        }
    }
    next_due
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::{MAX_QUEUED_BYTES_PER_TOKEN, MAX_UNADMITTED_BYTES_PER_TOKEN};
    use relay_link::{AdmissionTag, RoutingToken, routing_token_for};

    fn random_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn relay() -> (Arc<Mutex<Tables>>, RelayKeys) {
        (
            Arc::new(Mutex::new(Tables::new())),
            RelayKeys::new(random_signing_key()),
        )
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// A client's link: what it learned from its handshake.
    struct TestLink {
        session: SessionId,
        key: [u8; 32],
    }

    impl TestLink {
        fn data(&self, recipient: RoutingToken, inner: &[u8]) -> Vec<u8> {
            relay_link::data_packet(&self.key, &self.session, &recipient, None, inner)
        }

        fn admitted_data(
            &self,
            recipient: RoutingToken,
            tag: AdmissionTag,
            inner: &[u8],
        ) -> Vec<u8> {
            relay_link::data_packet(&self.key, &self.session, &recipient, Some(&tag), inner)
        }

        /// The sync an honest client sends: for the token its key owns.
        fn sync(&self, token_key: &SigningKey, admission: Vec<AdmissionTag>) -> Vec<u8> {
            let sync = Sync::new(token_key, &self.key, admission);
            relay_link::seal(&self.key, TYPE_SYNC, &self.session, &sync.to_bytes())
        }

        fn ack(&self, own_token: &RoutingToken, ids: &[DeliveryId]) -> Vec<u8> {
            let plaintext = relay_link::ack_plaintext(own_token, ids);
            relay_link::seal(&self.key, TYPE_ACK, &self.session, &plaintext)
        }

        /// What the client sends back when the relay challenges it.
        fn answer(&self, challenge_packet: &[u8]) -> Vec<u8> {
            assert_eq!(challenge_packet[0], TYPE_PATH_CHALLENGE);
            let challenge = relay_link::open(&self.key, challenge_packet).unwrap();
            relay_link::seal(&self.key, TYPE_PATH_RESPONSE, &self.session, &challenge)
        }
    }

    /// Handshake a new client link from `addr`.
    fn link_up(tables: &Arc<Mutex<Tables>>, keys: &RelayKeys, addr: SocketAddr) -> TestLink {
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_ephemeral = X25519PublicKey::from(&client_secret);
        let init = relay_link::handshake_init(&random_signing_key(), &client_ephemeral);
        let resp = handle_request(tables, keys, addr, &init).unwrap().unwrap();
        let (session, relay_ephemeral) = relay_link::parse_handshake_resp(
            &resp,
            &keys.identity.verifying_key(),
            &client_ephemeral,
        )
        .unwrap();
        TestLink {
            session,
            key: relay_link::derive_link_key(
                client_secret.diffie_hellman(&relay_ephemeral).as_bytes(),
            ),
        }
    }

    /// `link_up`, then sync `token_key`'s token on the new link.
    fn online(
        tables: &Arc<Mutex<Tables>>,
        keys: &RelayKeys,
        addr: SocketAddr,
        token_key: &SigningKey,
    ) -> TestLink {
        let link = link_up(tables, keys, addr);
        let sync = link.sync(token_key, Vec::new());
        assert!(handle_request(tables, keys, addr, &sync).unwrap().is_none());
        link
    }

    #[test]
    fn test_sync_then_forward() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let routing_token = routing_token_for(&token_key.verifying_key());
        let socket_address = addr(50000);

        let link = online(&tables, &keys, socket_address, &token_key);
        {
            let tables_lock = tables.lock().unwrap();
            let metadata = tables_lock.get_metadata(&routing_token).unwrap();
            assert_eq!(metadata.incoming_addr, socket_address);
            assert_eq!(metadata.session_id, link.session);
        }

        let forward_pkt = link.data(routing_token, b"Hello");
        handle_request(&tables, &keys, socket_address, &forward_pkt).unwrap();

        let mut tables_lock = tables.lock().unwrap();
        let (msgs, _) = tables_lock.take_due(Instant::now(), RELAY_PACKET_SPACING);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].addr, socket_address);
        assert_eq!(msgs[0].payload, b"Hello");
    }

    // ==========================================
    // Missing Edge Case: Server Relay & Handshake Tests
    // ==========================================

    #[test]
    fn test_dummy_packet_matches_forwarded_chat_packet() {
        let mut link_key = [0u8; 32];
        OsRng.fill_bytes(&mut link_key);
        let session_id = [7u8; 4];

        let dummy = dummy_packet(&link_key, &session_id);
        let chat = wrap_for_recipient(
            &link_key,
            &session_id,
            &[0x42; 16],
            &[0x07; CHAT_INNER_PAYLOAD_LEN],
        );
        assert_eq!(dummy.len(), 1154, "same size as a client's FEC chat packet");
        assert_eq!(dummy.len(), chat.len());
        assert_eq!(dummy[..5], chat[..5], "same packet type and session id");

        // Framed as the client expects: an all-zero delivery ID (nothing to
        // ack), then an inner payload starting with the type byte it ignores.
        let plaintext = relay_link::open(&link_key, &dummy).unwrap();
        assert_eq!(plaintext[..16], [0u8; 16]);
        assert_eq!(plaintext[16], INNER_TYPE_DUMMY);
    }

    #[test]
    fn test_edge_case_invalid_handshake() {
        let (tables, keys) = relay();
        let res = handle_request(&tables, &keys, addr(50000), &[]);
        assert!(res.is_err(), "Empty packet should fail");

        let res = handle_request(&tables, &keys, addr(50000), &[TYPE_HANDSHAKE_INIT, 0x01]);
        assert!(res.is_err(), "Invalid handshake length should fail");
    }

    #[test]
    fn test_edge_case_handshake_mutual_auth_failure() {
        let (tables, keys) = relay();
        let client_ephemeral = X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
        let mut hs_pkt = relay_link::handshake_init(&random_signing_key(), &client_ephemeral);

        // Corrupt the client's signature
        let len = hs_pkt.len();
        hs_pkt[len - 1] ^= 0x01;

        let res = handle_request(&tables, &keys, addr(50000), &hs_pkt);
        assert!(res.is_err(), "Invalid client signature must fail");
    }

    /// Session IDs are in the clear, so the relay picks them: replaying
    /// someone's handshake, or handshaking at all, never gets you their
    /// link.
    #[test]
    fn test_a_handshake_never_takes_over_a_live_link() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let victim = online(&tables, &keys, addr(50000), &token_key);

        // The victim's own handshake, copied off the wire and replayed.
        let client_ephemeral = X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
        let init = relay_link::handshake_init(&random_signing_key(), &client_ephemeral);
        let first = handle_request(&tables, &keys, addr(50000), &init)
            .unwrap()
            .unwrap();
        let replayed = handle_request(&tables, &keys, addr(50001), &init)
            .unwrap()
            .unwrap();
        assert_ne!(first[1..5], replayed[1..5], "a new session ID each time");
        for resp in [first, replayed] {
            assert_ne!(resp[1..5], victim.session);
        }

        // The victim's link still works, and is still where its packets go.
        let ack = victim.ack(&token, &[[0; 16]]);
        handle_request(&tables, &keys, addr(50000), &ack).unwrap();
        let tables = tables.lock().unwrap();
        assert_eq!(tables.get_link_key(&victim.session), Some(&victim.key));
        assert_eq!(
            tables.get_metadata(&token).unwrap().session_id,
            victim.session
        );
    }

    #[test]
    fn test_edge_case_offline_queuing_and_sync() {
        let (tables, keys) = relay();
        let sender_addr = addr(50001);
        let receiver_addr = addr(50002);
        let receiver_token_key = random_signing_key();
        let receiver_token = routing_token_for(&receiver_token_key.verifying_key());

        // 1. Sender handshakes and sends to the offline receiver
        let sender = link_up(&tables, &keys, sender_addr);
        let forward_pkt = sender.data(receiver_token, b"QueuedMsg");
        handle_request(&tables, &keys, sender_addr, &forward_pkt).unwrap();

        // Ensure it's in the offline queue, NOT the outbound queue
        {
            let mut tables_lock = tables.lock().unwrap();
            let (msgs, next_due) = tables_lock.take_due(Instant::now(), RELAY_PACKET_SPACING);
            assert_eq!(msgs.len(), 0, "Should not be outbound yet");
            assert!(next_due.is_none(), "an offline recipient schedules nothing");
            assert_eq!(
                tables_lock
                    .get_queued_packets(&receiver_token)
                    .unwrap()
                    .len(),
                1
            );
        }

        // 2. Receiver comes online: handshake, then sync
        let receiver = online(&tables, &keys, receiver_addr, &receiver_token_key);

        // 3. Check that the queued packet was flushed to the outbound queue
        let delivered_id = {
            let mut tables_lock = tables.lock().unwrap();
            let (msgs, _) = tables_lock.take_due(Instant::now(), RELAY_PACKET_SPACING);
            assert_eq!(
                msgs.len(),
                1,
                "Queued message should be flushed to outbound"
            );
            assert_eq!(msgs[0].payload, b"QueuedMsg");
            // Still queued until the receiver acknowledges it.
            assert_eq!(
                tables_lock
                    .get_queued_packets(&receiver_token)
                    .unwrap()
                    .len(),
                1
            );
            msgs[0].id
        };

        // 4. Receiver acks it, which removes it from the queue
        let ack_pkt = receiver.ack(&receiver_token, &[delivered_id]);
        handle_request(&tables, &keys, receiver_addr, &ack_pkt).unwrap();
        assert!(
            tables
                .lock()
                .unwrap()
                .get_queued_packets(&receiver_token)
                .is_none()
        );
    }

    /// Someone with their own link session can't sync a routing token they
    /// don't own, so they can't redirect its owner's queued packets to
    /// themselves (or ack them away).
    #[test]
    fn test_sync_for_someone_elses_token_is_rejected() {
        let (tables, keys) = relay();
        let link = link_up(&tables, &keys, addr(50001));
        let victim_key = random_signing_key();
        let victim_token = routing_token_for(&victim_key.verifying_key());
        let attacker_key = random_signing_key();

        // Their own key, claiming the victim's token.
        let mut claim = Sync::new(&attacker_key, &link.key, Vec::new());
        claim.token = victim_token;
        let claim = relay_link::seal(&link.key, TYPE_SYNC, &link.session, &claim.to_bytes());
        let err = handle_request(&tables, &keys, addr(50001), &claim).unwrap_err();
        assert!(err.to_string().contains("doesn't own"), "{err}");

        // The victim's public key (it's no secret), but not its signature.
        let mut forged = Sync::new(&attacker_key, &link.key, Vec::new());
        forged.token = victim_token;
        forged.token_public = victim_key.verifying_key();
        let forged = relay_link::seal(&link.key, TYPE_SYNC, &link.session, &forged.to_bytes());
        let err = handle_request(&tables, &keys, addr(50001), &forged).unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");

        assert!(tables.lock().unwrap().get_metadata(&victim_token).is_none());
    }

    /// A sync is signed for one link, so a copy of it can't be replayed on
    /// another.
    #[test]
    fn test_sync_signed_for_another_link_is_rejected() {
        let (tables, keys) = relay();
        let first_link = link_up(&tables, &keys, addr(50001));
        let second_link = link_up(&tables, &keys, addr(50001));
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());

        let signed_for_first = Sync::new(&token_key, &first_link.key, Vec::new());
        let replayed = relay_link::seal(
            &second_link.key,
            TYPE_SYNC,
            &second_link.session,
            &signed_for_first.to_bytes(),
        );
        assert!(handle_request(&tables, &keys, addr(50001), &replayed).is_err());
        assert!(tables.lock().unwrap().get_metadata(&token).is_none());

        let honest = second_link.sync(&token_key, Vec::new());
        handle_request(&tables, &keys, addr(50001), &honest).unwrap();
        assert_eq!(
            tables
                .lock()
                .unwrap()
                .get_metadata(&token)
                .unwrap()
                .session_id,
            second_link.session
        );
    }

    /// A sync copied off the wire and replayed from another address moves
    /// nothing: the relay only challenges that address, and the challenge
    /// is sealed with a key the replayer doesn't have.
    #[test]
    fn test_sync_replayed_from_another_address_moves_nothing() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let victim = link_up(&tables, &keys, addr(50000));
        let sync = victim.sync(&token_key, Vec::new());
        handle_request(&tables, &keys, addr(50000), &sync).unwrap();
        tables.lock().unwrap().enqueue_message(
            token,
            b"for the victim".to_vec(),
            MESSAGE_TTL,
            None,
        );

        let challenge = handle_request(&tables, &keys, addr(60000), &sync)
            .unwrap()
            .expect("challenged");
        assert_eq!(challenge[0], TYPE_PATH_CHALLENGE);
        assert!(
            relay_link::open(&[0; 32], &challenge).is_none(),
            "unreadable without the link key"
        );

        let mut tables = tables.lock().unwrap();
        assert_eq!(
            tables.get_metadata(&token).unwrap().incoming_addr,
            addr(50000)
        );
        let (due, _) = tables.take_due(Instant::now(), RELAY_PACKET_SPACING);
        assert_eq!(due[0].addr, addr(50000), "still sent to the victim");
    }

    /// A phone's NAT mapping changes: its next sync comes from a new
    /// address, the relay challenges it there, and once it answers from
    /// there everything goes to the new address, unacknowledged packets
    /// first.
    #[test]
    fn test_link_moves_once_it_answers_a_challenge_from_its_new_address() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let link = online(&tables, &keys, addr(50000), &token_key);
        tables
            .lock()
            .unwrap()
            .enqueue_message(token, b"queued".to_vec(), MESSAGE_TTL, None);
        let now = Instant::now();
        tables.lock().unwrap().take_due(now, RELAY_PACKET_SPACING);

        let sync = link.sync(&token_key, Vec::new());
        let challenge = handle_request(&tables, &keys, addr(50001), &sync)
            .unwrap()
            .unwrap();
        // An answer from anywhere else doesn't count.
        let answer = link.answer(&challenge);
        assert!(handle_request(&tables, &keys, addr(50002), &answer).is_err());
        assert_eq!(
            tables
                .lock()
                .unwrap()
                .get_metadata(&token)
                .unwrap()
                .incoming_addr,
            addr(50000)
        );

        assert!(
            handle_request(&tables, &keys, addr(50001), &answer)
                .unwrap()
                .is_none()
        );
        let mut tables = tables.lock().unwrap();
        assert_eq!(tables.link_addr(&link.session), Some(addr(50001)));
        assert_eq!(
            tables.get_metadata(&token).unwrap().incoming_addr,
            addr(50001)
        );
        let (resent, _) =
            tables.take_due(Instant::now() + RELAY_PACKET_SPACING, RELAY_PACKET_SPACING);
        assert_eq!(resent.len(), 1, "resent at once");
        assert_eq!(resent[0].addr, addr(50001));
    }

    #[test]
    fn test_path_challenges_expire_and_are_bound_to_their_link_and_address() {
        let key = [5u8; 32];
        let (session, at) = ([1u8; 4], addr(50000));
        let now = 1_000_000;
        let challenge = path_challenge(&key, &session, &at, now);
        assert!(answers_path_challenge(&key, &session, &at, &challenge, now));
        assert!(answers_path_challenge(
            &key,
            &session,
            &at,
            &challenge,
            now + CHALLENGE_WINDOW_SECS
        ));
        assert!(!answers_path_challenge(
            &key,
            &session,
            &at,
            &challenge,
            now + 2 * CHALLENGE_WINDOW_SECS
        ));
        assert!(!answers_path_challenge(&key, &[2; 4], &at, &challenge, now));
        assert!(!answers_path_challenge(
            &key,
            &session,
            &addr(50001),
            &challenge,
            now
        ));
        assert!(!answers_path_challenge(
            &[6; 32], &session, &at, &challenge, now
        ));
    }

    /// Syncing on a new link retires the old one, so a sync replayed from
    /// the old link can't move the token back to a link its owner no longer
    /// has the key for.
    #[test]
    fn test_old_links_sync_cannot_move_a_token_back() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let old = link_up(&tables, &keys, addr(50000));
        let old_sync = old.sync(&token_key, Vec::new());
        handle_request(&tables, &keys, addr(50000), &old_sync).unwrap();
        let new = online(&tables, &keys, addr(50000), &token_key);

        assert!(handle_request(&tables, &keys, addr(50000), &old_sync).is_err());
        assert_eq!(
            tables
                .lock()
                .unwrap()
                .get_metadata(&token)
                .unwrap()
                .session_id,
            new.session
        );
    }

    /// Anyone who knows a token (it's in its owner's QR code) can send to
    /// it, but once its owner has registered its contacts' admission tags,
    /// that only fills a small queue of its own: contacts' messages still
    /// get in.
    #[test]
    fn test_flooding_a_token_cannot_block_its_contacts() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let owner = link_up(&tables, &keys, addr(50000));
        let contact_tag = [0x5A; 8];
        let sync = owner.sync(&token_key, vec![contact_tag]);
        handle_request(&tables, &keys, addr(50000), &sync).unwrap();

        let flooder = link_up(&tables, &keys, addr(60000));
        for i in 0..(MAX_QUEUED_BYTES_PER_TOKEN / 1000 + 10) {
            let mut junk = vec![0xAB; 1000];
            junk[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let tag = [(i % 256) as u8; 8]; // guessing, or no tag at all
            let packet = if i % 2 == 0 {
                flooder.data(token, &junk)
            } else {
                flooder.admitted_data(token, tag, &junk)
            };
            handle_request(&tables, &keys, addr(60000), &packet).unwrap();
        }
        let contact = link_up(&tables, &keys, addr(50001));
        let message = contact.admitted_data(token, contact_tag, b"from a contact");
        handle_request(&tables, &keys, addr(50001), &message).unwrap();

        let tables = tables.lock().unwrap();
        let queue = tables.get_queued_packets(&token).unwrap();
        let junk_bytes: usize = queue
            .iter()
            .filter(|p| !p.admitted)
            .map(|p| p.payload.len())
            .sum();
        assert!(junk_bytes <= MAX_UNADMITTED_BYTES_PER_TOKEN);
        assert_eq!(queue.back().unwrap().payload, b"from a contact");
        assert!(queue.back().unwrap().admitted);
    }

    /// An empty data packet used to be how a client synced, unsigned. It's
    /// refused now, rather than queued or treated as a sync.
    #[test]
    fn test_empty_data_packet_is_not_a_sync() {
        let (tables, keys) = relay();
        let link = link_up(&tables, &keys, addr(50001));
        let token = [0xCC; 16];

        let old_style_sync = link.data(token, b"");
        assert!(handle_request(&tables, &keys, addr(50001), &old_style_sync).is_err());
        let tables = tables.lock().unwrap();
        assert!(tables.get_metadata(&token).is_none());
        assert!(tables.get_queued_packets(&token).is_none());
    }

    #[test]
    fn test_edge_case_offline_queue_dos_bounds() {
        let (tables, keys) = relay();
        let sender_addr = addr(50001);
        let receiver_token = [0xCC; 16];
        let sender = link_up(&tables, &keys, sender_addr);

        // Spam an offline token with more than its queue holds
        let cap = MAX_QUEUED_BYTES_PER_TOKEN;
        let packet = vec![0xAB; 1000];
        let fits = cap / packet.len();
        for i in 0..fits + 5 {
            let mut msg = packet.clone();
            msg[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let forward_pkt = sender.data(receiver_token, &msg);
            handle_request(&tables, &keys, sender_addr, &forward_pkt).unwrap();
        }

        // The queue is bounded by bytes, and keeps the *oldest* packets:
        // later ones are refused, rather than earlier ones evicted.
        let tables_lock = tables.lock().unwrap();
        let queue = tables_lock.get_queued_packets(&receiver_token).unwrap();
        assert_eq!(
            queue.len(),
            fits,
            "Offline queue must refuse packets beyond limit"
        );
        assert_eq!(queue.front().unwrap().payload[..8], 0u64.to_be_bytes());
        assert_eq!(
            queue.back().unwrap().payload[..8],
            (fits as u64 - 1).to_be_bytes()
        );
    }

    /// A backlog for an online recipient comes out whole, in order, and one
    /// packet per pacing slot — never all at once. Then nothing more until
    /// the first unacknowledged packet is due a resend.
    #[test]
    fn test_backlog_is_paced_out_whole_and_in_order() {
        let mut tables = Tables::new();
        let token = [0xDD; 16];
        tables.update_metadata(token, addr(50003), [0xEE; 4], METADATA_TTL);
        for i in 0..300u32 {
            tables.enqueue_message(token, i.to_be_bytes().to_vec(), MESSAGE_TTL, None);
        }
        let start = Instant::now();
        let mut now = start;
        for i in 0..300u32 {
            let (due, next_due) = tables.take_due(now, RELAY_PACKET_SPACING);
            assert_eq!(due.len(), 1, "one packet per slot");
            assert_eq!(due[0].payload, i.to_be_bytes());
            let (early, _) = tables.take_due(now, RELAY_PACKET_SPACING);
            assert!(early.is_empty(), "nothing before the next slot");
            if i < 299 {
                assert_eq!(next_due, Some(now + RELAY_PACKET_SPACING));
            } else {
                assert_eq!(
                    next_due,
                    Some(start + crate::stores::FIRST_RESEND_DELAY),
                    "all sent; next is the first resend"
                );
            }
            now += RELAY_PACKET_SPACING;
        }
    }

    /// Recipients are paced independently: one's backlog doesn't hold up
    /// another's packets.
    #[test]
    fn test_recipients_are_paced_independently() {
        let mut tables = Tables::new();
        let (a, b) = ([0xA1; 16], [0xB1; 16]);
        tables.update_metadata(a, addr(1), [1; 4], METADATA_TTL);
        tables.update_metadata(b, addr(2), [2; 4], METADATA_TTL);
        for _ in 0..10 {
            tables.enqueue_message(a, vec![0xA], MESSAGE_TTL, None);
        }
        tables.enqueue_message(b, vec![0xB], MESSAGE_TTL, None);
        let (due, _) = tables.take_due(Instant::now(), RELAY_PACKET_SPACING);
        let mut payloads: Vec<_> = due.iter().map(|p| p.payload.clone()).collect();
        payloads.sort();
        assert_eq!(payloads, [vec![0xA], vec![0xB]]);
    }

    /// The whole forwarding path: packets queued for an online recipient are
    /// re-encrypted under *their* link key, prefixed with their delivery ID,
    /// and sent over UDP — all of them, in order, paced, as soon as the
    /// outbound task is woken. They stay queued until acked.
    #[tokio::test]
    async fn test_outbound_forwarding_reencrypts_and_paces_every_packet() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let recipient = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wake = Arc::new(Notify::new());
        spawn_outbound_task(Arc::clone(&tables), relay, Arc::clone(&wake));
        let (token, link_key) = ([0x22; 16], [0x33; 32]);
        let session = {
            let mut t = tables.lock().unwrap();
            let session = t.register_link(link_key, recipient.local_addr().unwrap());
            t.apply_sync(token, session, Vec::new(), METADATA_TTL);
            for i in 0..60u8 {
                t.enqueue_message(token, vec![i; 40], MESSAGE_TTL, None);
            }
            session
        };
        let started = Instant::now();
        wake.notify_one();

        let mut buf = [0u8; 2048];
        let mut ids = Vec::new();
        for i in 0..60u8 {
            let (len, _) = recipient.recv_from(&mut buf).await.unwrap();
            let packet = &buf[..len];
            assert_eq!(packet[0], TYPE_DATA);
            assert_eq!(packet[1..5], session);
            let inner = relay_link::open(&link_key, packet).unwrap();
            ids.push(DeliveryId::try_from(&inner[..16]).unwrap());
            assert_eq!(inner[16..], [i; 40]);
        }
        assert!(started.elapsed() >= RELAY_PACKET_SPACING * 59, "paced");
        let mut t = tables.lock().unwrap();
        assert_eq!(
            t.get_queued_packets(&token).unwrap().len(),
            60,
            "awaiting acks"
        );
        assert_eq!(
            t.acknowledge(&token, &session, &ids),
            60,
            "IDs match the queue"
        );
        assert!(t.get_queued_packets(&token).is_none());
    }

    #[test]
    fn test_edge_case_offline_queue_ttl_expiry() {
        let mut tables = Tables::new();
        let receiver_token = [0xCC; 16];

        // Manually enqueue a message with 0 TTL (so it expires immediately)
        tables.enqueue_message(
            receiver_token,
            b"ExpiredMsg".to_vec(),
            std::time::Duration::from_secs(0),
            None,
        );

        // Wait 1 ms to ensure 'now' is past the expiry
        std::thread::sleep(std::time::Duration::from_millis(1));

        // Enqueue a valid message
        tables.enqueue_message(
            receiver_token,
            b"ValidMsg".to_vec(),
            std::time::Duration::from_secs(3600),
            None,
        );

        assert_eq!(tables.get_queued_packets(&receiver_token).unwrap().len(), 2);

        // Sweep
        tables.sweep_expired_messages();

        // Queue should now only have the valid message
        let queue = tables.get_queued_packets(&receiver_token).unwrap();
        assert_eq!(queue.len(), 1, "Expired message should be swept");
        assert_eq!(queue[0].payload, b"ValidMsg");
    }

    /// `--print-pubkey` must never make up an identity: a key no running
    /// relay has would be baked into every client built with it.
    #[test]
    fn test_loading_a_missing_identity_creates_nothing() {
        let path = std::env::temp_dir().join(format!("relay-identity-test-{}", std::process::id()));
        let path = path.to_string_lossy().into_owned();
        let _ = fs::remove_file(&path);
        assert!(load_identity(&path).unwrap().is_none());
        assert!(!std::path::Path::new(&path).exists());

        let created = load_or_create_identity(&path).unwrap();
        let loaded = load_identity(&path).unwrap().unwrap();
        assert_eq!(created.verifying_key(), loaded.verifying_key());
        fs::remove_file(&path).unwrap();
    }
}
