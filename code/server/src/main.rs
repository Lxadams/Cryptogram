use anyhow::{Result, anyhow};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use relay_link::{
    CHAT_INNER_PAYLOAD_LEN, Challenge, LinkEnd, SessionId, Sync, TYPE_ACK, TYPE_ADMITTED_DATA,
    TYPE_DATA, TYPE_HANDSHAKE_INIT, TYPE_PATH_CHALLENGE, TYPE_PATH_RESPONSE, TYPE_SYNC,
    TYPE_SYNC_ACK,
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

use crate::stores::{MAX_ADMISSION_ENTRIES, MAX_LINKS, MAX_UNREGISTERED_QUEUED_BYTES, Tables};

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
                // hundreds of packets, and this loop must keep draining. So
                // is a refused packet: anyone can send junk. Logs never name
                // a client's address or routing token.
                debug!("Received {} bytes", len);
                match handle_request(&tables, &keys, addr, &buffer[..len]) {
                    Ok(reply) => {
                        if let Some(reply) = reply
                            && let Err(e) = socket.send_to(&reply, addr).await
                        {
                            error!("Failed to send response: {}", e);
                        }
                        // A packet queued, or a recipient synced or moved.
                        outbound_wake.notify_one();
                    }
                    Err(e) => debug!("Refused a packet: {}", e),
                }
            }
            Err(e) => {
                error!("Receive error: {}", e);
            }
        }
    }
}

/// Handle one packet from `socket_address`. Returns the reply to send back
/// there, if any: a handshake reply, a path challenge, or a sync ack.
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
        let shared_secret = relay_secret.diffie_hellman(&client_ephemeral);
        if !shared_secret.was_contributory() {
            return Err(anyhow!("Handshake with a degenerate key"));
        }
        let link_keys = relay_link::derive_link_keys(shared_secret.as_bytes());
        let session_id = tables
            .lock()
            .unwrap()
            .register_link(link_keys, socket_address)
            .ok_or_else(|| anyhow!("Link table full; refused a handshake"))?;
        debug!("Registered a new link");
        return Ok(Some(relay_link::handshake_resp(
            &keys.identity,
            &client_ephemeral,
            &relay_ephemeral,
            &session_id,
        )));
    }

    // A link packet: refused unless it's for one of our links, authenticates
    // and isn't a copy of one taken in already.
    let opened = tables
        .lock()
        .unwrap()
        .open(payload)
        .map_err(|e| anyhow!("Refused a link packet: {e}"))?;
    let session_id = opened.header.session_id;
    let plaintext = opened.plaintext;
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
                debug!("A recipient's queue is full; dropped a packet");
            }
        }
        TYPE_SYNC => {
            let sync = Sync::from_bytes(&plaintext).map_err(|e| anyhow!("Malformed sync: {e}"))?;
            sync.verify(&opened.keys)
                .map_err(|e| anyhow!("Rejected sync: {e}"))?;
            let mut tables = tables.lock().unwrap();
            if tables.link_addr(&session_id) != Some(socket_address) {
                // From an address the link hasn't shown it's at: its NAT
                // mapping changed, say. (A copy of a sync replayed from
                // elsewhere was refused above.) Nothing moves until a
                // challenge sent there comes back over the link.
                debug!("Sync from a new address; challenging it");
                let challenge =
                    path_challenge(&keys.challenge, &session_id, &socket_address, unix_secs());
                return Ok(tables.seal_for(&session_id, TYPE_PATH_CHALLENGE, &challenge));
            }
            debug!("Sync request");
            tables
                .apply_sync(sync.token, session_id, sync.admission, METADATA_TTL)
                .map_err(|e| anyhow!("Rejected sync: {e}"))?;
            // So the client knows its link is still here.
            let ack = relay_link::sync_ack_plaintext(opened.header.packet_number);
            return Ok(tables.seal_for(&session_id, TYPE_SYNC_ACK, &ack));
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
                // Full tables refuse what doesn't fit rather than grow,
                // which someone flooding the relay may be causing.
                if tables.links_full() {
                    warn!("Link table full ({MAX_LINKS}): refusing handshakes until links expire");
                }
                if tables.admission_full() {
                    warn!(
                        "Admission table full ({MAX_ADMISSION_ENTRIES}): new recipients' tags aren't kept"
                    );
                }
                if tables.unregistered_queues_full() {
                    warn!(
                        "Queues for recipients without admission tags are full ({MAX_UNREGISTERED_QUEUED_BYTES} bytes): refusing more"
                    );
                }
            }
            tokio::time::sleep(SWEEPING_TASK_INTERVAL).await;
        }
    });
}

/// A dummy packet for the client on `link`: the same size and framing as a
/// forwarded chat packet, with an all-zero delivery ID (nothing to ack) and
/// an inner type the client drops. Cover traffic is switched off for now
/// (nothing sends these), but this keeps them ready to match real traffic
/// when it's turned back on.
#[allow(dead_code)]
fn dummy_packet(link: &mut LinkEnd) -> Vec<u8> {
    let mut inner = vec![0u8; CHAT_INNER_PAYLOAD_LEN];
    inner[0] = INNER_TYPE_DUMMY;
    relay_link::forwarded_packet(link, &[0u8; 16], &inner)
}

/// Forward every packet whose recipient's pacing slot is due (see
/// `Tables::take_due`), sealed on the recipient's own link: its key, and a
/// fresh packet number each time, resends included. Returns when the next
/// slot falls due, if anything is still waiting.
async fn send_due_packets(tables: &Mutex<Tables>, socket: &UdpSocket) -> Option<Instant> {
    let (due, next_due) = {
        let mut tables = tables.lock().unwrap();
        let (due, next_due) = tables.take_due(Instant::now(), RELAY_PACKET_SPACING);
        let due: Vec<_> = due
            .into_iter()
            .filter_map(|packet| Some((packet.addr, tables.forward(&packet)?)))
            .collect();
        (due, next_due)
    };
    for (addr, packet) in due {
        // Stays queued until acknowledged, so a failed send is resent like
        // a lost one.
        match socket.send_to(&packet, addr).await {
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
    use relay_link::{
        AdmissionTag, DeliveryId, Header, Lane, LinkError, LinkKeys, RoutingToken, Side,
        routing_token_for,
    };

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

    /// A client's end of a link, as its handshake left it.
    struct TestLink {
        end: LinkEnd,
    }

    impl TestLink {
        fn session(&self) -> SessionId {
            self.end.session_id()
        }

        fn keys(&self) -> LinkKeys {
            *self.end.keys()
        }

        fn data(&mut self, recipient: RoutingToken, inner: &[u8]) -> Vec<u8> {
            relay_link::data_packet(&mut self.end, Lane::Direct, &recipient, None, inner)
        }

        fn admitted_data(
            &mut self,
            recipient: RoutingToken,
            tag: AdmissionTag,
            inner: &[u8],
        ) -> Vec<u8> {
            relay_link::data_packet(&mut self.end, Lane::Direct, &recipient, Some(&tag), inner)
        }

        /// The sync an honest client sends: for the token its key owns.
        fn sync(&mut self, token_key: &SigningKey, admission: Vec<AdmissionTag>) -> Vec<u8> {
            let sync = Sync::new(token_key, &self.keys(), admission);
            self.end.seal(Lane::Direct, TYPE_SYNC, &sync.to_bytes())
        }

        fn ack(&mut self, own_token: &RoutingToken, ids: &[DeliveryId]) -> Vec<u8> {
            let plaintext = relay_link::ack_plaintext(own_token, ids);
            self.end.seal(Lane::Direct, TYPE_ACK, &plaintext)
        }

        /// Open what the relay sent this link.
        fn receive(&mut self, packet: &[u8]) -> (Header, Vec<u8>) {
            self.end.open(packet).unwrap()
        }

        /// The challenge in a path challenge the relay sent this link.
        fn challenge(&mut self, packet: &[u8]) -> Challenge {
            let (header, plaintext) = self.receive(packet);
            assert_eq!(header.packet_type, TYPE_PATH_CHALLENGE);
            relay_link::parse_challenge(&plaintext).unwrap()
        }

        /// What the client sends back to a challenge.
        fn answer(&mut self, challenge: &Challenge) -> Vec<u8> {
            self.end.seal(Lane::Direct, TYPE_PATH_RESPONSE, challenge)
        }
    }

    /// Handshake a new client link from `addr`.
    fn link_up(tables: &Arc<Mutex<Tables>>, keys: &RelayKeys, addr: SocketAddr) -> TestLink {
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_ephemeral = X25519PublicKey::from(&client_secret);
        let init = relay_link::handshake_init(&client_ephemeral);
        let resp = handle_request(tables, keys, addr, &init).unwrap().unwrap();
        let (session, relay_ephemeral) = relay_link::parse_handshake_resp(
            &resp,
            &keys.identity.verifying_key(),
            &client_ephemeral,
        )
        .unwrap();
        let link_keys =
            relay_link::derive_link_keys(client_secret.diffie_hellman(&relay_ephemeral).as_bytes());
        TestLink {
            end: LinkEnd::new(Side::Client, link_keys, session),
        }
    }

    /// Sync `token_key`'s token on `link` from `addr`, checking the relay
    /// acks that very sync.
    fn sync_acked(
        tables: &Arc<Mutex<Tables>>,
        keys: &RelayKeys,
        addr: SocketAddr,
        link: &mut TestLink,
        token_key: &SigningKey,
        admission: Vec<AdmissionTag>,
    ) {
        let sync = link.sync(token_key, admission);
        let ack = handle_request(tables, keys, addr, &sync)
            .unwrap()
            .expect("acked");
        let (header, plaintext) = link.receive(&ack);
        assert_eq!(header.packet_type, TYPE_SYNC_ACK);
        assert_eq!(
            relay_link::parse_sync_ack(&plaintext),
            relay_link::header(&sync).map(|sync| sync.packet_number)
        );
    }

    /// `link_up`, then sync `token_key`'s token on the new link.
    fn online(
        tables: &Arc<Mutex<Tables>>,
        keys: &RelayKeys,
        addr: SocketAddr,
        token_key: &SigningKey,
    ) -> TestLink {
        let mut link = link_up(tables, keys, addr);
        sync_acked(tables, keys, addr, &mut link, token_key, Vec::new());
        link
    }

    #[test]
    fn test_sync_then_forward() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let routing_token = routing_token_for(&token_key.verifying_key());
        let socket_address = addr(50000);

        let mut link = online(&tables, &keys, socket_address, &token_key);
        {
            let tables_lock = tables.lock().unwrap();
            let metadata = tables_lock.get_metadata(&routing_token).unwrap();
            assert_eq!(metadata.incoming_addr, socket_address);
            assert_eq!(metadata.session_id, link.session());
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
        let link_keys = relay_link::derive_link_keys(&[9u8; 32]);
        let mut relay_end = LinkEnd::new(Side::Relay, link_keys, [7u8; 4]);
        let mut client_end = LinkEnd::new(Side::Client, link_keys, [7u8; 4]);

        let dummy = dummy_packet(&mut relay_end);
        let chat = relay_link::forwarded_packet(
            &mut relay_end,
            &[0x42; 16],
            &[0x07; CHAT_INNER_PAYLOAD_LEN],
        );
        assert_eq!(dummy.len(), 1138, "same size as a client's FEC chat packet");
        assert_eq!(dummy.len(), chat.len());
        assert_eq!(dummy[..5], chat[..5], "same packet type and session id");

        // Framed as the client expects: an all-zero delivery ID (nothing to
        // ack), then an inner payload starting with the type byte it ignores.
        let (_, plaintext) = client_end.open(&dummy).unwrap();
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

        // An old client's init (ephemeral key, Ed25519 key and signature)
        // is the same length, but its padding isn't zeros.
        let client_ephemeral = X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
        let mut init = relay_link::handshake_init(&client_ephemeral);
        let len = init.len();
        init[len - 1] ^= 0x01;
        let res = handle_request(&tables, &keys, addr(50000), &init);
        assert!(res.is_err(), "Non-zero padding should fail");
    }

    /// Session IDs are in the clear, so the relay picks them: replaying
    /// someone's handshake, or handshaking at all, never gets you their
    /// link.
    #[test]
    fn test_a_handshake_never_takes_over_a_live_link() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let mut victim = online(&tables, &keys, addr(50000), &token_key);

        // A handshake, copied off the wire and replayed.
        let client_ephemeral = X25519PublicKey::from(&EphemeralSecret::random_from_rng(OsRng));
        let init = relay_link::handshake_init(&client_ephemeral);
        let first = handle_request(&tables, &keys, addr(50000), &init)
            .unwrap()
            .unwrap();
        let replayed = handle_request(&tables, &keys, addr(50001), &init)
            .unwrap()
            .unwrap();
        assert_ne!(first[1..5], replayed[1..5], "a new session ID each time");
        for resp in [first, replayed] {
            assert_ne!(resp[1..5], victim.session());
        }

        // The victim's link still works, and is still where its packets go.
        let ack = victim.ack(&token, &[[0; 16]]);
        handle_request(&tables, &keys, addr(50000), &ack).unwrap();
        let tables = tables.lock().unwrap();
        assert_eq!(
            tables.get_link_keys(&victim.session()),
            Some(&victim.keys())
        );
        assert_eq!(
            tables.get_metadata(&token).unwrap().session_id,
            victim.session()
        );
    }

    /// Once the link table is full, handshakes are refused rather than
    /// growing it, so a flood of handshakes can't run the relay out of
    /// memory. Links that never sync make room again within a minute.
    #[test]
    fn test_handshakes_are_refused_while_the_link_table_is_full() {
        let (tables, keys) = relay();
        for port in 0..MAX_LINKS {
            link_up(&tables, &keys, addr(port as u16));
        }
        let init = relay_link::handshake_init(&X25519PublicKey::from(
            &EphemeralSecret::random_from_rng(OsRng),
        ));
        let err = handle_request(&tables, &keys, addr(1), &init).unwrap_err();
        assert!(err.to_string().contains("full"), "{err}");
    }

    #[test]
    fn test_edge_case_offline_queuing_and_sync() {
        let (tables, keys) = relay();
        let sender_addr = addr(50001);
        let receiver_addr = addr(50002);
        let receiver_token_key = random_signing_key();
        let receiver_token = routing_token_for(&receiver_token_key.verifying_key());

        // 1. Sender handshakes and sends to the offline receiver
        let mut sender = link_up(&tables, &keys, sender_addr);
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
        let mut receiver = online(&tables, &keys, receiver_addr, &receiver_token_key);

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
        let mut link = link_up(&tables, &keys, addr(50001));
        let victim_key = random_signing_key();
        let victim_token = routing_token_for(&victim_key.verifying_key());
        let attacker_key = random_signing_key();

        // Their own key, claiming the victim's token.
        let mut claim = Sync::new(&attacker_key, &link.keys(), Vec::new());
        claim.token = victim_token;
        let claim = link.end.seal(Lane::Direct, TYPE_SYNC, &claim.to_bytes());
        let err = handle_request(&tables, &keys, addr(50001), &claim).unwrap_err();
        assert!(err.to_string().contains("doesn't own"), "{err}");

        // The victim's public key (it's no secret), but not its signature.
        let mut forged = Sync::new(&attacker_key, &link.keys(), Vec::new());
        forged.token = victim_token;
        forged.token_public = victim_key.verifying_key();
        let forged = link.end.seal(Lane::Direct, TYPE_SYNC, &forged.to_bytes());
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
        let mut second_link = link_up(&tables, &keys, addr(50001));
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());

        let signed_for_first = Sync::new(&token_key, &first_link.keys(), Vec::new());
        let replayed = second_link
            .end
            .seal(Lane::Direct, TYPE_SYNC, &signed_for_first.to_bytes());
        assert!(handle_request(&tables, &keys, addr(50001), &replayed).is_err());
        assert!(tables.lock().unwrap().get_metadata(&token).is_none());

        sync_acked(
            &tables,
            &keys,
            addr(50001),
            &mut second_link,
            &token_key,
            Vec::new(),
        );
        assert_eq!(
            tables
                .lock()
                .unwrap()
                .get_metadata(&token)
                .unwrap()
                .session_id,
            second_link.session()
        );
    }

    /// A copy of any packet taken in already is refused, wherever it comes
    /// from: a sync replayed from elsewhere doesn't even get a challenge
    /// sent there, and a data packet replayed doesn't queue it again.
    #[test]
    fn test_replayed_packets_are_refused() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let mut victim = link_up(&tables, &keys, addr(50000));
        let sync = victim.sync(&token_key, Vec::new());
        handle_request(&tables, &keys, addr(50000), &sync).unwrap();

        for from in [addr(60000), addr(50000)] {
            let err = handle_request(&tables, &keys, from, &sync).unwrap_err();
            assert!(err.to_string().contains("replayed"), "{err}");
        }
        assert_eq!(
            tables
                .lock()
                .unwrap()
                .get_metadata(&token)
                .unwrap()
                .incoming_addr,
            addr(50000)
        );

        let data = victim.data(token, b"once");
        handle_request(&tables, &keys, addr(50000), &data).unwrap();
        assert!(handle_request(&tables, &keys, addr(60000), &data).is_err());
        let tables = tables.lock().unwrap();
        assert_eq!(tables.get_queued_packets(&token).unwrap().len(), 1);
    }

    /// A phone's NAT mapping changes: its next sync comes from a new
    /// address, the relay challenges it there, and once it answers from
    /// there everything goes to the new address, unacknowledged packets
    /// first. An answer from any other address doesn't count, and nor does
    /// a copy of the real one replayed from somewhere else afterwards.
    #[test]
    fn test_link_moves_once_it_answers_a_challenge_from_its_new_address() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let mut link = online(&tables, &keys, addr(50000), &token_key);
        tables
            .lock()
            .unwrap()
            .enqueue_message(token, b"queued".to_vec(), MESSAGE_TTL, None);
        let now = Instant::now();
        tables.lock().unwrap().take_due(now, RELAY_PACKET_SPACING);

        let sync = link.sync(&token_key, Vec::new());
        let challenge_packet = handle_request(&tables, &keys, addr(50001), &sync)
            .unwrap()
            .unwrap();
        let challenge = link.challenge(&challenge_packet);
        // An answer from anywhere else doesn't count.
        let elsewhere = link.answer(&challenge);
        assert!(handle_request(&tables, &keys, addr(50002), &elsewhere).is_err());
        assert_eq!(
            tables
                .lock()
                .unwrap()
                .get_metadata(&token)
                .unwrap()
                .incoming_addr,
            addr(50000)
        );

        let answer = link.answer(&challenge);
        assert!(
            handle_request(&tables, &keys, addr(50001), &answer)
                .unwrap()
                .is_none()
        );
        // A copy of the answer, replayed from elsewhere, moves nothing.
        assert!(handle_request(&tables, &keys, addr(60000), &answer).is_err());
        let mut tables = tables.lock().unwrap();
        assert_eq!(tables.link_addr(&link.session()), Some(addr(50001)));
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

    /// Syncing on a new link retires the old one, so nothing from the old
    /// link can move the token back to a link its owner no longer has the
    /// key for.
    #[test]
    fn test_old_links_sync_cannot_move_a_token_back() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let mut old = link_up(&tables, &keys, addr(50000));
        let old_sync = old.sync(&token_key, Vec::new());
        handle_request(&tables, &keys, addr(50000), &old_sync).unwrap();
        let new = online(&tables, &keys, addr(50000), &token_key);

        assert!(handle_request(&tables, &keys, addr(50000), &old_sync).is_err());
        let fresh_from_old = old.sync(&token_key, Vec::new());
        assert!(handle_request(&tables, &keys, addr(50000), &fresh_from_old).is_err());
        assert_eq!(
            tables
                .lock()
                .unwrap()
                .get_metadata(&token)
                .unwrap()
                .session_id,
            new.session()
        );
    }

    /// The same when the token's metadata had expired before its new link
    /// synced (a phone offline for a while, then relaunched): the old link
    /// is still retired, so it can't take the token back and cut the new
    /// one off.
    #[test]
    fn test_old_link_cannot_reclaim_its_token_after_metadata_expires() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let mut old = online(&tables, &keys, addr(50000), &token_key);
        {
            let mut t = tables.lock().unwrap();
            t.update_metadata(token, addr(50000), old.session(), Duration::ZERO);
            std::thread::sleep(Duration::from_millis(2));
            t.sweep_metadata();
            assert!(t.get_metadata(&token).is_none());
        }
        let new = online(&tables, &keys, addr(50001), &token_key);
        assert!(
            tables
                .lock()
                .unwrap()
                .get_link_keys(&old.session())
                .is_none(),
            "the old link was retired"
        );

        let from_old = old.sync(&token_key, Vec::new());
        assert!(handle_request(&tables, &keys, addr(50000), &from_old).is_err());
        let t = tables.lock().unwrap();
        assert_eq!(t.get_metadata(&token).unwrap().session_id, new.session());
        assert!(t.get_link_keys(&new.session()).is_some());
    }

    /// A link carries one token, so one link can't register any number of
    /// made-up tokens, each leaving admission tags behind for days.
    #[test]
    fn test_a_link_syncs_one_token() {
        let (tables, keys) = relay();
        let first_key = random_signing_key();
        let mut link = online(&tables, &keys, addr(50000), &first_key);
        let second_key = random_signing_key();
        let second = link.sync(&second_key, vec![[1; 8]; 64]);
        let err = handle_request(&tables, &keys, addr(50000), &second).unwrap_err();
        assert!(err.to_string().contains("another token"), "{err}");
        assert!(
            tables
                .lock()
                .unwrap()
                .get_metadata(&routing_token_for(&second_key.verifying_key()))
                .is_none()
        );
        sync_acked(
            &tables,
            &keys,
            addr(50000),
            &mut link,
            &first_key,
            Vec::new(),
        );
    }

    /// A packet the relay forwarded, bounced back to it, isn't taken for
    /// one from the client: each direction has its own key.
    #[test]
    fn test_a_forwarded_packet_bounced_back_is_refused() {
        let (tables, keys) = relay();
        let token_key = random_signing_key();
        let token = routing_token_for(&token_key.verifying_key());
        let link = online(&tables, &keys, addr(50000), &token_key);
        let forwarded = {
            let mut t = tables.lock().unwrap();
            t.enqueue_message(token, vec![7u8; 100], MESSAGE_TTL, None);
            let (due, _) = t.take_due(Instant::now(), RELAY_PACKET_SPACING);
            t.forward(&due[0]).unwrap()
        };
        assert_eq!(forwarded[1..5], link.session());
        let err = handle_request(&tables, &keys, addr(60000), &forwarded).unwrap_err();
        assert!(err.to_string().contains("authenticate"), "{err}");
        let t = tables.lock().unwrap();
        assert_eq!(t.get_queued_packets(&token).unwrap().len(), 1);
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
        let mut owner = link_up(&tables, &keys, addr(50000));
        let contact_tag = [0x5A; 8];
        sync_acked(
            &tables,
            &keys,
            addr(50000),
            &mut owner,
            &token_key,
            vec![contact_tag],
        );

        let mut flooder = link_up(&tables, &keys, addr(60000));
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
        let mut contact = link_up(&tables, &keys, addr(50001));
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
        let mut link = link_up(&tables, &keys, addr(50001));
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
        let mut sender = link_up(&tables, &keys, sender_addr);

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
    /// sealed on *their* link, prefixed with their delivery ID, and sent
    /// over UDP — all of them, in order, paced, as soon as the outbound task
    /// is woken. They stay queued until acked.
    #[tokio::test]
    async fn test_outbound_forwarding_reencrypts_and_paces_every_packet() {
        let tables = Arc::new(Mutex::new(Tables::new()));
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let recipient = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wake = Arc::new(Notify::new());
        spawn_outbound_task(Arc::clone(&tables), relay, Arc::clone(&wake));
        let (token, link_keys) = ([0x22; 16], relay_link::derive_link_keys(&[0x33; 32]));
        let session = {
            let mut t = tables.lock().unwrap();
            let session = t
                .register_link(link_keys, recipient.local_addr().unwrap())
                .unwrap();
            t.apply_sync(token, session, Vec::new(), METADATA_TTL)
                .unwrap();
            for i in 0..60u8 {
                t.enqueue_message(token, vec![i; 40], MESSAGE_TTL, None);
            }
            session
        };
        let mut client_end = LinkEnd::new(Side::Client, link_keys, session);
        let started = Instant::now();
        wake.notify_one();

        let mut buf = [0u8; 2048];
        let mut ids = Vec::new();
        for i in 0..60u8 {
            let (len, _) = recipient.recv_from(&mut buf).await.unwrap();
            let (header, inner) = client_end.open(&buf[..len]).unwrap();
            assert_eq!(header.packet_type, TYPE_DATA);
            assert_eq!(header.session_id, session);
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

    /// Refused link packets say why, which is what the relay's (debug) log
    /// shows: unknown links, forgeries and replays alike.
    #[test]
    fn test_refused_link_packets_say_why() {
        let (tables, keys) = relay();
        let mut link = link_up(&tables, &keys, addr(50000));
        let mut stranger = TestLink {
            end: LinkEnd::new(Side::Client, LinkKeys::default(), [0xAA; 4]),
        };
        let unknown = stranger.data([1; 16], b"x");
        let err = handle_request(&tables, &keys, addr(50000), &unknown).unwrap_err();
        assert!(err.to_string().contains(&LinkError::WrongLink.to_string()));

        let mut forged = link.data([1; 16], b"x");
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let err = handle_request(&tables, &keys, addr(50000), &forged).unwrap_err();
        assert!(err.to_string().contains(&LinkError::Forged.to_string()));
    }
}
