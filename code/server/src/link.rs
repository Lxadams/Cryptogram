//! One client's link: a QUIC connection that has said hello.
//!
//! Until a cell with a valid hello arrives (see `cell::proof`), a
//! connection's datagrams are ignored and it gets none back; it's just a
//! visitor to the website. After that the relay sends it cells on its own
//! Poisson clock, whether or not anything is queued for it, and handles the
//! cells it sends: receipts settle what the relay sent, and forwarded
//! payloads are queued for their recipients.

use crate::stores::{LinkId, PacketId, RoutingToken, Tables};
use cell::{
    CellBuilder, CellTransport, Frame, ReceiveWindow, SendWindow,
    pace::PoissonClock,
    parse,
    proof::{AccessKey, verify_hello},
    quic::link_binding,
};
use quinn::Connection;
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tracing::{debug, info, warn};

/// How long a packet waits for an offline recipient. Long enough to cover a
/// phone that's been off for a while.
pub const MESSAGE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Closes one link's transport.
type Closer = Box<dyn FnOnce() + Send>;

/// Everything the relay's links share.
pub struct Relay {
    pub tables: Mutex<Tables>,
    access_key: AccessKey,
    next_link: AtomicU64,
    /// How to close each open link, so one that's been replaced can be.
    links: Mutex<HashMap<LinkId, Closer>>,
}

impl Relay {
    pub fn new(access_key: AccessKey) -> Self {
        Self {
            tables: Mutex::new(Tables::new()),
            access_key,
            next_link: AtomicU64::new(1),
            links: Mutex::new(HashMap::new()),
        }
    }
}

/// Receipt bookkeeping for one link. Our cells are tagged with the packet
/// each one carried, if any.
#[derive(Default)]
struct LinkState {
    rx: ReceiveWindow,
    tx: SendWindow<PacketId>,
}

/// Run a QUIC `connection` as a link once it says hello, until it closes.
pub async fn serve(relay: Arc<Relay>, connection: Connection) -> io::Result<()> {
    let binding = link_binding(&connection)?;
    let (token, hello_seq) = wait_for_hello(&connection, &relay.access_key, &binding).await?;
    let closer = {
        let connection = connection.clone();
        Box::new(move || connection.close(0u32.into(), b"")) as Closer
    };
    run_link(relay, Arc::new(connection), token, hello_seq, closer).await
}

/// Run a link whose hello (cell `hello_seq`) proved it owns `token`, over
/// any cell transport, until the transport fails. `close` closes it, if a
/// newer link for the same token takes over.
pub async fn run_link<T: CellTransport>(
    relay: Arc<Relay>,
    transport: Arc<T>,
    token: RoutingToken,
    hello_seq: u32,
    close: Closer,
) -> io::Result<()> {
    let link = relay.next_link.fetch_add(1, Ordering::Relaxed);
    let state = Arc::new(Mutex::new(LinkState::default()));
    state.lock().unwrap().rx.record(hello_seq);

    relay.links.lock().unwrap().insert(link, close);
    let replaced = relay.tables.lock().unwrap().bind(token, link);
    if let Some(close_old) = replaced.and_then(|old| relay.links.lock().unwrap().remove(&old)) {
        // The same user connected again (a new network, a restart). The
        // old link's unconfirmed packets go to this one instead.
        close_old();
    }
    info!("Link {link} up");

    let sender = tokio::spawn(send_cells(
        Arc::clone(&relay),
        Arc::clone(&transport),
        Arc::clone(&state),
        token,
        link,
    ));
    let result = receive_cells(&relay, &*transport, &state, token, link).await;
    sender.abort();

    // Anything sent on this link that no receipt settled goes back in line
    // for the user's next link.
    relay.tables.lock().unwrap().unbind(&token, link);
    relay.links.lock().unwrap().remove(&link);
    info!("Link {link} closed");
    result
}

/// Read cells until one carries a valid hello. Returns the routing token
/// it proved, and that cell's sequence number.
async fn wait_for_hello(
    connection: &Connection,
    access_key: &AccessKey,
    binding: &[u8; 32],
) -> io::Result<(RoutingToken, u32)> {
    loop {
        let cell = connection.recv_cell().await?;
        let Ok(parsed) = parse(&cell) else {
            continue;
        };
        for frame in &parsed.frames {
            if let Frame::Hello(hello) = frame {
                match verify_hello(hello, access_key, binding) {
                    Ok(token) => return Ok((token, parsed.seq)),
                    Err(e) => debug!("Ignored a hello: {e}"),
                }
            }
        }
    }
}

/// The relay's half of the constant-rate stream: one cell per tick of a
/// Poisson clock, carrying the next packet queued for this link's user if
/// there is one, and padding if not. The timing never depends on the queue.
async fn send_cells<T: CellTransport>(
    relay: Arc<Relay>,
    transport: Arc<T>,
    state: Arc<Mutex<LinkState>>,
    token: RoutingToken,
    link: LinkId,
) {
    let mut clock = PoissonClock::new();
    loop {
        clock.tick().await;
        let cell = {
            let next = relay.tables.lock().unwrap().next_for(&token, link);
            let mut state = state.lock().unwrap();
            let seq = state.tx.send(next.as_ref().map(|(id, _)| *id));
            let mut cell = CellBuilder::new(seq, state.rx.receipt());
            if let Some((_, payload)) = &next {
                // Forwarded payloads are at most MAX_FORWARD_PAYLOAD, which
                // is smaller than a deliver frame's room.
                cell.push(&Frame::Deliver(payload));
            }
            cell.finish()
        };
        if transport.send_cell(cell).is_err() {
            return;
        }
    }
}

async fn receive_cells<T: CellTransport>(
    relay: &Relay,
    transport: &T,
    state: &Mutex<LinkState>,
    token: RoutingToken,
    link: LinkId,
) -> io::Result<()> {
    loop {
        let cell = transport.recv_cell().await?;
        let Ok(parsed) = parse(&cell) else {
            debug!("Dropped a malformed cell");
            continue;
        };
        let settled = {
            let mut state = state.lock().unwrap();
            state.rx.record(parsed.seq);
            state.tx.on_receipt(parsed.receipt)
        };
        let mut tables = relay.tables.lock().unwrap();
        let delivered = tables.delivered(&token, &settled.delivered);
        tables.lost(&token, link, &settled.lost);
        if delivered > 0 || !settled.lost.is_empty() {
            debug!(
                "Receipt: {delivered} delivered, {} to resend",
                settled.lost.len()
            );
        }
        for frame in parsed.frames {
            if let Frame::Forward { to, payload } = frame
                && !payload.is_empty()
                && tables.enqueue(to, payload.to_vec(), MESSAGE_TTL).is_none()
            {
                warn!("A recipient's queue is full; dropped a packet");
            }
        }
    }
}
