//! Simulated packet loss on this device's own network, for testing how
//! messaging holds up on a bad connection without making the relay lossy
//! for everyone (as runserver-lan-lossy.sh does). Each direction drops a
//! set percentage of packets at random: outgoing ones are never handed to
//! the socket, incoming ones are read and thrown away before the client
//! sees them. Off (0%) until a front end turns it on with `set_loss`, and
//! process-wide, like a real network: it applies to every packet this
//! process sends to or receives from the relay.

use rand_core::{OsRng, RngCore};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::net::UdpSocket;

static SEND_LOSS: AtomicU8 = AtomicU8::new(0);
static RECEIVE_LOSS: AtomicU8 = AtomicU8::new(0);

/// The simulated loss, as `(sending, receiving)` percentages.
pub fn loss() -> (u8, u8) {
    (
        SEND_LOSS.load(Ordering::Relaxed),
        RECEIVE_LOSS.load(Ordering::Relaxed),
    )
}

/// Drop `send`% of outgoing packets and `receive`% of incoming ones from
/// now on. Each is capped at 100.
pub fn set_loss(send: u8, receive: u8) {
    SEND_LOSS.store(send.min(100), Ordering::Relaxed);
    RECEIVE_LOSS.store(receive.min(100), Ordering::Relaxed);
}

fn lose(percent: &AtomicU8) -> bool {
    let percent = percent.load(Ordering::Relaxed);
    percent > 0 && OsRng.next_u32() % 100 < u32::from(percent)
}

/// `socket.send_to`, unless the packet is lost on the way out: then it's
/// silently not sent, and this still reports success, as a real lossy
/// network would.
pub async fn send_to(socket: &UdpSocket, packet: &[u8], addr: SocketAddr) -> io::Result<usize> {
    if lose(&SEND_LOSS) {
        return Ok(packet.len());
    }
    socket.send_to(packet, addr).await
}

/// `socket.recv_from`, but packets lost on the way in are skipped: it waits
/// for the next one that gets through.
pub async fn recv_from(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    loop {
        let received = socket.recv_from(buf).await?;
        if !lose(&RECEIVE_LOSS) {
            return Ok(received);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only ever checks local percentages: changing the process-wide ones
    // would make other tests, running alongside, lose packets.
    #[test]
    fn no_loss_never_drops_and_full_loss_always_does() {
        let none = AtomicU8::new(0);
        let all = AtomicU8::new(100);
        assert!((0..1000).all(|_| !lose(&none)));
        assert!((0..1000).all(|_| lose(&all)));
    }
}
