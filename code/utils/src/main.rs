use utils::send_udp;

fn main() -> std::io::Result<()> {
    // Check out code/server/src/main.rs @fn handle_request for the rationale.
    send_udp(1, b"01", b"Hello") // 0 for sync request, 1 for forward request
}
