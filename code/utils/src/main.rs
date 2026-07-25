use std::net::UdpSocket;

fn send_udp() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    
    // Check out code/server/src/main.rs @fn handle_request for the rationale.

    let request_type = 0; // 0 for sync, 1 for forward
    let session_id = b"01";
    let data = b"Hello";

    let mut payload = Vec::new();
    payload.push(request_type);
    payload.extend_from_slice(session_id);
    payload.extend_from_slice(data);

    socket.send_to(&payload, "127.0.0.1:8080")?;
    println!("Sent UDP packet");
    Ok(())
}

fn main() -> std::io::Result<()> {
    send_udp()
}