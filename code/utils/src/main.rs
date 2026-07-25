use std::net::UdpSocket;

fn send_udp() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.send_to(b"Hello", "127.0.0.1:8080")?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    send_udp()
}