use std::net::UdpSocket;

pub const SESSION_ID_LEN: usize = 2;

pub fn prepare_udp_payload(
    request_type: u8,
    session_id: &[u8; SESSION_ID_LEN],
    data: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + SESSION_ID_LEN + data.len());
    payload.push(request_type);
    payload.extend_from_slice(session_id);
    payload.extend_from_slice(data);
    payload
}

pub fn send_udp(
    request_type: u8,
    session_id: &[u8; SESSION_ID_LEN],
    data: &[u8],
) -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    let payload = prepare_udp_payload(request_type, session_id, data);

    socket.send_to(&payload, "127.0.0.1:443")?;
    println!(
        "Sent UDP packet with request_type: {}, session_id: {}, data: {}",
        request_type,
        String::from_utf8_lossy(session_id),
        String::from_utf8_lossy(data)
    );
    Ok(())
}
