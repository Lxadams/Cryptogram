use std::net::UdpSocket;

pub fn prepare_udp_payload(request_type: u8, session_id: &[u8], data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(request_type);
    payload.extend_from_slice(session_id);
    payload.extend_from_slice(data);
    payload
}

pub fn send_udp(request_type: u8, session_id: &[u8], data: &[u8]) -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    
    let payload = prepare_udp_payload(request_type, session_id, data);

    socket.send_to(&payload, "127.0.0.1:8080")?;
    println!("Sent UDP packet with request_type: {}, session_id: {}, data: {:?}", request_type, String::from_utf8_lossy(session_id), String::from_utf8_lossy(data));
    Ok(())
}