//! The UDP and TCP listeners on the TURN port. For now they answer STUN Binding requests only.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::stun::{self, HEADER_LEN, Message};

/// The reply to one message from `from`, if it gets one.
fn answer(message: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    let message = Message::parse(message)?;
    message
        .is_binding_request()
        .then(|| stun::binding_success(message.transaction, from))
}

pub async fn serve_udp(socket: UdpSocket) -> io::Result<()> {
    // Larger than any datagram a browser sends; a longer one is cut short and then refused.
    let mut datagram = [0; 2048];
    loop {
        let (size, from) = socket.recv_from(&mut datagram).await?;
        if let Some(reply) = answer(&datagram[..size], from) {
            // A reply that cannot be sent is the client's loss, not the listener's.
            let _ = socket.send_to(&reply, from).await;
        }
    }
}

pub async fn serve_tcp(listener: TcpListener) -> io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, from)) => {
                tokio::spawn(connection(stream, from));
            }
            // Out of file descriptors, most likely: wait for connections to close.
            Err(error) => {
                tracing::warn!("accepting a TCP connection failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Over TCP, STUN messages follow each other with no other framing (RFC 8489 §6.2.2). Anything
/// that is not a STUN message ends the connection.
async fn connection(mut stream: TcpStream, from: SocketAddr) {
    let mut message = vec![0; HEADER_LEN];
    loop {
        message.resize(HEADER_LEN, 0);
        if stream.read_exact(&mut message).await.is_err() {
            return;
        }
        let Some(length) = stun::message_length(&message) else {
            return;
        };
        message.resize(length, 0);
        if stream.read_exact(&mut message[HEADER_LEN..]).await.is_err() {
            return;
        }
        if let Some(reply) = answer(&message, from)
            && stream.write_all(&reply).await.is_err()
        {
            return;
        }
    }
}
