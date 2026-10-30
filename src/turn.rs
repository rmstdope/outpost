//! The UDP and TCP listeners on the TURN port. For now they answer STUN Binding requests only.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::stun::attribute::{
    MESSAGE_INTEGRITY, NONCE, REALM, SOFTWARE, UNKNOWN_ATTRIBUTES, USERNAME, XOR_MAPPED_ADDRESS,
};
use crate::stun::{self, BINDING, Builder, Class, HEADER_LEN, Message};

/// The comprehension-required attributes outpost understands in a request; any other one below
/// 0x8000 is answered with 420 (RFC 8489 §6.3.1).
const UNDERSTOOD: [u16; 4] = [USERNAME, MESSAGE_INTEGRITY, REALM, NONCE];

/// The reply to one message from `from`, if it gets one. Responses, indications, methods outpost
/// does not serve and messages whose FINGERPRINT fails are dropped silently (RFC 8489 §6.3).
fn answer(message: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    let request = Message::parse(message)?;
    if request.class() != Class::Request
        || request.method() != BINDING
        || request.fingerprint() == Some(false)
    {
        return None;
    }
    let mut unknown = vec![];
    for attribute in request.attributes() {
        if attribute.kind < 0x8000
            && !UNDERSTOOD.contains(&attribute.kind)
            && !unknown.contains(&attribute.kind)
        {
            unknown.push(attribute.kind);
        }
    }
    let response = if unknown.is_empty() {
        Builder::response(&request, Class::Success).xor_address(XOR_MAPPED_ADDRESS, from)
    } else {
        let types: Vec<u8> = unknown.into_iter().flat_map(u16::to_be_bytes).collect();
        Builder::response(&request, Class::Error)
            .error_code(420, "Unknown Attribute")
            .attribute(UNKNOWN_ATTRIBUTES, &types)
    };
    Some(response.attribute(SOFTWARE, b"outpost").fingerprint())
}

pub async fn serve_udp(socket: UdpSocket) -> io::Result<()> {
    // Larger than any datagram a browser sends; a longer one is cut short and then refused.
    let mut datagram = [0; 2048];
    loop {
        let (size, from) = match socket.recv_from(&mut datagram).await {
            Ok(received) => received,
            // Such as an ICMP error for an earlier reply: the listener must outlive it.
            Err(error) => {
                tracing::warn!("receiving on UDP failed: {error}");
                continue;
            }
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::attribute::ERROR_CODE;

    const TRANSACTION: stun::Transaction = *b"turn-tests!!";

    fn from() -> SocketAddr {
        "203.0.113.9:50000".parse().unwrap()
    }

    fn request() -> Builder {
        Builder::new(BINDING, Class::Request, TRANSACTION)
    }

    #[test]
    fn a_binding_request_is_told_where_it_came_from_with_a_fingerprint() {
        let reply = answer(&request().build(), from()).unwrap();
        let reply = Message::parse(&reply).unwrap();
        assert_eq!((reply.method(), reply.class()), (BINDING, Class::Success));
        assert_eq!(reply.transaction(), TRANSACTION);
        assert_eq!(reply.mapped_address(), Some(from()));
        assert_eq!(reply.attribute(SOFTWARE), Some(&b"outpost"[..]));
        assert_eq!(reply.fingerprint(), Some(true));
    }

    #[test]
    fn a_request_whose_fingerprint_fails_is_dropped() {
        let mut bytes = request().fingerprint();
        assert!(answer(&bytes, from()).is_some());
        bytes[8] ^= 1;
        assert!(answer(&bytes, from()).is_none());
    }

    #[test]
    fn unknown_comprehension_required_attributes_are_named_in_a_420() {
        // RFC 5769's sample request carries ICE's PRIORITY (0x0024), which a server does not know.
        let bytes = request()
            .attribute(0x0024, &[0x6e, 0, 1, 0xff])
            .attribute(0x8029, &[0; 8])
            .attribute(USERNAME, b"evtj:h6vY")
            .attribute(0x7fff, b"x")
            .attribute(0x0024, &[0; 4])
            .fingerprint();
        let reply = answer(&bytes, from()).unwrap();
        let reply = Message::parse(&reply).unwrap();
        assert_eq!((reply.method(), reply.class()), (BINDING, Class::Error));
        assert_eq!(reply.transaction(), TRANSACTION);
        assert_eq!(reply.attribute(ERROR_CODE).unwrap()[..4], [0, 0, 4, 20]);
        assert_eq!(
            reply.attribute(UNKNOWN_ATTRIBUTES),
            Some(&[0x00, 0x24, 0x7f, 0xff][..])
        );
        assert_eq!(reply.mapped_address(), None);
        assert_eq!(reply.fingerprint(), Some(true));
    }

    #[test]
    fn unknown_optional_attributes_and_whatever_follows_message_integrity_are_ignored() {
        let bytes = request()
            .attribute(0x8050, b"optional")
            .attribute(USERNAME, b"user")
            .integrity(b"key")
            .attribute(0x0024, &[0; 4])
            .fingerprint();
        let reply = answer(&bytes, from()).unwrap();
        assert_eq!(Message::parse(&reply).unwrap().class(), Class::Success);
    }

    #[test]
    fn what_is_not_a_binding_request_gets_no_answer() {
        let allocate = 0x003;
        for bytes in [
            Builder::new(BINDING, Class::Indication, TRANSACTION).build(),
            Builder::new(BINDING, Class::Success, TRANSACTION).build(),
            Builder::new(BINDING, Class::Error, TRANSACTION).build(),
            Builder::new(allocate, Class::Request, TRANSACTION).build(),
            b"not stun at all, not stun at all".to_vec(),
        ] {
            assert!(answer(&bytes, from()).is_none(), "{bytes:02x?}");
        }
    }
}
