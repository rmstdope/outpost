//! The UDP and TCP listeners on the TURN port. They hand every message to the relay and send its
//! answer back on the transport the message came in on.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::relay::{self, Client, Relay, Transport};
use crate::stun::{self, HEADER_LEN};

pub type Shared = Arc<Mutex<Relay>>;

pub async fn serve_udp(socket: UdpSocket, relay: Shared) -> io::Result<()> {
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
        let client = Client {
            address: from,
            transport: Transport::Udp,
        };
        let reply = relay::handle(&relay, &datagram[..size], client, Instant::now());
        if let Some(reply) = reply {
            // A reply that cannot be sent is the client's loss, not the listener's.
            let _ = socket.send_to(&reply, from).await;
        }
    }
}

pub async fn serve_tcp(listener: TcpListener, relay: Shared) -> io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, from)) => {
                tokio::spawn(connection(stream, from, relay.clone()));
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
/// that is not a STUN message ends the connection, and with it the client's allocation.
async fn connection(mut stream: TcpStream, from: SocketAddr, relay: Shared) {
    let client = Client {
        address: from,
        transport: Transport::Tcp,
    };
    let _ = messages(&mut stream, client, &relay).await;
    relay.lock().unwrap().disconnect(client);
}

async fn messages(stream: &mut TcpStream, client: Client, relay: &Shared) -> io::Result<()> {
    let mut message = vec![0; HEADER_LEN];
    loop {
        message.resize(HEADER_LEN, 0);
        stream.read_exact(&mut message).await?;
        let Some(length) = stun::message_length(&message) else {
            return Ok(());
        };
        message.resize(length, 0);
        stream.read_exact(&mut message[HEADER_LEN..]).await?;
        let reply = relay::handle(relay, &message, client, Instant::now());
        if let Some(reply) = reply {
            stream.write_all(&reply).await?;
        }
    }
}

/// Forgets expired allocations every so often; until then they are only unreachable.
pub async fn sweep(relay: Shared) -> io::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        relay.lock().unwrap().sweep(Instant::now());
    }
}
