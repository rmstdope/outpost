//! The UDP and TCP listeners on the TURN port. They hand every message to the relay and deliver
//! what comes out: an answer to whoever asked, or data to the other player, on whichever
//! transport that client uses.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::relay::{self, Client, Outgoing, Relay, Transport};
use crate::stun::{self, HEADER_LEN};

/// Messages waiting to be written to one TCP client. A client that falls this far behind loses
/// what does not fit, as it would over UDP.
const TCP_QUEUE: usize = 256;

/// The relay and every way of reaching its clients.
pub struct Network {
    pub relay: Mutex<Relay>,
    pub udp: UdpSocket,
    tcp: Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
}

pub type Shared = Arc<Network>;

impl Network {
    pub fn new(relay: Relay, udp: UdpSocket) -> Shared {
        Arc::new(Network {
            relay: Mutex::new(relay),
            udp,
            tcp: Mutex::default(),
        })
    }

    async fn receive(&self, message: &[u8], client: Client) {
        if let Some(outgoing) = relay::handle(&self.relay, message, client, Instant::now()) {
            self.deliver(outgoing).await;
        }
    }

    /// Sends a message on its way. One that cannot be delivered is the client's loss, not the
    /// listener's.
    async fn deliver(&self, outgoing: Outgoing) {
        match outgoing.to.transport {
            Transport::Udp => {
                let _ = self
                    .udp
                    .send_to(&outgoing.message, outgoing.to.address)
                    .await;
            }
            Transport::Tcp => {
                let queue = self.tcp.lock().unwrap().get(&outgoing.to.address).cloned();
                if let Some(queue) = queue {
                    let _ = queue.try_send(outgoing.message);
                }
            }
        }
    }
}

pub async fn serve_udp(network: Shared) -> io::Result<()> {
    // Larger than any datagram a browser sends; a longer one is cut short and then refused.
    let mut datagram = [0; 2048];
    loop {
        let (size, from) = match network.udp.recv_from(&mut datagram).await {
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
        network.receive(&datagram[..size], client).await;
    }
}

pub async fn serve_tcp(listener: TcpListener, network: Shared) -> io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, from)) => {
                tokio::spawn(connection(stream, from, network.clone()));
            }
            // Out of file descriptors, most likely: wait for connections to close.
            Err(error) => {
                tracing::warn!("accepting a TCP connection failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// One TCP client: its messages are read here, and everything for it is written by a task of
/// its own, in the order it was queued. When the connection ends, so does its allocation.
async fn connection(stream: TcpStream, from: SocketAddr, network: Shared) {
    let client = Client {
        address: from,
        transport: Transport::Tcp,
    };
    let (mut reader, mut writer) = stream.into_split();
    let (queue, mut queued) = mpsc::channel::<Vec<u8>>(TCP_QUEUE);
    network.tcp.lock().unwrap().insert(from, queue);
    let writing = tokio::spawn(async move {
        while let Some(message) = queued.recv().await {
            if writer.write_all(&message).await.is_err() {
                break;
            }
        }
    });
    let _ = messages(&mut reader, client, &network).await;
    network.tcp.lock().unwrap().remove(&from);
    network.relay.lock().unwrap().disconnect(client);
    writing.abort();
}

/// Over TCP, STUN messages follow each other with no other framing (RFC 8489 §6.2.2). Anything
/// that is not a STUN message ends the connection.
async fn messages(reader: &mut OwnedReadHalf, client: Client, network: &Network) -> io::Result<()> {
    let mut message = vec![0; HEADER_LEN];
    loop {
        message.resize(HEADER_LEN, 0);
        reader.read_exact(&mut message).await?;
        let Some(length) = stun::message_length(&message) else {
            return Ok(());
        };
        message.resize(length, 0);
        reader.read_exact(&mut message[HEADER_LEN..]).await?;
        network.receive(&message, client).await;
    }
}

/// Forgets expired allocations every so often; until then they are only unreachable.
pub async fn sweep(network: Shared) -> io::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        network.relay.lock().unwrap().sweep(Instant::now());
    }
}
