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
use crate::stun::{self, CHANNEL_DATA_HEADER_LEN, HEADER_LEN};

/// The longest message outpost takes, over either transport: more than any browser sends, and
/// it keeps what a TCP client's queue can hold small.
const MAX_MESSAGE: usize = 2048;

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
    // A longer datagram is cut short, and then refused.
    let mut datagram = [0; MAX_MESSAGE];
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
///
/// Clients are told apart by address, and a new connection can arrive from an address whose
/// old connection has not been cleaned up yet. The new one takes the address over, ending the
/// old one's allocation, and the old one cleans up only what is still its own.
async fn connection(stream: TcpStream, from: SocketAddr, network: Shared) {
    let client = Client {
        address: from,
        transport: Transport::Tcp,
    };
    let (mut reader, mut writer) = stream.into_split();
    let (queue, mut queued) = mpsc::channel::<Vec<u8>>(TCP_QUEUE);
    let replaced = network
        .tcp
        .lock()
        .unwrap()
        .insert(from, queue.clone())
        .is_some();
    if replaced {
        network.relay.lock().unwrap().disconnect(client);
    }
    let writing = tokio::spawn(async move {
        while let Some(message) = queued.recv().await {
            if writer.write_all(&message).await.is_err() {
                break;
            }
        }
    });
    let _ = messages(&mut reader, client, &network).await;
    writing.abort();
    let still_ours = {
        let mut tcp = network.tcp.lock().unwrap();
        let ours = tcp
            .get(&from)
            .is_some_and(|entry| entry.same_channel(&queue));
        if ours {
            tcp.remove(&from);
        }
        ours
    };
    if still_ours {
        network.relay.lock().unwrap().disconnect(client);
    }
}

/// Over TCP, STUN and ChannelData messages follow each other with no other framing; the first
/// four bytes tell which comes next and how long it is (RFC 8489 §6.2.2, RFC 8656 §12.5).
/// Anything else, or a message longer than `MAX_MESSAGE`, ends the connection.
async fn messages(reader: &mut OwnedReadHalf, client: Client, network: &Network) -> io::Result<()> {
    let mut message = Vec::with_capacity(MAX_MESSAGE);
    loop {
        message.resize(CHANNEL_DATA_HEADER_LEN, 0);
        reader.read_exact(&mut message).await?;
        let length = if stun::is_channel_data(&message) {
            stun::channel_data_length(&message)
        } else {
            message.resize(HEADER_LEN, 0);
            reader
                .read_exact(&mut message[CHANNEL_DATA_HEADER_LEN..])
                .await?;
            stun::message_length(&message)
        };
        let Some(length) = length.filter(|length| *length <= MAX_MESSAGE) else {
            return Ok(());
        };
        let read = message.len();
        message.resize(length, 0);
        reader.read_exact(&mut message[read..]).await?;
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
