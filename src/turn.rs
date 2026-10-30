//! The UDP and TCP listeners on the TURN port. They hand every message to the relay and deliver
//! what comes out: an answer to whoever asked, or data to the other player, on whichever
//! transport that client uses.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::limit::{HashedBuckets, Limits};
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
    tcp_slots: Mutex<Slots>,
    udp_answers: Mutex<HashedBuckets>,
    limits: Limits,
}

/// TCP connections open, in all and per IP address.
#[derive(Default)]
struct Slots {
    total: usize,
    per_address: HashMap<IpAddr, usize>,
}

pub type Shared = Arc<Network>;

impl Network {
    pub fn new(relay: Relay, udp: UdpSocket, limits: Limits) -> Shared {
        Arc::new(Network {
            relay: Mutex::new(relay),
            udp,
            tcp: Mutex::default(),
            tcp_slots: Mutex::default(),
            udp_answers: Mutex::new(HashedBuckets::new(
                limits.udp_answers,
                limits.udp_answer_buckets,
                Instant::now(),
            )),
            limits,
        })
    }

    async fn receive(&self, message: &[u8], client: Client) {
        let now = Instant::now();
        let Some(outgoing) = relay::handle(&self.relay, message, client, now) else {
            return;
        };
        // An answer over UDP may be going to a forged source (`Limits::udp_answers`).
        if outgoing.forgeable
            && outgoing.to.transport == Transport::Udp
            && !self
                .udp_answers
                .lock()
                .unwrap()
                .allow(client.address.ip(), now)
        {
            return;
        }
        self.deliver(outgoing).await;
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
                // Beyond the limits the connection is dropped, and so closed, at once.
                if let Some(slot) = Slot::take(&network, from.ip()) {
                    tokio::spawn(connection(stream, from, network.clone(), slot));
                }
            }
            // Out of file descriptors, most likely: wait for connections to close.
            Err(error) => {
                tracing::warn!("accepting a TCP connection failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// One of an address's TCP connections (`Limits::tcp_connections_per_address`); its place is
/// given back when it is dropped.
struct Slot {
    network: Shared,
    address: IpAddr,
}

impl Slot {
    fn take(network: &Shared, address: IpAddr) -> Option<Slot> {
        let mut slots = network.tcp_slots.lock().unwrap();
        let from_address = slots.per_address.get(&address).copied().unwrap_or(0);
        if slots.total >= network.limits.tcp_connections
            || from_address >= network.limits.tcp_connections_per_address
        {
            return None;
        }
        slots.total += 1;
        slots.per_address.insert(address, from_address + 1);
        Some(Slot {
            network: network.clone(),
            address,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut slots = self.network.tcp_slots.lock().unwrap();
        slots.total -= 1;
        if let Some(count) = slots.per_address.get_mut(&self.address) {
            *count -= 1;
            if *count == 0 {
                slots.per_address.remove(&self.address);
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
async fn connection(stream: TcpStream, from: SocketAddr, network: Shared, _slot: Slot) {
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
        network
            .relay
            .lock()
            .unwrap()
            .disconnect(client, Instant::now());
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
        network
            .relay
            .lock()
            .unwrap()
            .disconnect(client, Instant::now());
    }
}

/// Reads and handles messages until the connection ends, sends something that is not a
/// message, sends no whole message for `Limits::tcp_idle`, or has no allocation
/// `Limits::tcp_setup` after it opened.
async fn messages(reader: &mut OwnedReadHalf, client: Client, network: &Network) -> io::Result<()> {
    let opened = Instant::now();
    let mut allocated = false;
    let mut message = Vec::with_capacity(MAX_MESSAGE);
    loop {
        // Once allocated, the idle timeout is enough: an allocation that ends early leaves the
        // connection as any other client's, silent or not.
        allocated = allocated || network.relay.lock().unwrap().has_allocation(client);
        let wait = if allocated {
            network.limits.tcp_idle
        } else {
            let left = network.limits.tcp_setup.saturating_sub(opened.elapsed());
            if left.is_zero() {
                return Ok(());
            }
            left.min(network.limits.tcp_idle)
        };
        match tokio::time::timeout(wait, read(reader, &mut message)).await {
            Ok(Ok(true)) => network.receive(&message, client).await,
            Ok(Ok(false)) | Err(_) => return Ok(()),
            Ok(Err(error)) => return Err(error),
        }
    }
}

/// Over TCP, STUN and ChannelData messages follow each other with no other framing; the first
/// four bytes tell which comes next and how long it is (RFC 8489 §6.2.2, RFC 8656 §12.5).
/// Answers whether `message` now holds one; anything else, or a message longer than
/// `MAX_MESSAGE`, does not.
async fn read(reader: &mut OwnedReadHalf, message: &mut Vec<u8>) -> io::Result<bool> {
    message.resize(CHANNEL_DATA_HEADER_LEN, 0);
    reader.read_exact(message).await?;
    let length = if stun::is_channel_data(message) {
        stun::channel_data_length(message)
    } else {
        message.resize(HEADER_LEN, 0);
        reader
            .read_exact(&mut message[CHANNEL_DATA_HEADER_LEN..])
            .await?;
        stun::message_length(message)
    };
    let Some(length) = length.filter(|length| *length <= MAX_MESSAGE) else {
        return Ok(false);
    };
    let read = message.len();
    message.resize(length, 0);
    reader.read_exact(&mut message[read..]).await?;
    Ok(true)
}

/// Forgets expired allocations every so often; until then they are only unreachable.
pub async fn sweep(network: Shared) -> io::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        network.relay.lock().unwrap().sweep(Instant::now());
    }
}
