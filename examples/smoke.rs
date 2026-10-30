//! Smoke test for a running outpost, used by CI against the production image:
//! `cargo run --example smoke -- 127.0.0.1:13478`. A Binding request over UDP and over TCP each
//! gets an address back.

use std::net::SocketAddr;
use std::time::Duration;

use outpost::stun::{self, Message};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("no answer in time")
}

fn mapped(reply: &[u8], transaction: stun::Transaction) -> SocketAddr {
    let reply = Message::parse(reply).expect("a STUN message");
    assert!(reply.is_binding_success());
    assert_eq!(reply.transaction, transaction);
    reply.mapped_address().expect("a mapped address")
}

#[tokio::main]
async fn main() {
    let server: SocketAddr = std::env::args()
        .nth(1)
        .expect("usage: smoke <host:port>")
        .parse()
        .expect("an address such as 127.0.0.1:13478");

    let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    udp.send_to(&stun::binding_request(*b"smoke-on-udp"), server)
        .await
        .unwrap();
    let mut datagram = [0; 512];
    let size = within(udp.recv(&mut datagram)).await.unwrap();
    println!(
        "UDP: seen as {}",
        mapped(&datagram[..size], *b"smoke-on-udp")
    );

    let mut tcp = within(TcpStream::connect(server)).await.unwrap();
    tcp.write_all(&stun::binding_request(*b"smoke-on-tcp"))
        .await
        .unwrap();
    let mut reply = vec![0; stun::HEADER_LEN];
    within(tcp.read_exact(&mut reply)).await.unwrap();
    reply.resize(stun::message_length(&reply).expect("a STUN header"), 0);
    within(tcp.read_exact(&mut reply[stun::HEADER_LEN..]))
        .await
        .unwrap();
    println!("TCP: seen as {}", mapped(&reply, *b"smoke-on-tcp"));
    println!("smoke test passed");
}
