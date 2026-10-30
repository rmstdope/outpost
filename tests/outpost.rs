//! End-to-end tests: a real outpost on loopback ports, asked over UDP, TCP and HTTP.

use std::net::SocketAddr;
use std::time::Duration;

use outpost::stun::{self, BINDING, Builder, Class, Message};
use outpost::{Config, Outpost};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const TRANSACTION: stun::Transaction = *b"outpost-test";

struct Running {
    web: SocketAddr,
    udp: SocketAddr,
    tcp: SocketAddr,
}

async fn start(revision: &str) -> Running {
    let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
    let outpost = Outpost::bind(Config {
        revision: revision.to_string(),
        web: loopback,
        turn: loopback,
        ..Config::default()
    })
    .await
    .unwrap();
    let running = Running {
        web: outpost.web_addr(),
        udp: outpost.udp_addr(),
        tcp: outpost.tcp_addr(),
    };
    tokio::spawn(outpost.run(std::future::pending()));
    running
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("no answer in time")
}

/// A plain HTTP/1.1 GET, answered with the status, the raw headers and the body.
async fn get(server: SocketAddr, path: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(server).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: outpost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    within(stream.read_to_string(&mut response)).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head[9..12].parse().unwrap();
    (status, head.to_ascii_lowercase(), body.to_string())
}

#[tokio::test]
async fn a_binding_request_over_udp_is_told_its_own_address() {
    let outpost = start("test").await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&stun::binding_request(TRANSACTION), outpost.udp)
        .await
        .unwrap();
    let mut datagram = [0; 512];
    let (size, from) = within(client.recv_from(&mut datagram)).await.unwrap();
    assert_eq!(from, outpost.udp);
    let reply = Message::parse(&datagram[..size]).unwrap();
    assert_eq!(reply.class(), Class::Success);
    assert_eq!(reply.transaction(), TRANSACTION);
    assert_eq!(reply.mapped_address(), Some(client.local_addr().unwrap()));
}

#[tokio::test]
async fn udp_ignores_what_is_not_a_binding_request_and_keeps_answering() {
    let outpost = start("test").await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let not_requests = [
        b"hello".to_vec(),
        Builder::new(BINDING, Class::Success, *b"not-asked-4u").build(),
    ];
    for datagram in &not_requests {
        client.send_to(datagram, outpost.udp).await.unwrap();
    }
    client
        .send_to(&stun::binding_request(TRANSACTION), outpost.udp)
        .await
        .unwrap();
    let mut datagram = [0; 512];
    let size = within(client.recv(&mut datagram)).await.unwrap();
    assert_eq!(
        Message::parse(&datagram[..size]).unwrap().transaction(),
        TRANSACTION,
        "the first answer is to the only request"
    );
}

#[tokio::test]
async fn binding_requests_over_tcp_are_answered_in_order_on_one_connection() {
    let outpost = start("test").await;
    let mut client = TcpStream::connect(outpost.tcp).await.unwrap();
    // Two requests in one write: the listener must find where the first one ends.
    let mut requests = stun::binding_request(*b"first-reques");
    requests.extend(stun::binding_request(*b"second-reque"));
    client.write_all(&requests).await.unwrap();

    for transaction in [b"first-reques", b"second-reque"] {
        let mut reply = vec![0; stun::HEADER_LEN];
        within(client.read_exact(&mut reply)).await.unwrap();
        reply.resize(stun::message_length(&reply).unwrap(), 0);
        within(client.read_exact(&mut reply[stun::HEADER_LEN..]))
            .await
            .unwrap();
        let reply = Message::parse(&reply).unwrap();
        assert_eq!(reply.class(), Class::Success);
        assert_eq!(&reply.transaction(), transaction);
        assert_eq!(reply.mapped_address(), Some(client.local_addr().unwrap()));
    }
}

#[tokio::test]
async fn tcp_closes_a_connection_that_does_not_speak_stun() {
    let outpost = start("test").await;
    let mut client = TcpStream::connect(outpost.tcp).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: outpost\r\n\r\n")
        .await
        .unwrap();
    // Closing with our request still unread makes the kernel reset the connection instead.
    let mut rest = vec![];
    match within(client.read_to_end(&mut rest)).await {
        Ok(_) => assert!(rest.is_empty(), "{rest:02x?}"),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
}

#[tokio::test]
async fn healthz_is_ok_while_the_turn_port_answers() {
    let outpost = start("test").await;
    let (status, _, body) = get(outpost.web, "/healthz").await;
    assert_eq!((status, body.as_str()), (200, "ok"));
}

#[tokio::test]
async fn healthz_is_unavailable_when_the_turn_port_is_silent() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let app = outpost::app(
        "test".to_string(),
        silent.local_addr().unwrap(),
        Duration::from_millis(200),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let (status, _, _) = get(web, "/healthz").await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn release_json_names_the_revision_and_is_never_cached() {
    let outpost = start("0123abc").await;
    let (status, head, body) = get(outpost.web, "/release.json").await;
    assert_eq!(status, 200);
    assert!(head.contains("content-type: application/json"), "{head}");
    assert!(head.contains("cache-control: no-cache"), "{head}");
    assert_eq!(body, r#"{"revision":"0123abc"}"#);
}

#[tokio::test]
async fn the_front_page_says_what_outpost_is() {
    let outpost = start("test").await;
    let (status, head, body) = get(outpost.web, "/").await;
    assert_eq!(status, 200);
    assert!(head.contains("content-type: text/html"), "{head}");
    assert!(body.contains("relay for NESER network play"), "{body}");
    assert!(body.contains("https://neser.rmstdope.eu"), "{body}");
}
