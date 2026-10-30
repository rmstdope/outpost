//! End-to-end tests: a real outpost on loopback ports, asked over UDP, TCP and HTTP.

use std::net::SocketAddr;
use std::time::Duration;

use outpost::stun::attribute::{
    CHANNEL_NUMBER, DATA, ERROR_CODE, NONCE, REALM, REQUESTED_TRANSPORT, USERNAME,
    XOR_PEER_ADDRESS, XOR_RELAYED_ADDRESS,
};
use outpost::stun::{
    self, ALLOCATE, BINDING, Builder, CHANNEL_BIND, CREATE_PERMISSION, Class, Message, SEND,
    long_term_key,
};
use outpost::{Config, Credentials, Outpost};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

const TRANSACTION: stun::Transaction = *b"outpost-test";

struct Running {
    web: SocketAddr,
    udp: SocketAddr,
    tcp: SocketAddr,
    room: Credentials,
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
        room: outpost.open_room(),
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

/// A TURN client's connection to outpost, over either transport.
enum Line {
    Udp(UdpSocket, SocketAddr),
    Tcp(TcpStream),
}

impl Line {
    async fn udp(server: SocketAddr) -> Line {
        Line::Udp(UdpSocket::bind("127.0.0.1:0").await.unwrap(), server)
    }

    async fn tcp(server: SocketAddr) -> Line {
        Line::Tcp(TcpStream::connect(server).await.unwrap())
    }

    async fn put(&mut self, message: &[u8]) {
        match self {
            Line::Udp(socket, server) => {
                socket.send_to(message, *server).await.unwrap();
            }
            Line::Tcp(stream) => stream.write_all(message).await.unwrap(),
        }
    }

    /// The next message outpost sends this way.
    async fn next(&mut self) -> Vec<u8> {
        match self {
            Line::Udp(socket, _) => {
                let mut datagram = vec![0; 2048];
                let size = within(socket.recv(&mut datagram)).await.unwrap();
                datagram.truncate(size);
                datagram
            }
            Line::Tcp(stream) => {
                let mut message = vec![0; stun::HEADER_LEN];
                within(stream.read_exact(&mut message[..4])).await.unwrap();
                let length = match stun::channel_data_length(&message) {
                    Some(length) => {
                        message.truncate(4);
                        length
                    }
                    None => {
                        within(stream.read_exact(&mut message[4..])).await.unwrap();
                        stun::message_length(&message).unwrap()
                    }
                };
                let read = message.len();
                message.resize(length, 0);
                within(stream.read_exact(&mut message[read..]))
                    .await
                    .unwrap();
                message
            }
        }
    }

    async fn ask(&mut self, request: &[u8]) -> Vec<u8> {
        self.put(request).await;
        self.next().await
    }

    /// Asks as a browser does: unsigned first, then signed with the nonce it was given.
    /// Answers the final reply.
    async fn ask_logged_in(
        &mut self,
        room: &Credentials,
        request: impl Fn(stun::Transaction) -> Builder,
    ) -> Vec<u8> {
        let challenge = self.ask(&request(*b"first-try!!!").build()).await;
        let challenge = Message::parse(&challenge).unwrap();
        assert_eq!(error_code(&challenge), Some(401));
        let key = long_term_key(&room.username, "outpost", &room.password);
        let signed = request(*b"second-try!!")
            .attribute(USERNAME, room.username.as_bytes())
            .attribute(REALM, challenge.attribute(REALM).unwrap())
            .attribute(NONCE, challenge.attribute(NONCE).unwrap())
            .integrity(&key)
            .fingerprint();
        self.ask(&signed).await
    }

    async fn allocate(&mut self, room: &Credentials) -> Vec<u8> {
        self.ask_logged_in(room, |transaction| {
            Builder::new(ALLOCATE, Class::Request, transaction)
                .attribute(REQUESTED_TRANSPORT, &[17, 0, 0, 0])
        })
        .await
    }

    /// Allocates and answers the relayed address.
    async fn relayed(&mut self, room: &Credentials) -> SocketAddr {
        let reply = self.allocate(room).await;
        Message::parse(&reply)
            .unwrap()
            .xor_address(XOR_RELAYED_ADDRESS)
            .unwrap()
    }

    async fn bind(&mut self, room: &Credentials, number: u16, peer: SocketAddr) {
        let reply = self
            .ask_logged_in(room, |transaction| {
                Builder::new(CHANNEL_BIND, Class::Request, transaction)
                    .attribute(CHANNEL_NUMBER, &[(number >> 8) as u8, number as u8, 0, 0])
                    .xor_address(XOR_PEER_ADDRESS, peer)
            })
            .await;
        assert_eq!(Message::parse(&reply).unwrap().class(), Class::Success);
    }

    async fn permit(&mut self, room: &Credentials, peer: SocketAddr) {
        let reply = self
            .ask_logged_in(room, |transaction| {
                Builder::new(CREATE_PERMISSION, Class::Request, transaction)
                    .xor_address(XOR_PEER_ADDRESS, peer)
            })
            .await;
        assert_eq!(Message::parse(&reply).unwrap().class(), Class::Success);
    }
}

fn error_code(message: &Message) -> Option<u16> {
    let value = message.attribute(ERROR_CODE)?;
    Some(u16::from(value[2]) * 100 + u16::from(value[3]))
}

#[tokio::test]
async fn both_players_of_a_room_get_relayed_addresses_over_udp_and_tcp() {
    let outpost = start("test").await;
    let key = long_term_key(&outpost.room.username, "outpost", &outpost.room.password);
    let mut relayed = vec![];
    for mut line in [Line::udp(outpost.udp).await, Line::tcp(outpost.tcp).await] {
        let reply = line.allocate(&outpost.room).await;
        let reply = Message::parse(&reply).unwrap();
        assert_eq!(reply.class(), Class::Success);
        assert!(reply.integrity_holds(&key));
        relayed.push(reply.xor_address(XOR_RELAYED_ADDRESS).unwrap());
    }
    assert_ne!(relayed[0], relayed[1]);
    assert!(relayed.iter().all(|address| address.ip().is_loopback()));
}

#[tokio::test]
async fn a_closed_tcp_connection_gives_its_place_in_the_room_back() {
    let outpost = start("test").await;
    let mut over_tcp = Line::tcp(outpost.tcp).await;
    let reply = over_tcp.allocate(&outpost.room).await;
    assert_eq!(Message::parse(&reply).unwrap().class(), Class::Success);
    // Fill the rest of the room over UDP.
    let mut lines = vec![];
    loop {
        let mut line = Line::udp(outpost.udp).await;
        let reply = line.allocate(&outpost.room).await;
        match error_code(&Message::parse(&reply).unwrap()) {
            None => lines.push(line),
            Some(code) => {
                assert_eq!(code, 486);
                break;
            }
        }
    }

    drop(over_tcp);
    within(async {
        loop {
            let mut line = Line::udp(outpost.udp).await;
            let reply = line.allocate(&outpost.room).await;
            if Message::parse(&reply).unwrap().class() == Class::Success {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn game_data_crosses_between_a_udp_player_and_a_tcp_player() {
    let outpost = start("test").await;
    let mut over_udp = Line::udp(outpost.udp).await;
    let mut over_tcp = Line::tcp(outpost.tcp).await;
    let udp_relayed = over_udp.relayed(&outpost.room).await;
    let tcp_relayed = over_tcp.relayed(&outpost.room).await;
    over_udp.permit(&outpost.room, tcp_relayed).await;
    over_tcp.permit(&outpost.room, udp_relayed).await;

    carries(
        &mut over_udp,
        udp_relayed,
        &mut over_tcp,
        tcp_relayed,
        b"over udp",
    )
    .await;
    carries(
        &mut over_tcp,
        tcp_relayed,
        &mut over_udp,
        udp_relayed,
        b"over tcp",
    )
    .await;
}

/// Sends `data` from one player to the other and checks it arrives as a Data indication from
/// the sender's relayed address.
async fn carries(
    from: &mut Line,
    from_relayed: SocketAddr,
    to: &mut Line,
    to_relayed: SocketAddr,
    data: &[u8],
) {
    let send = Builder::new(SEND, Class::Indication, *b"send-it-on!!")
        .xor_address(XOR_PEER_ADDRESS, to_relayed)
        .attribute(DATA, data)
        .build();
    from.put(&send).await;
    let arrived = to.next().await;
    let arrived = Message::parse(&arrived).unwrap();
    assert_eq!(
        (arrived.method(), arrived.class()),
        (stun::DATA, Class::Indication)
    );
    assert_eq!(arrived.xor_address(XOR_PEER_ADDRESS), Some(from_relayed));
    assert_eq!(arrived.attribute(DATA), Some(data));
}

#[tokio::test]
async fn game_data_crosses_between_two_tcp_players() {
    let outpost = start("test").await;
    let mut first = Line::tcp(outpost.tcp).await;
    let mut second = Line::tcp(outpost.tcp).await;
    let first_relayed = first.relayed(&outpost.room).await;
    let second_relayed = second.relayed(&outpost.room).await;
    first.permit(&outpost.room, second_relayed).await;
    second.permit(&outpost.room, first_relayed).await;
    carries(
        &mut first,
        first_relayed,
        &mut second,
        second_relayed,
        b"one",
    )
    .await;
    carries(
        &mut second,
        second_relayed,
        &mut first,
        first_relayed,
        b"two",
    )
    .await;
}

#[tokio::test]
async fn tcp_closes_a_connection_that_sends_a_message_longer_than_a_datagram() {
    let outpost = start("test").await;
    let mut client = TcpStream::connect(outpost.tcp).await.unwrap();
    let long = Builder::new(BINDING, Class::Request, TRANSACTION)
        .attribute(0x8050, &[0; 4096])
        .build();
    client.write_all(&long).await.unwrap();
    let mut rest = vec![];
    match within(client.read_to_end(&mut rest)).await {
        Ok(_) => assert!(rest.is_empty(), "answered {} bytes", rest.len()),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
}

/// Connects from `port` (any, if 0), so a new connection can reuse an old one's address.
/// Answers the line and the port it is on.
async fn connect_from(port: u16, server: SocketAddr) -> (Line, u16) {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket
        .bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    (Line::Tcp(socket.connect(server).await.unwrap()), port)
}

/// Ends a connection with a reset rather than a close, so its address is free again at once.
#[allow(deprecated)] // A zero linger does not block on drop, which is what the warning is about.
fn reset(line: Line) {
    let Line::Tcp(stream) = line else {
        unreachable!()
    };
    stream.set_linger(Some(Duration::ZERO)).unwrap();
}

#[tokio::test]
async fn a_new_connection_from_a_reused_address_is_served_whatever_the_old_one_does() {
    let outpost = start("test").await;
    let mut port = 0;
    for _ in 0..5 {
        let (mut old, bound) = connect_from(port, outpost.tcp).await;
        port = bound;
        old.relayed(&outpost.room).await;
        reset(old);

        let (mut new, _) = connect_from(port, outpost.tcp).await;
        let reply = new.allocate(&outpost.room).await;
        assert_eq!(Message::parse(&reply).unwrap().class(), Class::Success);
        // Give the old connection's end time to run, then check the new one still hears.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let binding = new.ask(&stun::binding_request(TRANSACTION)).await;
        assert_eq!(Message::parse(&binding).unwrap().class(), Class::Success);
        reset(new);
    }
}

#[tokio::test]
async fn channel_data_crosses_between_udp_and_tcp_padded_only_over_tcp() {
    let outpost = start("test").await;
    let mut over_udp = Line::udp(outpost.udp).await;
    let mut over_tcp = Line::tcp(outpost.tcp).await;
    let udp_relayed = over_udp.relayed(&outpost.room).await;
    let tcp_relayed = over_tcp.relayed(&outpost.room).await;
    over_udp.bind(&outpost.room, 0x4001, tcp_relayed).await;
    over_tcp.bind(&outpost.room, 0x4002, udp_relayed).await;

    over_udp
        .put(&stun::channel_data(0x4001, b"abc", false))
        .await;
    assert_eq!(
        over_tcp.next().await,
        stun::channel_data(0x4002, b"abc", true)
    );

    // Padded over TCP both ways; the stream must still be in step for what follows.
    over_tcp
        .put(&stun::channel_data(0x4002, b"defgh", true))
        .await;
    assert_eq!(
        over_udp.next().await,
        stun::channel_data(0x4001, b"defgh", false)
    );
    let binding = over_tcp.ask(&stun::binding_request(TRANSACTION)).await;
    assert_eq!(Message::parse(&binding).unwrap().transaction(), TRANSACTION);
}
