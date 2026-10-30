//! The TURN server's state (RFC 8656): rooms, their allocations, and the long-term credentials
//! that guard them. The listeners hand it each message along with the client it came from, and
//! send back whatever it answers.
//!
//! A room is one username and password, shared by its two players; it holds at most one
//! allocation for each.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::stun::attribute::{
    DONT_FRAGMENT, LIFETIME, MESSAGE_INTEGRITY, NONCE, REALM, REQUESTED_ADDRESS_FAMILY,
    REQUESTED_TRANSPORT, SOFTWARE, UNKNOWN_ATTRIBUTES, USERNAME, XOR_MAPPED_ADDRESS,
    XOR_RELAYED_ADDRESS,
};
use crate::stun::{
    ALLOCATE, BINDING, Builder, Class, Message, REFRESH, Transaction, long_term_key,
};

const REALM_TEXT: &str = "outpost";
const SOFTWARE_TEXT: &[u8] = b"outpost";
const DEFAULT_LIFETIME: u32 = 600;
const MAX_LIFETIME: u32 = 3600;
const NONCE_LIFETIME: u64 = 3600;
/// Allocations per room: one for each player.
const ROOM_SIZE: usize = 2;
/// Relayed ports come from the dynamic range (RFC 8656 §7.2). Nothing listens on them: an
/// allocation is reached only through outpost, by its address.
const PORTS: RangeInclusive<u16> = 49152..=65535;
const UDP: u8 = 17;
const IPV4: u8 = 0x01;

/// The comprehension-required attributes outpost understands in a request; any other one is
/// answered with 420 (RFC 8489 §6.3.1). DONT-FRAGMENT is among them because relayed data never
/// leaves this process, so it is never fragmented.
const UNDERSTOOD: [u16; 7] = [
    USERNAME,
    MESSAGE_INTEGRITY,
    REALM,
    NONCE,
    LIFETIME,
    REQUESTED_TRANSPORT,
    REQUESTED_ADDRESS_FAMILY,
];
const ALSO_UNDERSTOOD_IN_ALLOCATE: u16 = DONT_FRAGMENT;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp,
    Tcp,
}

/// A client as TURN tells them apart: by the address and transport its messages arrive on.
/// Together with outpost's own address this is the allocation's 5-tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Client {
    pub address: SocketAddr,
    pub transport: Transport,
}

/// What both players of a room use to log in.
#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

struct Room {
    key: [u8; 16],
    allocations: usize,
}

struct Allocation {
    room: String,
    port: u16,
    /// The Allocate request that made it, so a retransmission gets the same answer.
    transaction: Transaction,
    expires: Instant,
}

pub struct Relay {
    /// The address relayed addresses are given on: the one players reach outpost at.
    public_ip: IpAddr,
    rooms: HashMap<String, Room>,
    allocations: HashMap<Client, Allocation>,
    ports: HashMap<u16, Client>,
    nonce_secret: [u8; 20],
    epoch: Instant,
}

impl Relay {
    pub fn new(public_ip: IpAddr, now: Instant) -> Self {
        Relay {
            public_ip,
            rooms: HashMap::new(),
            allocations: HashMap::new(),
            ports: HashMap::new(),
            nonce_secret: rand::random(),
            epoch: now,
        }
    }

    /// Opens a room and returns the credentials both of its players log in with.
    pub fn open_room(&mut self) -> Credentials {
        let credentials = Credentials {
            username: random_text(),
            password: random_text(),
        };
        let key = long_term_key(&credentials.username, REALM_TEXT, &credentials.password);
        let room = Room {
            key,
            allocations: 0,
        };
        self.rooms.insert(credentials.username.clone(), room);
        credentials
    }

    /// The reply to one message from `client`, if it gets one. Responses, indications, methods
    /// outpost does not serve and messages whose FINGERPRINT fails are dropped silently
    /// (RFC 8489 §6.3).
    pub fn handle(&mut self, message: &[u8], client: Client, now: Instant) -> Option<Vec<u8>> {
        let request = Message::parse(message)?;
        if request.class() != Class::Request || request.fingerprint() == Some(false) {
            return None;
        }
        let reply = match request.method() {
            BINDING => finish(binding(&request, client), None),
            ALLOCATE | REFRESH => match self.authenticate(&request, client, now) {
                Err(refusal) => finish(refusal, None),
                Ok(room) => {
                    let key = self.rooms[&room].key;
                    let response = self.authenticated(&request, client, &room, now);
                    finish(response, Some(&key))
                }
            },
            _ => return None,
        };
        Some(reply)
    }

    /// Forgets the allocation of a client whose TCP connection has closed.
    pub fn disconnect(&mut self, client: Client) {
        self.remove(client);
    }

    /// Forgets allocations that have expired.
    pub fn sweep(&mut self, now: Instant) {
        let expired: Vec<Client> = self
            .allocations
            .iter()
            .filter(|(_, allocation)| allocation.expires <= now)
            .map(|(client, _)| *client)
            .collect();
        for client in expired {
            self.remove(client);
        }
    }

    /// The long-term credential checks of RFC 8489 §9.2.4, in its order. Answers the room the
    /// request logged in to, or the refusal.
    fn authenticate(
        &self,
        request: &Message,
        client: Client,
        now: Instant,
    ) -> Result<String, Builder> {
        let challenge = |code, reason| {
            error(request, code, reason)
                .attribute(REALM, REALM_TEXT.as_bytes())
                .attribute(NONCE, self.nonce(client, now).as_bytes())
        };
        if request.attribute(MESSAGE_INTEGRITY).is_none() {
            return Err(challenge(401, "Unauthenticated"));
        }
        let (Some(username), Some(_), Some(nonce)) = (
            request.attribute(USERNAME),
            request.attribute(REALM),
            request.attribute(NONCE),
        ) else {
            return Err(error(request, 400, "Bad Request"));
        };
        let room = std::str::from_utf8(username).ok().filter(|username| {
            self.rooms
                .get(*username)
                .is_some_and(|room| request.integrity_holds(&room.key))
        });
        let Some(room) = room else {
            return Err(challenge(401, "Unauthenticated"));
        };
        if !self.nonce_holds(nonce, client, now) {
            return Err(challenge(438, "Stale Nonce"));
        }
        Ok(room.to_string())
    }

    fn authenticated(
        &mut self,
        request: &Message,
        client: Client,
        room: &str,
        now: Instant,
    ) -> Builder {
        let also = (request.method() == ALLOCATE).then_some(ALSO_UNDERSTOOD_IN_ALLOCATE);
        if let Some(refusal) = unknown_attributes(request, also) {
            return refusal;
        }
        if request.method() == ALLOCATE {
            self.allocate(request, client, room, now)
        } else {
            self.refresh(request, client, room, now)
        }
    }

    /// RFC 8656 §7.2.
    fn allocate(&mut self, request: &Message, client: Client, room: &str, now: Instant) -> Builder {
        if let Some(allocation) = self.live(client, now) {
            return if allocation.transaction == request.transaction() {
                self.allocated(request, client, now)
            } else {
                error(request, 437, "Allocation Mismatch")
            };
        }
        match request.attribute(REQUESTED_TRANSPORT) {
            Some([UDP, _, _, _]) => {}
            Some([_, _, _, _]) => return error(request, 442, "Unsupported Transport Protocol"),
            _ => return error(request, 400, "Bad Request"),
        }
        match request.attribute(REQUESTED_ADDRESS_FAMILY) {
            None | Some([IPV4, _, _, _]) => {}
            Some([_, _, _, _]) => return error(request, 440, "Address Family not Supported"),
            Some(_) => return error(request, 400, "Bad Request"),
        }
        if self.rooms[room].allocations >= ROOM_SIZE {
            return error(request, 486, "Allocation Quota Reached");
        }
        let Some(port) = self.free_port() else {
            return error(request, 508, "Insufficient Capacity");
        };
        let lifetime = desired_lifetime(request).max(DEFAULT_LIFETIME);
        let allocation = Allocation {
            room: room.to_string(),
            port,
            transaction: request.transaction(),
            expires: now + Duration::from_secs(lifetime.into()),
        };
        self.allocations.insert(client, allocation);
        self.ports.insert(port, client);
        self.rooms.get_mut(room).unwrap().allocations += 1;
        self.allocated(request, client, now)
    }

    fn allocated(&self, request: &Message, client: Client, now: Instant) -> Builder {
        let allocation = &self.allocations[&client];
        let relayed = SocketAddr::new(self.public_ip, allocation.port);
        let lifetime = allocation.expires.saturating_duration_since(now).as_secs() as u32;
        Builder::response(request, Class::Success)
            .xor_address(XOR_RELAYED_ADDRESS, relayed)
            .attribute(LIFETIME, &lifetime.to_be_bytes())
            .xor_address(XOR_MAPPED_ADDRESS, client.address)
    }

    /// RFC 8656 §8.2.
    fn refresh(&mut self, request: &Message, client: Client, room: &str, now: Instant) -> Builder {
        let Some(allocation) = self.live(client, now) else {
            return error(request, 437, "Allocation Mismatch");
        };
        if allocation.room != room {
            return error(request, 441, "Wrong Credentials");
        }
        if let Some(family) = request.attribute(REQUESTED_ADDRESS_FAMILY)
            && family.first() != Some(&IPV4)
        {
            return error(request, 443, "Peer Address Family Mismatch");
        }
        let lifetime = desired_lifetime(request);
        if lifetime == 0 {
            self.remove(client);
        } else {
            allocation.expires = now + Duration::from_secs(lifetime.into());
        }
        Builder::response(request, Class::Success).attribute(LIFETIME, &lifetime.to_be_bytes())
    }

    /// The client's allocation, if it has one that has not expired.
    fn live(&mut self, client: Client, now: Instant) -> Option<&mut Allocation> {
        if self
            .allocations
            .get(&client)
            .is_some_and(|allocation| allocation.expires <= now)
        {
            self.remove(client);
        }
        self.allocations.get_mut(&client)
    }

    fn remove(&mut self, client: Client) {
        if let Some(allocation) = self.allocations.remove(&client) {
            self.ports.remove(&allocation.port);
            if let Some(room) = self.rooms.get_mut(&allocation.room) {
                room.allocations -= 1;
            }
        }
    }

    /// A random relayed port no allocation has (RFC 6056's random port choice).
    fn free_port(&self) -> Option<u16> {
        if self.ports.len() >= PORTS.len() {
            return None;
        }
        loop {
            let port = rand::random_range(PORTS);
            if !self.ports.contains_key(&port) {
                return Some(port);
            }
        }
    }

    /// A nonce for `client` (RFC 8489 §9.2): when it was issued, signed together with the client
    /// so that no two clients are given the same one, and so that it needs no storage.
    fn nonce(&self, client: Client, now: Instant) -> String {
        self.nonce_issued_at(client, now.duration_since(self.epoch).as_secs())
    }

    fn nonce_issued_at(&self, client: Client, issued: u64) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.nonce_secret).unwrap();
        mac.update(&issued.to_be_bytes());
        mac.update(format!("{:?}", client).as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("{issued:016x}{}", hex(&tag[..12]))
    }

    /// Whether `nonce` was issued to `client` within the last hour.
    fn nonce_holds(&self, nonce: &[u8], client: Client, now: Instant) -> bool {
        let Some(issued) = std::str::from_utf8(nonce)
            .ok()
            .and_then(|nonce| nonce.get(..16))
            .and_then(|issued| u64::from_str_radix(issued, 16).ok())
        else {
            return false;
        };
        let age = now.duration_since(self.epoch).as_secs().checked_sub(issued);
        age.is_some_and(|age| age < NONCE_LIFETIME)
            && self.nonce_issued_at(client, issued).as_bytes() == nonce
    }
}

/// A Binding request needs no credentials.
fn binding(request: &Message, client: Client) -> Builder {
    unknown_attributes(request, None).unwrap_or_else(|| {
        Builder::response(request, Class::Success).xor_address(XOR_MAPPED_ADDRESS, client.address)
    })
}

/// A 420 naming the comprehension-required attributes outpost does not understand, if any.
fn unknown_attributes(request: &Message, also: Option<u16>) -> Option<Builder> {
    let mut unknown = vec![];
    for attribute in request.attributes() {
        if attribute.kind < 0x8000
            && !UNDERSTOOD.contains(&attribute.kind)
            && also != Some(attribute.kind)
            && !unknown.contains(&attribute.kind)
        {
            unknown.push(attribute.kind);
        }
    }
    if unknown.is_empty() {
        return None;
    }
    let types: Vec<u8> = unknown.into_iter().flat_map(u16::to_be_bytes).collect();
    Some(error(request, 420, "Unknown Attribute").attribute(UNKNOWN_ATTRIBUTES, &types))
}

fn error(request: &Message, code: u16, reason: &str) -> Builder {
    Builder::response(request, Class::Error).error_code(code, reason)
}

/// Every response names outpost and ends in a FINGERPRINT; one to a request that logged in is
/// also signed with its key.
fn finish(response: Builder, key: Option<&[u8]>) -> Vec<u8> {
    let response = response.attribute(SOFTWARE, SOFTWARE_TEXT);
    match key {
        Some(key) => response.integrity(key).fingerprint(),
        None => response.fingerprint(),
    }
}

/// The lifetime a request asks for, as RFC 8656 §7.2 and §8.2 settle it: zero stays zero, and
/// anything else lies between the default and the maximum.
fn desired_lifetime(request: &Message) -> u32 {
    match request.attribute(LIFETIME) {
        Some([0, 0, 0, 0]) => 0,
        Some(&[a, b, c, d]) => {
            u32::from_be_bytes([a, b, c, d]).clamp(DEFAULT_LIFETIME, MAX_LIFETIME)
        }
        _ => DEFAULT_LIFETIME,
    }
}

fn random_text() -> String {
    hex(&rand::random::<[u8; 12]>())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::attribute::{ERROR_CODE, EVEN_PORT};

    const PUBLIC_IP: [u8; 4] = [198, 51, 100, 1];

    fn client(port: u16) -> Client {
        Client {
            address: SocketAddr::from(([203, 0, 113, 9], port)),
            transport: Transport::Udp,
        }
    }

    struct Setup {
        relay: Relay,
        room: Credentials,
        start: Instant,
    }

    fn setup() -> Setup {
        let start = Instant::now();
        let mut relay = Relay::new(PUBLIC_IP.into(), start);
        let room = relay.open_room();
        Setup { relay, room, start }
    }

    fn at(start: Instant, seconds: u64) -> Instant {
        start + Duration::from_secs(seconds)
    }

    /// A reply, with the parts the tests look at.
    struct Reply {
        bytes: Vec<u8>,
    }

    impl Reply {
        fn message(&self) -> Message<'_> {
            Message::parse(&self.bytes).unwrap()
        }

        fn code(&self) -> Option<u16> {
            let message = self.message();
            let value = message.attribute(ERROR_CODE)?;
            Some(u16::from(value[2]) * 100 + u16::from(value[3]))
        }

        fn nonce(&self) -> Vec<u8> {
            self.message().attribute(NONCE).unwrap().to_vec()
        }

        fn lifetime(&self) -> u32 {
            let value = self.message().attribute(LIFETIME).unwrap();
            u32::from_be_bytes(value.try_into().unwrap())
        }

        fn relayed(&self) -> SocketAddr {
            self.message().xor_address(XOR_RELAYED_ADDRESS).unwrap()
        }

        fn signed_with(&self, credentials: &Credentials) -> bool {
            let key = long_term_key(&credentials.username, REALM_TEXT, &credentials.password);
            self.message().integrity_holds(&key)
        }
    }

    impl Setup {
        fn ask(&mut self, request: Vec<u8>, client: Client, now: Instant) -> Reply {
            let bytes = self.relay.handle(&request, client, now).expect("an answer");
            Reply { bytes }
        }

        /// The nonce a first, unsigned Allocate is challenged with.
        fn nonce(&mut self, client: Client, now: Instant) -> Vec<u8> {
            let challenge = self.ask(unsigned(ALLOCATE, *b"challenge-me"), client, now);
            assert_eq!(challenge.code(), Some(401));
            challenge.nonce()
        }

        fn allocate(&mut self, client: Client, now: Instant) -> Reply {
            let nonce = self.nonce(client, now);
            let request = signed(ALLOCATE, &self.room.clone(), &nonce, *b"allocate-it!", udp);
            self.ask(request, client, now)
        }

        fn refresh(&mut self, client: Client, now: Instant, lifetime: Option<u32>) -> Reply {
            let nonce = self.nonce(client, now);
            let request =
                signed(
                    REFRESH,
                    &self.room.clone(),
                    &nonce,
                    *b"refresh-it!!",
                    |b| match lifetime {
                        Some(lifetime) => b.attribute(LIFETIME, &lifetime.to_be_bytes()),
                        None => b,
                    },
                );
            self.ask(request, client, now)
        }
    }

    fn unsigned(method: u16, transaction: Transaction) -> Vec<u8> {
        Builder::new(method, Class::Request, transaction)
            .attribute(REQUESTED_TRANSPORT, &[UDP, 0, 0, 0])
            .fingerprint()
    }

    fn udp(builder: Builder) -> Builder {
        builder.attribute(REQUESTED_TRANSPORT, &[UDP, 0, 0, 0])
    }

    /// A request logged in with `credentials`, carrying whatever `with` adds.
    fn signed(
        method: u16,
        credentials: &Credentials,
        nonce: &[u8],
        transaction: Transaction,
        with: impl FnOnce(Builder) -> Builder,
    ) -> Vec<u8> {
        let key = long_term_key(&credentials.username, REALM_TEXT, &credentials.password);
        with(Builder::new(method, Class::Request, transaction))
            .attribute(USERNAME, credentials.username.as_bytes())
            .attribute(REALM, REALM_TEXT.as_bytes())
            .attribute(NONCE, nonce)
            .integrity(&key)
            .fingerprint()
    }

    #[test]
    fn an_unsigned_allocate_is_challenged_with_the_realm_and_a_nonce_for_that_client() {
        let mut s = setup();
        let challenge = s.ask(unsigned(ALLOCATE, *b"challenge-me"), client(1), s.start);
        let message = challenge.message();
        assert_eq!(
            (message.method(), message.class()),
            (ALLOCATE, Class::Error)
        );
        assert_eq!(challenge.code(), Some(401));
        assert_eq!(message.attribute(REALM), Some(REALM_TEXT.as_bytes()));
        assert_eq!(message.attribute(MESSAGE_INTEGRITY), None);
        assert_eq!(message.attribute(SOFTWARE), Some(SOFTWARE_TEXT));
        assert_eq!(message.fingerprint(), Some(true));

        let again = s.nonce(client(1), s.start);
        let other = s.nonce(client(2), s.start);
        assert_eq!(challenge.nonce(), again);
        assert_ne!(challenge.nonce(), other, "no two clients share a nonce");
    }

    #[test]
    fn a_signed_allocate_gets_a_relayed_address_a_lifetime_and_the_mapped_address() {
        let mut s = setup();
        let reply = s.allocate(client(1), s.start);
        let message = reply.message();
        assert_eq!(
            (message.method(), message.class()),
            (ALLOCATE, Class::Success)
        );
        assert_eq!(message.transaction(), *b"allocate-it!");
        assert_eq!(reply.relayed().ip(), IpAddr::from(PUBLIC_IP));
        assert!(PORTS.contains(&reply.relayed().port()));
        assert_eq!(reply.lifetime(), DEFAULT_LIFETIME);
        assert_eq!(message.mapped_address(), Some(client(1).address));
        assert!(reply.signed_with(&s.room));
        assert_eq!(message.fingerprint(), Some(true));
        assert_eq!(message.attribute(REALM), None);
    }

    #[test]
    fn a_wrong_password_or_an_unknown_username_is_challenged_again() {
        let mut s = setup();
        let nonce = s.nonce(client(1), s.start);
        let wrong_password = Credentials {
            password: "not it".to_string(),
            ..s.room.clone()
        };
        let unknown_user = Credentials {
            username: "nobody".to_string(),
            ..s.room.clone()
        };
        for credentials in [wrong_password, unknown_user] {
            let request = signed(ALLOCATE, &credentials, &nonce, *b"allocate-it!", udp);
            let reply = s.ask(request, client(1), s.start);
            assert_eq!(reply.code(), Some(401));
            assert!(!reply.nonce().is_empty());
            assert_eq!(reply.message().attribute(MESSAGE_INTEGRITY), None);
        }
    }

    #[test]
    fn a_signed_request_without_username_realm_or_nonce_is_a_bad_request() {
        let mut s = setup();
        let key = long_term_key(&s.room.username, REALM_TEXT, &s.room.password);
        let request = udp(Builder::new(ALLOCATE, Class::Request, *b"allocate-it!"))
            .attribute(USERNAME, s.room.username.as_bytes())
            .attribute(REALM, REALM_TEXT.as_bytes())
            .integrity(&key)
            .fingerprint();
        let reply = s.ask(request, client(1), s.start);
        assert_eq!(reply.code(), Some(400));
        assert_eq!(reply.message().attribute(NONCE), None);
        assert_eq!(reply.message().attribute(REALM), None);
    }

    #[test]
    fn a_nonce_lasts_an_hour_for_its_own_client_only() {
        let mut s = setup();
        let room = s.room.clone();
        let nonce = s.nonce(client(1), s.start);

        let late = signed(ALLOCATE, &room, &nonce, *b"allocate-it!", udp);
        let reply = s.ask(late, client(1), at(s.start, NONCE_LIFETIME));
        assert_eq!(reply.code(), Some(438));
        let fresh = reply.nonce();
        assert_ne!(fresh, nonce);

        let elsewhere = signed(ALLOCATE, &room, &fresh, *b"allocate-it!", udp);
        assert_eq!(
            s.ask(elsewhere, client(2), at(s.start, NONCE_LIFETIME))
                .code(),
            Some(438)
        );

        let retry = signed(ALLOCATE, &room, &fresh, *b"allocate-it!", udp);
        let reply = s.ask(retry, client(1), at(s.start, NONCE_LIFETIME + 1));
        assert_eq!(reply.message().class(), Class::Success);

        let forged = signed(
            ALLOCATE,
            &room,
            b"0000000000000000forged",
            *b"allocate-it!",
            udp,
        );
        assert_eq!(s.ask(forged, client(3), s.start).code(), Some(438));
    }

    /// Adds attributes to a request.
    type Adds = fn(Builder) -> Builder;

    #[test]
    fn an_allocation_is_for_udp_over_ipv4_and_unknown_attributes_get_a_signed_420() {
        let mut s = setup();
        let room = s.room.clone();
        let nonce = s.nonce(client(1), s.start);
        let cases: [(Adds, u16); 5] = [
            (|b| b, 400),
            (|b| b.attribute(REQUESTED_TRANSPORT, &[6, 0, 0, 0]), 442),
            (|b| b.attribute(REQUESTED_TRANSPORT, &[UDP, 0]), 400),
            (
                |b| udp(b).attribute(REQUESTED_ADDRESS_FAMILY, &[0x02, 0, 0, 0]),
                440,
            ),
            (|b| udp(b).attribute(EVEN_PORT, &[0]), 420),
        ];
        for (with, code) in cases {
            let request = signed(ALLOCATE, &room, &nonce, *b"allocate-it!", with);
            let reply = s.ask(request, client(1), s.start);
            assert_eq!(reply.code(), Some(code));
            assert!(reply.signed_with(&room), "{code}");
        }
        let request = signed(ALLOCATE, &room, &nonce, *b"allocate-it!", |b| {
            udp(b).attribute(DONT_FRAGMENT, &[])
        });
        assert_eq!(
            s.ask(request, client(1), s.start).message().class(),
            Class::Success
        );
    }

    #[test]
    fn the_420_names_what_was_not_understood() {
        let mut s = setup();
        let room = s.room.clone();
        let nonce = s.nonce(client(1), s.start);
        let request = signed(ALLOCATE, &room, &nonce, *b"allocate-it!", |b| {
            udp(b).attribute(EVEN_PORT, &[0]).attribute(0x7fff, &[])
        });
        let reply = s.ask(request, client(1), s.start);
        assert_eq!(
            reply.message().attribute(UNKNOWN_ATTRIBUTES),
            Some(&[0x00, 0x18, 0x7f, 0xff][..])
        );
    }

    #[test]
    fn a_retransmitted_allocate_gets_the_same_answer_and_a_new_one_gets_a_437() {
        let mut s = setup();
        let room = s.room.clone();
        let first = s.allocate(client(1), s.start);
        let nonce = s.nonce(client(1), s.start);

        let retransmission = signed(ALLOCATE, &room, &nonce, *b"allocate-it!", udp);
        let again = s.ask(retransmission, client(1), at(s.start, 10));
        assert_eq!(again.relayed(), first.relayed());
        assert_eq!(again.lifetime(), DEFAULT_LIFETIME - 10);

        let another = signed(ALLOCATE, &room, &nonce, *b"another-one!", udp);
        assert_eq!(s.ask(another, client(1), s.start).code(), Some(437));
    }

    #[test]
    fn a_room_holds_two_allocations_with_different_relayed_addresses() {
        let mut s = setup();
        let first = s.allocate(client(1), s.start);
        let second = s.allocate(client(2), s.start);
        assert_ne!(first.relayed(), second.relayed());
        assert_eq!(s.allocate(client(3), s.start).code(), Some(486));

        // Another room is not affected.
        s.room = s.relay.open_room();
        assert_eq!(
            s.allocate(client(3), s.start).message().class(),
            Class::Success
        );
    }

    #[test]
    fn the_lifetime_asked_for_is_kept_between_the_default_and_the_maximum() {
        for (asked, given) in [(60, 600), (1200, 1200), (100_000, 3600)] {
            let mut s = setup();
            let room = s.room.clone();
            let nonce = s.nonce(client(1), s.start);
            let request = signed(ALLOCATE, &room, &nonce, *b"allocate-it!", |b| {
                udp(b).attribute(LIFETIME, &u32::to_be_bytes(asked))
            });
            assert_eq!(s.ask(request, client(1), s.start).lifetime(), given);
        }
    }

    #[test]
    fn a_refresh_extends_an_allocation_and_one_with_lifetime_zero_ends_it() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        assert_eq!(
            s.refresh(client(1), at(s.start, 500), Some(1200))
                .lifetime(),
            1200
        );
        let alive = s.refresh(client(1), at(s.start, 1000), None);
        assert_eq!(alive.lifetime(), DEFAULT_LIFETIME);
        assert!(alive.signed_with(&s.room));

        let ended = s.refresh(client(1), at(s.start, 1001), Some(0));
        assert_eq!(ended.lifetime(), 0);
        assert_eq!(
            s.refresh(client(1), at(s.start, 1002), None).code(),
            Some(437)
        );
    }

    #[test]
    fn an_allocation_that_was_not_refreshed_in_time_is_gone() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        let late = at(s.start, u64::from(DEFAULT_LIFETIME));
        assert_eq!(s.refresh(client(1), late, None).code(), Some(437));
        assert_eq!(s.refresh(client(2), s.start, None).code(), Some(437));
    }

    #[test]
    fn a_refresh_from_another_room_is_refused() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        s.room = s.relay.open_room();
        assert_eq!(s.refresh(client(1), s.start, None).code(), Some(441));
    }

    #[test]
    fn ended_expired_and_disconnected_allocations_give_their_place_back() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        s.allocate(client(2), s.start);

        s.refresh(client(1), s.start, Some(0));
        assert_eq!(
            s.allocate(client(3), s.start).message().class(),
            Class::Success
        );

        s.relay.disconnect(client(2));
        assert_eq!(
            s.allocate(client(4), s.start).message().class(),
            Class::Success
        );

        s.relay.sweep(at(s.start, u64::from(DEFAULT_LIFETIME)));
        assert!(s.relay.allocations.is_empty() && s.relay.ports.is_empty());
        assert_eq!(s.relay.rooms[&s.room.username].allocations, 0);
    }

    #[test]
    fn a_binding_request_needs_no_credentials() {
        let mut s = setup();
        let request = Builder::new(BINDING, Class::Request, *b"binding-test").build();
        let reply = s.ask(request, client(1), s.start);
        let message = reply.message();
        assert_eq!(
            (message.method(), message.class()),
            (BINDING, Class::Success)
        );
        assert_eq!(message.mapped_address(), Some(client(1).address));
        assert_eq!(message.attribute(SOFTWARE), Some(SOFTWARE_TEXT));
        assert_eq!(message.fingerprint(), Some(true));
    }

    #[test]
    fn a_binding_request_with_unknown_attributes_gets_an_unsigned_420() {
        let mut s = setup();
        let request = Builder::new(BINDING, Class::Request, *b"binding-test")
            .attribute(0x0024, &[0; 4])
            .attribute(0x8029, &[0; 8])
            .attribute(USERNAME, b"evtj:h6vY")
            .fingerprint();
        let reply = s.ask(request, client(1), s.start);
        assert_eq!(reply.code(), Some(420));
        assert_eq!(
            reply.message().attribute(UNKNOWN_ATTRIBUTES),
            Some(&[0x00, 0x24][..])
        );
        assert_eq!(reply.message().attribute(MESSAGE_INTEGRITY), None);
    }

    #[test]
    fn what_is_not_a_request_outpost_serves_gets_no_answer() {
        let mut s = setup();
        let mut broken_fingerprint =
            Builder::new(BINDING, Class::Request, *b"binding-test").fingerprint();
        broken_fingerprint[8] ^= 1;
        for bytes in [
            Builder::new(BINDING, Class::Indication, *b"binding-test").build(),
            Builder::new(BINDING, Class::Success, *b"binding-test").build(),
            Builder::new(ALLOCATE, Class::Error, *b"binding-test").build(),
            Builder::new(crate::stun::CHANNEL_BIND, Class::Request, *b"binding-test").build(),
            broken_fingerprint,
            b"not stun at all, not stun at all".to_vec(),
        ] {
            assert!(
                s.relay.handle(&bytes, client(1), s.start).is_none(),
                "{bytes:02x?}"
            );
        }
    }
}
