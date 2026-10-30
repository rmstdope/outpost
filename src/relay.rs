//! The TURN server's state (RFC 8656): rooms, their allocations, and the long-term credentials
//! that guard them. The listeners hand it each message along with the client it came from, and
//! send whatever comes out to whoever it is for.
//!
//! A room is one username and password, shared by its two players. Data is relayed only between
//! allocations of the same room, inside this process (PLAN.md D1).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::limit::{Bucket, Limits};
use crate::stun::attribute::{
    CHANNEL_NUMBER, DATA, DONT_FRAGMENT, LIFETIME, MESSAGE_INTEGRITY, NONCE, REALM,
    REQUESTED_ADDRESS_FAMILY, REQUESTED_TRANSPORT, SOFTWARE, UNKNOWN_ATTRIBUTES, USERNAME,
    XOR_MAPPED_ADDRESS, XOR_PEER_ADDRESS, XOR_RELAYED_ADDRESS,
};
use crate::stun::{
    self, ALLOCATE, BINDING, Builder, CHANNEL_BIND, CHANNELS, CREATE_PERMISSION, Class, Message,
    REFRESH, SEND, Transaction, long_term_key,
};

const REALM_TEXT: &str = "outpost";
const SOFTWARE_TEXT: &[u8] = b"outpost";
const DEFAULT_LIFETIME: u32 = 600;
const MAX_LIFETIME: u32 = 3600;
const NONCE_LIFETIME: u64 = 3600;
/// RFC 8656 §9 fixes it at five minutes.
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
/// Permissions one allocation may hold. A browser asks for one per address of the other player.
const MAX_PERMISSIONS: usize = 64;
/// RFC 8656 §12 fixes it at ten minutes.
const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
/// Channels one allocation may bind. A browser binds one per address of the other player.
const MAX_CHANNELS: usize = 64;
/// What a relayed message costs besides its data, at most: the header and attributes of a Data
/// indication, and the padding of its data. Charged on every message, so that empty ones are
/// not free.
const MESSAGE_COST: usize = 40;
/// Allocations per room. A browser allocates once per TURN URL and network interface (UDP and
/// TCP, Wi-Fi and a VPN), and a reloaded page leaves its old allocation behind until it expires.
/// Two players need room for all of that; relaying stays within the room whatever the number.
const ROOM_SIZE: usize = 8;
/// Relayed ports come from the dynamic range (RFC 8656 §7.2). Nothing listens on them: an
/// allocation is reached only through outpost, by its address.
const PORTS: RangeInclusive<u16> = 49152..=65535;
const UDP: u8 = 17;
const IPV4: u8 = 0x01;

/// The comprehension-required attributes outpost understands; any other one in a request is
/// answered with 420 (RFC 8489 §6.3.1), and in an indication drops it. DONT-FRAGMENT is among
/// them because relayed data never leaves this process, so it is never fragmented.
const UNDERSTOOD: [u16; 11] = [
    USERNAME,
    MESSAGE_INTEGRITY,
    REALM,
    NONCE,
    LIFETIME,
    REQUESTED_TRANSPORT,
    REQUESTED_ADDRESS_FAMILY,
    DONT_FRAGMENT,
    XOR_PEER_ADDRESS,
    DATA,
    CHANNEL_NUMBER,
];

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

/// A message for a client: an answer to what it sent, or data from the other player.
#[derive(Debug)]
pub struct Outgoing {
    pub to: Client,
    pub message: Vec<u8>,
    /// An answer to a request that did not log in. Its source address may have been forged,
    /// so over UDP it counts against `Limits::udp_answers`. One that logged in carries a nonce
    /// tied to the address it came from, which no one else can produce.
    pub forgeable: bool,
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
    /// What is left of the bytes the room may relay (`Limits::room_bandwidth`).
    bandwidth: Bucket,
}

struct Allocation {
    room: String,
    port: u16,
    /// The Allocate request that made it, so a retransmission gets the same answer.
    transaction: Transaction,
    expires: Instant,
    /// When each peer address's permission expires (RFC 8656 §9).
    permissions: HashMap<IpAddr, Instant>,
    /// The channels bound by number (RFC 8656 §12).
    channels: HashMap<u16, Channel>,
}

struct Channel {
    peer: SocketAddr,
    expires: Instant,
}

impl Allocation {
    fn permits(&self, peer: IpAddr, now: Instant) -> bool {
        self.permissions
            .get(&peer)
            .is_some_and(|expires| *expires > now)
    }

    /// Installs or renews a permission for each of `peers`: all of them, or none if they do not
    /// fit (RFC 8656 §10.2). Answers whether they did.
    fn grant(&mut self, peers: &[IpAddr], now: Instant) -> bool {
        self.permissions.retain(|_, expires| *expires > now);
        let mut new: Vec<IpAddr> = peers
            .iter()
            .filter(|ip| !self.permissions.contains_key(ip))
            .copied()
            .collect();
        new.sort_unstable();
        new.dedup();
        if self.permissions.len() + new.len() > MAX_PERMISSIONS {
            return false;
        }
        for peer in peers {
            self.permissions.insert(*peer, now + PERMISSION_LIFETIME);
        }
        true
    }

    /// The peer bound to a live channel `number`.
    fn channel(&self, number: u16, now: Instant) -> Option<SocketAddr> {
        self.channels
            .get(&number)
            .filter(|channel| channel.expires > now)
            .map(|channel| channel.peer)
    }

    /// The live channel bound to `peer`.
    fn channel_to(&self, peer: SocketAddr, now: Instant) -> Option<u16> {
        self.channels
            .iter()
            .find(|(_, channel)| channel.peer == peer && channel.expires > now)
            .map(|(number, _)| *number)
    }
}

/// Where relayed data goes: to which client, from which relayed address, and on which of the
/// receiver's channels, if it has one bound to the sender.
struct Forward {
    to: Client,
    from: SocketAddr,
    channel: Option<u16>,
}

pub struct Relay {
    /// The address relayed addresses are given on: the one players reach outpost at.
    public_ip: Ipv4Addr,
    rooms: HashMap<String, Room>,
    allocations: HashMap<Client, Allocation>,
    ports: HashMap<u16, Client>,
    nonce_secret: [u8; 20],
    epoch: Instant,
    limits: Limits,
}

impl Relay {
    pub fn new(public_ip: Ipv4Addr, limits: Limits, now: Instant) -> Self {
        Relay {
            public_ip,
            limits,
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
            bandwidth: Bucket::full(self.limits.room_bandwidth, self.epoch),
        };
        self.rooms.insert(credentials.username.clone(), room);
        credentials
    }

    /// The response to a TURN request, and the key to sign it with if it logged in.
    fn turn(
        &mut self,
        request: &Message,
        client: Client,
        now: Instant,
    ) -> (Builder, Option<[u8; 16]>) {
        match self.authenticate(request, client, now) {
            Err(refusal) => (refusal, None),
            Ok(room) => {
                let key = self.rooms[&room].key;
                (self.authenticated(request, client, &room, now), Some(key))
            }
        }
    }

    pub fn has_allocation(&self, client: Client) -> bool {
        self.allocations.contains_key(&client)
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
        // Only MESSAGE-INTEGRITY counts. MESSAGE-INTEGRITY-SHA256 is for clients that saw a nonce
        // cookie offering it, and outpost's nonces offer none.
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
        if let Some(refusal) = unknown_attributes(request) {
            return refusal;
        }
        match request.method() {
            ALLOCATE => self.allocate(request, client, room, now),
            REFRESH => self.refresh(request, client, room, now),
            CREATE_PERMISSION => self.create_permission(request, client, room, now),
            CHANNEL_BIND => self.channel_bind(request, client, room, now),
            // `handle` lets only the methods above through.
            _ => error(request, 400, "Bad Request"),
        }
    }

    /// RFC 8656 §7.2.
    fn allocate(&mut self, request: &Message, client: Client, room: &str, now: Instant) -> Builder {
        if let Some(allocation) = self.live(client, now) {
            return if allocation.transaction == request.transaction() && allocation.room == room {
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
        // An expired allocation not yet swept must not hold a place in the room.
        self.sweep(now);
        let from_address = self
            .allocations
            .keys()
            .filter(|other| other.address.ip() == client.address.ip())
            .count();
        if self.rooms[room].allocations >= ROOM_SIZE
            || from_address >= self.limits.allocations_per_address
        {
            return error(request, 486, "Allocation Quota Reached");
        }
        if self.allocations.len() >= self.limits.allocations {
            return error(request, 508, "Insufficient Capacity");
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
            permissions: HashMap::new(),
            channels: HashMap::new(),
        };
        self.allocations.insert(client, allocation);
        self.ports.insert(port, client);
        self.rooms.get_mut(room).unwrap().allocations += 1;
        self.allocated(request, client, now)
    }

    fn allocated(&self, request: &Message, client: Client, now: Instant) -> Builder {
        let allocation = &self.allocations[&client];
        let relayed = SocketAddr::from((self.public_ip, allocation.port));
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

    /// RFC 8656 §10.2. A permission is granted for any IPv4 address, because on its own it lets
    /// nothing through: data only ever reaches another allocation of the same room (`send`).
    fn create_permission(
        &mut self,
        request: &Message,
        client: Client,
        room: &str,
        now: Instant,
    ) -> Builder {
        let Some(allocation) = self.live(client, now) else {
            return error(request, 437, "Allocation Mismatch");
        };
        if allocation.room != room {
            return error(request, 441, "Wrong Credentials");
        }
        let peers: Option<Vec<SocketAddr>> = request.xor_addresses(XOR_PEER_ADDRESS).collect();
        let Some(peers) = peers.filter(|peers| !peers.is_empty()) else {
            return error(request, 400, "Bad Request");
        };
        if !peers.iter().all(SocketAddr::is_ipv4) {
            return error(request, 443, "Peer Address Family Mismatch");
        }
        let ips: Vec<IpAddr> = peers.iter().map(SocketAddr::ip).collect();
        if !allocation.grant(&ips, now) {
            return error(request, 508, "Insufficient Capacity");
        }
        Builder::response(request, Class::Success)
    }

    /// RFC 8656 §12.2. Like a permission, a channel may be bound to any IPv4 peer, because data
    /// on it still only reaches another allocation of the same room (`forward`).
    fn channel_bind(
        &mut self,
        request: &Message,
        client: Client,
        room: &str,
        now: Instant,
    ) -> Builder {
        let Some(allocation) = self.live(client, now) else {
            return error(request, 437, "Allocation Mismatch");
        };
        if allocation.room != room {
            return error(request, 441, "Wrong Credentials");
        }
        let number = match request.attribute(CHANNEL_NUMBER) {
            Some(&[high, low, _, _]) => u16::from_be_bytes([high, low]),
            _ => return error(request, 400, "Bad Request"),
        };
        let Some(peer) = request.xor_address(XOR_PEER_ADDRESS) else {
            return error(request, 400, "Bad Request");
        };
        if !CHANNELS.contains(&number) {
            return error(request, 400, "Bad Request");
        }
        if !peer.is_ipv4() {
            return error(request, 443, "Peer Address Family Mismatch");
        }
        allocation
            .channels
            .retain(|_, channel| channel.expires > now);
        let bound_elsewhere = allocation
            .channel(number, now)
            .is_some_and(|bound| bound != peer)
            || allocation
                .channel_to(peer, now)
                .is_some_and(|bound| bound != number);
        if bound_elsewhere {
            return error(request, 400, "Bad Request");
        }
        let new = !allocation.channels.contains_key(&number);
        if new && allocation.channels.len() >= MAX_CHANNELS || !allocation.grant(&[peer.ip()], now)
        {
            return error(request, 508, "Insufficient Capacity");
        }
        let expires = now + CHANNEL_LIFETIME;
        allocation
            .channels
            .insert(number, Channel { peer, expires });
        Builder::response(request, Class::Success)
    }

    /// Where data from `client` to `peer` goes: RFC 8656 §11.2 and §12.6, with the room rule
    /// (PLAN.md D1). The peer must be another live allocation of the sender's room, the sender
    /// must have a permission for the peer, and the peer one for the sender. Anything else is
    /// dropped silently, as is data beyond the room's bandwidth (`Limits::room_bandwidth`).
    fn forward(
        &mut self,
        client: Client,
        peer: SocketAddr,
        bytes: usize,
        now: Instant,
    ) -> Option<Forward> {
        let public_ip = IpAddr::from(self.public_ip);
        if peer.ip() != public_ip {
            return None;
        }
        let to = *self.ports.get(&peer.port())?;
        let live = |client| {
            self.allocations
                .get(client)
                .filter(|allocation| allocation.expires > now)
        };
        let (sender, receiver) = (live(&client)?, live(&to)?);
        if to == client
            || sender.room != receiver.room
            || !sender.permits(public_ip, now)
            || !receiver.permits(public_ip, now)
        {
            return None;
        }
        let from = SocketAddr::new(public_ip, sender.port);
        let channel = receiver.channel_to(from, now);
        let cost = (bytes + MESSAGE_COST) as f64;
        let room = self.rooms.get_mut(&sender.room)?;
        room.bandwidth
            .take(cost, self.limits.room_bandwidth, now)
            .then_some(Forward { to, from, channel })
    }

    /// Where data on the sender's channel `number` goes, if it is bound.
    fn forward_channel(
        &mut self,
        client: Client,
        number: u16,
        bytes: usize,
        now: Instant,
    ) -> Option<Forward> {
        let peer = self
            .allocations
            .get(&client)
            .filter(|allocation| allocation.expires > now)?
            .channel(number, now)?;
        self.forward(client, peer, bytes, now)
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

/// What one message from `client` leads to, if anything: an answer to a request, or data for
/// the other player from a Send indication or a ChannelData message. Responses, other
/// indications, methods outpost does not serve and messages whose FINGERPRINT fails are dropped
/// silently (RFC 8489 §6.3). Only TURN messages take the lock, and only for the relay's own work: reading, Binding, signing and
/// fingerprinting happen outside it.
pub fn handle(
    relay: &Mutex<Relay>,
    bytes: &[u8],
    client: Client,
    now: Instant,
) -> Option<Outgoing> {
    if stun::is_channel_data(bytes) {
        return channel_data(relay, bytes, client, now);
    }
    let message = Message::parse(bytes)?;
    if message.fingerprint() == Some(false) {
        return None;
    }
    let (response, key) = match (message.class(), message.method()) {
        (Class::Request, BINDING) => (binding(&message, client), None),
        (Class::Request, ALLOCATE | REFRESH | CREATE_PERMISSION | CHANNEL_BIND) => {
            relay.lock().unwrap().turn(&message, client, now)
        }
        (Class::Indication, SEND) => return send(relay, &message, client, now),
        _ => return None,
    };
    let message = finish(response, key.as_ref().map(|key| &key[..]));
    Some(Outgoing {
        to: client,
        message,
        forgeable: key.is_none(),
    })
}

/// What a Send indication becomes, if the relay lets it through. The checks that need no state
/// come first, and the message is built after the lock is let go.
fn send(
    relay: &Mutex<Relay>,
    indication: &Message,
    client: Client,
    now: Instant,
) -> Option<Outgoing> {
    if unknown_attributes(indication).is_some() {
        return None;
    }
    let peer = indication.xor_address(XOR_PEER_ADDRESS)?;
    let data = indication.attribute(DATA)?;
    let forward = relay
        .lock()
        .unwrap()
        .forward(client, peer, data.len(), now)?;
    Some(relayed(forward, data))
}

/// What a ChannelData message becomes, if its channel is bound and the relay lets it through.
fn channel_data(
    relay: &Mutex<Relay>,
    bytes: &[u8],
    client: Client,
    now: Instant,
) -> Option<Outgoing> {
    let (number, data) = stun::parse_channel_data(bytes)?;
    let forward = relay
        .lock()
        .unwrap()
        .forward_channel(client, number, data.len(), now)?;
    Some(relayed(forward, data))
}

/// Relayed data as the receiver gets it: on its channel to the sender if it has bound one
/// (padded over TCP, RFC 8656 §12.5), and as a Data indication otherwise.
fn relayed(forward: Forward, data: &[u8]) -> Outgoing {
    let message = match forward.channel {
        Some(number) => stun::channel_data(number, data, forward.to.transport == Transport::Tcp),
        None => Builder::new(stun::DATA, Class::Indication, rand::random())
            .xor_address(XOR_PEER_ADDRESS, forward.from)
            .attribute(DATA, data)
            .build(),
    };
    Outgoing {
        to: forward.to,
        message,
        forgeable: false,
    }
}

/// A Binding request needs no credentials.
fn binding(request: &Message, client: Client) -> Builder {
    unknown_attributes(request).unwrap_or_else(|| {
        Builder::response(request, Class::Success).xor_address(XOR_MAPPED_ADDRESS, client.address)
    })
}

/// A 420 naming the comprehension-required attributes outpost does not understand, if any.
fn unknown_attributes(request: &Message) -> Option<Builder> {
    let mut unknown: Vec<u16> = request
        .attributes()
        .map(|attribute| attribute.kind)
        .filter(|kind| *kind < 0x8000 && !UNDERSTOOD.contains(kind))
        .collect();
    // Sorting rather than searching keeps a message of thousands of attributes cheap.
    unknown.sort_unstable();
    unknown.dedup();
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
        relay: Mutex<Relay>,
        room: Credentials,
        start: Instant,
    }

    fn setup() -> Setup {
        setup_with(Limits::default())
    }

    fn setup_with(limits: Limits) -> Setup {
        let start = Instant::now();
        let mut relay = Relay::new(PUBLIC_IP.into(), limits, start);
        let room = relay.open_room();
        Setup {
            relay: Mutex::new(relay),
            room,
            start,
        }
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
        fn relay(&mut self) -> &mut Relay {
            self.relay.get_mut().unwrap()
        }

        fn ask(&mut self, request: Vec<u8>, client: Client, now: Instant) -> Reply {
            let outgoing = handle(&self.relay, &request, client, now).expect("an answer");
            assert_eq!(outgoing.to, client, "an answer goes back to who asked");
            Reply {
                bytes: outgoing.message,
            }
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

        fn permit(&mut self, client: Client, now: Instant, peers: &[SocketAddr]) -> Reply {
            let nonce = self.nonce(client, now);
            let request = signed(
                CREATE_PERMISSION,
                &self.room.clone(),
                &nonce,
                *b"permit-them!",
                |mut b| {
                    for peer in peers {
                        b = b.xor_address(XOR_PEER_ADDRESS, *peer);
                    }
                    b
                },
            );
            self.ask(request, client, now)
        }

        fn bind(&mut self, client: Client, now: Instant, number: u16, peer: SocketAddr) -> Reply {
            let nonce = self.nonce(client, now);
            let request = signed(
                CHANNEL_BIND,
                &self.room.clone(),
                &nonce,
                *b"bind-it-now!",
                |b| {
                    b.attribute(CHANNEL_NUMBER, &channel_number(number))
                        .xor_address(XOR_PEER_ADDRESS, peer)
                },
            );
            self.ask(request, client, now)
        }

        /// What ChannelData from `client` on channel `number` leads to.
        fn on_channel(&self, client: Client, now: Instant, number: u16) -> Option<Outgoing> {
            let message = stun::channel_data(number, b"game data", false);
            handle(&self.relay, &message, client, now)
        }

        /// What a Send indication from `client` to `peer` leads to.
        fn send(&self, client: Client, now: Instant, peer: SocketAddr) -> Option<Outgoing> {
            handle(
                &self.relay,
                &send_indication(peer, b"game data"),
                client,
                now,
            )
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

    fn channel_number(number: u16) -> [u8; 4] {
        let [high, low] = number.to_be_bytes();
        [high, low, 0, 0]
    }

    fn send_indication(peer: SocketAddr, data: &[u8]) -> Vec<u8> {
        Builder::new(SEND, Class::Indication, *b"send-it-on!!")
            .xor_address(XOR_PEER_ADDRESS, peer)
            .attribute(DATA, data)
            .build()
    }

    /// Two players of the room, each allocated and permitting the other. Answers their clients
    /// and relayed addresses.
    fn two_players(s: &mut Setup) -> [(Client, SocketAddr); 2] {
        let players =
            [client(1), client(2)].map(|player| (player, s.allocate(player, s.start).relayed()));
        for (player, _) in players {
            let others: Vec<SocketAddr> = players.iter().map(|(_, relayed)| *relayed).collect();
            assert_eq!(
                s.permit(player, s.start, &others).message().class(),
                Class::Success
            );
        }
        players
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
        let over_tcp = s.nonce(
            Client {
                transport: Transport::Tcp,
                ..client(1)
            },
            s.start,
        );
        assert_eq!(challenge.nonce(), again);
        assert_ne!(challenge.nonce(), other, "no two clients share a nonce");
        assert_ne!(challenge.nonce(), over_tcp, "nor two transports");
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
        assert_eq!(reply.relayed().ip(), Ipv4Addr::from(PUBLIC_IP));
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
        let nonce = s.nonce(client(1), s.start);
        let username = s.room.username.clone();
        let login = [
            (USERNAME, username.as_bytes()),
            (REALM, REALM_TEXT.as_bytes()),
            (NONCE, &nonce[..]),
        ];
        for missing in [USERNAME, REALM, NONCE] {
            let mut request = udp(Builder::new(ALLOCATE, Class::Request, *b"allocate-it!"));
            for (kind, value) in login {
                if kind != missing {
                    request = request.attribute(kind, value);
                }
            }
            let reply = s.ask(request.integrity(&key).fingerprint(), client(1), s.start);
            assert_eq!(reply.code(), Some(400), "without {missing:#06x}");
            assert_eq!(reply.message().attribute(NONCE), None);
            assert_eq!(reply.message().attribute(REALM), None);
        }
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
        assert_eq!(s.ask(another, client(1), at(s.start, 20)).code(), Some(437));

        // The same transaction logged in to another room is not a retransmission.
        let other_room = s.relay().open_room();
        let from_other_room = signed(ALLOCATE, &other_room, &nonce, *b"allocate-it!", udp);
        assert_eq!(
            s.ask(from_other_room, client(1), at(s.start, 30)).code(),
            Some(437)
        );
    }

    #[test]
    fn a_room_holds_its_allocations_on_different_relayed_addresses_up_to_its_size() {
        let mut s = setup();
        let mut relayed = std::collections::HashSet::new();
        for port in 0..ROOM_SIZE as u16 {
            relayed.insert(s.allocate(client(port), s.start).relayed());
        }
        assert_eq!(relayed.len(), ROOM_SIZE);
        assert_eq!(s.allocate(client(100), s.start).code(), Some(486));

        // Another room is not affected.
        s.room = s.relay().open_room();
        let reply = s.allocate(client(100), s.start);
        assert_eq!(reply.message().class(), Class::Success);
    }

    #[test]
    fn an_expired_allocation_does_not_hold_a_place_before_it_is_swept() {
        let mut s = setup();
        for port in 0..ROOM_SIZE as u16 {
            s.allocate(client(port), s.start);
        }
        let later = at(s.start, u64::from(DEFAULT_LIFETIME));
        let reply = s.allocate(client(100), later);
        assert_eq!(reply.message().class(), Class::Success);
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
    fn an_allocate_asking_for_lifetime_zero_gets_the_default() {
        let mut s = setup();
        let room = s.room.clone();
        let nonce = s.nonce(client(1), s.start);
        let request = signed(ALLOCATE, &room, &nonce, *b"allocate-it!", |b| {
            udp(b).attribute(LIFETIME, &[0, 0, 0, 0])
        });
        assert_eq!(
            s.ask(request, client(1), s.start).lifetime(),
            DEFAULT_LIFETIME
        );
        let alive = s.refresh(client(1), at(s.start, 1), None);
        assert_eq!(alive.message().class(), Class::Success);
    }

    #[test]
    fn a_refresh_for_another_address_family_is_a_443() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        let room = s.room.clone();
        let nonce = s.nonce(client(1), s.start);
        let request = signed(REFRESH, &room, &nonce, *b"refresh-it!!", |b| {
            b.attribute(REQUESTED_ADDRESS_FAMILY, &[0x02, 0, 0, 0])
        });
        assert_eq!(s.ask(request, client(1), s.start).code(), Some(443));
    }

    #[test]
    fn a_refresh_from_another_room_is_refused() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        s.room = s.relay().open_room();
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

        s.relay().disconnect(client(2));
        assert_eq!(
            s.allocate(client(4), s.start).message().class(),
            Class::Success
        );

        let expired = at(s.start, u64::from(DEFAULT_LIFETIME));
        s.relay().sweep(expired);
        let username = s.room.username.clone();
        let relay = s.relay();
        assert!(relay.allocations.is_empty() && relay.ports.is_empty());
        assert_eq!(relay.rooms[&username].allocations, 0);
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
        let s = setup();
        let mut broken_fingerprint =
            Builder::new(BINDING, Class::Request, *b"binding-test").fingerprint();
        broken_fingerprint[8] ^= 1;
        for bytes in [
            Builder::new(BINDING, Class::Indication, *b"binding-test").build(),
            Builder::new(BINDING, Class::Success, *b"binding-test").build(),
            Builder::new(ALLOCATE, Class::Error, *b"binding-test").build(),
            Builder::new(0x00A, Class::Request, *b"binding-test").build(), // Connect (RFC 6062)
            broken_fingerprint,
            b"not stun at all, not stun at all".to_vec(),
        ] {
            assert!(
                handle(&s.relay, &bytes, client(1), s.start).is_none(),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn a_permission_needs_an_allocation_and_ipv4_peer_addresses() {
        let mut s = setup();
        let peer: SocketAddr = "203.0.113.50:1234".parse().unwrap();
        assert_eq!(s.permit(client(1), s.start, &[peer]).code(), Some(437));
        s.allocate(client(1), s.start);
        assert_eq!(s.permit(client(1), s.start, &[]).code(), Some(400));
        let ipv6: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        assert_eq!(
            s.permit(client(1), s.start, &[peer, ipv6]).code(),
            Some(443)
        );
        let granted = s.permit(client(1), s.start, &[peer]);
        assert_eq!(granted.message().class(), Class::Success);
        assert!(granted.signed_with(&s.room));

        let room = s.room.clone();
        let nonce = s.nonce(client(1), s.start);
        let malformed = signed(CREATE_PERMISSION, &room, &nonce, *b"permit-them!", |b| {
            b.xor_address(XOR_PEER_ADDRESS, peer)
                .attribute(XOR_PEER_ADDRESS, &[0, 1])
        });
        assert_eq!(s.ask(malformed, client(1), s.start).code(), Some(400));

        s.room = s.relay().open_room();
        assert_eq!(s.permit(client(1), s.start, &[peer]).code(), Some(441));
    }

    #[test]
    fn data_goes_between_two_allocations_of_a_room_that_permit_each_other() {
        let mut s = setup();
        let [(first, first_relayed), (second, second_relayed)] = two_players(&mut s);
        for (from, from_relayed, to, to_relayed) in [
            (first, first_relayed, second, second_relayed),
            (second, second_relayed, first, first_relayed),
        ] {
            let outgoing = s.send(from, s.start, to_relayed).expect("relayed");
            assert_eq!(outgoing.to, to);
            let data = Message::parse(&outgoing.message).unwrap();
            assert_eq!(
                (data.method(), data.class()),
                (stun::DATA, Class::Indication)
            );
            assert_eq!(data.xor_address(XOR_PEER_ADDRESS), Some(from_relayed));
            assert_eq!(data.attribute(DATA), Some(&b"game data"[..]));
        }
    }

    #[test]
    fn data_needs_both_permissions() {
        let mut s = setup();
        let first = s.allocate(client(1), s.start).relayed();
        let second = s.allocate(client(2), s.start).relayed();
        s.permit(client(1), s.start, &[second]);
        assert!(
            s.send(client(1), s.start, second).is_none(),
            "the receiver permits nobody"
        );
        assert!(
            s.send(client(2), s.start, first).is_none(),
            "the sender permits nobody"
        );
        s.permit(client(2), s.start, &[first]);
        assert!(s.send(client(1), s.start, second).is_some());
    }

    #[test]
    fn data_goes_nowhere_but_to_another_allocation_of_the_same_room() {
        let mut s = setup();
        let [(first, first_relayed), (_, second_relayed)] = two_players(&mut s);
        let foreign: SocketAddr = "203.0.113.50:1234".parse().unwrap();
        // The second player's port on another address, so only the address can refuse it.
        let same_port_elsewhere = SocketAddr::new([10, 0, 0, 1].into(), second_relayed.port());
        let unallocated = SocketAddr::new(first_relayed.ip(), 1023);
        s.permit(first, s.start, &[foreign, same_port_elsewhere]);

        // A player of another room, permitting everyone.
        let ours = s.room.clone();
        s.room = s.relay().open_room();
        let stranger = s.allocate(client(9), s.start).relayed();
        s.permit(client(9), s.start, &[first_relayed]);
        s.room = ours;

        for peer in [
            foreign,
            same_port_elsewhere,
            unallocated,
            first_relayed,
            stranger,
        ] {
            assert!(s.send(first, s.start, peer).is_none(), "{peer}");
        }
        assert!(s.send(client(9), s.start, first_relayed).is_none());
    }

    #[test]
    fn a_permission_lasts_five_minutes_unless_renewed() {
        let mut s = setup();
        let [(first, _), (_, second_relayed)] = two_players(&mut s);
        let lifetime = PERMISSION_LIFETIME.as_secs();
        assert!(
            s.send(first, at(s.start, lifetime - 1), second_relayed)
                .is_some()
        );
        assert!(
            s.send(first, at(s.start, lifetime), second_relayed)
                .is_none()
        );

        s.permit(first, at(s.start, lifetime), &[second_relayed]);
        // The second player's permission lapsed too.
        assert!(
            s.send(first, at(s.start, lifetime), second_relayed)
                .is_none()
        );
        s.permit(client(2), at(s.start, lifetime), &[second_relayed]);
        assert!(
            s.send(first, at(s.start, 2 * lifetime - 1), second_relayed)
                .is_some()
        );
    }

    #[test]
    fn a_send_without_an_allocation_data_or_known_attributes_is_dropped() {
        let mut s = setup();
        let [(first, _), (_, second_relayed)] = two_players(&mut s);
        assert!(s.send(client(3), s.start, second_relayed).is_none());

        let without_data = Builder::new(SEND, Class::Indication, *b"send-it-on!!")
            .xor_address(XOR_PEER_ADDRESS, second_relayed)
            .build();
        let with_unknown = Builder::new(SEND, Class::Indication, *b"send-it-on!!")
            .xor_address(XOR_PEER_ADDRESS, second_relayed)
            .attribute(DATA, b"x")
            .attribute(0x7fff, &[])
            .build();
        let as_request = Builder::new(SEND, Class::Request, *b"send-it-on!!")
            .xor_address(XOR_PEER_ADDRESS, second_relayed)
            .attribute(DATA, b"x")
            .build();
        for bytes in [without_data, with_unknown, as_request] {
            assert!(handle(&s.relay, &bytes, first, s.start).is_none());
        }
        let empty = send_indication(second_relayed, b"");
        assert!(
            handle(&s.relay, &empty, first, s.start).is_some(),
            "DATA may be empty"
        );
    }

    #[test]
    fn an_allocation_holds_a_bounded_number_of_permissions() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        let peer = |n: u32| SocketAddr::from((Ipv4Addr::from(0x0a00_0000 + n), 1));
        let peers: Vec<SocketAddr> = (0..MAX_PERMISSIONS as u32 - 1).map(peer).collect();
        assert_eq!(
            s.permit(client(1), s.start, &peers).message().class(),
            Class::Success
        );

        // One place left: a request for two new peers gets neither.
        let two_new = [peer(1000), peer(1001)];
        assert_eq!(s.permit(client(1), s.start, &two_new).code(), Some(508));
        let last = s.permit(client(1), s.start, &[peer(1002)]);
        assert_eq!(
            last.message().class(),
            Class::Success,
            "the place is still free"
        );
        assert_eq!(
            s.permit(client(1), s.start, &[peer(1003)]).code(),
            Some(508)
        );

        let renewal = s.permit(client(1), s.start, &peers[..1]);
        assert_eq!(renewal.message().class(), Class::Success);
        let later = at(s.start, PERMISSION_LIFETIME.as_secs());
        let after_expiry = s.permit(client(1), later, &[peer(1003)]);
        assert_eq!(after_expiry.message().class(), Class::Success);
    }

    #[test]
    fn a_channel_needs_an_allocation_a_number_in_range_and_an_ipv4_peer() {
        let mut s = setup();
        let peer: SocketAddr = "203.0.113.50:1234".parse().unwrap();
        assert_eq!(s.bind(client(1), s.start, 0x4000, peer).code(), Some(437));
        s.allocate(client(1), s.start);
        for number in [0x3FFF, 0x5000, 0xFFFF] {
            assert_eq!(
                s.bind(client(1), s.start, number, peer).code(),
                Some(400),
                "{number:#x}"
            );
        }
        let ipv6: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        assert_eq!(s.bind(client(1), s.start, 0x4000, ipv6).code(), Some(443));

        let room = s.room.clone();
        let nonce = s.nonce(client(1), s.start);
        let without_number = signed(CHANNEL_BIND, &room, &nonce, *b"bind-it-now!", |b| {
            b.xor_address(XOR_PEER_ADDRESS, peer)
        });
        let without_peer = signed(CHANNEL_BIND, &room, &nonce, *b"bind-it-now!", |b| {
            b.attribute(CHANNEL_NUMBER, &channel_number(0x4000))
        });
        for request in [without_number, without_peer] {
            assert_eq!(s.ask(request, client(1), s.start).code(), Some(400));
        }

        let bound = s.bind(client(1), s.start, 0x4000, peer);
        assert_eq!(bound.message().class(), Class::Success);
        assert!(bound.signed_with(&s.room));
        s.room = s.relay().open_room();
        assert_eq!(s.bind(client(1), s.start, 0x4000, peer).code(), Some(441));
    }

    #[test]
    fn a_channel_and_its_peer_belong_to_each_other_until_the_binding_expires() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        // Outlive the channel, so that only the channel expires.
        s.refresh(client(1), s.start, Some(MAX_LIFETIME));
        let peer: SocketAddr = "203.0.113.50:1234".parse().unwrap();
        let other: SocketAddr = "203.0.113.50:1235".parse().unwrap();
        let ok = |reply: Reply| reply.message().class() == Class::Success;
        assert!(ok(s.bind(client(1), s.start, 0x4000, peer)));
        assert!(
            ok(s.bind(client(1), at(s.start, 1), 0x4000, peer)),
            "a refresh"
        );
        assert_eq!(s.bind(client(1), s.start, 0x4000, other).code(), Some(400));
        assert_eq!(s.bind(client(1), s.start, 0x4001, peer).code(), Some(400));

        let expired = at(s.start, 1 + CHANNEL_LIFETIME.as_secs());
        assert!(ok(s.bind(client(1), expired, 0x4000, other)));
        assert!(ok(s.bind(client(1), expired, 0x4001, peer)));
    }

    #[test]
    fn channels_alone_let_data_through_and_it_arrives_on_the_receivers_channel() {
        let mut s = setup();
        let first = s.allocate(client(1), s.start).relayed();
        let second = s.allocate(client(2), s.start).relayed();
        s.bind(client(1), s.start, 0x4000, second);
        s.bind(client(2), s.start, 0x4abc, first);

        let outgoing = s.on_channel(client(1), s.start, 0x4000).expect("relayed");
        assert_eq!(outgoing.to, client(2));
        assert_eq!(
            outgoing.message,
            stun::channel_data(0x4abc, b"game data", false)
        );

        // A Send indication reaches a receiver with a channel on that channel too.
        let outgoing = s.send(client(2), s.start, first).expect("relayed");
        assert_eq!(
            outgoing.message,
            stun::channel_data(0x4000, b"game data", false)
        );
    }

    #[test]
    fn data_on_a_channel_reaches_a_receiver_without_one_as_a_data_indication() {
        let mut s = setup();
        let first = s.allocate(client(1), s.start).relayed();
        let second = s.allocate(client(2), s.start).relayed();
        s.bind(client(1), s.start, 0x4000, second);
        s.permit(client(2), s.start, &[first]);
        let outgoing = s.on_channel(client(1), s.start, 0x4000).expect("relayed");
        let data = Message::parse(&outgoing.message).unwrap();
        assert_eq!(
            (data.method(), data.class()),
            (stun::DATA, Class::Indication)
        );
        assert_eq!(data.xor_address(XOR_PEER_ADDRESS), Some(first));
        assert_eq!(data.attribute(DATA), Some(&b"game data"[..]));
    }

    #[test]
    fn channel_data_for_a_tcp_client_is_padded() {
        let mut s = setup();
        let over_tcp = Client {
            transport: Transport::Tcp,
            ..client(2)
        };
        let first = s.allocate(client(1), s.start).relayed();
        let second = s.allocate(over_tcp, s.start).relayed();
        s.bind(client(1), s.start, 0x4000, second);
        s.bind(over_tcp, s.start, 0x4001, first);
        let three_bytes = stun::channel_data(0x4000, b"abc", false);
        let outgoing = handle(&s.relay, &three_bytes, client(1), s.start).expect("relayed");
        assert_eq!(outgoing.message, stun::channel_data(0x4001, b"abc", true));
        assert_eq!(outgoing.message.len(), 8);
    }

    #[test]
    fn channel_data_goes_nowhere_unbound_expired_or_outside_the_room() {
        let mut s = setup();
        let [(first, first_relayed), (second, second_relayed)] = two_players(&mut s);
        let foreign: SocketAddr = "203.0.113.50:1234".parse().unwrap();
        s.bind(first, s.start, 0x4000, second_relayed);
        s.bind(first, s.start, 0x4001, foreign);
        s.bind(first, s.start, 0x4002, first_relayed);

        let ours = s.room.clone();
        s.room = s.relay().open_room();
        let stranger = s.allocate(client(9), s.start).relayed();
        s.permit(client(9), s.start, &[first_relayed]);
        s.room = ours;
        s.bind(first, s.start, 0x4003, stranger);

        assert!(s.on_channel(first, s.start, 0x4000).is_some());
        for number in [0x4001, 0x4002, 0x4003, 0x4fff] {
            assert!(
                s.on_channel(first, s.start, number).is_none(),
                "{number:#x}"
            );
        }
        assert!(
            s.on_channel(second, s.start, 0x4000).is_none(),
            "another allocation's channel"
        );
        let reserved = [0x50, 0x00, 0x00, 0x00];
        assert!(handle(&s.relay, &reserved, first, s.start).is_none());

        // Data on a channel renews neither it nor the permissions; renewing the permissions
        // alone, and the allocations, keeps data flowing until the channel itself expires.
        s.refresh(first, s.start, Some(MAX_LIFETIME));
        s.refresh(second, s.start, Some(MAX_LIFETIME));
        let renew = at(s.start, 400);
        s.permit(first, renew, &[second_relayed]);
        s.permit(second, renew, &[first_relayed]);
        let lifetime = CHANNEL_LIFETIME.as_secs();
        assert!(
            s.on_channel(first, at(s.start, lifetime - 1), 0x4000)
                .is_some()
        );
        assert!(s.on_channel(first, at(s.start, lifetime), 0x4000).is_none());
    }

    #[test]
    fn an_allocation_binds_a_bounded_number_of_channels() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        let peer = |n: u16| SocketAddr::from(([10, 0, 0, 1], n));
        for n in 0..MAX_CHANNELS as u16 {
            let reply = s.bind(client(1), s.start, 0x4000 + n, peer(n));
            assert_eq!(reply.message().class(), Class::Success);
        }
        assert_eq!(
            s.bind(client(1), s.start, 0x4fff, peer(999)).code(),
            Some(508)
        );
        let refresh = s.bind(client(1), s.start, 0x4000, peer(0));
        assert_eq!(refresh.message().class(), Class::Success);
    }

    #[test]
    fn data_reaches_a_receiver_whose_channel_expired_as_a_data_indication() {
        let mut s = setup();
        let first = s.allocate(client(1), s.start).relayed();
        let second = s.allocate(client(2), s.start).relayed();
        s.refresh(client(1), s.start, Some(MAX_LIFETIME));
        s.refresh(client(2), s.start, Some(MAX_LIFETIME));
        s.bind(client(1), s.start, 0x4000, second);
        s.bind(client(2), s.start, 0x4001, first);
        let after = at(s.start, CHANNEL_LIFETIME.as_secs());
        s.permit(client(1), after, &[second]);
        s.permit(client(2), after, &[first]);
        let outgoing = s.send(client(1), after, second).expect("relayed");
        let data = Message::parse(&outgoing.message).expect("a Data indication, not ChannelData");
        assert_eq!(
            (data.method(), data.class()),
            (stun::DATA, Class::Indication)
        );
    }

    #[test]
    fn channel_data_does_not_renew_the_permissions_it_relies_on() {
        let mut s = setup();
        let first = s.allocate(client(1), s.start).relayed();
        let second = s.allocate(client(2), s.start).relayed();
        s.bind(client(1), s.start, 0x4000, second);
        s.bind(client(2), s.start, 0x4001, first);
        let lifetime = PERMISSION_LIFETIME.as_secs();
        for seconds in [1, lifetime / 2, lifetime - 1] {
            assert!(
                s.on_channel(client(1), at(s.start, seconds), 0x4000)
                    .is_some()
            );
        }
        assert!(
            s.on_channel(client(1), at(s.start, lifetime), 0x4000)
                .is_none()
        );
    }

    #[test]
    fn a_channel_to_a_new_peer_is_refused_when_its_permission_does_not_fit() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        let peers: Vec<SocketAddr> = (0..MAX_PERMISSIONS as u32)
            .map(|n| SocketAddr::from((Ipv4Addr::from(0x0a00_0000 + n), 1)))
            .collect();
        s.permit(client(1), s.start, &peers);
        let new_peer: SocketAddr = "203.0.113.50:1".parse().unwrap();
        assert_eq!(
            s.bind(client(1), s.start, 0x4000, new_peer).code(),
            Some(508)
        );
        // Nothing was bound: the number is free for a peer that already has a permission.
        let reply = s.bind(client(1), s.start, 0x4000, peers[0]);
        assert_eq!(reply.message().class(), Class::Success);
    }

    #[test]
    fn expired_channels_give_their_places_back() {
        let mut s = setup();
        s.allocate(client(1), s.start);
        s.refresh(client(1), s.start, Some(MAX_LIFETIME));
        let peer = |n: u16| SocketAddr::from(([10, 0, 0, 1], n));
        for n in 0..MAX_CHANNELS as u16 {
            s.bind(client(1), s.start, 0x4000 + n, peer(n));
        }
        let later = at(s.start, CHANNEL_LIFETIME.as_secs());
        let reply = s.bind(client(1), later, 0x4fff, peer(999));
        assert_eq!(reply.message().class(), Class::Success);
    }

    fn from_address(ip: [u8; 4], port: u16) -> Client {
        Client {
            address: SocketAddr::from((ip, port)),
            transport: Transport::Udp,
        }
    }

    #[test]
    fn one_address_holds_a_bounded_number_of_allocations() {
        let mut s = setup_with(Limits {
            allocations_per_address: 3,
            ..Limits::default()
        });
        for port in 1..=3 {
            s.allocate(client(port), s.start);
        }
        assert_eq!(s.allocate(client(4), s.start).code(), Some(486));
        let elsewhere = s.allocate(from_address([192, 0, 2, 7], 4), s.start);
        assert_eq!(elsewhere.message().class(), Class::Success);
        s.refresh(client(1), s.start, Some(0));
        assert_eq!(
            s.allocate(client(4), s.start).message().class(),
            Class::Success
        );
    }

    #[test]
    fn outpost_holds_a_bounded_number_of_allocations() {
        let mut s = setup_with(Limits {
            allocations: 3,
            ..Limits::default()
        });
        for n in 1..=3 {
            s.allocate(from_address([192, 0, 2, n], 1), s.start);
        }
        assert_eq!(
            s.allocate(from_address([192, 0, 2, 4], 1), s.start).code(),
            Some(508)
        );
        s.refresh(from_address([192, 0, 2, 1], 1), s.start, Some(0));
        let reply = s.allocate(from_address([192, 0, 2, 4], 1), s.start);
        assert_eq!(reply.message().class(), Class::Success);
    }

    fn with_room_bandwidth(per_second: f64, burst: f64) -> Setup {
        setup_with(Limits {
            room_bandwidth: crate::limit::Rate { per_second, burst },
            ..Limits::default()
        })
    }

    fn on_channel_with(s: &Setup, client: Client, seconds: u64, bytes: usize) -> bool {
        let message = stun::channel_data(0x4000, &vec![0; bytes], false);
        handle(&s.relay, &message, client, at(s.start, seconds)).is_some()
    }

    #[test]
    fn a_room_relays_at_most_its_bandwidth_shared_by_its_players() {
        let mut s = with_room_bandwidth(100.0, 1000.0);
        let [(first, first_relayed), (second, second_relayed)] = two_players(&mut s);
        s.bind(first, s.start, 0x4000, second_relayed);
        s.bind(second, s.start, 0x4000, first_relayed);
        let cost = |bytes: usize| bytes + MESSAGE_COST;
        assert!(on_channel_with(&s, first, 0, 600));
        assert!(!on_channel_with(&s, first, 0, 600), "beyond the burst");
        assert!(on_channel_with(
            &s,
            first,
            0,
            1000 - cost(600) - MESSAGE_COST
        ));
        assert!(
            !on_channel_with(&s, first, 0, 0),
            "nothing is left, not even for nothing"
        );
        assert!(
            !on_channel_with(&s, second, 0, 0),
            "the other player shares it"
        );
        assert!(
            on_channel_with(&s, second, 7, 600),
            "seven seconds at 100 bytes a second"
        );
    }

    #[test]
    fn every_relayed_message_costs_something_even_when_empty() {
        let mut s = with_room_bandwidth(0.0, 10.0 * MESSAGE_COST as f64);
        let [(first, _), (_, second_relayed)] = two_players(&mut s);
        s.bind(first, s.start, 0x4000, second_relayed);
        for _ in 0..10 {
            assert!(on_channel_with(&s, first, 0, 0));
        }
        assert!(!on_channel_with(&s, first, 0, 0));
    }

    #[test]
    fn allocating_again_does_not_refill_the_rooms_bandwidth() {
        let mut s = with_room_bandwidth(0.0, 1000.0);
        let [(first, _), (second, second_relayed)] = two_players(&mut s);
        s.bind(first, s.start, 0x4000, second_relayed);
        assert!(on_channel_with(&s, first, 0, 1000 - MESSAGE_COST - 10));

        s.refresh(first, s.start, Some(0));
        let again = Client {
            transport: Transport::Tcp,
            ..first
        };
        let again_relayed = s.allocate(again, s.start).relayed();
        s.permit(again, s.start, &[second_relayed]);
        s.permit(second, s.start, &[again_relayed]);
        s.bind(again, s.start, 0x4000, second_relayed);
        assert!(!on_channel_with(&s, again, 0, 0));
    }

    #[test]
    fn only_answers_that_did_not_log_in_could_be_going_to_a_forged_source() {
        let mut s = setup();
        let forgeable = |s: &mut Setup, request: Vec<u8>| {
            handle(&s.relay, &request, client(1), s.start)
                .unwrap()
                .forgeable
        };
        assert!(forgeable(&mut s, stun::binding_request(*b"binding-test")));
        assert!(forgeable(&mut s, unsigned(ALLOCATE, *b"challenge-me")));
        let nonce = s.nonce(client(1), s.start);
        let room = s.room.clone();
        let signed_allocate = signed(ALLOCATE, &room, &nonce, *b"allocate-it!", udp);
        assert!(!forgeable(&mut s, signed_allocate));

        let [(first, _), (_, second_relayed)] = two_players(&mut s);
        let data = s.send(first, s.start, second_relayed).unwrap();
        assert!(
            !data.forgeable,
            "relayed data goes to an allocation's own address"
        );
    }
}
