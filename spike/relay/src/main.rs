//! Spike for PLAN.md step 1: the smallest TURN relay (RFC 8656) that forwards only between
//! allocations on this server, inside the process, through one UDP port. It answers whether
//! browsers accept such a relay. Throwaway code: one fixed user, one room, no limits.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::net::UdpSocket;

const COOKIE: u32 = 0x2112_A442;
const REALM: &str = "outpost";
const NONCE: &str = "spike-nonce";
const USER: &str = "spike";
const PASSWORD: &str = "spike";

const BINDING: u16 = 0x001;
const ALLOCATE: u16 = 0x003;
const REFRESH: u16 = 0x004;
const SEND: u16 = 0x006;
const DATA: u16 = 0x007;
const CREATE_PERMISSION: u16 = 0x008;
const CHANNEL_BIND: u16 = 0x009;

const REQUEST: u16 = 0x0000;
const INDICATION: u16 = 0x0010;
const SUCCESS: u16 = 0x0100;
const ERROR: u16 = 0x0110;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_FINGERPRINT: u16 = 0x8028;

struct Attribute {
    kind: u16,
    offset: usize,
    value: Vec<u8>,
}

struct Message {
    method: u16,
    class: u16,
    tid: [u8; 12],
    attrs: Vec<Attribute>,
    raw: Vec<u8>,
}

impl Message {
    fn parse(buf: &[u8]) -> Option<Message> {
        if buf.len() < 20 || buf[0] & 0xC0 != 0 {
            return None;
        }
        let kind = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != COOKIE || 20 + len > buf.len() {
            return None;
        }
        let method = (kind & 0x000F) | ((kind & 0x00E0) >> 1) | ((kind & 0x3E00) >> 2);
        let class = kind & 0x0110;
        let mut attrs = vec![];
        let mut offset = 20;
        while offset + 4 <= 20 + len {
            let attr_kind = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            let value = buf.get(offset + 4..offset + 4 + attr_len)?.to_vec();
            attrs.push(Attribute { kind: attr_kind, offset, value });
            offset += 4 + attr_len.div_ceil(4) * 4;
        }
        Some(Message {
            method,
            class,
            tid: buf[8..20].try_into().unwrap(),
            attrs,
            raw: buf[..20 + len].to_vec(),
        })
    }

    fn attr(&self, kind: u16) -> Option<&[u8]> {
        self.attrs.iter().find(|a| a.kind == kind).map(|a| a.value.as_slice())
    }

    fn addresses(&self, kind: u16) -> Vec<SocketAddr> {
        self.attrs
            .iter()
            .filter(|a| a.kind == kind)
            .filter_map(|a| xor_address(&a.value, &self.tid))
            .collect()
    }

    /// Checks MESSAGE-INTEGRITY against the long-term key (RFC 8489 §14.5).
    fn authentic(&self, key: &[u8]) -> bool {
        let text = |kind| self.attr(kind).map(|v| String::from_utf8_lossy(v).into_owned());
        if text(ATTR_USERNAME).as_deref() != Some(USER)
            || text(ATTR_REALM).as_deref() != Some(REALM)
            || text(ATTR_NONCE).as_deref() != Some(NONCE)
        {
            return false;
        }
        let Some(mi) = self.attrs.iter().find(|a| a.kind == ATTR_MESSAGE_INTEGRITY) else {
            return false;
        };
        let mut covered = self.raw[..mi.offset].to_vec();
        covered[2..4].copy_from_slice(&((mi.offset - 20 + 24) as u16).to_be_bytes());
        let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
        mac.update(&covered);
        mac.verify_slice(&mi.value).is_ok()
    }
}

fn xor_address(value: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]) ^ (COOKIE >> 16) as u16;
    let ip: IpAddr = match value.get(1)? {
        1 => {
            let raw = u32::from_be_bytes(value.get(4..8)?.try_into().ok()?) ^ COOKIE;
            IpAddr::from(raw.to_be_bytes())
        }
        2 => {
            let mut mask = COOKIE.to_be_bytes().to_vec();
            mask.extend_from_slice(tid);
            let raw: Vec<u8> = value.get(4..20)?.iter().zip(mask).map(|(a, b)| a ^ b).collect();
            IpAddr::from(<[u8; 16]>::try_from(raw).ok()?)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

struct Builder {
    buf: Vec<u8>,
    tid: [u8; 12],
}

impl Builder {
    fn new(method: u16, class: u16, tid: [u8; 12]) -> Builder {
        let kind = (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | class;
        let mut buf = kind.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&COOKIE.to_be_bytes());
        buf.extend_from_slice(&tid);
        Builder { buf, tid }
    }

    fn set_len(&mut self, len: usize) {
        self.buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    }

    fn attr(mut self, kind: u16, value: &[u8]) -> Builder {
        self.buf.extend_from_slice(&kind.to_be_bytes());
        self.buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(value);
        self.buf.resize(self.buf.len().div_ceil(4) * 4, 0);
        let len = self.buf.len() - 20;
        self.set_len(len);
        self
    }

    fn address(self, kind: u16, addr: SocketAddr) -> Builder {
        let port = (addr.port() ^ (COOKIE >> 16) as u16).to_be_bytes();
        let mut value = vec![0];
        match addr.ip() {
            IpAddr::V4(ip) => {
                value.push(1);
                value.extend_from_slice(&port);
                value.extend_from_slice(&(u32::from(ip) ^ COOKIE).to_be_bytes());
            }
            IpAddr::V6(ip) => {
                value.push(2);
                value.extend_from_slice(&port);
                let mut mask = COOKIE.to_be_bytes().to_vec();
                mask.extend_from_slice(&self.tid);
                value.extend(ip.octets().iter().zip(mask).map(|(a, b)| a ^ b));
            }
        }
        self.attr(kind, &value)
    }

    fn integrity(mut self, key: &[u8]) -> Builder {
        let len = self.buf.len() - 20 + 24;
        self.set_len(len);
        let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
        mac.update(&self.buf);
        let digest = mac.finalize().into_bytes();
        self.attr(ATTR_MESSAGE_INTEGRITY, &digest)
    }

    fn fingerprint(mut self) -> Vec<u8> {
        let len = self.buf.len() - 20 + 8;
        self.set_len(len);
        let crc = crc32fast::hash(&self.buf) ^ 0x5354_554E;
        self.attr(ATTR_FINGERPRINT, &crc.to_be_bytes()).buf
    }
}

struct Allocation {
    relayed: SocketAddr,
    permissions: HashSet<IpAddr>,
    channels: HashMap<u16, SocketAddr>,
}

struct Relay {
    public_ip: IpAddr,
    key: Vec<u8>,
    next_port: u16,
    allocations: HashMap<SocketAddr, Allocation>,
    owners: HashMap<SocketAddr, SocketAddr>,
}

type Outgoing = Vec<(Vec<u8>, SocketAddr)>;

impl Relay {
    fn handle(&mut self, buf: &[u8], from: SocketAddr) -> Outgoing {
        if buf.len() >= 4 && buf[0] & 0xC0 == 0x40 {
            return self.channel_data(buf, from);
        }
        let Some(message) = Message::parse(buf) else {
            return vec![];
        };
        match (message.method, message.class) {
            (BINDING, REQUEST) => {
                let reply = Builder::new(BINDING, SUCCESS, message.tid)
                    .address(ATTR_XOR_MAPPED_ADDRESS, from)
                    .fingerprint();
                vec![(reply, from)]
            }
            (SEND, INDICATION) => {
                let (Some(peer), Some(data)) =
                    (message.addresses(ATTR_XOR_PEER_ADDRESS).first().copied(), message.attr(ATTR_DATA))
                else {
                    return vec![];
                };
                self.relay(from, peer, data)
            }
            (method, REQUEST) => self.request(method, &message, from),
            _ => vec![],
        }
    }

    fn request(&mut self, method: u16, message: &Message, from: SocketAddr) -> Outgoing {
        if !message.authentic(&self.key) {
            eprintln!("{from}: method {method:#x} challenged");
            let reply = Builder::new(method, ERROR, message.tid)
                .attr(ATTR_ERROR_CODE, b"\0\0\x04\x01Unauthorized")
                .attr(ATTR_REALM, REALM.as_bytes())
                .attr(ATTR_NONCE, NONCE.as_bytes())
                .fingerprint();
            return vec![(reply, from)];
        }
        let reply = Builder::new(method, SUCCESS, message.tid);
        let reply = match method {
            ALLOCATE => {
                let relayed = match self.allocations.get(&from) {
                    Some(existing) => existing.relayed,
                    None => {
                        let relayed = SocketAddr::new(self.public_ip, self.next_port);
                        self.next_port += 1;
                        self.allocations.insert(from, Allocation {
                            relayed,
                            permissions: HashSet::new(),
                            channels: HashMap::new(),
                        });
                        self.owners.insert(relayed, from);
                        eprintln!("{from}: allocated {relayed}");
                        relayed
                    }
                };
                reply
                    .address(ATTR_XOR_RELAYED_ADDRESS, relayed)
                    .address(ATTR_XOR_MAPPED_ADDRESS, from)
                    .attr(ATTR_LIFETIME, &600u32.to_be_bytes())
            }
            REFRESH => {
                let lifetime = message.attr(ATTR_LIFETIME).map_or(600, |v| {
                    u32::from_be_bytes(v.try_into().unwrap_or([0, 0, 2, 88]))
                });
                if lifetime == 0
                    && let Some(gone) = self.allocations.remove(&from)
                {
                    self.owners.remove(&gone.relayed);
                    eprintln!("{from}: released {}", gone.relayed);
                }
                reply.attr(ATTR_LIFETIME, &lifetime.to_be_bytes())
            }
            CREATE_PERMISSION => {
                let peers = message.addresses(ATTR_XOR_PEER_ADDRESS);
                if let Some(allocation) = self.allocations.get_mut(&from) {
                    allocation.permissions.extend(peers.iter().map(SocketAddr::ip));
                }
                eprintln!("{from}: permission {peers:?}");
                reply
            }
            CHANNEL_BIND => {
                let channel = message.attr(ATTR_CHANNEL_NUMBER).map(|v| u16::from_be_bytes([v[0], v[1]]));
                let peer = message.addresses(ATTR_XOR_PEER_ADDRESS).first().copied();
                if let (Some(channel), Some(peer), Some(allocation)) =
                    (channel, peer, self.allocations.get_mut(&from))
                {
                    allocation.channels.insert(channel, peer);
                    allocation.permissions.insert(peer.ip());
                    eprintln!("{from}: channel {channel:#x} -> {peer}");
                }
                reply
            }
            _ => return vec![],
        };
        vec![(reply.integrity(&self.key).fingerprint(), from)]
    }

    fn channel_data(&mut self, buf: &[u8], from: SocketAddr) -> Outgoing {
        let channel = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let Some(data) = buf.get(4..4 + len) else {
            return vec![];
        };
        let Some(peer) = self.allocations.get(&from).and_then(|a| a.channels.get(&channel)).copied() else {
            return vec![];
        };
        self.relay(from, peer, data)
    }

    /// The room rule: data goes only to another allocation on this server, never out to `peer`.
    fn relay(&self, from: SocketAddr, peer: SocketAddr, data: &[u8]) -> Outgoing {
        let Some(source) = self.allocations.get(&from) else {
            return vec![];
        };
        if !source.permissions.contains(&peer.ip()) {
            return vec![];
        }
        let Some((&client, target)) = self.owners.get(&peer).and_then(|c| self.allocations.get_key_value(c))
        else {
            eprintln!("{from}: dropped data for {peer}, not an allocation here");
            return vec![];
        };
        if !target.permissions.contains(&source.relayed.ip()) {
            return vec![];
        }
        let channel = target.channels.iter().find(|(_, p)| **p == source.relayed).map(|(c, _)| *c);
        let packet = match channel {
            Some(channel) => {
                let mut packet = channel.to_be_bytes().to_vec();
                packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
                packet.extend_from_slice(data);
                packet
            }
            None => {
                let tid: [u8; 12] = std::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ data.len() as u8);
                let mut builder = Builder::new(DATA, INDICATION, tid)
                    .address(ATTR_XOR_PEER_ADDRESS, source.relayed)
                    .attr(ATTR_DATA, data);
                let len = builder.buf.len() - 20;
                builder.set_len(len);
                builder.buf
            }
        };
        vec![(packet, client)]
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let public_ip: IpAddr = std::env::var("PUBLIC_IP").unwrap_or("127.0.0.1".into()).parse().unwrap();
    let socket = UdpSocket::bind("0.0.0.0:3478").await?;
    let key = Md5::digest(format!("{USER}:{REALM}:{PASSWORD}")).to_vec();
    let mut relay = Relay { public_ip, key, next_port: 60000, allocations: HashMap::new(), owners: HashMap::new() };
    eprintln!("spike relay on udp 3478, relayed addresses on {public_ip}");
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, from) = socket.recv_from(&mut buf).await?;
        for (packet, to) in relay.handle(&buf[..len], from) {
            socket.send_to(&packet, to).await?;
        }
    }
}
