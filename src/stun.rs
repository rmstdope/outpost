//! The STUN message format (RFC 8489 §5 and §14): enough to answer a Binding request, and to ask
//! one when checking our own health.

use std::net::{IpAddr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_LEN: usize = 20;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub type Transaction = [u8; 12];

/// One whole STUN message whose header and attribute framing are well formed.
pub struct Message<'a> {
    pub kind: u16,
    pub transaction: Transaction,
    attributes: &'a [u8],
}

impl<'a> Message<'a> {
    /// Reads `bytes` as exactly one STUN message.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if message_length(bytes)? != bytes.len() {
            return None;
        }
        let message = Message {
            kind: u16::from_be_bytes([bytes[0], bytes[1]]),
            transaction: bytes[8..HEADER_LEN].try_into().unwrap(),
            attributes: &bytes[HEADER_LEN..],
        };
        let mut rest = message.attributes;
        while !rest.is_empty() {
            rest = rest.get(attribute_span(rest)?..)?;
        }
        Some(message)
    }

    pub fn is_binding_request(&self) -> bool {
        self.kind == BINDING_REQUEST
    }

    pub fn is_binding_success(&self) -> bool {
        self.kind == BINDING_SUCCESS
    }

    /// The first attribute of type `kind`, without its padding.
    pub fn attribute(&self, kind: u16) -> Option<&'a [u8]> {
        let mut rest = self.attributes;
        while !rest.is_empty() {
            let length = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            if u16::from_be_bytes([rest[0], rest[1]]) == kind {
                return Some(&rest[4..4 + length]);
            }
            rest = &rest[attribute_span(rest)?..];
        }
        None
    }

    /// The address a Binding response says the request came from.
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        let value = self.attribute(XOR_MAPPED_ADDRESS)?;
        let port =
            u16::from_be_bytes([*value.get(2)?, *value.get(3)?]) ^ (MAGIC_COOKIE >> 16) as u16;
        let mut address = value.get(4..)?.to_vec();
        xor(&mut address, &self.transaction);
        let ip = match (value.get(1)?, address.len()) {
            (1, 4) => IpAddr::from(<[u8; 4]>::try_from(address).unwrap()),
            (2, 16) => IpAddr::from(<[u8; 16]>::try_from(address).unwrap()),
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }
}

/// The length of the STUN message whose header starts `bytes`, if it is a STUN header: the top
/// two bits clear, the magic cookie in place, and a body length that is a multiple of four.
pub fn message_length(bytes: &[u8]) -> Option<usize> {
    let header = bytes.get(..HEADER_LEN)?;
    let body = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let cookie = u32::from_be_bytes(header[4..8].try_into().unwrap());
    (header[0] & 0xC0 == 0 && cookie == MAGIC_COOKIE && body % 4 == 0).then_some(HEADER_LEN + body)
}

/// How many bytes the attribute starting `bytes` takes, padding included, if all of it is there.
fn attribute_span(bytes: &[u8]) -> Option<usize> {
    let length = usize::from(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]));
    let span = 4 + length.div_ceil(4) * 4;
    (span <= bytes.len()).then_some(span)
}

pub fn binding_request(transaction: Transaction) -> Vec<u8> {
    header(BINDING_REQUEST, transaction, 0)
}

pub fn binding_success(transaction: Transaction, mapped: SocketAddr) -> Vec<u8> {
    let (family, mut address) = match mapped.ip() {
        IpAddr::V4(ip) => (1, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2, ip.octets().to_vec()),
    };
    xor(&mut address, &transaction);
    let mut value = vec![0, family];
    value.extend_from_slice(&(mapped.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    value.extend_from_slice(&address);
    let mut message = header(BINDING_SUCCESS, transaction, 4 + value.len());
    message.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    message.extend_from_slice(&(value.len() as u16).to_be_bytes());
    message.extend_from_slice(&value);
    message
}

fn header(kind: u16, transaction: Transaction, body: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(HEADER_LEN + body);
    message.extend_from_slice(&kind.to_be_bytes());
    message.extend_from_slice(&(body as u16).to_be_bytes());
    message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message.extend_from_slice(&transaction);
    message
}

/// XORs an address with the magic cookie, followed for IPv6 by the transaction ID (§14.2).
fn xor(octets: &mut [u8], transaction: &Transaction) {
    let mask = MAGIC_COOKIE.to_be_bytes().into_iter().chain(*transaction);
    for (octet, mask) in octets.iter_mut().zip(mask) {
        *octet ^= mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transaction ID of the sample messages in RFC 5769.
    const SAMPLE: Transaction = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn a_binding_success_carries_the_xor_mapped_address_of_rfc_5769() {
        let ipv4 = binding_success(SAMPLE, "192.0.2.1:32853".parse().unwrap());
        assert_eq!(ipv4[20..], hex("0020 0008 0001 a147 e112a643"));
        assert_eq!(ipv4[..4], hex("0101 000c"));

        let ipv6 = binding_success(
            SAMPLE,
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            ipv6[20..],
            hex("0020 0014 0002 a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9")
        );
    }

    #[test]
    fn the_mapped_address_reads_back() {
        for address in ["203.0.113.9:3478", "[2001:db8::1]:65535"] {
            let address: SocketAddr = address.parse().unwrap();
            let bytes = binding_success(SAMPLE, address);
            let message = Message::parse(&bytes).unwrap();
            assert!(message.is_binding_success());
            assert_eq!(message.transaction, SAMPLE);
            assert_eq!(message.mapped_address(), Some(address));
        }
    }

    #[test]
    fn a_binding_request_is_a_bare_header() {
        let bytes = binding_request(SAMPLE);
        assert_eq!(bytes[..8], hex("0001 0000 2112a442"));
        let message = Message::parse(&bytes).unwrap();
        assert!(message.is_binding_request());
        assert_eq!(message.transaction, SAMPLE);
    }

    #[test]
    fn attributes_are_found_past_padding() {
        // SOFTWARE (11 bytes, padded to 12), then XOR-MAPPED-ADDRESS: the start of RFC 5769 §2.2.
        let bytes = hex("0101 001c 2112a442 b7e7a701 bc34d686 fa87dfae \
             8022 000b 74657374 20766563 746f7220 \
             0020 0008 0001 a147 e112a643");
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.attribute(0x8022), Some(&b"test vector"[..]));
        assert_eq!(
            message.mapped_address(),
            Some("192.0.2.1:32853".parse().unwrap())
        );
    }

    #[test]
    fn what_is_not_one_well_formed_message_is_refused() {
        let good = binding_success(SAMPLE, "192.0.2.1:32853".parse().unwrap());
        assert!(Message::parse(&good).is_some());

        let mut top_bits = good.clone();
        top_bits[0] |= 0x40;
        let mut cookie = good.clone();
        cookie[4] ^= 1;
        let mut odd_length = good.clone();
        odd_length[3] = 0x0b;
        let mut overlong_attribute = good.clone();
        overlong_attribute[23] = 0x0c;
        let mut trailing = good.clone();
        trailing.push(0);
        for bytes in [
            &good[..19],
            &good[..good.len() - 4],
            &top_bits,
            &cookie,
            &odd_length,
            &overlong_attribute,
            &trailing,
            &b"GET / HTTP/1.1\r\n\r\n.."[..],
        ] {
            assert!(Message::parse(bytes).is_none(), "{bytes:02x?}");
        }
    }

    #[test]
    fn the_message_length_comes_from_the_header_alone() {
        let bytes = binding_success(SAMPLE, "192.0.2.1:32853".parse().unwrap());
        assert_eq!(message_length(&bytes[..HEADER_LEN]), Some(32));
        assert_eq!(message_length(&bytes[..HEADER_LEN - 1]), None);
        assert_eq!(message_length(b"\x16\x03\x01 TLS hello, not STUN"), None);
    }
}
