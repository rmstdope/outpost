//! The STUN message format (RFC 8489 §5 and §14): reading and writing messages, and checking
//! their MESSAGE-INTEGRITY and FINGERPRINT.

use std::net::{IpAddr, SocketAddr};

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_LEN: usize = 20;

pub const BINDING: u16 = 0x001;
/// TURN's methods (RFC 8656 §18).
pub const ALLOCATE: u16 = 0x003;
pub const REFRESH: u16 = 0x004;
pub const SEND: u16 = 0x006;
pub const DATA: u16 = 0x007;
pub const CREATE_PERMISSION: u16 = 0x008;
pub const CHANNEL_BIND: u16 = 0x009;

/// Attribute types (RFC 8489 §18.3, RFC 8656 §18). Those below 0x8000 are
/// comprehension-required.
pub mod attribute {
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
    pub const EVEN_PORT: u16 = 0x0018;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const DONT_FRAGMENT: u16 = 0x001A;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const RESERVATION_TOKEN: u16 = 0x0022;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
}

use attribute::{
    ERROR_CODE, FINGERPRINT, MESSAGE_INTEGRITY, MESSAGE_INTEGRITY_SHA256, XOR_MAPPED_ADDRESS,
};

const FINGERPRINT_XOR: u32 = 0x5354_554E;
const INTEGRITY_LEN: usize = 20;

pub type Transaction = [u8; 12];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

impl Class {
    /// The class's two bits, C1 and C0, in place in the message type (§5).
    fn bits(self) -> u16 {
        match self {
            Class::Request => 0x000,
            Class::Indication => 0x010,
            Class::Success => 0x100,
            Class::Error => 0x110,
        }
    }
}

/// One attribute as it appears in a message.
pub struct Attribute<'a> {
    pub kind: u16,
    pub value: &'a [u8],
    /// Where its header starts in the message.
    offset: usize,
}

/// One whole STUN message whose header and attribute framing are well formed.
pub struct Message<'a> {
    bytes: &'a [u8],
}

impl<'a> Message<'a> {
    /// Reads `bytes` as exactly one STUN message.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if message_length(bytes)? != bytes.len() {
            return None;
        }
        let mut rest = &bytes[HEADER_LEN..];
        while !rest.is_empty() {
            rest = rest.get(attribute_span(rest)?..)?;
        }
        Some(Message { bytes })
    }

    fn kind(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    pub fn method(&self) -> u16 {
        let kind = self.kind();
        (kind & 0x000F) | ((kind & 0x00E0) >> 1) | ((kind & 0x3E00) >> 2)
    }

    pub fn class(&self) -> Class {
        match self.kind() & 0x0110 {
            0x000 => Class::Request,
            0x010 => Class::Indication,
            0x100 => Class::Success,
            _ => Class::Error,
        }
    }

    pub fn transaction(&self) -> Transaction {
        self.bytes[8..HEADER_LEN].try_into().unwrap()
    }

    /// The attributes a receiver may act on (§14.5, §14.6): after MESSAGE-INTEGRITY only
    /// MESSAGE-INTEGRITY-SHA256 and FINGERPRINT count, and after MESSAGE-INTEGRITY-SHA256 only
    /// FINGERPRINT.
    pub fn attributes(&self) -> impl Iterator<Item = Attribute<'a>> + use<'a> {
        let bytes = self.bytes;
        let mut offset = HEADER_LEN;
        let mut sealed_by = None;
        std::iter::from_fn(move || {
            while offset < bytes.len() {
                let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                let length =
                    usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
                let attribute = Attribute {
                    kind,
                    value: &bytes[offset + 4..offset + 4 + length],
                    offset,
                };
                offset += 4 + length.div_ceil(4) * 4;
                let counts = match sealed_by {
                    None => true,
                    Some(MESSAGE_INTEGRITY) => {
                        kind == MESSAGE_INTEGRITY_SHA256 || kind == FINGERPRINT
                    }
                    Some(_) => kind == FINGERPRINT,
                };
                if counts {
                    if kind == MESSAGE_INTEGRITY || kind == MESSAGE_INTEGRITY_SHA256 {
                        sealed_by = Some(kind);
                    }
                    return Some(attribute);
                }
            }
            None
        })
    }

    /// The first attribute of type `kind`, without its padding.
    pub fn attribute(&self, kind: u16) -> Option<&'a [u8]> {
        self.attributes()
            .find(|attribute| attribute.kind == kind)
            .map(|attribute| attribute.value)
    }

    /// The address a Binding response says the request came from.
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        self.xor_address(XOR_MAPPED_ADDRESS)
    }

    /// An address attribute in the XOR-MAPPED-ADDRESS format (§14.2).
    pub fn xor_address(&self, kind: u16) -> Option<SocketAddr> {
        let value = self.attribute(kind)?;
        let port =
            u16::from_be_bytes([*value.get(2)?, *value.get(3)?]) ^ (MAGIC_COOKIE >> 16) as u16;
        let mut address = value.get(4..)?.to_vec();
        xor(&mut address, &self.transaction());
        let ip = match (value.get(1)?, address.len()) {
            (1, 4) => IpAddr::from(<[u8; 4]>::try_from(address).unwrap()),
            (2, 16) => IpAddr::from(<[u8; 16]>::try_from(address).unwrap()),
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// Whether the message's FINGERPRINT holds, or `None` if it has none. A FINGERPRINT that is not
    /// the last attribute does not hold (§14.7).
    pub fn fingerprint(&self) -> Option<bool> {
        let attribute = self
            .attributes()
            .find(|attribute| attribute.kind == FINGERPRINT)?;
        let expected = fingerprint_of(&self.bytes[..attribute.offset]).to_be_bytes();
        Some(attribute.offset + 8 == self.bytes.len() && attribute.value == expected)
    }

    /// Whether the message carries a MESSAGE-INTEGRITY made with `key` (§14.5).
    pub fn integrity_holds(&self, key: &[u8]) -> bool {
        let Some(attribute) = self
            .attributes()
            .find(|attribute| attribute.kind == MESSAGE_INTEGRITY)
        else {
            return false;
        };
        let mut mac = hmac(key);
        mac.update(&self.bytes[..2]);
        mac.update(&length_field(attribute.offset + 4 + INTEGRITY_LEN));
        mac.update(&self.bytes[4..attribute.offset]);
        mac.verify_slice(attribute.value).is_ok()
    }
}

/// The key of the long-term credential mechanism (§9.2.2), for credentials that need no SASLprep.
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    Md5::digest(format!("{username}:{realm}:{password}")).into()
}

/// Writes a message one attribute at a time; MESSAGE-INTEGRITY and FINGERPRINT come last.
pub struct Builder {
    bytes: Vec<u8>,
}

impl Builder {
    pub fn new(method: u16, class: Class, transaction: Transaction) -> Self {
        let kind =
            ((method & 0x0F80) << 2) | ((method & 0x0070) << 1) | (method & 0x000F) | class.bits();
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&transaction);
        Builder { bytes }
    }

    /// A response to `request`: the same method and transaction.
    pub fn response(request: &Message, class: Class) -> Self {
        Builder::new(request.method(), class, request.transaction())
    }

    pub fn attribute(mut self, kind: u16, value: &[u8]) -> Self {
        self.bytes.extend_from_slice(&kind.to_be_bytes());
        self.bytes
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.bytes.extend_from_slice(value);
        self.bytes.resize(self.bytes.len().next_multiple_of(4), 0);
        let length = length_field(self.bytes.len());
        self.bytes[2..4].copy_from_slice(&length);
        self
    }

    pub fn xor_address(self, kind: u16, address: SocketAddr) -> Self {
        let (family, mut octets) = match address.ip() {
            IpAddr::V4(ip) => (1, ip.octets().to_vec()),
            IpAddr::V6(ip) => (2, ip.octets().to_vec()),
        };
        xor(&mut octets, &self.bytes[8..HEADER_LEN].try_into().unwrap());
        let mut value = vec![0, family];
        value.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        value.extend_from_slice(&octets);
        self.attribute(kind, &value)
    }

    /// ERROR-CODE (§14.8): `code` such as 420, and a reason phrase for people.
    pub fn error_code(self, code: u16, reason: &str) -> Self {
        let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
        value.extend_from_slice(reason.as_bytes());
        self.attribute(ERROR_CODE, &value)
    }

    pub fn integrity(mut self, key: &[u8]) -> Self {
        let length = length_field(self.bytes.len() + 4 + INTEGRITY_LEN);
        self.bytes[2..4].copy_from_slice(&length);
        let mut mac = hmac(key);
        mac.update(&self.bytes);
        self.attribute(MESSAGE_INTEGRITY, &mac.finalize().into_bytes())
    }

    /// The finished message, ending in a FINGERPRINT.
    pub fn fingerprint(mut self) -> Vec<u8> {
        let length = length_field(self.bytes.len() + 8);
        self.bytes[2..4].copy_from_slice(&length);
        let fingerprint = fingerprint_of(&self.bytes);
        self.attribute(FINGERPRINT, &fingerprint.to_be_bytes())
            .build()
    }

    pub fn build(self) -> Vec<u8> {
        self.bytes
    }
}

pub fn binding_request(transaction: Transaction) -> Vec<u8> {
    Builder::new(BINDING, Class::Request, transaction).build()
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

/// The header's length field for a message that ends at `end`.
fn length_field(end: usize) -> [u8; 2] {
    ((end - HEADER_LEN) as u16).to_be_bytes()
}

fn fingerprint_of(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes) ^ FINGERPRINT_XOR
}

fn hmac(key: &[u8]) -> Hmac<Sha1> {
    Hmac::new_from_slice(key).expect("HMAC takes a key of any length")
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
    use super::attribute::*;
    use super::*;

    /// The sample messages of RFC 5769 §2.1 to §2.4.
    const SAMPLE_REQUEST: &str = "
        0001 0058 2112a442 b7e7a701 bc34d686 fa87dfae
        8022 0010 5354554e 20746573 7420636c 69656e74
        0024 0004 6e0001ff
        8029 0008 932ff9b1 51263b36
        0006 0009 6576746a 3a683676 59202020
        0008 0014 9aeaa70c bfd8cb56 781ef2b5 b2d3f249 c1b571a2
        8028 0004 e57a3bcf";
    const SAMPLE_IPV4_RESPONSE: &str = "
        0101 003c 2112a442 b7e7a701 bc34d686 fa87dfae
        8022 000b 74657374 20766563 746f7220
        0020 0008 0001a147 e112a643
        0008 0014 2b91f599 fd9e90c3 8c7489f9 2af9ba53 f06be7d7
        8028 0004 c07d4c96";
    const SAMPLE_IPV6_RESPONSE: &str = "
        0101 0048 2112a442 b7e7a701 bc34d686 fa87dfae
        8022 000b 74657374 20766563 746f7220
        0020 0014 0002a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9
        0008 0014 a382954e 4be67bf1 1784c97c 8292c275 bfe3ed41
        8028 0004 c8fb0b4c";
    const SAMPLE_LONG_TERM_REQUEST: &str = "
        0001 0060 2112a442 78ad3433 c6ad72c0 29da412e
        0006 0012 e3839ee3 8388e383 aae38383 e382afe3 82b90000
        0015 001c 662f2f34 39396b39 35346436 4f4c3334 6f4c3946 53547679 36347341
        0014 000b 6578616d 706c652e 6f726700
        0008 0014 f6702465 6dd64a3e 02b8e071 2e85c9a2 8ca89666";
    const SAMPLE_PASSWORD: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";
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

    fn sample_long_term_key() -> [u8; 16] {
        // The password after SASLprep, as RFC 5769 §2.4 gives it.
        long_term_key("マトリックス", "example.org", "TheMatrIX")
    }

    #[test]
    fn the_sample_request_passes_its_checks() {
        let bytes = hex(SAMPLE_REQUEST);
        let request = Message::parse(&bytes).unwrap();
        assert_eq!(
            (request.method(), request.class()),
            (BINDING, Class::Request)
        );
        assert_eq!(request.transaction(), SAMPLE);
        assert_eq!(request.attribute(USERNAME), Some(&b"evtj:h6vY"[..]));
        assert_eq!(request.attribute(SOFTWARE), Some(&b"STUN test client"[..]));
        assert_eq!(request.fingerprint(), Some(true));
        assert!(request.integrity_holds(SAMPLE_PASSWORD));
        assert!(!request.integrity_holds(b"not the password"));
    }

    #[test]
    fn the_sample_responses_carry_their_addresses_and_pass_their_checks() {
        for (sample, address) in [
            (SAMPLE_IPV4_RESPONSE, "192.0.2.1:32853"),
            (
                SAMPLE_IPV6_RESPONSE,
                "[2001:db8:1234:5678:11:2233:4455:6677]:32853",
            ),
        ] {
            let bytes = hex(sample);
            let response = Message::parse(&bytes).unwrap();
            assert_eq!(
                (response.method(), response.class()),
                (BINDING, Class::Success)
            );
            assert_eq!(response.mapped_address(), Some(address.parse().unwrap()));
            assert_eq!(response.attribute(SOFTWARE), Some(&b"test vector"[..]));
            assert_eq!(response.fingerprint(), Some(true), "{sample}");
            assert!(response.integrity_holds(SAMPLE_PASSWORD), "{sample}");
        }
    }

    #[test]
    fn the_long_term_sample_request_holds_with_the_long_term_key() {
        let bytes = hex(SAMPLE_LONG_TERM_REQUEST);
        let request = Message::parse(&bytes).unwrap();
        assert!(request.integrity_holds(&sample_long_term_key()));
        assert!(!request.integrity_holds(&long_term_key("マトリックス", "example.org", "wrong")));
        assert_eq!(request.fingerprint(), None);
    }

    #[test]
    fn the_builder_reproduces_the_long_term_sample_request() {
        let transaction = hex("78ad3433 c6ad72c0 29da412e").try_into().unwrap();
        let built = Builder::new(BINDING, Class::Request, transaction)
            .attribute(USERNAME, "マトリックス".as_bytes())
            .attribute(NONCE, b"f//499k954d6OL34oL9FSTvy64sA")
            .attribute(REALM, b"example.org")
            .integrity(&sample_long_term_key())
            .build();
        assert_eq!(built, hex(SAMPLE_LONG_TERM_REQUEST));
    }

    #[test]
    fn the_builder_writes_the_samples_xor_mapped_addresses() {
        let ipv4 = Builder::new(BINDING, Class::Success, SAMPLE)
            .xor_address(XOR_MAPPED_ADDRESS, "192.0.2.1:32853".parse().unwrap())
            .build();
        assert_eq!(ipv4[20..], hex("0020 0008 0001 a147 e112a643"));
        assert_eq!(ipv4[..4], hex("0101 000c"));

        let ipv6 = Builder::new(BINDING, Class::Success, SAMPLE)
            .xor_address(
                XOR_MAPPED_ADDRESS,
                "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                    .parse()
                    .unwrap(),
            )
            .build();
        assert_eq!(
            ipv6[20..],
            hex("0020 0014 0002 a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9")
        );
    }

    #[test]
    fn what_the_builder_signs_and_fingerprints_passes_the_checks() {
        let built = Builder::new(BINDING, Class::Success, SAMPLE)
            .attribute(SOFTWARE, b"outpost")
            .integrity(b"key")
            .fingerprint();
        let message = Message::parse(&built).unwrap();
        assert_eq!(message.fingerprint(), Some(true));
        assert!(message.integrity_holds(b"key"));
    }

    #[test]
    fn a_changed_byte_breaks_the_fingerprint_and_the_integrity() {
        let mut bytes = hex(SAMPLE_REQUEST);
        bytes[24] ^= 1; // in SOFTWARE
        let request = Message::parse(&bytes).unwrap();
        assert_eq!(request.fingerprint(), Some(false));
        assert!(!request.integrity_holds(SAMPLE_PASSWORD));
    }

    #[test]
    fn a_fingerprint_that_is_not_last_does_not_hold() {
        // A correct CRC over everything before it, so only its position can reject it.
        let mut bytes = Builder::new(BINDING, Class::Request, SAMPLE).fingerprint();
        bytes.extend_from_slice(&hex("8022 0004 6c617465"));
        bytes[3] += 8;
        let crc = fingerprint_of(&bytes[..HEADER_LEN]).to_be_bytes();
        bytes[24..28].copy_from_slice(&crc);
        assert_eq!(Message::parse(&bytes).unwrap().fingerprint(), Some(false));
    }

    #[test]
    fn only_the_first_of_two_fingerprints_counts() {
        let mut bytes = Builder::new(BINDING, Class::Request, SAMPLE).fingerprint();
        let second = bytes[20..28].to_vec();
        bytes.extend_from_slice(&second);
        bytes[3] += 8;
        assert_eq!(Message::parse(&bytes).unwrap().fingerprint(), Some(false));
    }

    #[test]
    fn attributes_after_message_integrity_are_ignored_except_fingerprint() {
        let built = Builder::new(BINDING, Class::Request, SAMPLE)
            .attribute(USERNAME, b"user")
            .integrity(b"key")
            .attribute(SOFTWARE, b"late")
            .attribute(MESSAGE_INTEGRITY, &[0; 20])
            .fingerprint();
        let message = Message::parse(&built).unwrap();
        assert_eq!(message.attribute(USERNAME), Some(&b"user"[..]));
        assert_eq!(message.attribute(SOFTWARE), None);
        assert!(message.integrity_holds(b"key"));
        assert_eq!(message.fingerprint(), Some(true));
    }

    #[test]
    fn message_integrity_sha256_counts_after_message_integrity_and_seals_what_follows() {
        // RFC 8489 §14.5 and §14.6: after MESSAGE-INTEGRITY only MESSAGE-INTEGRITY-SHA256 and
        // FINGERPRINT count, and after MESSAGE-INTEGRITY-SHA256 only FINGERPRINT.
        let both = Builder::new(BINDING, Class::Request, SAMPLE)
            .integrity(b"key")
            .attribute(MESSAGE_INTEGRITY_SHA256, &[0; 32])
            .attribute(SOFTWARE, b"late")
            .fingerprint();
        let both = Message::parse(&both).unwrap();
        assert_eq!(both.attribute(MESSAGE_INTEGRITY_SHA256), Some(&[0; 32][..]));
        assert_eq!(both.attribute(SOFTWARE), None);
        assert_eq!(both.fingerprint(), Some(true));

        let alone = Builder::new(BINDING, Class::Request, SAMPLE)
            .attribute(MESSAGE_INTEGRITY_SHA256, &[0; 32])
            .attribute(SOFTWARE, b"late")
            .attribute(MESSAGE_INTEGRITY, &[0; 20])
            .fingerprint();
        let alone = Message::parse(&alone).unwrap();
        assert_eq!(alone.attribute(SOFTWARE), None);
        assert_eq!(alone.attribute(MESSAGE_INTEGRITY), None);
        assert_eq!(alone.fingerprint(), Some(true));
    }

    #[test]
    fn integrity_does_not_hold_without_a_whole_message_integrity() {
        let none = Builder::new(BINDING, Class::Request, SAMPLE).build();
        assert!(!Message::parse(&none).unwrap().integrity_holds(b"key"));

        let mut short = Builder::new(BINDING, Class::Request, SAMPLE)
            .integrity(b"key")
            .build();
        short.truncate(short.len() - 4);
        short[3] -= 4;
        short[22..24].copy_from_slice(&16u16.to_be_bytes());
        assert!(!Message::parse(&short).unwrap().integrity_holds(b"key"));
    }

    #[test]
    fn an_address_whose_family_and_length_disagree_is_no_address() {
        for value in [
            "0002 a147 e112a643",
            "0001 a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9",
            "0000 a147 e112a643",
            "0003 a147 e112a643",
            "0001 a1",
        ] {
            let bytes = Builder::new(BINDING, Class::Success, SAMPLE)
                .attribute(XOR_MAPPED_ADDRESS, &hex(value))
                .build();
            assert_eq!(
                Message::parse(&bytes).unwrap().mapped_address(),
                None,
                "{value}"
            );
        }
    }

    #[test]
    fn methods_and_classes_go_where_section_5_puts_them() {
        for (method, class, kind) in [
            (BINDING, Class::Request, 0x0001),
            (BINDING, Class::Indication, 0x0011),
            (BINDING, Class::Success, 0x0101),
            (BINDING, Class::Error, 0x0111),
            (0x003, Class::Success, 0x0103), // Allocate
            (0x009, Class::Error, 0x0119),   // ChannelBind
            (0xFFF, Class::Error, 0x3FFF),
        ] {
            let bytes = Builder::new(method, class, SAMPLE).build();
            assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), kind);
            let message = Message::parse(&bytes).unwrap();
            assert_eq!((message.method(), message.class()), (method, class));
        }
    }

    #[test]
    fn an_error_code_splits_into_class_and_number() {
        let bytes = Builder::new(BINDING, Class::Error, SAMPLE)
            .error_code(420, "Unknown Attribute")
            .build();
        let message = Message::parse(&bytes).unwrap();
        let value = message.attribute(ERROR_CODE).unwrap();
        assert_eq!(value[..4], [0, 0, 4, 20]);
        assert_eq!(&value[4..], b"Unknown Attribute");
    }

    #[test]
    fn a_binding_request_is_a_bare_header() {
        let bytes = binding_request(SAMPLE);
        assert_eq!(bytes, hex("0001 0000 2112a442 b7e7a701 bc34d686 fa87dfae"));
    }

    #[test]
    fn what_is_not_one_well_formed_message_is_refused() {
        let good = hex(SAMPLE_IPV4_RESPONSE);
        assert!(Message::parse(&good).is_some());

        let mut top_bits = good.clone();
        top_bits[0] |= 0x40;
        let mut cookie = good.clone();
        cookie[4] ^= 1;
        let mut odd_length = good.clone();
        odd_length[3] = 0x3b;
        let mut overlong_attribute = good.clone();
        overlong_attribute[23] = 0x50;
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
        let bytes = hex(SAMPLE_IPV4_RESPONSE);
        assert_eq!(message_length(&bytes[..HEADER_LEN]), Some(80));
        assert_eq!(message_length(&bytes[..HEADER_LEN - 1]), None);
        assert_eq!(message_length(b"\x16\x03\x01 TLS hello, not STUN"), None);
    }
}
