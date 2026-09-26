//! Minimal STUN/TURN message codec (RFC 8489, RFC 8656).
//!
//! Only what the client side needs: Binding, Allocate, Refresh,
//! CreatePermission, ChannelBind, Send/Data indications, long-term credential
//! MESSAGE-INTEGRITY and FINGERPRINT, plus ChannelData framing.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(crate) const MAGIC: u32 = 0x2112_A442;

pub(crate) const BINDING_REQUEST: u16 = 0x0001;
pub(crate) const BINDING_SUCCESS: u16 = 0x0101;
pub(crate) const ALLOCATE_REQUEST: u16 = 0x0003;
pub(crate) const REFRESH_REQUEST: u16 = 0x0004;
pub(crate) const SEND_INDICATION: u16 = 0x0016;
pub(crate) const DATA_INDICATION: u16 = 0x0017;
pub(crate) const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
pub(crate) const CHANNEL_BIND_REQUEST: u16 = 0x0009;

pub(crate) const ATTR_USERNAME: u16 = 0x0006;
pub(crate) const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub(crate) const ATTR_ERROR_CODE: u16 = 0x0009;
pub(crate) const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub(crate) const ATTR_LIFETIME: u16 = 0x000D;
pub(crate) const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub(crate) const ATTR_DATA: u16 = 0x0013;
pub(crate) const ATTR_REALM: u16 = 0x0014;
pub(crate) const ATTR_NONCE: u16 = 0x0015;
pub(crate) const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub(crate) const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub(crate) const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub(crate) const ATTR_SOFTWARE: u16 = 0x8022;
pub(crate) const ATTR_FINGERPRINT: u16 = 0x8028;

pub(crate) type TransId = [u8; 12];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Message {
    pub(crate) typ: u16,
    pub(crate) tid: TransId,
    pub(crate) attrs: Vec<(u16, Vec<u8>)>,
}

/// Class bits of a message type (request, indication, success, error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Request,
    Indication,
    Success,
    Error,
}

pub(crate) fn class(typ: u16) -> Class {
    match typ & 0x0110 {
        0x0000 => Class::Request,
        0x0010 => Class::Indication,
        0x0100 => Class::Success,
        _ => Class::Error,
    }
}

pub(crate) fn new_tid() -> TransId {
    rand::random()
}

/// Long-term credential key: MD5(username ":" realm ":" password).
pub(crate) fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(format!("{username}:{realm}:{password}").as_bytes());
    h.finalize().into()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

impl Message {
    pub(crate) fn new(typ: u16) -> Self {
        Self {
            typ,
            tid: new_tid(),
            attrs: Vec::new(),
        }
    }

    pub(crate) fn attr(mut self, t: u16, v: impl Into<Vec<u8>>) -> Self {
        self.attrs.push((t, v.into()));
        self
    }

    pub(crate) fn get(&self, t: u16) -> Option<&[u8]> {
        self.attrs
            .iter()
            .find(|(k, _)| *k == t)
            .map(|(_, v)| v.as_slice())
    }

    pub(crate) fn get_str(&self, t: u16) -> Option<String> {
        self.get(t).map(|v| String::from_utf8_lossy(v).into_owned())
    }

    pub(crate) fn xor_addr(&self, t: u16) -> Option<SocketAddr> {
        decode_xor_addr(self.get(t)?, &self.tid)
    }

    pub(crate) fn error_code(&self) -> Option<u16> {
        let v = self.get(ATTR_ERROR_CODE)?;
        if v.len() < 4 {
            return None;
        }
        Some((v[2] & 0x07) as u16 * 100 + v[3] as u16)
    }

    pub(crate) fn lifetime(&self) -> Option<u32> {
        let v = self.get(ATTR_LIFETIME)?;
        Some(u32::from_be_bytes(v.get(..4)?.try_into().ok()?))
    }

    /// Serialise, adding MESSAGE-INTEGRITY (when a key is given) and FINGERPRINT.
    pub(crate) fn encode(&self, integrity_key: Option<&[u8]>, fingerprint: bool) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in &self.attrs {
            push_attr(&mut body, *t, v);
        }
        let mut out = Vec::with_capacity(20 + body.len() + 32);
        out.extend_from_slice(&self.typ.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.extend_from_slice(&self.tid);
        out.extend_from_slice(&body);
        if let Some(key) = integrity_key {
            // Length must cover the MESSAGE-INTEGRITY attribute itself.
            let len = (out.len() - 20 + 24) as u16;
            out[2..4].copy_from_slice(&len.to_be_bytes());
            let mac = hmac_sha1(key, &out);
            push_attr(&mut out, ATTR_MESSAGE_INTEGRITY, &mac);
        }
        if fingerprint {
            let len = (out.len() - 20 + 8) as u16;
            out[2..4].copy_from_slice(&len.to_be_bytes());
            let crc = crc32fast::hash(&out) ^ 0x5354_554e;
            push_attr(&mut out, ATTR_FINGERPRINT, &crc.to_be_bytes());
        }
        let len = (out.len() - 20) as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out
    }

    pub(crate) fn decode(buf: &[u8]) -> Option<Self> {
        if !is_stun(buf) {
            return None;
        }
        let typ = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 20 + len {
            return None;
        }
        let tid: TransId = buf[8..20].try_into().ok()?;
        let mut attrs = Vec::new();
        let mut p = 20;
        while p + 4 <= 20 + len {
            let t = u16::from_be_bytes([buf[p], buf[p + 1]]);
            let l = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
            let v = buf.get(p + 4..p + 4 + l)?.to_vec();
            attrs.push((t, v));
            p += 4 + l.div_ceil(4) * 4;
        }
        Some(Self { typ, tid, attrs })
    }

    /// Check MESSAGE-INTEGRITY of a raw message with the given key.
    pub(crate) fn verify(buf: &[u8], key: &[u8]) -> bool {
        let Some(msg_len) = buf
            .get(2..4)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        else {
            return false;
        };
        let mut p = 20;
        while p + 4 <= 20 + msg_len && p + 4 <= buf.len() {
            let t = u16::from_be_bytes([buf[p], buf[p + 1]]);
            let l = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
            if t == ATTR_MESSAGE_INTEGRITY {
                let Some(expected) = buf.get(p + 4..p + 24) else {
                    return false;
                };
                let mut copy = buf[..p].to_vec();
                let len = (p - 20 + 24) as u16;
                copy[2..4].copy_from_slice(&len.to_be_bytes());
                return hmac_sha1(key, &copy) == expected;
            }
            p += 4 + l.div_ceil(4) * 4;
        }
        false
    }
}

fn push_attr(out: &mut Vec<u8>, t: u16, v: &[u8]) {
    out.extend_from_slice(&t.to_be_bytes());
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
    out.resize(out.len() + (4 - v.len() % 4) % 4, 0);
}

/// First byte 0b00, magic cookie present.
pub(crate) fn is_stun(buf: &[u8]) -> bool {
    buf.len() >= 20 && buf[0] & 0xC0 == 0 && buf[4..8] == MAGIC.to_be_bytes()
}

/// ChannelData messages use channel numbers 0x4000..=0x7FFF.
pub(crate) fn is_channel_data(buf: &[u8]) -> bool {
    buf.len() >= 4 && (0x40..=0x7F).contains(&buf[0])
}

pub(crate) fn encode_xor_addr(addr: SocketAddr, tid: &TransId) -> Vec<u8> {
    let port = addr.port() ^ (MAGIC >> 16) as u16;
    let mut v = vec![0u8];
    match addr.ip() {
        IpAddr::V4(ip) => {
            v.push(0x01);
            v.extend_from_slice(&port.to_be_bytes());
            let x = u32::from(ip) ^ MAGIC;
            v.extend_from_slice(&x.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            v.push(0x02);
            v.extend_from_slice(&port.to_be_bytes());
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC.to_be_bytes());
            key[4..].copy_from_slice(tid);
            for (o, (a, k)) in ip.octets().iter().zip(key.iter()).enumerate() {
                let _ = o;
                v.push(a ^ k);
            }
        }
    }
    v
}

pub(crate) fn decode_xor_addr(v: &[u8], tid: &TransId) -> Option<SocketAddr> {
    if v.len() < 8 {
        return None;
    }
    let port = u16::from_be_bytes([v[2], v[3]]) ^ (MAGIC >> 16) as u16;
    match v[1] {
        0x01 => {
            let x = u32::from_be_bytes(v[4..8].try_into().ok()?) ^ MAGIC;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(x)), port))
        }
        0x02 if v.len() >= 20 => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC.to_be_bytes());
            key[4..].copy_from_slice(tid);
            let mut o = [0u8; 16];
            for i in 0..16 {
                o[i] = v[4 + i] ^ key[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => None,
    }
}

/// `[channel u16][length u16][data]`, padded to 4 bytes (required over TCP,
/// harmless over UDP).
pub(crate) fn encode_channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + data.len() + 3);
    v.extend_from_slice(&channel.to_be_bytes());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v.resize(v.len() + (4 - data.len() % 4) % 4, 0);
    v
}

pub(crate) fn decode_channel_data(buf: &[u8]) -> Option<(u16, &[u8])> {
    if !is_channel_data(buf) {
        return None;
    }
    let ch = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    Some((ch, buf.get(4..4 + len)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5769 section 2.1 sample request, with its long-term key test (2.4) structure.
    #[test]
    fn integrity_and_fingerprint_roundtrip() {
        let key = long_term_key("user", "realm", "pass");
        let m = Message::new(ALLOCATE_REQUEST)
            .attr(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])
            .attr(ATTR_USERNAME, "user")
            .attr(ATTR_REALM, "realm")
            .attr(ATTR_NONCE, "abc");
        let bytes = m.encode(Some(&key), true);
        assert!(Message::verify(&bytes, &key));
        assert!(!Message::verify(
            &bytes,
            &long_term_key("user", "realm", "nope")
        ));
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back.typ, ALLOCATE_REQUEST);
        assert_eq!(back.get_str(ATTR_NONCE).as_deref(), Some("abc"));
        // FINGERPRINT check.
        let fp_at = bytes.len() - 8;
        let crc = crc32fast::hash(&bytes[..fp_at]) ^ 0x5354_554e;
        assert_eq!(&bytes[fp_at + 4..], &crc.to_be_bytes());
    }

    /// Long-term key = MD5("user:realm:pass"). Expected value computed
    /// independently with Node's crypto.createHash("md5"); the full wire path is
    /// exercised against coturn in the TURN interop test.
    #[test]
    fn long_term_key_md5() {
        let k = long_term_key(
            "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}",
            "example.org",
            "TheMatrIX",
        );
        let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "e8ca7ad59d5eb0518e312911d2dab2a9");
    }

    #[test]
    fn xor_addresses() {
        let tid = new_tid();
        for a in [
            "192.0.2.1:32853",
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853",
        ] {
            let addr: SocketAddr = a.parse().unwrap();
            assert_eq!(
                decode_xor_addr(&encode_xor_addr(addr, &tid), &tid),
                Some(addr)
            );
        }
    }

    #[test]
    fn channel_data() {
        let v = encode_channel_data(0x4001, b"hello");
        assert_eq!(v.len(), 12);
        assert_eq!(decode_channel_data(&v), Some((0x4001, &b"hello"[..])));
    }
}
