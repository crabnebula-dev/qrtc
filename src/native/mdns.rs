//! One-shot mDNS resolver for `*.local` ICE candidates (RFC 6762).
//!
//! Browsers replace host candidate IPs with random `<uuid>.local` names and
//! answer multicast A/AAAA queries for them. We send a query and listen on the
//! mDNS group for the answer.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const PORT: u16 = 5353;

fn encode_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]; // id 0, flags 0, 1 question
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&0x0001u16.to_be_bytes()); // IN, multicast response
    q
}

/// Read a (possibly compressed) DNS name starting at `p`. Returns name and the
/// offset after it in the original position.
fn read_name(buf: &[u8], mut p: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *buf.get(p)? as usize;
        if len == 0 {
            p += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *buf.get(p + 1)? as usize;
            end.get_or_insert(p + 2);
            p = ptr;
            continue;
        }
        labels.push(String::from_utf8_lossy(buf.get(p + 1..p + 1 + len)?).into_owned());
        p += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(p)))
}

/// Parse answers (and additional records) for A/AAAA records of `name`.
fn parse_answer(buf: &[u8], name: &str) -> Option<IpAddr> {
    if buf.len() < 12 || buf[2] & 0x80 == 0 {
        return None; // not a response
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let rr = u16::from_be_bytes([buf[6], buf[7]]) as usize
        + u16::from_be_bytes([buf[8], buf[9]]) as usize
        + u16::from_be_bytes([buf[10], buf[11]]) as usize;
    let mut p = 12;
    for _ in 0..qd {
        let (_, np) = read_name(buf, p)?;
        p = np + 4;
    }
    for _ in 0..rr {
        let (n, np) = read_name(buf, p)?;
        let typ = u16::from_be_bytes([*buf.get(np)?, *buf.get(np + 1)?]);
        let rdlen = u16::from_be_bytes([*buf.get(np + 8)?, *buf.get(np + 9)?]) as usize;
        let rdata = buf.get(np + 10..np + 10 + rdlen)?;
        if n.eq_ignore_ascii_case(name.trim_end_matches('.')) {
            match (typ, rdlen) {
                (1, 4) => return Some(IpAddr::from(<[u8; 4]>::try_from(rdata).ok()?)),
                (28, 16) => return Some(IpAddr::from(<[u8; 16]>::try_from(rdata).ok()?)),
                _ => {}
            }
        }
        p = np + 10 + rdlen;
    }
    None
}

fn group_socket() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)).into())?;
    // Join on every IPv4 interface, so answers from any LAN reach us.
    let mut joined = false;
    for a in if_addrs::get_if_addrs().unwrap_or_default() {
        if let IpAddr::V4(ip) = a.ip() {
            if s.join_multicast_v4(&GROUP, &ip).is_ok() {
                joined = true;
            }
        }
    }
    if !joined {
        s.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)?;
    }
    s.set_multicast_loop_v4(true)?;
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}

/// Resolve `name` (e.g. `2d3c...e1.local`) with a few retries.
pub(crate) async fn resolve(name: &str, timeout: Duration) -> Option<IpAddr> {
    let sock = match group_socket() {
        Ok(s) => s,
        Err(e) => {
            log::debug!("mDNS socket: {e}");
            return None;
        }
    };
    let dest = SocketAddr::from((GROUP, PORT));
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    for attempt in 0..3u32 {
        let _ = sock.send_to(&encode_query(name, 1), dest).await;
        let wait = tokio::time::Instant::now() + Duration::from_millis(250 << attempt);
        let until = wait.min(deadline);
        loop {
            match tokio::time::timeout_at(until, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let Some(ip) = parse_answer(&buf[..n], name) {
                        return Some(ip);
                    }
                }
                _ => break,
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compressed_answer() {
        // Response echoing the question, answer name compressed to offset 12.
        let name = "abc-123.local";
        let mut r = encode_query(name, 1);
        r[2] = 0x84; // response, authoritative
        r[7] = 1; // one answer
        r.extend_from_slice(&[0xC0, 12, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 7]);
        assert_eq!(parse_answer(&r, name), Some(IpAddr::from([192, 0, 2, 7])));
        assert_eq!(parse_answer(&r, "other.local"), None);
    }
}
