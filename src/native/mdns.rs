//! mDNS for ICE candidates (RFC 6762).
//!
//! Browsers replace the IP address of each host candidate with a random
//! `<uuid>.local` name and answer multicast A/AAAA queries for it, so the
//! remote side learns the address only when it actually tries to connect, and
//! the signalling server never does. The engine does the same: [`Responder`]
//! answers queries for the names its peer connections register, and
//! [`resolve`] looks up the names remote peers send.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const PORT: u16 = 5353;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
/// Time to live of our answers, in seconds. Browsers use 120.
const TTL: u32 = 120;
/// RFC 6762 section 6: a record is multicast at most once per second.
const MULTICAST_INTERVAL: Duration = Duration::from_secs(1);
/// Unicast answers for one name, at most this often. Bounds what a host on
/// the local network can make the responder send.
const UNICAST_INTERVAL: Duration = Duration::from_millis(50);

/// Whether `name` is an mDNS host name the engine resolves for an ICE
/// candidate: one label of letters, digits and hyphens under `.local`, the
/// shape browsers generate (a UUID). Anything else from a remote peer is
/// ignored, so the resolver cannot be used to send arbitrary multicast
/// queries on the local network.
pub(crate) fn is_candidate_name(name: &str) -> bool {
    let Some(label) = name.trim_end_matches('.').strip_suffix(".local") else {
        return false;
    };
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A fresh `<uuid>.local` name (UUID version 4, from the OS generator).
fn random_name() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("operating system random number generator");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = |r: &[u8]| r.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}.local",
        hex(&b[..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..])
    )
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// A query with one question per type in `qtypes`.
fn encode_query(name: &str, qtypes: &[u16]) -> Vec<u8> {
    let mut q = vec![0, 0, 0, 0, 0, qtypes.len() as u8, 0, 0, 0, 0, 0, 0]; // id 0, flags 0
    for &qtype in qtypes {
        push_name(&mut q, name);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&0x0001u16.to_be_bytes()); // IN, multicast response
    }
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
                (TYPE_A, 4) => return Some(IpAddr::from(<[u8; 4]>::try_from(rdata).ok()?)),
                (TYPE_AAAA, 16) => return Some(IpAddr::from(<[u8; 16]>::try_from(rdata).ok()?)),
                _ => {}
            }
        }
        p = np + 10 + rdlen;
    }
    None
}

/// One question of a query: `(name, qtype, QU bit)`.
type Question = (String, u16, bool);

/// The questions of a query, with the message id.
fn parse_query(buf: &[u8]) -> Option<(u16, Vec<Question>)> {
    if buf.len() < 12 || buf[2] & 0x80 != 0 {
        return None; // not a query
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let mut p = 12;
    let mut out = Vec::new();
    for _ in 0..qd.min(32) {
        let (name, np) = read_name(buf, p)?;
        let qtype = u16::from_be_bytes([*buf.get(np)?, *buf.get(np + 1)?]);
        let qclass = u16::from_be_bytes([*buf.get(np + 2)?, *buf.get(np + 3)?]);
        out.push((name, qtype, qclass & 0x8000 != 0));
        p = np + 4;
    }
    Some((id, out))
}

/// A response with one answer and no question section (RFC 6762 section 6).
/// A legacy unicast response (section 6.7) echoes the query id, has no
/// cache-flush bit and a TTL of at most 10 seconds.
fn encode_answer(id: u16, name: &str, ip: IpAddr, legacy: bool) -> Vec<u8> {
    let mut r = Vec::with_capacity(64);
    r.extend_from_slice(&id.to_be_bytes());
    r.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
    r.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // no question, one answer
    push_name(&mut r, name);
    let (typ, rdata): (u16, Vec<u8>) = match ip {
        IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
        IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
    };
    r.extend_from_slice(&typ.to_be_bytes());
    let class: u16 = if legacy { 0x0001 } else { 0x8001 };
    r.extend_from_slice(&class.to_be_bytes());
    let ttl = if legacy { 10 } else { TTL };
    r.extend_from_slice(&ttl.to_be_bytes());
    r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    r.extend_from_slice(&rdata);
    r
}

fn v4_interfaces() -> Vec<Ipv4Addr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .iter()
        .filter_map(|a| match a.ip() {
            IpAddr::V4(ip) if !a.is_loopback() => Some(ip),
            _ => None,
        })
        .collect()
}

fn v6_interface_indexes() -> Vec<u32> {
    let mut v: Vec<u32> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .iter()
        .filter(|a| a.ip().is_ipv6() && !a.is_loopback())
        .filter_map(|a| a.index)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// The IPv4 group socket: bound to port 5353 on every address, joined to the
/// group on every interface, so queries and answers from any LAN reach us.
fn socket_v4() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)).into())?;
    let mut joined = false;
    for ip in v4_interfaces() {
        if s.join_multicast_v4(&GROUP_V4, &ip).is_ok() {
            joined = true;
        }
    }
    if !joined {
        s.join_multicast_v4(&GROUP_V4, &Ipv4Addr::UNSPECIFIED)?;
    }
    s.set_multicast_loop_v4(true)?;
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}

/// The IPv6 group socket, joined to ff02::fb on every interface.
fn socket_v6() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(true)?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, PORT)).into())?;
    let mut joined = false;
    for idx in v6_interface_indexes() {
        if s.join_multicast_v6(&GROUP_V6, idx).is_ok() {
            joined = true;
        }
    }
    if !joined {
        s.join_multicast_v6(&GROUP_V6, 0)?;
    }
    s.set_multicast_loop_v6(true)?;
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}

/// Multicast `pkt` on every interface of the socket's family.
async fn send_multicast(sock: &UdpSocket, pkt: &[u8]) {
    let s = socket2::SockRef::from(sock);
    let mut sent = false;
    if sock.local_addr().map(|a| a.is_ipv4()).unwrap_or(true) {
        let dest = SocketAddr::from((GROUP_V4, PORT));
        for ip in v4_interfaces() {
            if s.set_multicast_if_v4(&ip).is_ok() && sock.send_to(pkt, dest).await.is_ok() {
                sent = true;
            }
        }
        if !sent {
            let _ = sock.send_to(pkt, dest).await;
        }
    } else {
        for idx in v6_interface_indexes() {
            let dest = SocketAddr::V6(SocketAddrV6::new(GROUP_V6, PORT, 0, idx));
            if s.set_multicast_if_v6(idx).is_ok() && sock.send_to(pkt, dest).await.is_ok() {
                sent = true;
            }
        }
        if !sent {
            let _ = sock.send_to(pkt, SocketAddr::from((GROUP_V6, PORT))).await;
        }
    }
}

/// Resolve `name` (e.g. `2d3c...e1.local`) with a few retries.
pub(crate) async fn resolve(name: &str, timeout: Duration) -> Option<IpAddr> {
    let sock = match socket_v4() {
        Ok(s) => s,
        Err(e) => {
            log::debug!("mDNS socket: {e}");
            return None;
        }
    };
    let query = encode_query(name, &[TYPE_A, TYPE_AAAA]);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    for attempt in 0..3u32 {
        send_multicast(&sock, &query).await;
        let wait = tokio::time::Instant::now() + Duration::from_millis(250 << attempt);
        let until = wait.min(deadline);
        while let Ok(Ok((n, _))) = tokio::time::timeout_at(until, sock.recv_from(&mut buf)).await {
            if let Some(ip) = parse_answer(&buf[..n], name) {
                return Some(ip);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    None
}

/// Answers A/AAAA queries for the names registered by peer connections.
///
/// One responder per engine. It listens on the IPv4 and IPv6 mDNS groups;
/// when neither socket can be opened the engine falls back to host candidates
/// with plain addresses ([`Responder::register`] returns `None`).
pub(crate) struct Responder {
    /// Name (lower case, no trailing dot) to the address it stands for.
    names: Mutex<HashMap<String, IpAddr>>,
    /// Last multicast and last unicast answer per name, for rate limiting.
    sent: Mutex<HashMap<(String, bool), Instant>>,
    running: AtomicBool,
}

impl Responder {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            names: Mutex::new(HashMap::new()),
            sent: Mutex::new(HashMap::new()),
            running: AtomicBool::new(false),
        })
    }

    /// Open the group sockets and answer queries on `rt` from now on.
    pub(crate) fn start(self: &Arc<Self>, rt: &tokio::runtime::Runtime) {
        // tokio sockets need the runtime's reactor.
        let _guard = rt.enter();
        let sockets: Vec<UdpSocket> = [socket_v4(), socket_v6()]
            .into_iter()
            .filter_map(|r| match r {
                Ok(s) => Some(s),
                Err(e) => {
                    log::debug!("mDNS responder socket: {e}");
                    None
                }
            })
            .collect();
        if sockets.is_empty() {
            log::warn!("mDNS responder unavailable: host candidates carry plain addresses");
            return;
        }
        self.running.store(true, Ordering::SeqCst);
        for sock in sockets {
            let me = self.clone();
            rt.spawn(async move { me.serve(sock).await });
        }
    }

    /// Register `ip` under a fresh name and return the name, or `None` when
    /// the responder is not running.
    pub(crate) fn register(&self, ip: IpAddr) -> Option<String> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }
        let name = random_name();
        self.names.lock().unwrap().insert(name.clone(), ip);
        Some(name)
    }

    /// The address behind a name this engine registered itself, so peers in
    /// the same process resolve each other without multicast.
    pub(crate) fn lookup(&self, name: &str) -> Option<IpAddr> {
        let key = name.trim_end_matches('.').to_ascii_lowercase();
        self.names.lock().unwrap().get(&key).copied()
    }

    pub(crate) fn unregister(&self, name: &str) {
        self.names.lock().unwrap().remove(name);
        let mut sent = self.sent.lock().unwrap();
        sent.retain(|(n, _), _| n != name);
    }

    /// Whether an answer for `name` may go out now, and record that it did.
    fn allow(&self, name: &str, unicast: bool, now: Instant) -> bool {
        let interval = if unicast {
            UNICAST_INTERVAL
        } else {
            MULTICAST_INTERVAL
        };
        let mut sent = self.sent.lock().unwrap();
        let key = (name.to_string(), unicast);
        if sent.get(&key).is_some_and(|t| now < *t + interval) {
            return false;
        }
        sent.insert(key, now);
        true
    }

    async fn serve(self: Arc<Self>, sock: UdpSocket) {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    log::trace!("mDNS recv: {e}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let Some((id, questions)) = parse_query(&buf[..n]) else {
                continue;
            };
            // RFC 6762 section 6.7: a query from another port is a legacy
            // unicast query, answered to its source.
            let legacy = from.port() != PORT;
            let now = Instant::now();
            for (qname, qtype, qu) in questions {
                let key = qname.to_ascii_lowercase();
                let Some(ip) = self.names.lock().unwrap().get(&key).copied() else {
                    continue;
                };
                let wanted = match ip {
                    IpAddr::V4(_) => qtype == TYPE_A || qtype == TYPE_ANY,
                    IpAddr::V6(_) => qtype == TYPE_AAAA || qtype == TYPE_ANY,
                };
                if !wanted {
                    continue;
                }
                let unicast = legacy || qu;
                if !self.allow(&key, unicast, now) {
                    continue;
                }
                let pkt = encode_answer(if legacy { id } else { 0 }, &key, ip, legacy);
                if unicast {
                    let _ = sock.send_to(&pkt, from).await;
                } else {
                    send_multicast(&sock, &pkt).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compressed_answer() {
        // Response echoing the question, answer name compressed to offset 12.
        let name = "abc-123.local";
        let mut r = encode_query(name, &[TYPE_A]);
        r[2] = 0x84; // response, authoritative
        r[7] = 1; // one answer
        r.extend_from_slice(&[0xC0, 12, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 7]);
        assert_eq!(parse_answer(&r, name), Some(IpAddr::from([192, 0, 2, 7])));
        assert_eq!(parse_answer(&r, "other.local"), None);
    }

    #[test]
    fn query_and_answer_roundtrip() {
        let name = random_name();
        assert!(is_candidate_name(&name));
        assert_eq!(name.len(), 36 + 6);
        let q = encode_query(&name, &[TYPE_A, TYPE_AAAA]);
        let (id, questions) = parse_query(&q).unwrap();
        assert_eq!(id, 0);
        assert_eq!(questions.len(), 2);
        assert_eq!(questions[0], (name.clone(), TYPE_A, false));
        assert_eq!(questions[1], (name.clone(), TYPE_AAAA, false));
        // A response is not a query, and vice versa.
        let v4: IpAddr = "192.0.2.9".parse().unwrap();
        let a = encode_answer(0, &name, v4, false);
        assert!(parse_query(&a).is_none());
        assert_eq!(parse_answer(&a, &name), Some(v4));
        assert_eq!(parse_answer(&a, &name.to_ascii_uppercase()), Some(v4));
        assert_eq!(parse_answer(&q, &name), None);
        // Cache-flush bit and TTL on multicast answers; legacy unicast without.
        assert_eq!(&a[a.len() - 12..a.len() - 10], &[0x80, 0x01]);
        assert_eq!(&a[a.len() - 10..a.len() - 6], &[0, 0, 0, 120]);
        let v6: IpAddr = "2001:db8::7".parse().unwrap();
        let legacy = encode_answer(0x1234, &name, v6, true);
        assert_eq!(&legacy[..2], &[0x12, 0x34]);
        assert_eq!(parse_answer(&legacy, &name), Some(v6));
        let n = legacy.len();
        assert_eq!(&legacy[n - 24..n - 22], &[0x00, 0x01]);
        assert_eq!(&legacy[n - 22..n - 18], &[0, 0, 0, 10]);
    }

    #[test]
    fn candidate_names() {
        assert!(is_candidate_name(
            "6e9f6a4e-3d2b-4c1a-9f0e-2b7c8d9e0f1a.local"
        ));
        assert!(is_candidate_name("abc-123.local."));
        assert!(!is_candidate_name(".local"));
        assert!(!is_candidate_name("host.example.local"));
        assert!(!is_candidate_name("a b.local"));
        assert!(!is_candidate_name(&format!("{}.local", "x".repeat(64))));
        assert!(!is_candidate_name("printer.local.example.org"));
    }

    #[test]
    fn responder_registry_and_rate_limit() {
        let r = Responder::new();
        // Not running: no name, so the driver keeps plain addresses.
        assert!(r.register("192.0.2.1".parse().unwrap()).is_none());
        r.running.store(true, Ordering::SeqCst);
        let name = r.register("192.0.2.1".parse().unwrap()).unwrap();
        assert!(is_candidate_name(&name));
        let now = Instant::now();
        assert!(r.allow(&name, false, now));
        assert!(!r.allow(&name, false, now + Duration::from_millis(500)));
        assert!(r.allow(&name, false, now + MULTICAST_INTERVAL));
        assert!(r.allow(&name, true, now));
        assert!(!r.allow(&name, true, now + Duration::from_millis(10)));
        r.unregister(&name);
        assert!(r.names.lock().unwrap().is_empty());
        assert!(r.sent.lock().unwrap().is_empty());
    }
}
