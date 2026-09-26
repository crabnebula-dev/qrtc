//! TURN client (RFC 8656) over UDP, as a sans-I/O state machine.
//!
//! The driver feeds it packets from the TURN server and asks it to wrap
//! outgoing packets for relayed candidates. Permissions are installed on
//! demand, channels are bound after the permission exists, and allocation,
//! permissions and channels are refreshed before they expire.

use super::stun::*;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const RTO: Duration = Duration::from_millis(500);
const MAX_TRIES: u32 = 6;
const PERMISSION_REFRESH: Duration = Duration::from_secs(240);
const CHANNEL_REFRESH: Duration = Duration::from_secs(540);
const SOFTWARE: &str = "tauri-plugin-webrtc";

#[derive(Debug, Clone)]
pub(crate) enum TurnEvent {
    Allocated {
        relay: SocketAddr,
        mapped: Option<SocketAddr>,
    },
    Failed(String),
    Data {
        peer: SocketAddr,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Allocate,
    Refresh(u32),
    Permission(IpAddr),
    ChannelBind(SocketAddr, u16),
}

struct Txn {
    kind: Kind,
    msg: Message,
    tries: u32,
    next: Instant,
    auth_retried: bool,
}

struct Chan {
    num: u16,
    bound: bool,
    refresh_at: Instant,
}

pub(crate) struct TurnClient {
    pub(crate) server: SocketAddr,
    pub(crate) sock_idx: usize,
    username: String,
    password: String,
    realm: Option<String>,
    nonce: Option<String>,
    key: Option<[u8; 16]>,
    pub(crate) relay: Option<SocketAddr>,
    pub(crate) done: bool,
    refresh_at: Option<Instant>,
    txns: HashMap<TransId, Txn>,
    perms: HashMap<IpAddr, Option<Instant>>, // None = requested, Some = refresh time
    chans: HashMap<SocketAddr, Chan>,
    by_num: HashMap<u16, SocketAddr>,
    next_num: u16,
    closing: bool,
}

impl TurnClient {
    pub(crate) fn new(
        server: SocketAddr,
        sock_idx: usize,
        username: String,
        password: String,
    ) -> Self {
        Self {
            server,
            sock_idx,
            username,
            password,
            realm: None,
            nonce: None,
            key: None,
            relay: None,
            done: false,
            refresh_at: None,
            txns: HashMap::new(),
            perms: HashMap::new(),
            chans: HashMap::new(),
            by_num: HashMap::new(),
            next_num: 0x4000,
            closing: false,
        }
    }

    fn with_auth(&self, mut m: Message) -> Message {
        if let (Some(realm), Some(nonce)) = (&self.realm, &self.nonce) {
            m = m
                .attr(ATTR_USERNAME, self.username.as_bytes())
                .attr(ATTR_REALM, realm.as_bytes())
                .attr(ATTR_NONCE, nonce.as_bytes());
        }
        m
    }

    fn encode(&self, m: &Message) -> Vec<u8> {
        self.with_auth(m.clone())
            .encode(self.key.as_ref().map(|k| k.as_slice()), true)
    }

    fn request(&mut self, now: Instant, kind: Kind, msg: Message) -> Vec<u8> {
        let bytes = self.encode(&msg);
        self.txns.insert(
            msg.tid,
            Txn {
                kind,
                msg,
                tries: 1,
                next: now + RTO,
                auth_retried: false,
            },
        );
        bytes
    }

    /// Start the allocation. Returns packets to send to the server.
    pub(crate) fn start(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let msg = Message::new(ALLOCATE_REQUEST)
            .attr(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])
            .attr(ATTR_SOFTWARE, SOFTWARE);
        vec![self.request(now, Kind::Allocate, msg)]
    }

    /// Handle a datagram from the TURN server.
    pub(crate) fn handle(&mut self, now: Instant, buf: &[u8]) -> (Vec<TurnEvent>, Vec<Vec<u8>>) {
        let mut ev = Vec::new();
        let mut out = Vec::new();
        if let Some((num, data)) = decode_channel_data(buf) {
            if let Some(peer) = self.by_num.get(&num) {
                ev.push(TurnEvent::Data {
                    peer: *peer,
                    data: data.to_vec(),
                });
            }
            return (ev, out);
        }
        let Some(msg) = Message::decode(buf) else {
            return (ev, out);
        };
        if msg.typ == DATA_INDICATION {
            if let (Some(peer), Some(data)) =
                (msg.xor_addr(ATTR_XOR_PEER_ADDRESS), msg.get(ATTR_DATA))
            {
                ev.push(TurnEvent::Data {
                    peer,
                    data: data.to_vec(),
                });
            }
            return (ev, out);
        }
        let Some(mut txn) = self.txns.remove(&msg.tid) else {
            return (ev, out);
        };
        match class(msg.typ) {
            Class::Success => {
                if let Some(key) = &self.key {
                    if msg.get(ATTR_MESSAGE_INTEGRITY).is_some() && !Message::verify(buf, key) {
                        log::warn!("TURN {}: response failed integrity check", self.server);
                        return (ev, out);
                    }
                }
                self.on_success(now, txn.kind, &msg, &mut ev, &mut out);
            }
            Class::Error => {
                let code = msg.error_code().unwrap_or(0);
                if (code == 401 || code == 438) && !txn.auth_retried {
                    if let Some(realm) = msg.get_str(ATTR_REALM) {
                        self.key = Some(long_term_key(&self.username, &realm, &self.password));
                        self.realm = Some(realm);
                    }
                    if let Some(nonce) = msg.get_str(ATTR_NONCE) {
                        self.nonce = Some(nonce);
                    }
                    let fresh = Message {
                        tid: new_tid(),
                        ..txn.msg.clone()
                    };
                    txn.msg = fresh;
                    txn.auth_retried = true;
                    txn.tries = 1;
                    txn.next = now + RTO;
                    out.push(self.encode(&txn.msg));
                    self.txns.insert(txn.msg.tid, txn);
                } else {
                    self.on_failure(txn.kind, format!("error {code}"), &mut ev);
                }
            }
            _ => {}
        }
        (ev, out)
    }

    fn on_success(
        &mut self,
        now: Instant,
        kind: Kind,
        msg: &Message,
        ev: &mut Vec<TurnEvent>,
        out: &mut Vec<Vec<u8>>,
    ) {
        match kind {
            Kind::Allocate => {
                let Some(relay) = msg.xor_addr(ATTR_XOR_RELAYED_ADDRESS) else {
                    self.on_failure(kind, "no relayed address".into(), ev);
                    return;
                };
                let lifetime = msg.lifetime().unwrap_or(600).max(120);
                self.refresh_at = Some(now + Duration::from_secs(lifetime as u64 - 60));
                self.relay = Some(relay);
                self.done = true;
                ev.push(TurnEvent::Allocated {
                    relay,
                    mapped: msg.xor_addr(ATTR_XOR_MAPPED_ADDRESS),
                });
            }
            Kind::Refresh(lifetime) => {
                if lifetime > 0 {
                    let l = msg.lifetime().unwrap_or(lifetime).max(120);
                    self.refresh_at = Some(now + Duration::from_secs(l as u64 - 60));
                }
            }
            Kind::Permission(ip) => {
                self.perms.insert(ip, Some(now + PERMISSION_REFRESH));
                // Bind channels for peers on this IP that are waiting.
                let waiting: Vec<SocketAddr> = self
                    .chans
                    .iter()
                    .filter(|(p, c)| p.ip() == ip && !c.bound)
                    .map(|(p, _)| *p)
                    .collect();
                for peer in waiting {
                    out.extend(self.bind_channel(now, peer));
                }
            }
            Kind::ChannelBind(peer, num) => {
                if let Some(c) = self.chans.get_mut(&peer) {
                    if c.num == num {
                        c.bound = true;
                        c.refresh_at = now + CHANNEL_REFRESH;
                    }
                }
            }
        }
    }

    fn on_failure(&mut self, kind: Kind, why: String, ev: &mut Vec<TurnEvent>) {
        match kind {
            Kind::Allocate => {
                self.done = true;
                ev.push(TurnEvent::Failed(format!(
                    "TURN {} allocate: {why}",
                    self.server
                )));
            }
            Kind::Permission(ip) => {
                self.perms.remove(&ip);
            }
            Kind::ChannelBind(peer, _) => {
                if let Some(c) = self.chans.remove(&peer) {
                    self.by_num.remove(&c.num);
                }
            }
            Kind::Refresh(_) => log::debug!("TURN {} refresh failed: {why}", self.server),
        }
    }

    fn bind_channel(&mut self, now: Instant, peer: SocketAddr) -> Vec<Vec<u8>> {
        let num = match self.chans.get(&peer) {
            Some(c) => c.num,
            None => return Vec::new(),
        };
        let msg = Message::new(CHANNEL_BIND_REQUEST).attr(
            ATTR_CHANNEL_NUMBER,
            [(num >> 8) as u8, num as u8, 0, 0].to_vec(),
        );
        let tid = msg.tid;
        let msg = msg.attr(ATTR_XOR_PEER_ADDRESS, encode_xor_addr(peer, &tid));
        vec![self.request(now, Kind::ChannelBind(peer, num), msg)]
    }

    fn create_permission(&mut self, now: Instant, ip: IpAddr) -> Vec<Vec<u8>> {
        self.perms.insert(ip, None);
        let msg = Message::new(CREATE_PERMISSION_REQUEST);
        let tid = msg.tid;
        let msg = msg.attr(
            ATTR_XOR_PEER_ADDRESS,
            encode_xor_addr(SocketAddr::new(ip, 0), &tid),
        );
        vec![self.request(now, Kind::Permission(ip), msg)]
    }

    /// Wrap a datagram from our relayed candidate to `peer`.
    pub(crate) fn send(&mut self, now: Instant, peer: SocketAddr, data: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.relay.is_none() || self.closing {
            return out;
        }
        if !self.perms.contains_key(&peer.ip()) {
            out.extend(self.create_permission(now, peer.ip()));
        }
        if !self.chans.contains_key(&peer) && self.next_num <= 0x7FFF {
            let num = self.next_num;
            self.next_num += 1;
            self.chans.insert(
                peer,
                Chan {
                    num,
                    bound: false,
                    refresh_at: now,
                },
            );
            self.by_num.insert(num, peer);
            if matches!(self.perms.get(&peer.ip()), Some(Some(_))) {
                out.extend(self.bind_channel(now, peer));
            }
        }
        match self.chans.get(&peer) {
            Some(c) if c.bound => out.push(encode_channel_data(c.num, data)),
            _ => {
                let msg = Message::new(SEND_INDICATION);
                let tid = msg.tid;
                let msg = msg
                    .attr(ATTR_XOR_PEER_ADDRESS, encode_xor_addr(peer, &tid))
                    .attr(ATTR_DATA, data.to_vec());
                out.push(msg.encode(None, false));
            }
        }
        out
    }

    /// Retransmit requests and refresh allocation, permissions and channels.
    pub(crate) fn poll(&mut self, now: Instant) -> (Vec<TurnEvent>, Vec<Vec<u8>>) {
        let mut ev = Vec::new();
        let mut out = Vec::new();
        let due: Vec<TransId> = self
            .txns
            .iter()
            .filter(|(_, t)| t.next <= now)
            .map(|(k, _)| *k)
            .collect();
        for tid in due {
            let Some(mut t) = self.txns.remove(&tid) else {
                continue;
            };
            if t.tries >= MAX_TRIES {
                self.on_failure(t.kind, "timeout".into(), &mut ev);
                continue;
            }
            t.tries += 1;
            t.next = now + RTO * (1 << (t.tries - 1)).min(8);
            out.push(self.encode(&t.msg));
            self.txns.insert(tid, t);
        }
        if self.closing {
            return (ev, out);
        }
        if self.refresh_at.map(|r| r <= now).unwrap_or(false) {
            self.refresh_at = None;
            let msg =
                Message::new(REFRESH_REQUEST).attr(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec());
            out.push(self.request(now, Kind::Refresh(600), msg));
        }
        let perms: Vec<IpAddr> = self
            .perms
            .iter()
            .filter(|(_, r)| r.map(|r| r <= now).unwrap_or(false))
            .map(|(ip, _)| *ip)
            .collect();
        for ip in perms {
            out.extend(self.create_permission(now, ip));
        }
        let chans: Vec<SocketAddr> = self
            .chans
            .iter()
            .filter(|(_, c)| c.bound && c.refresh_at <= now)
            .map(|(p, _)| *p)
            .collect();
        for peer in chans {
            if let Some(c) = self.chans.get_mut(&peer) {
                c.refresh_at = now + CHANNEL_REFRESH;
            }
            out.extend(self.bind_channel(now, peer));
        }
        (ev, out)
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let mut d = self.txns.values().map(|t| t.next).min();
        let mut consider = |x: Option<Instant>| {
            if let Some(x) = x {
                d = Some(d.map_or(x, |d| d.min(x)));
            }
        };
        if !self.closing {
            consider(self.refresh_at);
            consider(self.perms.values().filter_map(|r| *r).min());
            consider(
                self.chans
                    .values()
                    .filter(|c| c.bound)
                    .map(|c| c.refresh_at)
                    .min(),
            );
        }
        d
    }

    /// Deallocate (Refresh with lifetime 0). Fire and forget.
    pub(crate) fn close(&mut self) -> Vec<Vec<u8>> {
        if self.relay.is_none() || self.closing {
            return Vec::new();
        }
        self.closing = true;
        self.txns.clear();
        let msg = Message::new(REFRESH_REQUEST).attr(ATTR_LIFETIME, 0u32.to_be_bytes().to_vec());
        vec![self.encode(&msg)]
    }
}
