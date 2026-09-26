//! The per-connection driver: owns the `Rtc`, sockets, JSEP state and data
//! channel queues. Every mutation of the `Rtc` is followed by [`Driver::drain`].

use super::net::{bind_host_sockets, HostSocket};
use super::jsep;
use super::stun::{self, Message, TransId};
use super::turn::{TurnClient, TurnEvent};
use super::{ChannelShared, Cmd, Shared};
use crate::*;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::net::{Protocol, Receive};
use str0m::stats::PeerStats;
use str0m::format::Codec;
use str0m::media::{Frequency, KeyframeRequestKind, MediaKind, MediaTime, Mid};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};
use std::collections::BTreeMap;
use tokio::sync::mpsc;

/// A STUN or TURN server after DNS resolution.
#[derive(Debug, Clone)]
pub(crate) enum IceServerAddr {
    Stun(SocketAddr),
    Turn { addr: SocketAddr, username: String, password: String },
}

/// Results of background work (DNS, mDNS) delivered back to the driver.
pub(crate) enum Aux {
    Servers(Vec<IceServerAddr>),
    RemoteCandidate(String),
}

struct StunTxn {
    server: SocketAddr,
    sock_idx: usize,
    msg: Vec<u8>,
    tries: u32,
    next: Instant,
}

/// Parse W3C ICE server URLs into resolvable targets. TURN over TCP and TLS
/// are skipped for now and reported in the log.
fn parse_ice_url(url: &str) -> Option<(bool, String, u16)> {
    let (scheme, rest) = url.split_once(':')?;
    let rest = rest.trim_start_matches("//");
    let (hostport, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (is_turn, default_port) = match scheme {
        "stun" => (false, 3478),
        "turn" => (true, 3478),
        "stuns" | "turns" => {
            log::info!("ICE server {url}: TLS transport not supported yet, skipping");
            return None;
        }
        _ => return None,
    };
    if is_turn && query.contains("transport=tcp") {
        log::info!("ICE server {url}: TCP transport not supported yet, skipping");
        return None;
    }
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (h, p) = h.split_once(']')?;
        (h.to_string(), p.trim_start_matches(':').parse().unwrap_or(default_port))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (hostport.to_string(), default_port),
        }
    };
    Some((is_turn, host, port))
}

pub(crate) async fn resolve_ice_servers(config: RtcConfiguration) -> Vec<IceServerAddr> {
    let mut out = Vec::new();
    for s in &config.ice_servers {
        for url in &s.urls {
            let Some((is_turn, host, port)) = parse_ice_url(url) else { continue };
            let lookup = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((host.as_str(), port))).await;
            let addrs: Vec<SocketAddr> = match lookup {
                Ok(Ok(a)) => a.collect(),
                _ => {
                    log::info!("ICE server {url}: DNS lookup failed");
                    continue;
                }
            };
            for addr in addrs.into_iter().take(2) {
                out.push(if is_turn {
                    IceServerAddr::Turn {
                        addr,
                        username: s.username.clone().unwrap_or_default(),
                        password: s.credential.clone().unwrap_or_default(),
                    }
                } else {
                    IceServerAddr::Stun(addr)
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sig {
    Stable,
    HaveLocalOffer,
    HaveRemoteOffer,
}

fn s_kind(k: TrackKind) -> MediaKind {
    match k {
        TrackKind::Audio => MediaKind::Audio,
        TrackKind::Video => MediaKind::Video,
    }
}

fn s_dir(d: Direction) -> str0m::media::Direction {
    use str0m::media::Direction as S;
    match d {
        Direction::Sendrecv => S::SendRecv,
        Direction::Sendonly => S::SendOnly,
        Direction::Recvonly => S::RecvOnly,
        Direction::Inactive | Direction::Stopped => S::Inactive,
    }
}

fn codec_name(c: Codec) -> Option<CodecName> {
    Some(match c {
        Codec::Opus => CodecName::Opus,
        Codec::Vp8 => CodecName::Vp8,
        Codec::Vp9 => CodecName::Vp9,
        Codec::H264 => CodecName::H264,
        Codec::Av1 => CodecName::Av1,
        _ => return None,
    })
}

fn same_codec(c: Codec, n: CodecName) -> bool {
    codec_name(c) == Some(n)
}

/// One transceiver as the JSEP layer sees it.
struct Tx {
    spec: TransceiverSpec,
    /// Negotiated (or pending, see `mid_pending`) mid.
    mid: Option<String>,
    /// The mid came from an offer that is not answered yet (rollback-able).
    mid_pending: bool,
    /// Mid allocated in a created-but-not-set local offer.
    offered_mid: Option<String>,
    offered_direction: Option<Direction>,
    negotiated_direction: Option<Direction>,
    current_direction: Option<Direction>,
    remote_dir: Option<Direction>,
    remote_streams: Vec<String>,
    remote_track: Option<String>,
    created_by_remote: bool,
    stop_sent: bool,
    last_kf_req: Option<Instant>,
}

impl Tx {
    fn new(spec: TransceiverSpec) -> Self {
        Tx {
            spec,
            mid: None,
            mid_pending: false,
            offered_mid: None,
            offered_direction: None,
            negotiated_direction: None,
            current_direction: None,
            remote_dir: None,
            remote_streams: Vec::new(),
            remote_track: None,
            created_by_remote: false,
            stop_sent: false,
            last_kf_req: None,
        }
    }
    fn stopped(&self) -> bool {
        self.spec.stopped || self.spec.direction == Direction::Stopped
    }
    fn set_remote(&mut self, sec: &jsep::Section) {
        self.remote_dir = Some(if sec.port_zero { Direction::Inactive } else { sec.direction });
        self.remote_streams = sec.stream_ids();
        self.remote_track = sec.track_id();
    }
    fn state(&self) -> TransceiverState {
        TransceiverState {
            id: self.spec.id,
            kind: self.spec.kind,
            mid: self.mid.clone(),
            direction: self.spec.direction,
            current_direction: self.current_direction,
            remote_direction: self.remote_dir,
            remote_stream_ids: self.remote_streams.clone(),
            remote_track_id: self.remote_track.clone(),
            created_by_remote: self.created_by_remote,
            sender_track_id: self.spec.sender_track_id.clone(),
            stopped: self.stopped() || self.current_direction == Some(Direction::Stopped),
        }
    }
}

struct Chan {
    config: ChannelConfig,
    /// str0m channel id, once the channel was added to a session change.
    id: Option<ChannelId>,
    /// True once the change creating it was applied (answered or direct).
    confirmed: bool,
    open: bool,
    closed: bool,
    threshold: u64,
    queue: VecDeque<(bool, Vec<u8>)>,
    queued_bytes: u64,
}

pub(crate) struct Driver {
    aux_tx: mpsc::UnboundedSender<Aux>,
    aux_rx: Option<mpsc::UnboundedReceiver<Aux>>,
    config: RtcConfiguration,
    relay_only: bool,
    turns: Vec<TurnClient>,
    stun_txns: std::collections::HashMap<TransId, StunTxn>,
    gathered: Vec<Candidate>,
    resolving: bool,
    gathering_complete: bool,
    rtc: Rtc,
    events: EventSink,
    shared: Arc<Shared>,
    sockets: Vec<HostSocket>,
    host_candidates: Vec<Candidate>,
    sig: Sig,
    created_offer: Option<(String, SdpPendingOffer)>,
    local_offer: Option<(String, SdpPendingOffer)>,
    answer: Option<String>,
    local_sdp: Option<String>,
    app_negotiated: bool,
    chans: HashMap<DcHandle, Chan>,
    by_id: HashMap<ChannelId, DcHandle>,
    next_handle: DcHandle,
    gathering_started: bool,
    ice_state: &'static str,
    conn_state: &'static str,
    dtls_connected: bool,
    stats: Option<PeerStats>,
    timeout: Instant,
    closed: bool,
    /// Channels to flush after the current mutation. Flushing from inside
    /// `drain` would recurse (flush -> drain -> buffered-low -> flush ...).
    pending_flush: Vec<DcHandle>,
    /// Channels whose buffered-low event is due to the JS side this cycle.
    pending_low: Vec<DcHandle>,
    txs: BTreeMap<TxId, Tx>,
    next_remote_tx: TxId,
    /// Remote offer set but not yet applied to str0m (applied in createAnswer).
    pending_remote: Option<String>,
    /// str0m's answer to `pending_remote`, before our rewrite.
    raw_answer: Option<String>,
    buffered_candidates: Vec<String>,
    ice_restart: bool,
}

fn norm(sdp: &str) -> String {
    sdp.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

fn has_app(sdp: &str) -> bool {
    sdp.lines().any(|l| l.starts_with("m=application"))
}

fn op<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::Operation(format!("{what}: {e}"))
}

impl Driver {
    pub(crate) fn new(config: RtcConfiguration, events: EventSink, shared: Arc<Shared>) -> Result<Self> {
        let now = Instant::now();
        let relay_only = config.ice_transport_policy.as_deref() == Some("relay");
        // Offer what the page can encode and decode: Opus (engine) and VP8
        // (WebCodecs, always present with WebKitGTK via gst-plugins-good).
        let rtc = RtcConfig::new()
            .clear_codecs()
            .enable_opus(true, false)
            .enable_vp8(true)
            .set_stats_interval(Some(Duration::from_secs(1)))
            .build(now);
        let sockets = bind_host_sockets().map_err(op("bind sockets"))?;
        if sockets.is_empty() {
            return Err(Error::Operation("no usable network interface".into()));
        }
        let (aux_tx, aux_rx) = mpsc::unbounded_channel();
        let mut d = Driver {
            aux_tx,
            aux_rx: Some(aux_rx),
            resolving: !config.ice_servers.is_empty(),
            config,
            relay_only,
            turns: Vec::new(),
            stun_txns: HashMap::new(),
            gathered: Vec::new(),
            gathering_complete: false,
            rtc,
            events,
            shared,
            sockets,
            host_candidates: Vec::new(),
            sig: Sig::Stable,
            created_offer: None,
            local_offer: None,
            answer: None,
            local_sdp: None,
            app_negotiated: false,
            chans: HashMap::new(),
            by_id: HashMap::new(),
            next_handle: 1,
            gathering_started: false,
            ice_state: "new",
            conn_state: "new",
            dtls_connected: false,
            stats: None,
            timeout: now,
            closed: false,
            pending_flush: Vec::new(),
            pending_low: Vec::new(),
            txs: BTreeMap::new(),
            next_remote_tx: REMOTE_TX_BASE,
            pending_remote: None,
            raw_answer: None,
            buffered_candidates: Vec::new(),
            ice_restart: false,
        };
        for s in d.sockets.iter().filter(|_| !relay_only) {
            match Candidate::host(s.local, "udp") {
                Ok(c) => {
                    if let Some(c) = d.rtc.add_local_candidate(c) {
                        d.host_candidates.push(c.clone());
                    }
                }
                Err(e) => log::debug!("host candidate {}: {e}", s.local),
            }
        }
        d.drain();
        Ok(d)
    }

    pub(crate) async fn run(mut self, mut cmds: mpsc::UnboundedReceiver<Cmd>) {
        let (ptx, mut prx) = mpsc::channel::<(usize, SocketAddr, Vec<u8>)>(1024);
        let readers: Vec<_> = self
            .sockets
            .iter()
            .enumerate()
            .map(|(idx, s)| {
                let sock = s.socket.clone();
                let tx = ptx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    loop {
                        match sock.recv_from(&mut buf).await {
                            Ok((n, from)) => {
                                if tx.send((idx, from, buf[..n].to_vec())).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => log::trace!("recv: {e}"),
                        }
                    }
                })
            })
            .collect();
        drop(ptx);

        let mut arx = self.aux_rx.take().expect("run once");
        if self.resolving {
            let cfg = self.config.clone();
            let atx = self.aux_tx.clone();
            tokio::spawn(async move {
                let _ = atx.send(Aux::Servers(resolve_ice_servers(cfg).await));
            });
        }

        while !self.closed {
            let deadline = tokio::time::Instant::from_std(self.next_deadline());
            tokio::select! {
                Some(aux) = arx.recv() => match aux {
                    Aux::Servers(servers) => self.start_servers(servers),
                    Aux::RemoteCandidate(c) => self.add_remote_candidate_str(&c),
                },
                cmd = cmds.recv() => match cmd {
                    Some(c) => self.handle_cmd(c),
                    None => break,
                },
                Some((idx, from, data)) = prx.recv() => self.handle_packet(idx, from, &data),
                _ = tokio::time::sleep_until(deadline) => self.on_timer(),
            }
            self.run_deferred();
        }
        let now = Instant::now();
        for i in 0..self.turns.len() {
            let pkts = self.turns[i].close();
            self.send_to_server(i, pkts);
        }
        let _ = now;
        for r in readers {
            r.abort();
        }
        log::debug!("peer connection driver stopped");
    }

    /// Drain `poll_output` until it yields a timeout. Called after every mutation.
    fn drain(&mut self) {
        loop {
            match self.rtc.poll_output() {
                Ok(Output::Timeout(t)) => {
                    self.timeout = t;
                    return;
                }
                Ok(Output::Transmit(t)) => {
                    if let Some(ti) = self.turns.iter().position(|c| c.relay == Some(t.source)) {
                        let pkts = self.turns[ti].send(Instant::now(), t.destination, &t.contents);
                        self.send_to_server(ti, pkts);
                    } else if let Some(s) = self.sockets.iter().find(|s| s.local == t.source) {
                        if let Err(e) = s.socket.try_send_to(&t.contents, t.destination) {
                            log::debug!("send {} -> {}: {e}", t.source, t.destination);
                        }
                    } else {
                        log::trace!("no socket for source {}", t.source);
                    }
                }
                Ok(Output::Event(e)) => self.on_event(e),
                Err(e) => {
                    log::debug!("poll_output: {e}");
                    self.timeout = Instant::now() + Duration::from_millis(100);
                    return;
                }
            }
        }
    }

    /// Flush queued channel writes and report buffered-low, iteratively.
    fn run_deferred(&mut self) {
        let mut rounds = 0;
        while !self.pending_flush.is_empty() && rounds < 64 {
            rounds += 1;
            let mut hs = std::mem::take(&mut self.pending_flush);
            hs.sort_unstable();
            hs.dedup();
            for h in hs {
                self.flush(h);
            }
        }
        let mut lows = std::mem::take(&mut self.pending_low);
        lows.sort_unstable();
        lows.dedup();
        for h in lows {
            self.update_shared(h);
            self.emit(PeerEvent::DcBufferedAmountLow { handle: h });
        }
    }

    fn emit(&self, e: PeerEvent) {
        (self.events)(e);
    }

    fn handle_packet(&mut self, idx: usize, from: SocketAddr, data: &[u8]) {
        if let Some(ti) = self.turns.iter().position(|t| t.sock_idx == idx && t.server == from) {
            let (ev, out) = self.turns[ti].handle(Instant::now(), data);
            self.send_to_server(ti, out);
            self.on_turn_events(ti, ev);
            return;
        }
        if stun::is_stun(data) {
            if let Some(m) = Message::decode(data) {
                if let Some(txn) = self.stun_txns.get(&m.tid) {
                    if txn.server == from && txn.sock_idx == idx {
                        self.stun_txns.remove(&m.tid);
                        if m.typ == stun::BINDING_SUCCESS {
                            if let Some(mapped) = m.xor_addr(stun::ATTR_XOR_MAPPED_ADDRESS) {
                                self.add_srflx(idx, mapped);
                            }
                        }
                        self.check_gathering_complete();
                        return;
                    }
                }
            }
        }
        let Some(sock) = self.sockets.get(idx) else { return };
        let Ok(contents) = data.try_into() else { return };
        let input = Input::Receive(
            Instant::now(),
            Receive { proto: Protocol::Udp, source: from, destination: sock.local, contents },
        );
        if !self.rtc.accepts(&input) {
            return;
        }
        if let Err(e) = self.rtc.handle_input(input) {
            log::debug!("handle_input: {e}");
        }
        self.drain();
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::CreateOffer(r) => {
                let _ = r.send(self.create_offer());
            }
            Cmd::CreateAnswer(r) => {
                let _ = r.send(self.create_answer());
            }
            Cmd::UpsertTx(spec, r) => {
                self.upsert_tx(spec);
                let _ = r.send(Ok(()));
            }
            Cmd::SendFrame(f) => self.send_frame(f),
            Cmd::RequestKeyframe(tx) => self.request_keyframe(tx),
            Cmd::RestartIce => self.ice_restart = true,
            Cmd::SetLocal(d, r) => {
                let _ = r.send(self.set_local(d));
            }
            Cmd::SetRemote(d, r) => {
                let _ = r.send(self.set_remote(d));
            }
            Cmd::AddIce(c, r) => {
                let _ = r.send(self.add_ice(c));
            }
            Cmd::CreateDc(label, init, r) => {
                let _ = r.send(self.create_dc(label, init));
            }
            Cmd::DcSend(h, p) => {
                if let Some(ch) = self.chans.get_mut(&h) {
                    let (bin, bytes) = match p {
                        Payload::Text(t) => (false, t.into_bytes()),
                        Payload::Binary(b) => (true, b),
                    };
                    ch.queued_bytes += bytes.len() as u64;
                    ch.queue.push_back((bin, bytes));
                    self.pending_flush.push(h);
                }
            }
            Cmd::DcThreshold(h, t) => {
                if let Some(ch) = self.chans.get_mut(&h) {
                    ch.threshold = t;
                    if let Some(id) = ch.id.filter(|_| ch.open) {
                        if let Some(mut c) = self.rtc.channel(id) {
                            c.set_buffered_amount_low_threshold(t as usize);
                        }
                        self.drain();
                    }
                }
            }
            Cmd::DcClose(h) => self.close_dc(h),
            Cmd::Stats(r) => {
                let _ = r.send(Ok(self.stats_json()));
            }
            Cmd::Close => {
                let _ = self.rtc.close();
                self.drain();
                self.closed = true;
            }
        }
    }

    // ============================ JSEP ============================

    fn tx_by_mid(&self, mid: &str) -> Option<TxId> {
        self.txs.iter().find(|(_, t)| t.mid.as_deref() == Some(mid)).map(|(id, _)| *id)
    }

    fn tx_states(&self) -> Vec<TransceiverState> {
        self.txs.values().map(Tx::state).collect()
    }

    /// Rewrite direction and msid of outgoing SDP from the transceiver model.
    fn munge(&self, raw: &str, answer: bool) -> String {
        jsep::rewrite(raw, |mid| {
            let t = self
                .txs
                .values()
                .find(|t| t.mid.as_deref() == Some(mid) || t.offered_mid.as_deref() == Some(mid))?;
            let dir = if t.stopped() {
                Direction::Inactive
            } else if answer {
                let remote = t.remote_dir.unwrap_or(Direction::Sendrecv);
                Direction::from_flags(
                    t.spec.direction.sends() && remote.recvs(),
                    t.spec.direction.recvs() && remote.sends(),
                )
            } else {
                t.spec.direction
            };
            let msid = dir.sends().then(|| (t.spec.stream_ids.clone(), t.spec.sender_track_id.clone()));
            Some(jsep::Rewrite { direction: dir, msid })
        })
    }

    fn create_offer(&mut self) -> Result<SessionDescription> {
        match self.sig {
            Sig::HaveRemoteOffer => return Err(Error::InvalidState("have-remote-offer".into())),
            Sig::HaveLocalOffer => {
                if let Some((sdp, _)) = &self.local_offer {
                    return Ok(SessionDescription { kind: SdpType::Offer, sdp: sdp.clone() });
                }
            }
            Sig::Stable => {}
        }
        // Built from scratch each time; an earlier created-but-unset offer is discarded.
        self.created_offer = None;
        for t in self.txs.values_mut() {
            t.offered_mid = None;
        }
        for ch in self.chans.values_mut().filter(|c| !c.confirmed) {
            ch.id = None;
        }
        let mut api = self.rtc.sdp_api();
        for t in self.txs.values_mut() {
            if t.stopped() {
                if let (Some(mid), false) = (&t.mid, t.stop_sent) {
                    api.stop_media(Mid::from(mid.as_str()));
                }
                continue;
            }
            match &t.mid {
                None => {
                    let mid = api.add_media(
                        s_kind(t.spec.kind),
                        s_dir(t.spec.direction),
                        t.spec.stream_ids.first().cloned(),
                        Some(t.spec.sender_track_id.clone()),
                        None,
                    );
                    t.offered_mid = Some(mid.to_string());
                    t.offered_direction = Some(t.spec.direction);
                }
                Some(mid) => {
                    if t.negotiated_direction != Some(t.spec.direction) {
                        api.set_direction(Mid::from(mid.as_str()), s_dir(t.spec.direction));
                    }
                    t.offered_direction = Some(t.spec.direction);
                }
            }
        }
        for ch in self.chans.values_mut().filter(|c| c.id.is_none() && !c.closed) {
            ch.id = Some(api.add_channel_with_config(ch.config.clone()));
        }
        if self.ice_restart {
            api.ice_restart(true);
        }
        let applied = api.apply();
        self.rebuild_by_id();
        self.drain();
        match applied {
            Some((offer, pending)) => {
                let sdp = self.munge(&offer.to_sdp_string(), false);
                self.created_offer = Some((sdp.clone(), pending));
                Ok(SessionDescription { kind: SdpType::Offer, sdp })
            }
            None => Err(Error::Operation("nothing to negotiate".into())),
        }
    }

    fn create_answer(&mut self) -> Result<SessionDescription> {
        if self.sig != Sig::HaveRemoteOffer {
            return Err(Error::InvalidState("createAnswer needs a remote offer".into()));
        }
        // str0m's accept_offer happens here rather than in setRemoteDescription,
        // so tracks added after the remote offer (matrix-js-sdk's inbound flow)
        // shape the answer, and remote offers stay rollback-able until now.
        if self.raw_answer.is_none() {
            let (sdp, has_app_line) = match &self.pending_remote {
                Some(p) => (p.clone(), has_app(p)),
                None => return Err(Error::InvalidState("no remote offer".into())),
            };
            let offer = SdpOffer::from_sdp_string(&sdp)
                .map_err(|e| Error::Operation(format!("Failed to parse SessionDescription: {e}")))?;
            let res = self.rtc.sdp_api().accept_offer(offer);
            self.drain();
            let answer = res.map_err(op("createAnswer"))?;
            self.raw_answer = Some(answer.to_sdp_string());
            for c in std::mem::take(&mut self.buffered_candidates) {
                self.add_remote_candidate_str(&c);
            }
            if has_app_line {
                self.app_negotiated = true;
                for ch in self.chans.values_mut().filter(|c| !c.confirmed) {
                    ch.id = None;
                }
                self.create_pending_direct();
            }
        }
        let sdp = self.munge(self.raw_answer.as_deref().unwrap_or_default(), true);
        self.answer = Some(sdp.clone());
        Ok(SessionDescription { kind: SdpType::Answer, sdp })
    }

    fn rollback_local(&mut self) {
        self.created_offer = None;
        self.local_offer = None;
        for t in self.txs.values_mut() {
            if t.mid_pending {
                t.mid = None;
                t.mid_pending = false;
            }
            t.offered_mid = None;
            t.offered_direction = None;
        }
        for ch in self.chans.values_mut().filter(|c| !c.confirmed) {
            ch.id = None;
        }
        self.sig = Sig::Stable;
    }

    fn rollback_remote(&mut self) -> Result<()> {
        if self.raw_answer.is_some() {
            return Err(Error::InvalidState("remote offer was already applied by createAnswer()".into()));
        }
        self.pending_remote = None;
        self.buffered_candidates.clear();
        self.txs.retain(|_, t| !(t.created_by_remote && t.mid_pending));
        for t in self.txs.values_mut() {
            if t.mid_pending {
                t.mid = None;
                t.mid_pending = false;
                t.remote_dir = None;
                t.remote_streams.clear();
                t.remote_track = None;
            }
        }
        self.sig = Sig::Stable;
        Ok(())
    }

    fn set_local(&mut self, d: SessionDescription) -> Result<Vec<TransceiverState>> {
        match d.kind {
            SdpType::Offer => {
                if self.sig != Sig::Stable {
                    return Err(Error::InvalidState(format!("cannot set local offer in {:?}", self.sig)));
                }
                let Some((sdp, pending)) = self.created_offer.take() else {
                    return Err(Error::InvalidState("no offer was created".into()));
                };
                if norm(&sdp) != norm(&d.sdp) {
                    self.created_offer = Some((sdp, pending));
                    return Err(Error::InvalidModification("SDP munging is not supported".into()));
                }
                for t in self.txs.values_mut() {
                    if let Some(mid) = t.offered_mid.take() {
                        t.mid = Some(mid);
                        t.mid_pending = true;
                    }
                }
                self.local_sdp = Some(sdp.clone());
                self.local_offer = Some((sdp, pending));
                self.sig = Sig::HaveLocalOffer;
            }
            SdpType::Answer => {
                let ok = self.sig == Sig::HaveRemoteOffer
                    && self.answer.as_ref().map(|a| norm(a) == norm(&d.sdp)).unwrap_or(false);
                if !ok {
                    return Err(Error::InvalidModification("answer does not match createAnswer()".into()));
                }
                let answer = self.answer.take().unwrap_or_default();
                for sec in jsep::parse(&answer) {
                    let Some(id) = sec.mid.as_deref().and_then(|m| self.tx_by_mid(m)) else { continue };
                    if let Some(t) = self.txs.get_mut(&id) {
                        t.current_direction = Some(if sec.port_zero { Direction::Stopped } else { sec.direction });
                        t.negotiated_direction = Some(t.spec.direction);
                        t.mid_pending = false;
                        if sec.port_zero {
                            t.stop_sent = true;
                        }
                    }
                }
                self.local_sdp = Some(answer);
                self.pending_remote = None;
                self.raw_answer = None;
                self.sig = Sig::Stable;
            }
            SdpType::Rollback => match self.sig {
                Sig::HaveLocalOffer => self.rollback_local(),
                Sig::HaveRemoteOffer => self.rollback_remote()?,
                Sig::Stable => return Err(Error::InvalidState("nothing to roll back".into())),
            },
            SdpType::Pranswer => return Err(Error::NotSupported("pranswer".into())),
        }
        if d.kind != SdpType::Rollback {
            self.start_gathering();
        }
        Ok(self.tx_states())
    }

    fn set_remote(&mut self, d: SessionDescription) -> Result<Vec<TransceiverState>> {
        match d.kind {
            SdpType::Offer => {
                match self.sig {
                    // Perfect negotiation: a remote offer implicitly rolls back ours.
                    Sig::HaveLocalOffer => self.rollback_local(),
                    Sig::HaveRemoteOffer => self.rollback_remote()?,
                    Sig::Stable => {}
                }
                SdpOffer::from_sdp_string(&d.sdp)
                    .map_err(|e| Error::Operation(format!("Failed to parse SessionDescription: {e}")))?;
                for sec in jsep::parse(&d.sdp) {
                    let jsep::SectionKind::Media(kind) = sec.kind else { continue };
                    let Some(mid) = sec.mid.clone() else { continue };
                    let id = match self.tx_by_mid(&mid) {
                        Some(id) => id,
                        None => {
                            let reuse = self
                                .txs
                                .iter()
                                .filter(|(_, t)| {
                                    t.spec.kind == kind && t.mid.is_none() && !t.stopped() && t.spec.from_add_track
                                })
                                .map(|(id, _)| *id)
                                .min();
                            match reuse {
                                Some(id) => {
                                    let t = self.txs.get_mut(&id).unwrap();
                                    t.mid = Some(mid.clone());
                                    t.mid_pending = true;
                                    id
                                }
                                None => {
                                    let id = self.next_remote_tx;
                                    self.next_remote_tx += 1;
                                    let mut t = Tx::new(TransceiverSpec {
                                        id,
                                        kind,
                                        direction: Direction::Recvonly,
                                        stream_ids: Vec::new(),
                                        sender_track_id: format!("{:016x}", rand::random::<u64>()),
                                        from_add_track: false,
                                        stopped: false,
                                    });
                                    t.created_by_remote = true;
                                    t.mid = Some(mid.clone());
                                    t.mid_pending = true;
                                    self.txs.insert(id, t);
                                    id
                                }
                            }
                        }
                    };
                    if let Some(t) = self.txs.get_mut(&id) {
                        t.set_remote(&sec);
                    }
                }
                self.pending_remote = Some(d.sdp.clone());
                self.raw_answer = None;
                self.answer = None;
                self.sig = Sig::HaveRemoteOffer;
            }
            SdpType::Answer => {
                if self.sig != Sig::HaveLocalOffer {
                    return Err(Error::InvalidState("no local offer to answer".into()));
                }
                let answer = SdpAnswer::from_sdp_string(&d.sdp)
                    .map_err(|e| Error::Operation(format!("Failed to parse SessionDescription: {e}")))?;
                let (sdp, pending) = self.local_offer.take().expect("have-local-offer has an offer");
                let res = self.rtc.sdp_api().accept_answer(pending, answer);
                self.drain();
                if let Err(e) = res {
                    self.rollback_local();
                    return Err(Error::Operation(format!("setRemoteDescription: {e}")));
                }
                for sec in jsep::parse(&d.sdp) {
                    let Some(id) = sec.mid.as_deref().and_then(|m| self.tx_by_mid(m)) else { continue };
                    if let Some(t) = self.txs.get_mut(&id) {
                        t.mid_pending = false;
                        t.negotiated_direction = t.offered_direction.take().or(t.negotiated_direction);
                        t.current_direction =
                            Some(if sec.port_zero { Direction::Stopped } else { sec.direction.invert() });
                        if t.stopped() || sec.port_zero {
                            t.stop_sent = true;
                        }
                        t.set_remote(&sec);
                    }
                }
                self.sig = Sig::Stable;
                if has_app(&sdp) && has_app(&d.sdp) {
                    self.app_negotiated = true;
                    for ch in self.chans.values_mut().filter(|c| c.id.is_some()) {
                        ch.confirmed = true;
                    }
                    self.create_pending_direct();
                }
                self.ice_restart = false;
            }
            SdpType::Rollback => {
                if self.sig != Sig::HaveRemoteOffer {
                    return Err(Error::InvalidState("no remote offer to roll back".into()));
                }
                self.rollback_remote()?;
            }
            SdpType::Pranswer => return Err(Error::NotSupported("pranswer".into())),
        }
        Ok(self.tx_states())
    }

    fn upsert_tx(&mut self, spec: TransceiverSpec) {
        match self.txs.get_mut(&spec.id) {
            Some(t) => t.spec = spec,
            None => {
                self.txs.insert(spec.id, Tx::new(spec));
            }
        }
    }

    fn send_frame(&mut self, f: EncodedFrame) {
        let Some(t) = self.txs.get(&f.tx) else { return };
        let can_send = !t.stopped() && t.current_direction.map(|d| d.sends()).unwrap_or(false);
        let Some(mid) = t.mid.clone().filter(|_| can_send) else { return };
        let Some(w) = self.rtc.writer(Mid::from(mid.as_str())) else { return };
        let Some(pt) = w.payload_params().find(|p| same_codec(p.spec().codec, f.codec)).map(|p| p.pt()) else {
            log::debug!("tx {} ({mid}): {:?} not negotiated", f.tx, f.codec);
            return;
        };
        let rtp_time = match f.codec.kind() {
            TrackKind::Audio => MediaTime::new(f.timestamp_us * 48 / 1000, Frequency::FORTY_EIGHT_KHZ),
            TrackKind::Video => MediaTime::new(f.timestamp_us * 9 / 100, Frequency::NINETY_KHZ),
        };
        if let Err(e) = w.write(pt, Instant::now(), rtp_time, f.data) {
            log::debug!("write {mid}: {e}");
        }
        self.drain();
    }

    fn request_keyframe(&mut self, tx: TxId) {
        let Some(mid) = self.txs.get(&tx).and_then(|t| t.mid.clone()) else { return };
        if let Some(t) = self.txs.get_mut(&tx) {
            let now = Instant::now();
            if t.last_kf_req.map(|l| now - l < Duration::from_millis(300)).unwrap_or(false) {
                return;
            }
            t.last_kf_req = Some(now);
        }
        if let Some(mut w) = self.rtc.writer(Mid::from(mid.as_str())) {
            if w.is_request_keyframe_possible(KeyframeRequestKind::Pli) {
                let _ = w.request_keyframe(None, KeyframeRequestKind::Pli);
            }
        }
        self.drain();
    }

    fn add_ice(&mut self, c: IceCandidate) -> Result<()> {
        let s = c.candidate.trim().trim_start_matches("a=");
        if s.is_empty() {
            return Ok(());
        }
        let fields: Vec<&str> = s.split_whitespace().collect();
        if let Some(host) = fields.get(4).filter(|a| a.ends_with(".local")) {
            // mDNS-obfuscated host candidate: resolve in the background. Until
            // then connectivity can still form through peer-reflexive candidates.
            let (host, cand, tx) = (host.to_string(), s.to_string(), self.aux_tx.clone());
            tokio::spawn(async move {
                match super::mdns::resolve(&host, Duration::from_secs(3)).await {
                    Some(ip) => {
                        log::debug!("mDNS {host} -> {ip}");
                        let _ = tx.send(Aux::RemoteCandidate(cand.replacen(&host, &ip.to_string(), 1)));
                    }
                    None => log::debug!("mDNS {host}: no answer"),
                }
            });
            return Ok(());
        }
        Candidate::from_sdp_string(s).map_err(|e| Error::Operation(format!("Error processing ICE candidate: {e}")))?;
        self.add_remote_candidate_str(s);
        Ok(())
    }

    fn add_remote_candidate_str(&mut self, s: &str) {
        // Until createAnswer applies a pending remote offer, str0m has no remote
        // ICE credentials; hold candidates until then.
        if self.pending_remote.is_some() && self.raw_answer.is_none() {
            self.buffered_candidates.push(s.to_string());
            return;
        }
        match Candidate::from_sdp_string(s) {
            Ok(c) => {
                self.rtc.add_remote_candidate(c);
                self.drain();
            }
            Err(e) => log::debug!("remote candidate {s}: {e}"),
        }
    }

    fn create_dc(&mut self, label: String, init: DataChannelInit) -> Result<DataChannelInfo> {
        let reliability = match (init.max_packet_life_time, init.max_retransmits) {
            (Some(lifetime), _) => Reliability::MaxPacketLifetime { lifetime },
            (_, Some(retransmits)) => Reliability::MaxRetransmits { retransmits },
            _ => Reliability::Reliable,
        };
        let negotiated = if init.negotiated.unwrap_or(false) {
            Some(init.id.ok_or_else(|| Error::Syntax("negotiated channel needs an id".into()))?)
        } else {
            None
        };
        let config = ChannelConfig {
            label: label.clone(),
            ordered: init.ordered.unwrap_or(true),
            reliability,
            negotiated,
            protocol: init.protocol.clone().unwrap_or_default(),
        };
        let handle = self.next_handle;
        self.next_handle += 1;
        self.chans.insert(
            handle,
            Chan {
                config,
                id: None,
                confirmed: false,
                open: false,
                closed: false,
                threshold: 0,
                queue: VecDeque::new(),
                queued_bytes: 0,
            },
        );
        self.shared.channels.lock().unwrap().insert(handle, ChannelShared::default());
        if self.app_negotiated {
            self.create_pending_direct();
        }
        Ok(DataChannelInfo {
            handle,
            label,
            ordered: init.ordered.unwrap_or(true),
            protocol: init.protocol.unwrap_or_default(),
            negotiated: negotiated.is_some(),
            id: negotiated,
            max_packet_life_time: init.max_packet_life_time,
            max_retransmits: init.max_retransmits,
        })
    }

    /// Open queued channels in-band, now that SCTP is negotiated.
    fn create_pending_direct(&mut self) {
        let todo: Vec<DcHandle> = self
            .chans
            .iter()
            .filter(|(_, c)| c.id.is_none() && !c.closed)
            .map(|(h, _)| *h)
            .collect();
        for h in todo {
            let config = self.chans[&h].config.clone();
            let mut api = self.rtc.sdp_api();
            let id = api.add_channel_with_config(config);
            if api.apply().is_some() {
                log::warn!("direct channel creation unexpectedly required negotiation");
            }
            if let Some(ch) = self.chans.get_mut(&h) {
                ch.id = Some(id);
                ch.confirmed = true;
            }
            self.drain();
        }
        self.rebuild_by_id();
    }

    fn rebuild_by_id(&mut self) {
        self.by_id = self.chans.iter().filter_map(|(h, c)| c.id.map(|id| (id, *h))).collect();
    }

    fn start_gathering(&mut self) {
        if self.gathering_started {
            return;
        }
        self.gathering_started = true;
        let mid = self.local_sdp.as_deref().map(sdp_mids).and_then(|m| m.into_iter().next().flatten());
        self.emit(PeerEvent::IceGatheringStateChange { state: "gathering".into() });
        let all: Vec<Candidate> = self.host_candidates.iter().chain(self.gathered.iter()).cloned().collect();
        for c in &all {
            self.emit_candidate(c, mid.clone());
        }
        self.check_gathering_complete();
    }

    fn first_mid(&self) -> Option<String> {
        self.local_sdp.as_deref().map(sdp_mids).and_then(|m| m.into_iter().next().flatten())
    }

    fn emit_candidate(&self, c: &Candidate, mid: Option<String>) {
        self.emit(PeerEvent::IceCandidate {
            candidate: Some(IceCandidate { candidate: c.to_sdp_string(), sdp_mid: mid, sdp_m_line_index: Some(0) }),
        });
    }

    /// Add a gathered (non-host) local candidate and trickle it if gathering started.
    fn add_gathered(&mut self, c: Candidate) {
        let added = self.rtc.add_local_candidate(c).cloned();
        self.drain();
        if let Some(c) = added {
            if self.gathering_started {
                self.emit_candidate(&c, self.first_mid());
            }
            self.gathered.push(c);
        }
    }

    fn add_srflx(&mut self, idx: usize, mapped: SocketAddr) {
        if self.relay_only {
            return;
        }
        let base = self.sockets[idx].local;
        if mapped == base {
            return;
        }
        match Candidate::server_reflexive(mapped, base, "udp") {
            Ok(c) => self.add_gathered(c),
            Err(e) => log::debug!("srflx {mapped}: {e}"),
        }
    }

    fn check_gathering_complete(&mut self) {
        let done = !self.resolving && self.stun_txns.is_empty() && self.turns.iter().all(|t| t.done);
        if done && self.gathering_started && !self.gathering_complete {
            self.gathering_complete = true;
            self.emit(PeerEvent::IceGatheringStateChange { state: "complete".into() });
            self.emit(PeerEvent::IceCandidate { candidate: None });
        }
    }

    fn start_servers(&mut self, servers: Vec<IceServerAddr>) {
        self.resolving = false;
        let now = Instant::now();
        for s in servers {
            match s {
                IceServerAddr::Stun(addr) => {
                    if self.relay_only {
                        continue;
                    }
                    for idx in 0..self.sockets.len() {
                        if self.sockets[idx].local.is_ipv4() != addr.is_ipv4() {
                            continue;
                        }
                        let m = Message::new(stun::BINDING_REQUEST);
                        let bytes = m.encode(None, true);
                        let _ = self.sockets[idx].socket.try_send_to(&bytes, addr);
                        self.stun_txns.insert(
                            m.tid,
                            StunTxn { server: addr, sock_idx: idx, msg: bytes, tries: 1, next: now + Duration::from_millis(250) },
                        );
                    }
                }
                IceServerAddr::Turn { addr, username, password } => {
                    let Some(idx) = self.sockets.iter().position(|s| s.local.is_ipv4() == addr.is_ipv4()) else {
                        continue;
                    };
                    let mut t = TurnClient::new(addr, idx, username, password);
                    let pkts = t.start(now);
                    self.turns.push(t);
                    self.send_to_server(self.turns.len() - 1, pkts);
                }
            }
        }
        self.check_gathering_complete();
    }

    fn send_to_server(&self, ti: usize, pkts: Vec<Vec<u8>>) {
        let t = &self.turns[ti];
        let sock = &self.sockets[t.sock_idx].socket;
        for p in pkts {
            if let Err(e) = sock.try_send_to(&p, t.server) {
                log::trace!("TURN send: {e}");
            }
        }
    }

    fn on_turn_events(&mut self, ti: usize, events: Vec<TurnEvent>) {
        for e in events {
            match e {
                TurnEvent::Allocated { relay, mapped } => {
                    let local = self.sockets[self.turns[ti].sock_idx].local;
                    log::debug!("TURN {} allocated relay {relay}", self.turns[ti].server);
                    match Candidate::relayed(relay, local, "udp") {
                        Ok(c) => self.add_gathered(c),
                        Err(e) => log::debug!("relay candidate {relay}: {e}"),
                    }
                    if let Some(m) = mapped {
                        self.add_srflx(self.turns[ti].sock_idx, m);
                    }
                    self.check_gathering_complete();
                }
                TurnEvent::Failed(why) => {
                    log::warn!("{why}");
                    self.check_gathering_complete();
                }
                TurnEvent::Data { peer, data } => {
                    let Some(relay) = self.turns[ti].relay else { continue };
                    let Ok(contents) = data.as_slice().try_into() else { continue };
                    let input = Input::Receive(
                        Instant::now(),
                        Receive { proto: Protocol::Udp, source: peer, destination: relay, contents },
                    );
                    if self.rtc.accepts(&input) {
                        if let Err(e) = self.rtc.handle_input(input) {
                            log::debug!("relayed input: {e}");
                        }
                        self.drain();
                    }
                }
            }
        }
    }

    fn next_deadline(&self) -> Instant {
        let mut d = self.timeout;
        for t in &self.turns {
            if let Some(x) = t.next_deadline() {
                d = d.min(x);
            }
        }
        if let Some(x) = self.stun_txns.values().map(|t| t.next).min() {
            d = d.min(x);
        }
        d
    }

    fn on_timer(&mut self) {
        let now = Instant::now();
        if now >= self.timeout {
            if let Err(e) = self.rtc.handle_input(Input::Timeout(now)) {
                log::debug!("timeout input: {e}");
            }
            self.drain();
        }
        for ti in 0..self.turns.len() {
            let (ev, out) = self.turns[ti].poll(now);
            self.send_to_server(ti, out);
            self.on_turn_events(ti, ev);
        }
        let due: Vec<TransId> = self.stun_txns.iter().filter(|(_, t)| t.next <= now).map(|(k, _)| *k).collect();
        for tid in due {
            let Some(t) = self.stun_txns.get_mut(&tid) else { continue };
            if t.tries >= 5 {
                log::debug!("STUN {} timed out", t.server);
                self.stun_txns.remove(&tid);
                continue;
            }
            t.tries += 1;
            t.next = now + Duration::from_millis(250 << t.tries.min(4));
            let _ = self.sockets[t.sock_idx].socket.try_send_to(&t.msg, t.server);
        }
        self.check_gathering_complete();
    }

    fn set_conn(&mut self, s: &'static str) {
        if self.conn_state != s {
            self.conn_state = s;
            self.emit(PeerEvent::ConnectionStateChange { state: s.into() });
        }
    }

    fn update_shared(&mut self, h: DcHandle) {
        let Some(ch) = self.chans.get(&h) else { return };
        let (open, queued, id) = (ch.open, ch.queued_bytes, ch.id);
        let sctp = match id.filter(|_| open) {
            Some(id) => self.rtc.channel(id).map(|mut c| c.buffered_amount() as u64).unwrap_or(0),
            None => 0,
        };
        self.shared
            .channels
            .lock()
            .unwrap()
            .insert(h, ChannelShared { open, buffered: queued + sctp });
    }

    fn flush(&mut self, h: DcHandle) {
        let (id, mut queue) = match self.chans.get_mut(&h) {
            Some(ch) if ch.open && ch.id.is_some() => (ch.id.unwrap(), std::mem::take(&mut ch.queue)),
            _ => return,
        };
        let mut sent = 0u64;
        while let Some((bin, buf)) = queue.pop_front() {
            let accepted = match self.rtc.channel(id) {
                Some(mut c) => c.write(bin, &buf),
                None => break,
            };
            match accepted {
                Ok(true) => {
                    sent += buf.len() as u64;
                    self.drain();
                }
                Ok(false) => {
                    queue.push_front((bin, buf));
                    break;
                }
                Err(e) => {
                    log::debug!("channel write: {e}");
                    sent += buf.len() as u64;
                }
            }
        }
        if let Some(ch) = self.chans.get_mut(&h) {
            queue.extend(ch.queue.drain(..));
            ch.queue = queue;
            ch.queued_bytes = ch.queued_bytes.saturating_sub(sent);
        }
        self.update_shared(h);
    }

    fn close_dc(&mut self, h: DcHandle) {
        let Some(ch) = self.chans.get_mut(&h) else { return };
        if ch.closed {
            return;
        }
        ch.closed = true;
        match ch.id.filter(|_| ch.open) {
            Some(id) => {
                self.rtc.direct_api().close_data_channel(id);
                self.drain();
            }
            None => {
                ch.open = false;
                self.update_shared(h);
                self.emit(PeerEvent::DcClose { handle: h });
            }
        }
    }

    fn on_event(&mut self, e: Event) {
        match e {
            Event::IceConnectionStateChange(s) => {
                let st = match s {
                    IceConnectionState::New => "new",
                    IceConnectionState::Checking => "checking",
                    IceConnectionState::Connected => "connected",
                    IceConnectionState::Completed => "completed",
                    IceConnectionState::Disconnected => "disconnected",
                };
                if self.ice_state != st {
                    self.ice_state = st;
                    self.emit(PeerEvent::IceConnectionStateChange { state: st.into() });
                }
                match s {
                    IceConnectionState::Checking if !self.dtls_connected => self.set_conn("connecting"),
                    IceConnectionState::Disconnected => self.set_conn("disconnected"),
                    IceConnectionState::Connected | IceConnectionState::Completed if self.dtls_connected => {
                        self.set_conn("connected")
                    }
                    _ => {}
                }
            }
            Event::Connected => {
                self.dtls_connected = true;
                self.set_conn("connected");
            }
            Event::ChannelOpen(id, label) => {
                let stream = self.rtc.direct_api().sctp_stream_id_by_channel_id(id);
                if let Some(&h) = self.by_id.get(&id) {
                    let threshold = if let Some(ch) = self.chans.get_mut(&h) {
                        ch.open = true;
                        ch.threshold
                    } else {
                        0
                    };
                    if threshold > 0 {
                        if let Some(mut c) = self.rtc.channel(id) {
                            c.set_buffered_amount_low_threshold(threshold as usize);
                        }
                    }
                    self.update_shared(h);
                    self.emit(PeerEvent::DcOpen { handle: h, id: stream });
                    self.pending_flush.push(h);
                } else {
                    let config = self
                        .rtc
                        .channel(id)
                        .and_then(|c| c.config().cloned())
                        .unwrap_or_else(|| ChannelConfig { label: label.clone(), ..Default::default() });
                    let h = self.next_handle;
                    self.next_handle += 1;
                    let (mpl, mr) = match config.reliability {
                        Reliability::MaxPacketLifetime { lifetime } => (Some(lifetime), None),
                        Reliability::MaxRetransmits { retransmits } => (None, Some(retransmits)),
                        Reliability::Reliable => (None, None),
                    };
                    let info = DataChannelInfo {
                        handle: h,
                        label: config.label.clone(),
                        ordered: config.ordered,
                        protocol: config.protocol.clone(),
                        negotiated: config.negotiated.is_some(),
                        id: stream,
                        max_packet_life_time: mpl,
                        max_retransmits: mr,
                    };
                    self.chans.insert(
                        h,
                        Chan {
                            config,
                            id: Some(id),
                            confirmed: true,
                            open: true,
                            closed: false,
                            threshold: 0,
                            queue: VecDeque::new(),
                            queued_bytes: 0,
                        },
                    );
                    self.by_id.insert(id, h);
                    self.update_shared(h);
                    self.emit(PeerEvent::DataChannel { channel: info });
                    self.emit(PeerEvent::DcOpen { handle: h, id: stream });
                }
            }
            Event::ChannelData(d) => {
                if let Some(&h) = self.by_id.get(&d.id) {
                    let payload = if d.binary {
                        Payload::Binary(d.data)
                    } else {
                        Payload::Text(String::from_utf8_lossy(&d.data).into_owned())
                    };
                    self.emit(PeerEvent::DcMessage { handle: h, payload });
                }
            }
            Event::ChannelClose(id) => {
                if let Some(&h) = self.by_id.get(&id) {
                    if let Some(ch) = self.chans.get_mut(&h) {
                        ch.open = false;
                        ch.closed = true;
                        ch.queue.clear();
                        ch.queued_bytes = 0;
                    }
                    self.update_shared(h);
                    self.emit(PeerEvent::DcClose { handle: h });
                }
            }
            Event::ChannelBufferedAmountLow(id) => {
                if let Some(&h) = self.by_id.get(&id) {
                    self.pending_flush.push(h);
                    self.pending_low.push(h);
                }
            }
            Event::PeerStats(s) => self.stats = Some(s),
            Event::MediaData(d) => {
                let mid = d.mid.to_string();
                let Some(tx) = self.tx_by_mid(&mid) else { return };
                let Some(codec) = codec_name(d.params.spec().codec) else { return };
                let keyframe = match (&d.codec_extra, codec) {
                    (_, CodecName::Vp8) => d.data.first().map(|b| b & 1 == 0).unwrap_or(false),
                    (_, CodecName::Opus) => true,
                    _ => false,
                };
                if !d.contiguous && codec.kind() == TrackKind::Video {
                    self.request_keyframe(tx);
                }
                let timestamp_us = d.time.numer().saturating_mul(1_000_000) / d.time.denom() as u64;
                self.emit(PeerEvent::MediaFrame(EncodedFrame { tx, codec, keyframe, timestamp_us, data: d.data }));
            }
            Event::KeyframeRequest(r) => {
                if let Some(tx) = self.tx_by_mid(&r.mid.to_string()) {
                    self.emit(PeerEvent::KeyframeRequest { tx });
                }
            }
            Event::EgressBitrateEstimate(b) => {
                let bps = match b {
                    str0m::bwe::BweKind::Twcc { estimate, .. } => estimate.as_u64(),
                    str0m::bwe::BweKind::Remb { estimate, .. } => estimate.as_u64(),
                    _ => return,
                };
                self.emit(PeerEvent::TargetBitrate { bps });
            }
            Event::Closed => {
                let open: Vec<DcHandle> = self.chans.iter().filter(|(_, c)| c.open).map(|(h, _)| *h).collect();
                for h in open {
                    if let Some(ch) = self.chans.get_mut(&h) {
                        ch.open = false;
                        ch.closed = true;
                    }
                    self.update_shared(h);
                    self.emit(PeerEvent::DcClose { handle: h });
                }
                self.set_conn("disconnected");
            }
            _ => {}
        }
    }

    fn stats_json(&self) -> serde_json::Value {
        use serde_json::json;
        let open = self.chans.values().filter(|c| c.open).count();
        let mut out = serde_json::Map::new();
        out.insert(
            "P".into(),
            json!({"type": "peer-connection", "id": "P", "dataChannelsOpened": open}),
        );
        if let Some(s) = &self.stats {
            out.insert(
                "T".into(),
                json!({"type": "transport", "id": "T", "bytesSent": s.peer_bytes_tx, "bytesReceived": s.peer_bytes_rx,
                       "dtlsState": if self.dtls_connected { "connected" } else { "new" }}),
            );
            if let Some(p) = &s.selected_candidate_pair {
                out.insert(
                    "CP".into(),
                    json!({"type": "candidate-pair", "id": "CP", "state": "succeeded", "nominated": true,
                           "currentRoundTripTime": s.rtt.map(|d| d.as_secs_f64()),
                           "localCandidateId": "LC", "remoteCandidateId": "RC", "protocol": format!("{:?}", p.protocol).to_lowercase()}),
                );
                out.insert("LC".into(), json!({"type": "local-candidate", "id": "LC", "address": p.local.addr.ip().to_string(), "port": p.local.addr.port()}));
                out.insert("RC".into(), json!({"type": "remote-candidate", "id": "RC", "address": p.remote.addr.ip().to_string(), "port": p.remote.addr.port()}));
            }
        }
        serde_json::Value::Object(out)
    }
}
