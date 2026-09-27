//! The per-connection driver: owns the `Rtc`, sockets, JSEP state and data
//! channel queues. Every mutation of the `Rtc` is followed by [`Driver::drain`].

use super::audio::{AudioHub, AudioReceiver, AudioSender, CaptureProcessing};
use super::jsep;
use super::net::{bind_host_sockets, HostSocket};
use super::stun::{self, Message, TransId};
use super::turn::{TurnClient, TurnEvent};
use super::turn_stream::{self, StreamEvent, TurnTransport};
use super::{ChannelShared, Cmd, Shared};
use crate::*;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::format::Codec;
use str0m::format::FormatParams;
use str0m::media::{Frequency, KeyframeRequestKind, MediaKind, MediaTime, Mid, TelephoneEvent};
use str0m::net::{Protocol, Receive};
use str0m::stats::PeerStats;
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};
use tokio::sync::mpsc;

/// A STUN or TURN server after DNS resolution.
#[derive(Debug, Clone)]
pub(crate) enum IceServerAddr {
    Stun(SocketAddr),
    Turn {
        addr: SocketAddr,
        username: String,
        password: String,
        transport: TurnTransport,
    },
}

/// Results of background work (DNS, mDNS) delivered back to the driver.
pub(crate) enum Aux {
    Servers(Vec<IceServerAddr>),
    RemoteCandidate(String),
    /// From the stream task of TURN client `.0` (TCP/TLS transports).
    TurnStream(usize, StreamEvent),
}

struct TurnStreamLink {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    local: Option<SocketAddr>,
}

struct StunTxn {
    server: SocketAddr,
    sock_idx: usize,
    msg: Vec<u8>,
    tries: u32,
    next: Instant,
}

/// Parse W3C ICE server URLs (RFC 7064, RFC 7065) into resolvable targets:
/// (is TURN, transport, host, port). `stuns:` and DTLS TURN are skipped and
/// reported in the log, as Chromium does.
fn parse_ice_url(url: &str) -> Option<(bool, TurnTransport, String, u16)> {
    let (scheme, rest) = url.split_once(':')?;
    let rest = rest.trim_start_matches("//");
    let (hostport, query) = rest.split_once('?').unwrap_or((rest, ""));
    let transport_q = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("transport="))
        .map(|t| t.to_ascii_lowercase());
    let (is_turn, default_port) = match scheme {
        "stun" => (false, 3478),
        "turn" => (true, 3478),
        "turns" => (true, 5349),
        "stuns" => {
            log::info!("ICE server {url}: STUN over TLS is not supported, skipping");
            return None;
        }
        _ => return None,
    };
    let tls = scheme == "turns";
    if tls && transport_q.as_deref() == Some("udp") {
        log::info!("ICE server {url}: TURN over DTLS is not supported, skipping");
        return None;
    }
    if tls && !turn_stream::TLS_AVAILABLE {
        log::info!("ICE server {url}: built without TLS support, skipping");
        return None;
    }
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (h, p) = h.split_once(']')?;
        (
            h.to_string(),
            p.trim_start_matches(':').parse().unwrap_or(default_port),
        )
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (hostport.to_string(), default_port),
        }
    };
    let transport = if tls {
        TurnTransport::Tls(host.clone())
    } else if is_turn && transport_q.as_deref() == Some("tcp") {
        TurnTransport::Tcp
    } else {
        TurnTransport::Udp
    };
    Some((is_turn, transport, host, port))
}

pub(crate) async fn resolve_ice_servers(config: RtcConfiguration) -> Vec<IceServerAddr> {
    let mut out = Vec::new();
    for s in &config.ice_servers {
        for url in &s.urls {
            let Some((is_turn, transport, host, port)) = parse_ice_url(url) else {
                continue;
            };
            let lookup = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((host.as_str(), port)),
            )
            .await;
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
                        transport: transport.clone(),
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
    /// Video: nothing written yet on this sender, so it must start with a keyframe.
    awaiting_key: bool,
    last_key_ask: Option<Instant>,
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
            awaiting_key: true,
            last_key_ask: None,
        }
    }
    fn stopped(&self) -> bool {
        self.spec.stopped || self.spec.direction == Direction::Stopped
    }
    fn set_remote(&mut self, sec: &jsep::Section) {
        self.remote_dir = Some(if sec.port_zero {
            Direction::Inactive
        } else {
            sec.direction
        });
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
    /// Stream links of TURN clients over TCP/TLS, by index in `turns`.
    turn_streams: HashMap<usize, TurnStreamLink>,
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
    audio: Arc<AudioHub>,
    uid: u64,
    audio_senders: HashMap<TxId, AudioSender>,
    audio_receivers: HashMap<TxId, AudioReceiver>,
    /// Transceivers whose engine-side Opus goes through the page's transform.
    transform_send: HashSet<TxId>,
    /// Capture processing per audio sender (default: full, as for a microphone).
    audio_processing: HashMap<TxId, CaptureProcessing>,
    transform_recv: HashSet<TxId>,
    bwe_desired_set: bool,
    /// DTMF tones waiting for the next audio write, per sender, with the
    /// earliest time each may start (RFC 4733: 50 ms after the previous end).
    dtmf_out: HashMap<TxId, VecDeque<TelephoneEvent>>,
    dtmf_next_at: HashMap<TxId, Instant>,
    dtmf_sent: HashMap<TxId, u32>,
    /// Tones received per transceiver, as characters (not exposed by the W3C
    /// API; reported in stats for diagnostics).
    dtmf_in: HashMap<TxId, String>,
    dtmf_in_last: HashMap<TxId, u64>,
}

/// Comparable form of an SDP for the "was it munged?" check. Like Chrome and
/// Safari, we compare semantically: line order within a section, whitespace,
/// candidates (they arrive by trickle anyway) and codec parameters (`a=fmtp`)
/// may differ. matrix-js-sdk parses and re-serialises every local description
/// with sdp-transform and adds `usedtx=1` to Opus. Structural edits (setup
/// role, ICE credentials, fingerprints, m-lines, directions) are still refused.
/// `a=msid-semantic` is informational and sdp-transform keeps only its first
/// stream id; `a=extmap-allow-mixed` is dropped by some serialisers.
fn norm(sdp: &str) -> String {
    let mut sections: Vec<Vec<String>> = vec![Vec::new()];
    for line in sdp.lines().map(str::trim) {
        if line.is_empty()
            || line.starts_with("a=fmtp:")
            || line.starts_with("a=candidate:")
            || line == "a=end-of-candidates"
            || line.starts_with("c=")
            || line.starts_with("a=msid-semantic")
            || line == "a=extmap-allow-mixed"
        {
            continue;
        }
        if line.starts_with("m=") {
            sections.push(Vec::new());
        }
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        sections.last_mut().expect("non-empty").push(line);
    }
    sections
        .into_iter()
        .map(|mut s| {
            s.sort();
            s.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n--\n")
}

/// Lines that differ between two SDPs after normalisation, for error messages.
fn munge_diff(created: &str, given: &str) -> String {
    let na = norm(created);
    let ng = norm(given);
    let set_a: std::collections::BTreeSet<&str> = na.lines().collect();
    let set_g: std::collections::BTreeSet<&str> = ng.lines().collect();
    let removed: Vec<&str> = set_a.difference(&set_g).copied().take(4).collect();
    let added: Vec<&str> = set_g.difference(&set_a).copied().take(4).collect();
    format!("removed {removed:?}, added {added:?}")
}

fn has_app(sdp: &str) -> bool {
    sdp.lines().any(|l| l.starts_with("m=application"))
}

fn op<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::Operation(format!("{what}: {e}"))
}

impl Driver {
    pub(crate) fn new(
        config: RtcConfiguration,
        events: EventSink,
        shared: Arc<Shared>,
        audio: Arc<AudioHub>,
        uid: u64,
    ) -> Result<Self> {
        let now = Instant::now();
        let relay_only = config.ice_transport_policy.as_deref() == Some("relay");
        // Offer what the page can encode and decode: Opus (engine) and VP8
        // (WebCodecs, always present with WebKitGTK via gst-plugins-good).
        let mut cfg = RtcConfig::new().clear_codecs().enable_opus(true, false);
        // DTMF (RFC 4733) as Chrome offers it: at Opus's clock, and at 8 kHz
        // for gateways to the phone network.
        for (pt, rate) in [
            (110u8, Frequency::FORTY_EIGHT_KHZ),
            (126, Frequency::EIGHT_KHZ),
        ] {
            let format = FormatParams {
                telephone_event_max: Some(15),
                ..Default::default()
            };
            cfg.codec_config()
                .add_config(pt.into(), None, Codec::Tele, rate, Some(1), format);
        }
        let rtc = cfg
            .enable_vp8(true)
            // TWCC bandwidth estimation drives the page's video encoder bitrate.
            .enable_bwe(Some(str0m::bwe::Bitrate::kbps(800)))
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
            turn_streams: HashMap::new(),
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
            audio,
            uid,
            audio_senders: HashMap::new(),
            audio_receivers: HashMap::new(),
            transform_send: HashSet::new(),
            audio_processing: HashMap::new(),
            transform_recv: HashSet::new(),
            bwe_desired_set: false,
            dtmf_out: HashMap::new(),
            dtmf_next_at: HashMap::new(),
            dtmf_sent: HashMap::new(),
            dtmf_in: HashMap::new(),
            dtmf_in_last: HashMap::new(),
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
                    Aux::TurnStream(ti, ev) => self.on_turn_stream(ti, ev),
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
        // Dropping the writers lets stream tasks flush the deallocation and close.
        self.turn_streams.clear();
        let _ = now;
        for r in readers {
            r.abort();
        }
        self.audio.remove_pc(self.uid);
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
        if let Some(ti) = self.turns.iter().enumerate().position(|(i, t)| {
            t.sock_idx == idx && t.server == from && !self.turn_streams.contains_key(&i)
        }) {
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
        let Some(sock) = self.sockets.get(idx) else {
            return;
        };
        let Ok(contents) = data.try_into() else {
            return;
        };
        let input = Input::Receive(
            Instant::now(),
            Receive {
                proto: Protocol::Udp,
                source: from,
                destination: sock.local,
                contents,
            },
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
            Cmd::Pcm(tx, samples) => self.push_pcm(tx, samples),
            Cmd::AudioProcessing(tx, p) => {
                self.audio_processing.insert(tx, p);
                if self.audio_senders.contains_key(&tx) {
                    self.audio.add_apm((self.uid << 32) | tx as u64, p);
                }
            }
            Cmd::Dtmf(tx, event, duration_ms) => {
                self.dtmf_out
                    .entry(tx)
                    .or_default()
                    .push_back(TelephoneEvent {
                        event,
                        end: true,
                        volume: 10,
                        duration: Duration::from_millis(duration_ms.clamp(40, 6000) as u64),
                    });
            }
            Cmd::Transform(tx, send, recv) => {
                if send {
                    self.transform_send.insert(tx);
                } else {
                    self.transform_send.remove(&tx);
                }
                if recv {
                    self.transform_recv.insert(tx);
                } else {
                    self.transform_recv.remove(&tx);
                }
            }
            Cmd::DecodeAudio(tx, data) => self.play_opus(tx, &data, true),
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
        self.txs
            .iter()
            .find(|(_, t)| t.mid.as_deref() == Some(mid))
            .map(|(id, _)| *id)
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
            let msid = dir
                .sends()
                .then(|| (t.spec.stream_ids.clone(), t.spec.sender_track_id.clone()));
            Some(jsep::Rewrite {
                direction: dir,
                msid,
            })
        })
    }

    fn create_offer(&mut self) -> Result<SessionDescription> {
        match self.sig {
            Sig::HaveRemoteOffer => return Err(Error::InvalidState("have-remote-offer".into())),
            Sig::HaveLocalOffer => {
                if let Some((sdp, _)) = &self.local_offer {
                    return Ok(SessionDescription {
                        kind: SdpType::Offer,
                        sdp: sdp.clone(),
                    });
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
        for ch in self
            .chans
            .values_mut()
            .filter(|c| c.id.is_none() && !c.closed)
        {
            ch.id = Some(api.add_channel_with_config(ch.config.clone()));
        }
        if self.ice_restart {
            api.ice_restart(true);
        }
        // JSEP: an unchanged session still gets an offer (vendored str0m patch).
        let (offer, pending) = api.apply_offer();
        self.rebuild_by_id();
        self.drain();
        let sdp = self.munge(&offer.to_sdp_string(), false);
        self.created_offer = Some((sdp.clone(), pending));
        Ok(SessionDescription {
            kind: SdpType::Offer,
            sdp,
        })
    }

    fn create_answer(&mut self) -> Result<SessionDescription> {
        if self.sig != Sig::HaveRemoteOffer {
            return Err(Error::InvalidState(
                "createAnswer needs a remote offer".into(),
            ));
        }
        // str0m's accept_offer happens here rather than in setRemoteDescription,
        // so tracks added after the remote offer (matrix-js-sdk's inbound flow)
        // shape the answer, and remote offers stay rollback-able until now.
        if self.raw_answer.is_none() {
            let (sdp, has_app_line) = match &self.pending_remote {
                Some(p) => (p.clone(), has_app(p)),
                None => return Err(Error::InvalidState("no remote offer".into())),
            };
            let offer = SdpOffer::from_sdp_string(&sdp).map_err(|e| {
                Error::Operation(format!("Failed to parse SessionDescription: {e}"))
            })?;
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
        Ok(SessionDescription {
            kind: SdpType::Answer,
            sdp,
        })
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
            return Err(Error::InvalidState(
                "remote offer was already applied by createAnswer()".into(),
            ));
        }
        self.pending_remote = None;
        self.buffered_candidates.clear();
        self.txs
            .retain(|_, t| !(t.created_by_remote && t.mid_pending));
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
        log::trace!("local {:?}:\n{}", d.kind, d.sdp);
        match d.kind {
            SdpType::Offer => {
                if self.sig != Sig::Stable {
                    return Err(Error::InvalidState(format!(
                        "cannot set local offer in {:?}",
                        self.sig
                    )));
                }
                let Some((sdp, pending)) = self.created_offer.take() else {
                    return Err(Error::InvalidState("no offer was created".into()));
                };
                if norm(&sdp) != norm(&d.sdp) {
                    let diff = munge_diff(&sdp, &d.sdp);
                    self.created_offer = Some((sdp, pending));
                    return Err(Error::InvalidModification(format!(
                        "SDP munging is not supported ({diff})"
                    )));
                }
                for t in self.txs.values_mut() {
                    if let Some(mid) = t.offered_mid.take() {
                        t.mid = Some(mid);
                        t.mid_pending = true;
                    }
                }
                // Report what the page set (it may carry fmtp edits).
                self.local_sdp = Some(d.sdp.clone());
                self.local_offer = Some((d.sdp.clone(), pending));
                self.sig = Sig::HaveLocalOffer;
            }
            SdpType::Answer => {
                let ok = self.sig == Sig::HaveRemoteOffer
                    && self
                        .answer
                        .as_ref()
                        .map(|a| norm(a) == norm(&d.sdp))
                        .unwrap_or(false);
                if !ok {
                    return Err(Error::InvalidModification(
                        "answer does not match createAnswer()".into(),
                    ));
                }
                let answer = self.answer.take().unwrap_or_default();
                for sec in jsep::parse(&answer) {
                    let Some(id) = sec.mid.as_deref().and_then(|m| self.tx_by_mid(m)) else {
                        continue;
                    };
                    if let Some(t) = self.txs.get_mut(&id) {
                        t.current_direction = Some(if sec.port_zero {
                            Direction::Stopped
                        } else {
                            sec.direction
                        });
                        t.negotiated_direction = Some(t.spec.direction);
                        t.mid_pending = false;
                        if sec.port_zero {
                            t.stop_sent = true;
                        }
                    }
                }
                self.local_sdp = Some(d.sdp.clone());
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
        log::trace!("remote {:?}:\n{}", d.kind, d.sdp);
        match d.kind {
            SdpType::Offer => {
                match self.sig {
                    // Perfect negotiation: a remote offer implicitly rolls back ours.
                    Sig::HaveLocalOffer => self.rollback_local(),
                    Sig::HaveRemoteOffer => self.rollback_remote()?,
                    Sig::Stable => {}
                }
                SdpOffer::from_sdp_string(&d.sdp).map_err(|e| {
                    Error::Operation(format!("Failed to parse SessionDescription: {e}"))
                })?;
                for sec in jsep::parse(&d.sdp) {
                    let jsep::SectionKind::Media(kind) = sec.kind else {
                        continue;
                    };
                    let Some(mid) = sec.mid.clone() else { continue };
                    let id = match self.tx_by_mid(&mid) {
                        Some(id) => id,
                        None => {
                            let reuse = self
                                .txs
                                .iter()
                                .filter(|(_, t)| {
                                    t.spec.kind == kind
                                        && t.mid.is_none()
                                        && !t.stopped()
                                        && t.spec.from_add_track
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
                let answer = SdpAnswer::from_sdp_string(&d.sdp).map_err(|e| {
                    Error::Operation(format!("Failed to parse SessionDescription: {e}"))
                })?;
                let (sdp, pending) = self
                    .local_offer
                    .take()
                    .expect("have-local-offer has an offer");
                let res = self.rtc.sdp_api().accept_answer(pending, answer);
                self.drain();
                if let Err(e) = res {
                    self.rollback_local();
                    return Err(Error::Operation(format!("setRemoteDescription: {e}")));
                }
                for sec in jsep::parse(&d.sdp) {
                    let Some(id) = sec.mid.as_deref().and_then(|m| self.tx_by_mid(m)) else {
                        continue;
                    };
                    if let Some(t) = self.txs.get_mut(&id) {
                        t.mid_pending = false;
                        t.negotiated_direction =
                            t.offered_direction.take().or(t.negotiated_direction);
                        t.current_direction = Some(if sec.port_zero {
                            Direction::Stopped
                        } else {
                            sec.direction.invert()
                        });
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
        let Some(t) = self.txs.get(&f.tx) else {
            log::debug!("frame for unknown tx {}", f.tx);
            return;
        };
        let can_send = !t.stopped() && t.current_direction.map(|d| d.sends()).unwrap_or(false);
        let Some(mid) = t.mid.clone().filter(|_| can_send) else {
            log::debug!(
                "tx {} cannot send (mid {:?}, current {:?})",
                f.tx,
                t.mid,
                t.current_direction
            );
            return;
        };
        if f.codec.kind() == TrackKind::Video {
            // Deltas before the first keyframe cannot be decoded by anyone, and
            // an SFU keeps the track dark until it sees one: ask the page.
            let now = Instant::now();
            if let Some(t) = self.txs.get_mut(&f.tx) {
                if f.keyframe {
                    t.awaiting_key = false;
                } else if t.awaiting_key {
                    if t.last_key_ask
                        .map(|l| now - l >= Duration::from_millis(200))
                        .unwrap_or(true)
                    {
                        t.last_key_ask = Some(now);
                        self.emit(PeerEvent::KeyframeRequest { tx: f.tx });
                    }
                    return;
                }
            }
        }
        let Some(w) = self.rtc.writer(Mid::from(mid.as_str())) else {
            log::debug!("tx {} ({mid}): no writer", f.tx);
            return;
        };
        let Some(pt) = w
            .payload_params()
            .find(|p| same_codec(p.spec().codec, f.codec))
            .map(|p| p.pt())
        else {
            log::debug!("tx {} ({mid}): {:?} not negotiated", f.tx, f.codec);
            return;
        };
        let rtp_time = match f.codec.kind() {
            TrackKind::Audio => {
                MediaTime::new(f.timestamp_us * 48 / 1000, Frequency::FORTY_EIGHT_KHZ)
            }
            TrackKind::Video => MediaTime::new(f.timestamp_us * 9 / 100, Frequency::NINETY_KHZ),
        };
        let now = Instant::now();
        let mut w = w;
        if f.codec == CodecName::Opus && self.dtmf_next_at.get(&f.tx).is_none_or(|t| *t <= now) {
            if let Some(ev) = self.dtmf_out.get_mut(&f.tx).and_then(|q| q.pop_front()) {
                self.dtmf_next_at
                    .insert(f.tx, now + ev.duration + Duration::from_millis(50));
                *self.dtmf_sent.entry(f.tx).or_default() += 1;
                w = w.telephone_event(ev);
            }
        }
        if let Err(e) = w.write(pt, now, rtp_time, f.data) {
            log::debug!("write {mid}: {e}");
        }
        if f.codec.kind() == TrackKind::Video && !self.bwe_desired_set {
            // Let the estimator probe up to what a 720p30 VP8 stream wants.
            self.bwe_desired_set = true;
            self.rtc
                .bwe()
                .set_desired_bitrate(str0m::bwe::Bitrate::kbps(2_500));
        }
        self.drain();
    }

    fn push_pcm(&mut self, tx: TxId, samples: Vec<i16>) {
        let key = (self.uid << 32) | tx as u64;
        let audio = self.audio.clone();
        let processing = self.audio_processing.get(&tx).copied().unwrap_or_default();
        let sender = self.audio_senders.entry(tx).or_insert_with(|| {
            audio.add_apm(key, processing);
            AudioSender::new(key)
        });
        let packets = sender.push(&audio, &samples);
        let transform = self.transform_send.contains(&tx);
        for (start, data) in packets {
            let f = EncodedFrame {
                tx,
                codec: CodecName::Opus,
                keyframe: true,
                timestamp_us: start * 1000 / 48,
                data: data.into(),
            };
            if transform {
                self.emit(PeerEvent::EncodedOut(f));
            } else {
                self.send_frame(f);
            }
        }
    }

    fn play_opus(&mut self, tx: TxId, data: &[u8], contiguous: bool) {
        let key = (self.uid, tx);
        let rx = self
            .audio_receivers
            .entry(tx)
            .or_insert_with(AudioReceiver::new);
        let pcm = rx.decode(data, contiguous);
        if rx.packets == 1 {
            self.audio.add_playout(key, self.events.clone());
        }
        self.audio.push_playout(key, &pcm);
    }

    fn request_keyframe(&mut self, tx: TxId) {
        let Some(mid) = self.txs.get(&tx).and_then(|t| t.mid.clone()) else {
            return;
        };
        if let Some(t) = self.txs.get_mut(&tx) {
            let now = Instant::now();
            if t.last_kf_req
                .map(|l| now - l < Duration::from_millis(300))
                .unwrap_or(false)
            {
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
                        let _ = tx.send(Aux::RemoteCandidate(cand.replacen(
                            &host,
                            &ip.to_string(),
                            1,
                        )));
                    }
                    None => log::debug!("mDNS {host}: no answer"),
                }
            });
            return Ok(());
        }
        Candidate::from_sdp_string(s)
            .map_err(|e| Error::Operation(format!("Error processing ICE candidate: {e}")))?;
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
            Some(
                init.id
                    .ok_or_else(|| Error::Syntax("negotiated channel needs an id".into()))?,
            )
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
        self.shared
            .channels
            .lock()
            .unwrap()
            .insert(handle, ChannelShared::default());
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
        self.by_id = self
            .chans
            .iter()
            .filter_map(|(h, c)| c.id.map(|id| (id, *h)))
            .collect();
    }

    fn start_gathering(&mut self) {
        if self.gathering_started {
            return;
        }
        self.gathering_started = true;
        let mid = self
            .local_sdp
            .as_deref()
            .map(sdp_mids)
            .and_then(|m| m.into_iter().next().flatten());
        self.emit(PeerEvent::IceGatheringStateChange {
            state: "gathering".into(),
        });
        let all: Vec<Candidate> = self
            .host_candidates
            .iter()
            .chain(self.gathered.iter())
            .cloned()
            .collect();
        for c in &all {
            self.emit_candidate(c, mid.clone());
        }
        self.check_gathering_complete();
    }

    fn first_mid(&self) -> Option<String> {
        self.local_sdp
            .as_deref()
            .map(sdp_mids)
            .and_then(|m| m.into_iter().next().flatten())
    }

    fn emit_candidate(&self, c: &Candidate, mid: Option<String>) {
        self.emit(PeerEvent::IceCandidate {
            candidate: Some(IceCandidate {
                candidate: c.to_sdp_string(),
                sdp_mid: mid,
                sdp_m_line_index: Some(0),
            }),
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
        let done =
            !self.resolving && self.stun_txns.is_empty() && self.turns.iter().all(|t| t.done);
        if done && self.gathering_started && !self.gathering_complete {
            self.gathering_complete = true;
            self.emit(PeerEvent::IceGatheringStateChange {
                state: "complete".into(),
            });
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
                            StunTxn {
                                server: addr,
                                sock_idx: idx,
                                msg: bytes,
                                tries: 1,
                                next: now + Duration::from_millis(250),
                            },
                        );
                    }
                }
                IceServerAddr::Turn {
                    addr,
                    username,
                    password,
                    transport,
                } => {
                    let Some(idx) = self
                        .sockets
                        .iter()
                        .position(|s| s.local.is_ipv4() == addr.is_ipv4())
                    else {
                        continue;
                    };
                    let reliable = transport != TurnTransport::Udp;
                    let mut t = TurnClient::new(addr, idx, username, password, reliable);
                    let pkts = t.start(now);
                    self.turns.push(t);
                    let ti = self.turns.len() - 1;
                    if reliable {
                        // The writer buffers the Allocate until the stream is up.
                        let (wtx, wrx) = mpsc::unbounded_channel();
                        self.turn_streams.insert(
                            ti,
                            TurnStreamLink {
                                tx: wtx,
                                local: None,
                            },
                        );
                        let atx = self.aux_tx.clone();
                        tokio::spawn(turn_stream::run(addr, transport, wrx, move |ev| {
                            let _ = atx.send(Aux::TurnStream(ti, ev));
                        }));
                    }
                    self.send_to_server(ti, pkts);
                }
            }
        }
        self.check_gathering_complete();
    }

    fn send_to_server(&self, ti: usize, pkts: Vec<Vec<u8>>) {
        if let Some(link) = self.turn_streams.get(&ti) {
            for p in pkts {
                let _ = link.tx.send(p);
            }
            return;
        }
        let t = &self.turns[ti];
        let sock = &self.sockets[t.sock_idx].socket;
        for p in pkts {
            if let Err(e) = sock.try_send_to(&p, t.server) {
                log::trace!("TURN send: {e}");
            }
        }
    }

    fn on_turn_stream(&mut self, ti: usize, ev: StreamEvent) {
        if ti >= self.turns.len() {
            return;
        }
        match ev {
            StreamEvent::Connected(local) => {
                log::debug!(
                    "TURN {} stream connected from {local}",
                    self.turns[ti].server
                );
                if let Some(l) = self.turn_streams.get_mut(&ti) {
                    l.local = Some(local);
                }
            }
            StreamEvent::Frame(data) => {
                let (ev, out) = self.turns[ti].handle(Instant::now(), &data);
                self.send_to_server(ti, out);
                self.on_turn_events(ti, ev);
            }
            StreamEvent::Closed(why) => {
                let ev = self.turns[ti].transport_failed(&why);
                self.on_turn_events(ti, ev);
            }
        }
    }

    fn on_turn_events(&mut self, ti: usize, events: Vec<TurnEvent>) {
        for e in events {
            match e {
                TurnEvent::Allocated { relay, mapped } => {
                    let stream_local = self.turn_streams.get(&ti).and_then(|l| l.local);
                    let local = stream_local.unwrap_or(self.sockets[self.turns[ti].sock_idx].local);
                    log::debug!("TURN {} allocated relay {relay}", self.turns[ti].server);
                    match Candidate::relayed(relay, local, "udp") {
                        Ok(c) => self.add_gathered(c),
                        Err(e) => log::debug!("relay candidate {relay}: {e}"),
                    }
                    // Over a stream the mapped address is the TCP one: not a UDP candidate.
                    if let (Some(m), None) = (mapped, stream_local) {
                        self.add_srflx(self.turns[ti].sock_idx, m);
                    }
                    self.check_gathering_complete();
                }
                TurnEvent::Failed(why) => {
                    log::warn!("{why}");
                    self.check_gathering_complete();
                }
                TurnEvent::Data { peer, data } => {
                    let Some(relay) = self.turns[ti].relay else {
                        continue;
                    };
                    let Ok(contents) = data.as_slice().try_into() else {
                        continue;
                    };
                    let input = Input::Receive(
                        Instant::now(),
                        Receive {
                            proto: Protocol::Udp,
                            source: peer,
                            destination: relay,
                            contents,
                        },
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
        let due: Vec<TransId> = self
            .stun_txns
            .iter()
            .filter(|(_, t)| t.next <= now)
            .map(|(k, _)| *k)
            .collect();
        for tid in due {
            let Some(t) = self.stun_txns.get_mut(&tid) else {
                continue;
            };
            if t.tries >= 5 {
                log::debug!("STUN {} timed out", t.server);
                self.stun_txns.remove(&tid);
                continue;
            }
            t.tries += 1;
            t.next = now + Duration::from_millis(250 << t.tries.min(4));
            let _ = self.sockets[t.sock_idx]
                .socket
                .try_send_to(&t.msg, t.server);
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
            Some(id) => self
                .rtc
                .channel(id)
                .map(|mut c| c.buffered_amount() as u64)
                .unwrap_or(0),
            None => 0,
        };
        self.shared.channels.lock().unwrap().insert(
            h,
            ChannelShared {
                open,
                buffered: queued + sctp,
            },
        );
    }

    fn flush(&mut self, h: DcHandle) {
        let (id, mut queue) = match self.chans.get_mut(&h) {
            Some(ch) if ch.open && ch.id.is_some() => {
                (ch.id.unwrap(), std::mem::take(&mut ch.queue))
            }
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
        let Some(ch) = self.chans.get_mut(&h) else {
            return;
        };
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
                    IceConnectionState::Checking if !self.dtls_connected => {
                        self.set_conn("connecting")
                    }
                    IceConnectionState::Disconnected => self.set_conn("disconnected"),
                    IceConnectionState::Connected | IceConnectionState::Completed
                        if self.dtls_connected =>
                    {
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
                    self.emit(PeerEvent::DcOpen {
                        handle: h,
                        id: stream,
                    });
                    self.pending_flush.push(h);
                } else {
                    let config = self
                        .rtc
                        .channel(id)
                        .and_then(|c| c.config().cloned())
                        .unwrap_or_else(|| ChannelConfig {
                            label: label.clone(),
                            ..Default::default()
                        });
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
                    self.emit(PeerEvent::DcOpen {
                        handle: h,
                        id: stream,
                    });
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
                let Some(tx) = self.tx_by_mid(&mid) else {
                    return;
                };
                if d.params.spec().codec == Codec::Tele {
                    // One tone per event: the end report is sent three times
                    // (RFC 4733 section 2.5.1.4); the RTP timestamp identifies the event.
                    let rate = d.params.spec().clock_rate;
                    let start = d.time.numer();
                    let ended = TelephoneEvent::parse(&d.data, rate).filter(|e| e.end);
                    let first_end = ended.is_some() && self.dtmf_in_last.get(&tx) != Some(&start);
                    if let Some(ev) = ended.filter(|_| first_end) {
                        self.dtmf_in_last.insert(tx, start);
                        let c = b"0123456789*#ABCD"
                            .get(ev.event as usize)
                            .map(|b| *b as char)
                            .unwrap_or('?');
                        self.dtmf_in.entry(tx).or_default().push(c);
                    }
                    return;
                }
                let Some(codec) = codec_name(d.params.spec().codec) else {
                    return;
                };
                let keyframe = match (&d.codec_extra, codec) {
                    (_, CodecName::Vp8) => d.data.first().map(|b| b & 1 == 0).unwrap_or(false),
                    (_, CodecName::Opus) => true,
                    _ => false,
                };
                if codec == CodecName::Opus && !self.transform_recv.contains(&tx) {
                    self.play_opus(tx, &d.data, d.contiguous);
                    return;
                }
                if !d.contiguous && codec.kind() == TrackKind::Video {
                    self.request_keyframe(tx);
                }
                let timestamp_us = d.time.numer().saturating_mul(1_000_000) / d.time.denom() as u64;
                self.emit(PeerEvent::MediaFrame(EncodedFrame {
                    tx,
                    codec,
                    keyframe,
                    timestamp_us,
                    data: d.data,
                }));
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
                let open: Vec<DcHandle> = self
                    .chans
                    .iter()
                    .filter(|(_, c)| c.open)
                    .map(|(h, _)| *h)
                    .collect();
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
        for (tx, rx) in &self.audio_receivers {
            let (depth, underruns, trimmed, target) = self
                .audio
                .playout_stats((self.uid, *tx))
                .unwrap_or_default();
            out.insert(
                format!("AIN{tx}"),
                json!({"type": "engine-audio-in", "id": format!("AIN{tx}"), "tx": tx, "packetsReceived": rx.packets,
                       "concealedPackets": rx.concealed, "jitterBufferFrames": depth, "jitterTargetFrames": target, "underruns": underruns, "trimmedFrames": trimmed}),
            );
        }
        for (tx, s) in &self.audio_senders {
            out.insert(
                format!("AOUT{tx}"),
                json!({"type": "engine-audio-out", "id": format!("AOUT{tx}"), "tx": tx, "samplesEncoded": s.samples_sent,
                       "dtmfSent": self.dtmf_sent.get(tx).copied().unwrap_or(0)}),
            );
        }
        for (tx, tones) in &self.dtmf_in {
            out.insert(
                format!("DTMF{tx}"),
                json!({"type": "engine-dtmf-in", "id": format!("DTMF{tx}"), "tx": tx, "tones": tones}),
            );
        }
        serde_json::Value::Object(out)
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn ice_server_urls() {
        let p = |u: &str| parse_ice_url(u).map(|(t, tr, h, port)| (t, tr, h, port));
        assert_eq!(
            p("stun:stun.example.org"),
            Some((false, TurnTransport::Udp, "stun.example.org".into(), 3478))
        );
        assert_eq!(
            p("turn:t.example.org:3479"),
            Some((true, TurnTransport::Udp, "t.example.org".into(), 3479))
        );
        assert_eq!(
            p("turn:t.example.org?transport=udp"),
            Some((true, TurnTransport::Udp, "t.example.org".into(), 3478))
        );
        assert_eq!(
            p("turn:[2001:db8::1]:3478?transport=tcp"),
            Some((true, TurnTransport::Tcp, "2001:db8::1".into(), 3478))
        );
        assert_eq!(
            p("turn:t.example.org?transport=TCP"),
            Some((true, TurnTransport::Tcp, "t.example.org".into(), 3478))
        );
        assert_eq!(p("stuns:s.example.org"), None);
        assert_eq!(
            p("turns:t.example.org:5349?transport=udp"),
            None,
            "DTLS TURN is not supported"
        );
        assert_eq!(p("mailto:x@example.org"), None);
        if turn_stream::TLS_AVAILABLE {
            assert_eq!(
                p("turns:t.example.org"),
                Some((
                    true,
                    TurnTransport::Tls("t.example.org".into()),
                    "t.example.org".into(),
                    5349
                ))
            );
            assert_eq!(
                p("turns:t.example.org:443?transport=tcp"),
                Some((
                    true,
                    TurnTransport::Tls("t.example.org".into()),
                    "t.example.org".into(),
                    443
                ))
            );
        } else {
            assert_eq!(p("turns:t.example.org"), None);
        }
    }
}
