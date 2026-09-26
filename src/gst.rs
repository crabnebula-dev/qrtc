//! GStreamer `webrtcbin` engine.
//!
//! One `gst::Pipeline` holding one `webrtcbin` per peer connection. Signalling
//! calls are bridged from `GstPromise` to blocking calls. Events are forwarded
//! from webrtcbin's own threads to the [`EventSink`].

use crate::*;
use gst::glib;
use gst::prelude::*;
use gstreamer as gst;
use gstreamer_sdp as gst_sdp;
use gstreamer_webrtc as gst_webrtc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

const PROMISE_TIMEOUT: Duration = Duration::from_secs(15);

/// Elements webrtcbin needs at runtime, with the Debian/Ubuntu package that
/// ships each one. Used to give an actionable error instead of a silent hang.
const REQUIRED_ELEMENTS: &[(&str, &str)] = &[
    ("webrtcbin", "gstreamer1.0-plugins-bad"),
    ("nicesrc", "gstreamer1.0-nice"),
    ("nicesink", "gstreamer1.0-nice"),
    ("dtlsdec", "gstreamer1.0-plugins-bad"),
    ("srtpdec", "gstreamer1.0-plugins-bad"),
    ("sctpdec", "gstreamer1.0-plugins-bad"),
    ("rtpbin", "gstreamer1.0-plugins-good"),
];

/// Engine backed by GStreamer `webrtcbin`.
pub struct GstEngine {
    _priv: (),
}

impl GstEngine {
    /// Initialise GStreamer and check that every required element exists.
    pub fn new() -> Result<Self> {
        gst::init().map_err(|e| Error::NotSupported(format!("GStreamer init failed: {e}")))?;
        let missing = missing_elements();
        if !missing.is_empty() {
            return Err(Error::NotSupported(format!(
                "missing GStreamer elements: {}",
                missing.join(", ")
            )));
        }
        Ok(Self { _priv: () })
    }
}

/// Missing elements as `element (package)` strings. Empty when usable.
pub fn missing_elements() -> Vec<String> {
    REQUIRED_ELEMENTS
        .iter()
        .filter(|(el, _)| gst::ElementFactory::find(el).is_none())
        .map(|(el, pkg)| format!("{el} ({pkg})"))
        .collect()
}

impl PeerEngine for GstEngine {
    fn name(&self) -> &'static str {
        "gstreamer-webrtcbin"
    }

    fn create_peer(&self, config: &RtcConfiguration, events: EventSink) -> Result<Box<dyn Peer>> {
        GstPeer::new(config, events).map(|p| Box::new(p) as Box<dyn Peer>)
    }
}

struct Shared {
    events: EventSink,
    next_handle: AtomicU32,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    channels: HashMap<DcHandle, gst_webrtc::WebRTCDataChannel>,
    local: Option<SessionDescription>,
    remote: Option<SessionDescription>,
    local_mids: Vec<Option<String>>,
    remote_mids: Vec<Option<String>>,
    closed: bool,
}

pub struct GstPeer {
    pipeline: gst::Pipeline,
    webrtc: gst::Element,
    shared: Arc<Shared>,
}

/// `HaveLocalOffer` -> `have-local-offer`, matching W3C enum strings.
fn kebab<T: std::fmt::Debug>(v: T) -> String {
    let s = format!("{v:?}");
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Convert a W3C ICE server URL to the form webrtcbin expects.
/// `stun:host:port` -> `stun://host:port`,
/// `turn:host:port?transport=udp` + creds -> `turn://user:pass@host:port?transport=udp`.
fn gst_ice_url(url: &str, username: Option<&str>, credential: Option<&str>) -> Option<String> {
    let (scheme, rest) = url.split_once(':')?;
    let rest = rest.trim_start_matches("//");
    match scheme {
        "stun" | "stuns" => Some(format!("{scheme}://{rest}")),
        "turn" | "turns" => {
            let user = username.map(pct).unwrap_or_default();
            let pass = credential.map(pct).unwrap_or_default();
            Some(format!("{scheme}://{user}:{pass}@{rest}"))
        }
        _ => None,
    }
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn to_gst_desc(desc: &SessionDescription) -> Result<gst_webrtc::WebRTCSessionDescription> {
    let kind = match desc.kind {
        SdpType::Offer => gst_webrtc::WebRTCSDPType::Offer,
        SdpType::Answer => gst_webrtc::WebRTCSDPType::Answer,
        SdpType::Pranswer => gst_webrtc::WebRTCSDPType::Pranswer,
        SdpType::Rollback => return Err(Error::NotSupported("rollback".into())),
    };
    // GStreamer's SDP parser is lenient and accepts arbitrary text. Browsers
    // reject anything without the mandatory session lines, so do the same.
    let lines: Vec<&str> = desc.sdp.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect();
    let has = |p: &str| lines.iter().any(|l| l.starts_with(p));
    if lines.first() != Some(&"v=0") || !has("o=") || !has("s=") || !has("t=") {
        return Err(Error::Operation("Failed to parse SessionDescription".into()));
    }
    let msg = gst_sdp::SDPMessage::parse_buffer(desc.sdp.as_bytes())
        .map_err(|e| Error::Syntax(format!("invalid SDP: {e}")))?;
    Ok(gst_webrtc::WebRTCSessionDescription::new(kind, msg))
}

fn from_gst_desc(desc: &gst_webrtc::WebRTCSessionDescription) -> Result<SessionDescription> {
    let kind = match desc.type_() {
        gst_webrtc::WebRTCSDPType::Offer => SdpType::Offer,
        gst_webrtc::WebRTCSDPType::Answer => SdpType::Answer,
        gst_webrtc::WebRTCSDPType::Pranswer => SdpType::Pranswer,
        _ => SdpType::Rollback,
    };
    let sdp = desc
        .sdp()
        .as_text()
        .map_err(|e| Error::Operation(format!("SDP serialise: {e}")))?;
    Ok(SessionDescription { kind, sdp })
}

/// Run a webrtcbin action that takes a `GstPromise` and wait for the reply.
fn run_promise(f: impl FnOnce(&gst::Promise)) -> Result<Option<gst::Structure>> {
    let (tx, rx) = mpsc::channel();
    let promise = gst::Promise::with_change_func(move |reply| {
        let r = match reply {
            Ok(Some(s)) => Ok(Some(s.to_owned())),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("{e:?}")),
        };
        let _ = tx.send(r);
    });
    f(&promise);
    let reply = rx
        .recv_timeout(PROMISE_TIMEOUT)
        .map_err(|_| Error::Operation("webrtcbin did not answer".into()))?
        .map_err(Error::Operation)?;
    if let Some(s) = &reply {
        if let Ok(err) = s.get::<glib::Error>("error") {
            return Err(Error::Operation(err.message().to_string()));
        }
    }
    Ok(reply)
}

fn dc_info(handle: DcHandle, dc: &gst_webrtc::WebRTCDataChannel) -> DataChannelInfo {
    let opt_u16 = |v: i32| if v >= 0 { u16::try_from(v).ok() } else { None };
    DataChannelInfo {
        handle,
        label: dc.property::<Option<String>>("label").unwrap_or_default(),
        ordered: dc.property::<bool>("ordered"),
        protocol: dc.property::<Option<String>>("protocol").unwrap_or_default(),
        negotiated: dc.property::<bool>("negotiated"),
        id: opt_u16(dc.property::<i32>("id")),
        max_packet_life_time: opt_u16(dc.property::<i32>("max-packet-lifetime")),
        max_retransmits: opt_u16(dc.property::<i32>("max-retransmits")),
    }
}

/// Register a data channel and forward its signals. Returns its handle.
fn wire_channel(shared: &Arc<Shared>, dc: &gst_webrtc::WebRTCDataChannel) -> DcHandle {
    let handle = shared.next_handle.fetch_add(1, Ordering::Relaxed);
    shared.state.lock().unwrap().channels.insert(handle, dc.clone());

    let ev = shared.events.clone();
    dc.connect_on_open(move |dc| {
        let id = dc.property::<i32>("id");
        ev(PeerEvent::DcOpen { handle, id: u16::try_from(id).ok() });
    });
    let ev = shared.events.clone();
    dc.connect_on_close(move |_| ev(PeerEvent::DcClose { handle }));
    let ev = shared.events.clone();
    dc.connect_on_error(move |_, err| {
        ev(PeerEvent::DcError { handle, message: err.message().to_string() })
    });
    let ev = shared.events.clone();
    dc.connect_on_message_string(move |_, s| {
        ev(PeerEvent::DcMessage { handle, payload: Payload::Text(s.unwrap_or_default().to_string()) })
    });
    let ev = shared.events.clone();
    dc.connect_on_message_data(move |_, b| {
        let data = b.map(|b| b.to_vec()).unwrap_or_default();
        ev(PeerEvent::DcMessage { handle, payload: Payload::Binary(data) })
    });
    let ev = shared.events.clone();
    dc.connect_on_buffered_amount_low(move |_| ev(PeerEvent::DcBufferedAmountLow { handle }));
    handle
}

impl GstPeer {
    fn new(config: &RtcConfiguration, events: EventSink) -> Result<Self> {
        let pipeline = gst::Pipeline::new();
        let webrtc = gst::ElementFactory::make("webrtcbin")
            .build()
            .map_err(|e| Error::NotSupported(format!("webrtcbin: {e}")))?;
        webrtc.set_property_from_str(
            "bundle-policy",
            config.bundle_policy.as_deref().unwrap_or("max-bundle"),
        );
        if config.ice_transport_policy.as_deref() == Some("relay") {
            webrtc.set_property_from_str("ice-transport-policy", "relay");
        }
        let mut stun_set = false;
        for server in &config.ice_servers {
            for url in &server.urls {
                let Some(u) = gst_ice_url(url, server.username.as_deref(), server.credential.as_deref())
                else {
                    log::warn!("ignoring unsupported ICE server URL {url}");
                    continue;
                };
                if u.starts_with("stun") {
                    if !stun_set {
                        webrtc.set_property("stun-server", &u);
                        stun_set = true;
                    }
                } else if !webrtc.emit_by_name::<bool>("add-turn-server", &[&u]) {
                    log::warn!("webrtcbin rejected TURN server {url}");
                }
            }
        }
        pipeline
            .add(&webrtc)
            .map_err(|e| Error::Operation(format!("pipeline add: {e}")))?;

        let shared = Arc::new(Shared {
            events,
            next_handle: AtomicU32::new(1),
            state: Mutex::new(State::default()),
        });

        if let Some(bus) = pipeline.bus() {
            // Pipeline errors are logged only. The remote closing its peer
            // connection aborts the SCTP association, which sctpenc reports
            // as an error; browsers do not surface that as a failed state.
            // Real failures reach the page through webrtcbin's own
            // connection-state and data channel close events.
            bus.set_sync_handler(move |_, msg| {
                if let gst::MessageView::Error(err) = msg.view() {
                    log::debug!("webrtcbin pipeline error: {} ({:?})", err.error(), err.debug());
                }
                gst::BusSyncReply::Drop
            });
        }

        let sh = shared.clone();
        webrtc.connect("on-ice-candidate", false, move |vals| {
            let mline = vals[1].get::<u32>().ok()?;
            let candidate = vals[2].get::<String>().ok()?;
            let mid = sh
                .state
                .lock()
                .unwrap()
                .local_mids
                .get(mline as usize)
                .cloned()
                .flatten();
            (sh.events)(PeerEvent::IceCandidate {
                candidate: Some(IceCandidate {
                    candidate,
                    sdp_mid: mid,
                    sdp_m_line_index: Some(mline),
                }),
            });
            None
        });

        let sh = shared.clone();
        webrtc.connect("on-negotiation-needed", false, move |_| {
            (sh.events)(PeerEvent::NegotiationNeeded);
            None
        });

        let sh = shared.clone();
        webrtc.connect("on-data-channel", false, move |vals| {
            let dc = vals[1].get::<gst_webrtc::WebRTCDataChannel>().ok()?;
            let handle = wire_channel(&sh, &dc);
            (sh.events)(PeerEvent::DataChannel { channel: dc_info(handle, &dc) });
            if dc.property::<gst_webrtc::WebRTCDataChannelState>("ready-state")
                == gst_webrtc::WebRTCDataChannelState::Open
            {
                let id = dc.property::<i32>("id");
                (sh.events)(PeerEvent::DcOpen { handle, id: u16::try_from(id).ok() });
            }
            None
        });

        let sh = shared.clone();
        webrtc.connect_notify(Some("ice-gathering-state"), move |el, _| {
            let st = el.property::<gst_webrtc::WebRTCICEGatheringState>("ice-gathering-state");
            (sh.events)(PeerEvent::IceGatheringStateChange { state: kebab(st) });
            if st == gst_webrtc::WebRTCICEGatheringState::Complete {
                (sh.events)(PeerEvent::IceCandidate { candidate: None });
            }
        });
        let sh = shared.clone();
        webrtc.connect_notify(Some("ice-connection-state"), move |el, _| {
            let st = el.property::<gst_webrtc::WebRTCICEConnectionState>("ice-connection-state");
            (sh.events)(PeerEvent::IceConnectionStateChange { state: kebab(st) });
        });
        let sh = shared.clone();
        webrtc.connect_notify(Some("connection-state"), move |el, _| {
            let st = el.property::<gst_webrtc::WebRTCPeerConnectionState>("connection-state");
            (sh.events)(PeerEvent::ConnectionStateChange { state: kebab(st) });
        });
        let sh = shared.clone();
        webrtc.connect_notify(Some("signaling-state"), move |el, _| {
            let st = el.property::<gst_webrtc::WebRTCSignalingState>("signaling-state");
            (sh.events)(PeerEvent::SignalingStateChange { state: kebab(st) });
        });

        pipeline
            .set_state(gst::State::Playing)
            .map_err(|e| Error::Operation(format!("pipeline start: {e}")))?;

        Ok(Self { pipeline, webrtc, shared })
    }

    fn channel(&self, handle: DcHandle) -> Result<gst_webrtc::WebRTCDataChannel> {
        self.shared
            .state
            .lock()
            .unwrap()
            .channels
            .get(&handle)
            .cloned()
            .ok_or_else(|| Error::InvalidState(format!("unknown data channel {handle}")))
    }

    fn ensure_open(&self) -> Result<()> {
        if self.shared.state.lock().unwrap().closed {
            return Err(Error::InvalidState("peer connection is closed".into()));
        }
        Ok(())
    }

    fn create(&self, action: &str, field: &str) -> Result<SessionDescription> {
        self.ensure_open()?;
        let reply = run_promise(|p| {
            self.webrtc.emit_by_name::<()>(action, &[&None::<gst::Structure>, p]);
        })?
        .ok_or_else(|| Error::Operation(format!("{action}: empty reply")))?;
        let desc = reply
            .get::<gst_webrtc::WebRTCSessionDescription>(field)
            .map_err(|e| Error::Operation(format!("{action}: {e}")))?;
        from_gst_desc(&desc)
    }
}

impl Peer for GstPeer {
    fn create_offer(&self) -> Result<SessionDescription> {
        self.create("create-offer", "offer")
    }

    fn create_answer(&self) -> Result<SessionDescription> {
        self.create("create-answer", "answer")
    }

    fn set_local_description(&self, desc: &SessionDescription) -> Result<()> {
        self.ensure_open()?;
        let gdesc = to_gst_desc(desc)?;
        // Store mids first: candidates can fire before the promise resolves.
        self.shared.state.lock().unwrap().local_mids = sdp_mids(&desc.sdp);
        run_promise(|p| {
            self.webrtc.emit_by_name::<()>("set-local-description", &[&gdesc, p]);
        })?;
        self.shared.state.lock().unwrap().local = Some(desc.clone());
        Ok(())
    }

    fn set_remote_description(&self, desc: &SessionDescription) -> Result<()> {
        self.ensure_open()?;
        let gdesc = to_gst_desc(desc)?;
        run_promise(|p| {
            self.webrtc.emit_by_name::<()>("set-remote-description", &[&gdesc, p]);
        })?;
        let mut st = self.shared.state.lock().unwrap();
        st.remote_mids = sdp_mids(&desc.sdp);
        st.remote = Some(desc.clone());
        Ok(())
    }

    fn local_description(&self) -> Option<SessionDescription> {
        self.shared.state.lock().unwrap().local.clone()
    }

    fn remote_description(&self) -> Option<SessionDescription> {
        self.shared.state.lock().unwrap().remote.clone()
    }

    fn add_ice_candidate(&self, c: &IceCandidate) -> Result<()> {
        self.ensure_open()?;
        let cand = c.candidate.trim().trim_start_matches("a=");
        if cand.is_empty() {
            // End-of-candidates: webrtcbin needs no signal for it.
            return Ok(());
        }
        let mline = match (c.sdp_m_line_index, &c.sdp_mid) {
            (Some(i), _) => i,
            (None, Some(mid)) => self
                .shared
                .state
                .lock()
                .unwrap()
                .remote_mids
                .iter()
                .position(|m| m.as_deref() == Some(mid))
                .ok_or_else(|| Error::Operation(format!("unknown sdpMid {mid}")))?
                as u32,
            (None, None) => return Err(Error::Syntax("candidate needs sdpMid or sdpMLineIndex".into())),
        };
        self.webrtc.emit_by_name::<()>("add-ice-candidate", &[&mline, &cand]);
        Ok(())
    }

    fn create_data_channel(&self, label: &str, init: &DataChannelInit) -> Result<DataChannelInfo> {
        self.ensure_open()?;
        if init.max_packet_life_time.is_some() && init.max_retransmits.is_some() {
            return Err(Error::Syntax("maxPacketLifeTime and maxRetransmits are exclusive".into()));
        }
        let mut b = gst::Structure::builder("config").field("ordered", init.ordered.unwrap_or(true));
        if let Some(v) = init.max_packet_life_time {
            b = b.field("max-packet-lifetime", v as i32);
        }
        if let Some(v) = init.max_retransmits {
            b = b.field("max-retransmits", v as i32);
        }
        if let Some(p) = &init.protocol {
            b = b.field("protocol", p);
        }
        if init.negotiated.unwrap_or(false) {
            let id = init
                .id
                .ok_or_else(|| Error::Syntax("negotiated channel needs an id".into()))?;
            b = b.field("negotiated", true).field("id", id as i32);
        }
        let dc = self
            .webrtc
            .emit_by_name::<Option<gst_webrtc::WebRTCDataChannel>>(
                "create-data-channel",
                &[&label, &b.build()],
            )
            .ok_or_else(|| Error::Operation("webrtcbin refused to create the data channel".into()))?;
        let handle = wire_channel(&self.shared, &dc);
        Ok(dc_info(handle, &dc))
    }

    fn dc_send(&self, handle: DcHandle, payload: Payload) -> Result<()> {
        let dc = self.channel(handle)?;
        if dc.property::<gst_webrtc::WebRTCDataChannelState>("ready-state")
            != gst_webrtc::WebRTCDataChannelState::Open
        {
            return Err(Error::InvalidState("data channel is not open".into()));
        }
        let r = match payload {
            Payload::Text(s) => dc.send_string_full(Some(&s)),
            Payload::Binary(v) => dc.send_data_full(Some(&glib::Bytes::from_owned(v))),
        };
        r.map_err(|e| Error::Operation(e.message().to_string()))
    }

    fn dc_buffered_amount(&self, handle: DcHandle) -> Result<u64> {
        Ok(self.channel(handle)?.property::<u64>("buffered-amount"))
    }

    fn dc_set_buffered_amount_low_threshold(&self, handle: DcHandle, threshold: u64) -> Result<()> {
        self.channel(handle)?
            .set_property("buffered-amount-low-threshold", threshold);
        Ok(())
    }

    fn dc_close(&self, handle: DcHandle) -> Result<()> {
        self.channel(handle)?.close();
        Ok(())
    }

    fn stats(&self) -> Result<serde_json::Value> {
        self.ensure_open()?;
        let reply = run_promise(|p| {
            self.webrtc.emit_by_name::<()>("get-stats", &[&None::<gst::Pad>, p]);
        })?;
        let mut out = serde_json::Map::new();
        if let Some(s) = reply {
            for (name, value) in s.iter() {
                let Ok(entry) = value.get::<gst::Structure>() else { continue };
                let mut obj = serde_json::Map::new();
                for (k, v) in entry.iter() {
                    let json = if let Ok(n) = v.get::<f64>() {
                        serde_json::json!(n)
                    } else if let Ok(n) = v.get::<u64>() {
                        serde_json::json!(n)
                    } else if let Ok(n) = v.get::<i64>() {
                        serde_json::json!(n)
                    } else if let Ok(n) = v.get::<u32>() {
                        serde_json::json!(n)
                    } else if let Ok(n) = v.get::<i32>() {
                        serde_json::json!(n)
                    } else if let Ok(b) = v.get::<bool>() {
                        serde_json::json!(b)
                    } else if let Ok(Some(s)) = v.get::<Option<String>>() {
                        serde_json::json!(s)
                    } else if let Ok(t) = v.get::<gst_webrtc::WebRTCStatsType>() {
                        serde_json::json!(kebab(t))
                    } else {
                        continue;
                    };
                    obj.insert(k.to_string(), json);
                }
                out.insert(name.to_string(), serde_json::Value::Object(obj));
            }
        }
        Ok(serde_json::Value::Object(out))
    }

    fn close(&self) {
        let mut st = self.shared.state.lock().unwrap();
        if st.closed {
            return;
        }
        st.closed = true;
        for dc in st.channels.values() {
            dc.close();
        }
        st.channels.clear();
        drop(st);
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

impl Drop for GstPeer {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kebab_matches_w3c() {
        assert_eq!(kebab(gst_webrtc::WebRTCSignalingState::HaveLocalOffer), "have-local-offer");
        assert_eq!(kebab(gst_webrtc::WebRTCPeerConnectionState::Connected), "connected");
    }

    #[test]
    fn ice_urls() {
        assert_eq!(gst_ice_url("stun:stun.l.google.com:19302", None, None).unwrap(), "stun://stun.l.google.com:19302");
        assert_eq!(
            gst_ice_url("turns:t.example:443?transport=tcp", Some("u@x"), Some("p/w")).unwrap(),
            "turns://u%40x:p%2Fw@t.example:443?transport=tcp"
        );
    }

    /// Two webrtcbin peers in one process exchange a data channel message.
    #[test]
    fn loopback_data_channel() {
        let engine = GstEngine::new().expect("GStreamer elements present");
        let (tx_a, rx_a) = mpsc::channel::<PeerEvent>();
        let (tx_b, rx_b) = mpsc::channel::<PeerEvent>();
        let tx_a = Mutex::new(tx_a);
        let tx_b = Mutex::new(tx_b);
        let a = engine
            .create_peer(&RtcConfiguration::default(), Arc::new(move |e| { let _ = tx_a.lock().unwrap().send(e); }))
            .unwrap();
        let b = engine
            .create_peer(&RtcConfiguration::default(), Arc::new(move |e| { let _ = tx_b.lock().unwrap().send(e); }))
            .unwrap();
        let dc = a.create_data_channel("chat", &DataChannelInit::default()).unwrap();
        let offer = a.create_offer().unwrap();
        a.set_local_description(&offer).unwrap();
        b.set_remote_description(&offer).unwrap();
        let answer = b.create_answer().unwrap();
        b.set_local_description(&answer).unwrap();
        a.set_remote_description(&answer).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut a_open = false;
        let mut got = None;
        while std::time::Instant::now() < deadline && got.is_none() {
            while let Ok(e) = rx_a.try_recv() {
                match e {
                    PeerEvent::IceCandidate { candidate: Some(c) } => b.add_ice_candidate(&c).unwrap(),
                    PeerEvent::DcOpen { handle, .. } if handle == dc.handle && !a_open => {
                        a_open = true;
                        a.dc_send(dc.handle, Payload::Text("hello".into())).unwrap();
                    }
                    _ => {}
                }
            }
            while let Ok(e) = rx_b.try_recv() {
                match e {
                    PeerEvent::IceCandidate { candidate: Some(c) } => a.add_ice_candidate(&c).unwrap(),
                    PeerEvent::DcMessage { payload: Payload::Text(t), .. } => got = Some(t),
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(got.as_deref(), Some("hello"));
        a.close();
        b.close();
    }
}
