//! Engine abstraction for `tauri-plugin-webrtc`.
//!
//! The plugin core talks only to [`PeerEngine`] and [`Peer`]. The shipped
//! implementation is [`native::NativeEngine`]: pure Rust, built on the sans-I/O
//! str0m stack, with our own JSEP layer, candidate gathering and STUN/TURN.
//!
//! All methods are blocking. Callers on an async runtime should run them on a
//! blocking pool. Events are delivered through an [`EventSink`] from engine
//! threads, in order per peer connection.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod native;

/// Opaque handle for a data channel, unique per peer connection.
///
/// This is not the SCTP stream id, which may be unknown until negotiation.
pub type DcHandle = u32;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Maps to DOMException `InvalidStateError`.
    #[error("InvalidStateError: {0}")]
    InvalidState(String),
    /// Maps to DOMException `OperationError`.
    #[error("OperationError: {0}")]
    Operation(String),
    /// Maps to DOMException `NotSupportedError`.
    #[error("NotSupportedError: {0}")]
    NotSupported(String),
    /// Maps to DOMException `SyntaxError` (bad SDP or candidate).
    #[error("SyntaxError: {0}")]
    Syntax(String),
    /// Maps to DOMException `InvalidModificationError` (munged SDP).
    #[error("InvalidModificationError: {0}")]
    InvalidModification(String),
}

impl Error {
    /// DOMException name the JS shim rethrows.
    pub fn dom_name(&self) -> &'static str {
        match self {
            Error::InvalidState(_) => "InvalidStateError",
            Error::Operation(_) => "OperationError",
            Error::NotSupported(_) => "NotSupportedError",
            Error::Syntax(_) => "SyntaxError",
            Error::InvalidModification(_) => "InvalidModificationError",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IceServer {
    #[serde(deserialize_with = "one_or_many")]
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential: Option<String>,
}

fn one_or_many<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

/// Subset of W3C `RTCConfiguration` the engine honours.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RtcConfiguration {
    #[serde(default)]
    pub ice_servers: Vec<IceServer>,
    /// `"all"` or `"relay"`.
    #[serde(default)]
    pub ice_transport_policy: Option<String>,
    /// `"balanced"`, `"max-compat"` or `"max-bundle"`.
    #[serde(default)]
    pub bundle_policy: Option<String>,
    /// Not W3C: video codecs the page can encode and decode (`"vp8"`,
    /// `"h264"`). The shim probes WebCodecs and fills this in. Absent means
    /// VP8 only.
    #[serde(default)]
    pub video_codecs: Option<Vec<String>>,
}

/// One entry of `RTCRtpTransceiver.setCodecPreferences()` (an
/// RTCRtpCodecCapability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodecPreference {
    pub mime_type: String,
    #[serde(default)]
    pub sdp_fmtp_line: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdpType {
    Offer,
    Pranswer,
    Answer,
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDescription {
    #[serde(rename = "type")]
    pub kind: SdpType,
    pub sdp: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(default)]
    pub sdp_mid: Option<String>,
    #[serde(default)]
    pub sdp_m_line_index: Option<u32>,
}

/// Subset of W3C `RTCDataChannelInit`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataChannelInit {
    #[serde(default)]
    pub ordered: Option<bool>,
    #[serde(default)]
    pub max_packet_life_time: Option<u16>,
    #[serde(default)]
    pub max_retransmits: Option<u16>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub negotiated: Option<bool>,
    #[serde(default)]
    pub id: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataChannelInfo {
    pub handle: DcHandle,
    pub label: String,
    pub ordered: bool,
    pub protocol: String,
    pub negotiated: bool,
    /// SCTP stream id, when known.
    pub id: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub max_retransmits: Option<u16>,
}

/// Transceiver handle. The JS shim allocates ids for transceivers it
/// creates; the engine allocates ids at or above [`REMOTE_TX_BASE`] for
/// transceivers created by a remote offer.
pub type TxId = u32;
pub const REMOTE_TX_BASE: TxId = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrackKind {
    Audio,
    Video,
}

/// W3C `RTCRtpTransceiverDirection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Sendrecv,
    Sendonly,
    Recvonly,
    Inactive,
    Stopped,
}

impl Direction {
    pub fn sends(self) -> bool {
        matches!(self, Direction::Sendrecv | Direction::Sendonly)
    }
    pub fn recvs(self) -> bool {
        matches!(self, Direction::Sendrecv | Direction::Recvonly)
    }
    pub fn from_flags(send: bool, recv: bool) -> Self {
        match (send, recv) {
            (true, true) => Direction::Sendrecv,
            (true, false) => Direction::Sendonly,
            (false, true) => Direction::Recvonly,
            (false, false) => Direction::Inactive,
        }
    }
    /// The same m-line seen from the other side.
    pub fn invert(self) -> Self {
        match self {
            Direction::Sendonly => Direction::Recvonly,
            Direction::Recvonly => Direction::Sendonly,
            d => d,
        }
    }
    pub fn as_sdp(self) -> &'static str {
        match self {
            Direction::Sendrecv => "sendrecv",
            Direction::Sendonly => "sendonly",
            Direction::Recvonly => "recvonly",
            Direction::Inactive | Direction::Stopped => "inactive",
        }
    }
}

/// What the JS side knows about one of its transceivers. Sent whole on
/// every change; the engine treats it as an upsert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransceiverSpec {
    pub id: TxId,
    pub kind: TrackKind,
    pub direction: Direction,
    #[serde(default)]
    pub stream_ids: Vec<String>,
    /// Stable msid track id of the sender (W3C: sender's track id at creation).
    pub sender_track_id: String,
    /// Created by `addTrack` (eligible for association with remote m-lines).
    #[serde(default)]
    pub from_add_track: bool,
    #[serde(default)]
    pub stopped: bool,
    /// From setCodecPreferences(); empty means the default order.
    #[serde(default)]
    pub codec_preferences: Vec<CodecPreference>,
}

/// Negotiation facts the JS side needs to update transceivers and fire
/// `track` / `removetrack` per the W3C algorithms.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransceiverState {
    pub id: TxId,
    pub kind: TrackKind,
    pub mid: Option<String>,
    pub direction: Direction,
    pub current_direction: Option<Direction>,
    /// Direction attribute of the remote m-line, from the remote's perspective.
    pub remote_direction: Option<Direction>,
    pub remote_stream_ids: Vec<String>,
    pub remote_track_id: Option<String>,
    pub created_by_remote: bool,
    pub sender_track_id: String,
    pub stopped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodecName {
    Opus,
    Vp8,
    Vp9,
    H264,
    Av1,
}

impl CodecName {
    pub fn wire_id(self) -> u8 {
        match self {
            CodecName::Vp8 => 1,
            CodecName::Vp9 => 2,
            CodecName::H264 => 3,
            CodecName::Av1 => 4,
            CodecName::Opus => 10,
        }
    }
    pub fn from_wire_id(v: u8) -> Option<Self> {
        Some(match v {
            1 => CodecName::Vp8,
            2 => CodecName::Vp9,
            3 => CodecName::H264,
            4 => CodecName::Av1,
            10 => CodecName::Opus,
            _ => return None,
        })
    }
    pub fn kind(self) -> TrackKind {
        if self == CodecName::Opus {
            TrackKind::Audio
        } else {
            TrackKind::Video
        }
    }
}

/// An encoded frame travelling between the page and the engine.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub tx: TxId,
    pub codec: CodecName,
    pub keyframe: bool,
    /// Capture (send) or RTP (receive) time in microseconds.
    pub timestamp_us: u64,
    pub data: Arc<[u8]>,
}

/// Payload of a data channel message.
#[derive(Debug, Clone)]
pub enum Payload {
    Text(String),
    Binary(Vec<u8>),
}

/// Engine events. Names follow the W3C events they drive in the shim.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PeerEvent {
    /// A local candidate; `None` signals end of candidates.
    IceCandidate {
        candidate: Option<IceCandidate>,
    },
    IceGatheringStateChange {
        state: String,
    },
    IceConnectionStateChange {
        state: String,
    },
    ConnectionStateChange {
        state: String,
    },
    SignalingStateChange {
        state: String,
    },
    NegotiationNeeded,
    /// Remote peer opened a data channel.
    DataChannel {
        channel: DataChannelInfo,
    },
    #[serde(rename = "dc.open")]
    DcOpen {
        handle: DcHandle,
        id: Option<u16>,
    },
    #[serde(rename = "dc.close")]
    DcClose {
        handle: DcHandle,
    },
    #[serde(rename = "dc.error")]
    DcError {
        handle: DcHandle,
        message: String,
    },
    #[serde(rename = "dc.bufferedamountlow")]
    DcBufferedAmountLow {
        handle: DcHandle,
    },
    /// Message payloads are delivered through the raw sink, not serialised.
    #[serde(skip)]
    DcMessage {
        handle: DcHandle,
        payload: Payload,
    },
    /// The remote asked our sender for a keyframe (PLI/FIR).
    KeyframeRequest {
        tx: TxId,
    },
    /// Bandwidth estimate for our outgoing media, in bits per second.
    TargetBitrate {
        bps: u64,
    },
    /// Encoded media received on a transceiver. Raw path, not serialised.
    #[serde(skip)]
    MediaFrame(EncodedFrame),
    /// Decoded 48 kHz mono PCM for a receiver's playout, 20 ms per event.
    /// Raw path, not serialised.
    #[serde(skip)]
    AudioPcm {
        tx: TxId,
        samples: Vec<i16>,
    },
    /// An engine-encoded frame (Opus) for a sender in transform mode. The page
    /// runs it through its `RTCRtpScriptTransform` and returns it with
    /// `send_frame`. Raw path, not serialised.
    #[serde(skip)]
    EncodedOut(EncodedFrame),
}

/// Receives engine events. Called from engine threads.
pub type EventSink = Arc<dyn Fn(PeerEvent) + Send + Sync>;

/// Factory for peer connections.
pub trait PeerEngine: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn create_peer(&self, config: &RtcConfiguration, events: EventSink) -> Result<Box<dyn Peer>>;
}

/// One peer connection. Mirrors `RTCPeerConnection` for the L1 data scope.
pub trait Peer: Send + Sync {
    fn create_offer(&self) -> Result<SessionDescription>;
    fn create_answer(&self) -> Result<SessionDescription>;
    fn set_local_description(&self, desc: &SessionDescription) -> Result<Vec<TransceiverState>>;
    fn set_remote_description(&self, desc: &SessionDescription) -> Result<Vec<TransceiverState>>;
    /// Create or update a transceiver from the JS side.
    fn upsert_transceiver(&self, spec: TransceiverSpec) -> Result<()>;
    /// Send an encoded frame on a transceiver (non-blocking; dropped if the
    /// transceiver cannot send).
    fn send_frame(&self, frame: EncodedFrame) -> Result<()>;
    /// Ask the remote sender on this transceiver for a keyframe.
    fn request_keyframe(&self, tx: TxId) -> Result<()>;
    /// `restartIce()`: the next offer restarts ICE.
    fn restart_ice(&self) -> Result<()>;
    /// Captured 48 kHz mono PCM for an audio sender (non-blocking). The engine
    /// runs echo cancellation, noise suppression and AGC, then encodes Opus.
    fn push_pcm(&self, tx: TxId, samples: Vec<i16>) -> Result<()>;
    /// Route a transceiver's engine-side encoded frames through the page
    /// (`RTCRtpScriptTransform`): `send` for our Opus before RTP, `recv` for
    /// remote Opus before decode. Video is encoded and decoded in the page, so
    /// only audio needs this.
    fn set_transform(&self, tx: TxId, send: bool, recv: bool) -> Result<()>;
    /// Send one DTMF tone as RFC 4733 telephone events on an audio sender.
    /// `event`: 0-9, 10 (*), 11 (#), 12-15 (A-D). Timing between tones is the
    /// caller's (RTCDTMFSender); the engine keeps RFC 4733's 50 ms gap.
    fn insert_dtmf(&self, tx: TxId, event: u8, duration_ms: u32) -> Result<()>;
    /// Capture processing for an audio sender, from its track's settings.
    /// Browsers process microphone tracks only; a WebAudio or file track goes
    /// out untouched.
    fn set_audio_processing(
        &self,
        tx: TxId,
        echo_cancellation: bool,
        noise_suppression: bool,
        auto_gain_control: bool,
    ) -> Result<()>;
    /// Decode a (transformed) received Opus frame into the playout.
    fn decode_audio(&self, tx: TxId, data: Vec<u8>) -> Result<()>;
    fn local_description(&self) -> Option<SessionDescription>;
    fn remote_description(&self) -> Option<SessionDescription>;
    fn add_ice_candidate(&self, candidate: &IceCandidate) -> Result<()>;
    fn create_data_channel(&self, label: &str, init: &DataChannelInit) -> Result<DataChannelInfo>;
    fn dc_send(&self, handle: DcHandle, payload: Payload) -> Result<()>;
    fn dc_buffered_amount(&self, handle: DcHandle) -> Result<u64>;
    fn dc_set_buffered_amount_low_threshold(&self, handle: DcHandle, threshold: u64) -> Result<()>;
    fn dc_close(&self, handle: DcHandle) -> Result<()>;
    /// Minimal stats as JSON (`RTCStatsReport` shaped entries).
    fn stats(&self) -> Result<serde_json::Value>;
    fn close(&self);
}

/// Extract `a=mid:` values per m-line, in order.
pub fn sdp_mids(sdp: &str) -> Vec<Option<String>> {
    let mut mids = Vec::new();
    for line in sdp.lines() {
        let line = line.trim_end();
        if line.starts_with("m=") {
            mids.push(None);
        } else if let Some(mid) = line.strip_prefix("a=mid:") {
            if let Some(last) = mids.last_mut() {
                *last = Some(mid.to_string());
            }
        }
    }
    mids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mids_follow_m_lines() {
        let sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:data\r\n";
        assert_eq!(sdp_mids(sdp), vec![Some("0".into()), Some("data".into())]);
    }

    #[test]
    fn ice_server_urls_accept_string() {
        let s: IceServer = serde_json::from_str(r#"{"urls":"stun:example.org"}"#).unwrap();
        assert_eq!(s.urls, vec!["stun:example.org"]);
    }
}
