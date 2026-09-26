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

fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<String>, D::Error> {
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
    IceCandidate { candidate: Option<IceCandidate> },
    IceGatheringStateChange { state: String },
    IceConnectionStateChange { state: String },
    ConnectionStateChange { state: String },
    SignalingStateChange { state: String },
    NegotiationNeeded,
    /// Remote peer opened a data channel.
    DataChannel { channel: DataChannelInfo },
    #[serde(rename = "dc.open")]
    DcOpen { handle: DcHandle, id: Option<u16> },
    #[serde(rename = "dc.close")]
    DcClose { handle: DcHandle },
    #[serde(rename = "dc.error")]
    DcError { handle: DcHandle, message: String },
    #[serde(rename = "dc.bufferedamountlow")]
    DcBufferedAmountLow { handle: DcHandle },
    /// Message payloads are delivered through the raw sink, not serialised.
    #[serde(skip)]
    DcMessage { handle: DcHandle, payload: Payload },
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
    fn set_local_description(&self, desc: &SessionDescription) -> Result<()>;
    fn set_remote_description(&self, desc: &SessionDescription) -> Result<()>;
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
