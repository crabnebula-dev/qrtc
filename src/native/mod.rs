//! Pure Rust engine: str0m for ICE/DTLS/SRTP/SCTP, plus our own JSEP layer,
//! candidate gathering and socket I/O.
//!
//! Each peer connection runs as one task (the *driver*) on a private tokio
//! runtime. The driver owns the `str0m::Rtc`, its sockets and all JSEP state,
//! so str0m's single-mutation invariant is upheld in exactly one place.
//! [`NativePeer`] is a cheap handle that sends commands to the driver.

mod audio;
mod driver;
mod jsep;
mod mdns;
mod net;
mod stun;
mod turn;
mod turn_stream;

use crate::*;
use audio::CaptureProcessing;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::{mpsc, oneshot};

/// Engine that creates pure Rust peer connections.
pub struct NativeEngine {
    rt: tokio::runtime::Runtime,
    audio: Arc<audio::AudioHub>,
    next_uid: std::sync::atomic::AtomicU64,
}

impl NativeEngine {
    pub fn new() -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("webrtc-engine")
            // str0m's SCTP path uses deep, large frames in debug builds; the
            // 2 MiB tokio default overflowed under data channel load.
            .thread_stack_size(8 * 1024 * 1024)
            .enable_all()
            .build()
            .map_err(|e| Error::NotSupported(format!("engine runtime: {e}")))?;
        let audio = audio::AudioHub::new();
        audio.start_clock(&rt);
        Ok(Self {
            rt,
            audio,
            next_uid: std::sync::atomic::AtomicU64::new(1),
        })
    }
}

impl PeerEngine for NativeEngine {
    fn name(&self) -> &'static str {
        "native-str0m"
    }

    fn create_peer(&self, config: &RtcConfiguration, events: EventSink) -> Result<Box<dyn Peer>> {
        let shared = Arc::new(Shared::default());
        let (tx, rx) = mpsc::unbounded_channel();
        let driver = {
            let _guard = self.rt.enter();
            let uid = self
                .next_uid
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            driver::Driver::new(
                config.clone(),
                events,
                shared.clone(),
                self.audio.clone(),
                uid,
            )?
        };
        self.rt.spawn(driver.run(rx));
        Ok(Box::new(NativePeer { tx, shared }))
    }
}

/// State the driver publishes for synchronous reads from the plugin.
#[derive(Default)]
pub(crate) struct Shared {
    pub(crate) channels: Mutex<HashMap<DcHandle, ChannelShared>>,
    pub(crate) closed: std::sync::atomic::AtomicBool,
}

#[derive(Default, Clone, Copy)]
pub(crate) struct ChannelShared {
    pub(crate) open: bool,
    /// Bytes queued in the driver plus bytes buffered in SCTP.
    pub(crate) buffered: u64,
}

pub(crate) type Reply<T> = oneshot::Sender<Result<T>>;

pub(crate) enum Cmd {
    CreateOffer(Reply<SessionDescription>),
    CreateAnswer(Reply<SessionDescription>),
    SetLocal(SessionDescription, Reply<Vec<TransceiverState>>),
    SetRemote(SessionDescription, Reply<Vec<TransceiverState>>),
    UpsertTx(TransceiverSpec, Reply<()>),
    SendFrame(EncodedFrame),
    RequestKeyframe(TxId),
    RestartIce,
    Pcm(TxId, Vec<i16>),
    Transform(TxId, bool, bool),
    Dtmf(TxId, u8, u32),
    AudioProcessing(TxId, CaptureProcessing),
    DecodeAudio(TxId, Vec<u8>),
    AddIce(IceCandidate, Reply<()>),
    CreateDc(String, DataChannelInit, Reply<DataChannelInfo>),
    DcSend(DcHandle, Payload),
    DcThreshold(DcHandle, u64),
    DcClose(DcHandle),
    Stats(Reply<serde_json::Value>),
    Close,
}

/// Handle to a peer connection driver.
pub struct NativePeer {
    tx: mpsc::UnboundedSender<Cmd>,
    shared: Arc<Shared>,
}

impl NativePeer {
    fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Cmd) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(make(tx))
            .map_err(|_| Error::InvalidState("peer connection is closed".into()))?;
        rx.blocking_recv()
            .map_err(|_| Error::InvalidState("peer connection is closed".into()))?
    }
}

impl Peer for NativePeer {
    fn create_offer(&self) -> Result<SessionDescription> {
        self.call(Cmd::CreateOffer)
    }
    fn create_answer(&self) -> Result<SessionDescription> {
        self.call(Cmd::CreateAnswer)
    }
    fn set_local_description(&self, desc: &SessionDescription) -> Result<Vec<TransceiverState>> {
        let d = desc.clone();
        self.call(|r| Cmd::SetLocal(d, r))
    }
    fn set_remote_description(&self, desc: &SessionDescription) -> Result<Vec<TransceiverState>> {
        let d = desc.clone();
        self.call(|r| Cmd::SetRemote(d, r))
    }
    fn upsert_transceiver(&self, spec: TransceiverSpec) -> Result<()> {
        self.call(|r| Cmd::UpsertTx(spec, r))
    }
    fn send_frame(&self, frame: EncodedFrame) -> Result<()> {
        self.tx
            .send(Cmd::SendFrame(frame))
            .map_err(|_| Error::InvalidState("peer connection is closed".into()))
    }
    fn request_keyframe(&self, tx: TxId) -> Result<()> {
        let _ = self.tx.send(Cmd::RequestKeyframe(tx));
        Ok(())
    }
    fn restart_ice(&self) -> Result<()> {
        let _ = self.tx.send(Cmd::RestartIce);
        Ok(())
    }
    fn push_pcm(&self, tx: TxId, samples: Vec<i16>) -> Result<()> {
        self.tx
            .send(Cmd::Pcm(tx, samples))
            .map_err(|_| Error::InvalidState("peer connection is closed".into()))
    }
    fn set_transform(&self, tx: TxId, send: bool, recv: bool) -> Result<()> {
        let _ = self.tx.send(Cmd::Transform(tx, send, recv));
        Ok(())
    }
    fn insert_dtmf(&self, tx: TxId, event: u8, duration_ms: u32) -> Result<()> {
        if event > 15 {
            return Err(Error::Syntax(format!("DTMF event {event}")));
        }
        let _ = self.tx.send(Cmd::Dtmf(tx, event, duration_ms));
        Ok(())
    }
    fn set_audio_processing(
        &self,
        tx: TxId,
        echo_cancellation: bool,
        noise_suppression: bool,
        auto_gain_control: bool,
    ) -> Result<()> {
        let p = CaptureProcessing {
            echo_cancellation,
            noise_suppression,
            auto_gain_control,
        };
        let _ = self.tx.send(Cmd::AudioProcessing(tx, p));
        Ok(())
    }
    fn decode_audio(&self, tx: TxId, data: Vec<u8>) -> Result<()> {
        let _ = self.tx.send(Cmd::DecodeAudio(tx, data));
        Ok(())
    }
    fn local_description(&self) -> Option<SessionDescription> {
        None
    }
    fn remote_description(&self) -> Option<SessionDescription> {
        None
    }
    fn add_ice_candidate(&self, candidate: &IceCandidate) -> Result<()> {
        let c = candidate.clone();
        self.call(|r| Cmd::AddIce(c, r))
    }
    fn create_data_channel(&self, label: &str, init: &DataChannelInit) -> Result<DataChannelInfo> {
        let (l, i) = (label.to_string(), init.clone());
        self.call(|r| Cmd::CreateDc(l, i, r))
    }
    fn dc_send(&self, handle: DcHandle, payload: Payload) -> Result<()> {
        // Non-blocking: the plugin calls this from async command context.
        {
            let mut chans = self.shared.channels.lock().unwrap();
            let ch = chans
                .get_mut(&handle)
                .ok_or_else(|| Error::InvalidState(format!("unknown data channel {handle}")))?;
            if !ch.open {
                return Err(Error::InvalidState("data channel is not open".into()));
            }
            ch.buffered += match &payload {
                Payload::Text(t) => t.len() as u64,
                Payload::Binary(b) => b.len() as u64,
            };
        }
        self.tx
            .send(Cmd::DcSend(handle, payload))
            .map_err(|_| Error::InvalidState("peer connection is closed".into()))
    }
    fn dc_buffered_amount(&self, handle: DcHandle) -> Result<u64> {
        Ok(self
            .shared
            .channels
            .lock()
            .unwrap()
            .get(&handle)
            .map(|c| c.buffered)
            .unwrap_or(0))
    }
    fn dc_set_buffered_amount_low_threshold(&self, handle: DcHandle, threshold: u64) -> Result<()> {
        let _ = self.tx.send(Cmd::DcThreshold(handle, threshold));
        Ok(())
    }
    fn dc_close(&self, handle: DcHandle) -> Result<()> {
        let _ = self.tx.send(Cmd::DcClose(handle));
        Ok(())
    }
    fn stats(&self) -> Result<serde_json::Value> {
        self.call(Cmd::Stats)
    }
    fn close(&self) {
        if !self
            .shared
            .closed
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            let _ = self.tx.send(Cmd::Close);
        }
    }
}

impl Drop for NativePeer {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc as smpsc;
    use std::time::{Duration, Instant};

    fn peer(engine: &NativeEngine) -> (Box<dyn Peer>, smpsc::Receiver<PeerEvent>) {
        let (tx, rx) = smpsc::channel();
        let tx = Mutex::new(tx);
        let p = engine
            .create_peer(
                &RtcConfiguration::default(),
                Arc::new(move |e| {
                    let _ = tx.lock().unwrap().send(e);
                }),
            )
            .unwrap();
        (p, rx)
    }

    /// Two native peers in one process exchange data channel messages both ways.
    #[test]
    fn loopback_data_channel() {
        let engine = NativeEngine::new().unwrap();
        let (a, rx_a) = peer(&engine);
        let (b, rx_b) = peer(&engine);
        let dc = a
            .create_data_channel("chat", &DataChannelInit::default())
            .unwrap();
        let offer = a.create_offer().unwrap();
        assert!(offer.sdp.contains("m=application"));
        a.set_local_description(&offer).unwrap();
        b.set_remote_description(&offer).unwrap();
        let answer = b.create_answer().unwrap();
        b.set_local_description(&answer).unwrap();
        a.set_remote_description(&answer).unwrap();

        let deadline = Instant::now() + Duration::from_secs(15);
        let (mut a_got, mut b_got, mut b_handle) = (None, None, None);
        while Instant::now() < deadline && (a_got.is_none() || b_got.is_none()) {
            while let Ok(e) = rx_a.try_recv() {
                match e {
                    PeerEvent::IceCandidate { candidate: Some(c) } => {
                        b.add_ice_candidate(&c).unwrap()
                    }
                    PeerEvent::DcOpen { handle, .. } if handle == dc.handle => {
                        a.dc_send(dc.handle, Payload::Text("hello".into())).unwrap()
                    }
                    PeerEvent::DcMessage {
                        payload: Payload::Binary(v),
                        ..
                    } => a_got = Some(v),
                    _ => {}
                }
            }
            while let Ok(e) = rx_b.try_recv() {
                match e {
                    PeerEvent::IceCandidate { candidate: Some(c) } => {
                        a.add_ice_candidate(&c).unwrap()
                    }
                    PeerEvent::DataChannel { channel } => {
                        assert_eq!(channel.label, "chat");
                        b_handle = Some(channel.handle);
                    }
                    PeerEvent::DcMessage {
                        payload: Payload::Text(t),
                        ..
                    } => {
                        b_got = Some(t);
                        b.dc_send(b_handle.unwrap(), Payload::Binary(vec![1, 2, 3]))
                            .unwrap();
                    }
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(b_got.as_deref(), Some("hello"));
        assert_eq!(a_got, Some(vec![1, 2, 3]));
        a.close();
        b.close();
    }

    /// Codec parameter edits are tolerated (matrix-js-sdk adds usedtx=1) and
    /// the edited SDP is what localDescription reports.
    #[test]
    fn fmtp_munging_is_accepted() {
        let engine = NativeEngine::new().unwrap();
        let (a, _rx) = peer(&engine);
        a.upsert_transceiver(crate::TransceiverSpec {
            id: 1,
            kind: TrackKind::Audio,
            direction: crate::Direction::Sendrecv,
            stream_ids: vec!["s".into()],
            sender_track_id: "t".into(),
            from_add_track: true,
            stopped: false,
        })
        .unwrap();
        let mut offer = a.create_offer().unwrap();
        let fmtp = offer
            .sdp
            .lines()
            .find(|l| l.starts_with("a=fmtp:111"))
            .unwrap()
            .to_string();
        offer.sdp = offer.sdp.replace(&fmtp, &format!("{fmtp};usedtx=1"));
        // sdp-transform style re-serialisation: same lines, different order.
        let mut lines: Vec<&str> = offer.sdp.lines().collect();
        let n = lines.len();
        lines.swap(n - 1, n - 2);
        offer.sdp = lines.join("\r\n") + "\r\n";
        a.set_local_description(&offer).unwrap();
        a.close();
    }

    #[test]
    fn munged_offer_is_rejected() {
        let engine = NativeEngine::new().unwrap();
        let (a, _rx) = peer(&engine);
        a.create_data_channel("x", &DataChannelInit::default())
            .unwrap();
        let mut offer = a.create_offer().unwrap();
        offer.sdp = offer.sdp.replace("a=setup:actpass", "a=setup:active");
        assert!(matches!(
            a.set_local_description(&offer),
            Err(Error::InvalidModification(_))
        ));
    }
}

#[cfg(test)]
mod media_tests {
    use super::*;
    use std::sync::mpsc as smpsc;
    use std::time::{Duration, Instant};

    fn fixture() -> Vec<(bool, Vec<u8>)> {
        let raw = include_bytes!("../../tests/fixtures/vp8-160x120.bin");
        let mut out = Vec::new();
        let mut p = 0;
        while p + 5 <= raw.len() {
            let key = raw[p] == 1;
            let len = u32::from_le_bytes(raw[p + 1..p + 5].try_into().unwrap()) as usize;
            out.push((key, raw[p + 5..p + 5 + len].to_vec()));
            p += 5 + len;
        }
        out
    }

    fn peer(engine: &NativeEngine) -> (Box<dyn Peer>, smpsc::Receiver<PeerEvent>) {
        let (tx, rx) = smpsc::channel();
        let tx = Mutex::new(tx);
        let p = engine
            .create_peer(
                &RtcConfiguration::default(),
                Arc::new(move |e| {
                    let _ = tx.lock().unwrap().send(e);
                }),
            )
            .unwrap();
        (p, rx)
    }

    fn spec(
        id: TxId,
        kind: TrackKind,
        dir: Direction,
        stream: &str,
        track: &str,
        from_add_track: bool,
    ) -> TransceiverSpec {
        TransceiverSpec {
            id,
            kind,
            direction: dir,
            stream_ids: vec![stream.into()],
            sender_track_id: track.into(),
            from_add_track,
            stopped: false,
        }
    }

    /// Pump candidates between two peers; return frames each side received.
    fn pump(
        a: &dyn Peer,
        rx_a: &smpsc::Receiver<PeerEvent>,
        b: &dyn Peer,
        rx_b: &smpsc::Receiver<PeerEvent>,
        a_tx: TxId,
        b_tx: TxId,
        secs: u64,
    ) -> (Vec<EncodedFrame>, Vec<EncodedFrame>) {
        let frames = fixture();
        let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
        let start = Instant::now();
        let mut i = 0usize;
        while start.elapsed() < Duration::from_secs(secs) {
            for (rx, other, got) in [(rx_a, b, &mut got_a), (rx_b, a, &mut got_b)] {
                while let Ok(e) = rx.try_recv() {
                    match e {
                        PeerEvent::IceCandidate { candidate: Some(c) } => {
                            other.add_ice_candidate(&c).unwrap()
                        }
                        PeerEvent::MediaFrame(f) => got.push(f),
                        _ => {}
                    }
                }
            }
            // ~15 fps from both sides, looping the fixture (restart = keyframe).
            let (key, data) = &frames[i % frames.len()];
            let ts = (i as u64) * 66_666;
            for (p, tx) in [(a, a_tx), (b, b_tx)] {
                p.send_frame(EncodedFrame {
                    tx,
                    codec: CodecName::Vp8,
                    keyframe: *key,
                    timestamp_us: ts,
                    data: data.clone().into(),
                })
                .unwrap();
            }
            i += 1;
            std::thread::sleep(Duration::from_millis(66));
        }
        (got_a, got_b)
    }

    #[test]
    fn video_both_ways_with_msid() {
        let engine = NativeEngine::new().unwrap();
        let (a, rx_a) = peer(&engine);
        let (b, rx_b) = peer(&engine);
        a.upsert_transceiver(spec(
            1,
            TrackKind::Video,
            Direction::Sendrecv,
            "streamA",
            "trackA",
            true,
        ))
        .unwrap();
        let offer = a.create_offer().unwrap();
        assert!(
            offer.sdp.contains("a=msid:streamA trackA"),
            "offer carries page msid"
        );
        a.set_local_description(&offer).unwrap();

        // matrix-js-sdk inbound flow: setRemote first, then addTrack, then createAnswer.
        let states = b.set_remote_description(&offer).unwrap();
        assert_eq!(states.len(), 1);
        let remote_tx = &states[0];
        assert!(remote_tx.created_by_remote);
        assert_eq!(remote_tx.remote_stream_ids, vec!["streamA".to_string()]);
        assert_eq!(remote_tx.remote_track_id.as_deref(), Some("trackA"));
        let b_tx = remote_tx.id;
        let mut s = spec(
            b_tx,
            TrackKind::Video,
            Direction::Sendrecv,
            "streamB",
            "trackB",
            false,
        );
        s.sender_track_id = remote_tx.sender_track_id.clone();
        s.stream_ids = vec!["streamB".into()];
        b.upsert_transceiver(s.clone()).unwrap();
        let answer = b.create_answer().unwrap();
        assert!(
            answer
                .sdp
                .contains(&format!("a=msid:streamB {}", s.sender_track_id)),
            "answer carries answerer msid"
        );
        assert!(answer.sdp.contains("a=sendrecv"));
        let b_states = b.set_local_description(&answer).unwrap();
        assert_eq!(b_states[0].current_direction, Some(Direction::Sendrecv));
        let a_states = a.set_remote_description(&answer).unwrap();
        assert_eq!(a_states[0].current_direction, Some(Direction::Sendrecv));
        assert_eq!(a_states[0].remote_stream_ids, vec!["streamB".to_string()]);

        let (got_a, got_b) = pump(&*a, &rx_a, &*b, &rx_b, 1, b_tx, 4);
        assert!(got_b.len() > 20, "B received {} frames", got_b.len());
        assert!(got_a.len() > 20, "A received {} frames", got_a.len());
        assert!(got_b.iter().any(|f| f.keyframe) && got_a.iter().any(|f| f.keyframe));
        assert!(got_b
            .iter()
            .all(|f| f.codec == CodecName::Vp8 && f.tx == b_tx));
        // Frame bytes survive packetisation.
        let fx = fixture();
        assert!(got_b.iter().any(|f| &*f.data == fx[0].1.as_slice()));
        a.close();
        b.close();
    }

    #[test]
    fn glare_rolls_back_polite_offer() {
        let engine = NativeEngine::new().unwrap();
        let (a, _ra) = peer(&engine);
        let (b, _rb) = peer(&engine);
        a.upsert_transceiver(spec(
            1,
            TrackKind::Audio,
            Direction::Sendrecv,
            "sa",
            "ta",
            true,
        ))
        .unwrap();
        b.upsert_transceiver(spec(
            1,
            TrackKind::Audio,
            Direction::Sendrecv,
            "sb",
            "tb",
            true,
        ))
        .unwrap();
        let offer_a = a.create_offer().unwrap();
        a.set_local_description(&offer_a).unwrap();
        let offer_b = b.create_offer().unwrap();
        b.set_local_description(&offer_b).unwrap();
        // b is polite: accepts a's offer, implicitly rolling back its own.
        let states = b.set_remote_description(&offer_a).unwrap();
        // b's addTrack transceiver is associated with a's audio m-line, not duplicated.
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].id, 1);
        assert!(!states[0].created_by_remote);
        let answer = b.create_answer().unwrap();
        assert!(answer.sdp.contains("a=msid:sb tb"));
        b.set_local_description(&answer).unwrap();
        a.set_remote_description(&answer).unwrap();
        a.close();
        b.close();
    }

    #[test]
    fn explicit_rollback_of_remote_offer() {
        let engine = NativeEngine::new().unwrap();
        let (a, _ra) = peer(&engine);
        let (b, _rb) = peer(&engine);
        a.upsert_transceiver(spec(
            1,
            TrackKind::Video,
            Direction::Sendonly,
            "s",
            "t",
            true,
        ))
        .unwrap();
        let offer = a.create_offer().unwrap();
        a.set_local_description(&offer).unwrap();
        let st = b.set_remote_description(&offer).unwrap();
        assert_eq!(st.len(), 1);
        let st = b
            .set_local_description(&SessionDescription {
                kind: SdpType::Rollback,
                sdp: String::new(),
            })
            .unwrap();
        assert!(
            st.is_empty(),
            "remote-created transceiver removed on rollback"
        );
    }

    /// DTMF: tones sent with the audio arrive as RFC 4733 events, in order.
    #[test]
    fn dtmf_between_engines() {
        let engine = NativeEngine::new().unwrap();
        let (a, rx_a) = peer(&engine);
        let (b, rx_b) = peer(&engine);
        a.upsert_transceiver(spec(
            1,
            TrackKind::Audio,
            Direction::Sendonly,
            "s",
            "t",
            true,
        ))
        .unwrap();
        let offer = a.create_offer().unwrap();
        assert!(offer.sdp.contains("telephone-event/48000"), "{}", offer.sdp);
        a.set_local_description(&offer).unwrap();
        let st = b.set_remote_description(&offer).unwrap();
        let b_tx = st[0].id;
        let answer = b.create_answer().unwrap();
        assert!(answer.sdp.contains("telephone-event/48000"));
        b.set_local_description(&answer).unwrap();
        a.set_remote_description(&answer).unwrap();
        let start = Instant::now();
        let mut sent = false;
        let mut n = 0u64;
        while start.elapsed() < Duration::from_secs(8) {
            for (rx, other) in [(&rx_a, &*b), (&rx_b, &*a)] {
                while let Ok(e) = rx.try_recv() {
                    if let PeerEvent::IceCandidate { candidate: Some(c) } = e {
                        other.add_ice_candidate(&c).unwrap();
                    }
                }
            }
            // 20 ms of a 440 Hz tone per round.
            let pcm: Vec<i16> = (0..960)
                .map(|i| {
                    (((n * 960 + i) as f32 * 440.0 * 2.0 * std::f32::consts::PI / 48_000.0).sin()
                        * 8000.0) as i16
                })
                .collect();
            n += 1;
            a.push_pcm(1, pcm).unwrap();
            if !sent && start.elapsed() > Duration::from_secs(2) {
                for ev in [1u8, 11, 10, 15] {
                    a.insert_dtmf(1, ev, 100).unwrap();
                }
                sent = true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let stats = b.stats().unwrap();
        let tones = stats[format!("DTMF{b_tx}")]["tones"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_eq!(tones, "1#*D", "received {stats}");
        a.close();
        b.close();
    }

    /// JSEP: createOffer() on an unchanged session re-offers it (LiveKit does this).
    #[test]
    fn reoffer_of_unchanged_session() {
        let engine = NativeEngine::new().unwrap();
        let (a, _ra) = peer(&engine);
        let (b, _rb) = peer(&engine);
        a.upsert_transceiver(spec(
            1,
            TrackKind::Audio,
            Direction::Sendonly,
            "s",
            "t",
            true,
        ))
        .unwrap();
        let offer = a.create_offer().unwrap();
        a.set_local_description(&offer).unwrap();
        b.set_remote_description(&offer).unwrap();
        let answer = b.create_answer().unwrap();
        b.set_local_description(&answer).unwrap();
        a.set_remote_description(&answer).unwrap();
        // Nothing changed, still an offer with the same m-line.
        let again = a.create_offer().unwrap();
        assert_eq!(crate::sdp_mids(&again.sdp), crate::sdp_mids(&offer.sdp));
        a.set_local_description(&again).unwrap();
        b.set_remote_description(&again).unwrap();
        let answer = b.create_answer().unwrap();
        b.set_local_description(&answer).unwrap();
        let st = a.set_remote_description(&answer).unwrap();
        assert_eq!(st[0].current_direction, Some(Direction::Sendonly));
        a.close();
        b.close();
    }
}
