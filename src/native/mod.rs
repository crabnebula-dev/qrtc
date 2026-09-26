//! Pure Rust engine: str0m for ICE/DTLS/SRTP/SCTP, plus our own JSEP layer,
//! candidate gathering and socket I/O.
//!
//! Each peer connection runs as one task (the *driver*) on a private tokio
//! runtime. The driver owns the `str0m::Rtc`, its sockets and all JSEP state,
//! so str0m's single-mutation invariant is upheld in exactly one place.
//! [`NativePeer`] is a cheap handle that sends commands to the driver.

mod driver;
mod mdns;
mod net;
mod stun;
mod turn;

use crate::*;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::{mpsc, oneshot};

/// Engine that creates pure Rust peer connections.
pub struct NativeEngine {
    rt: tokio::runtime::Runtime,
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
        Ok(Self { rt })
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
            driver::Driver::new(config.clone(), events, shared.clone())?
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
    SetLocal(SessionDescription, Reply<()>),
    SetRemote(SessionDescription, Reply<()>),
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
    fn set_local_description(&self, desc: &SessionDescription) -> Result<()> {
        let d = desc.clone();
        self.call(|r| Cmd::SetLocal(d, r))
    }
    fn set_remote_description(&self, desc: &SessionDescription) -> Result<()> {
        let d = desc.clone();
        self.call(|r| Cmd::SetRemote(d, r))
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
        Ok(self.shared.channels.lock().unwrap().get(&handle).map(|c| c.buffered).unwrap_or(0))
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
        if !self.shared.closed.swap(true, std::sync::atomic::Ordering::SeqCst) {
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
            .create_peer(&RtcConfiguration::default(), Arc::new(move |e| { let _ = tx.lock().unwrap().send(e); }))
            .unwrap();
        (p, rx)
    }

    /// Two native peers in one process exchange data channel messages both ways.
    #[test]
    fn loopback_data_channel() {
        let engine = NativeEngine::new().unwrap();
        let (a, rx_a) = peer(&engine);
        let (b, rx_b) = peer(&engine);
        let dc = a.create_data_channel("chat", &DataChannelInit::default()).unwrap();
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
                    PeerEvent::IceCandidate { candidate: Some(c) } => b.add_ice_candidate(&c).unwrap(),
                    PeerEvent::DcOpen { handle, .. } if handle == dc.handle => {
                        a.dc_send(dc.handle, Payload::Text("hello".into())).unwrap()
                    }
                    PeerEvent::DcMessage { payload: Payload::Binary(v), .. } => a_got = Some(v),
                    _ => {}
                }
            }
            while let Ok(e) = rx_b.try_recv() {
                match e {
                    PeerEvent::IceCandidate { candidate: Some(c) } => a.add_ice_candidate(&c).unwrap(),
                    PeerEvent::DataChannel { channel } => {
                        assert_eq!(channel.label, "chat");
                        b_handle = Some(channel.handle);
                    }
                    PeerEvent::DcMessage { payload: Payload::Text(t), .. } => {
                        b_got = Some(t);
                        b.dc_send(b_handle.unwrap(), Payload::Binary(vec![1, 2, 3])).unwrap();
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

    #[test]
    fn munged_offer_is_rejected() {
        let engine = NativeEngine::new().unwrap();
        let (a, _rx) = peer(&engine);
        a.create_data_channel("x", &DataChannelInit::default()).unwrap();
        let mut offer = a.create_offer().unwrap();
        offer.sdp = offer.sdp.replace("a=setup:actpass", "a=setup:active");
        assert!(matches!(a.set_local_description(&offer), Err(Error::InvalidModification(_))));
    }
}
