//! Audio: pure-Rust Opus (rusty-opus) and WebRTC audio processing (sonora
//! AEC3 + NS + AGC2), with an engine-side playout clock.
//!
//! Capture: the page pushes 48 kHz mono PCM per sender. Each 10 ms frame runs
//! through that sender's APM (echo cancellation needs the far-end signal, see
//! below), then 20 ms frames are Opus-encoded and written as RTP.
//!
//! Playout: decoded remote audio enters a per-track jitter queue. A 10 ms
//! clock pops one frame per track, mixes them, feeds the mix to every APM as
//! the far-end reference, and sends each track's PCM to the page, where an
//! AudioWorklet plays it into the track's MediaStreamAudioDestinationNode.

use crate::{EventSink, PeerEvent, TxId};
use rusty_opus::{Application, OpusDecoder, OpusEncoder};
use sonora::config::{EchoCanceller, GainController2, NoiseSuppression};
use sonora::{AudioProcessing, Config, StreamConfig};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) const SR: usize = 48_000;
pub(crate) const F10: usize = 480;
pub(crate) const F20: usize = 960;
/// Initial jitter target in 10 ms frames, and its adaptive bounds.
const START_TARGET: usize = 4;
const MIN_TARGET: usize = 3;
const MAX_TARGET: usize = 16;
/// A stream that has not underrun for this many ticks lowers its target by one.
const STABLE_TICKS: u32 = 1000;

/// Samples per channel at 48 kHz in an Opus packet (RFC 6716 section 3.1).
pub(crate) fn opus_packet_samples(p: &[u8]) -> Option<usize> {
    let toc = *p.first()?;
    let config = toc >> 3;
    let per_frame = match config {
        0..=11 => [480, 960, 1920, 2880][(config % 4) as usize], // SILK 10/20/40/60 ms
        12..=15 => [480, 960][(config % 2) as usize],           // Hybrid 10/20 ms
        _ => [120, 240, 480, 960][(config % 4) as usize],       // CELT 2.5/5/10/20 ms
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => (*p.get(1)? & 0x3F) as usize,
    };
    let n = per_frame * frames;
    (n > 0 && n <= 5760).then_some(n)
}

/// Which processing a capture stream gets.
#[derive(Debug, Clone, Copy)]
pub struct CaptureProcessing {
    pub echo_cancellation: bool,
    pub noise_suppression: bool,
    pub auto_gain_control: bool,
}

impl Default for CaptureProcessing {
    fn default() -> Self {
        Self { echo_cancellation: true, noise_suppression: true, auto_gain_control: true }
    }
}

struct Playout {
    queue: VecDeque<[f32; F10]>,
    started: bool,
    pending: Vec<i16>,
    sink: EventSink,
    tx: TxId,
    underruns: u64,
    trimmed: u64,
    /// Adaptive jitter target: grows on underrun, shrinks after a stable period.
    target: usize,
    stable: u32,
    /// Last frame played, faded out to mask an underrun.
    last: [f32; F10],
}

#[derive(Default)]
struct HubInner {
    apms: HashMap<u64, AudioProcessing>,
    playouts: HashMap<(u64, TxId), Playout>,
}

/// Engine-global audio state shared by all peer connections.
#[derive(Default)]
pub(crate) struct AudioHub {
    inner: Mutex<HubInner>,
}

impl AudioHub {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Start the 10 ms playout clock on the engine runtime.
    pub(crate) fn start_clock(self: &Arc<Self>, rt: &tokio::runtime::Runtime) {
        let hub = Arc::downgrade(self);
        rt.spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(10));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
            loop {
                iv.tick().await;
                let Some(h) = hub.upgrade() else { break };
                h.tick();
            }
        });
    }

    fn tick(&self) {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        let mut mix = [0f32; F10];
        let mut any = false;
        let mut out: Vec<(EventSink, TxId, Vec<i16>)> = Vec::new();
        for p in inner.playouts.values_mut() {
            if !p.started {
                if p.queue.len() < p.target {
                    continue;
                }
                p.started = true;
            }
            // Latency cap: trim a backlog well above the target.
            if p.queue.len() > p.target * 2 + 4 {
                let drop = p.queue.len() - p.target;
                p.queue.drain(..drop);
                p.trimmed += drop as u64;
            }
            let frame = match p.queue.pop_front() {
                Some(f) => {
                    p.stable += 1;
                    if p.stable >= STABLE_TICKS && p.target > MIN_TARGET {
                        p.target -= 1;
                        p.stable = 0;
                    }
                    f
                }
                None => {
                    // Underrun: fade the last frame out instead of a hard gap,
                    // and buffer deeper from now on.
                    p.underruns += 1;
                    p.started = false;
                    p.stable = 0;
                    p.target = (p.target + 2).min(MAX_TARGET);
                    let mut f = p.last;
                    for (i, v) in f.iter_mut().enumerate() {
                        *v *= 1.0 - i as f32 / F10 as f32;
                    }
                    f
                }
            };
            p.last = frame;
            any = true;
            for (m, s) in mix.iter_mut().zip(frame.iter()) {
                *m += *s;
            }
            p.pending.extend(frame.iter().map(|s| (s.clamp(-1.0, 1.0) * 32767.0) as i16));
            if p.pending.len() >= F20 {
                out.push((p.sink.clone(), p.tx, std::mem::take(&mut p.pending)));
            }
        }
        if any {
            for m in mix.iter_mut() {
                *m = m.clamp(-1.0, 1.0);
            }
            for apm in inner.apms.values_mut() {
                let mut dst = [0f32; F10];
                let _ = apm.process_render_f32(&[&mix], &mut [&mut dst]);
            }
        }
        drop(g);
        for (sink, tx, samples) in out {
            sink(PeerEvent::AudioPcm { tx, samples });
        }
    }

    pub(crate) fn add_playout(&self, key: (u64, TxId), sink: EventSink) {
        self.inner.lock().unwrap().playouts.entry(key).or_insert_with(|| Playout {
            queue: VecDeque::new(),
            started: false,
            pending: Vec::new(),
            sink,
            tx: key.1,
            underruns: 0,
            trimmed: 0,
            target: START_TARGET,
            stable: 0,
            last: [0f32; F10],
        });
    }

    pub(crate) fn push_playout(&self, key: (u64, TxId), pcm: &[f32]) {
        let mut g = self.inner.lock().unwrap();
        if let Some(p) = g.playouts.get_mut(&key) {
            for chunk in pcm.chunks_exact(F10) {
                let mut f = [0f32; F10];
                f.copy_from_slice(chunk);
                p.queue.push_back(f);
            }
        }
    }

    pub(crate) fn playout_stats(&self, key: (u64, TxId)) -> Option<(usize, u64, u64, usize)> {
        let g = self.inner.lock().unwrap();
        g.playouts.get(&key).map(|p| (p.queue.len(), p.underruns, p.trimmed, p.target))
    }

    pub(crate) fn remove_pc(&self, pc: u64) {
        let mut g = self.inner.lock().unwrap();
        g.playouts.retain(|k, _| k.0 != pc);
        g.apms.retain(|k, _| (*k >> 32) != pc);
    }

    pub(crate) fn add_apm(&self, key: u64, p: CaptureProcessing) {
        let config = Config {
            echo_canceller: p.echo_cancellation.then(EchoCanceller::default),
            noise_suppression: p.noise_suppression.then(NoiseSuppression::default),
            gain_controller2: p.auto_gain_control.then(GainController2::default),
            ..Default::default()
        };
        let apm = AudioProcessing::builder()
            .config(config)
            .capture_config(StreamConfig::new(SR as u32, 1))
            .render_config(StreamConfig::new(SR as u32, 1))
            .build();
        self.inner.lock().unwrap().apms.insert(key, apm);
    }

    /// Run one 10 ms capture frame through the sender's APM, in place.
    pub(crate) fn capture(&self, key: u64, frame: &mut [f32; F10]) {
        let mut g = self.inner.lock().unwrap();
        if let Some(apm) = g.apms.get_mut(&key) {
            let src = *frame;
            let _ = apm.process_capture_f32(&[&src], &mut [&mut frame[..]]);
        }
    }

    #[cfg(test)]
    pub(crate) fn render_direct(&self, mix: &[f32; F10]) {
        let mut g = self.inner.lock().unwrap();
        for apm in g.apms.values_mut() {
            let mut dst = [0f32; F10];
            let _ = apm.process_render_f32(&[mix], &mut [&mut dst]);
        }
    }
}

/// Per-sender capture state: PCM accumulator, APM key and Opus encoder.
pub(crate) struct AudioSender {
    pub(crate) apm_key: u64,
    acc: Vec<f32>,
    frame20: Vec<f32>,
    enc: OpusEncoder,
    pub(crate) samples_sent: u64,
    pkt: Vec<u8>,
}

impl AudioSender {
    pub(crate) fn new(apm_key: u64) -> Self {
        let mut enc = OpusEncoder::new(SR as i32, 1, Application::Voip).expect("Opus encoder");
        enc.bitrate_bps = 32_000;
        enc.use_inband_fec = true;
        enc.packet_loss_perc = 10;
        Self { apm_key, acc: Vec::with_capacity(F20 * 2), frame20: Vec::with_capacity(F20), enc, samples_sent: 0, pkt: vec![0; 1500] }
    }

    /// Feed PCM; returns encoded 20 ms Opus packets with their start sample.
    pub(crate) fn push(&mut self, hub: &AudioHub, pcm: &[i16]) -> Vec<(u64, Vec<u8>)> {
        self.acc.extend(pcm.iter().map(|s| *s as f32 / 32768.0));
        let mut out = Vec::new();
        while self.acc.len() >= F10 {
            let mut f = [0f32; F10];
            f.copy_from_slice(&self.acc[..F10]);
            self.acc.drain(..F10);
            hub.capture(self.apm_key, &mut f);
            self.frame20.extend_from_slice(&f);
            if self.frame20.len() == F20 {
                match self.enc.encode(&self.frame20, F20, &mut self.pkt) {
                    Ok(n) => out.push((self.samples_sent, self.pkt[..n].to_vec())),
                    Err(e) => log::debug!("opus encode: {e}"),
                }
                self.samples_sent += F20 as u64;
                self.frame20.clear();
            }
        }
        out
    }
}

/// Per-receiver Opus decoder with loss concealment.
pub(crate) struct AudioReceiver {
    dec: OpusDecoder,
    pcm: Vec<f32>,
    pub(crate) packets: u64,
    pub(crate) concealed: u64,
}

impl AudioReceiver {
    pub(crate) fn new() -> Self {
        Self { dec: OpusDecoder::new(SR as i32, 1).expect("Opus decoder"), pcm: vec![0f32; 5760], packets: 0, concealed: 0 }
    }

    /// Decode one packet. When the previous packet was lost (`contiguous ==
    /// false`), first recover it from this packet's in-band FEC (or PLC).
    pub(crate) fn decode(&mut self, packet: &[u8], contiguous: bool) -> Vec<f32> {
        let Some(n) = opus_packet_samples(packet) else { return Vec::new() };
        let mut out = Vec::with_capacity(n * 2);
        if !contiguous && self.packets > 0 {
            if let Ok(m) = self.dec.decode_fec(packet, n, &mut self.pcm) {
                out.extend_from_slice(&self.pcm[..m]);
                self.concealed += 1;
            }
        }
        match self.dec.decode(packet, n, &mut self.pcm) {
            Ok(m) => out.extend_from_slice(&self.pcm[..m]),
            Err(e) => log::debug!("opus decode: {e}"),
        }
        self.packets += 1;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toc_durations() {
        assert_eq!(opus_packet_samples(&[0b0000_1000]), Some(960)); // SILK NB 20 ms, 1 frame
        assert_eq!(opus_packet_samples(&[0b1111_1000]), Some(960)); // CELT FB 20 ms
        assert_eq!(opus_packet_samples(&[0b0001_1001]), Some(5760)); // SILK 60 ms, 2 frames
        assert_eq!(opus_packet_samples(&[0b1110_0011, 3]), Some(360)); // CELT FB 2.5 ms x3
        assert_eq!(opus_packet_samples(&[0b1111_0011, 3]), Some(1440)); // CELT FB 10 ms x3
    }

    fn tone(freq: f32, n: usize, amp: f32) -> Vec<f32> {
        (0..n).map(|i| amp * (2.0 * std::f32::consts::PI * freq * i as f32 / SR as f32).sin()).collect()
    }

    #[test]
    fn opus_roundtrip_keeps_tone() {
        let hub = AudioHub::default();
        let mut tx = AudioSender::new(1); // no APM registered: raw path
        let mut rx = AudioReceiver::new();
        let sig = tone(440.0, SR, 0.3);
        let pcm: Vec<i16> = sig.iter().map(|s| (s * 32767.0) as i16).collect();
        let mut dec = Vec::new();
        for (_, pkt) in tx.push(&hub, &pcm) {
            dec.extend(rx.decode(&pkt, true));
        }
        let rms = (dec[F20 * 10..].iter().map(|v| v * v).sum::<f32>() / (dec.len() - F20 * 10) as f32).sqrt();
        assert!(rms > 0.15, "decoded tone rms {rms}");
    }

    /// Speech-like test signal: gated harmonic bursts with a gliding pitch.
    fn speechish(n: usize, base: f32) -> Vec<f32> {
        let mut phase = 0f32;
        (0..n)
            .map(|i| {
                let t = i as f32 / SR as f32;
                let syll = (t * 3.1).fract();
                let gate = if syll < 0.65 { (syll / 0.65 * std::f32::consts::PI).sin() } else { 0.0 };
                phase += 2.0 * std::f32::consts::PI * base * (1.0 + 0.25 * (t * 1.7).sin()) / SR as f32;
                0.25 * gate * (1..6).map(|h| (phase * h as f32).sin() / h as f32).sum::<f32>()
            })
            .collect()
    }

    fn erle(p: CaptureProcessing) -> f64 {
        let hub = AudioHub::default();
        hub.add_apm(7, p);
        let far = speechish(SR * 8, 140.0);
        let delay = SR * 60 / 1000;
        let (mut in_e, mut out_e) = (0f64, 0f64);
        for f in 0..far.len() / F10 {
            let mut r = [0f32; F10];
            r.copy_from_slice(&far[f * F10..(f + 1) * F10]);
            hub.render_direct(&r);
            let mut cap = [0f32; F10];
            for (i, c) in cap.iter_mut().enumerate() {
                let k = f * F10 + i;
                *c = if k >= delay + 48 { 0.5 * far[k - delay] + 0.2 * far[k - delay - 48] } else { 0.0 };
            }
            let before = cap;
            hub.capture(7, &mut cap);
            if f * F10 > SR * 4 {
                in_e += before.iter().map(|v| (*v as f64).powi(2)).sum::<f64>();
                out_e += cap.iter().map(|v| (*v as f64).powi(2)).sum::<f64>();
            }
        }
        10.0 * (in_e / out_e.max(1e-12)).log10()
    }

    /// Production config (AEC3 + NS) removes a 60 ms room echo.
    #[test]
    fn apm_cancels_echo() {
        let full = erle(CaptureProcessing { echo_cancellation: true, noise_suppression: true, auto_gain_control: false });
        let aec_only = erle(CaptureProcessing { echo_cancellation: true, noise_suppression: false, auto_gain_control: false });
        eprintln!("ERLE: AEC3+NS {full:.1} dB, AEC3 alone {aec_only:.1} dB");
        assert!(full > 20.0, "ERLE {full:.1} dB");
        assert!(aec_only > 20.0, "AEC3 alone {aec_only:.1} dB");
    }
}
