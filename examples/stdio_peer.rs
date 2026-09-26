//! Engine peer driven by JSON lines on stdin/stdout, for interop tests.
//!
//! `stdio_peer answerer`: waits for `{"op":"offer"}`, answers, echoes every
//! data channel message back on the same channel.
//! `stdio_peer offerer`: creates channel "engine" and an offer, then sends
//! `hello from engine` once it opens, and echoes like the answerer.

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};
use tauri_webrtc_engine::native::NativeEngine;
use tauri_webrtc_engine::*;

fn out(v: Value) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{v}");
    let _ = o.flush();
}

fn main() {
    env_logger::init();
    let role = std::env::args().nth(1).unwrap_or_else(|| "answerer".into());
    let engine = NativeEngine::new().unwrap_or_else(|e| {
        out(json!({"op":"fatal","error":e.to_string()}));
        std::process::exit(2)
    });

    let peer: Arc<Mutex<Option<Arc<dyn Peer>>>> = Arc::new(Mutex::new(None));
    let echo_peer = peer.clone();
    let offerer = role == "offerer";
    let sink: EventSink = Arc::new(move |e: PeerEvent| match e {
        PeerEvent::DcMessage { handle, payload } => {
            let (kind, len) = match &payload {
                Payload::Text(t) => ("text", t.len()),
                Payload::Binary(b) => ("binary", b.len()),
            };
            if let Some(p) = echo_peer.lock().unwrap().clone() {
                if let Err(err) = p.dc_send(handle, payload) {
                    out(json!({"op":"error","where":"echo","error":err.to_string()}));
                }
            }
            if len < 64 || std::env::var("VERBOSE").is_ok() {
                out(json!({"op":"msg","handle":handle,"kind":kind,"len":len}));
            }
        }
        PeerEvent::DcOpen { handle, id } => {
            out(json!({"op":"dc.open","handle":handle,"id":id}));
            if offerer {
                if let Some(p) = echo_peer.lock().unwrap().clone() {
                    let _ = p.dc_send(handle, Payload::Text("hello from engine".into()));
                }
            }
        }
        other => out(json!({"op":"event","event":other})),
    });

    let config: RtcConfiguration = std::env::var("WEBRTC_CONFIG")
        .ok()
        .map(|c| serde_json::from_str(&c).expect("WEBRTC_CONFIG is RTCConfiguration JSON"))
        .unwrap_or_default();
    let p: Arc<dyn Peer> = Arc::from(engine.create_peer(&config, sink).unwrap());
    *peer.lock().unwrap() = Some(p.clone());

    if offerer {
        let info = p
            .create_data_channel("engine", &DataChannelInit::default())
            .unwrap();
        out(json!({"op":"dc.created","channel":info}));
        let offer = p.create_offer().unwrap();
        p.set_local_description(&offer).unwrap();
        out(json!({"op":"offer","sdp":offer.sdp}));
    }

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let r: Result<()> = (|| {
            match v["op"].as_str() {
                Some("offer") => {
                    let d = SessionDescription {
                        kind: SdpType::Offer,
                        sdp: v["sdp"].as_str().unwrap_or_default().into(),
                    };
                    p.set_remote_description(&d)?;
                    let answer = p.create_answer()?;
                    p.set_local_description(&answer)?;
                    out(json!({"op":"answer","sdp":answer.sdp}));
                }
                Some("answer") => {
                    let d = SessionDescription {
                        kind: SdpType::Answer,
                        sdp: v["sdp"].as_str().unwrap_or_default().into(),
                    };
                    p.set_remote_description(&d)?;
                }
                Some("candidate") => {
                    let c: IceCandidate = serde_json::from_value(v["candidate"].clone())
                        .map_err(|e| Error::Syntax(e.to_string()))?;
                    p.add_ice_candidate(&c)?;
                }
                Some("stats") => out(json!({"op":"stats","stats":p.stats()?})),
                Some("close") => {
                    p.close();
                    out(json!({"op":"closed"}));
                    std::process::exit(0);
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(e) = r {
            out(json!({"op":"error","error":e.to_string()}));
        }
    }
}
