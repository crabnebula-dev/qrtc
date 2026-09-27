//! SDP section parsing and the few rewrites our JSEP layer owns.
//!
//! str0m generates the SDP. We rewrite only what W3C semantics decide and
//! str0m cannot know: the direction attribute of each media section (answers
//! narrow str0m's maximal direction to the transceiver's) and `a=msid` (the
//! page's MediaStream and track ids, which Matrix `sdp_stream_metadata` keys on),
//! and the payload list when the page called setCodecPreferences().

use crate::{CodecPreference, Direction, TrackKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SectionKind {
    Media(TrackKind),
    Application,
    Other,
}

#[derive(Debug, Clone)]
pub(crate) struct Section {
    pub(crate) kind: SectionKind,
    pub(crate) mid: Option<String>,
    pub(crate) direction: Direction,
    /// `(stream id, track id)` pairs from `a=msid`; stream id `-` means none.
    pub(crate) msids: Vec<(String, String)>,
    pub(crate) port_zero: bool,
}

impl Section {
    pub(crate) fn stream_ids(&self) -> Vec<String> {
        self.msids
            .iter()
            .map(|(s, _)| s.clone())
            .filter(|s| s != "-")
            .collect()
    }
    pub(crate) fn track_id(&self) -> Option<String> {
        self.msids.first().map(|(_, t)| t.clone())
    }
}

fn split(sdp: &str) -> (Vec<&str>, Vec<Vec<&str>>) {
    let mut session = Vec::new();
    let mut sections: Vec<Vec<&str>> = Vec::new();
    for line in sdp.lines().map(str::trim_end).filter(|l| !l.is_empty()) {
        if line.starts_with("m=") {
            sections.push(vec![line]);
        } else if let Some(s) = sections.last_mut() {
            s.push(line);
        } else {
            session.push(line);
        }
    }
    (session, sections)
}

fn dir_attr(line: &str) -> Option<Direction> {
    Some(match line {
        "a=sendrecv" => Direction::Sendrecv,
        "a=sendonly" => Direction::Sendonly,
        "a=recvonly" => Direction::Recvonly,
        "a=inactive" => Direction::Inactive,
        _ => return None,
    })
}

pub(crate) fn parse(sdp: &str) -> Vec<Section> {
    let (session, sections) = split(sdp);
    let session_dir = session
        .iter()
        .find_map(|l| dir_attr(l))
        .unwrap_or(Direction::Sendrecv);
    sections
        .into_iter()
        .map(|lines| {
            let m = lines[0];
            let mut parts = m[2..].split_whitespace();
            let kind = match parts.next() {
                Some("audio") => SectionKind::Media(TrackKind::Audio),
                Some("video") => SectionKind::Media(TrackKind::Video),
                Some("application") => SectionKind::Application,
                _ => SectionKind::Other,
            };
            let port_zero = parts.next() == Some("0");
            let mut sec = Section {
                kind,
                mid: None,
                direction: session_dir,
                msids: Vec::new(),
                port_zero,
            };
            for l in &lines[1..] {
                if let Some(mid) = l.strip_prefix("a=mid:") {
                    sec.mid = Some(mid.to_string());
                } else if let Some(d) = dir_attr(l) {
                    sec.direction = d;
                } else if let Some(v) = l.strip_prefix("a=msid:") {
                    let mut it = v.split_whitespace();
                    if let Some(stream) = it.next() {
                        sec.msids
                            .push((stream.to_string(), it.next().unwrap_or("").to_string()));
                    }
                }
            }
            sec
        })
        .collect()
}

/// What to write into one media section.
pub(crate) struct Rewrite {
    pub(crate) direction: Direction,
    /// `Some((stream_ids, track_id))` when the section sends.
    pub(crate) msid: Option<(Vec<String>, String)>,
    /// setCodecPreferences(): empty keeps str0m's payload list.
    pub(crate) codecs: Vec<CodecPreference>,
}

/// Payload types of one section: `(pt, "kind/name", fmtp)`.
fn payloads<'a>(kind: &str, lines: &[&'a str]) -> Vec<(String, String, &'a str)> {
    let fmtp = |pt: &str| {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(&format!("a=fmtp:{pt} ")[..]))
            .unwrap_or("")
    };
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("a=rtpmap:"))
        .filter_map(|v| {
            let (pt, enc) = v.split_once(' ')?;
            let name = enc.split('/').next()?.to_ascii_lowercase();
            Some((pt.to_string(), format!("{kind}/{name}"), fmtp(pt)))
        })
        .collect()
}

fn fmtp_param<'a>(fmtp: &'a str, key: &str) -> Option<&'a str> {
    fmtp.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v)
}

/// Whether a payload matches a codec preference: same MIME type, and for
/// H.264 the same profile (profile_idc and constraints, not the level) and
/// packetization mode, as in libwebrtc.
fn matches(pref: &CodecPreference, mime: &str, fmtp: &str) -> bool {
    if !pref.mime_type.eq_ignore_ascii_case(mime) {
        return false;
    }
    let Some(want) = pref.sdp_fmtp_line.as_deref() else {
        return true;
    };
    if mime == "video/h264" {
        let profile = |f: &str| {
            fmtp_param(f, "profile-level-id").map(|p| p.get(..4).unwrap_or(p).to_ascii_lowercase())
        };
        let mode = |f: &str| {
            fmtp_param(f, "packetization-mode")
                .unwrap_or("0")
                .to_string()
        };
        return profile(want) == profile(fmtp) && mode(want) == mode(fmtp);
    }
    true
}

/// Reorder and filter the payload types of a media section to follow the
/// preferences (W3C setCodecPreferences). RTX follows its primary codec;
/// RED, ULPFEC, FlexFEC, comfort noise and telephone-event are kept after the
/// chosen codecs. Returns None when no preference matches (keep the section).
fn apply_codec_preferences(
    m_line: &str,
    kind: &str,
    lines: &[&str],
    prefs: &[CodecPreference],
) -> Option<(String, Vec<String>)> {
    let pls = payloads(kind, lines);
    let mut keep: Vec<String> = Vec::new();
    for pref in prefs {
        for (pt, mime, fmtp) in &pls {
            if !keep.contains(pt) && matches(pref, mime, fmtp) && !mime.ends_with("/rtx") {
                keep.push(pt.clone());
            }
        }
    }
    if keep.is_empty() {
        return None;
    }
    let mut ordered: Vec<String> = Vec::new();
    for pt in &keep {
        ordered.push(pt.clone());
        for (rpt, mime, fmtp) in &pls {
            if mime.ends_with("/rtx") && fmtp_param(fmtp, "apt") == Some(pt.as_str()) {
                ordered.push(rpt.clone());
            }
        }
    }
    for (pt, mime, _) in &pls {
        let utility = ["/red", "/ulpfec", "/flexfec-03", "/cn", "/telephone-event"]
            .iter()
            .any(|s| mime.ends_with(s));
        if utility && !ordered.contains(pt) {
            ordered.push(pt.clone());
        }
    }
    let mut parts = m_line.split_whitespace();
    let head: Vec<&str> = parts.by_ref().take(3).collect();
    let m = format!("{} {}", head.join(" "), ordered.join(" "));
    let dropped = |l: &str| {
        ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"].iter().any(|p| {
            l.strip_prefix(p)
                .and_then(|v| v.split(|c: char| c == ' ').next())
                .is_some_and(|pt| pt != "*" && !ordered.iter().any(|o| o == pt))
        })
    };
    Some((
        m,
        lines[1..]
            .iter()
            .filter(|l| !dropped(l))
            .map(|l| l.to_string())
            .collect(),
    ))
}

/// Rewrite direction and msid of media sections, keyed by mid.
pub(crate) fn rewrite(sdp: &str, mut f: impl FnMut(&str) -> Option<Rewrite>) -> String {
    let (session, sections) = split(sdp);
    let mut out: Vec<String> = session.iter().map(|s| s.to_string()).collect();
    for lines in sections {
        let is_media = lines[0].starts_with("m=audio") || lines[0].starts_with("m=video");
        let mid = lines
            .iter()
            .find_map(|l| l.strip_prefix("a=mid:"))
            .map(str::to_string);
        let rw = match (is_media, mid.as_deref()) {
            (true, Some(mid)) => f(mid),
            _ => None,
        };
        let Some(rw) = rw else {
            out.extend(lines.iter().map(|s| s.to_string()));
            continue;
        };
        let kind = if lines[0].starts_with("m=audio") {
            "audio"
        } else {
            "video"
        };
        let owned: Vec<String>;
        let lines: Vec<&str> = match (!rw.codecs.is_empty())
            .then(|| apply_codec_preferences(lines[0], kind, &lines, &rw.codecs))
            .flatten()
        {
            Some((m, rest)) => {
                owned = std::iter::once(m).chain(rest).collect();
                owned.iter().map(String::as_str).collect()
            }
            None => lines,
        };
        let mut wrote = false;
        for l in &lines {
            if dir_attr(l).is_some() {
                out.push(format!("a={}", rw.direction.as_sdp()));
                if let Some((streams, track)) = &rw.msid {
                    if streams.is_empty() {
                        out.push(format!("a=msid:- {track}"));
                    }
                    for s in streams {
                        out.push(format!("a=msid:{s} {track}"));
                    }
                }
                wrote = true;
                continue;
            }
            if l.starts_with("a=msid:") {
                continue;
            }
            if l.starts_with("a=ssrc:") && l.contains(" msid:") {
                continue;
            }
            out.push(l.to_string());
        }
        if !wrote {
            out.push(format!("a={}", rw.direction.as_sdp()));
        }
    }
    let mut s = out.join("\r\n");
    s.push_str("\r\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDP: &str = "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1 2\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendrecv\r\na=msid:s1 t1\r\na=ssrc:1 msid:s1 t1\r\na=ssrc:1 cname:x\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=recvonly\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:2\r\n";

    #[test]
    fn parses_sections() {
        let s = parse(SDP);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].kind, SectionKind::Media(TrackKind::Audio));
        assert_eq!(s[0].mid.as_deref(), Some("0"));
        assert_eq!(s[0].stream_ids(), vec!["s1"]);
        assert_eq!(s[0].track_id().as_deref(), Some("t1"));
        assert_eq!(s[1].direction, Direction::Recvonly);
        assert_eq!(s[2].kind, SectionKind::Application);
    }

    #[test]
    fn rewrites_direction_and_msid() {
        let out = rewrite(SDP, |mid| match mid {
            "0" => Some(Rewrite {
                direction: Direction::Sendonly,
                msid: Some((vec!["page-stream".into()], "page-track".into())),
                codecs: Vec::new(),
            }),
            "1" => Some(Rewrite {
                direction: Direction::Inactive,
                msid: None,
                codecs: Vec::new(),
            }),
            _ => None,
        });
        let s = parse(&out);
        assert_eq!(s[0].direction, Direction::Sendonly);
        assert_eq!(
            s[0].msids,
            vec![("page-stream".to_string(), "page-track".to_string())]
        );
        assert!(!out.contains("a=ssrc:1 msid"));
        assert!(out.contains("a=ssrc:1 cname:x"));
        assert_eq!(s[1].direction, Direction::Inactive);
        assert!(out.contains("m=application"));
    }

    const VIDEO: &str = "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96 97 108 109 127 121\r\na=mid:0\r\na=sendrecv\r\n\
a=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 nack\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\n\
a=rtpmap:108 H264/90000\r\na=rtcp-fb:108 nack\r\na=fmtp:108 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n\
a=rtpmap:109 rtx/90000\r\na=fmtp:109 apt=108\r\n\
a=rtpmap:127 H264/90000\r\na=fmtp:127 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n\
a=rtpmap:121 rtx/90000\r\na=fmtp:121 apt=127\r\n";

    fn pref(mime: &str, fmtp: Option<&str>) -> CodecPreference {
        CodecPreference {
            mime_type: mime.into(),
            sdp_fmtp_line: fmtp.map(Into::into),
        }
    }

    #[test]
    fn codec_preferences_reorder_and_filter() {
        let rw = |codecs: Vec<CodecPreference>| {
            rewrite(VIDEO, move |_| {
                Some(Rewrite {
                    direction: Direction::Sendrecv,
                    msid: None,
                    codecs: codecs.clone(),
                })
            })
        };
        // H.264 constrained baseline first, then VP8; baseline 42001f dropped.
        let out = rw(vec![
            pref(
                "video/H264",
                Some("level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"),
            ),
            pref("video/VP8", None),
        ]);
        assert!(
            out.contains("m=video 9 UDP/TLS/RTP/SAVPF 108 109 96 97\r\n"),
            "{out}"
        );
        assert!(!out.contains("a=rtpmap:127") && !out.contains("a=fmtp:121"));
        assert!(out.contains("a=rtcp-fb:108 nack") && out.contains("a=rtcp-fb:96 nack"));
        // VP8 only.
        let out = rw(vec![pref("video/VP8", None)]);
        assert!(
            out.contains("SAVPF 96 97\r\n") && !out.contains("H264"),
            "{out}"
        );
        // H.264 without fmtp keeps every H.264 payload, in offer order.
        let out = rw(vec![pref("video/h264", None)]);
        assert!(out.contains("SAVPF 108 109 127 121\r\n"), "{out}");
        // Nothing matches: unchanged.
        let out = rw(vec![pref("video/AV1", None)]);
        assert!(out.contains("SAVPF 96 97 108 109 127 121\r\n"));
    }
}
