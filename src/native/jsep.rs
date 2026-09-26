//! SDP section parsing and the few rewrites our JSEP layer owns.
//!
//! str0m generates the SDP. We rewrite only what W3C semantics decide and
//! str0m cannot know: the direction attribute of each media section (answers
//! narrow str0m's maximal direction to the transceiver's) and `a=msid` (the
//! page's MediaStream and track ids, which Matrix `sdp_stream_metadata` keys on).

use crate::{Direction, TrackKind};

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
        self.msids.iter().map(|(s, _)| s.clone()).filter(|s| s != "-").collect()
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
    let session_dir = session.iter().find_map(|l| dir_attr(l)).unwrap_or(Direction::Sendrecv);
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
            let mut sec = Section { kind, mid: None, direction: session_dir, msids: Vec::new(), port_zero };
            for l in &lines[1..] {
                if let Some(mid) = l.strip_prefix("a=mid:") {
                    sec.mid = Some(mid.to_string());
                } else if let Some(d) = dir_attr(l) {
                    sec.direction = d;
                } else if let Some(v) = l.strip_prefix("a=msid:") {
                    let mut it = v.split_whitespace();
                    if let Some(stream) = it.next() {
                        sec.msids.push((stream.to_string(), it.next().unwrap_or("").to_string()));
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
}

/// Rewrite direction and msid of media sections, keyed by mid.
pub(crate) fn rewrite(sdp: &str, mut f: impl FnMut(&str) -> Option<Rewrite>) -> String {
    let (session, sections) = split(sdp);
    let mut out: Vec<String> = session.iter().map(|s| s.to_string()).collect();
    for lines in sections {
        let is_media = lines[0].starts_with("m=audio") || lines[0].starts_with("m=video");
        let mid = lines.iter().find_map(|l| l.strip_prefix("a=mid:")).map(str::to_string);
        let rw = match (is_media, mid.as_deref()) {
            (true, Some(mid)) => f(mid),
            _ => None,
        };
        let Some(rw) = rw else {
            out.extend(lines.iter().map(|s| s.to_string()));
            continue;
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
            "0" => Some(Rewrite { direction: Direction::Sendonly, msid: Some((vec!["page-stream".into()], "page-track".into())) }),
            "1" => Some(Rewrite { direction: Direction::Inactive, msid: None }),
            _ => None,
        });
        let s = parse(&out);
        assert_eq!(s[0].direction, Direction::Sendonly);
        assert_eq!(s[0].msids, vec![("page-stream".to_string(), "page-track".to_string())]);
        assert!(!out.contains("a=ssrc:1 msid"));
        assert!(out.contains("a=ssrc:1 cname:x"));
        assert_eq!(s[1].direction, Direction::Inactive);
        assert!(out.contains("m=application"));
    }
}
