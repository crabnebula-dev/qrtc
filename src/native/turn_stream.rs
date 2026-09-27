//! Stream transports to a TURN server: TCP (`turn:...?transport=tcp`) and TLS
//! (`turns:`). The task connects, then moves whole STUN messages and
//! ChannelData frames between the socket and the driver. The TURN state
//! machine itself stays in `turn.rs` and does not know the transport.

use super::turn::stream_frame_len;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FRAME: usize = 65_535 + 20;

/// Stream transport kind of a TURN server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TurnTransport {
    Udp,
    Tcp,
    /// TLS over TCP; the host name is used for SNI and certificate checks.
    Tls(String),
}

/// What the stream task reports to the driver.
pub(crate) enum StreamEvent {
    Connected(SocketAddr),
    Frame(Vec<u8>),
    Closed(String),
}

/// Whether this build can speak TLS to TURN servers.
pub(crate) const TLS_AVAILABLE: bool = cfg!(any(
    feature = "turn-tls-ring",
    feature = "turn-tls-rustcrypto"
));

/// Connect and run until either side closes. `outgoing` carries encoded
/// messages from the TURN client; `report` gets frames and state changes.
pub(crate) async fn run(
    server: SocketAddr,
    transport: TurnTransport,
    pq: crate::PqPolicy,
    mut outgoing: mpsc::UnboundedReceiver<Vec<u8>>,
    report: impl Fn(StreamEvent) + Send + 'static,
) {
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return report(StreamEvent::Closed(format!("connect: {e}"))),
        Err(_) => return report(StreamEvent::Closed("connect: timed out".into())),
    };
    let _ = tcp.set_nodelay(true);
    let local = match tcp.local_addr() {
        Ok(a) => a,
        Err(e) => return report(StreamEvent::Closed(format!("local address: {e}"))),
    };
    match transport {
        TurnTransport::Udp => report(StreamEvent::Closed("not a stream transport".into())),
        TurnTransport::Tcp => {
            report(StreamEvent::Connected(local));
            pump(tcp, &mut outgoing, &report).await
        }
        TurnTransport::Tls(host) => match tls::connect(tcp, &host, pq).await {
            Ok(s) => {
                report(StreamEvent::Connected(local));
                pump(s, &mut outgoing, &report).await
            }
            Err(e) => report(StreamEvent::Closed(format!("TLS: {e}"))),
        },
    }
}

async fn pump<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    outgoing: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    report: &(impl Fn(StreamEvent) + Send),
) {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            msg = outgoing.recv() => match msg {
                Some(m) => {
                    if let Err(e) = wr.write_all(&m).await {
                        return report(StreamEvent::Closed(format!("write: {e}")));
                    }
                }
                None => {
                    // Driver gone: flush what was queued (the deallocation) and close.
                    let _ = wr.flush().await;
                    let _ = wr.shutdown().await;
                    return;
                }
            },
            n = rd.read(&mut chunk) => match n {
                Ok(0) => return report(StreamEvent::Closed("closed by server".into())),
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(len) = stream_frame_len(&buf) {
                        if len > MAX_FRAME {
                            return report(StreamEvent::Closed("framing error".into()));
                        }
                        let rest = buf.split_off(len);
                        report(StreamEvent::Frame(std::mem::replace(&mut buf, rest)));
                    }
                }
                Err(e) => return report(StreamEvent::Closed(format!("read: {e}"))),
            },
        }
    }
}

#[cfg(any(feature = "turn-tls-ring", feature = "turn-tls-rustcrypto"))]
mod tls {
    use crate::PqPolicy;
    use std::sync::{Arc, OnceLock};
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::{self, pki_types::ServerName};

    fn provider(pq: PqPolicy) -> Result<Arc<rustls::crypto::CryptoProvider>, String> {
        #[cfg(feature = "turn-tls-ring")]
        let base = rustls::crypto::ring::default_provider();
        #[cfg(all(feature = "turn-tls-rustcrypto", not(feature = "turn-tls-ring")))]
        let base = rustls_rustcrypto::provider();
        match pq {
            PqPolicy::Off => Ok(Arc::new(base)),
            #[cfg(feature = "_pq")]
            _ => Ok(Arc::new(super::super::pq::tls::with_pq_groups(base, pq))),
            #[cfg(not(feature = "_pq"))]
            _ => Err("postQuantum needs the pq-hybrid or pq-moduletto feature".into()),
        }
    }

    /// Certificates are checked against the platform trust store, with
    /// Mozilla's roots as the fallback when the platform store is empty.
    fn config(pq: PqPolicy) -> Result<Arc<rustls::ClientConfig>, String> {
        type Cell = OnceLock<Result<Arc<rustls::ClientConfig>, String>>;
        static OFF: Cell = OnceLock::new();
        static PREFER: Cell = OnceLock::new();
        static REQUIRE: Cell = OnceLock::new();
        let cell = match pq {
            PqPolicy::Off => &OFF,
            PqPolicy::Prefer => &PREFER,
            PqPolicy::Require => &REQUIRE,
        };
        cell.get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            for e in &native.errors {
                log::debug!("platform certificate store: {e}");
            }
            let (added, _) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            let builder = rustls::ClientConfig::builder_with_provider(provider(pq)?);
            // Post-quantum groups exist only in TLS 1.3.
            let builder = if pq == PqPolicy::Require {
                builder.with_protocol_versions(&[&rustls::version::TLS13])
            } else {
                builder.with_safe_default_protocol_versions()
            };
            let cfg = builder
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            Ok(Arc::new(cfg))
        })
        .clone()
    }

    pub(super) async fn connect(
        tcp: TcpStream,
        host: &str,
        pq: PqPolicy,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
        let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let s = tokio_rustls::TlsConnector::from(config(pq)?)
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let group = s.get_ref().1.negotiated_key_exchange_group().map(|g| g.name());
        log::debug!("TURN TLS {host}: key exchange {group:?}");
        Ok(s)
    }

    /// Post-quantum TLS against an independent implementation. Run by
    /// `tests/pq-tls-interop.mjs`, which starts an OpenSSL 3.5 server
    /// (Node's TLS) offering only X25519MLKEM768 and sets PQ_TLS_PORT and
    /// SSL_CERT_FILE.
    #[cfg(feature = "_pq")]
    #[tokio::test]
    #[ignore]
    async fn post_quantum_against_openssl() {
        let port: u16 = std::env::var("PQ_TLS_PORT").expect("PQ_TLS_PORT").parse().unwrap();
        for (pq, expect) in [
            (PqPolicy::Require, Some("X25519MLKEM768")),
            (PqPolicy::Prefer, Some("X25519MLKEM768")),
            (PqPolicy::Off, None),
        ] {
            let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let r = connect(tcp, "localhost", pq).await;
            let group = r
                .as_ref()
                .ok()
                .and_then(|s| s.get_ref().1.negotiated_key_exchange_group())
                .map(|g| format!("{:?}", g.name()));
            eprintln!("{pq:?}: {:?}", r.as_ref().err().map(String::as_str).or(group.as_deref()));
            match expect {
                Some(g) => assert_eq!(group.as_deref(), Some(g), "{pq:?}"),
                // The server offers only X25519MLKEM768, so classical fails.
                None => assert!(r.is_err(), "{pq:?} should fail"),
            }
        }
    }
}

#[cfg(not(any(feature = "turn-tls-ring", feature = "turn-tls-rustcrypto")))]
mod tls {
    use tokio::net::TcpStream;
    pub(super) async fn connect(_: TcpStream, _: &str, _: crate::PqPolicy) -> Result<TcpStream, String> {
        Err("built without a TLS provider (feature turn-tls-ring or turn-tls-rustcrypto)".into())
    }
}

#[cfg(test)]
mod tests {
    use super::stream_frame_len;

    #[test]
    fn frames_stun_and_padded_channel_data() {
        // STUN header: type, length 4, cookie, tid, then 4 bytes of attributes.
        let mut stun = vec![0x01, 0x01, 0x00, 0x04, 0x21, 0x12, 0xa4, 0x42];
        stun.extend([0u8; 12]);
        stun.extend([0u8; 4]);
        assert_eq!(stream_frame_len(&stun[..10]), None);
        assert_eq!(stream_frame_len(&stun), Some(24));
        // ChannelData with 5 bytes of data is padded to 8 on a stream.
        let chan = [0x40, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5, 0, 0, 0];
        assert_eq!(stream_frame_len(&chan[..9]), None);
        assert_eq!(stream_frame_len(&chan), Some(12));
        let mut both = chan.to_vec();
        both.extend(&stun);
        assert_eq!(stream_frame_len(&both), Some(12));
        assert_eq!(stream_frame_len(&[0xff, 0, 0, 0]), Some(usize::MAX));
    }
}
