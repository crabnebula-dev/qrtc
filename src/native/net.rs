//! Local interface discovery and host socket binding.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// A bound UDP socket used for host candidates and as the base for
/// server-reflexive and relayed candidates.
pub(crate) struct HostSocket {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) local: SocketAddr,
}

fn usable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_link_local() && !v4.is_multicast(),
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            // Skip link-local (fe80::/10) and unique-local only when a global exists is
            // overkill here; browsers gather both, we skip only link-local.
            !v6.is_unspecified() && !v6.is_multicast() && (seg0 & 0xffc0) != 0xfe80
        }
    }
}

/// Bind one UDP socket per usable interface address. Loopback is used only
/// when nothing else exists (e.g. an isolated CI container).
pub(crate) fn bind_host_sockets() -> std::io::Result<Vec<HostSocket>> {
    let addrs = if_addrs::get_if_addrs()?;
    let mut ips: Vec<IpAddr> = addrs
        .iter()
        .filter(|a| !a.is_loopback())
        .map(|a| a.ip())
        .filter(usable)
        .collect();
    if ips.is_empty() {
        ips = addrs
            .iter()
            .filter(|a| a.is_loopback())
            .map(|a| a.ip())
            .collect();
    }
    ips.sort();
    ips.dedup();
    let mut out = Vec::new();
    for ip in ips {
        let std_sock = match std::net::UdpSocket::bind(SocketAddr::new(ip, 0)) {
            Ok(s) => s,
            Err(e) => {
                log::debug!("skip {ip}: {e}");
                continue;
            }
        };
        std_sock.set_nonblocking(true)?;
        let local = std_sock.local_addr()?;
        let socket = UdpSocket::from_std(std_sock)?;
        out.push(HostSocket {
            socket: Arc::new(socket),
            local,
        });
    }
    Ok(out)
}
