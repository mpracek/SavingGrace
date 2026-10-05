//! UDP and TCP listeners for the filtering resolver (loopback only).

use super::filter::{DnsFilter, EngineProvider, Upstream};
use super::Transport;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

const MAX_INFLIGHT_UDP: usize = 256;
const MAX_TCP_CONNECTIONS: usize = 64;
const TCP_IDLE: Duration = Duration::from_secs(10);

pub struct DnsServerHandle {
    /// Addresses actually bound (UDP and TCP both succeeded).
    pub bound: Vec<SocketAddr>,
    /// Addresses that could not be bound, with the reason.
    pub failed: Vec<(String, String)>,
    tasks: Vec<JoinHandle<()>>,
}

impl DnsServerHandle {
    pub fn is_bound(&self, addr_is_v4: bool) -> bool {
        self.bound.iter().any(|a| a.is_ipv4() == addr_is_v4)
    }

    pub async fn join(self) {
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

/// Binds UDP+TCP on every address. Failures are collected, not fatal: the caller
/// decides what is acceptable (for example IPv6 loopback may be unavailable).
pub async fn start<U: Upstream, E: EngineProvider>(
    listen: &[SocketAddr],
    filter: Arc<DnsFilter<U, E>>,
    shutdown: watch::Receiver<bool>,
) -> DnsServerHandle {
    let mut bound = Vec::new();
    let mut failed = Vec::new();
    let mut tasks = Vec::new();

    for addr in listen {
        // Bind UDP first: with port 0 the OS picks the port and TCP must reuse it.
        let udp = match UdpSocket::bind(addr).await {
            Ok(s) => s,
            Err(e) => {
                failed.push((addr.to_string(), format!("udp: {e}")));
                continue;
            }
        };
        let local = match udp.local_addr() {
            Ok(a) => a,
            Err(e) => {
                failed.push((addr.to_string(), e.to_string()));
                continue;
            }
        };
        let tcp = match TcpListener::bind(local).await {
            Ok(l) => l,
            Err(e) => {
                failed.push((addr.to_string(), format!("tcp: {e}")));
                continue;
            }
        };
        bound.push(local);
        tasks.push(tokio::spawn(udp_loop(
            Arc::new(udp),
            Arc::clone(&filter),
            shutdown.clone(),
        )));
        tasks.push(tokio::spawn(tcp_loop(
            tcp,
            Arc::clone(&filter),
            shutdown.clone(),
        )));
    }
    DnsServerHandle {
        bound,
        failed,
        tasks,
    }
}

async fn udp_loop<U: Upstream, E: EngineProvider>(
    sock: Arc<UdpSocket>,
    filter: Arc<DnsFilter<U, E>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let limiter = Arc::new(Semaphore::new(MAX_INFLIGHT_UDP));
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((n, peer)) = r else { continue };
                let packet = buf[..n].to_vec();
                let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
                    super::DnsStats::bump(&filter.stats().dropped_overload);
                    continue;
                };
                let (sock, filter) = (Arc::clone(&sock), Arc::clone(&filter));
                tokio::spawn(async move {
                    if let Some(resp) = filter.handle(&packet, Transport::Udp).await {
                        let _ = sock.send_to(&resp, peer).await;
                    }
                    drop(permit);
                });
            }
            _ = shutdown.changed() => break,
        }
    }
}

async fn tcp_loop<U: Upstream, E: EngineProvider>(
    listener: TcpListener,
    filter: Arc<DnsFilter<U, E>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let limiter = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        tokio::select! {
            r = listener.accept() => {
                let Ok((stream, _)) = r else { continue };
                let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
                    super::DnsStats::bump(&filter.stats().dropped_overload);
                    continue;
                };
                let filter = Arc::clone(&filter);
                tokio::spawn(async move {
                    tcp_connection(stream, filter).await;
                    drop(permit);
                });
            }
            _ = shutdown.changed() => break,
        }
    }
}

async fn tcp_connection<U: Upstream, E: EngineProvider>(
    mut s: tokio::net::TcpStream,
    filter: Arc<DnsFilter<U, E>>,
) {
    loop {
        let mut lb = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, s.read_exact(&mut lb)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let len = usize::from(u16::from_be_bytes(lb));
        if len == 0 {
            return;
        }
        let mut body = vec![0u8; len];
        if tokio::time::timeout(TCP_IDLE, s.read_exact(&mut body))
            .await
            .map_or(true, |r| r.is_err())
        {
            return;
        }
        let Some(resp) = filter.handle(&body, Transport::Tcp).await else {
            return;
        };
        let Ok(rl) = u16::try_from(resp.len()) else {
            return;
        };
        let mut out = rl.to_be_bytes().to_vec();
        out.extend_from_slice(&resp);
        if s.write_all(&out).await.is_err() {
            return;
        }
    }
}
