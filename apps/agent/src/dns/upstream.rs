//! Forwarding to the upstream resolvers over plain UDP/TCP.

use super::filter::Upstream;
use super::Transport;
use std::io;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

pub struct UdpTcpUpstream {
    servers: RwLock<Vec<SocketAddr>>,
    per_server_timeout: Duration,
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "upstream timed out")
}

/// DNS header TC bit (truncated).
fn is_truncated(resp: &[u8]) -> bool {
    resp.len() >= 4 && resp[2] & 0x02 != 0
}

async fn udp_exchange(server: SocketAddr, packet: &[u8], dur: Duration) -> io::Result<Vec<u8>> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("static address");
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    sock.send(packet).await?;
    let mut buf = vec![0u8; 65535];
    timeout(dur, async {
        loop {
            let n = sock.recv(&mut buf).await?;
            // Only accept an answer carrying our transaction id; ignore anything else.
            if n >= 2 && packet.len() >= 2 && buf[..2] == packet[..2] {
                return Ok(buf[..n].to_vec());
            }
        }
    })
    .await
    .map_err(|_| timed_out())?
}

async fn tcp_exchange(server: SocketAddr, packet: &[u8], dur: Duration) -> io::Result<Vec<u8>> {
    let len = u16::try_from(packet.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too large"))?;
    timeout(dur, async {
        let mut s = TcpStream::connect(server).await?;
        let mut framed = len.to_be_bytes().to_vec();
        framed.extend_from_slice(packet);
        s.write_all(&framed).await?;
        let mut lb = [0u8; 2];
        s.read_exact(&mut lb).await?;
        let mut resp = vec![0u8; usize::from(u16::from_be_bytes(lb))];
        s.read_exact(&mut resp).await?;
        Ok(resp)
    })
    .await
    .map_err(|_| timed_out())?
}

impl UdpTcpUpstream {
    pub fn new(servers: Vec<SocketAddr>, per_server_timeout: Duration) -> Self {
        Self {
            servers: RwLock::new(servers),
            per_server_timeout,
        }
    }

    pub fn servers(&self) -> Vec<SocketAddr> {
        self.servers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Replaces the upstream list (network change). An empty list is ignored so a
    /// transient discovery failure never leaves the resolver without upstreams.
    pub fn set_servers(&self, servers: Vec<SocketAddr>) {
        if !servers.is_empty() {
            *self.servers.write().unwrap_or_else(|e| e.into_inner()) = servers;
        }
    }
}

impl Upstream for UdpTcpUpstream {
    async fn query(&self, packet: &[u8], transport: Transport) -> io::Result<Vec<u8>> {
        let servers = self.servers();
        let mut last = io::Error::new(io::ErrorKind::NotConnected, "no upstream DNS servers known");
        for s in servers {
            let r = match transport {
                Transport::Tcp => tcp_exchange(s, packet, self.per_server_timeout).await,
                Transport::Udp => match udp_exchange(s, packet, self.per_server_timeout).await {
                    Ok(resp) if is_truncated(&resp) => {
                        tcp_exchange(s, packet, self.per_server_timeout).await
                    }
                    other => other,
                },
            };
            match r {
                Ok(v) => return Ok(v),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}
