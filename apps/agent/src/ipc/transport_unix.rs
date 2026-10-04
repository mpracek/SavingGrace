//! Unix-domain-socket transport. Development and test hosts only:
//! the product targets Windows.

use super::{read_response, spawn_connection, Request, Response, MAX_CONNECTIONS};
use crate::state::Shared;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct IpcEndpoint(pub PathBuf);

impl IpcEndpoint {
    pub fn default_for(dirs: &crate::paths::DataDirs) -> Self {
        Self(dirs.root.join("agent.sock"))
    }
}

impl std::fmt::Display for IpcEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// Binds the endpoint and starts accepting clients until `shutdown` fires.
pub async fn bind(
    endpoint: &IpcEndpoint,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<JoinHandle<()>> {
    // A stale socket from a crashed run must not block startup.
    let _ = std::fs::remove_file(&endpoint.0);
    let listener = UnixListener::bind(&endpoint.0)?;
    std::fs::set_permissions(&endpoint.0, std::fs::Permissions::from_mode(0o600))?;
    let path = endpoint.0.clone();
    let limiter = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => spawn_connection(stream, Arc::clone(&shared), &limiter),
                    Err(e) => tracing::warn!("ipc accept failed: {e}"),
                },
                _ = shutdown.changed() => break,
            }
        }
        let _ = std::fs::remove_file(&path);
    }))
}

pub async fn send_request(endpoint: &IpcEndpoint, req: &Request) -> anyhow::Result<Response> {
    let mut stream = UnixStream::connect(&endpoint.0).await?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    read_response(stream).await
}
