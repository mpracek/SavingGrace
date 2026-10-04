//! Windows named-pipe transport: `\\.\pipe\savinggrace-agent`.
//!
//! - `first_pipe_instance(true)` fails if another process already owns the name,
//!   which prevents a rogue process from squatting the pipe and impersonating the agent.
//! - `reject_remote_clients(true)`: local clients only.
//! - The pipe uses the default security descriptor of the service account
//!   (SYSTEM and Administrators full control, other users read access). Acceptable
//!   while every command is read-only; see ADR 006.

use super::{read_response, spawn_connection, Request, Response, MAX_CONNECTIONS};
use crate::state::Shared;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

const PIPE_NAME: &str = r"\\.\pipe\savinggrace-agent";
const ERROR_PIPE_BUSY: i32 = 231;

#[derive(Debug, Clone)]
pub struct IpcEndpoint(pub String);

impl IpcEndpoint {
    pub fn default_for(_dirs: &crate::paths::DataDirs) -> Self {
        Self(PIPE_NAME.to_string())
    }
}

impl std::fmt::Display for IpcEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub async fn bind(
    endpoint: &IpcEndpoint,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<JoinHandle<()>> {
    let name = endpoint.0.clone();
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&name)?;
    let limiter = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                connected = server.connect() => {
                    if let Err(e) = connected {
                        tracing::warn!("ipc connect failed: {e}");
                        continue;
                    }
                    let next = match ServerOptions::new().reject_remote_clients(true).create(&name) {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::error!("cannot create next pipe instance: {e}");
                            break;
                        }
                    };
                    let client = std::mem::replace(&mut server, next);
                    spawn_connection(client, Arc::clone(&shared), &limiter);
                }
                _ = shutdown.changed() => break,
            }
        }
    }))
}

pub async fn send_request(endpoint: &IpcEndpoint, req: &Request) -> anyhow::Result<Response> {
    let mut attempts = 0;
    let mut client = loop {
        match ClientOptions::new().open(&endpoint.0) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 20 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    client.write_all(&line).await?;
    read_response(client).await
}
