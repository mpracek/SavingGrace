//! Local IPC: newline-delimited JSON over a Windows named pipe (Unix socket on
//! non-Windows development hosts).
//!
//! Phase 2 authorization model: every command is READ-ONLY and carries no
//! secrets, so no caller authentication is needed yet. Commands that change
//! state (lists, temporary disable) arrive in later phases together with an
//! explicit caller-authorization design (see ADR 006).

use crate::rules::Decision;
use crate::state::{Shared, Status};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;

#[cfg(unix)]
mod transport_unix;
#[cfg(windows)]
mod transport_windows;

#[cfg(unix)]
use transport_unix as transport;
#[cfg(windows)]
use transport_windows as transport;

pub use transport::{bind, send_request, IpcEndpoint};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 8 * 1024;
pub const MAX_CONNECTIONS: usize = 16;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    Ping,
    GetStatus,
    /// Evaluates a hostname/URL against the loaded rules. Does not log or persist anything.
    CheckDomain {
        target: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    fn success<T: Serialize>(v: &T) -> Self {
        match serde_json::to_value(v) {
            Ok(result) => Self {
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(_) => Self::failure("internal", "could not serialize result"),
        }
    }

    pub fn failure(code: &str, message: &str) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Pong {
    protocol_version: u32,
    version: &'static str,
}

pub fn handle_request(shared: &Shared, req: &Request) -> Response {
    match req {
        Request::Ping => Response::success(&Pong {
            protocol_version: PROTOCOL_VERSION,
            version: crate::VERSION,
        }),
        Request::GetStatus => Response::success::<Status>(&shared.status()),
        Request::CheckDomain { target } => {
            let decision: Decision = shared.engine().evaluate(target);
            Response::success(&decision)
        }
    }
}

enum Frame {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

/// Reads one `\n`-terminated frame, never buffering more than `max` bytes.
async fn read_frame<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<Frame> {
    let mut buf = Vec::new();
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(if buf.is_empty() {
                Frame::Eof
            } else {
                Frame::Line(buf)
            });
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.unwrap_or(available.len());
        if buf.len() + take > max {
            return Ok(Frame::TooLong);
        }
        buf.extend_from_slice(&available[..take]);
        r.consume(newline.map_or(take, |i| i + 1));
        if newline.is_some() {
            return Ok(Frame::Line(buf));
        }
    }
}

async fn write_response<W: AsyncWrite + Unpin>(w: &mut W, resp: &Response) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(resp).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    bytes.push(b'\n');
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Serves one client until EOF, idle timeout, protocol abuse or I/O error.
pub async fn serve_connection<S>(stream: S, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    loop {
        let frame = match tokio::time::timeout(
            IDLE_TIMEOUT,
            read_frame(&mut reader, MAX_FRAME_BYTES),
        )
        .await
        {
            Ok(Ok(f)) => f,
            Ok(Err(_)) | Err(_) => return,
        };
        let line = match frame {
            Frame::Eof => return,
            Frame::TooLong => {
                let _ = write_response(
                    &mut w,
                    &Response::failure("too_large", "request exceeds the frame limit"),
                )
                .await;
                return;
            }
            Frame::Line(l) => l,
        };
        let resp = match serde_json::from_slice::<Request>(&line) {
            Ok(req) => handle_request(&shared, &req),
            Err(_) => Response::failure("bad_request", "invalid or unknown command"),
        };
        if write_response(&mut w, &resp).await.is_err() {
            return;
        }
    }
}

/// Spawns a handler unless the connection limit is reached.
pub(crate) fn spawn_connection<S>(stream: S, shared: Arc<Shared>, limiter: &Arc<Semaphore>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match Arc::clone(limiter).try_acquire_owned() {
        Ok(permit) => {
            tokio::spawn(async move {
                serve_connection(stream, shared).await;
                drop(permit);
            });
        }
        Err(_) => tracing::warn!("ipc connection limit reached; dropping connection"),
    }
}

/// Reads exactly one response line from a client stream (used by `send_request`).
pub(crate) async fn read_response<R: AsyncRead + Unpin>(r: R) -> anyhow::Result<Response> {
    let mut reader = BufReader::new(r);
    match tokio::time::timeout(Duration::from_secs(5), read_frame(&mut reader, 1024 * 1024)).await {
        Ok(Ok(Frame::Line(l))) => Ok(serde_json::from_slice(&l)?),
        Ok(Ok(_)) => anyhow::bail!("agent closed the connection without a complete response"),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => anyhow::bail!("timed out waiting for the agent"),
    }
}
