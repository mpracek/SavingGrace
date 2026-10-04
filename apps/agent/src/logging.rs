//! Logging foundation. Privacy rule: logs contain lifecycle and error events
//! only, never hostnames or URLs a user visited or that were checked.

use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Keep alive for the lifetime of the process so buffered log lines are flushed.
pub struct LogGuard {
    _file: Option<WorkerGuard>,
}

/// Initializes tracing: daily-rotated file `agent.<date>.log` (14 files kept)
/// and optionally stderr. Level via `SAVINGGRACE_LOG` (default `info`).
/// Never panics: if the log file cannot be set up, logging falls back to stderr only.
pub fn init(logs_dir: &Path, console: bool) -> LogGuard {
    let filter =
        EnvFilter::try_from_env("SAVINGGRACE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    let mut guard = None;
    let file_layer = std::fs::create_dir_all(logs_dir).ok().and_then(|()| {
        tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("agent")
            .filename_suffix("log")
            .max_log_files(14)
            .build(logs_dir)
            .ok()
    });
    let file_layer = file_layer.map(|appender| {
        let (writer, g) = tracing_appender::non_blocking(appender);
        guard = Some(g);
        fmt::layer().with_ansi(false).with_writer(writer)
    });
    let console_layer =
        (console || file_layer.is_none()).then(|| fmt::layer().with_writer(std::io::stderr));

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(console_layer)
        .try_init();

    std::panic::set_hook(Box::new(|info| {
        tracing::error!("panic: {info}");
    }));
    LogGuard { _file: guard }
}
