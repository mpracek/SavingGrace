//! SavingGrace system agent library.
//!
//! The binary (`main.rs`) is a thin CLI around this crate. Everything that can
//! be tested without Windows lives here; Windows-only code is behind `cfg(windows)`.

pub mod agent;
pub mod config;
pub mod dns;
pub mod domain;
pub mod enforce;
pub mod ipc;
pub mod logging;
pub mod paths;
pub mod rules;
pub mod state;
pub mod storage;

#[cfg(windows)]
pub mod security_windows;
#[cfg(windows)]
pub mod service_windows;

/// Crate version, reported over IPC.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
