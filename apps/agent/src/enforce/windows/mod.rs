//! Windows implementations of the enforcement backends.
//!
//! NOTE: type-checked via cross-compilation only. None of this has been executed on
//! Windows yet; the first real run is `scripts/smoke-windows.ps1` in CI.

mod dns;
mod registry;
mod wfp;

pub use dns::WindowsDns;
pub use registry::WindowsRegistry;
pub use wfp::WindowsFirewall;

use super::store::RestoreStore;
use super::{Enforcer, PlatformEnforcer};
use crate::paths::DataDirs;

/// The production enforcer: IP Helper + WFP + registry policies.
pub fn platform_enforcer(
    dirs: &DataDirs,
) -> Result<(Box<dyn PlatformEnforcer>, Option<String>), String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot determine the agent path: {e}"))?;
    let (store, warning) = RestoreStore::open(&dirs.root.join("enforcement-state.json"));
    let fw = WindowsFirewall::new(exe);
    Ok((
        Box::new(Enforcer::new(WindowsDns, fw, WindowsRegistry, store)),
        warning,
    ))
}
