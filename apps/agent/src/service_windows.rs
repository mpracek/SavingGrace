//! Windows Service integration and (un)installation.
//!
//! NOTE: type-checked on a non-Windows host only; it has NOT been run on Windows yet.
//! The CI job `scripts/smoke-windows.ps1` is the first real execution (see PHASE-02-REPORT.md).

use crate::agent::{self, AgentOptions};
use crate::ipc::IpcEndpoint;
use crate::paths::DataDirs;
use anyhow::{anyhow, Context};
use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "SavingGrace";
const DISPLAY_NAME: &str = "SavingGrace Protection";
const DESCRIPTION: &str = "SavingGrace system agent: rule engine and local management interface.";

define_windows_service!(ffi_service_main, service_main);

/// Called when the Service Control Manager launched us (`savinggrace-agent service`).
pub fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e:#}");
    }
}

fn status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    code: ServiceExitCode,
    checkpoint: u32,
    wait: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: code,
        checkpoint,
        wait_hint: wait,
        process_id: None,
    }
}

fn run_service() -> anyhow::Result<()> {
    let dirs = DataDirs::platform_default().ok_or_else(|| anyhow!("%PROGRAMDATA% is not set"))?;
    let _log = crate::logging::init(&dirs.logs_dir, false);

    // None = running; Some(true) = service Stop (restore system settings); Some(false) = system Shutdown (keep them).
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(None::<bool>);
    let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop => {
            let _ = stop_tx.send(Some(true));
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Shutdown => {
            let _ = stop_tx.send(Some(false));
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        1,
        Duration::from_secs(15),
    ))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result: anyhow::Result<()> = runtime.block_on(async {
        let endpoint = IpcEndpoint::default_for(&dirs);
        let running = agent::start(AgentOptions::new(dirs.clone(), endpoint)).await?;
        handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::Win32(0),
            0,
            Duration::default(),
        ))?;
        let _ = stop_rx.changed().await;
        let restore = (*stop_rx.borrow()).unwrap_or(true);
        handle.set_service_status(status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            1,
            Duration::from_secs(10),
        ))?;
        running.shutdown(restore).await;
        Ok(())
    });

    let exit = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
        0,
        Duration::default(),
    ))?;
    result
}

/// Registers the service (automatic start, restart on failure) and starts it.
/// Must run elevated, from the final install location of the executable.
pub fn install() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("cannot open the service manager (run as Administrator)")?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        // Plain automatic start, deliberately NOT "delayed": delayed start leaves minutes of unprotected time after boot.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(
        &info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    )?;
    service.set_description(DESCRIPTION)?;
    let restart = |secs| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(secs),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(5), restart(5), restart(30)]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.start::<OsString>(&[])?;
    Ok(())
}

/// Stops (if running) and deletes the service. Data in %ProgramData%\SavingGrace is kept.
pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        for _ in 0..50 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    service.delete()?;
    Ok(())
}
