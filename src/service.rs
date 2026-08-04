use std::{ffi::OsString, sync::mpsc, time::Duration};

use anyhow::{Context, Result};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use crate::{
    app::{AppPaths, execute_once},
    logging,
};

pub const SERVICE_NAME: &str = "RdpGuard";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

pub fn run_dispatcher() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    let paths = AppPaths::default();
    if let Err(error) = run_service(&paths) {
        let _ = logging::append(&paths.log, &format!("fatal service error: {error:#}"));
    }
}

fn run_service(paths: &AppPaths) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = shutdown_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)
        .context("failed to register service control handler")?;
    status
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        })
        .context("failed to report running service status")?;

    loop {
        let check_interval_seconds = match execute_once(paths, false) {
            Ok(outcome) => outcome.check_interval_seconds,
            Err(error) => {
                let _ = logging::append(&paths.log, &format!("check failed: {error:#}"));
                60
            }
        };
        match shutdown_rx.recv_timeout(Duration::from_secs(check_interval_seconds)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }

    status
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        })
        .context("failed to report stopped service status")?;
    Ok(())
}
