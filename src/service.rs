use std::{
    ffi::OsString,
    sync::mpsc,
    time::{Duration, Instant},
};

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
    config::Config,
    firewall::firewall_policy_status,
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
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
        .context("failed to report pending service status")?;

    let firewall_policy = firewall_policy_status().context("FW001: firewall preflight failed")?;
    if firewall_policy.disabled_profiles != 0 {
        anyhow::bail!(
            "FW005: Windows Firewall is disabled for active profiles 0x{:X}",
            firewall_policy.disabled_profiles
        );
    }
    if !firewall_policy.local_rules_allowed() {
        anyhow::bail!(
            "FW004: local firewall rules are not effective (modify state {})",
            firewall_policy.local_modify_state.0
        );
    }
    let initial = execute_once(paths, false).context("service initialization check failed")?;
    if let Some(warning) = initial.report.warnings.first() {
        anyhow::bail!("service initialization degraded: {warning}");
    }
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

    let config = Config::load(&paths.config)?;
    let heartbeat_interval = Duration::from_secs(config.heartbeat_minutes.saturating_mul(60));
    let log_policy =
        logging::RotationPolicy::from_megabytes(config.max_log_size_mb, config.log_retention_files);
    let mut last_heartbeat = Instant::now()
        .checked_sub(heartbeat_interval)
        .unwrap_or_else(Instant::now);
    let mut last_error: Option<String> = None;
    let mut last_error_log = Instant::now();
    log_health(
        paths,
        &initial.report,
        &mut last_heartbeat,
        heartbeat_interval,
        log_policy,
    );

    loop {
        let check_interval_seconds = match execute_once(paths, false) {
            Ok(outcome) => {
                let error = (!outcome.report.warnings.is_empty())
                    .then(|| outcome.report.warnings.join(" | "));
                match (&last_error, &error) {
                    (Some(previous), None) => {
                        let _ = logging::append_with_policy(
                            &paths.log,
                            &format!("error recovered: {previous}"),
                            log_policy,
                        );
                    }
                    (_, Some(current))
                        if last_error.as_deref() != Some(current)
                            || last_error_log.elapsed() >= heartbeat_interval =>
                    {
                        let _ = logging::append_with_policy(
                            &paths.log,
                            &format!("check degraded: {current}"),
                            log_policy,
                        );
                        last_error_log = Instant::now();
                    }
                    _ => {}
                }
                last_error = error;
                log_health(
                    paths,
                    &outcome.report,
                    &mut last_heartbeat,
                    heartbeat_interval,
                    log_policy,
                );
                outcome.check_interval_seconds
            }
            Err(error) => {
                let current = format!("{error:#}");
                if last_error.as_deref() != Some(&current)
                    || last_error_log.elapsed() >= heartbeat_interval
                {
                    let _ = logging::append_with_policy(
                        &paths.log,
                        &format!("check failed: {current}"),
                        log_policy,
                    );
                    last_error_log = Instant::now();
                }
                last_error = Some(current);
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

fn log_health(
    paths: &AppPaths,
    report: &crate::engine::RunReport,
    last_heartbeat: &mut Instant,
    heartbeat_interval: Duration,
    log_policy: logging::RotationPolicy,
) {
    if last_heartbeat.elapsed() < heartbeat_interval {
        return;
    }
    let _ = logging::append_with_policy(
        &paths.log,
        &format!(
            "health heartbeat: failures={}, blocked={}, unblocked={}, repaired={}, orphans_removed={}, warnings={}",
            report.failures,
            report.blocked,
            report.unblocked,
            report.repaired,
            report.orphans_removed,
            report.warnings.len()
        ),
        log_policy,
    );
    *last_heartbeat = Instant::now();
}
