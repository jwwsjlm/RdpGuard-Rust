use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Utc;

use crate::{
    config::Config,
    engine::{FileStateStore, MemoryStateStore, RunReport, run_once},
    events::WindowsEventSource,
    firewall::{DryRunFirewall, FirewallChange, WindowsFirewall},
    logging,
    policy::Action,
    state::load_state,
};

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config: PathBuf,
    pub state: PathBuf,
    pub log: PathBuf,
}

impl Default for AppPaths {
    fn default() -> Self {
        let root = PathBuf::from(r"C:\ProgramData\RdpGuard");
        Self {
            config: root.join("config.json"),
            state: root.join("state.json"),
            log: root.join("rdpguard.log"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub report: RunReport,
    pub planned_changes: Vec<FirewallChange>,
    pub check_interval_seconds: u64,
}

pub fn execute_once(paths: &AppPaths, dry_run: bool) -> Result<RunOutcome> {
    let config = Config::load(&paths.config)?;
    let mut events = WindowsEventSource;
    let now = Utc::now();

    let outcome = if dry_run {
        let state = load_state(&paths.state)?;
        let mut store = MemoryStateStore::new(state);
        let mut firewall = DryRunFirewall::default();
        let report = run_once(&mut events, &mut firewall, &mut store, now, &config)?;
        RunOutcome {
            report,
            planned_changes: firewall.changes,
            check_interval_seconds: config.check_interval_seconds,
        }
    } else {
        let mut store = FileStateStore::new(paths.state.clone());
        let mut firewall = WindowsFirewall::new()?;
        let report = run_once(&mut events, &mut firewall, &mut store, now, &config)?;
        RunOutcome {
            report,
            planned_changes: Vec::new(),
            check_interval_seconds: config.check_interval_seconds,
        }
    };

    log_run_report(&paths.log, dry_run, &outcome.report)?;
    Ok(outcome)
}

pub fn log_run_report(path: &Path, dry_run: bool, report: &RunReport) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    for action in &report.applied_actions {
        match action {
            Action::Block {
                ip,
                failures,
                expires_at,
            } => logging::append(
                path,
                &format!(
                    "block applied: ip={ip}, failures={failures}, expires_at={}",
                    expires_at.to_rfc3339()
                ),
            )?,
            Action::Unblock { ip } => {
                logging::append(path, &format!("unblock applied: ip={ip}"))?;
            }
        }
    }
    logging::append(
        path,
        &format!(
            "check complete: failures={}, blocked={}, unblocked={}",
            report.failures, report.blocked, report.unblocked
        ),
    )
}
