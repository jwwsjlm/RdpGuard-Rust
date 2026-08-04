use std::{collections::HashMap, path::PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::{
    config::Config,
    events::EventSource,
    firewall::Firewall,
    policy::{Action, failure_counts, plan_actions},
    state::{BlockRecord, State, load_state, save_state_atomic},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunReport {
    pub failures: usize,
    pub blocked: usize,
    pub unblocked: usize,
}

pub trait StateStore {
    fn load(&self) -> Result<State>;
    fn save(&mut self, state: &State) -> Result<()>;
}

pub struct FileStateStore {
    path: PathBuf,
}

pub struct MemoryStateStore {
    pub state: State,
}

impl MemoryStateStore {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl StateStore for MemoryStateStore {
    fn load(&self) -> Result<State> {
        Ok(self.state.clone())
    }

    fn save(&mut self, state: &State) -> Result<()> {
        self.state = state.clone();
        Ok(())
    }
}

impl FileStateStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl StateStore for FileStateStore {
    fn load(&self) -> Result<State> {
        load_state(&self.path)
    }

    fn save(&mut self, state: &State) -> Result<()> {
        save_state_atomic(&self.path, state)
    }
}

pub fn run_once<E, F, S>(
    events: &mut E,
    firewall: &mut F,
    store: &mut S,
    now: DateTime<Utc>,
    config: &Config,
) -> Result<RunReport>
where
    E: EventSource,
    F: Firewall,
    S: StateStore,
{
    let mut state = store.load().context("failed to load block state")?;
    let failures = events
        .recent_failures(config.window_minutes)
        .context("failed to read recent RDP failures")?;
    let counts = failure_counts(failures.iter().copied());
    let active: HashMap<_, _> = state
        .blocks
        .iter()
        .map(|(&ip, record)| (ip, record.expires_at))
        .collect();
    let actions = plan_actions(now, &counts, &active, config);
    let mut report = RunReport {
        failures: failures.len(),
        blocked: 0,
        unblocked: 0,
    };

    for action in actions {
        match action {
            Action::Block {
                ip,
                failures,
                expires_at,
            } => {
                firewall
                    .block(ip)
                    .with_context(|| format!("failed to block {ip}"))?;
                let old = state.blocks.insert(
                    ip,
                    BlockRecord {
                        created_at: now,
                        expires_at,
                        failures,
                    },
                );
                if let Err(error) = store.save(&state) {
                    if let Some(record) = old {
                        state.blocks.insert(ip, record);
                    } else {
                        state.blocks.remove(&ip);
                    }
                    let _ = firewall.unblock(ip);
                    return Err(error)
                        .context("failed to persist new block; firewall change rolled back");
                }
                report.blocked += 1;
            }
            Action::Unblock { ip } => {
                firewall
                    .unblock(ip)
                    .with_context(|| format!("failed to unblock {ip}"))?;
                let old = state.blocks.remove(&ip);
                if let Err(error) = store.save(&state) {
                    if let Some(record) = old {
                        state.blocks.insert(ip, record);
                    }
                    let _ = firewall.block(ip);
                    return Err(error)
                        .context("failed to persist unblock; firewall change rolled back");
                }
                report.unblocked += 1;
            }
        }
    }

    Ok(report)
}
