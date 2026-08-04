use std::{cell::Cell, collections::HashMap, path::PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::{
    config::Config,
    events::EventSource,
    firewall::{Firewall, ManagedRule},
    policy::{Action, block_duration, failure_counts, is_public_unicast, next_repeat_count},
    state::{BlockRecord, RepeatRecord, State, load_state_resilient, save_state_atomic},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub failures: usize,
    pub blocked: usize,
    pub unblocked: usize,
    pub applied_actions: Vec<Action>,
    pub repaired: usize,
    pub orphans_removed: usize,
    pub capacity_dropped: usize,
    pub warnings: Vec<String>,
}

pub trait StateStore {
    fn load(&self) -> Result<State>;
    fn save(&mut self, state: &State) -> Result<()>;

    fn recovered_from_corruption(&self) -> bool {
        false
    }
}

pub struct FileStateStore {
    path: PathBuf,
    recovered: Cell<bool>,
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
        Self {
            path,
            recovered: Cell::new(false),
        }
    }
}

impl StateStore for FileStateStore {
    fn load(&self) -> Result<State> {
        let recovered = load_state_resilient(&self.path)?;
        self.recovered.set(recovered.recovery_pending);
        Ok(recovered.state)
    }

    fn save(&mut self, state: &State) -> Result<()> {
        save_state_atomic(&self.path, state)
    }

    fn recovered_from_corruption(&self) -> bool {
        self.recovered.get()
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
    run_once_observed(events, firewall, store, now, config, |_| Ok(()))
}

pub fn run_once_observed<E, F, S, O>(
    events: &mut E,
    firewall: &mut F,
    store: &mut S,
    now: DateTime<Utc>,
    config: &Config,
    mut observer: O,
) -> Result<RunReport>
where
    E: EventSource,
    F: Firewall,
    S: StateStore,
    O: FnMut(&Action) -> Result<()>,
{
    let mut state = store
        .load()
        .context("STATE001: failed to load block state")?;
    let mut report = RunReport {
        failures: 0,
        blocked: 0,
        unblocked: 0,
        applied_actions: Vec::new(),
        repaired: 0,
        orphans_removed: 0,
        capacity_dropped: 0,
        warnings: Vec::new(),
    };

    let mut inventory = match firewall.managed_rules() {
        Ok(rules) => rules,
        Err(error) => {
            report.warnings.push(format!(
                "FW001: failed to enumerate managed rules: {error:#}"
            ));
            None
        }
    };

    if store.recovered_from_corruption()
        && let Some(rules) = &inventory
    {
        for rule in rules.iter().filter(|rule| rule.expires_at > now) {
            state.blocks.entry(rule.ip).or_insert(BlockRecord {
                created_at: now,
                expires_at: rule.expires_at,
                failures: rule.failures,
            });
            state.repeat_history.entry(rule.ip).or_insert(RepeatRecord {
                count: rule.repeat_count.max(1),
                last_blocked_at: now,
            });
        }
        if let Err(error) = store.save(&state) {
            report.warnings.push(format!(
                "STATE001: failed to persist recovered state: {error:#}"
            ));
        }
    }

    if store.recovered_from_corruption() && inventory.is_none() {
        report.warnings.push(
            "STATE001: state recovery is pending until managed firewall rules can be read"
                .to_owned(),
        );
        return Ok(report);
    }

    let history_before = state.repeat_history.len();
    state
        .repeat_history
        .retain(|ip, _| !config.is_whitelisted(*ip));
    if state.repeat_history.len() != history_before
        && let Err(error) = store.save(&state)
    {
        report.warnings.push(format!(
            "STATE001: failed to clear whitelisted repeat history: {error:#}"
        ));
    }

    let mut remove_ips: Vec<_> = state
        .blocks
        .iter()
        .filter_map(|(&ip, record)| {
            (record.expires_at <= now || config.is_whitelisted(ip)).then_some(ip)
        })
        .collect();
    remove_ips.sort();
    for ip in remove_ips {
        match firewall.unblock(ip) {
            Ok(()) => {
                let old_block = state.blocks.remove(&ip);
                let old_repeat = if config.is_whitelisted(ip) {
                    state.repeat_history.remove(&ip)
                } else {
                    None
                };
                if let Err(error) = store.save(&state) {
                    if let Some(record) = old_block {
                        state.blocks.insert(ip, record);
                    }
                    if let Some(record) = old_repeat {
                        state.repeat_history.insert(ip, record);
                    }
                    report.warnings.push(format!(
                        "STATE001: failed to persist unblock for {ip}: {error:#}"
                    ));
                    continue;
                }
                report.unblocked += 1;
                if let Some(rules) = &mut inventory {
                    rules.retain(|rule| rule.ip != ip);
                }
                report.applied_actions.push(Action::Unblock { ip });
                if let Err(error) = observer(report.applied_actions.last().unwrap()) {
                    report.warnings.push(format!(
                        "LOG001: failed to record unblock for {ip}: {error:#}"
                    ));
                }
            }
            Err(error) => report
                .warnings
                .push(format!("FW001: failed to unblock {ip}: {error:#}")),
        }
    }

    if let Some(rules) = inventory {
        let by_ip: HashMap<_, _> = rules.into_iter().map(|rule| (rule.ip, rule)).collect();
        let mut active_ips: Vec<_> = state.blocks.keys().copied().collect();
        active_ips.sort();
        for ip in active_ips {
            let record = &state.blocks[&ip];
            let desired = managed_rule(ip, record, &state, config);
            if by_ip.get(&ip) != Some(&desired) {
                match firewall.apply_rule(&desired) {
                    Ok(()) => report.repaired += 1,
                    Err(error) => report
                        .warnings
                        .push(format!("FW001: failed to repair rule for {ip}: {error:#}")),
                }
            }
        }
        let mut orphans: Vec<_> = by_ip
            .keys()
            .filter(|ip| !state.blocks.contains_key(ip))
            .copied()
            .collect();
        orphans.sort();
        for ip in orphans {
            match firewall.unblock(ip) {
                Ok(()) => report.orphans_removed += 1,
                Err(error) => report.warnings.push(format!(
                    "FW001: failed to remove orphan rule for {ip}: {error:#}"
                )),
            }
        }
    }

    let failures = match events.recent_failures(config.window_minutes) {
        Ok(failures) => failures,
        Err(error) => {
            report.warnings.push(format!(
                "EVT001: failed to read recent RDP failures: {error:#}"
            ));
            return Ok(report);
        }
    };
    report.failures = failures.len();
    let counts = failure_counts(failures);
    let mut candidates: Vec<_> = counts
        .into_iter()
        .filter(|(ip, failures)| {
            *failures >= config.failure_threshold
                && is_public_unicast(*ip)
                && !config.is_whitelisted(*ip)
                && !state.blocks.contains_key(ip)
        })
        .collect();
    candidates.sort_by(|(left_ip, left_count), (right_ip, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_ip.cmp(right_ip))
    });
    let available = config.max_active_blocks.saturating_sub(state.blocks.len());
    report.capacity_dropped = candidates.len().saturating_sub(available);
    if report.capacity_dropped > 0 {
        report.warnings.push(format!(
            "FW002: active block limit {} reached; {} qualifying addresses were not blocked",
            config.max_active_blocks, report.capacity_dropped
        ));
    }

    for (ip, failures) in candidates.into_iter().take(available) {
        let previous = state
            .repeat_history
            .get(&ip)
            .map(|record| (record.count, record.last_blocked_at));
        let repeat_count = next_repeat_count(now, previous, config);
        let expires_at = now + block_duration(config, repeat_count);
        let record = BlockRecord {
            created_at: now,
            expires_at,
            failures,
        };
        let desired = ManagedRule {
            ip,
            scope: config.block_scope,
            port: (config.block_scope == crate::config::BlockScope::RdpOnly)
                .then_some(config.rdp_port.unwrap_or(3389)),
            expires_at,
            failures,
            repeat_count,
        };
        if let Err(error) = firewall.apply_rule(&desired) {
            report
                .warnings
                .push(format!("FW001: failed to block {ip}: {error:#}"));
            continue;
        }
        state.blocks.insert(ip, record);
        state.repeat_history.insert(
            ip,
            RepeatRecord {
                count: repeat_count,
                last_blocked_at: now,
            },
        );
        if let Err(error) = store.save(&state) {
            state.blocks.remove(&ip);
            if let Some(previous) = previous {
                state.repeat_history.insert(
                    ip,
                    RepeatRecord {
                        count: previous.0,
                        last_blocked_at: previous.1,
                    },
                );
            } else {
                state.repeat_history.remove(&ip);
            }
            let _ = firewall.unblock(ip);
            report.warnings.push(format!(
                "STATE001: failed to persist block for {ip}; firewall change rolled back: {error:#}"
            ));
            continue;
        }
        report.blocked += 1;
        report.applied_actions.push(Action::Block {
            ip,
            failures,
            expires_at,
        });
        if let Err(error) = observer(report.applied_actions.last().unwrap()) {
            report.warnings.push(format!(
                "LOG001: failed to record block for {ip}: {error:#}"
            ));
        }
    }

    Ok(report)
}

pub(crate) fn managed_rule(
    ip: std::net::IpAddr,
    record: &BlockRecord,
    state: &State,
    config: &Config,
) -> ManagedRule {
    ManagedRule {
        ip,
        scope: config.block_scope,
        port: (config.block_scope == crate::config::BlockScope::RdpOnly)
            .then_some(config.rdp_port.unwrap_or(3389)),
        expires_at: record.expires_at,
        failures: record.failures,
        repeat_count: state
            .repeat_history
            .get(&ip)
            .map_or(1, |record| record.count),
    }
}
