use std::{collections::HashMap, net::IpAddr};

use chrono::{DateTime, Utc};

use crate::state::State;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEvent {
    pub timestamp: DateTime<Utc>,
    pub ip: IpAddr,
    pub username: String,
    pub result: AuthResult,
    pub event_id: u32,
    pub logon_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardFailureEvent {
    pub timestamp: DateTime<Utc>,
    pub ip: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorSnapshot {
    pub summaries: Vec<IpSummary>,
    pub auth_events: Vec<AuthEvent>,
    pub warnings: Vec<MonitorWarning>,
    pub auth_truncated: bool,
    pub guard_truncated: bool,
    pub refreshed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorWarningKind {
    AuthLog,
    GuardLog,
    BlockState,
    Firewall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorWarning {
    pub kind: MonitorWarningKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSummary {
    pub ip: IpAddr,
    pub login_attempts: usize,
    pub successes: usize,
    pub failures: usize,
    pub guard_failures: usize,
    pub blocked: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

impl IpSummary {
    fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            login_attempts: 0,
            successes: 0,
            failures: 0,
            guard_failures: 0,
            blocked: false,
            expires_at: None,
            last_seen: None,
        }
    }

    fn observe(&mut self, timestamp: DateTime<Utc>) {
        self.last_seen = Some(
            self.last_seen
                .map_or(timestamp, |previous| previous.max(timestamp)),
        );
    }
}

pub fn aggregate_ip_summaries(
    auth_events: &[AuthEvent],
    guard_events: &[GuardFailureEvent],
    state: &State,
) -> Vec<IpSummary> {
    let mut summaries = HashMap::new();

    for event in auth_events {
        let summary = summaries
            .entry(event.ip)
            .or_insert_with(|| IpSummary::new(event.ip));
        summary.login_attempts += 1;
        match event.result {
            AuthResult::Success => summary.successes += 1,
            AuthResult::Failure => summary.failures += 1,
        }
        summary.observe(event.timestamp);
    }

    for event in guard_events {
        let summary = summaries
            .entry(event.ip)
            .or_insert_with(|| IpSummary::new(event.ip));
        summary.guard_failures += 1;
        summary.observe(event.timestamp);
    }

    for (&ip, record) in &state.blocks {
        let summary = summaries.entry(ip).or_insert_with(|| IpSummary::new(ip));
        summary.blocked = true;
        summary.expires_at = Some(record.expires_at);
    }

    let mut summaries: Vec<_> = summaries.into_values().collect();
    summaries.sort_by(|left, right| {
        right
            .guard_failures
            .cmp(&left.guard_failures)
            .then_with(|| right.failures.cmp(&left.failures))
            .then_with(|| right.last_seen.cmp(&left.last_seen))
            .then_with(|| left.ip.cmp(&right.ip))
    });
    summaries
}
