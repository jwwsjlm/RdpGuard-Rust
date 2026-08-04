use anyhow::{Result, anyhow};
use chrono::{TimeZone, Utc};
use rdpguard::{
    config::BlockScope,
    events::EventQueryResult,
    firewall::ManagedRule,
    monitor::{AuthEvent, AuthResult, GuardFailureEvent, MonitorWarningKind},
    monitor_runtime::{MonitorSources, collect_snapshot},
    state::{BlockRecord, State},
};

struct PartialSources {
    now: chrono::DateTime<Utc>,
}

struct ActualFirewallSources(StableSources);

impl MonitorSources for ActualFirewallSources {
    fn auth_events(&mut self, minutes: u64) -> Result<EventQueryResult<AuthEvent>> {
        self.0.auth_events(minutes)
    }
    fn guard_events(&mut self, minutes: u64) -> Result<EventQueryResult<GuardFailureEvent>> {
        self.0.guard_events(minutes)
    }
    fn state(&mut self) -> Result<State> {
        self.0.state()
    }
    fn firewall_rules(&mut self) -> Result<Option<Vec<ManagedRule>>> {
        Ok(Some(Vec::new()))
    }
}

#[test]
fn actual_firewall_inventory_overrides_stale_state_block_flag() {
    let now = Utc.with_ymd_and_hms(2026, 8, 5, 0, 30, 0).unwrap();
    let mut sources = ActualFirewallSources(StableSources { now });
    let snapshot = collect_snapshot(&mut sources, 60, now);
    assert!(!snapshot.summaries[0].blocked);
    assert!(snapshot.warnings.iter().any(|warning| {
        warning.kind == MonitorWarningKind::Firewall && warning.detail.contains("missing")
    }));
    let _type_check = ManagedRule {
        ip: "203.0.113.1".parse().unwrap(),
        scope: BlockScope::AllInbound,
        port: None,
        expires_at: now,
        failures: 5,
        repeat_count: 1,
    };
}

impl MonitorSources for PartialSources {
    fn auth_events(&mut self, _window_minutes: u64) -> Result<EventQueryResult<AuthEvent>> {
        Err(anyhow!("access denied"))
    }

    fn guard_events(
        &mut self,
        _window_minutes: u64,
    ) -> Result<EventQueryResult<GuardFailureEvent>> {
        Ok(EventQueryResult {
            events: vec![GuardFailureEvent {
                timestamp: self.now,
                ip: "198.51.100.20".parse().unwrap(),
            }],
            truncated: false,
        })
    }

    fn state(&mut self) -> Result<State> {
        Err(anyhow!("state denied"))
    }
}

#[test]
fn partial_source_failures_preserve_available_monitor_data() {
    let now = Utc.with_ymd_and_hms(2026, 8, 5, 0, 30, 0).unwrap();
    let mut sources = PartialSources { now };

    let snapshot = collect_snapshot(&mut sources, 60, now);

    assert!(snapshot.auth_events.is_empty());
    assert_eq!(snapshot.summaries.len(), 1);
    assert_eq!(snapshot.summaries[0].guard_failures, 1);
    assert_eq!(snapshot.warnings.len(), 2);
    assert!(
        snapshot
            .warnings
            .iter()
            .any(|warning| warning.kind == MonitorWarningKind::AuthLog)
    );
    assert!(
        snapshot
            .warnings
            .iter()
            .any(|warning| warning.kind == MonitorWarningKind::BlockState)
    );
}

struct StableSources {
    now: chrono::DateTime<Utc>,
}

impl MonitorSources for StableSources {
    fn auth_events(&mut self, _window_minutes: u64) -> Result<EventQueryResult<AuthEvent>> {
        Ok(EventQueryResult {
            events: vec![AuthEvent {
                timestamp: self.now,
                ip: "198.51.100.20".parse().unwrap(),
                username: "Administrator".into(),
                result: AuthResult::Failure,
                event_id: 4625,
                logon_type: 10,
            }],
            truncated: false,
        })
    }

    fn guard_events(
        &mut self,
        _window_minutes: u64,
    ) -> Result<EventQueryResult<GuardFailureEvent>> {
        Ok(EventQueryResult {
            events: Vec::new(),
            truncated: false,
        })
    }

    fn state(&mut self) -> Result<State> {
        Ok(State {
            blocks: std::collections::HashMap::from([(
                "198.51.100.20".parse().unwrap(),
                BlockRecord {
                    created_at: self.now,
                    expires_at: self.now,
                    failures: 5,
                },
            )]),
            ..State::default()
        })
    }
}

#[test]
fn refresh_recomputes_instead_of_accumulating_previous_counts() {
    let now = Utc.with_ymd_and_hms(2026, 8, 5, 0, 30, 0).unwrap();
    let mut sources = StableSources { now };

    let first = collect_snapshot(&mut sources, 60, now);
    let second = collect_snapshot(&mut sources, 60, now);

    assert_eq!(first.summaries[0].login_attempts, 1);
    assert_eq!(second.summaries[0].login_attempts, 1);
    assert!(second.summaries[0].blocked);
}
