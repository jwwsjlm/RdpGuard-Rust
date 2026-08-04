use std::{collections::HashMap, net::IpAddr};

use anyhow::{Result, anyhow};
use chrono::{Duration, TimeZone, Utc};
use rdpguard::{
    config::{BlockScope, Config},
    engine::{RunReport, StateStore, run_once, run_once_observed},
    events::EventSource,
    firewall::{Firewall, FirewallChange, ManagedRule},
    policy::Action,
    state::{BlockRecord, RepeatRecord, State},
};

struct FakeEvents(Result<Vec<IpAddr>>);

impl EventSource for FakeEvents {
    fn recent_failures(&mut self, _window_minutes: u64) -> Result<Vec<IpAddr>> {
        std::mem::replace(&mut self.0, Ok(Vec::new()))
    }
}

#[derive(Default)]
struct FakeFirewall {
    changes: Vec<FirewallChange>,
    fail: bool,
}

impl Firewall for FakeFirewall {
    fn block(&mut self, ip: IpAddr) -> Result<()> {
        if self.fail {
            return Err(anyhow!("firewall failed"));
        }
        self.changes.push(FirewallChange::Block(ip));
        Ok(())
    }

    fn unblock(&mut self, ip: IpAddr) -> Result<()> {
        if self.fail {
            return Err(anyhow!("firewall failed"));
        }
        self.changes.push(FirewallChange::Unblock(ip));
        Ok(())
    }
}

#[derive(Default)]
struct MemoryState {
    state: State,
    saves: usize,
}

#[derive(Default)]
struct RecoveryPendingState {
    state: State,
    saves: usize,
}

impl StateStore for RecoveryPendingState {
    fn load(&self) -> Result<State> {
        Ok(self.state.clone())
    }

    fn save(&mut self, state: &State) -> Result<()> {
        self.state = state.clone();
        self.saves += 1;
        Ok(())
    }

    fn recovered_from_corruption(&self) -> bool {
        true
    }
}

struct CountingEvents {
    calls: usize,
}

impl EventSource for CountingEvents {
    fn recent_failures(&mut self, _window_minutes: u64) -> Result<Vec<IpAddr>> {
        self.calls += 1;
        Ok(vec![ip(); 5])
    }
}

impl StateStore for MemoryState {
    fn load(&self) -> Result<State> {
        Ok(self.state.clone())
    }
    fn save(&mut self, state: &State) -> Result<()> {
        self.state = state.clone();
        self.saves += 1;
        Ok(())
    }
}

fn ip() -> IpAddr {
    "45.227.254.154".parse().unwrap()
}

#[test]
fn event_query_failure_still_unblocks_expired_rules() {
    let mut events = FakeEvents(Err(anyhow!("query failed")));
    let mut firewall = FakeFirewall::default();
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let mut store = MemoryState {
        state: State {
            blocks: HashMap::from([(
                ip(),
                BlockRecord {
                    created_at: now - Duration::hours(6),
                    expires_at: now,
                    failures: 5,
                },
            )]),
            ..State::default()
        },
        saves: 0,
    };

    let report = run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();
    assert_eq!(firewall.changes, vec![FirewallChange::Unblock(ip())]);
    assert!(store.state.blocks.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("EVT001"))
    );
}

#[test]
fn corrupt_state_waits_for_firewall_inventory_before_processing_new_events() {
    let mut events = CountingEvents { calls: 0 };
    let mut firewall = FakeFirewall::default();
    let mut store = RecoveryPendingState::default();
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();

    let report = run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();

    assert_eq!(events.calls, 0);
    assert_eq!(store.saves, 0);
    assert!(firewall.changes.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("recovery is pending"))
    );
}

#[test]
fn fifth_failure_blocks_and_persists() {
    let mut events = FakeEvents(Ok(vec![ip(); 5]));
    let mut firewall = FakeFirewall::default();
    let mut store = MemoryState::default();
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();

    let report = run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();
    assert_eq!(
        report,
        RunReport {
            failures: 5,
            blocked: 1,
            unblocked: 0,
            applied_actions: vec![Action::Block {
                ip: ip(),
                failures: 5,
                expires_at: now + Duration::minutes(360),
            }],
            repaired: 0,
            orphans_removed: 0,
            capacity_dropped: 0,
            warnings: Vec::new(),
        }
    );
    assert_eq!(firewall.changes, vec![FirewallChange::Block(ip())]);
    assert_eq!(
        store.state.blocks[&ip()].expires_at,
        now + Duration::minutes(360)
    );
    assert_eq!(store.saves, 1);
}

#[test]
fn firewall_failure_does_not_persist_block() {
    let mut events = FakeEvents(Ok(vec![ip(); 5]));
    let mut firewall = FakeFirewall {
        fail: true,
        ..FakeFirewall::default()
    };
    let mut store = MemoryState::default();
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();

    let report = run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();
    assert!(store.state.blocks.is_empty());
    assert_eq!(store.saves, 0);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("FW001"))
    );
}

#[test]
fn expired_rule_is_removed_and_state_is_saved() {
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let record = BlockRecord {
        created_at: now - Duration::minutes(360),
        expires_at: now,
        failures: 5,
    };
    let mut events = FakeEvents(Ok(Vec::new()));
    let mut firewall = FakeFirewall::default();
    let mut store = MemoryState {
        state: State {
            blocks: HashMap::from([(ip(), record)]),
            ..State::default()
        },
        saves: 0,
    };

    let report = run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();
    assert_eq!(report.applied_actions, vec![Action::Unblock { ip: ip() }]);
    assert_eq!(firewall.changes, vec![FirewallChange::Unblock(ip())]);
    assert!(store.state.blocks.is_empty());
    assert_eq!(store.saves, 1);
}

#[derive(Default)]
struct ReconFirewall {
    rules: Vec<ManagedRule>,
    changes: Vec<FirewallChange>,
}

impl Firewall for ReconFirewall {
    fn block(&mut self, ip: IpAddr) -> Result<()> {
        self.changes.push(FirewallChange::Block(ip));
        Ok(())
    }

    fn unblock(&mut self, ip: IpAddr) -> Result<()> {
        self.changes.push(FirewallChange::Unblock(ip));
        self.rules.retain(|rule| rule.ip != ip);
        Ok(())
    }

    fn managed_rules(&mut self) -> Result<Option<Vec<ManagedRule>>> {
        Ok(Some(self.rules.clone()))
    }

    fn apply_rule(&mut self, rule: &ManagedRule) -> Result<()> {
        self.changes.push(FirewallChange::Block(rule.ip));
        self.rules.retain(|current| current.ip != rule.ip);
        self.rules.push(rule.clone());
        Ok(())
    }
}

#[test]
fn reconciliation_repairs_missing_rules_and_removes_orphans() {
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let orphan: IpAddr = "203.0.113.99".parse().unwrap();
    let record = BlockRecord {
        created_at: now,
        expires_at: now + Duration::hours(6),
        failures: 8,
    };
    let mut store = MemoryState {
        state: State {
            blocks: HashMap::from([(ip(), record)]),
            ..State::default()
        },
        saves: 0,
    };
    let mut firewall = ReconFirewall {
        rules: vec![ManagedRule {
            ip: orphan,
            scope: BlockScope::AllInbound,
            port: None,
            expires_at: now + Duration::hours(1),
            failures: 5,
            repeat_count: 1,
        }],
        changes: Vec::new(),
    };
    let mut events = FakeEvents(Ok(Vec::new()));

    let report = run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();

    assert!(firewall.changes.contains(&FirewallChange::Unblock(orphan)));
    assert!(firewall.changes.contains(&FirewallChange::Block(ip())));
    assert_eq!(report.repaired, 1);
    assert_eq!(report.orphans_removed, 1);
}

#[test]
fn corrupt_state_recovers_active_blocks_from_metadata_rules() {
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let mut store = RecoveryPendingState::default();
    let mut firewall = ReconFirewall {
        rules: vec![ManagedRule {
            ip: ip(),
            scope: BlockScope::AllInbound,
            port: None,
            expires_at: now + Duration::hours(6),
            failures: 9,
            repeat_count: 3,
        }],
        changes: Vec::new(),
    };
    let mut events = FakeEvents(Ok(Vec::new()));

    let report = run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();

    assert_eq!(store.state.blocks[&ip()].failures, 9);
    assert_eq!(store.state.repeat_history[&ip()].count, 3);
    assert!(store.saves >= 1);
    assert_eq!(report.repaired, 0);
}

#[test]
fn whitelisting_an_active_ip_unblocks_and_clears_repeat_history() {
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let mut config = Config::default();
    config.whitelist.push(ip().to_string().parse().unwrap());
    let mut store = MemoryState {
        state: State {
            blocks: HashMap::from([(
                ip(),
                BlockRecord {
                    created_at: now,
                    expires_at: now + Duration::hours(6),
                    failures: 5,
                },
            )]),
            repeat_history: HashMap::from([(
                ip(),
                RepeatRecord {
                    count: 4,
                    last_blocked_at: now,
                },
            )]),
        },
        saves: 0,
    };
    let mut firewall = FakeFirewall::default();
    let mut events = FakeEvents(Ok(vec![ip(); 20]));

    run_once(&mut events, &mut firewall, &mut store, now, &config).unwrap();
    assert_eq!(firewall.changes, vec![FirewallChange::Unblock(ip())]);
    assert!(!store.state.repeat_history.contains_key(&ip()));
}

#[test]
fn capacity_prefers_addresses_with_the_most_failures() {
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let low: IpAddr = "45.227.254.155".parse().unwrap();
    let high: IpAddr = "45.227.254.156".parse().unwrap();
    let mut failures = vec![low; 5];
    failures.extend(vec![high; 9]);
    let mut events = FakeEvents(Ok(failures));
    let mut firewall = FakeFirewall::default();
    let mut store = MemoryState::default();
    let config = Config {
        max_active_blocks: 1,
        ..Config::default()
    };

    let report = run_once(&mut events, &mut firewall, &mut store, now, &config).unwrap();
    assert!(store.state.blocks.contains_key(&high));
    assert!(!store.state.blocks.contains_key(&low));
    assert_eq!(report.capacity_dropped, 1);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("FW002"))
    );
}

#[test]
fn repeat_history_makes_the_second_block_twelve_hours() {
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let mut events = FakeEvents(Ok(vec![ip(); 5]));
    let mut firewall = FakeFirewall::default();
    let mut store = MemoryState {
        state: State {
            repeat_history: HashMap::from([(
                ip(),
                RepeatRecord {
                    count: 1,
                    last_blocked_at: now - Duration::days(1),
                },
            )]),
            ..State::default()
        },
        saves: 0,
    };

    run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();
    assert_eq!(store.state.repeat_history[&ip()].count, 2);
    assert_eq!(
        store.state.blocks[&ip()].expires_at,
        now + Duration::hours(12)
    );
}

#[test]
fn changing_to_rdp_only_replaces_the_existing_all_inbound_rule() {
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let record = BlockRecord {
        created_at: now,
        expires_at: now + Duration::hours(6),
        failures: 5,
    };
    let mut store = MemoryState {
        state: State {
            blocks: HashMap::from([(ip(), record.clone())]),
            ..State::default()
        },
        saves: 0,
    };
    let mut firewall = ReconFirewall {
        rules: vec![ManagedRule {
            ip: ip(),
            scope: BlockScope::AllInbound,
            port: None,
            expires_at: record.expires_at,
            failures: 5,
            repeat_count: 1,
        }],
        changes: Vec::new(),
    };
    let mut events = FakeEvents(Ok(Vec::new()));
    let config = Config {
        block_scope: BlockScope::RdpOnly,
        rdp_port: Some(3390),
        ..Config::default()
    };

    let report = run_once(&mut events, &mut firewall, &mut store, now, &config).unwrap();
    assert_eq!(report.repaired, 1);
    assert_eq!(firewall.rules[0].scope, BlockScope::RdpOnly);
    assert_eq!(firewall.rules[0].port, Some(3390));
}

struct FailingSaveStore {
    state: State,
}

impl StateStore for FailingSaveStore {
    fn load(&self) -> Result<State> {
        Ok(self.state.clone())
    }

    fn save(&mut self, _state: &State) -> Result<()> {
        Err(anyhow!("state save failed"))
    }
}

#[test]
fn failed_state_save_returns_no_action_report_and_rolls_back() {
    let mut events = FakeEvents(Ok(vec![ip(); 5]));
    let mut firewall = FakeFirewall::default();
    let mut store = FailingSaveStore {
        state: State::default(),
    };
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();

    let report = run_once(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
    )
    .unwrap();

    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("STATE001"))
    );
    assert!(store.state.blocks.is_empty());
    assert_eq!(
        firewall.changes,
        vec![FirewallChange::Block(ip()), FirewallChange::Unblock(ip())]
    );
}

#[test]
fn successful_action_is_observed_before_a_later_action_fails() {
    struct FailSecondBlock {
        calls: usize,
    }

    impl Firewall for FailSecondBlock {
        fn block(&mut self, _ip: IpAddr) -> Result<()> {
            self.calls += 1;
            if self.calls == 2 {
                Err(anyhow!("second firewall change failed"))
            } else {
                Ok(())
            }
        }

        fn unblock(&mut self, _ip: IpAddr) -> Result<()> {
            Ok(())
        }
    }

    let first_ip: IpAddr = "45.227.254.154".parse().unwrap();
    let second_ip: IpAddr = "45.227.254.155".parse().unwrap();
    let mut failures = vec![first_ip; 5];
    failures.extend(vec![second_ip; 5]);
    let mut events = FakeEvents(Ok(failures));
    let mut firewall = FailSecondBlock { calls: 0 };
    let mut store = MemoryState::default();
    let mut observed = Vec::new();
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();

    let report = run_once_observed(
        &mut events,
        &mut firewall,
        &mut store,
        now,
        &Config::default(),
        |action| {
            observed.push(action.clone());
            Ok(())
        },
    )
    .unwrap();

    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("FW001"))
    );
    assert_eq!(observed.len(), 1);
    assert!(matches!(
        observed[0],
        Action::Block { ip, failures: 5, .. } if ip == first_ip
    ));
    assert!(store.state.blocks.contains_key(&first_ip));
    assert!(!store.state.blocks.contains_key(&second_ip));
}
