use std::{collections::HashMap, net::IpAddr};

use anyhow::{Result, anyhow};
use chrono::{Duration, TimeZone, Utc};
use rdpguard::{
    config::Config,
    engine::{RunReport, StateStore, run_once},
    events::EventSource,
    firewall::{Firewall, FirewallChange},
    state::{BlockRecord, State},
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
fn event_query_failure_never_changes_firewall_or_state() {
    let mut events = FakeEvents(Err(anyhow!("query failed")));
    let mut firewall = FakeFirewall::default();
    let mut store = MemoryState::default();
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();

    assert!(
        run_once(
            &mut events,
            &mut firewall,
            &mut store,
            now,
            &Config::default()
        )
        .is_err()
    );
    assert!(firewall.changes.is_empty());
    assert_eq!(store.saves, 0);
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
            unblocked: 0
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

    assert!(
        run_once(
            &mut events,
            &mut firewall,
            &mut store,
            now,
            &Config::default()
        )
        .is_err()
    );
    assert!(store.state.blocks.is_empty());
    assert_eq!(store.saves, 0);
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
    assert_eq!(firewall.changes, vec![FirewallChange::Unblock(ip())]);
    assert!(store.state.blocks.is_empty());
    assert_eq!(store.saves, 1);
}
