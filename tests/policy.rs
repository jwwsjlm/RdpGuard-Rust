use std::{collections::HashMap, net::IpAddr};

use chrono::{Duration, TimeZone, Utc};
use rdpguard::{
    config::Config,
    policy::{Action, failure_counts, is_public_unicast, plan_actions},
};

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

#[test]
fn only_public_unicast_addresses_are_blockable() {
    for value in [
        "127.0.0.1",
        "0.0.0.0",
        "10.1.2.3",
        "169.254.1.2",
        "224.0.0.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "ff02::1",
    ] {
        assert!(
            !is_public_unicast(ip(value)),
            "{value} must not be blockable"
        );
    }
    assert!(is_public_unicast(ip("45.227.254.154")));
    assert!(is_public_unicast(ip("2606:4700:4700::1111")));
}

#[test]
fn fifth_failure_creates_a_360_minute_block() {
    let attacker = ip("45.227.254.154");
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let config = Config::default();

    let four = failure_counts([attacker; 4]);
    assert!(plan_actions(now, &four, &HashMap::new(), &config).is_empty());

    let five = failure_counts([attacker; 5]);
    assert_eq!(
        plan_actions(now, &five, &HashMap::new(), &config),
        vec![Action::Block {
            ip: attacker,
            failures: 5,
            expires_at: now + Duration::minutes(360),
        }]
    );
}

#[test]
fn whitelist_and_active_blocks_are_not_blocked_again() {
    let attacker = ip("45.227.254.154");
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let counts = failure_counts([attacker; 5]);

    let mut whitelisted = Config::default();
    whitelisted.whitelist.push(attacker);
    assert!(plan_actions(now, &counts, &HashMap::new(), &whitelisted).is_empty());

    let active = HashMap::from([(attacker, now + Duration::minutes(1))]);
    assert!(plan_actions(now, &counts, &active, &Config::default()).is_empty());
}

#[test]
fn expired_block_is_unblocked_before_new_decisions() {
    let attacker = ip("45.227.254.154");
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let active = HashMap::from([(attacker, now)]);
    assert_eq!(
        plan_actions(now, &HashMap::new(), &active, &Config::default()),
        vec![Action::Unblock { ip: attacker }]
    );
}
