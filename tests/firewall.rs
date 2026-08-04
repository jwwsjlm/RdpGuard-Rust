use std::net::IpAddr;

use chrono::{TimeZone, Utc};
use rdpguard::{
    config::BlockScope,
    firewall::{
        DryRunFirewall, Firewall, FirewallChange, ManagedRule, format_rule_metadata,
        parse_rule_metadata, rule_name,
    },
};

#[test]
fn automatic_rule_name_contains_only_validated_ip() {
    let ipv4: IpAddr = "45.227.254.154".parse().unwrap();
    let ipv6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
    assert_eq!(rule_name(ipv4), "RdpGuard AutoBlock 45.227.254.154");
    assert_eq!(rule_name(ipv6), "RdpGuard AutoBlock 2606:4700:4700::1111");
}

#[test]
fn managed_rule_metadata_round_trips_for_state_recovery() {
    let rule = ManagedRule {
        ip: "203.0.113.8".parse().unwrap(),
        scope: BlockScope::RdpOnly,
        port: Some(3390),
        expires_at: Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap(),
        failures: 17,
        repeat_count: 3,
    };
    let metadata = format_rule_metadata(&rule);
    assert!(metadata.starts_with("RdpGuard:v2|"));
    assert_eq!(parse_rule_metadata(&metadata), Some(rule));
    assert_eq!(
        parse_rule_metadata("Automatically blocked by RdpGuard"),
        None
    );
}

#[test]
fn dry_run_records_exact_block_and_unblock_actions() {
    let address: IpAddr = "45.227.254.154".parse().unwrap();
    let mut firewall = DryRunFirewall::default();
    firewall.block(address).unwrap();
    firewall.unblock(address).unwrap();
    assert_eq!(
        firewall.changes,
        vec![
            FirewallChange::Block(address),
            FirewallChange::Unblock(address)
        ]
    );
}
