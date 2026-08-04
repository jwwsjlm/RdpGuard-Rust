use std::net::IpAddr;

use rdpguard::firewall::{DryRunFirewall, Firewall, FirewallChange, rule_name};

#[test]
fn automatic_rule_name_contains_only_validated_ip() {
    let ipv4: IpAddr = "45.227.254.154".parse().unwrap();
    let ipv6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
    assert_eq!(rule_name(ipv4), "RdpGuard AutoBlock 45.227.254.154");
    assert_eq!(rule_name(ipv6), "RdpGuard AutoBlock 2606:4700:4700::1111");
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
