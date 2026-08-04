use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rdpguard::config::{BlockScope, Config};
use rdpguard::events::{build_query, parse_failed_ips};

#[test]
fn default_config_is_sixty_ten_five_three_sixty() {
    let config = Config::default();
    assert_eq!(config.check_interval_seconds, 60);
    assert_eq!(config.window_minutes, 10);
    assert_eq!(config.failure_threshold, 5);
    assert_eq!(config.block_minutes, 360);
    assert_eq!(config.max_log_size_mb, 10);
    assert_eq!(config.log_retention_files, 5);
    assert!(config.whitelist.is_empty());
    config.validate().unwrap();
}

#[test]
fn zero_config_values_are_rejected() {
    for config in [
        Config {
            window_minutes: 0,
            ..Config::default()
        },
        Config {
            failure_threshold: 0,
            ..Config::default()
        },
        Config {
            block_minutes: 0,
            ..Config::default()
        },
    ] {
        assert!(config.validate().is_err());
    }
}

#[test]
fn check_interval_is_loaded_from_json() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
            "check_interval_seconds": 120,
            "window_minutes": 10,
            "failure_threshold": 5,
            "block_minutes": 360,
            "whitelist": []
        }"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    let json = serde_json::to_value(config).unwrap();

    assert_eq!(json["check_interval_seconds"], 120);
    assert_eq!(json["max_log_size_mb"], 10);
    assert_eq!(json["log_retention_files"], 5);
}

#[test]
fn unsafe_check_intervals_are_rejected() {
    for seconds in [9, 3_601] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::write(
            &path,
            format!(
                r#"{{
                    "check_interval_seconds": {seconds},
                    "window_minutes": 10,
                    "failure_threshold": 5,
                    "block_minutes": 360,
                    "whitelist": []
                }}"#
            ),
        )
        .unwrap();

        assert!(Config::load(&path).is_err());
    }
}

#[test]
fn unsafe_policy_limits_are_rejected() {
    for config in [
        Config {
            window_minutes: 1_441,
            ..Config::default()
        },
        Config {
            failure_threshold: 10_001,
            ..Config::default()
        },
        Config {
            block_minutes: 525_601,
            ..Config::default()
        },
        Config {
            max_log_size_mb: 1_025,
            ..Config::default()
        },
        Config {
            log_retention_files: 101,
            ..Config::default()
        },
    ] {
        assert!(config.validate().is_err());
    }
}

#[test]
fn parser_reads_only_named_valid_ip_values() {
    let xml = include_str!("../fixtures/rdp-failures.xml");
    let ips = parse_failed_ips(xml).unwrap();
    assert_eq!(
        ips,
        vec![
            IpAddr::V4(Ipv4Addr::new(45, 227, 254, 154)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]
    );
}

#[test]
fn malformed_xml_is_rejected() {
    assert!(parse_failed_ips("<Events><EventData>").is_err());
}

#[test]
fn event_query_uses_id_140_and_requested_window() {
    assert_eq!(
        build_query(10),
        "*[System[(EventID=140) and TimeCreated[timediff(@SystemTime) <= 600000]]]"
    );
}

#[test]
fn legacy_config_loads_with_v2_hardening_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
  "check_interval_seconds": 60,
  "window_minutes": 10,
  "failure_threshold": 5,
  "block_minutes": 360,
  "max_log_size_mb": 10,
  "log_retention_files": 5,
  "whitelist": ["203.0.113.8"]
}"#,
    )
    .unwrap();

    let config = Config::load(&path).unwrap();
    assert_eq!(config.schema_version, 2);
    assert_eq!(config.block_scope, BlockScope::AllInbound);
    assert_eq!(config.rdp_port, None);
    assert_eq!(config.repeat_block_multiplier, 2);
    assert_eq!(config.max_block_minutes, 10_080);
    assert_eq!(config.repeat_reset_days, 30);
    assert_eq!(config.max_active_blocks, 5_000);
    assert_eq!(config.heartbeat_minutes, 60);
    assert!(config.is_whitelisted("203.0.113.8".parse().unwrap()));
}

#[test]
fn whitelist_accepts_cidr_and_normalizes_mapped_ipv4() {
    let config: Config =
        serde_json::from_str(r#"{"whitelist":["198.51.100.0/24","2001:db8::/32","203.0.113.7"]}"#)
            .unwrap();

    assert!(config.is_whitelisted("198.51.100.42".parse().unwrap()));
    assert!(config.is_whitelisted("2001:db8::42".parse().unwrap()));
    assert!(config.is_whitelisted("::ffff:203.0.113.7".parse().unwrap()));
    assert!(!config.is_whitelisted("198.51.101.1".parse().unwrap()));
}
