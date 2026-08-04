use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rdpguard::config::Config;
use rdpguard::events::{build_query, parse_failed_ips};

#[test]
fn default_config_is_sixty_ten_five_three_sixty() {
    let config = Config::default();
    assert_eq!(config.check_interval_seconds, 60);
    assert_eq!(config.window_minutes, 10);
    assert_eq!(config.failure_threshold, 5);
    assert_eq!(config.block_minutes, 360);
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
