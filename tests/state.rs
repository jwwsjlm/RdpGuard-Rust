use std::net::IpAddr;

use chrono::{Duration, TimeZone, Utc};
use rdpguard::state::{BlockRecord, State, load_state, load_state_resilient, save_state_atomic};

#[test]
fn missing_state_file_is_empty() {
    let directory = tempfile::tempdir().unwrap();
    let state = load_state(&directory.path().join("missing.json")).unwrap();
    assert!(state.blocks.is_empty());
}

#[test]
fn state_round_trips_ip_and_expiration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.json");
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let address: IpAddr = "45.227.254.154".parse().unwrap();
    let mut state = State::default();
    state.blocks.insert(
        address,
        BlockRecord {
            created_at: now,
            expires_at: now + Duration::minutes(360),
            failures: 5,
        },
    );

    save_state_atomic(&path, &state).unwrap();
    assert_eq!(load_state(&path).unwrap(), state);
    assert!(!path.with_extension("json.tmp").exists());
}

#[test]
fn corrupt_state_is_quarantined_and_service_can_recover() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.json");
    std::fs::write(&path, "{ definitely not json").unwrap();

    let recovered = load_state_resilient(&path).unwrap();
    assert!(recovered.state.blocks.is_empty());
    assert!(recovered.quarantined_path.is_some());
    assert!(recovered.recovery_pending);
    assert!(!path.exists());
    assert!(recovered.quarantined_path.unwrap().exists());

    let retried = load_state_resilient(&path).unwrap();
    assert!(retried.recovery_pending);
    save_state_atomic(&path, &retried.state).unwrap();
    assert!(!load_state_resilient(&path).unwrap().recovery_pending);
}

#[test]
fn legacy_state_loads_without_losing_active_blocks_and_normalizes_mapped_ipv4() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.json");
    std::fs::write(
        &path,
        r#"{"blocks":{"::ffff:203.0.113.8":{"created_at":"2026-08-04T12:00:00Z","expires_at":"2026-08-04T18:00:00Z","failures":5}}}"#,
    )
    .unwrap();
    let state = load_state(&path).unwrap();
    assert!(state.blocks.contains_key(&"203.0.113.8".parse().unwrap()));
    assert!(state.repeat_history.is_empty());
}
