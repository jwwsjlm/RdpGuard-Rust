use std::net::IpAddr;

use chrono::{Duration, TimeZone, Utc};
use rdpguard::state::{BlockRecord, State, load_state, save_state_atomic};

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
