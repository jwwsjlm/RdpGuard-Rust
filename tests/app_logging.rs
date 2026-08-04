use chrono::{Duration, TimeZone, Utc};
use rdpguard::{app::log_run_report, engine::RunReport, policy::Action};

#[test]
fn applied_blocks_and_unblocks_are_logged_before_the_summary() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("rdpguard.log");
    let now = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let blocked_ip = "203.0.113.10".parse().unwrap();
    let unblocked_ip = "203.0.113.20".parse().unwrap();
    let expires_at = now + Duration::minutes(360);
    let report = RunReport {
        failures: 5,
        blocked: 1,
        unblocked: 1,
        applied_actions: vec![
            Action::Block {
                ip: blocked_ip,
                failures: 5,
                expires_at,
            },
            Action::Unblock { ip: unblocked_ip },
        ],
    };

    log_run_report(&log, false, &report).unwrap();

    let text = std::fs::read_to_string(log).unwrap();
    let block = text
        .find(&format!(
            "block applied: ip={blocked_ip}, failures=5, expires_at={}",
            expires_at.to_rfc3339()
        ))
        .unwrap();
    let unblock = text
        .find(&format!("unblock applied: ip={unblocked_ip}"))
        .unwrap();
    let summary = text
        .find("check complete: failures=5, blocked=1, unblocked=1")
        .unwrap();
    assert!(block < unblock && unblock < summary);
}

#[test]
fn dry_run_does_not_create_a_log() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("rdpguard.log");
    let report = RunReport {
        failures: 5,
        blocked: 1,
        unblocked: 0,
        applied_actions: vec![Action::Block {
            ip: "203.0.113.10".parse().unwrap(),
            failures: 5,
            expires_at: Utc.with_ymd_and_hms(2026, 8, 4, 18, 0, 0).unwrap(),
        }],
    };

    log_run_report(&log, true, &report).unwrap();

    assert!(!log.exists());
}
