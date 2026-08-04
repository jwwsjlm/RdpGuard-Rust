use chrono::{Duration, TimeZone, Utc};
use rdpguard::{
    app::log_run_report,
    engine::RunReport,
    logging::{RotationPolicy, append_with_policy},
    policy::Action,
};

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
        repaired: 0,
        orphans_removed: 0,
        capacity_dropped: 0,
        warnings: Vec::new(),
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
        .find("health heartbeat: failures=5, active_actions=2, repaired=0, orphans_removed=0, warnings=0")
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
        repaired: 0,
        orphans_removed: 0,
        capacity_dropped: 0,
        warnings: Vec::new(),
    };

    log_run_report(&log, true, &report).unwrap();

    assert!(!log.exists());
}

#[test]
fn oversized_logs_rotate_and_keep_the_configured_history() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("rdpguard.log");
    let policy = RotationPolicy {
        max_bytes: 1,
        retained_files: 2,
    };

    for message in ["first", "second", "third", "fourth"] {
        append_with_policy(&log, message, policy).unwrap();
    }

    assert!(std::fs::read_to_string(&log).unwrap().contains("fourth"));
    assert!(
        std::fs::read_to_string(directory.path().join("rdpguard.log.1"))
            .unwrap()
            .contains("third")
    );
    let second_archive = std::fs::read_to_string(directory.path().join("rdpguard.log.2")).unwrap();
    assert!(second_archive.contains("second"));
    assert!(!second_archive.contains("first"));
}
