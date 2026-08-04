use std::process::Command;

#[test]
fn version_flag_prints_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_rdpguard"))
        .arg("--version")
        .output()
        .expect("rdpguard executable should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("rdpguard {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn help_lists_service_and_safety_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_rdpguard"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("--service"));
    assert!(text.contains("--dry-run"));
    assert!(text.contains("--once"));
    assert!(text.contains("doctor"));
}

#[test]
fn doctor_json_is_machine_readable_even_when_the_host_is_degraded() {
    let output = Command::new(env!("CARGO_BIN_EXE_rdpguard"))
        .args(["doctor", "--json", "--language", "en-US"])
        .output()
        .unwrap();
    assert!(matches!(output.status.code(), Some(0 | 1)));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(value["architecture"].is_string());
    assert!(
        value["checks"]
            .as_array()
            .is_some_and(|checks| !checks.is_empty())
    );
}

#[test]
fn doctor_rejects_unknown_language_with_usage_exit_code() {
    let output = Command::new(env!("CARGO_BIN_EXE_rdpguard"))
        .args(["doctor", "--language", "xx"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("language"));
}

#[test]
fn unknown_argument_returns_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_rdpguard"))
        .arg("--unknown")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown argument"));
}
