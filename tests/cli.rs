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
