use std::process::Command;

#[test]
fn monitor_version_and_help_do_not_require_elevation() {
    let binary = env!("CARGO_BIN_EXE_rdpguard-monitor");
    let version = Command::new(binary).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        format!("rdpguard-monitor {}", env!("CARGO_PKG_VERSION"))
    );

    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("Tab"));
    assert!(text.contains("30"));
}
