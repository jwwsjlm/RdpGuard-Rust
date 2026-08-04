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
    assert!(text.contains("--language"));
    assert!(text.contains("l"));
    assert!(!text.contains("30 seconds"));

    let chinese_help = Command::new(binary)
        .args(["--language", "zh-CN", "--help"])
        .output()
        .unwrap();
    assert!(chinese_help.status.success());
    assert!(String::from_utf8_lossy(&chinese_help.stdout).contains("历史"));

    let invalid_language = Command::new(binary)
        .args(["--language", "de-DE"])
        .output()
        .unwrap();
    assert!(!invalid_language.status.success());
}
