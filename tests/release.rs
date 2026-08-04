const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const ONLINE_INSTALLER: &str = include_str!("../Install-RdpGuard-Online.ps1");

#[test]
fn release_package_contains_service_and_monitor_binaries() {
    for required in [
        "target\\release\\rdpguard.exe",
        "target\\release\\rdpguard-monitor.exe",
        "Install-RdpGuard-Online.ps1",
        "README.md",
        "docs\\ADVANCED.md",
    ] {
        assert!(
            RELEASE_WORKFLOW.contains(required),
            "release workflow is missing packaged file: {required}"
        );
    }
    assert!(
        RELEASE_WORKFLOW.contains("Join-Path $staging 'docs'"),
        "the release archive must preserve README's docs/ADVANCED.md link"
    );
}

#[test]
fn online_launcher_is_an_artifact_and_separate_release_asset() {
    assert!(CI_WORKFLOW.contains("Install-RdpGuard-Online.ps1"));
    assert!(
        RELEASE_WORKFLOW.contains("$env:ONLINE_INSTALLER_PATH"),
        "release workflow must publish the stable online installer asset"
    );
    assert!(ONLINE_INSTALLER.contains("$ReleaseTag = 'v0.3.2'"));
    assert!(!ONLINE_INSTALLER.contains("api.github.com"));
}

#[test]
fn ci_artifact_contains_the_monitor() {
    assert!(CI_WORKFLOW.contains("target/release/rdpguard-monitor.exe"));
}
