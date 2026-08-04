const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");

#[test]
fn release_package_contains_service_and_monitor_binaries() {
    for required in [
        "target\\release\\rdpguard.exe",
        "target\\release\\rdpguard-monitor.exe",
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
fn ci_artifact_contains_the_monitor() {
    assert!(CI_WORKFLOW.contains("target/release/rdpguard-monitor.exe"));
}
