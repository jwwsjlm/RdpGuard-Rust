const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const ONLINE_INSTALLER: &str = include_str!("../Install-RdpGuard-Online.ps1");

#[test]
fn release_package_contains_service_and_monitor_binaries() {
    for required in [
        "target\\${{ matrix.target }}\\release\\$name",
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
        RELEASE_WORKFLOW.contains("Join-Path $root 'docs'"),
        "the release archive must preserve README's docs/ADVANCED.md link"
    );
}

#[test]
fn online_launcher_is_an_artifact_and_separate_release_asset() {
    assert!(
        RELEASE_WORKFLOW.contains("dist/* Install-RdpGuard-Online.ps1"),
        "release workflow must publish the stable online installer asset"
    );
    let expected_tag = format!("$ReleaseTag = 'v{}'", env!("CARGO_PKG_VERSION"));
    assert!(ONLINE_INSTALLER.contains(&expected_tag));
    assert!(!ONLINE_INSTALLER.contains("api.github.com"));
    assert!(
        RELEASE_WORKFLOW.contains("Online tag differs"),
        "release workflow must verify the online installer tag"
    );
}

#[test]
fn ci_artifact_contains_the_monitor() {
    for target in [
        "x86_64-pc-windows-msvc",
        "i686-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ] {
        assert!(CI_WORKFLOW.contains(target));
        assert!(RELEASE_WORKFLOW.contains(target));
    }
    assert!(CI_WORKFLOW.contains("rdpguard-monitor.exe"));
}

#[test]
fn release_has_sbom_checksums_attestation_and_powershell_tests() {
    for required in [
        "cargo-cyclonedx",
        "SHA256SUMS.txt",
        "actions/attest-build-provenance@",
        "Test-InstallerConfig.ps1",
        "Test-OnlineInstaller.ps1",
    ] {
        assert!(RELEASE_WORKFLOW.contains(required), "missing {required}");
    }
}
