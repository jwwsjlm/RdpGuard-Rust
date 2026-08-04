const INSTALLER: &str = include_str!("../Install-RdpGuard.ps1");
const UNINSTALLER: &str = include_str!("../Uninstall-RdpGuard.ps1");

#[test]
fn local_installer_refuses_to_execute_from_a_user_writable_path_via_self_elevation() {
    assert!(INSTALLER.contains("requires an elevated PowerShell window"));
    assert!(!INSTALLER.contains("Invoke-SelfElevation -ResolvedLanguage $ResolvedLanguage"));
}

#[test]
fn installer_supports_bilingual_interactive_and_noninteractive_configuration() {
    for required in [
        "$Language",
        "$NonInteractive",
        "$LibraryMode",
        "Resolve-RdpGuardLanguage",
        "Resolve-InstallerLanguageChoice",
        "Get-InteractiveConfig",
        "check_interval_seconds",
        "window_minutes",
        "failure_threshold",
        "block_minutes",
        "whitelist",
        "Read-BoundedInteger",
        "Read-Whitelist",
    ] {
        assert!(
            INSTALLER.contains(required),
            "installer is missing configuration behavior: {required}"
        );
    }
}

#[test]
fn installer_rolls_back_binaries_and_configuration_when_upgrade_fails() {
    for required in [
        "$PendingConfig",
        "$BackupConfig",
        "$BackupExecutable",
        "$BackupMonitor",
        "$PreflightState",
        "Previous installation was restored",
        "Restore-ServiceConfiguration",
        "Set-ProtectedInstallDirectory",
        "ReparsePoint",
        "sc.exe",
        "'config', $ServiceName",
    ] {
        assert!(
            INSTALLER.contains(required),
            "installer is missing safe configuration replacement: {required}"
        );
    }
}

#[test]
fn installer_copies_the_read_only_monitor() {
    for required in [
        "$SourceMonitor",
        "$TargetMonitor",
        "rdpguard-monitor.exe",
        "Copy-Item -LiteralPath $SourceMonitor -Destination $PendingMonitor -Force",
    ] {
        assert!(
            INSTALLER.contains(required),
            "installer is missing monitor installation element: {required}"
        );
    }
}

#[test]
fn installed_monitor_is_executable_before_it_requests_uac() {
    assert!(
        INSTALLER.contains("*S-1-5-32-545:RX"),
        "the protected install directory must grant Users read/execute on the monitor only"
    );
}

#[test]
fn default_uninstall_removes_both_binaries_but_preserves_data() {
    assert!(UNINSTALLER.contains("$TargetMonitor"));
    assert!(UNINSTALLER.contains("@($TargetExecutable, $TargetMonitor)"));
    assert!(UNINSTALLER.contains("Remove-Item -LiteralPath $binary -Force"));
}
