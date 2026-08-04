const INSTALLER: &str = include_str!("../Install-RdpGuard.ps1");
const UNINSTALLER: &str = include_str!("../Uninstall-RdpGuard.ps1");

#[test]
fn non_admin_install_self_elevates_via_uac() {
    for required in [
        "$PSCommandPath",
        "WindowsPowerShell\\v1.0\\powershell.exe",
        "-EncodedCommand",
        "-Verb RunAs",
        "-Wait",
        "-PassThru",
        ".ExitCode",
    ] {
        assert!(
            INSTALLER.contains(required),
            "installer is missing self-elevation element: {required}"
        );
    }
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
fn installer_rolls_back_configuration_when_service_installation_fails() {
    for required in [
        "$PendingConfig",
        "$BackupConfig",
        "Move-Item -LiteralPath $TargetConfig -Destination $BackupConfig",
        "Move-Item -LiteralPath $PendingConfig -Destination $TargetConfig",
        "Restore-PreviousConfig",
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
        "Copy-Item -LiteralPath $SourceMonitor -Destination $TargetMonitor -Force",
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
