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
fn installer_starts_and_stops_services_with_bounded_polling() {
    for required in [
        "Start-RdpGuardServiceBounded",
        "Stop-RdpGuardServiceBounded",
        "Invoke-ServiceControl -Arguments @('start', $ServiceName)",
        "SVC002:",
        "SVC003:",
        "$LASTEXITCODE -ne 1061",
        "Start-Sleep -Milliseconds 250",
    ] {
        assert!(
            INSTALLER.contains(required),
            "installer is missing bounded service control behavior: {required}"
        );
    }
    assert!(
        !INSTALLER.contains("Start-Service -Name $ServiceName"),
        "Start-Service can block indefinitely while SCM reports START_PENDING"
    );
}

#[test]
fn installer_pending_binaries_keep_the_windows_executable_extension() {
    assert!(
        INSTALLER.contains(
            "$PendingExecutable = Join-Path $InstallDirectory \"rdpguard.pending.$suffix.exe\""
        ),
        "the service preflight copy must end in .exe so PowerShell executes it"
    );
    assert!(
        INSTALLER.contains(
            "$PendingMonitor = Join-Path $InstallDirectory \"rdpguard-monitor.pending.$suffix.exe\""
        ),
        "the monitor preflight copy must end in .exe so PowerShell executes it"
    );
    assert!(!INSTALLER.contains("$PendingExecutable = \"$TargetExecutable.pending.$suffix\""));
    assert!(!INSTALLER.contains("$PendingMonitor = \"$TargetMonitor.pending.$suffix\""));
}

#[test]
fn installer_preflight_errors_report_native_process_diagnostics_once() {
    for required in [
        "Invoke-ExecutablePreflight",
        "path=",
        "exit_code=",
        "start_error=",
        "output=",
        "Add-RdpGuardErrorCode",
    ] {
        assert!(
            INSTALLER.contains(required),
            "installer preflight errors are missing diagnostic field: {required}"
        );
    }
    assert!(
        !INSTALLER.contains("throw \"UPGRADE001: $($failure.Exception.Message) Previous installation was restored.\""),
        "rollback must not prepend UPGRADE001 when the original error already has that code"
    );
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
