const INSTALLER: &str = include_str!("../Install-RdpGuard.ps1");

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
