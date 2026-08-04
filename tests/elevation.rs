const ELEVATION: &str = include_str!("../src/elevation.rs");
use std::path::Path;

use rdpguard::elevation::is_trusted_monitor_location_for;

#[test]
fn elevated_monitor_is_waited_for_before_temporary_files_can_be_removed() {
    for required in [
        "ShellExecuteExW",
        "SEE_MASK_NOCLOSEPROCESS",
        "WaitForSingleObject",
        "GetExitCodeProcess",
        "CloseHandle",
    ] {
        assert!(
            ELEVATION.contains(required),
            "elevation path is missing required process lifetime handling: {required}"
        );
    }
}

#[test]
fn only_the_protected_installed_monitor_may_self_elevate() {
    let root = Path::new(r"C:\ProgramData");
    assert!(is_trusted_monitor_location_for(
        Path::new(r"C:\ProgramData\RdpGuard\rdpguard-monitor.exe"),
        root
    ));
    assert!(!is_trusted_monitor_location_for(
        Path::new(r"C:\Users\user\Downloads\rdpguard-monitor.exe"),
        root
    ));
    assert!(!is_trusted_monitor_location_for(
        Path::new(r"C:\ProgramData\RdpGuard-evil\rdpguard-monitor.exe"),
        root
    ));
}
