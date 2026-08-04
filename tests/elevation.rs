const ELEVATION: &str = include_str!("../src/elevation.rs");

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
