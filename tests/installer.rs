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
