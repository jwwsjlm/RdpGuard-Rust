const SERVICE: &str = include_str!("../src/service.rs");

#[test]
fn initialization_failures_are_reported_to_scm_as_stopped() {
    for required in [
        "report_service_failure",
        "current_state: ServiceState::Stopped",
        "exit_code: ServiceExitCode::ServiceSpecific(1)",
    ] {
        assert!(
            SERVICE.contains(required),
            "service initialization failure path is missing: {required}"
        );
    }
}
