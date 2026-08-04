# RdpGuard Rust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, test, package, and install a Rust utility that blocks an IP for 360 minutes after 5 RDP password failures within 10 minutes, checked every minute.

**Architecture:** A small Rust executable separates pure event parsing and policy decisions from native Windows adapters. Windows Event Log APIs supply event XML, Windows Firewall COM manages narrowly named rules, and a JSON state file tracks expiration. PowerShell installers copy the release binary and register/remove an automatically recovered LocalSystem service.

**Tech Stack:** Rust 1.97.1 stable MSVC, Cargo, `chrono`, `serde`, `serde_json`, `quick-xml`, `windows`, `windows-service`, PowerShell, Windows Event Log, Windows Defender Firewall.

---

## File map

- `work/rdpguard/Cargo.toml`: package metadata and dependencies.
- `work/rdpguard/src/config.rs`: defaults, JSON loading, and validation.
- `work/rdpguard/src/events.rs`: event XML parser and native Event Log query.
- `work/rdpguard/src/policy.rs`: address safety filters, failure aggregation, and action planning.
- `work/rdpguard/src/state.rs`: block records and atomic JSON persistence.
- `work/rdpguard/src/firewall.rs`: Windows Firewall COM adapter.
- `work/rdpguard/src/logging.rs`: append-only operational log.
- `work/rdpguard/src/lib.rs`: public module boundaries and one-run orchestration.
- `work/rdpguard/src/main.rs`: CLI arguments and exit codes.
- `work/rdpguard/fixtures/rdp-failures.xml`: realistic event ID 140 test events.
- `work/rdpguard/tests/cli.rs`: executable-level dry-run tests.
- `work/rdpguard/Install-RdpGuard.ps1`: elevated installation and Windows service registration.
- `work/rdpguard/Uninstall-RdpGuard.ps1`: task/rule cleanup with optional data removal.
- `work/rdpguard/config.json`: shipped default configuration.
- `work/rdpguard/README.md`: operation, whitelist, logs, install, and uninstall instructions.

### Task 1: Scaffold a compilable Rust package

**Files:** Create `Cargo.toml`, `src/lib.rs`, and `src/main.rs`.

- [ ] Write a CLI integration test that runs the expected binary and fails because the package does not exist.
- [ ] Run `cargo test --manifest-path work/rdpguard/Cargo.toml`; expect failure indicating the manifest or binary is missing.
- [ ] Add package `rdpguard` with dependencies `anyhow`, `chrono` with `serde`, `quick-xml`, `serde`, `serde_json`, and `windows-sys` with `Win32_Storage_FileSystem`; add `tempfile` as a dev dependency.
- [ ] Add `pub const VERSION: &str = env!("CARGO_PKG_VERSION");` and a CLI that prints it for `--version`.
- [ ] Run `cargo test --manifest-path work/rdpguard/Cargo.toml`; expect the version test to pass.

### Task 2: Parse configuration and RDP failure XML

**Files:** Create `src/config.rs`, `src/events.rs`, and `fixtures/rdp-failures.xml`; modify `src/lib.rs`.

- [ ] Add tests proving defaults are 10 minutes, 5 failures, and 360 block minutes; invalid zero values must be rejected.
- [ ] Run the focused tests and verify they fail because `Config` does not exist.
- [ ] Implement `Config { check_interval_seconds: u64, window_minutes: u64, failure_threshold: usize, block_minutes: u64, whitelist: Vec<IpAddr> }`, `Default`, safe range validation, and `load`.
- [ ] Run the focused tests and verify they pass.
- [ ] Add XML tests for named `IPString`, invalid strings, IPv4, and IPv6 using event ID 140 XML.
- [ ] Run them and verify failure because `parse_failed_ips` does not exist.
- [ ] Implement `parse_failed_ips(xml: &str) -> Result<Vec<IpAddr>>` with `quick_xml::Reader`, selecting only `Data` elements whose `Name` attribute is `IPString`.
- [ ] Implement `query_recent_failures(window_minutes)` with `EvtQuery`, `EvtNext`, and `EvtRender`, closing every event handle on all paths.
- [ ] Run all tests and verify they pass.

### Task 3: Implement the pure blocking policy

**Files:** Create `src/policy.rs`; modify `src/lib.rs`.

- [ ] Add tests for rejecting loopback, unspecified, multicast, link-local, and private addresses while accepting public unicast addresses.
- [ ] Add tests that four failures do nothing, five failures yield one block action, whitelisted IPs do nothing, an active record is not re-blocked, and an expired record yields an unblock action.
- [ ] Run focused tests and verify failure because policy functions and action types do not exist.
- [ ] Implement `is_public_unicast`, `failure_counts`, and `plan_actions(now, counts, state, config) -> Vec<Action>` where `Action` is `Block { ip, failures, expires_at }` or `Unblock { ip }`.
- [ ] Run the policy tests and verify they pass.

### Task 4: Persist state and manage firewall rules

**Files:** Create `src/state.rs`, `src/firewall.rs`, and `src/logging.rs`; modify `src/lib.rs`.

- [ ] Add state tests for missing-file default, round-trip JSON, and expiration serialization.
- [ ] Run them and verify failure because `State` and persistence functions do not exist.
- [ ] Implement `BlockRecord`, `State`, `load_state`, and `save_state_atomic`; on Windows use `MoveFileExW` with replace-existing and write-through flags after writing a sibling temporary file.
- [ ] Run the state tests and verify they pass.
- [ ] Add adapter tests proving rule names are exact, block covers inbound/all profiles/all protocols, and unblock targets only `RdpGuard AutoBlock <IP>`.
- [ ] Run them and verify failure because the firewall adapter does not exist.
- [ ] Implement `Firewall` trait plus `WindowsFirewall` and `DryRunFirewall`; use `INetFwPolicy2`/`INetFwRule`, normalizing only the exact automatic rule name without touching other rules.
- [ ] Add append-only UTF-8 log lines with timestamps and run all tests.

### Task 5: Orchestrate one safe run and expose CLI modes

**Files:** Modify `src/lib.rs`, `src/main.rs`, and `tests/cli.rs`.

- [ ] Add orchestration tests with injected event source, firewall, clock, and temporary state: query failure must produce zero firewall calls; block success must persist; firewall failure must not persist; successful expiry deletion must remove state.
- [ ] Run tests and verify they fail because `run_once` is missing.
- [ ] Implement `run_once` with cleanup, query, aggregation, action application, persistence, and operational logging in that order.
- [ ] Add CLI handling for `--once`, `--dry-run`, `--config <path>`, `--state <path>`, `--log <path>`, and `--version`; unknown arguments return exit code 2.
- [ ] Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`; all must pass without warnings.

### Task 6: Add service host, installers, documentation, and release package

**Files:** Create `Install-RdpGuard.ps1`, `Uninstall-RdpGuard.ps1`, `config.json`, and `README.md`.

- [ ] Add Pester-independent syntax checks using PowerShell parser APIs; verify they initially fail while files are absent.
- [ ] Implement the `windows-service` dispatcher and control handler for start, stop, shutdown, and a configurable cancellable wait loop (60 seconds by default).
- [ ] Implement installer admin check, ProgramData copy, preserved existing config, automatic LocalSystem service registration, restricted directory ACL, and service failure recovery.
- [ ] Implement uninstaller that stops/removes the service and only `RdpGuard AutoBlock *` rules; preserve data unless `-RemoveData` is passed.
- [ ] Parse both scripts with `[System.Management.Automation.Language.Parser]::ParseFile` and require zero errors.
- [ ] Build `cargo build --release`, assemble `outputs/RdpGuard-Rust/`, and create `outputs/RdpGuard-Rust.zip` containing the executable, installers, config, README, design, and test summary.

### Task 7: Install and verify on this computer

**Files:** System paths under `C:\ProgramData\RdpGuard`; Windows service `RdpGuard`.

- [ ] Run the release executable with `--dry-run` against the live event log and confirm no firewall mutation.
- [ ] Run the installer elevated as authorized by the user.
- [ ] Verify the service exists, runs as LocalSystem, starts automatically, is running, and has restart-on-failure actions.
- [ ] Verify `config.json` contains 10/5/360 and that installed binary `--version` matches the release.
- [ ] Verify existing manual rule `Codex - Block RDP Failed IPs` remains enabled and unchanged.
- [ ] Run fresh `cargo test`, `cargo clippy`, PowerShell syntax checks, executable dry-run, installed-file checks, and service checks before reporting completion.
