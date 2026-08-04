# RdpGuard v0.3.2 Bilingual Online Launcher and History Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish RdpGuard v0.3.2 with a verified `irm`-launched bilingual menu, an interactive five-field service configuration flow, and a two-page on-demand historical log viewer with no live connection polling or automatic refresh.

**Architecture:** A PowerShell bootstrap owns the online menu and verified Release download, then delegates service changes to the existing elevated installer or launches the verified Rust monitor temporarily. Rust owns locale detection and terminal localization; monitor snapshots contain only historical authentication/guard events plus persisted block state. The Windows protection service remains unchanged and continues running continuously.

**Tech Stack:** Rust 2024, Ratatui 0.30.2, Crossterm 0.29.0, windows-sys 0.61.2, Windows PowerShell 5.1, GitHub Actions and GitHub Releases.

---

## File structure

- Create `src/language.rs` for locale detection, CLI language values and toggling.
- Modify `src/elevation.rs` and `src/bin/rdpguard-monitor.rs` to preserve language through UAC.
- Modify `src/monitor.rs`, `src/monitor_runtime.rs` and `src/monitor_ui.rs` for structured warnings, two pages, bilingual rendering and explicit refreshes.
- Delete `src/connections.rs` and `tests/connections.rs` because live TCP monitoring is removed.
- Create `Install-RdpGuard-Online.ps1` for the menu, verified download and temporary execution.
- Modify `Install-RdpGuard.ps1` for bilingual configuration, UAC argument forwarding and configuration rollback.
- Create dependency-free PowerShell test runners under `tests/` and extend Rust integration tests.
- Modify CI, Release workflow, README, advanced documentation, changelog and acceptance summary.

### Task 1: Shared language model and monitor CLI

**Files:**
- Create: `src/language.rs`
- Create: `tests/language.rs`
- Modify: `src/lib.rs`
- Modify: `src/elevation.rs`
- Modify: `src/bin/rdpguard-monitor.rs`
- Modify: `tests/monitor_cli.rs`
- Create: `tests/elevation.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Write the failing language tests**

Create `tests/language.rs`:

```rust
use rdpguard::language::Language;

#[test]
fn chinese_locales_map_to_chinese_and_other_locales_to_english() {
    assert_eq!(Language::from_locale_name("zh-CN"), Language::Chinese);
    assert_eq!(Language::from_locale_name("zh-Hant-TW"), Language::Chinese);
    assert_eq!(Language::from_locale_name("en-US"), Language::English);
    assert_eq!(Language::from_locale_name("ja-JP"), Language::English);
}

#[test]
fn cli_values_round_trip_and_toggle() {
    assert_eq!(Language::parse_cli("zh-CN").unwrap(), Language::Chinese);
    assert_eq!(Language::parse_cli("en-US").unwrap(), Language::English);
    assert_eq!(Language::Chinese.toggle(), Language::English);
    assert_eq!(Language::English.toggle(), Language::Chinese);
    assert!(Language::parse_cli("de-DE").is_err());
}
```

Update `tests/monitor_cli.rs` so help must contain `--language` and `l`, must not contain the old 30-second claim, accepts `--language zh-CN --help`, and rejects unsupported language values.

Create `tests/elevation.rs` using `include_str!("../src/elevation.rs")` and assert the relaunch path contains `ShellExecuteExW`, `SEE_MASK_NOCLOSEPROCESS`, `WaitForSingleObject`, `GetExitCodeProcess` and `CloseHandle`. This regression test ensures a temporary monitor does not return control to the online launcher before its elevated process exits.

- [ ] **Step 2: Run RED**

```powershell
cargo test --test language --test monitor_cli --test elevation
```

Expected: compilation or assertions fail because the language module and CLI option do not exist.

- [ ] **Step 3: Implement the language API**

Implement this public contract in `src/language.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language { Chinese, English }

impl Language {
    pub fn from_locale_name(value: &str) -> Self;
    pub fn detect() -> Self;
    pub fn parse_cli(value: &str) -> anyhow::Result<Self>;
    pub const fn cli_value(self) -> &'static str;
    pub const fn toggle(self) -> Self;
}
```

`from_locale_name` treats any case-insensitive `zh` prefix as Chinese and everything else as English. `detect` calls Windows `GetUserDefaultLocaleName` and falls back to English. Add `Win32_Globalization` to windows-sys features and export `pub mod language`.

- [ ] **Step 4: Implement CLI parsing and UAC forwarding**

Accept exactly these forms:

```text
rdpguard-monitor
rdpguard-monitor --language zh-CN
rdpguard-monitor --language en-US
rdpguard-monitor --help
rdpguard-monitor --version
```

No language option uses `Language::detect()`. Change elevation relaunch to accept `Language` and pass only the fixed parameter string `--language zh-CN` or `--language en-US`; keep the EXE path in the Shell API's separate file parameter. Use `ShellExecuteExW` with `SEE_MASK_NOCLOSEPROCESS`, wait on the returned process handle, read its exit code with `GetExitCodeProcess`, close the handle on every path, and return a failure when the elevated monitor fails. This keeps the online launcher and its temporary directory alive until the elevated viewer really exits. Pass the selected language into `run_interactive_monitor(language)`. Replace help with bilingual usage that lists two historical pages, `r`, `l`, and no automatic refresh.

- [ ] **Step 5: Run GREEN and commit**

```powershell
cargo test --test language --test monitor_cli --test elevation
cargo test --all-targets
git add Cargo.toml Cargo.lock src/language.rs src/lib.rs src/elevation.rs src/bin/rdpguard-monitor.rs tests/language.rs tests/monitor_cli.rs tests/elevation.rs
git commit -m "Add bilingual monitor language selection"
```

Expected: tests pass and the commit contains only language/CLI changes.

### Task 2: Remove live TCP data from the monitor domain

**Files:**
- Modify: `src/monitor.rs`
- Modify: `src/monitor_runtime.rs`
- Modify: `src/lib.rs`
- Modify: `tests/monitor.rs`
- Modify: `tests/monitor_runtime.rs`
- Modify: `Cargo.toml`
- Delete: `src/connections.rs`
- Delete: `tests/connections.rs`

- [ ] **Step 1: Write the history-only tests**

Change aggregation tests to call:

```rust
let summaries = aggregate_ip_summaries(&auth_events, &guard_events, &State::default());
```

Remove `TcpConnection` fixtures and current-connection assertions. Change fake `MonitorSources` to expose only `auth_events`, `guard_events`, and `state`. Assert partial failures return structured `AuthLog` and `BlockState` warning kinds while guard history remains available.

- [ ] **Step 2: Run RED**

```powershell
cargo test --test monitor --test monitor_runtime
```

Expected: compilation fails because production snapshots and source traits still require live connections.

- [ ] **Step 3: Implement the history-only contract**

Delete `TcpConnection`, snapshot `connections`/`rdp_port`, and `IpSummary.current_connections`. Change aggregation to:

```rust
pub fn aggregate_ip_summaries(
    auth_events: &[AuthEvent],
    guard_events: &[GuardFailureEvent],
    state: &State,
) -> Vec<IpSummary>;
```

Add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorWarningKind { AuthLog, GuardLog, BlockState }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorWarning {
    pub kind: MonitorWarningKind,
    pub detail: String,
}
```

Remove RDP port and connection methods from `MonitorSources` and `WindowsMonitorSources`. Delete the connections module and tests. Remove now-unused IpHelper, WinSock and Registry windows-sys features.

- [ ] **Step 4: Run GREEN, search and commit**

```powershell
cargo test --test monitor --test monitor_runtime
cargo check --all-targets
rg -n "TcpConnection|current_connections|query_rdp_connections|read_rdp_port" src tests
git add Cargo.toml Cargo.lock src/lib.rs src/monitor.rs src/monitor_runtime.rs tests/monitor.rs tests/monitor_runtime.rs
git rm src/connections.rs tests/connections.rs
git commit -m "Make monitor history-only"
```

Expected: tests/check pass and the search returns no matches before commit.

### Task 3: Two bilingual pages with explicit refresh only

**Files:**
- Modify: `src/monitor_ui.rs`
- Modify: `src/monitor_runtime.rs`
- Modify: `tests/terminal.rs`
- Modify: `tests/monitor_runtime.rs`

- [ ] **Step 1: Write failing UI behavior tests**

Construct the app with `MonitorApp::new(sample_snapshot(), Language::Chinese)`. Assert two Tab presses wrap back to Overview. Assert `l` changes `app.language()` to English without requesting a data refresh, and render both languages:

```rust
assert!(rendered_text(&app, 120, 24).contains("IP 概 览"));
app.handle_key(KeyCode::Char('l'));
assert_eq!(app.language(), Language::English);
assert!(!app.take_refresh_request());
assert!(rendered_text(&app, 120, 24).contains("Login Events"));
```

Assert a new app has no pending refresh; navigation, scrolling and language changes do not request one; `r` and changing range do request one.

- [ ] **Step 2: Run RED**

```powershell
cargo test --test terminal --test monitor_runtime
```

Expected: compilation fails because the app has no language and still exposes Connections.

- [ ] **Step 3: Implement the two-page localized UI**

Reduce `MonitorPage` to `Overview` and `AuthEvents`. Add `language: Language`, `language()` and `toggle_language()` to `MonitorApp`. Create a private `MonitorText` selected by language with localized page names, ranges, headings, columns, success/failure, yes/no, warnings, truncation notices, narrow-window guidance and footer.

Remove connection renderer, RDP port text and current-count column. The English footer must be:

```text
Tab:page  1:10m  2:1h  3:24h  4:7d  r:refresh  l:language  Up/Down:scroll  q:quit
```

In runtime, remove `Instant`, `REFRESH_INTERVAL`, `last_refresh` and elapsed-time checks. Keep the 250 ms keyboard poll. Recollect only when `app.take_refresh_request()` is true.

- [ ] **Step 4: Run GREEN, search and commit**

```powershell
cargo test --test terminal --test monitor_runtime
rg -n "Connections|当前连接|current_connections|REFRESH_INTERVAL|last_refresh" src tests
git add src/monitor_ui.rs src/monitor_runtime.rs tests/terminal.rs tests/monitor_runtime.rs
git commit -m "Add bilingual on-demand history UI"
```

Expected: tests pass and obsolete runtime/UI terms are absent.

### Task 4: Bilingual five-field installer configuration

**Files:**
- Modify: `Install-RdpGuard.ps1`
- Create: `tests/Test-InstallerConfig.ps1`
- Modify: `tests/installer.rs`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write failing dependency-free PowerShell tests**

Create `tests/Test-InstallerConfig.ps1`, dot-source the installer with `-LibraryMode`, and use assertion helpers that throw. Cover:

```powershell
Assert-Equal (Resolve-RdpGuardLanguage auto 'zh-CN') 'zh-CN'
Assert-Equal (Resolve-RdpGuardLanguage auto 'en-US') 'en-US'
Assert-Equal (Resolve-InstallerLanguageChoice 'l' 'zh-CN') 'en-US'
Assert-Equal (Read-BoundedInteger '' 60 10 3600) 60
Assert-Equal (Read-BoundedInteger '120' 60 10 3600) 120
Assert-Throws { Read-BoundedInteger '9' 60 10 3600 }
Assert-Equal ((Read-Whitelist '' @('203.0.113.1')) -join ',') '203.0.113.1'
Assert-Equal ((Read-Whitelist 'clear' @('203.0.113.1')).Count) 0
Assert-Throws { Read-Whitelist 'not-an-ip' @() }
```

Extend `tests/installer.rs` to require `Language`, `NonInteractive`, `LibraryMode`, all five JSON keys, pending/backup paths, rollback, and encoded UAC forwarding.

- [ ] **Step 2: Run RED**

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tests\Test-InstallerConfig.ps1
cargo test --test installer
```

Expected: failures because library mode and configuration helpers do not exist.

- [ ] **Step 3: Implement parameters, localization and validation**

Use this header:

```powershell
[CmdletBinding()]
param(
    [ValidateSet('auto', 'zh-CN', 'en-US')][string]$Language = 'auto',
    [switch]$NonInteractive,
    [switch]$LibraryMode
)
```

Implement pure helpers `Resolve-RdpGuardLanguage`, `Resolve-InstallerLanguageChoice`, `Get-RdpGuardText`, `Read-BoundedInteger`, `Read-Whitelist` and `Get-InteractiveConfig`. Whitelist parsing uses `[Net.IPAddress]::TryParse`, canonicalizes and deduplicates addresses, preserves on blank, and clears only for `clear` or `清空`.

Use the Rust ranges exactly: interval `10..3600`, window `1..1440`, threshold `1..10000`, block duration `1..525600`. Each prompt displays current value/range, Enter preserves it, and invalid input repeats the same field. When the installer was started directly with `-Language auto`, show a short prelude where Enter continues with detected language and `l` toggles Chinese/English before configuration; an explicit language inherited from the online menu skips that prelude. Return after definitions for `-LibraryMode`. `-NonInteractive` loads existing valid config or defaults and never calls `Read-Host`.

- [ ] **Step 4: Forward UAC parameters and add rollback**

The encoded elevated command contains only escaped script path, validated language and the optional fixed `-NonInteractive` switch. Serialize selected configuration into a same-directory pending file, dry-run the copied EXE with it, move old config to a unique backup, atomically rename pending config to `config.json`, then start the service. On any later failure remove the new config and restore the backup. On success remove backup; never delete state or log.

- [ ] **Step 5: Run GREEN, parser checks, wire CI and commit**

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tests\Test-InstallerConfig.ps1
cargo test --test installer
$errors = $null
[Management.Automation.Language.Parser]::ParseFile((Resolve-Path '.\Install-RdpGuard.ps1'), [ref]$null, [ref]$errors) | Out-Null
if ($errors.Count) { $errors | Format-List; exit 1 }
git add Install-RdpGuard.ps1 tests/Test-InstallerConfig.ps1 tests/installer.rs .github/workflows/ci.yml
git commit -m "Add bilingual installer configuration wizard"
```

Add the PowerShell test command to CI. Expected: tests/parser pass.

### Task 5: Verified bilingual online menu

**Files:**
- Create: `Install-RdpGuard-Online.ps1`
- Create: `tests/Test-OnlineInstaller.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/release.rs`

- [ ] **Step 1: Write failing online launcher tests**

Dot-source the new script with `-LibraryMode` and test locale selection plus strict checksum handling:

```powershell
Assert-Equal (Resolve-RdpGuardLanguage auto 'zh-CN') 'zh-CN'
Assert-Equal (Get-ExpectedArchiveHash ((('a' * 64) + '  RdpGuard-Rust-v0.3.2.zip')) 'RdpGuard-Rust-v0.3.2.zip') ('a' * 64)
Assert-Throws { Get-ExpectedArchiveHash 'invalid' 'RdpGuard-Rust-v0.3.2.zip' }
Assert-Throws { Assert-ArchiveHash ('0' * 64) ('1' * 64) }
```

Use injected bundle/action scriptblocks to prove: `0` never downloads; `1` invokes installer with selected language; `2` invokes monitor with selected language; language toggle does not download; an action exception still removes the owned temporary directory. Extend `tests/release.rs` to require the script in CI/ZIP and as a separate Release asset.

- [ ] **Step 2: Run RED**

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tests\Test-OnlineInstaller.ps1
cargo test --test release
```

Expected: missing script/workflow entries fail.

- [ ] **Step 3: Implement verified acquisition**

Use fixed repository `jwwsjlm/RdpGuard-Rust` and `/releases/latest`. Validate `tag_name` with `^v[0-9]+\.[0-9]+\.[0-9]+$`; require exactly one `RdpGuard-Rust-$tag.zip` and one `SHA256SUMS.txt`. Accept only HTTPS asset URLs hosted by GitHub download infrastructure. Enable TLS 1.2 without disabling newer protocols. Download to a GUID directory under system TEMP, strictly parse one 64-hex checksum line for the expected ZIP, compare `Get-FileHash`, then extract. Require one package root containing both EXEs, both installers and `config.json`.

- [ ] **Step 4: Implement menu and delegated actions**

Render choices `1` install/configure, `2` history, `3` language and `0` exit. Download lazily for `1`/`2` and cache only the verified extracted bundle for that process. Choice `1` runs Windows PowerShell with `-File Install-RdpGuard.ps1 -Language <value>`. Choice `2` runs `rdpguard-monitor.exe --language <value>`. Wait, check exit codes, then return to the menu. Delete only the owned GUID temp directory in `finally`. `-LibraryMode` returns after function definitions.

- [ ] **Step 5: Run GREEN, syntax checks, wire CI and commit**

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tests\Test-OnlineInstaller.ps1
cargo test --test release
$errors = $null
[Management.Automation.Language.Parser]::ParseFile((Resolve-Path '.\Install-RdpGuard-Online.ps1'), [ref]$null, [ref]$errors) | Out-Null
if ($errors.Count) { $errors | Format-List; exit 1 }
git add Install-RdpGuard-Online.ps1 tests/Test-OnlineInstaller.ps1 tests/release.rs .github/workflows/ci.yml
git commit -m "Add verified bilingual online launcher"
```

Add the online PowerShell test and script artifact to CI.

### Task 6: Version, package and documentation

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `.github/workflows/release.yml`
- Modify: `README.md`
- Modify: `docs/ADVANCED.md`
- Modify: `CHANGELOG.md`
- Modify: `TEST-SUMMARY.md`
- Modify: `tests/release.rs`

- [ ] **Step 1: Write failing Release expectations**

Require `Install-RdpGuard-Online.ps1` in the staging list and as the third asset passed to `gh release create`. Run `cargo test --test release` and expect failure before the workflow change.

- [ ] **Step 2: Bump and package v0.3.2**

Set package version to `0.3.2`, run `cargo check --all-targets` to update Cargo.lock, copy the online script into the ZIP, and pass its repository path to `gh release create` alongside ZIP and checksum.

- [ ] **Step 3: Rewrite concise user docs**

Put the exact `irm` command first, show the four menu choices, five configuration fields, language behavior, and the fact that option `2` works temporarily without service installation. Keep manual ZIP installation secondary. Remove live-connection and 30-second refresh claims. State clearly that the protection service remains continuous while the history viewer is on demand. Add the v0.3.2 changelog and update acceptance coverage.

- [ ] **Step 4: Test, search and commit**

```powershell
cargo test --test release --test cli --test monitor_cli
rg -n "30 秒|30 seconds|当前连接|current connection" README.md docs/ADVANCED.md TEST-SUMMARY.md
git add Cargo.toml Cargo.lock .github/workflows/release.yml README.md docs/ADVANCED.md CHANGELOG.md TEST-SUMMARY.md tests/release.rs
git commit -m "Prepare RdpGuard v0.3.2"
```

Expected: tests pass and obsolete user-facing claims are absent.

### Task 7: Full local verification

**Files:**
- Modify only if a failing check identifies an in-scope defect.

- [ ] **Step 1: Run Rust verification**

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

Expected: all exit zero, no Clippy warnings and zero test failures.

- [ ] **Step 2: Run PowerShell/workflow verification**

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tests\Test-InstallerConfig.ps1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File tests\Test-OnlineInstaller.ps1
actionlint
npx prettier --check .github/workflows/ci.yml .github/workflows/release.yml
```

Parse all three PowerShell scripts with `System.Management.Automation.Language.Parser` and require zero parser errors.

- [ ] **Step 3: Verify removals, versions and scope**

```powershell
rg -n "REFRESH_INTERVAL|current_connections|query_rdp_connections|MonitorPage::Connections" src tests
.\target\release\rdpguard.exe --version
.\target\release\rdpguard-monitor.exe --version
git status --short
git diff origin/main...HEAD --stat
```

Expected: removal search has no matches, both EXEs print `0.3.2`, worktree is clean and only intended files differ. If a correction is necessary, rerun the failing check and commit exact corrected files as `Fix v0.3.2 verification findings`; do not make an empty commit.

### Task 8: Push, tag and verify GitHub Release

**Files:**
- No source edits expected.

- [ ] **Step 1: Confirm publication prerequisites**

```powershell
gh --version
gh auth status
git status --short --branch
git log --oneline origin/main..HEAD
```

Expected: authenticated CLI, clean tree and only reviewed v0.3.2 commits ahead.

- [ ] **Step 2: Push main and wait for CI**

```powershell
git push origin main
$ci = gh run list --repo jwwsjlm/RdpGuard-Rust --workflow CI --limit 1 --json databaseId --jq '.[0].databaseId'
gh run watch --repo jwwsjlm/RdpGuard-Rust $ci --exit-status
```

Expected: push and CI succeed.

- [ ] **Step 3: Tag and wait for Release**

```powershell
git tag -a v0.3.2 -m "RdpGuard v0.3.2"
git push origin v0.3.2
$releaseRun = gh run list --repo jwwsjlm/RdpGuard-Rust --workflow Release --limit 1 --json databaseId --jq '.[0].databaseId'
gh run watch --repo jwwsjlm/RdpGuard-Rust $releaseRun --exit-status
gh release view v0.3.2 --repo jwwsjlm/RdpGuard-Rust --json url,isDraft,isPrerelease,assets
```

Expected: formal Release with ZIP, SHA256SUMS and online launcher assets.

- [ ] **Step 4: Download and verify official assets**

Download to `D:\code\RdpGuard-Rust-releases\v0.3.2`, compare the ZIP hash against `SHA256SUMS.txt`, expand it, verify the expected file list, and run both packaged EXEs with `--version`. Both must print `0.3.2`.

- [ ] **Step 5: Smoke-test stable entry and report**

```powershell
$script = irm 'https://github.com/jwwsjlm/RdpGuard-Rust/releases/latest/download/Install-RdpGuard-Online.ps1'
if ($script -notmatch 'Invoke-OnlineLauncher') { throw 'unexpected latest launcher content' }
```

Report Release URL, exact `irm` command, official ZIP SHA-256, local archive path, final test count, and the distinction between continuous protection service and on-demand history viewer.
