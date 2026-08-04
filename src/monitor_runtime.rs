use std::{
    io,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::{
    app::AppPaths,
    connections::{query_rdp_connections, read_rdp_port},
    events::{EventQueryResult, query_recent_auth_events, query_recent_guard_failures},
    monitor::{
        AuthEvent, GuardFailureEvent, MonitorSnapshot, TcpConnection, aggregate_ip_summaries,
    },
    monitor_ui::{MonitorApp, render},
    state::{State, load_state},
};

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_RDP_PORT: u16 = 3389;

pub trait MonitorSources {
    fn auth_events(&mut self, window_minutes: u64) -> Result<EventQueryResult<AuthEvent>>;
    fn guard_events(&mut self, window_minutes: u64) -> Result<EventQueryResult<GuardFailureEvent>>;
    fn rdp_port(&mut self) -> Result<u16>;
    fn connections(&mut self, rdp_port: u16) -> Result<Vec<TcpConnection>>;
    fn state(&mut self) -> Result<State>;
}

#[derive(Default)]
pub struct WindowsMonitorSources {
    paths: AppPaths,
}

impl MonitorSources for WindowsMonitorSources {
    fn auth_events(&mut self, window_minutes: u64) -> Result<EventQueryResult<AuthEvent>> {
        query_recent_auth_events(window_minutes)
    }

    fn guard_events(&mut self, window_minutes: u64) -> Result<EventQueryResult<GuardFailureEvent>> {
        query_recent_guard_failures(window_minutes)
    }

    fn rdp_port(&mut self) -> Result<u16> {
        read_rdp_port()
    }

    fn connections(&mut self, rdp_port: u16) -> Result<Vec<TcpConnection>> {
        query_rdp_connections(rdp_port)
    }

    fn state(&mut self) -> Result<State> {
        load_state(&self.paths.state)
    }
}

pub fn collect_snapshot<S: MonitorSources>(
    sources: &mut S,
    window_minutes: u64,
    now: DateTime<Utc>,
) -> MonitorSnapshot {
    let mut warnings = Vec::new();

    let (mut auth_events, auth_truncated) = match sources.auth_events(window_minutes) {
        Ok(result) => (result.events, result.truncated),
        Err(error) => {
            warnings.push(format!("Security 登录日志读取失败: {error:#}"));
            (Vec::new(), false)
        }
    };
    auth_events.sort_by_key(|event| std::cmp::Reverse(event.timestamp));

    let (guard_events, guard_truncated) = match sources.guard_events(window_minutes) {
        Ok(result) => (result.events, result.truncated),
        Err(error) => {
            warnings.push(format!("RdpCoreTS 防护日志读取失败: {error:#}"));
            (Vec::new(), false)
        }
    };

    let rdp_port = match sources.rdp_port() {
        Ok(port) => port,
        Err(error) => {
            warnings.push(format!(
                "RDP 端口读取失败，暂用 {DEFAULT_RDP_PORT}: {error:#}"
            ));
            DEFAULT_RDP_PORT
        }
    };
    let connections = match sources.connections(rdp_port) {
        Ok(connections) => connections,
        Err(error) => {
            warnings.push(format!("当前 RDP 连接读取失败: {error:#}"));
            Vec::new()
        }
    };
    let state = match sources.state() {
        Ok(state) => state,
        Err(error) => {
            warnings.push(format!("封禁状态读取失败: {error:#}"));
            State::default()
        }
    };
    let summaries = aggregate_ip_summaries(&auth_events, &guard_events, &connections, &state);

    MonitorSnapshot {
        summaries,
        auth_events,
        connections,
        warnings,
        auth_truncated,
        guard_truncated,
        rdp_port,
        refreshed_at: now,
    }
}

struct TerminalRestore;

impl Drop for TerminalRestore {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
    }
}

pub fn run_interactive_monitor() -> Result<()> {
    let mut sources = WindowsMonitorSources::default();
    let snapshot = collect_snapshot(&mut sources, 60, Utc::now());
    let mut app = MonitorApp::new(snapshot);

    enable_raw_mode().context("failed to enable terminal raw mode")?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen, Hide) {
        let _ = disable_raw_mode();
        return Err(error).context("failed to enter the monitor screen");
    }
    let _restore = TerminalRestore;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal monitor")?;
    terminal
        .clear()
        .context("failed to clear terminal monitor")?;
    let mut last_refresh = Instant::now();

    while !app.should_quit() {
        terminal
            .draw(|frame| render(frame, &app))
            .context("failed to draw terminal monitor")?;

        if event::poll(Duration::from_millis(250)).context("failed to poll terminal input")?
            && let Event::Key(key) = event::read().context("failed to read terminal input")?
            && matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
        {
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                break;
            }
            app.handle_key(key.code);
        }

        if app.take_refresh_request() || last_refresh.elapsed() >= REFRESH_INTERVAL {
            let snapshot = collect_snapshot(&mut sources, app.range().minutes(), Utc::now());
            app.replace_snapshot(snapshot);
            last_refresh = Instant::now();
        }
    }

    Ok(())
}
