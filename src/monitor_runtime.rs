use std::{io, time::Duration};

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
    events::{EventQueryResult, query_recent_auth_events, query_recent_guard_failures},
    language::Language,
    monitor::{
        AuthEvent, GuardFailureEvent, MonitorSnapshot, MonitorWarning, MonitorWarningKind,
        aggregate_ip_summaries,
    },
    monitor_ui::{MonitorApp, render},
    state::{State, load_state},
};

pub trait MonitorSources {
    fn auth_events(&mut self, window_minutes: u64) -> Result<EventQueryResult<AuthEvent>>;
    fn guard_events(&mut self, window_minutes: u64) -> Result<EventQueryResult<GuardFailureEvent>>;
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
            warnings.push(MonitorWarning {
                kind: MonitorWarningKind::AuthLog,
                detail: format!("{error:#}"),
            });
            (Vec::new(), false)
        }
    };
    auth_events.sort_by_key(|event| std::cmp::Reverse(event.timestamp));

    let (guard_events, guard_truncated) = match sources.guard_events(window_minutes) {
        Ok(result) => (result.events, result.truncated),
        Err(error) => {
            warnings.push(MonitorWarning {
                kind: MonitorWarningKind::GuardLog,
                detail: format!("{error:#}"),
            });
            (Vec::new(), false)
        }
    };

    let state = match sources.state() {
        Ok(state) => state,
        Err(error) => {
            warnings.push(MonitorWarning {
                kind: MonitorWarningKind::BlockState,
                detail: format!("{error:#}"),
            });
            State::default()
        }
    };
    let summaries = aggregate_ip_summaries(&auth_events, &guard_events, &state);

    MonitorSnapshot {
        summaries,
        auth_events,
        warnings,
        auth_truncated,
        guard_truncated,
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

pub fn run_interactive_monitor(language: Language) -> Result<()> {
    let mut sources = WindowsMonitorSources::default();
    let snapshot = collect_snapshot(&mut sources, 60, Utc::now());
    let mut app = MonitorApp::new(snapshot, language);

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

        if app.take_refresh_request() {
            let snapshot = collect_snapshot(&mut sources, app.range().minutes(), Utc::now());
            app.replace_snapshot(snapshot);
        }
    }

    Ok(())
}
