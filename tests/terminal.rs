use chrono::{TimeZone, Utc};
use crossterm::event::KeyCode;
use ratatui::{Terminal, backend::TestBackend};
use rdpguard::{
    language::Language,
    monitor::{
        AuthEvent, AuthResult, IpSummary, MonitorSnapshot, MonitorWarning, MonitorWarningKind,
    },
    monitor_ui::{MonitorApp, MonitorPage, TimeRange, render},
};

fn sample_snapshot() -> MonitorSnapshot {
    let now = Utc.with_ymd_and_hms(2026, 8, 5, 0, 30, 0).unwrap();
    let ip = "198.51.100.20".parse().unwrap();
    MonitorSnapshot {
        summaries: vec![IpSummary {
            ip,
            login_attempts: 5,
            successes: 0,
            failures: 5,
            guard_failures: 5,
            blocked: true,
            expires_at: Some(now),
            last_seen: Some(now),
        }],
        auth_events: vec![AuthEvent {
            timestamp: now,
            ip,
            username: "Administrator".into(),
            result: AuthResult::Failure,
            event_id: 4625,
            logon_type: 10,
        }],
        warnings: vec![MonitorWarning {
            kind: MonitorWarningKind::AuthLog,
            detail: "access denied".into(),
        }],
        auth_truncated: true,
        guard_truncated: false,
        refreshed_at: now,
    }
}

fn rendered_text(app: &MonitorApp, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn keyboard_switches_pages_ranges_and_scrolls() {
    let mut app = MonitorApp::new(sample_snapshot(), Language::Chinese);
    assert_eq!(app.page(), MonitorPage::Overview);
    assert_eq!(app.range(), TimeRange::OneHour);

    app.handle_key(KeyCode::Tab);
    assert_eq!(app.page(), MonitorPage::AuthEvents);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.page(), MonitorPage::Overview);
    app.handle_key(KeyCode::Char('4'));
    assert_eq!(app.range(), TimeRange::SevenDays);
    assert!(app.take_refresh_request());
    app.handle_key(KeyCode::Char('l'));
    assert_eq!(app.language(), Language::English);
    assert!(!app.take_refresh_request());
    app.handle_key(KeyCode::Down);
    assert_eq!(app.row_offset(), 1);
    app.handle_key(KeyCode::Char('q'));
    assert!(app.should_quit());
}

#[test]
fn both_pages_render_chinese_and_english_data_and_warnings() {
    let mut app = MonitorApp::new(sample_snapshot(), Language::Chinese);
    let overview = rendered_text(&app, 120, 24);
    assert!(overview.contains("IP 概 览"));
    assert!(overview.contains("198.51.100.20"));
    assert!(overview.contains("Security 登 录 日 志 读 取 失 败"));
    assert!(overview.contains("access denied"));

    app.handle_key(KeyCode::Tab);
    let events = rendered_text(&app, 120, 24);
    assert!(events.contains("登 录 事 件"));
    assert!(events.contains("Administrator"));

    app.handle_key(KeyCode::Char('l'));
    let english_events = rendered_text(&app, 120, 24);
    assert!(english_events.contains("Login Events"));
    assert!(english_events.contains("Failure"));
}

#[test]
fn narrow_terminal_renders_without_panicking() {
    let app = MonitorApp::new(sample_snapshot(), Language::Chinese);
    let text = rendered_text(&app, 40, 10);
    assert!(text.contains("RdpGuard"));
}

#[test]
fn only_explicit_data_actions_request_refresh() {
    let mut app = MonitorApp::new(sample_snapshot(), Language::English);
    assert!(!app.take_refresh_request());

    for key in [KeyCode::Tab, KeyCode::Down, KeyCode::Up, KeyCode::Char('l')] {
        app.handle_key(key);
        assert!(
            !app.take_refresh_request(),
            "unexpected refresh for {key:?}"
        );
    }

    app.handle_key(KeyCode::Char('r'));
    assert!(app.take_refresh_request());
    app.handle_key(KeyCode::Char('4'));
    assert!(app.take_refresh_request());
}
