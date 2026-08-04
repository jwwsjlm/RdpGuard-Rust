use chrono::{DateTime, Local, Utc};
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap},
};

use crate::monitor::{AuthResult, MonitorSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorPage {
    Overview,
    AuthEvents,
    Connections,
}

impl MonitorPage {
    fn next(self) -> Self {
        match self {
            Self::Overview => Self::AuthEvents,
            Self::AuthEvents => Self::Connections,
            Self::Connections => Self::Overview,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Overview => Self::Connections,
            Self::AuthEvents => Self::Overview,
            Self::Connections => Self::AuthEvents,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::AuthEvents => 1,
            Self::Connections => 2,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Overview => "IP 概览",
            Self::AuthEvents => "登录事件",
            Self::Connections => "当前连接",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRange {
    TenMinutes,
    OneHour,
    OneDay,
    SevenDays,
}

impl TimeRange {
    pub fn minutes(self) -> u64 {
        match self {
            Self::TenMinutes => 10,
            Self::OneHour => 60,
            Self::OneDay => 24 * 60,
            Self::SevenDays => 7 * 24 * 60,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::TenMinutes => "10 分钟",
            Self::OneHour => "1 小时",
            Self::OneDay => "24 小时",
            Self::SevenDays => "7 天",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MonitorApp {
    snapshot: MonitorSnapshot,
    page: MonitorPage,
    range: TimeRange,
    row_offset: usize,
    should_quit: bool,
    refresh_requested: bool,
}

impl MonitorApp {
    pub fn new(snapshot: MonitorSnapshot) -> Self {
        Self {
            snapshot,
            page: MonitorPage::Overview,
            range: TimeRange::OneHour,
            row_offset: 0,
            should_quit: false,
            refresh_requested: false,
        }
    }

    pub fn page(&self) -> MonitorPage {
        self.page
    }

    pub fn range(&self) -> TimeRange {
        self.range
    }

    pub fn row_offset(&self) -> usize {
        self.row_offset
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn snapshot(&self) -> &MonitorSnapshot {
        &self.snapshot
    }

    pub fn replace_snapshot(&mut self, snapshot: MonitorSnapshot) {
        self.snapshot = snapshot;
        self.row_offset = 0;
    }

    pub fn request_refresh(&mut self) {
        self.refresh_requested = true;
    }

    pub fn take_refresh_request(&mut self) -> bool {
        std::mem::take(&mut self.refresh_requested)
    }

    pub fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Tab => {
                self.page = self.page.next();
                self.row_offset = 0;
            }
            KeyCode::BackTab => {
                self.page = self.page.previous();
                self.row_offset = 0;
            }
            KeyCode::Char('1') => self.set_range(TimeRange::TenMinutes),
            KeyCode::Char('2') => self.set_range(TimeRange::OneHour),
            KeyCode::Char('3') => self.set_range(TimeRange::OneDay),
            KeyCode::Char('4') => self.set_range(TimeRange::SevenDays),
            KeyCode::Char('r') | KeyCode::Char('R') => self.request_refresh(),
            KeyCode::Down => self.row_offset = self.row_offset.saturating_add(1),
            KeyCode::Up => self.row_offset = self.row_offset.saturating_sub(1),
            KeyCode::PageDown => self.row_offset = self.row_offset.saturating_add(10),
            KeyCode::PageUp => self.row_offset = self.row_offset.saturating_sub(10),
            KeyCode::Home => self.row_offset = 0,
            _ => {}
        }
    }

    fn set_range(&mut self, range: TimeRange) {
        if self.range != range {
            self.range = range;
            self.row_offset = 0;
            self.request_refresh();
        }
    }
}

fn local_time(timestamp: Option<DateTime<Utc>>) -> String {
    timestamp
        .map(|value| {
            value
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "-".into())
}

pub fn render(frame: &mut Frame<'_>, app: &MonitorApp) {
    let area = frame.area();
    if area.width < 60 || area.height < 12 {
        let text = format!(
            "RdpGuard Monitor\n{} | 范围 {}\n终端窗口过小，请放大后查看完整表格。",
            app.page.title(),
            app.range.label()
        );
        frame.render_widget(
            Paragraph::new(text)
                .block(Block::default().borders(Borders::ALL).title(" RdpGuard "))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let warning_height = if app.snapshot.warnings.is_empty()
        && !app.snapshot.auth_truncated
        && !app.snapshot.guard_truncated
    {
        0
    } else {
        3
    };
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(warning_height),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .split(area);

    let header = format!(
        "RdpGuard Monitor  |  RDP 端口 {}  |  范围 {}  |  更新 {}",
        app.snapshot.rdp_port,
        app.range.label(),
        local_time(Some(app.snapshot.refreshed_at))
    );
    frame.render_widget(
        Paragraph::new(header.bold()).block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );

    frame.render_widget(
        Tabs::new(["IP 概览", "登录事件", "当前连接"])
            .select(app.page.index())
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(" | ")
            .block(Block::default().borders(Borders::ALL)),
        chunks[1],
    );

    if warning_height > 0 {
        let mut warnings = app.snapshot.warnings.clone();
        if app.snapshot.auth_truncated {
            warnings.push("Security 登录事件超过 50,000 条，结果已截断".into());
        }
        if app.snapshot.guard_truncated {
            warnings.push("RdpCoreTS 防护事件超过 50,000 条，结果已截断".into());
        }
        frame.render_widget(
            Paragraph::new(warnings.join(" | "))
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" 提示 ")),
            chunks[2],
        );
    }

    match app.page {
        MonitorPage::Overview => render_overview(frame, chunks[3], app),
        MonitorPage::AuthEvents => render_auth_events(frame, chunks[3], app),
        MonitorPage::Connections => render_connections(frame, chunks[3], app),
    }

    frame.render_widget(
        Paragraph::new(Line::from(
            "Tab/Shift+Tab 页面  1:10分钟  2:1小时  3:24小时  4:7天  r:刷新  ↑↓:滚动  q:退出",
        ))
        .style(Style::default().fg(Color::DarkGray)),
        chunks[4],
    );
}

fn render_overview(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &MonitorApp) {
    let rows = app
        .snapshot
        .summaries
        .iter()
        .skip(app.row_offset)
        .map(|item| {
            let style = if item.blocked {
                Style::default().fg(Color::Red)
            } else if item.failures > 0 || item.guard_failures > 0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(item.ip.to_string()),
                Cell::from(item.login_attempts.to_string()),
                Cell::from(item.successes.to_string()),
                Cell::from(item.failures.to_string()),
                Cell::from(item.guard_failures.to_string()),
                Cell::from(item.current_connections.to_string()),
                Cell::from(if item.blocked { "是" } else { "否" }),
                Cell::from(local_time(item.expires_at)),
                Cell::from(local_time(item.last_seen)),
            ])
            .style(style)
        });
    let header = Row::new([
        "IP",
        "尝试",
        "成功",
        "失败",
        "防护失败",
        "当前",
        "封禁",
        "解封时间",
        "最后活动",
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let widths = [
        Constraint::Length(20),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(20),
        Constraint::Min(19),
    ];
    frame.render_widget(
        Table::new(rows, widths)
            .header(header)
            .column_spacing(1)
            .block(Block::default().borders(Borders::ALL).title(" IP 概览 ")),
        area,
    );
}

fn render_auth_events(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &MonitorApp) {
    let rows = app
        .snapshot
        .auth_events
        .iter()
        .skip(app.row_offset)
        .map(|event| {
            let (result, color) = match event.result {
                AuthResult::Success => ("成功", Color::Green),
                AuthResult::Failure => ("失败", Color::Red),
            };
            Row::new(vec![
                Cell::from(local_time(Some(event.timestamp))),
                Cell::from(result),
                Cell::from(event.ip.to_string()),
                Cell::from(event.username.clone()),
                Cell::from(event.event_id.to_string()),
                Cell::from(event.logon_type.to_string()),
            ])
            .style(Style::default().fg(color))
        });
    let header = Row::new(["本地时间", "结果", "IP", "用户名", "事件", "类型"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(20),
                Constraint::Length(6),
                Constraint::Length(24),
                Constraint::Min(16),
                Constraint::Length(7),
                Constraint::Length(6),
            ],
        )
        .header(header)
        .column_spacing(1)
        .block(Block::default().borders(Borders::ALL).title(" 登录事件 ")),
        area,
    );
}

fn render_connections(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &MonitorApp) {
    let rows = app
        .snapshot
        .connections
        .iter()
        .skip(app.row_offset)
        .map(|item| {
            Row::new(vec![
                Cell::from(item.remote_ip.to_string()),
                Cell::from(item.remote_port.to_string()),
                Cell::from(item.local_port.to_string()),
                Cell::from(item.state.clone()),
                Cell::from(item.pid.to_string()),
            ])
        });
    let header = Row::new(["远程 IP", "远程端口", "本地端口", "状态", "PID"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Min(24),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(14),
                Constraint::Length(10),
            ],
        )
        .header(header)
        .column_spacing(1)
        .block(Block::default().borders(Borders::ALL).title(" 当前连接 ")),
        area,
    );
}
