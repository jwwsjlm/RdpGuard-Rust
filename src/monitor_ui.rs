use chrono::{DateTime, Local, Utc};
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style, Stylize},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap},
};

use crate::{
    language::Language,
    monitor::{AuthResult, MonitorSnapshot, MonitorWarningKind},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorPage {
    Overview,
    AuthEvents,
}

impl MonitorPage {
    fn next(self) -> Self {
        match self {
            Self::Overview => Self::AuthEvents,
            Self::AuthEvents => Self::Overview,
        }
    }

    fn previous(self) -> Self {
        self.next()
    }

    fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::AuthEvents => 1,
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
}

#[derive(Debug, Clone)]
pub struct MonitorApp {
    snapshot: MonitorSnapshot,
    page: MonitorPage,
    range: TimeRange,
    language: Language,
    row_offset: usize,
    should_quit: bool,
    refresh_requested: bool,
}

impl MonitorApp {
    pub fn new(snapshot: MonitorSnapshot, language: Language) -> Self {
        Self {
            snapshot,
            page: MonitorPage::Overview,
            range: TimeRange::OneHour,
            language,
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

    pub fn language(&self) -> Language {
        self.language
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
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => self.should_quit = true,
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
            KeyCode::Char('l') | KeyCode::Char('L') => self.language = self.language.toggle(),
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

struct MonitorText(Language);

impl MonitorText {
    fn choose<'a>(&self, chinese: &'a str, english: &'a str) -> &'a str {
        match self.0 {
            Language::Chinese => chinese,
            Language::English => english,
        }
    }

    fn page(&self, page: MonitorPage) -> &'static str {
        match page {
            MonitorPage::Overview => self.choose("IP 概览", "IP Overview"),
            MonitorPage::AuthEvents => self.choose("登录事件", "Login Events"),
        }
    }

    fn range(&self, range: TimeRange) -> &'static str {
        match range {
            TimeRange::TenMinutes => self.choose("10 分钟", "10 minutes"),
            TimeRange::OneHour => self.choose("1 小时", "1 hour"),
            TimeRange::OneDay => self.choose("24 小时", "24 hours"),
            TimeRange::SevenDays => self.choose("7 天", "7 days"),
        }
    }

    fn warning_prefix(&self, kind: MonitorWarningKind) -> &'static str {
        match kind {
            MonitorWarningKind::AuthLog => {
                self.choose("Security 登录日志读取失败", "Failed to read Security log")
            }
            MonitorWarningKind::GuardLog => self.choose(
                "RdpCoreTS 防护日志读取失败",
                "Failed to read RdpCoreTS guard log",
            ),
            MonitorWarningKind::BlockState => {
                self.choose("封禁状态读取失败", "Failed to read block state")
            }
        }
    }

    fn footer(&self, compact: bool) -> Vec<Line<'static>> {
        match (self.0, compact) {
            (Language::Chinese, false) => vec![
                Line::from("快捷键  Tab/Shift+Tab:切换页面  1:10分钟  2:1小时  3:24小时  4:7天"),
                Line::from("        r:刷新  l:语言  ↑/↓:滚动  q/Esc:退出"),
            ],
            (Language::Chinese, true) => vec![
                Line::from("快捷键  Tab/Shift+Tab:切换页面"),
                Line::from("        1:10分钟  2:1小时  3:24小时  4:7天"),
                Line::from("        r:刷新  l:语言  ↑/↓:滚动  q/Esc:退出"),
            ],
            (Language::English, false) => vec![
                Line::from("Keys  Tab/Shift+Tab:page  1:10m  2:1h  3:24h  4:7d"),
                Line::from("      r:refresh  l:language  Up/Down:scroll  q/Esc:quit"),
            ],
            (Language::English, true) => vec![
                Line::from("Keys  Tab/Shift+Tab:page"),
                Line::from("      1:10m  2:1h  3:24h  4:7d"),
                Line::from("      r:refresh  l:language  Up/Down:scroll  q/Esc:quit"),
            ],
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
    let text = MonitorText(app.language);
    let area = frame.area();
    let warning_height = if app.snapshot.warnings.is_empty()
        && !app.snapshot.auth_truncated
        && !app.snapshot.guard_truncated
    {
        0
    } else {
        3
    };
    let footer = text.footer(area.width < 100);
    let footer_height = footer.len() as u16;
    let minimum_height = 3 + 3 + warning_height + 5 + footer_height;
    if area.width < 60 || area.height < minimum_height {
        let message = format!(
            "RdpGuard Monitor\n{} | {} {}\n{}",
            text.page(app.page),
            text.choose("范围", "Range"),
            text.range(app.range),
            text.choose(
                "终端窗口过小，请放大后查看完整表格。",
                "The terminal is too small; enlarge it to view the table."
            )
        );
        frame.render_widget(
            Paragraph::new(message)
                .block(Block::default().borders(Borders::ALL).title(" RdpGuard "))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(warning_height),
        Constraint::Min(5),
        Constraint::Length(footer_height),
    ])
    .split(area);

    let header = format!(
        "RdpGuard Monitor  |  {} {}  |  {} {}",
        text.choose("范围", "Range"),
        text.range(app.range),
        text.choose("读取时间", "Read at"),
        local_time(Some(app.snapshot.refreshed_at))
    );
    frame.render_widget(
        Paragraph::new(header.bold()).block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );

    frame.render_widget(
        Tabs::new([
            text.page(MonitorPage::Overview),
            text.page(MonitorPage::AuthEvents),
        ])
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
        let mut warnings: Vec<_> = app
            .snapshot
            .warnings
            .iter()
            .map(|warning| format!("{}: {}", text.warning_prefix(warning.kind), warning.detail))
            .collect();
        if app.snapshot.auth_truncated {
            warnings.push(
                text.choose(
                    "Security 登录事件超过 50,000 条，结果已截断",
                    "Security events exceeded 50,000; results were truncated",
                )
                .into(),
            );
        }
        if app.snapshot.guard_truncated {
            warnings.push(
                text.choose(
                    "RdpCoreTS 防护事件超过 50,000 条，结果已截断",
                    "RdpCoreTS guard events exceeded 50,000; results were truncated",
                )
                .into(),
            );
        }
        frame.render_widget(
            Paragraph::new(warnings.join(" | "))
                .style(Style::default().fg(Color::Yellow))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" {} ", text.choose("提示", "Warning"))),
                ),
            chunks[2],
        );
    }

    match app.page {
        MonitorPage::Overview => render_overview(frame, chunks[3], app, &text),
        MonitorPage::AuthEvents => render_auth_events(frame, chunks[3], app, &text),
    }

    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
        chunks[4],
    );
}

fn render_overview(
    frame: &mut Frame<'_>,
    area: ratatui::layout::Rect,
    app: &MonitorApp,
    text: &MonitorText,
) {
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
                Cell::from(if item.blocked {
                    text.choose("是", "Yes")
                } else {
                    text.choose("否", "No")
                }),
                Cell::from(local_time(item.expires_at)),
                Cell::from(local_time(item.last_seen)),
            ])
            .style(style)
        });
    let header = Row::new([
        "IP",
        text.choose("尝试", "Attempts"),
        text.choose("成功", "Success"),
        text.choose("失败", "Failures"),
        text.choose("RDP 失败", "RDP failures"),
        text.choose("封禁", "Blocked"),
        text.choose("解封时间", "Unblock time"),
        text.choose("最后活动", "Last activity"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(20),
                Constraint::Length(8),
                Constraint::Length(7),
                Constraint::Length(8),
                Constraint::Length(11),
                Constraint::Length(8),
                Constraint::Length(20),
                Constraint::Min(19),
            ],
        )
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", text.page(MonitorPage::Overview))),
        ),
        area,
    );
}

fn render_auth_events(
    frame: &mut Frame<'_>,
    area: ratatui::layout::Rect,
    app: &MonitorApp,
    text: &MonitorText,
) {
    let rows = app
        .snapshot
        .auth_events
        .iter()
        .skip(app.row_offset)
        .map(|event| {
            let (result, color) = match event.result {
                AuthResult::Success => (text.choose("成功", "Success"), Color::Green),
                AuthResult::Failure => (text.choose("失败", "Failure"), Color::Red),
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
    let header = Row::new([
        text.choose("本地时间", "Local time"),
        text.choose("结果", "Result"),
        "IP",
        text.choose("用户名", "Username"),
        text.choose("事件", "Event"),
        text.choose("类型", "Type"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(20),
                Constraint::Length(8),
                Constraint::Length(24),
                Constraint::Min(16),
                Constraint::Length(7),
                Constraint::Length(6),
            ],
        )
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", text.page(MonitorPage::AuthEvents))),
        ),
        area,
    );
}
