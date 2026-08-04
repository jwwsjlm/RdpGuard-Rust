use std::{collections::HashMap, net::IpAddr};

use chrono::{DateTime, TimeZone, Utc};
use rdpguard::{
    events::{EventQueryResult, MAX_QUERY_EVENTS, parse_auth_event, parse_guard_failure_events},
    monitor::{AuthEvent, AuthResult, GuardFailureEvent, IpSummary, aggregate_ip_summaries},
    state::{BlockRecord, State},
};

fn timestamp(hour: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 4, hour, 0, 0).unwrap()
}

fn security_xml(event_id: u32, ip: &str, username: &str, logon_type: &str) -> String {
    format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="2026-08-04T12:00:00.1234567Z" />
  </System>
  <EventData>
    <Data Name="TargetUserName">{username}</Data>
    <Data Name="IpAddress">{ip}</Data>
    <Data Name="LogonType">{logon_type}</Data>
  </EventData>
</Event>"#
    )
}

fn auth(ip: &str, result: AuthResult, hour: u32) -> AuthEvent {
    AuthEvent {
        timestamp: timestamp(hour),
        ip: ip.parse().unwrap(),
        username: "alice".into(),
        result,
        event_id: if result == AuthResult::Success {
            4624
        } else {
            4625
        },
        logon_type: 10,
    }
}

fn summary<'a>(summaries: &'a [IpSummary], ip: &str) -> &'a IpSummary {
    let ip: IpAddr = ip.parse().unwrap();
    summaries.iter().find(|item| item.ip == ip).unwrap()
}

#[test]
fn parses_4624_ipv4_success() {
    let event = parse_auth_event(&security_xml(4624, "203.0.113.10", "alice", "10"))
        .unwrap()
        .unwrap();

    assert_eq!(event.ip, "203.0.113.10".parse::<IpAddr>().unwrap());
    assert_eq!(event.username, "alice");
    assert_eq!(event.result, AuthResult::Success);
    assert_eq!(event.event_id, 4624);
    assert_eq!(event.logon_type, 10);
    assert_eq!(
        event.timestamp,
        DateTime::parse_from_rfc3339("2026-08-04T12:00:00.1234567Z")
            .unwrap()
            .with_timezone(&Utc)
    );
}

#[test]
fn parses_4625_ipv6_failure() {
    let event = parse_auth_event(&security_xml(4625, "2001:db8::5", "bob", "10"))
        .unwrap()
        .unwrap();

    assert_eq!(event.ip, "2001:db8::5".parse::<IpAddr>().unwrap());
    assert_eq!(event.username, "bob");
    assert_eq!(event.result, AuthResult::Failure);
    assert_eq!(event.event_id, 4625);
}

#[test]
fn ignores_non_rdp_unsupported_missing_and_dash_security_events() {
    let cases = [
        security_xml(4625, "203.0.113.10", "alice", "3"),
        security_xml(4634, "203.0.113.10", "alice", "10"),
        security_xml(4625, "-", "alice", "10"),
        security_xml(4625, "203.0.113.10", "-", "10"),
        security_xml(4625, "not-an-ip", "alice", "10"),
        security_xml(4625, "203.0.113.10", "alice", ""),
        security_xml(4625, "", "alice", "10"),
    ];

    for xml in cases {
        assert_eq!(parse_auth_event(&xml).unwrap(), None, "{xml}");
    }
    assert_eq!(
        parse_auth_event(
            r#"<Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-08-04T12:00:00Z" /></System><EventData><Data Name="IpAddress">203.0.113.10</Data><Data Name="LogonType">10</Data></EventData></Event>"#
        )
        .unwrap(),
        None
    );
}

#[test]
fn malformed_security_xml_is_an_error() {
    assert!(parse_auth_event("<Event><System>").is_err());
}

#[test]
fn parses_only_timestamped_id_140_guard_failures_for_ipv4_and_ipv6() {
    let xml = r#"<Events>
      <Event><System><EventID>140</EventID><TimeCreated SystemTime="2026-08-04T11:00:00Z" /></System><EventData><Data Name="IPString">203.0.113.10</Data></EventData></Event>
      <Event><System><EventID>140</EventID><TimeCreated SystemTime="2026-08-04T12:00:00Z" /></System><EventData><Data Name="IPString">2001:db8::5</Data></EventData></Event>
      <Event><System><EventID>141</EventID><TimeCreated SystemTime="2026-08-04T13:00:00Z" /></System><EventData><Data Name="IPString">203.0.113.11</Data></EventData></Event>
      <Event><System><EventID>140</EventID></System><EventData><Data Name="IPString">203.0.113.12</Data></EventData></Event>
      <Event><System><EventID>140</EventID><TimeCreated SystemTime="2026-08-04T14:00:00Z" /></System><EventData><Data Name="IPString">-</Data></EventData></Event>
    </Events>"#;

    assert_eq!(
        parse_guard_failure_events(xml).unwrap(),
        vec![
            GuardFailureEvent {
                timestamp: timestamp(11),
                ip: "203.0.113.10".parse().unwrap(),
            },
            GuardFailureEvent {
                timestamp: timestamp(12),
                ip: "2001:db8::5".parse().unwrap(),
            },
        ]
    );
}

#[test]
fn malformed_guard_xml_is_an_error() {
    assert!(parse_guard_failure_events("<Events><Event>").is_err());
}

#[test]
fn query_results_are_capped_and_report_truncation() {
    let exact = EventQueryResult::limited(0..MAX_QUERY_EVENTS);
    assert_eq!(exact.events.len(), MAX_QUERY_EVENTS);
    assert!(!exact.truncated);

    let over = EventQueryResult::limited(0..=MAX_QUERY_EVENTS);
    assert_eq!(over.events.len(), MAX_QUERY_EVENTS);
    assert!(over.truncated);
}

#[test]
fn five_auth_failures_are_five_login_attempts_without_successes() {
    let auth_events: Vec<_> = (0..5)
        .map(|_| auth("203.0.113.10", AuthResult::Failure, 12))
        .collect();

    let summaries = aggregate_ip_summaries(&auth_events, &[], &State::default());
    let item = summary(&summaries, "203.0.113.10");

    assert_eq!(item.login_attempts, 5);
    assert_eq!(item.successes, 0);
    assert_eq!(item.failures, 5);
}

#[test]
fn guard_failures_do_not_double_count_auth_attempts() {
    let auth_events = [auth("203.0.113.10", AuthResult::Failure, 11)];
    let guard_events = [GuardFailureEvent {
        timestamp: timestamp(12),
        ip: "203.0.113.10".parse().unwrap(),
    }];
    let summaries = aggregate_ip_summaries(&auth_events, &guard_events, &State::default());
    let item = summary(&summaries, "203.0.113.10");

    assert_eq!(item.login_attempts, 1);
    assert_eq!(item.failures, 1);
    assert_eq!(item.guard_failures, 1);
    assert_eq!(item.last_seen, Some(timestamp(12)));
}

#[test]
fn state_only_ips_are_blocked_with_expiration() {
    let ip = "203.0.113.20".parse().unwrap();
    let expires_at = timestamp(15);
    let state = State {
        blocks: HashMap::from([(
            ip,
            BlockRecord {
                created_at: timestamp(10),
                expires_at,
                failures: 5,
            },
        )]),
        ..State::default()
    };

    let summaries = aggregate_ip_summaries(&[], &[], &state);
    let item = summary(&summaries, "203.0.113.20");

    assert!(item.blocked);
    assert_eq!(item.expires_at, Some(expires_at));
    assert_eq!(item.last_seen, None);
}

#[test]
fn summaries_sort_by_guard_failures_failures_last_seen_then_ip() {
    let auth_events = [
        auth("203.0.113.40", AuthResult::Failure, 13),
        auth("203.0.113.30", AuthResult::Failure, 12),
        auth("203.0.113.30", AuthResult::Failure, 12),
        auth("203.0.113.20", AuthResult::Failure, 11),
        auth("203.0.113.25", AuthResult::Failure, 11),
        auth("203.0.113.10", AuthResult::Failure, 11),
    ];
    let guard_events = [
        GuardFailureEvent {
            timestamp: timestamp(10),
            ip: "203.0.113.20".parse().unwrap(),
        },
        GuardFailureEvent {
            timestamp: timestamp(10),
            ip: "203.0.113.10".parse().unwrap(),
        },
        GuardFailureEvent {
            timestamp: timestamp(9),
            ip: "203.0.113.10".parse().unwrap(),
        },
        GuardFailureEvent {
            timestamp: timestamp(9),
            ip: "203.0.113.40".parse().unwrap(),
        },
        GuardFailureEvent {
            timestamp: timestamp(9),
            ip: "203.0.113.30".parse().unwrap(),
        },
        GuardFailureEvent {
            timestamp: timestamp(9),
            ip: "203.0.113.25".parse().unwrap(),
        },
    ];

    let summaries = aggregate_ip_summaries(&auth_events, &guard_events, &State::default());
    let ips: Vec<_> = summaries.iter().map(|item| item.ip.to_string()).collect();

    assert_eq!(
        ips,
        [
            "203.0.113.10",
            "203.0.113.30",
            "203.0.113.40",
            "203.0.113.20",
            "203.0.113.25",
        ]
    );
}
