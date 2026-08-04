use std::{collections::HashMap, net::IpAddr};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};
use windows::{
    Win32::System::EventLog::{
        EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
        EvtRender, EvtRenderEventXml,
    },
    core::HSTRING,
};

use crate::monitor::{AuthEvent, AuthResult, GuardFailureEvent};

const RDP_CHANNEL: &str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
const SECURITY_CHANNEL: &str = "Security";
const ERROR_INSUFFICIENT_BUFFER_HRESULT: u32 = 0x8007007a;
const ERROR_NO_MORE_ITEMS_HRESULT: u32 = 0x80070103;
pub const MAX_QUERY_EVENTS: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventQueryResult<T> {
    pub events: Vec<T>,
    pub truncated: bool,
}

impl<T> EventQueryResult<T> {
    pub fn limited(events: impl IntoIterator<Item = T>) -> Self {
        let mut events = events.into_iter();
        let values = events.by_ref().take(MAX_QUERY_EVENTS).collect();
        Self {
            events: values,
            truncated: events.next().is_some(),
        }
    }
}

pub trait EventSource {
    fn recent_failures(&mut self, window_minutes: u64) -> Result<Vec<IpAddr>>;
}

#[derive(Debug, Default)]
pub struct WindowsEventSource;

struct EventHandle(EVT_HANDLE);

impl Drop for EventHandle {
    fn drop(&mut self) {
        let _ = unsafe { EvtClose(self.0) };
    }
}

pub fn build_query(window_minutes: u64) -> String {
    let milliseconds = window_minutes.saturating_mul(60_000);
    format!("*[System[(EventID=140) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]")
}

pub fn build_auth_query(window_minutes: u64) -> String {
    let milliseconds = window_minutes.saturating_mul(60_000);
    format!(
        "*[System[((EventID=4624) or (EventID=4625)) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]] and EventData[Data[@Name='LogonType']='10']]"
    )
}

impl EventSource for WindowsEventSource {
    fn recent_failures(&mut self, window_minutes: u64) -> Result<Vec<IpAddr>> {
        query_recent_failures(window_minutes)
    }
}

pub fn query_recent_failures(window_minutes: u64) -> Result<Vec<IpAddr>> {
    let result = query_event_xml(RDP_CHANNEL, &build_query(window_minutes))?;
    let mut ips = Vec::new();
    for xml in result.events {
        ips.extend(parse_failed_ips(&xml)?);
    }
    Ok(ips)
}

pub fn query_recent_auth_events(window_minutes: u64) -> Result<EventQueryResult<AuthEvent>> {
    let result = query_event_xml(SECURITY_CHANNEL, &build_auth_query(window_minutes))?;
    let mut events = Vec::new();
    for xml in result.events {
        if let Some(event) = parse_auth_event(&xml)? {
            events.push(event);
        }
    }
    Ok(EventQueryResult {
        events,
        truncated: result.truncated,
    })
}

pub fn query_recent_guard_failures(
    window_minutes: u64,
) -> Result<EventQueryResult<GuardFailureEvent>> {
    let result = query_event_xml(RDP_CHANNEL, &build_query(window_minutes))?;
    let mut events = Vec::new();
    for xml in result.events {
        events.extend(parse_guard_failure_events(&xml)?);
    }
    Ok(EventQueryResult {
        events,
        truncated: result.truncated,
    })
}

pub fn query_event_xml(channel: &str, query: &str) -> Result<EventQueryResult<String>> {
    let channel = HSTRING::from(channel);
    let query = HSTRING::from(query);
    let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;
    let query_handle = EventHandle(
        unsafe { EvtQuery(None, &channel, &query, flags) }
            .context("failed to query the Windows event log")?,
    );
    let mut events = Vec::new();

    'query: loop {
        let mut raw_events = [0isize; 16];
        let mut returned = 0u32;
        match unsafe { EvtNext(query_handle.0, &mut raw_events, 0, 0, &mut returned) } {
            Ok(()) => {
                let handles: Vec<_> = raw_events[..returned as usize]
                    .iter()
                    .map(|raw| EventHandle(EVT_HANDLE(*raw)))
                    .collect();
                for handle in &handles {
                    let xml = render_event_xml(handle.0)?;
                    events.push(xml);
                    if events.len() > MAX_QUERY_EVENTS {
                        break 'query;
                    }
                }
            }
            Err(error) if error.code().0 as u32 == ERROR_NO_MORE_ITEMS_HRESULT => break,
            Err(error) => return Err(error).context("failed to read Windows event records"),
        }
    }

    Ok(EventQueryResult::limited(events))
}

fn render_event_xml(event: EVT_HANDLE) -> Result<String> {
    let mut used_bytes = 0u32;
    let mut property_count = 0u32;
    let first = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut used_bytes,
            &mut property_count,
        )
    };
    match first {
        Err(error) if error.code().0 as u32 == ERROR_INSUFFICIENT_BUFFER_HRESULT => {}
        Err(error) => return Err(error).context("failed to size event XML buffer"),
        Ok(()) => bail!("event XML unexpectedly required no buffer"),
    }

    let mut buffer = vec![0u16; used_bytes.div_ceil(2) as usize];
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            used_bytes,
            Some(buffer.as_mut_ptr().cast()),
            &mut used_bytes,
            &mut property_count,
        )
    }
    .context("failed to render event XML")?;
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).context("event XML was not valid UTF-16")
}

pub fn parse_failed_ips(xml: &str) -> Result<Vec<IpAddr>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut inside_ip_data = false;
    let mut depth = 0usize;
    let mut ips = Vec::new();

    loop {
        match reader.read_event().context("failed to parse event XML")? {
            Event::Start(element) => {
                depth += 1;
                inside_ip_data = element.name().as_ref().ends_with(b"Data")
                    && element
                        .attributes()
                        .filter_map(Result::ok)
                        .any(|attribute| {
                            attribute.key.as_ref() == b"Name"
                                && attribute
                                    .decoded_and_normalized_value(
                                        XmlVersion::Implicit1_0,
                                        reader.decoder(),
                                    )
                                    .is_ok_and(|value| value == "IPString")
                        });
            }
            Event::Text(text) if inside_ip_data => {
                let value = text.decode().context("failed to decode IPString")?;
                if let Ok(ip) = value.parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
            Event::End(element) if element.name().as_ref().ends_with(b"Data") => {
                inside_ip_data = false;
                depth = depth.checked_sub(1).context("unexpected XML closing tag")?;
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).context("unexpected XML closing tag")?;
            }
            Event::Eof => {
                if depth != 0 {
                    bail!("incomplete event XML");
                }
                break;
            }
            _ => {}
        }
    }

    Ok(ips)
}

#[derive(Debug, Default)]
struct ParsedEvent {
    event_id: Option<u32>,
    timestamp: Option<DateTime<Utc>>,
    data: HashMap<String, String>,
}

enum TextTarget {
    EventId,
    Data(String),
}

fn local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

fn attribute_value(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    name: &[u8],
) -> Result<Option<String>> {
    for attribute in element.attributes() {
        let attribute = attribute.context("failed to parse event XML attribute")?;
        if local_name(attribute.key.as_ref()) == name {
            return Ok(Some(
                attribute
                    .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                    .context("failed to decode event XML attribute")?
                    .into_owned(),
            ));
        }
    }
    Ok(None)
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn parse_event_records(xml: &str) -> Result<Vec<ParsedEvent>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut records = Vec::new();
    let mut current = None;
    let mut target = None;
    let mut depth = 0usize;

    loop {
        match reader.read_event().context("failed to parse event XML")? {
            Event::Start(element) => {
                depth += 1;
                match local_name(element.name().as_ref()) {
                    b"Event" => current = Some(ParsedEvent::default()),
                    b"EventID" if current.is_some() => target = Some(TextTarget::EventId),
                    b"TimeCreated" if current.is_some() => {
                        if let Some(value) = attribute_value(&reader, &element, b"SystemTime")? {
                            current.as_mut().unwrap().timestamp = parse_timestamp(&value);
                        }
                    }
                    b"Data" if current.is_some() => {
                        target = attribute_value(&reader, &element, b"Name")?.map(TextTarget::Data);
                    }
                    _ => {}
                }
            }
            Event::Empty(element) => {
                if local_name(element.name().as_ref()) == b"TimeCreated"
                    && let (Some(record), Some(value)) = (
                        current.as_mut(),
                        attribute_value(&reader, &element, b"SystemTime")?,
                    )
                {
                    record.timestamp = parse_timestamp(&value);
                }
            }
            Event::Text(text) => {
                let value = text.decode().context("failed to decode event XML text")?;
                match (&target, current.as_mut()) {
                    (Some(TextTarget::EventId), Some(record)) => {
                        record.event_id = value.parse().ok();
                    }
                    (Some(TextTarget::Data(name)), Some(record)) => {
                        record.data.insert(name.clone(), value.into_owned());
                    }
                    _ => {}
                }
            }
            Event::End(element) => {
                let qualified_name = element.name();
                let name = local_name(qualified_name.as_ref());
                if matches!(name, b"EventID" | b"Data") {
                    target = None;
                }
                if name == b"Event"
                    && let Some(record) = current.take()
                {
                    records.push(record);
                }
                depth = depth.checked_sub(1).context("unexpected XML closing tag")?;
            }
            Event::Eof => {
                if depth != 0 {
                    bail!("incomplete event XML");
                }
                break;
            }
            _ => {}
        }
    }

    Ok(records)
}

pub fn parse_auth_event(xml: &str) -> Result<Option<AuthEvent>> {
    for record in parse_event_records(xml)? {
        let result = match record.event_id {
            Some(4624) => AuthResult::Success,
            Some(4625) => AuthResult::Failure,
            _ => continue,
        };
        let Some(timestamp) = record.timestamp else {
            continue;
        };
        let Some(username) = record.data.get("TargetUserName") else {
            continue;
        };
        if username.is_empty() || username == "-" {
            continue;
        }
        let Some(ip) = record
            .data
            .get("IpAddress")
            .filter(|value| !value.is_empty() && value.as_str() != "-")
            .and_then(|value| value.parse().ok())
        else {
            continue;
        };
        let Some(logon_type) = record
            .data
            .get("LogonType")
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value == 10)
        else {
            continue;
        };
        return Ok(Some(AuthEvent {
            timestamp,
            ip,
            username: username.clone(),
            result,
            event_id: record.event_id.unwrap(),
            logon_type,
        }));
    }
    Ok(None)
}

pub fn parse_guard_failure_events(xml: &str) -> Result<Vec<GuardFailureEvent>> {
    Ok(parse_event_records(xml)?
        .into_iter()
        .filter_map(|record| {
            if record.event_id != Some(140) {
                return None;
            }
            Some(GuardFailureEvent {
                timestamp: record.timestamp?,
                ip: record.data.get("IPString")?.parse().ok()?,
            })
        })
        .collect())
}
