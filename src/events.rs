use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use quick_xml::{Reader, XmlVersion, events::Event};
use windows::{
    Win32::System::EventLog::{
        EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
        EvtRender, EvtRenderEventXml,
    },
    core::HSTRING,
};

const RDP_CHANNEL: &str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
const ERROR_INSUFFICIENT_BUFFER_HRESULT: u32 = 0x8007007a;
const ERROR_NO_MORE_ITEMS_HRESULT: u32 = 0x80070103;

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

impl EventSource for WindowsEventSource {
    fn recent_failures(&mut self, window_minutes: u64) -> Result<Vec<IpAddr>> {
        query_recent_failures(window_minutes)
    }
}

pub fn query_recent_failures(window_minutes: u64) -> Result<Vec<IpAddr>> {
    let channel = HSTRING::from(RDP_CHANNEL);
    let query = HSTRING::from(build_query(window_minutes));
    let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;
    let query_handle = EventHandle(
        unsafe { EvtQuery(None, &channel, &query, flags) }
            .context("failed to query the RDP event log")?,
    );
    let mut ips = Vec::new();

    loop {
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
                    ips.extend(parse_failed_ips(&xml)?);
                }
            }
            Err(error) if error.code().0 as u32 == ERROR_NO_MORE_ITEMS_HRESULT => break,
            Err(error) => return Err(error).context("failed to read RDP event records"),
        }
    }

    Ok(ips)
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
