use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Networking::WinSock::{AF_INET, AF_INET6},
    System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSClientAddress,
        WTSClientProtocolType, WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW,
    },
};

use crate::policy::{is_public_unicast, normalize_ip};

const RDP_PROTOCOL_TYPE: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSessionSource {
    pub state: i32,
    pub protocol_type: u16,
    pub address_family: u32,
    pub address: [u8; 20],
}

struct WtsMemory(*mut c_void);

impl Drop for WtsMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WTSFreeMemory(self.0) };
        }
    }
}

pub fn decode_wts_client_address(family: u32, address: [u8; 20]) -> Option<IpAddr> {
    match family {
        value if value == u32::from(AF_INET) => Some(IpAddr::V4(Ipv4Addr::new(
            address[2], address[3], address[4], address[5],
        ))),
        value if value == u32::from(AF_INET6) => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&address[..16]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

pub fn select_active_public_rdp_sources(records: &[RawSessionSource]) -> Vec<IpAddr> {
    let mut addresses: Vec<_> = records
        .iter()
        .filter(|record| record.state == WTSActive && record.protocol_type == RDP_PROTOCOL_TYPE)
        .filter_map(|record| decode_wts_client_address(record.address_family, record.address))
        .map(normalize_ip)
        .filter(|address| is_public_unicast(*address))
        .collect();
    addresses.sort();
    addresses.dedup();
    addresses
}

fn query_session_bytes(session_id: u32, information_class: i32) -> Option<Vec<u8>> {
    let mut buffer = std::ptr::null_mut();
    let mut bytes_returned = 0u32;
    let success = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            information_class,
            &mut buffer,
            &mut bytes_returned,
        )
    };
    if success == 0 || buffer.is_null() || bytes_returned == 0 {
        return None;
    }
    let _memory = WtsMemory(buffer.cast());
    Some(unsafe {
        std::slice::from_raw_parts(buffer.cast::<u8>(), bytes_returned as usize).to_vec()
    })
}

fn enumerate_session_sources() -> Result<Vec<RawSessionSource>> {
    let mut sessions = std::ptr::null_mut::<WTS_SESSION_INFOW>();
    let mut count = 0u32;
    let success = unsafe {
        WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut count)
    };
    if success == 0 {
        return Err(std::io::Error::last_os_error())
            .context("CONN002: failed to enumerate Windows logon sessions");
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if sessions.is_null() {
        bail!("CONN002: Windows returned a null session list");
    }
    let _memory = WtsMemory(sessions.cast());
    let sessions = unsafe { std::slice::from_raw_parts(sessions, count as usize) };
    let mut records = Vec::new();
    for session in sessions {
        let Some(protocol) = query_session_bytes(session.SessionId, WTSClientProtocolType) else {
            continue;
        };
        if protocol.len() < std::mem::size_of::<u16>() {
            continue;
        }
        let protocol_type = u16::from_ne_bytes([protocol[0], protocol[1]]);
        let Some(client) = query_session_bytes(session.SessionId, WTSClientAddress) else {
            continue;
        };
        if client.len() < 24 {
            continue;
        }
        let address_family = u32::from_ne_bytes([client[0], client[1], client[2], client[3]]);
        let mut address = [0; 20];
        address.copy_from_slice(&client[4..24]);
        records.push(RawSessionSource {
            state: session.State,
            protocol_type,
            address_family,
            address,
        });
    }
    Ok(records)
}

pub fn active_public_rdp_session_sources() -> Result<Vec<IpAddr>> {
    enumerate_session_sources().map(|records| select_active_public_rdp_sources(&records))
}
