use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP_STATE_ESTAB, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW},
};

use crate::monitor::TcpConnection;

const RDP_REGISTRY_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
const RDP_PORT_VALUE: &str = "PortNumber";

pub fn port_from_windows(value: u32) -> u16 {
    u16::from_be(value as u16)
}

pub fn ipv4_from_windows(value: u32) -> Ipv4Addr {
    Ipv4Addr::from(value.to_ne_bytes())
}

pub fn ipv6_from_windows(value: [u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(value)
}

pub fn connection_from_parts(
    remote_ip: IpAddr,
    local_port: u16,
    remote_port: u16,
    state: u32,
    pid: u32,
    rdp_port: u16,
) -> Option<TcpConnection> {
    if state != MIB_TCP_STATE_ESTAB as u32 || local_port != rdp_port {
        return None;
    }
    Some(TcpConnection {
        remote_ip,
        local_port,
        remote_port,
        state: "ESTABLISHED".into(),
        pid,
    })
}

pub fn read_rdp_port() -> Result<u16> {
    let key: Vec<u16> = RDP_REGISTRY_KEY.encode_utf16().chain(Some(0)).collect();
    let value_name: Vec<u16> = RDP_PORT_VALUE.encode_utf16().chain(Some(0)).collect();
    let mut value = 0u32;
    let mut size = size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("failed to read the configured RDP port");
    }
    u16::try_from(value).context("configured RDP port is outside the valid range")
}

fn query_table(family: u32) -> Result<Vec<u8>> {
    let mut size = 0u32;
    let first = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            1,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER {
        bail!(
            "failed to size the TCP table: {}",
            std::io::Error::from_raw_os_error(first as i32)
        );
    }
    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            1,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("failed to read the TCP table");
    }
    Ok(buffer)
}

unsafe fn rows_from_buffer<T: Copy>(buffer: &[u8]) -> Result<Vec<T>> {
    if buffer.len() < size_of::<u32>() {
        bail!("TCP table buffer is too small");
    }
    let count = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    let bytes = count
        .checked_mul(size_of::<T>())
        .and_then(|rows| rows.checked_add(size_of::<u32>()))
        .context("TCP table size overflow")?;
    if bytes > buffer.len() {
        bail!("TCP table buffer is truncated");
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let offset = size_of::<u32>() + index * size_of::<T>();
        rows.push(unsafe { ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<T>()) });
    }
    Ok(rows)
}

pub fn query_rdp_connections(rdp_port: u16) -> Result<Vec<TcpConnection>> {
    let mut connections = Vec::new();

    let ipv4 = query_table(AF_INET as u32)?;
    for row in unsafe { rows_from_buffer::<MIB_TCPROW_OWNER_PID>(&ipv4)? } {
        if let Some(connection) = connection_from_parts(
            IpAddr::V4(ipv4_from_windows(row.dwRemoteAddr)),
            port_from_windows(row.dwLocalPort),
            port_from_windows(row.dwRemotePort),
            row.dwState,
            row.dwOwningPid,
            rdp_port,
        ) {
            connections.push(connection);
        }
    }

    let ipv6 = query_table(AF_INET6 as u32)?;
    for row in unsafe { rows_from_buffer::<MIB_TCP6ROW_OWNER_PID>(&ipv6)? } {
        if let Some(connection) = connection_from_parts(
            IpAddr::V6(ipv6_from_windows(row.ucRemoteAddr)),
            port_from_windows(row.dwLocalPort),
            port_from_windows(row.dwRemotePort),
            row.dwState,
            row.dwOwningPid,
            rdp_port,
        ) {
            connections.push(connection);
        }
    }

    connections.sort_by_key(|connection| (connection.remote_ip, connection.remote_port));
    Ok(connections)
}
