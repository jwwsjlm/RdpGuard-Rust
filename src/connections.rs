use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP_STATE_ESTAB, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpConnection {
    pub remote_ip: IpAddr,
    pub local_port: u16,
    pub pid: u32,
}

pub fn decode_tcp_port(value: u32) -> u16 {
    u16::from_be(value as u16)
}

pub fn ipv4_from_windows(value: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(value.to_ne_bytes()))
}

pub fn ipv6_from_windows(value: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(value))
}

pub fn established_rdp_connections(port: u16) -> Result<Vec<RdpConnection>> {
    let mut connections = query_ipv4(port)?;
    connections.extend(query_ipv6(port)?);
    connections.sort_by_key(|connection| (connection.remote_ip, connection.pid));
    connections.dedup();
    Ok(connections)
}

fn tcp_table(address_family: u32) -> Result<Vec<usize>> {
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    let mut size = 0u32;
    let first = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            address_family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        bail!("CONN001: failed to size TCP table (Windows error {first})");
    }
    for _ in 0..4 {
        let words = (size as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0usize; words];
        let result = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast(),
                &mut size,
                0,
                address_family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if result == 0 {
            return Ok(buffer);
        }
        if result != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return Err(std::io::Error::from_raw_os_error(result as i32))
                .context("CONN001: failed to read TCP table");
        }
    }
    bail!("CONN001: TCP table changed repeatedly while it was being read")
}

fn query_ipv4(port: u16) -> Result<Vec<RdpConnection>> {
    let buffer = tcp_table(AF_INET.into())?;
    let table = unsafe { &*(buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>()) };
    let rows =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
    Ok(rows
        .iter()
        .filter(|row| {
            row.dwState == MIB_TCP_STATE_ESTAB as u32 && decode_tcp_port(row.dwLocalPort) == port
        })
        .map(|row| RdpConnection {
            remote_ip: ipv4_from_windows(row.dwRemoteAddr),
            local_port: port,
            pid: row.dwOwningPid,
        })
        .collect())
}

fn query_ipv6(port: u16) -> Result<Vec<RdpConnection>> {
    let buffer = tcp_table(AF_INET6.into())?;
    let table = unsafe { &*(buffer.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>()) };
    let rows =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
    Ok(rows
        .iter()
        .filter(|row| {
            row.dwState == MIB_TCP_STATE_ESTAB as u32 && decode_tcp_port(row.dwLocalPort) == port
        })
        .map(|row| RdpConnection {
            remote_ip: ipv6_from_windows(row.ucRemoteAddr),
            local_port: port,
            pid: row.dwOwningPid,
        })
        .collect())
}
