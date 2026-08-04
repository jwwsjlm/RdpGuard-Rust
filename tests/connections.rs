use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rdpguard::connections::{decode_tcp_port, ipv4_from_windows, ipv6_from_windows};

#[test]
fn windows_tcp_ports_are_decoded_from_network_byte_order() {
    assert_eq!(decode_tcp_port(u32::from(3389u16.to_be())), 3389);
}

#[test]
fn windows_connection_addresses_preserve_ipv4_and_ipv6() {
    assert_eq!(
        ipv4_from_windows(u32::from_ne_bytes([203, 0, 113, 8])),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))
    );
    assert_eq!(
        ipv6_from_windows([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
    );
}
