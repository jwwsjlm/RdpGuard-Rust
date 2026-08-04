use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rdpguard::connections::{
    connection_from_parts, ipv4_from_windows, ipv6_from_windows, port_from_windows,
};

#[test]
fn windows_network_values_convert_to_addresses_and_ports() {
    assert_eq!(port_from_windows(0x0000_3d0d), 3389);
    assert_eq!(
        ipv4_from_windows(u32::from_ne_bytes([192, 0, 2, 10])),
        Ipv4Addr::new(192, 0, 2, 10)
    );
    assert_eq!(
        ipv6_from_windows([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        "2001:db8::1".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn only_established_connections_to_the_rdp_port_are_kept() {
    let ip: IpAddr = "198.51.100.20".parse().unwrap();
    let connection = connection_from_parts(ip, 3389, 50_000, 5, 1234, 3389).unwrap();

    assert_eq!(connection.remote_ip, ip);
    assert_eq!(connection.local_port, 3389);
    assert_eq!(connection.remote_port, 50_000);
    assert_eq!(connection.state, "ESTABLISHED");
    assert_eq!(connection.pid, 1234);

    assert!(connection_from_parts(ip, 3390, 50_000, 5, 1234, 3389).is_none());
    assert!(connection_from_parts(ip, 3389, 50_000, 2, 1234, 3389).is_none());
}
