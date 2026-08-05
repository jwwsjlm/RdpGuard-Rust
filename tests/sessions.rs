use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rdpguard::sessions::{
    RawSessionSource, decode_wts_client_address, select_active_public_rdp_sources,
};

fn ipv4_address(address: [u8; 4]) -> [u8; 20] {
    let mut raw = [0; 20];
    raw[2..6].copy_from_slice(&address);
    raw
}

#[test]
fn wts_client_addresses_decode_ipv4_and_ipv6() {
    assert_eq!(
        decode_wts_client_address(2, ipv4_address([203, 0, 113, 8])),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)))
    );

    let ipv6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let mut raw = [0; 20];
    raw[..16].copy_from_slice(&ipv6.octets());
    assert_eq!(decode_wts_client_address(23, raw), Some(IpAddr::V6(ipv6)));
    assert_eq!(decode_wts_client_address(0, [0; 20]), None);
}

#[test]
fn only_active_authenticated_public_rdp_sessions_are_suggested() {
    let records = vec![
        RawSessionSource {
            state: 0,
            protocol_type: 2,
            address_family: 2,
            address: ipv4_address([8, 8, 8, 8]),
        },
        RawSessionSource {
            state: 4,
            protocol_type: 2,
            address_family: 2,
            address: ipv4_address([1, 1, 1, 1]),
        },
        RawSessionSource {
            state: 0,
            protocol_type: 0,
            address_family: 2,
            address: ipv4_address([9, 9, 9, 9]),
        },
        RawSessionSource {
            state: 0,
            protocol_type: 2,
            address_family: 2,
            address: ipv4_address([192, 168, 5, 10]),
        },
        RawSessionSource {
            state: 0,
            protocol_type: 2,
            address_family: 2,
            address: ipv4_address([8, 8, 8, 8]),
        },
    ];

    assert_eq!(
        select_active_public_rdp_sources(&records),
        vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
    );
}
