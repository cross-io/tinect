//! Pure MTU accounting shared by configuration validation and the data plane.

/// Capacity units used by the control and data planes.
///
/// `UserIpCapacity` is the length of a complete user IP packet.  It excludes
/// Tinect's end-to-end DATA and Physical Forward envelopes.  Carrier-specific
/// headers are handled by `carrier` before a link publishes this value.
pub type UserIpCapacity = u16;

/// QUIC's initial minimum path payload before path discovery completes.
///
/// Quinn's `TransportConfig::initial_mtu` and
/// `MtuDiscoveryConfig::upper_bound` use this path-payload unit. They are not
/// the application payload limit accepted by `Connection::send_datagram`.
pub const INITIAL_QUIC_PATH_PAYLOAD_SIZE: usize = 1200;
/// Conservative QUIC 1-RTT packet overhead used by Quinn when calculating the
/// maximum application DATAGRAM payload: flags, an 8-byte connection ID, the
/// maximum packet number, the AEAD tag, and the DATAGRAM frame header.
pub const QUIC_DATAGRAM_OVERHEAD: usize = 38;
/// QUIC application DATAGRAM capacity at the initial path payload limit.
pub const INITIAL_QUIC_DATAGRAM_SIZE: usize =
    INITIAL_QUIC_PATH_PAYLOAD_SIZE - QUIC_DATAGRAM_OVERHEAD;
/// Bare-carrier probe target, including its four-byte receive-id header.
pub const INITIAL_BARE_TARGET_SIZE: usize = 1200;
/// Bare Physical packets carry the destination receive ID outside the
/// Physical frame itself.
pub const BARE_RECEIVE_ID_LEN: usize = 4;
/// Bare Physical-frame capacity after removing the receive-id header once.
pub const INITIAL_BARE_PHYSICAL_SIZE: usize = INITIAL_BARE_TARGET_SIZE - BARE_RECEIVE_ID_LEN;
/// Maximum QUIC path payloads for a 1500-byte Ethernet path. These are the
/// units used by Quinn's DPLPMTUD upper bound, before QUIC packet framing.
pub const MAX_QUIC_IPV4_PATH_PAYLOAD_SIZE: usize = 1472;
pub const MAX_QUIC_IPV6_PATH_PAYLOAD_SIZE: usize = 1452;
/// QUICP path payloads use a 32-byte established TCP header (20-byte base
/// header plus 12-byte Timestamp options).
pub const MAX_QUICP_IPV4_PATH_PAYLOAD_SIZE: usize = 1448;
pub const MAX_QUICP_IPV6_PATH_PAYLOAD_SIZE: usize = 1428;
/// Maximum QUIC application DATAGRAM capacities at the same path limits.
pub const MAX_QUIC_IPV4_DATAGRAM_SIZE: usize =
    MAX_QUIC_IPV4_PATH_PAYLOAD_SIZE - QUIC_DATAGRAM_OVERHEAD;
pub const MAX_QUIC_IPV6_DATAGRAM_SIZE: usize =
    MAX_QUIC_IPV6_PATH_PAYLOAD_SIZE - QUIC_DATAGRAM_OVERHEAD;
pub const MAX_QUICP_IPV4_DATAGRAM_SIZE: usize =
    MAX_QUICP_IPV4_PATH_PAYLOAD_SIZE - QUIC_DATAGRAM_OVERHEAD;
pub const MAX_QUICP_IPV6_DATAGRAM_SIZE: usize =
    MAX_QUICP_IPV6_PATH_PAYLOAD_SIZE - QUIC_DATAGRAM_OVERHEAD;
/// Established fake-TCP data packets have a 20-byte base TCP header plus
/// 12-byte timestamps, in addition to the IP header.
pub const FAKE_TCP_IPV4_DATA_OVERHEAD: usize = 20 + 32;
pub const FAKE_TCP_IPV6_DATA_OVERHEAD: usize = 40 + 32;

/// Returns the fixed Tinect overhead added to one ordinary Forward packet.
///
/// The end-to-end frame currently costs 41 bytes and the per-hop Physical
/// Forward envelope costs 25 bytes.  Keeping the sum here prevents the path,
/// topology, and Circuit layers from each maintaining their own arithmetic.
pub const fn tinect_forward_overhead() -> usize {
    crate::crypto::FRAME_OVERHEAD + crate::physical::FORWARD_OVERHEAD
}

/// Fixed overhead of a FEC source packet. The source carries the existing
/// Forward envelope plus transmission sequence and ESI metadata.
pub const fn tinect_fec_source_overhead() -> usize {
    tinect_forward_overhead() + 8
}

/// Worst-case overhead of a FEC repair packet. Repair vectors contain the
/// two-byte source length prefix and a complete end-to-end frame.
pub const fn tinect_fec_forward_overhead() -> usize {
    crate::crypto::FRAME_OVERHEAD + 41
}

/// Converts a carrier-normalized Physical frame capacity into user IP bytes.
pub const fn user_ip_capacity_from_physical(physical: usize) -> usize {
    physical.saturating_sub(tinect_forward_overhead())
}

/// Converts a user IP capacity into the minimum Physical frame capacity needed
/// for a normal Forward packet without an optional FakeIP envelope.
pub const fn physical_capacity_from_user_ip(user_ip: usize) -> usize {
    user_ip.saturating_add(tinect_forward_overhead())
}

pub const fn user_ip_capacity_from_physical_with_fec(physical: usize, fec: bool) -> usize {
    physical.saturating_sub(if fec {
        tinect_fec_forward_overhead()
    } else {
        tinect_forward_overhead()
    })
}

pub const fn physical_capacity_from_user_ip_with_fec(user_ip: usize, fec: bool) -> usize {
    user_ip.saturating_add(if fec {
        tinect_fec_forward_overhead()
    } else {
        tinect_forward_overhead()
    })
}

/// Selects the DPLPMTUD path-payload upper bound from the actual carrier and
/// address family. `is_ipv4` must come from the resolved `SocketAddr`, not
/// from the endpoint hostname: one hostname may resolve to either family.
pub const fn max_quic_path_payload_size(is_quicp: bool, is_ipv4: bool) -> usize {
    match (is_quicp, is_ipv4) {
        (false, true) => MAX_QUIC_IPV4_PATH_PAYLOAD_SIZE,
        (false, false) => MAX_QUIC_IPV6_PATH_PAYLOAD_SIZE,
        (true, true) => MAX_QUICP_IPV4_PATH_PAYLOAD_SIZE,
        (true, false) => MAX_QUICP_IPV6_PATH_PAYLOAD_SIZE,
    }
}

/// Converts a QUIC DPLPMTUD path-payload limit into the application DATAGRAM
/// limit accepted by `Connection::send_datagram`.
pub const fn quic_datagram_capacity_from_path_payload(path_payload: usize) -> usize {
    path_payload.saturating_sub(QUIC_DATAGRAM_OVERHEAD)
}

/// Selects the maximum application DATAGRAM capacity for a carrier and
/// address family. This is distinct from `max_quic_path_payload_size`, which
/// is only used to configure Quinn's path-MTU search.
pub const fn max_quic_datagram_size(is_quicp: bool, is_ipv4: bool) -> usize {
    quic_datagram_capacity_from_path_payload(max_quic_path_payload_size(is_quicp, is_ipv4))
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::{
        BARE_RECEIVE_ID_LEN, FAKE_TCP_IPV4_DATA_OVERHEAD, FAKE_TCP_IPV6_DATA_OVERHEAD,
        INITIAL_BARE_TARGET_SIZE, INITIAL_QUIC_DATAGRAM_SIZE, INITIAL_QUIC_PATH_PAYLOAD_SIZE,
        MAX_QUIC_IPV4_DATAGRAM_SIZE, MAX_QUIC_IPV4_PATH_PAYLOAD_SIZE, MAX_QUIC_IPV6_DATAGRAM_SIZE,
        MAX_QUIC_IPV6_PATH_PAYLOAD_SIZE, MAX_QUICP_IPV4_DATAGRAM_SIZE,
        MAX_QUICP_IPV4_PATH_PAYLOAD_SIZE, MAX_QUICP_IPV6_DATAGRAM_SIZE,
        MAX_QUICP_IPV6_PATH_PAYLOAD_SIZE, max_quic_datagram_size, max_quic_path_payload_size,
        physical_capacity_from_user_ip, physical_capacity_from_user_ip_with_fec,
        quic_datagram_capacity_from_path_payload, tinect_fec_forward_overhead,
        tinect_fec_source_overhead, tinect_forward_overhead, user_ip_capacity_from_physical,
        user_ip_capacity_from_physical_with_fec,
    };

    #[test]
    fn quicp_ipv6_payload_fits_standard_ethernet_mtu() {
        // IPv6 + TCP(20+12 Timestamp) + QUIC path payload ≤ 1500.
        assert_eq!(40 + 32 + MAX_QUICP_IPV6_PATH_PAYLOAD_SIZE, 1500);
    }

    #[test]
    fn carrier_and_address_family_select_the_expected_path_limit() {
        assert_eq!(
            max_quic_path_payload_size(false, true),
            MAX_QUIC_IPV4_PATH_PAYLOAD_SIZE
        );
        assert_eq!(
            max_quic_path_payload_size(false, false),
            MAX_QUIC_IPV6_PATH_PAYLOAD_SIZE
        );
        assert_eq!(
            max_quic_path_payload_size(true, true),
            MAX_QUICP_IPV4_PATH_PAYLOAD_SIZE
        );
        assert_eq!(
            max_quic_path_payload_size(true, false),
            MAX_QUICP_IPV6_PATH_PAYLOAD_SIZE
        );
    }

    #[test]
    fn quic_application_capacity_is_below_the_path_payload_limit() {
        assert_eq!(quic_datagram_capacity_from_path_payload(1200), 1162);
        assert_eq!(
            max_quic_datagram_size(false, true),
            MAX_QUIC_IPV4_DATAGRAM_SIZE
        );
        assert_eq!(
            max_quic_datagram_size(false, false),
            MAX_QUIC_IPV6_DATAGRAM_SIZE
        );
        assert_eq!(
            max_quic_datagram_size(true, true),
            MAX_QUICP_IPV4_DATAGRAM_SIZE
        );
        assert_eq!(
            max_quic_datagram_size(true, false),
            MAX_QUICP_IPV6_DATAGRAM_SIZE
        );
        assert_eq!(max_quic_datagram_size(false, true), 1434);
        assert_eq!(max_quic_datagram_size(false, false), 1414);
        assert_eq!(max_quic_datagram_size(true, true), 1410);
        assert_eq!(max_quic_datagram_size(true, false), 1390);
        assert_eq!(INITIAL_QUIC_DATAGRAM_SIZE, 1162);
        assert_eq!(
            quic_datagram_capacity_from_path_payload(INITIAL_QUIC_PATH_PAYLOAD_SIZE),
            INITIAL_QUIC_DATAGRAM_SIZE
        );
    }

    #[test]
    fn quic_application_capacity_accounts_for_tinect_once() {
        assert_eq!(tinect_forward_overhead(), 66);
        assert_eq!(
            user_ip_capacity_from_physical(INITIAL_QUIC_DATAGRAM_SIZE),
            1096
        );
        assert_eq!(user_ip_capacity_from_physical(1200), 1134);
        assert_eq!(physical_capacity_from_user_ip(1134), 1200);
        assert_eq!(user_ip_capacity_from_physical(65), 0);
    }

    #[test]
    fn fec_capacity_is_unchanged_when_disabled_and_reserves_worst_case_repair_space() {
        assert_eq!(tinect_fec_forward_overhead(), 82);
        assert_eq!(
            user_ip_capacity_from_physical_with_fec(1200, false),
            user_ip_capacity_from_physical(1200)
        );
        assert_eq!(user_ip_capacity_from_physical_with_fec(1200, true), 1118);
    }

    #[test]
    fn bare_udp_receive_id_is_removed_before_tinect_overhead() {
        let physical = INITIAL_BARE_TARGET_SIZE - BARE_RECEIVE_ID_LEN;
        let user = user_ip_capacity_from_physical(physical);
        assert_eq!(user, 1130);
        assert_eq!(physical_capacity_from_user_ip(user), physical);
        assert_eq!(
            physical_capacity_from_user_ip(user) + BARE_RECEIVE_ID_LEN,
            1200
        );
    }

    #[test]
    fn fake_tcp_ipv4_and_ipv6_outer_headers_are_counted_once() {
        let cases = [
            (
                true,
                MAX_QUICP_IPV4_PATH_PAYLOAD_SIZE,
                FAKE_TCP_IPV4_DATA_OVERHEAD,
                1378,
            ),
            (
                false,
                MAX_QUICP_IPV6_PATH_PAYLOAD_SIZE,
                FAKE_TCP_IPV6_DATA_OVERHEAD,
                1358,
            ),
        ];
        for (is_ipv4, fake_tcp_payload_limit, outer_overhead, expected_user) in cases {
            assert_eq!(
                fake_tcp_payload_limit + outer_overhead,
                1500,
                "fake-TCP {} outer header accounting",
                if is_ipv4 { "IPv4" } else { "IPv6" }
            );
            let physical = fake_tcp_payload_limit - BARE_RECEIVE_ID_LEN;
            let user = user_ip_capacity_from_physical(physical);
            assert_eq!(user, expected_user);
            assert_eq!(
                physical_capacity_from_user_ip(user) + BARE_RECEIVE_ID_LEN + outer_overhead,
                1500
            );
        }
    }

    #[test]
    fn carrier_capacity_table_round_trips_without_unit_changes() {
        let cases = [
            ("quic/IPv4", false, true, false, BARE_RECEIVE_ID_LEN, 1402),
            ("quic/IPv6", false, false, false, BARE_RECEIVE_ID_LEN, 1382),
            ("quicfull/IPv4", false, true, true, 0, 1368),
            ("quicfull/IPv6", false, false, true, 0, 1348),
            (
                "quic-faketcp/IPv4",
                true,
                true,
                false,
                BARE_RECEIVE_ID_LEN,
                1378,
            ),
            (
                "quic-faketcp/IPv6",
                true,
                false,
                false,
                BARE_RECEIVE_ID_LEN,
                1358,
            ),
            ("quicfull-faketcp/IPv4", true, true, true, 0, 1344),
            ("quicfull-faketcp/IPv6", true, false, true, 0, 1324),
        ];
        for (carrier, is_quicp, is_ipv4, is_quicfull, carrier_overhead, expected_user) in cases {
            let path_payload = max_quic_path_payload_size(is_quicp, is_ipv4);
            let carrier_limit = if is_quicfull {
                max_quic_datagram_size(is_quicp, is_ipv4)
            } else {
                path_payload
            };
            let physical = carrier_limit - carrier_overhead;
            let user = user_ip_capacity_from_physical(physical);
            assert_eq!(user, expected_user, "{carrier}");
            assert_eq!(
                physical_capacity_from_user_ip(user) + carrier_overhead,
                carrier_limit,
                "{carrier} carrier limit"
            );
        }
    }

    #[test]
    fn fec_source_overhead_and_physical_capacity_with_fec_round_trip() {
        assert_eq!(tinect_fec_source_overhead(), tinect_forward_overhead() + 8);
        assert_eq!(
            physical_capacity_from_user_ip_with_fec(1200, true),
            1200 + tinect_fec_forward_overhead()
        );
        assert_eq!(
            physical_capacity_from_user_ip_with_fec(1200, false),
            1200 + tinect_forward_overhead()
        );
    }
}
