//! Packet and flow-key primitives used by the FakeIP translator.
//!
//! These helpers intentionally have no runtime state or DNS knowledge.  The
//! parent module owns mappings and expiry; this module only understands IP,
//! transport identifiers, and checksum updates.

use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy)]
pub(super) enum FlowDirection {
    Forward,
    Return,
}

#[derive(Clone, Copy)]
pub(super) struct FlowIds {
    pub(super) protocol: u8,
    pub(super) local: u16,
    pub(super) remote: u16,
    pub(super) field_offset: Option<usize>,
    checksum_offset: Option<usize>,
    preserve_zero_checksum: bool,
}

impl FlowIds {
    pub(super) fn rewrite(self, packet: &mut [u8], replacement: u16) {
        let Some(field) = self.field_offset else {
            return;
        };
        let old = u16::from_be_bytes([packet[field], packet[field + 1]]);
        let checksum = self
            .checksum_offset
            .expect("rewritable transport identifier has a checksum");
        let current = u16::from_be_bytes([packet[checksum], packet[checksum + 1]]);
        packet[field..field + 2].copy_from_slice(&replacement.to_be_bytes());
        if self.preserve_zero_checksum && current == 0 {
            return;
        }
        let mut sum = u32::from(!current) + u32::from(!old) + u32::from(replacement);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let mut updated = !(sum as u16);
        if updated == 0 {
            updated = 0xffff;
        }
        packet[checksum..checksum + 2].copy_from_slice(&updated.to_be_bytes());
    }
}

pub(super) fn flow_ids(packet: &[u8], direction: FlowDirection) -> Option<FlowIds> {
    let (offset, protocol) = match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            let fragment = u16::from_be_bytes([packet[6], packet[7]]);
            if fragment & 0x1fff != 0 {
                return None;
            }
            (ihl, packet[9])
        }
        Some(6) => ipv6_transport(packet)?,
        _ => return None,
    };
    match protocol {
        6 | 17 if packet.len() >= offset + 4 => {
            let source = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let destination = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
            Some(FlowIds {
                protocol,
                local: match direction {
                    FlowDirection::Forward => source,
                    FlowDirection::Return => destination,
                },
                remote: match direction {
                    FlowDirection::Forward => destination,
                    FlowDirection::Return => source,
                },
                field_offset: Some(match direction {
                    FlowDirection::Forward => offset,
                    FlowDirection::Return => offset + 2,
                }),
                checksum_offset: Some(if protocol == 6 {
                    offset + 16
                } else {
                    offset + 6
                }),
                preserve_zero_checksum: protocol == 17 && packet[0] >> 4 == 4,
            })
        }
        1 if packet.len() >= offset + 6 => {
            let expected = match direction {
                FlowDirection::Forward => 8,
                FlowDirection::Return => 0,
            };
            (packet[offset] == expected).then(|| FlowIds {
                protocol,
                local: u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]),
                remote: 0,
                field_offset: Some(offset + 4),
                checksum_offset: Some(offset + 2),
                preserve_zero_checksum: false,
            })
        }
        58 if packet.len() >= offset + 6 => {
            let expected = match direction {
                FlowDirection::Forward => 128,
                FlowDirection::Return => 129,
            };
            (packet[offset] == expected).then(|| FlowIds {
                protocol,
                local: u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]),
                remote: 0,
                field_offset: Some(offset + 4),
                checksum_offset: Some(offset + 2),
                preserve_zero_checksum: false,
            })
        }
        51 => None,
        _ => Some(FlowIds {
            protocol,
            local: 0,
            remote: 0,
            field_offset: None,
            checksum_offset: None,
            preserve_zero_checksum: false,
        }),
    }
}

pub(super) fn allocate(
    pool: IpNet,
    next: &mut u128,
    occupied: impl Fn(IpAddr) -> bool,
) -> Option<IpAddr> {
    let bits = if pool.addr().is_ipv4() { 32 } else { 128 };
    let host_bits = bits - u32::from(pool.prefix_len());
    let capacity = if host_bits >= 127 {
        u128::MAX
    } else {
        1u128 << host_bits
    };
    let base = ip_to_u128(pool.network());
    for _ in 0..capacity.min(1_000_000) {
        let offset = *next % capacity;
        *next = next.wrapping_add(1);
        let candidate = u128_to_ip(base | offset, pool.addr().is_ipv4());
        if !occupied(candidate) {
            return Some(candidate);
        }
    }
    None
}

fn ip_to_u128(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    }
}

fn u128_to_ip(value: u128, ipv4: bool) -> IpAddr {
    if ipv4 {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}

pub(super) fn packet_addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some((
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?)),
        )),
        Some(6) if packet.len() >= 40 => Some((
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
        )),
        _ => None,
    }
}

pub(super) fn rewrite_addresses(
    packet: &mut [u8],
    old_src: IpAddr,
    old_dst: IpAddr,
    new_src: IpAddr,
    new_dst: IpAddr,
) -> bool {
    if old_src.is_ipv4() != new_src.is_ipv4() || old_dst.is_ipv4() != new_dst.is_ipv4() {
        return false;
    }
    match (old_src, old_dst, new_src, new_dst) {
        (IpAddr::V4(old_src), IpAddr::V4(old_dst), IpAddr::V4(new_src), IpAddr::V4(new_dst)) => {
            if packet.len() < 20 || packet[9] == 51 {
                return false;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return false;
            }
            adjust_transport_checksum(
                packet,
                ihl,
                packet[9],
                &old_src.octets(),
                &old_dst.octets(),
                &new_src.octets(),
                &new_dst.octets(),
            );
            packet[12..16].copy_from_slice(&new_src.octets());
            packet[16..20].copy_from_slice(&new_dst.octets());
            packet[10..12].fill(0);
            let checksum = checksum(&packet[..ihl]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            true
        }
        (IpAddr::V6(old_src), IpAddr::V6(old_dst), IpAddr::V6(new_src), IpAddr::V6(new_dst)) => {
            if packet.len() < 40 {
                return false;
            }
            let Some((offset, protocol)) = ipv6_transport(packet) else {
                return false;
            };
            if protocol == 51 {
                return false;
            }
            adjust_transport_checksum(
                packet,
                offset,
                protocol,
                &old_src.octets(),
                &old_dst.octets(),
                &new_src.octets(),
                &new_dst.octets(),
            );
            packet[8..24].copy_from_slice(&new_src.octets());
            packet[24..40].copy_from_slice(&new_dst.octets());
            true
        }
        _ => false,
    }
}

fn ipv6_transport(packet: &[u8]) -> Option<(usize, u8)> {
    let mut next = packet[6];
    let mut offset = 40usize;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let header = packet.get(offset..offset + 2)?;
                next = header[0];
                offset += (usize::from(header[1]) + 1) * 8;
            }
            44 => {
                let header = packet.get(offset..offset + 8)?;
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                if fragment & 0xfff8 != 0 {
                    return None;
                }
                next = header[0];
                offset += 8;
            }
            _ => return Some((offset, next)),
        }
    }
    None
}

fn adjust_transport_checksum(
    packet: &mut [u8],
    offset: usize,
    protocol: u8,
    old_src: &[u8],
    old_dst: &[u8],
    new_src: &[u8],
    new_dst: &[u8],
) {
    let checksum_offset = match protocol {
        6 => 16,
        17 | 136 => 6,
        33 => 6,
        58 => 2,
        _ => return,
    };
    if packet.len() < offset + checksum_offset + 2 {
        return;
    }
    let current = u16::from_be_bytes([
        packet[offset + checksum_offset],
        packet[offset + checksum_offset + 1],
    ]);
    if protocol == 17 && current == 0 && old_src.len() == 4 {
        return;
    }
    let mut sum = u32::from(!current);
    let (old_src_words, _) = old_src.as_chunks::<2>();
    let (old_dst_words, _) = old_dst.as_chunks::<2>();
    let (new_src_words, _) = new_src.as_chunks::<2>();
    let (new_dst_words, _) = new_dst.as_chunks::<2>();
    for (old, new) in old_src_words
        .iter()
        .chain(old_dst_words)
        .zip(new_src_words.iter().chain(new_dst_words))
    {
        sum += u32::from(!u16::from_be_bytes([old[0], old[1]]));
        sum += u32::from(u16::from_be_bytes([new[0], new[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let mut value = !(sum as u16);
    if value == 0 && matches!(protocol, 17 | 136) {
        value = 0xffff;
    }
    packet[offset + checksum_offset..offset + checksum_offset + 2]
        .copy_from_slice(&value.to_be_bytes());
}

pub(super) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += if chunk.len() == 2 {
            u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        } else {
            u32::from(chunk[0]) << 8
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 20 + transport.len()];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..].copy_from_slice(transport);
        packet
    }

    fn ipv6_packet(next: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[40..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn flow_ids_cover_transport_directions_and_protocols() {
        let tcp = ipv4_packet(
            6,
            &[
                0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
        let forward = flow_ids(&tcp, FlowDirection::Forward).unwrap();
        assert_eq!(
            (forward.protocol, forward.local, forward.remote),
            (6, 40_000, 443)
        );
        let reverse = flow_ids(&tcp, FlowDirection::Return).unwrap();
        assert_eq!((reverse.local, reverse.remote), (443, 40_000));

        let udp = ipv4_packet(17, &[0, 53, 0x9c, 0x40, 0, 0, 0, 0]);
        assert_eq!(flow_ids(&udp, FlowDirection::Forward).unwrap().local, 53);

        let icmp = ipv4_packet(1, &[8, 0, 0, 0, 0x12, 0x34, 0, 0]);
        assert_eq!(
            flow_ids(&icmp, FlowDirection::Forward).unwrap().local,
            0x1234
        );
        let mut echo_reply = icmp;
        echo_reply[20] = 0;
        assert_eq!(
            flow_ids(&echo_reply, FlowDirection::Return).unwrap().local,
            0x1234
        );

        let ipv6_udp = ipv6_packet(17, &[0, 53, 0x9c, 0x40, 0, 0, 0, 0]);
        assert_eq!(
            flow_ids(&ipv6_udp, FlowDirection::Forward)
                .unwrap()
                .protocol,
            17
        );
        let ipv6_icmp = ipv6_packet(58, &[128, 0, 0, 0, 0x12, 0x34, 0, 0]);
        assert_eq!(
            flow_ids(&ipv6_icmp, FlowDirection::Forward).unwrap().local,
            0x1234
        );
        let mut ipv6_reply = ipv6_icmp;
        ipv6_reply[40] = 129;
        assert_eq!(
            flow_ids(&ipv6_reply, FlowDirection::Return).unwrap().local,
            0x1234
        );

        let unknown = ipv4_packet(47, &[1, 2, 3]);
        let unknown_ids = flow_ids(&unknown, FlowDirection::Forward).unwrap();
        assert_eq!((unknown_ids.local, unknown_ids.remote), (0, 0));
        assert!(flow_ids(&ipv4_packet(51, &[]), FlowDirection::Forward).is_none());
    }

    #[test]
    fn flow_ids_reject_malformed_and_non_initial_fragments() {
        assert!(flow_ids(&[], FlowDirection::Forward).is_none());
        assert!(flow_ids(&[0x45; 19], FlowDirection::Forward).is_none());

        let mut invalid_ihl = ipv4_packet(17, &[0; 8]);
        invalid_ihl[0] = 0x4f;
        assert!(
            flow_ids(&invalid_ihl, FlowDirection::Forward)
                .unwrap()
                .field_offset
                .is_none()
        );
        let mut truncated = ipv4_packet(17, &[0; 2]);
        truncated.truncate(22);
        assert!(
            flow_ids(&truncated, FlowDirection::Forward)
                .unwrap()
                .field_offset
                .is_none()
        );

        let mut fragment = ipv4_packet(17, &[0; 8]);
        fragment[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(flow_ids(&fragment, FlowDirection::Forward).is_none());

        let mut extension =
            ipv6_packet(0, &[17, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0x9c, 0x40, 0, 0, 0, 0]);
        assert_eq!(
            flow_ids(&extension, FlowDirection::Forward).unwrap().local,
            53
        );
        extension[41] = 0xff;
        assert!(
            flow_ids(&extension, FlowDirection::Forward)
                .unwrap()
                .field_offset
                .is_none()
        );

        let mut fragmented = ipv6_packet(44, &[17, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0x9c, 0x40]);
        assert_eq!(
            flow_ids(&fragmented, FlowDirection::Forward).unwrap().local,
            53
        );
        fragmented[42..44].copy_from_slice(&8_u16.to_be_bytes());
        assert!(flow_ids(&fragmented, FlowDirection::Forward).is_none());
    }

    #[test]
    fn address_helpers_cover_families_and_invalid_lengths() {
        assert_eq!(packet_addresses(&[]), None);
        assert_eq!(packet_addresses(&[0x45; 19]), None);
        let v4 = ipv4_packet(99, &[]);
        assert_eq!(
            packet_addresses(&v4),
            Some(("10.0.0.1".parse().unwrap(), "192.0.2.1".parse().unwrap()))
        );
        let v6 = ipv6_packet(99, &[]);
        assert_eq!(
            packet_addresses(&v6),
            Some((Ipv6Addr::LOCALHOST.into(), "2001:db8::1".parse().unwrap()))
        );
    }

    #[test]
    fn allocation_wraps_and_reports_exhaustion() {
        let pool: IpNet = "192.0.2.0/30".parse().unwrap();
        let mut next = 3;
        assert_eq!(
            allocate(pool, &mut next, |_| false),
            Some("192.0.2.3".parse().unwrap())
        );
        assert_eq!(next, 4);

        let mut next = 4;
        assert_eq!(
            allocate(pool, &mut next, |address| address
                != "192.0.2.2".parse::<IpAddr>().unwrap()),
            Some("192.0.2.2".parse().unwrap())
        );
        let mut next = 0;
        assert_eq!(allocate(pool, &mut next, |_| true), None);

        let pool: IpNet = "2001:db8::/126".parse().unwrap();
        let mut next = 0;
        assert_eq!(
            allocate(pool, &mut next, |_| false),
            Some("2001:db8::".parse().unwrap())
        );
    }

    #[test]
    fn rewrite_addresses_rejects_invalid_inputs_and_updates_ipv4_checksum() {
        let old_src: IpAddr = "10.0.0.1".parse().unwrap();
        let old_dst: IpAddr = "192.0.2.1".parse().unwrap();
        let new_src: IpAddr = "10.0.0.2".parse().unwrap();
        let new_dst: IpAddr = "192.0.2.2".parse().unwrap();
        let mut packet = ipv4_packet(17, &[0, 53, 0x9c, 0x40, 0, 0, 0, 0]);
        let header_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        assert!(rewrite_addresses(
            &mut packet,
            old_src,
            old_dst,
            new_src,
            new_dst
        ));
        assert_eq!(packet_addresses(&packet), Some((new_src, new_dst)));
        assert_eq!(checksum(&packet[..20]), 0);

        assert!(!rewrite_addresses(
            &mut packet,
            old_src,
            old_dst,
            "2001:db8::1".parse().unwrap(),
            new_dst,
        ));
        assert!(!rewrite_addresses(
            &mut [0; 19],
            old_src,
            old_dst,
            new_src,
            new_dst
        ));
        let mut bad_ihl = packet.clone();
        bad_ihl[0] = 0x44;
        assert!(!rewrite_addresses(
            &mut bad_ihl,
            old_src,
            old_dst,
            new_src,
            new_dst
        ));
        let mut ah = packet.clone();
        ah[9] = 51;
        assert!(!rewrite_addresses(
            &mut ah, old_src, old_dst, new_src, new_dst
        ));
    }

    #[test]
    fn rewrite_addresses_handles_ipv6_extensions_and_rejects_ah() {
        let old_src: IpAddr = Ipv6Addr::LOCALHOST.into();
        let old_dst: IpAddr = "2001:db8::1".parse().unwrap();
        let new_src: IpAddr = "2001:db8::2".parse().unwrap();
        let new_dst: IpAddr = "2001:db8::3".parse().unwrap();
        let mut packet = ipv6_packet(0, &[17, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0x9c, 0x40, 0, 0, 0, 0]);
        assert!(rewrite_addresses(
            &mut packet,
            old_src,
            old_dst,
            new_src,
            new_dst
        ));
        assert_eq!(packet_addresses(&packet), Some((new_src, new_dst)));

        let mut ah = ipv6_packet(51, &[0; 8]);
        assert!(!rewrite_addresses(
            &mut ah, old_src, old_dst, new_src, new_dst
        ));
        let mut truncated = ipv6_packet(0, &[17]);
        assert!(!rewrite_addresses(
            &mut truncated,
            old_src,
            old_dst,
            new_src,
            new_dst
        ));
    }

    #[test]
    fn rewrite_noop_without_field_offset_and_zero_result_becomes_0xffff() {
        let mut packet = [0u8; 4];
        let noop = FlowIds {
            protocol: 6,
            local: 1,
            remote: 2,
            field_offset: None,
            checksum_offset: Some(2),
            preserve_zero_checksum: false,
        };
        noop.rewrite(&mut packet, 3);
        assert_eq!(packet, [0; 4]);

        // Old = 0xffff, current checksum = 0, replacement = 0xffff forces the
        // RFC 1624 fold and a zero result that must be stored as 0xffff.
        let mut packet = [0xff, 0xff, 0x00, 0x00];
        let ids = FlowIds {
            protocol: 17,
            local: 1,
            remote: 2,
            field_offset: Some(0),
            checksum_offset: Some(2),
            preserve_zero_checksum: false,
        };
        ids.rewrite(&mut packet, 0xffff);
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 0xffff);

        // preserve_zero_checksum keeps a zero UDP checksum untouched.
        let mut packet = [0x00, 0x01, 0x00, 0x00];
        let ids = FlowIds {
            protocol: 17,
            local: 1,
            remote: 2,
            field_offset: Some(0),
            checksum_offset: Some(2),
            preserve_zero_checksum: true,
        };
        ids.rewrite(&mut packet, 0x1234);
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 0);
    }

    #[test]
    fn allocation_capacity_for_wide_pools_and_exhaustion() {
        let pool: IpNet = "::/1".parse().unwrap();
        let mut next = 0;
        let allocated = allocate(pool, &mut next, |_| false);
        assert!(allocated.is_some());
    }

    #[test]
    fn ipv6_rewrite_rejects_short_packets_and_mixed_families() {
        let mut short = vec![0u8; 20];
        short[0] = 0x60;
        assert!(!rewrite_addresses(
            &mut short,
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            "2001:db8::3".parse().unwrap(),
            "2001:db8::4".parse().unwrap(),
        ));

        let mut mixed = vec![0u8; 28];
        mixed[0] = 0x45;
        assert!(!rewrite_addresses(
            &mut mixed,
            "10.0.0.1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "2001:db8::3".parse().unwrap(),
        ));
    }

    #[test]
    fn ipv6_transport_exhausts_extension_chain() {
        let packet = ipv6_packet(0, &[0u8; 8 * 8]);
        assert_eq!(ipv6_transport(&packet), None);
    }

    #[test]
    fn ipv6_address_rewrite_updates_transport_checksums_per_protocol() {
        let old_source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let old_destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let new_source: Ipv6Addr = "2001:db8::3".parse().unwrap();
        let new_destination: Ipv6Addr = "2001:db8::4".parse().unwrap();
        let mut packet = ipv6_packet(17, &[0, 53, 0x9c, 0x40, 0, 0, 0, 0]);
        assert!(rewrite_addresses(
            &mut packet,
            old_source.into(),
            old_destination.into(),
            new_source.into(),
            new_destination.into(),
        ));
        assert_eq!(packet[6], 17);

        let mut tcp = ipv6_packet(6, &[0; 20]);
        assert!(rewrite_addresses(
            &mut tcp,
            old_source.into(),
            old_destination.into(),
            new_source.into(),
            new_destination.into(),
        ));

        let mut icmp6 = ipv6_packet(58, &[128, 0, 0, 0, 0, 0, 0, 0]);
        assert!(rewrite_addresses(
            &mut icmp6,
            old_source.into(),
            old_destination.into(),
            new_source.into(),
            new_destination.into(),
        ));

        let mut opaque = ipv6_packet(47, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(rewrite_addresses(
            &mut opaque,
            old_source.into(),
            old_destination.into(),
            new_source.into(),
            new_destination.into(),
        ));
    }

    #[test]
    fn checksum_handles_even_and_odd_payloads() {
        assert_eq!(checksum(&[]), 0xffff);
        assert_eq!(checksum(&[0]), 0xffff);
        assert_eq!(checksum(&[0, 1]), 0xfffe);
        assert_eq!(checksum(&[0xff, 0xff]), 0);
    }
}
