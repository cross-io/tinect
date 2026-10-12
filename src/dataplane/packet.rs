//! Pure inner-IP parsing, flow inspection, and TCP MSS clamping.

use super::*;

/// The portion of an inner IPv4/IPv6 packet that routing and policy need.
/// IPv6 extension headers are walked so TCP/UDP behind Hop-by-Hop, Routing,
/// or Destination Options headers remain subject to the same ACL. Packets
/// with a Fragment Header are rejected until bounded reassembly is designed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Protocol,
    pub source_port: u16,
    pub destination_port: u16,
    pub transport_offset: usize,
}

pub fn inspect_packet(packet: &[u8]) -> Option<PacketMeta> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => inspect_ipv4_packet(packet),
        Some(6) => inspect_ipv6_packet(packet),
        _ => None,
    }
}

/// Returns the destination from a syntactically valid IPv4/IPv6 header,
/// without requiring a recognized transport protocol. Direct fallback must be
/// able to handle fake-IP packets whose L4 protocol is intentionally opaque.
pub fn inspect_ip_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            (header_len >= 20 && packet.len() >= header_len).then(|| {
                IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                ))
            })
        }
        Some(6) if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).ok()?,
        ))),
        _ => None,
    }
}

/// Returns the source from a syntactically valid IPv4/IPv6 header without
/// requiring a recognized transport protocol. Source binding is an IP-layer
/// identity check and must also cover unknown protocols and fragments.
pub fn inspect_ip_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            (header_len >= 20 && packet.len() >= header_len).then(|| {
                IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                ))
            })
        }
        Some(6) if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).ok()?,
        ))),
        _ => None,
    }
}

/// Returns the six-bit DSCP value from an IPv4 or IPv6 header.
pub fn packet_dscp(packet: &[u8]) -> Option<u8> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some(packet[1] >> 2),
        Some(6) if packet.len() >= 40 => {
            let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
            Some(traffic_class >> 2)
        }
        _ => None,
    }
}

/// Rewrites DSCP while preserving ECN. IPv4's header checksum is recomputed;
/// IPv6 has no header checksum and therefore only needs the traffic-class
/// bytes updated.
pub fn set_packet_dscp(packet: &mut [u8], dscp: u8) -> bool {
    if dscp > 63 {
        return false;
    }
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || packet.len() < header_len {
                return false;
            }
            packet[1] = (dscp << 2) | (packet[1] & 0x03);
            packet[10..12].fill(0);
            let mut sum = 0_u32;
            let (chunks, []) = packet[..header_len].as_chunks::<2>() else {
                return false;
            };
            for chunk in chunks {
                sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            true
        }
        Some(6) if packet.len() >= 40 => {
            let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
            let next = (dscp << 2) | (traffic_class & 0x03);
            packet[0] = (packet[0] & 0xf0) | (next >> 4);
            packet[1] = (packet[1] & 0x0f) | (next << 4);
            true
        }
        _ => false,
    }
}

fn transport(protocol: u8) -> Option<Protocol> {
    match protocol {
        6 => Some(Protocol::Tcp),
        17 => Some(Protocol::Udp),
        1 => Some(Protocol::Icmp),
        58 => Some(Protocol::Icmpv6),
        _ => None,
    }
}

fn inspect_ipv4_packet(packet: &[u8]) -> Option<PacketMeta> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    // A port ACL cannot safely authorize an IP fragment without a bounded,
    // source-isolated reassembler. In a non-first fragment the bytes below
    // are arbitrary transport payload, not source/destination ports; even a
    // first fragment cannot be authorized independently of its companions.
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }
    let protocol = transport(packet[9])?;
    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let (source_port, destination_port) = ports(packet, header_len, protocol);
    Some(PacketMeta {
        source,
        destination,
        protocol,
        source_port,
        destination_port,
        transport_offset: header_len,
    })
}

fn inspect_ipv6_packet(packet: &[u8]) -> Option<PacketMeta> {
    if packet.len() < 40 {
        return None;
    }
    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
    let mut next = packet[6];
    let mut offset = 40;
    // RFC 8200 extension headers. ESP and unknown headers are deliberately
    // rejected: without seeing the transport protocol an egress ACL cannot
    // safely decide whether to allow them.
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let header = packet.get(offset..offset + 2)?;
                next = header[0];
                let length = (usize::from(header[1]) + 1) * 8;
                offset = offset.checked_add(length)?;
                if offset > packet.len() {
                    return None;
                }
            }
            44 => {
                // Do not parse a partial IPv6 datagram as transport data.
                // Fragment reassembly has to be an explicit, bounded
                // data-plane feature before port ACLs can support it.
                let _header = packet.get(offset..offset + 8)?;
                return None;
            }
            51 => {
                // ESP authenticates and encrypts everything after its SPI and
                // sequence number, so the transport header is not visible
                // here.  Without a bounded ESP decryption boundary an egress
                // ACL cannot decide what the packet carries; reject it.
                return None;
            }
            _ => break,
        }
    }
    let protocol = transport(next)?;
    let (source_port, destination_port) = ports(packet, offset, protocol);
    Some(PacketMeta {
        source,
        destination,
        protocol,
        source_port,
        destination_port,
        transport_offset: offset,
    })
}

fn ports(packet: &[u8], offset: usize, protocol: Protocol) -> (u16, u16) {
    if matches!(protocol, Protocol::Tcp | Protocol::Udp) && packet.len() >= offset + 4 {
        (
            u16::from_be_bytes([packet[offset], packet[offset + 1]]),
            u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]),
        )
    } else {
        (0, 0)
    }
}

/// Clamp TCP SYN MSS to the effective inner path MTU. This mirrors tinc's
/// ClampMSS behaviour and avoids relying on ICMP PTB messages surviving every
/// NAT/firewall. Non-SYN traffic and packets without an MSS option are left
/// untouched.
pub fn clamp_tcp_mss(packet: &mut [u8], mtu: u16) -> bool {
    let Some(meta) = inspect_packet(packet) else {
        return false;
    };
    if meta.protocol != Protocol::Tcp
        || packet.len() < meta.transport_offset + 20
        || packet[meta.transport_offset + 13] & 0x02 == 0
    {
        return false;
    }
    let tcp_len = usize::from(packet[meta.transport_offset + 12] >> 4) * 4;
    if tcp_len < 20 || packet.len() < meta.transport_offset + tcp_len {
        return false;
    }
    let ip_len = meta.transport_offset;
    let limit = usize::from(mtu).saturating_sub(ip_len + tcp_len) as u16;
    // Never advertise MSS 0: with a pathological budget smaller than the
    // headers the peer would stall. Leave the original MSS so the packet is
    // dropped as exceeds_path_mtu and the sender learns via PTB instead.
    if limit == 0 {
        return false;
    }
    let mut offset = ip_len + 20;
    let end = ip_len + tcp_len;
    let mut changed = false;
    while offset < end {
        match packet[offset] {
            0 => break,
            1 => offset += 1,
            2 if offset + 3 < end && packet[offset + 1] == 4 => {
                let current = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                if current > limit {
                    packet[offset + 2..offset + 4].copy_from_slice(&limit.to_be_bytes());
                    changed = true;
                }
                offset += 4;
            }
            _ => {
                let length = usize::from(packet.get(offset + 1).copied().unwrap_or(0));
                if length < 2 || offset + length > end {
                    break;
                }
                offset += length;
            }
        }
    }
    if changed {
        packet[ip_len + 16..ip_len + 18].fill(0);
        // The TCP checksum covers the complete segment, not just its header.
        // A SYN may legally carry data (for example, TCP Fast Open).
        let checksum = tcp_checksum(packet, &meta);
        packet[ip_len + 16..ip_len + 18].copy_from_slice(&checksum.to_be_bytes());
    }
    changed
}

pub(super) fn clamp_mss_if_enabled(packet: &mut [u8], mtu: u16, enabled: bool) -> bool {
    enabled && clamp_tcp_mss(packet, mtu)
}

/// Builds an ICMP Fragmentation-Needed (IPv4, type 3 code 4) or Packet-Too-Big
/// (IPv6, type 2) message for an inner packet that exceeds the current path
/// budget.
///
/// The returned packet is addressed from the original destination back to the
/// original source with `mtu` as the advertised next-hop MTU, so a kernel
/// receiving it via the TUN can shrink its route MTU and retransmit smaller
/// segments instead of retrying the same oversized packet forever (which is
/// what stalls bulk TCP such as a larger hybrid-KEX reply when `tcp_mtu_probing`
/// is disabled).
///
/// Returns `None` for packets that must not trigger an error (fragments,
/// ICMP errors themselves, malformed headers) to avoid loops and
/// amplification. Callers must rate-limit transmission; this function is pure.
pub fn build_ptb_for_oversize(original: &[u8], mtu: u16) -> Option<Vec<u8>> {
    // Never advertise MTU 0: kernels ignore it and it indicates a transient
    // empty budget rather than a real path. The caller drops the packet and
    // retries on retransmit once the budget is repopulated.
    if mtu == 0 {
        return None;
    }
    match original.first().map(|byte| byte >> 4) {
        Some(4) => build_ipv4_ptb(original, mtu),
        Some(6) => build_ipv6_ptb(original, mtu),
        _ => None,
    }
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks(2) {
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

fn icmp_checksum(data: &[u8]) -> u16 {
    ipv4_header_checksum(data)
}

fn build_ipv4_ptb(original: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if original.len() < 20 {
        return None;
    }
    let ihl = usize::from(original[0] & 0x0f) * 4;
    if ihl < 20 || original.len() < ihl {
        return None;
    }
    let fragment = u16::from_be_bytes([original[6], original[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }
    let src = Ipv4Addr::new(original[12], original[13], original[14], original[15]);
    let dst = Ipv4Addr::new(original[16], original[17], original[18], original[19]);
    // RFC 1812: never send ICMP errors for multicast, broadcast, loopback,
    // or unspecified sources/destinations (loops/amplification).
    if src.is_multicast()
        || dst.is_multicast()
        || src.is_broadcast()
        || dst.is_broadcast()
        || src.is_loopback()
        || dst.is_loopback()
        || src.is_unspecified()
        || dst.is_unspecified()
    {
        return None;
    }
    let protocol = original[9];
    if protocol == 1 {
        let transport = ihl;
        if original.len() <= transport {
            return None;
        }
        // Never answer an ICMP error with another error (loops/amplification).
        // Destination Unreachable (3), Source Quench (4), Redirect (5),
        // Time Exceeded (11), Parameter Problem (12).
        if matches!(original[transport], 3 | 4 | 5 | 11 | 12) {
            return None;
        }
    }
    let embedded_len = ihl.checked_add(8)?;
    if original.len() < embedded_len {
        return None;
    }
    // Outer IPv4 (20) + ICMP Frag-Needed header (8) + embedded header+8.
    let total_len = 20_usize.checked_add(8)?.checked_add(embedded_len)?;
    if total_len > u16::MAX as usize {
        return None;
    }
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    // Identification 0, flags 0, TTL 64, protocol ICMP.
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&original[16..20]);
    packet[16..20].copy_from_slice(&original[12..16]);
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20] = 3;
    packet[21] = 4;
    // RFC 1191 / Linux `struct icmphdr.un.frag`: bytes 4..6 are unused (0),
    // bytes 6..8 are the next-hop MTU. An earlier revision put the MTU at
    // 4..6, which kernels/tcpdump read as unused and ignore.
    packet[26..28].copy_from_slice(&mtu.to_be_bytes());
    packet[28..28 + embedded_len].copy_from_slice(&original[..embedded_len]);
    let checksum = icmp_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

fn build_ipv6_ptb(original: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if original.len() < 48 {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&original[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&original[24..40]).ok()?);
    if src.is_multicast() || dst.is_multicast() {
        return None;
    }
    // Unspecified (::) and loopback (::1) must not trigger errors either.
    if src.is_unspecified() || dst.is_unspecified() || src.is_loopback() || dst.is_loopback() {
        return None;
    }
    // Walk extension headers (like `inspect_ipv6_packet`, max 8) to find a
    // Fragment header or the transport protocol. A fragment or an ICMPv6 error
    // behind any extension must not trigger another error.
    let mut next = original[6];
    let mut offset = 40_usize;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let header = original.get(offset..offset + 2)?;
                next = header[0];
                let length = (usize::from(header[1]) + 1) * 8;
                offset = offset.checked_add(length)?;
                if offset > original.len() {
                    return None;
                }
            }
            44 => return None,
            51 => return None,
            _ => break,
        }
    }
    if next == 58 {
        let icmp_type = *original.get(offset)?;
        if matches!(icmp_type, 1..=4) {
            return None;
        }
    }
    let embedded_len = 48_usize;
    let payload_len = 8_usize.checked_add(embedded_len)?;
    let total_len = 40_usize.checked_add(payload_len)?;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    packet[6] = 58;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&original[24..40]);
    packet[24..40].copy_from_slice(&original[8..24]);
    packet[40] = 2;
    packet[41] = 0;
    packet[44..48].copy_from_slice(&(u32::from(mtu)).to_be_bytes());
    packet[48..48 + embedded_len].copy_from_slice(&original[..embedded_len]);
    let checksum = icmpv6_checksum(&packet[8..40], &packet[40..]);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

fn icmpv6_checksum(addresses: &[u8], icmp: &[u8]) -> u16 {
    debug_assert_eq!(addresses.len(), 32);
    let mut sum = 0_u32;
    for chunk in addresses.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    let icmp_len = icmp.len() as u32;
    sum += (icmp_len >> 16) + (icmp_len & 0xffff);
    sum += 58;
    for chunk in icmp.chunks(2) {
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

pub(super) fn tcp_checksum(packet: &[u8], meta: &PacketMeta) -> u16 {
    let tcp = &packet[meta.transport_offset..];
    let tcp_len = tcp.len();
    let mut sum = 0_u32;
    match (meta.source, meta.destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            for offset in (12..20).step_by(2) {
                sum += u32::from(u16::from_be_bytes([packet[offset], packet[offset + 1]]));
            }
            sum += 6 + tcp_len as u32;
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            let (words, []) = packet[8..40].as_chunks::<2>() else {
                return 0;
            };
            for chunk in words {
                sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            sum += ((tcp_len as u32) >> 16) + ((tcp_len as u32) & 0xffff) + 6;
        }
        _ => return 0,
    }
    for chunk in tcp.chunks(2) {
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

pub fn inspect_ipv4_flow(packet: &[u8]) -> Option<(IpAddr, Protocol, u16)> {
    let meta = inspect_packet(packet)?;
    Some((meta.destination, meta.protocol, meta.destination_port))
}

/// Returns whether a destination may be reinjected by direct fallback.
///
/// The kernel emits link-local multicast and IPv4 broadcast control traffic
/// (IPv6 MLD/NS, IPv4 IGMP probes, DHCP broadcast) for the TUN interface
/// itself. Those are never fake-IP destinations, and reinjecting them would
/// only re-mark and re-route local control packets, so they stay on the
/// ordinary drop path.
pub fn direct_eligible(destination: IpAddr) -> bool {
    !destination.is_multicast()
        && !matches!(destination, IpAddr::V4(address) if address.is_broadcast())
}

/// Segments a TCP super-packet (for example a GSO super-segment from a TUN
/// with offloads on) into chunks that each fit `mtu`.
///
/// Returns `None` when no segmentation is needed or possible: the packet fits,
/// is not TCP data (SYN/RST/URG are never segmented), has no payload, or its
/// headers alone exceed `mtu`. Otherwise returns 2+ packets with identical IP
/// (except lengths/IDs) and TCP headers (except sequence numbers and
/// PSH/FIN, which move to the last segment), each with correct checksums.
///
/// This is what lets bulk TCP (for example a multi-KB hybrid-KEX reply in a
/// single `write`) traverse a path smaller than the sending TUN MTU without
/// being dropped as `packet:exceeds_path_mtu`: with GSO on, the kernel may
/// hand userspace one multi-MSS read; each MSS-sized piece still fits the
/// live path budget once split here.
pub fn segment_tcp_gso(packet: &[u8], mtu: u16) -> Option<Vec<Vec<u8>>> {
    let meta = inspect_packet(packet)?;
    if meta.protocol != Protocol::Tcp {
        return None;
    }
    if packet.len() <= usize::from(mtu) {
        return None;
    }
    let ip_len = meta.transport_offset;
    if packet.len() < ip_len + 20 {
        return None;
    }
    let flags = packet[ip_len + 13];
    // SYN (handshake, small), RST (must not be split), URG (pointer would need
    // per-segment adjustment) are never segmented; the caller drops+PTBs them.
    if flags & 0x02 != 0 || flags & 0x04 != 0 || flags & 0x20 != 0 {
        return None;
    }
    let tcp_len = usize::from(packet[ip_len + 12] >> 4) * 4;
    if tcp_len < 20 || packet.len() < ip_len + tcp_len {
        return None;
    }
    let payload_len = packet.len() - ip_len - tcp_len;
    if payload_len == 0 {
        return None;
    }
    let max_payload = usize::from(mtu).checked_sub(ip_len + tcp_len)?;
    // Refuse degenerate splits: 1-byte payloads would turn one 64KB read into
    // ~64k allocations and queue floods. The caller drops+PTBs instead, and the
    // sender retransmits with a sane MSS.
    const MIN_SEGMENT_PAYLOAD: usize = 64;
    const MAX_SEGMENTS: usize = 128;
    if max_payload < MIN_SEGMENT_PAYLOAD {
        return None;
    }
    if payload_len <= max_payload {
        return None;
    }
    if payload_len.div_ceil(max_payload) > MAX_SEGMENTS {
        return None;
    }
    let is_ipv4 = packet[0] >> 4 == 4;
    let base_seq = u32::from_be_bytes(
        packet[ip_len + 4..ip_len + 8]
            .try_into()
            .expect("TCP sequence fits"),
    );
    let base_id = if is_ipv4 {
        u16::from_be_bytes([packet[4], packet[5]])
    } else {
        0
    };
    let mut segments = Vec::new();
    let mut offset = 0_usize;
    let mut index = 0_u32;
    while offset < payload_len {
        let chunk = max_payload.min(payload_len - offset);
        let seg_len = ip_len + tcp_len + chunk;
        let mut segment = vec![0_u8; seg_len];
        segment[..ip_len].copy_from_slice(&packet[..ip_len]);
        segment[ip_len..ip_len + tcp_len].copy_from_slice(&packet[ip_len..ip_len + tcp_len]);
        segment[ip_len + tcp_len..]
            .copy_from_slice(&packet[ip_len + tcp_len + offset..ip_len + tcp_len + offset + chunk]);
        let seq = base_seq.wrapping_add(offset as u32);
        segment[ip_len + 4..ip_len + 8].copy_from_slice(&seq.to_be_bytes());
        let last = offset + chunk == payload_len;
        if !last {
            segment[ip_len + 13] &= !(0x01 | 0x08);
        }
        if is_ipv4 {
            let total = u16::try_from(seg_len).ok()?;
            segment[2..4].copy_from_slice(&total.to_be_bytes());
            let id = base_id.wrapping_add(index as u16);
            segment[4..6].copy_from_slice(&id.to_be_bytes());
            segment[10..12].fill(0);
            let checksum = ipv4_header_checksum(&segment[..ip_len]);
            segment[10..12].copy_from_slice(&checksum.to_be_bytes());
        } else {
            let payload = u16::try_from(seg_len.checked_sub(40)?).ok()?;
            segment[4..6].copy_from_slice(&payload.to_be_bytes());
        }
        segment[ip_len + 16..ip_len + 18].fill(0);
        let seg_meta = inspect_packet(&segment)?;
        debug_assert_eq!(seg_meta.transport_offset, ip_len);
        let checksum = tcp_checksum(&segment, &seg_meta);
        segment[ip_len + 16..ip_len + 18].copy_from_slice(&checksum.to_be_bytes());
        segments.push(segment);
        offset += chunk;
        index += 1;
    }
    if segments.len() < 2 {
        return None;
    }
    Some(segments)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_rewrites_ipv4_dscp_and_checksum() {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[1] = 0x03;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
        assert_eq!(packet_dscp(&packet), Some(0));
        assert!(set_packet_dscp(&mut packet, 46));
        assert_eq!(packet[1], (46 << 2) | 3);
        assert_eq!(packet_dscp(&packet), Some(46));
        let (chunks, []) = packet.as_chunks::<2>() else {
            unreachable!();
        };
        let sum = chunks.iter().fold(0_u32, |sum, chunk| {
            sum + u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        });
        assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff);
    }

    #[test]
    fn direct_rewrites_ipv4_options_and_preserves_ecn() {
        let mut packet = vec![0_u8; 24];
        packet[0] = 0x46;
        packet[1] = (12 << 2) | 2;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
        packet[20..24].copy_from_slice(&[1, 2, 3, 4]);
        let options = packet[20..24].to_vec();

        assert!(set_packet_dscp(&mut packet, 63));
        assert_eq!(packet_dscp(&packet), Some(63));
        assert_eq!(packet[1] & 0x03, 2);
        assert_eq!(&packet[20..24], options.as_slice());
        let (chunks, []) = packet.as_chunks::<2>() else {
            unreachable!();
        };
        let sum = chunks.iter().fold(0_u32, |sum, chunk| {
            sum + u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        });
        assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff);
    }

    #[test]
    fn direct_rewrites_ipv6_dscp_and_preserves_ecn() {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x6A;
        packet[1] = 0xB7;
        packet[2..4].copy_from_slice(&[0x12, 0x34]);
        let flow_label = packet[1..4].to_vec();
        assert_eq!(packet_dscp(&packet), Some(0x2A));
        assert!(set_packet_dscp(&mut packet, 46));
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(packet_dscp(&packet), Some(46));
        assert_eq!((((packet[0] & 0x0f) << 4) | (packet[1] >> 4)) & 3, 3);
        assert_eq!(packet[1] & 0x0f, 7);
        assert_eq!(&packet[1..4], flow_label.as_slice());
    }

    #[test]
    fn direct_rejects_invalid_or_truncated_headers_without_mutation() {
        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x45;
        let original_ipv4 = ipv4.clone();
        assert!(!set_packet_dscp(&mut ipv4, 64));
        assert_eq!(ipv4, original_ipv4);

        let mut truncated_ipv4 = vec![0x46; 20];
        let original_truncated_ipv4 = truncated_ipv4.clone();
        assert_eq!(packet_dscp(&truncated_ipv4), Some(17));
        assert!(!set_packet_dscp(&mut truncated_ipv4, 46));
        assert_eq!(truncated_ipv4, original_truncated_ipv4);

        let mut truncated_ipv6 = vec![0x60; 39];
        let original_truncated_ipv6 = truncated_ipv6.clone();
        assert_eq!(packet_dscp(&truncated_ipv6), None);
        assert!(!set_packet_dscp(&mut truncated_ipv6, 46));
        assert_eq!(truncated_ipv6, original_truncated_ipv6);
    }

    #[test]
    fn direct_accepts_unknown_transport_for_destination_lookup() {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            inspect_ip_destination(&packet),
            Some("2001:db8::1".parse::<IpAddr>().unwrap())
        );
        assert!(inspect_packet(&packet).is_none());
    }

    #[test]
    fn direct_accepts_unknown_ipv4_transport_for_destination_lookup() {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[9] = 143;
        packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
        assert_eq!(
            inspect_ip_destination(&packet),
            Some("198.51.100.1".parse::<IpAddr>().unwrap())
        );
        assert!(inspect_packet(&packet).is_none());
    }

    #[test]
    fn direct_destination_lookup_rejects_invalid_headers() {
        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x44;
        assert_eq!(inspect_ip_destination(&ipv4), None);
        assert_eq!(inspect_ip_destination(&[0x60; 39]), None);
    }

    #[test]
    fn direct_excludes_multicast_and_broadcast_destinations() {
        assert!(direct_eligible("10.250.0.2".parse().unwrap()));
        assert!(direct_eligible("fd00:250::2".parse().unwrap()));
        assert!(direct_eligible("100.64.0.1".parse().unwrap()));
        assert!(!direct_eligible("224.0.0.251".parse().unwrap()));
        assert!(!direct_eligible("255.255.255.255".parse().unwrap()));
        assert!(!direct_eligible("ff02::16".parse().unwrap()));
        assert!(!direct_eligible("ff00::".parse().unwrap()));
    }

    #[test]
    fn packet_parser_covers_transport_and_extension_rejections() {
        assert!(inspect_packet(&[]).is_none());
        assert!(inspect_packet(&[0x70]).is_none());
        assert!(!clamp_tcp_mss(&mut [0x45], 1200));

        let mut ipv4 = vec![0_u8; 24];
        ipv4[0] = 0x45;
        ipv4[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ipv4[16..20].copy_from_slice(&[198, 51, 100, 1]);
        ipv4[20..24].copy_from_slice(&[12, 34, 0, 53]);
        for protocol in [6, 17, 1, 58] {
            ipv4[9] = protocol;
            assert!(inspect_packet(&ipv4).is_some());
        }
        ipv4[9] = 99;
        assert!(inspect_packet(&ipv4).is_none());
        ipv4[9] = 6;
        ipv4[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(inspect_packet(&ipv4).is_none());
        let mut invalid_ihl = ipv4;
        invalid_ihl[6..8].fill(0);
        invalid_ihl[0] = 0x44;
        assert!(inspect_packet(&invalid_ihl).is_none());

        let mut ipv6 = vec![0_u8; 52];
        ipv6[0] = 0x60;
        ipv6[6] = 0;
        ipv6[40] = 17;
        ipv6[41] = 0;
        ipv6[48..52].copy_from_slice(&[12, 34, 0, 53]);
        assert_eq!(inspect_packet(&ipv6).unwrap().transport_offset, 48);
        let mut truncated_extension = vec![0_u8; 40];
        truncated_extension[0] = 0x60;
        truncated_extension[6] = 0;
        assert!(inspect_packet(&truncated_extension).is_none());

        let mut fragment = vec![0_u8; 48];
        fragment[0] = 0x60;
        fragment[6] = 44;
        assert!(inspect_packet(&fragment).is_none());
        let mut truncated_fragment = vec![0_u8; 44];
        truncated_fragment[0] = 0x60;
        truncated_fragment[6] = 44;
        assert!(inspect_packet(&truncated_fragment).is_none());
        let mut esp = vec![0_u8; 40];
        esp[0] = 0x60;
        esp[6] = 51;
        assert!(inspect_packet(&esp).is_none());
        let mut unknown_ipv6 = esp;
        unknown_ipv6[6] = 99;
        assert!(inspect_packet(&unknown_ipv6).is_none());

        let mut short_tcp = vec![0_u8; 20];
        short_tcp[0] = 0x45;
        short_tcp[9] = 6;
        assert!(!clamp_tcp_mss(&mut short_tcp, 1200));
        let mut invalid_tcp_header = vec![0_u8; 40];
        invalid_tcp_header[0] = 0x45;
        invalid_tcp_header[9] = 6;
        invalid_tcp_header[20 + 12] = 0x40;
        invalid_tcp_header[20 + 13] = 0x02;
        assert!(!clamp_tcp_mss(&mut invalid_tcp_header, 1200));

        let mut eol = vec![0_u8; 44];
        eol[0] = 0x45;
        eol[9] = 6;
        eol[20 + 12] = 0x60;
        eol[20 + 13] = 0x02;
        assert!(!clamp_tcp_mss(&mut eol, 1200));
        let mut malformed_option = eol.clone();
        malformed_option[40] = 3;
        malformed_option[41] = 1;
        assert!(!clamp_tcp_mss(&mut malformed_option, 1200));
        malformed_option[41] = 6;
        assert!(!clamp_tcp_mss(&mut malformed_option, 1200));

        let meta = PacketMeta {
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination: IpAddr::V6(Ipv6Addr::LOCALHOST),
            protocol: Protocol::Tcp,
            source_port: 0,
            destination_port: 0,
            transport_offset: 0,
        };
        assert_eq!(tcp_checksum(&[0; 20], &meta), 0);
    }

    fn ipv4_oversize_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 60];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&60_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 0x50;
        packet
    }

    fn ipv6_oversize_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[40..42].copy_from_slice(&40000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
        packet[52] = 0x50;
        packet
    }

    fn ipv4_checksum_valid(header: &[u8]) -> bool {
        let mut sum = 0_u32;
        for chunk in header.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xffff
    }

    #[test]
    fn ptb_for_ipv4_oversize_carries_mtu_and_valid_checksums() {
        let original = ipv4_oversize_packet();
        let ptb = build_ptb_for_oversize(&original, 1114).expect("IPv4 PTB");
        assert_eq!(ptb[0] >> 4, 4);
        assert_eq!(u16::from_be_bytes([ptb[2], ptb[3]]) as usize, ptb.len());
        assert_eq!(ptb[9], 1);
        assert_eq!(&ptb[12..16], &original[16..20]);
        assert_eq!(&ptb[16..20], &original[12..16]);
        assert!(ipv4_checksum_valid(&ptb[..20]));
        assert_eq!(ptb[20], 3);
        assert_eq!(ptb[21], 4);
        assert_eq!(u16::from_be_bytes([ptb[24], ptb[25]]), 0);
        assert_eq!(u16::from_be_bytes([ptb[26], ptb[27]]), 1114);
        assert_eq!(&ptb[28..56], &original[..28]);
        assert!(ipv4_checksum_valid(&ptb[20..]));
    }

    #[test]
    fn ptb_for_ipv6_oversize_carries_mtu_and_valid_checksum() {
        let original = ipv6_oversize_packet();
        let ptb = build_ptb_for_oversize(&original, 1114).expect("IPv6 PTB");
        assert_eq!(ptb[0] >> 4, 6);
        assert_eq!(
            u16::from_be_bytes([ptb[4], ptb[5]]) as usize,
            ptb.len() - 40
        );
        assert_eq!(ptb[6], 58);
        assert_eq!(&ptb[8..24], &original[24..40]);
        assert_eq!(&ptb[24..40], &original[8..24]);
        assert_eq!(ptb[40], 2);
        assert_eq!(ptb[41], 0);
        assert_eq!(
            u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]),
            1114
        );
        assert_eq!(&ptb[48..96], &original[..48]);
        // Verify the ICMPv6 checksum covers the pseudo-header.
        let mut sum = 0_u32;
        for chunk in ptb[8..40].chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        let icmp_len = (ptb.len() - 40) as u32;
        sum += (icmp_len >> 16) + (icmp_len & 0xffff) + 58;
        for chunk in ptb[40..].chunks(2) {
            sum += if chunk.len() == 2 {
                u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
            } else {
                u32::from(chunk[0]) << 8
            };
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
    }

    #[test]
    fn ptb_is_suppressed_for_fragments_icmp_errors_and_malformed() {
        assert!(build_ptb_for_oversize(&[], 1200).is_none());
        assert!(build_ptb_for_oversize(&[0x70], 1200).is_none());

        let mut fragment = ipv4_oversize_packet();
        fragment[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        assert!(build_ptb_for_oversize(&fragment, 1200).is_none());

        let mut icmp_error = ipv4_oversize_packet();
        icmp_error[9] = 1;
        icmp_error[20] = 3;
        assert!(build_ptb_for_oversize(&icmp_error, 1200).is_none());

        let mut icmp6_error = ipv6_oversize_packet();
        icmp6_error[6] = 58;
        icmp6_error[40] = 3;
        assert!(build_ptb_for_oversize(&icmp6_error, 1200).is_none());

        let mut v6_fragment = ipv6_oversize_packet();
        v6_fragment[6] = 44;
        assert!(build_ptb_for_oversize(&v6_fragment, 1200).is_none());

        assert!(build_ptb_for_oversize(&[0x45; 10], 1200).is_none());
        assert!(build_ptb_for_oversize(&[0x60; 40], 1200).is_none());
    }

    fn tcp_data_packet(payload_len: usize) -> Vec<u8> {
        let total = 20 + 20 + payload_len;
        let mut packet = vec![0_u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        let seq = 1000_u32;
        packet[24..28].copy_from_slice(&seq.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        for (i, byte) in packet[40..].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let meta = inspect_packet(&packet).expect("valid TCP packet");
        let checksum = tcp_checksum(&packet, &meta);
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
        let ip_checksum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }

    fn tcp_segment_valid(segment: &[u8], mtu: u16) -> bool {
        if segment.len() > usize::from(mtu) {
            return false;
        }
        if !ipv4_checksum_valid(&segment[..20]) {
            return false;
        }
        let meta = inspect_packet(segment).expect("segment parses");
        let stored = u16::from_be_bytes([
            segment[meta.transport_offset + 16],
            segment[meta.transport_offset + 17],
        ]);
        let mut probe = segment.to_vec();
        probe[meta.transport_offset + 16..meta.transport_offset + 18].fill(0);
        stored == tcp_checksum(&probe, &meta)
    }

    #[test]
    fn gso_segmentation_splits_large_tcp_to_mtu_with_valid_checksums() {
        let mtu = 1114_u16;
        let original = tcp_data_packet(3000);
        assert!(original.len() > usize::from(mtu));
        let segments = segment_tcp_gso(&original, mtu).expect("segments");
        assert!(segments.len() >= 3);
        let mut reassembled = Vec::new();
        let mut expected_seq = 1000_u32;
        for (index, segment) in segments.iter().enumerate() {
            assert!(tcp_segment_valid(segment, mtu));
            let meta = inspect_packet(segment).unwrap();
            let seq = u32::from_be_bytes(
                segment[meta.transport_offset + 4..meta.transport_offset + 8]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(seq, expected_seq);
            let tcp_len = usize::from(segment[meta.transport_offset + 12] >> 4) * 4;
            reassembled.extend_from_slice(&segment[meta.transport_offset + tcp_len..]);
            expected_seq =
                expected_seq.wrapping_add((segment.len() - meta.transport_offset - tcp_len) as u32);
            let flags = segment[meta.transport_offset + 13];
            if index + 1 < segments.len() {
                assert_eq!(flags & 0x01, 0);
                assert_eq!(flags & 0x08, 0);
            } else {
                assert_ne!(flags & 0x18, 0);
            }
        }
        assert_eq!(reassembled, original[40..]);
    }

    #[test]
    fn gso_segmentation_refuses_non_data_and_fitting_packets() {
        assert!(segment_tcp_gso(&tcp_data_packet(100), 1500).is_none());
        let mut udp = vec![0_u8; 2000];
        udp[0] = 0x45;
        udp[9] = 17;
        assert!(segment_tcp_gso(&udp, 1200).is_none());
        let mut syn = tcp_data_packet(0);
        syn[33] = 0x02;
        assert!(segment_tcp_gso(&syn, 60).is_none());
        let mut rst = tcp_data_packet(100);
        rst[33] = 0x04;
        assert!(segment_tcp_gso(&rst, 100).is_none());
        // Headers alone exceed the budget: nothing to split.
        assert!(segment_tcp_gso(&tcp_data_packet(100), 30).is_none());
        // Degenerate MSS (headers leave <64 payload bytes) is refused to avoid
        // 1-byte segment floods; the caller drops+PTBs instead.
        assert!(segment_tcp_gso(&tcp_data_packet(3000), 100).is_none());
    }

    fn tcp6_data_packet(payload_len: usize) -> Vec<u8> {
        let total = 40 + 20 + payload_len;
        let mut packet = vec![0_u8; total];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[40..42].copy_from_slice(&40000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
        packet[44..48].copy_from_slice(&1000_u32.to_be_bytes());
        packet[52] = 0x50;
        packet[53] = 0x18;
        for (i, byte) in packet[60..].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let meta = inspect_packet(&packet).expect("valid TCPv6 packet");
        let checksum = tcp_checksum(&packet, &meta);
        packet[56..58].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn gso_segmentation_splits_ipv6_tcp_with_valid_checksums() {
        let mtu = 1114_u16;
        let original = tcp6_data_packet(3000);
        assert!(original.len() > usize::from(mtu));
        let segments = segment_tcp_gso(&original, mtu).expect("segments");
        assert!(segments.len() >= 3);
        let mut reassembled = Vec::new();
        let mut expected_seq = 1000_u32;
        for segment in &segments {
            assert!(segment.len() <= usize::from(mtu));
            let meta = inspect_packet(segment).expect("segment parses");
            let mut probe = segment.clone();
            probe[meta.transport_offset + 16..meta.transport_offset + 18].fill(0);
            let stored = u16::from_be_bytes([
                segment[meta.transport_offset + 16],
                segment[meta.transport_offset + 17],
            ]);
            assert_eq!(stored, tcp_checksum(&probe, &meta));
            let seq = u32::from_be_bytes(
                segment[meta.transport_offset + 4..meta.transport_offset + 8]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(seq, expected_seq);
            let tcp_len = usize::from(segment[meta.transport_offset + 12] >> 4) * 4;
            reassembled.extend_from_slice(&segment[meta.transport_offset + tcp_len..]);
            expected_seq =
                expected_seq.wrapping_add((segment.len() - meta.transport_offset - tcp_len) as u32);
        }
        assert_eq!(reassembled, original[60..]);
    }

    #[test]
    fn ptb_suppresses_multicast_and_ipv6_errors_behind_extensions() {
        // IPv4 multicast destination must not trigger PTB (RFC 1812).
        let mut multicast = ipv4_oversize_packet();
        multicast[16..20].copy_from_slice(&[224, 0, 0, 251]);
        assert!(build_ptb_for_oversize(&multicast, 1200).is_none());
        // IPv4 loopback and unspecified must not trigger PTB either.
        let mut loopback = ipv4_oversize_packet();
        loopback[12..16].copy_from_slice(&[127, 0, 0, 1]);
        assert!(build_ptb_for_oversize(&loopback, 1200).is_none());
        let mut unspecified = ipv4_oversize_packet();
        unspecified[16..20].fill(0);
        assert!(build_ptb_for_oversize(&unspecified, 1200).is_none());
        // IPv6 multicast destination must not trigger PTB.
        let mut multicast6 = ipv6_oversize_packet();
        multicast6[24..40].copy_from_slice(&"ff02::1".parse::<Ipv6Addr>().unwrap().octets());
        assert!(build_ptb_for_oversize(&multicast6, 1200).is_none());
        let mut loopback6 = ipv6_oversize_packet();
        loopback6[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert!(build_ptb_for_oversize(&loopback6, 1200).is_none());
        // ICMPv6 error behind a Hop-by-Hop extension must not trigger PTB.
        let mut ext_error = vec![0_u8; 56];
        ext_error[0] = 0x60;
        ext_error[6] = 0;
        ext_error[40] = 58;
        ext_error[41] = 0;
        ext_error[48] = 3;
        ext_error[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        ext_error[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        assert!(build_ptb_for_oversize(&ext_error, 1200).is_none());
    }
}
