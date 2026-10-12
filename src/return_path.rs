//! Stateful return-path demultiplexing for overlapping source address spaces.
//!
//! The final circuit node still knows which authenticated circuit delivered a
//! plaintext packet.  This table preserves that fact across the kernel/TUN
//! boundary.  TCP/UDP source ports and ICMP Echo identifiers are rewritten
//! only when their reverse tuple would otherwise collide.

use crate::{circuit::CircuitId, link::LinkRef};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

fn return_flow_ttl() -> Duration {
    crate::timing::active().return_flow_ttl
}
const MAX_RETURN_FLOWS: usize = 65_536;

#[derive(Clone)]
pub struct ReturnTarget {
    pub link: LinkRef,
    pub circuit_id: CircuitId,
}

#[derive(Clone)]
pub struct ReturnTranslation {
    pub target: ReturnTarget,
    pub fake_destination: Option<IpAddr>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FlowTuple {
    remote: IpAddr,
    local: IpAddr,
    protocol: u8,
    remote_id: u16,
    local_id: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct ForwardTuple {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    source_id: u16,
    destination_id: u16,
    link_instance: u64,
    circuit_id: CircuitId,
}

struct Flow {
    forward: ForwardTuple,
    original_local_id: u16,
    fake_destination: Option<IpAddr>,
    target: ReturnTarget,
    expires: Instant,
}

#[derive(Default)]
struct State {
    reverse: HashMap<FlowTuple, Flow>,
    forward: HashMap<ForwardTuple, FlowTuple>,
    next_id: u16,
    keys: HashMap<(u64, CircuitId), chacha20poly1305::Key>,
    senders: HashMap<(u64, CircuitId), crate::crypto::SenderSession>,
    dns_senders: HashMap<(u64, CircuitId), crate::crypto::SenderSession>,
}

#[derive(Clone, Default)]
pub struct ReturnFlowTable {
    state: Arc<Mutex<State>>,
    active: Arc<AtomicBool>,
}

impl ReturnFlowTable {
    pub fn install_circuit(
        &self,
        link_instance: u64,
        circuit_id: CircuitId,
        key: chacha20poly1305::Key,
    ) {
        let mut state = self.state.lock().expect("return-flow state lock");
        state.keys.entry((link_instance, circuit_id)).or_insert(key);
    }

    pub fn encrypt_dns_return(
        &self,
        link_instance: u64,
        circuit_id: CircuitId,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let mut state = self.state.lock().expect("return-flow state lock");
        let key = *state.keys.get(&(link_instance, circuit_id))?;
        state
            .dns_senders
            .entry((link_instance, circuit_id))
            .or_insert_with(|| crate::crypto::SenderSession::dns_return_from_key(circuit_id, key))
            .encrypt(payload)
            .ok()
            .map(ToOwned::to_owned)
    }

    pub fn encrypt_return(&self, target: &ReturnTarget, packet: &[u8]) -> Option<Vec<u8>> {
        let mut state = self.state.lock().expect("return-flow state lock");
        let lookup = (target.link.instance(), target.circuit_id);
        let key = *state.keys.get(&lookup)?;
        state
            .senders
            .entry(lookup)
            .or_insert_with(|| {
                crate::crypto::SenderSession::return_from_key(target.circuit_id, key)
            })
            .encrypt(packet)
            .ok()
            .map(ToOwned::to_owned)
    }

    /// Register a packet immediately before the final node writes it to TUN.
    ///
    /// `Ok(true)` means a reliable reverse association was installed.
    /// `Ok(false)` is a protocol for which only best-effort tuple association
    /// is possible.  A supported transport that cannot allocate state returns
    /// `Err`, so callers can fail closed rather than emit an ambiguous flow.
    pub fn track_forward(
        &self,
        packet: &mut [u8],
        fake_destination: Option<IpAddr>,
        link: LinkRef,
        circuit_id: CircuitId,
    ) -> Result<bool, &'static str> {
        let parsed = ParsedPacket::parse(packet).ok_or("malformed IP packet")?;
        if parsed.protocol == 51 {
            return Err("AH cannot be return-path translated");
        }
        let ids = match parsed.transport_ids(packet, Direction::Forward) {
            Some(ids) => ids,
            None if matches!(parsed.protocol, 6 | 17 | 58 | 1) => {
                return Err("supported transport header is unavailable");
            }
            None => TransportIds {
                source: 0,
                destination: 0,
                field_offset: None,
                checksum_offset: None,
                preserve_zero_checksum: false,
            },
        };
        let forward = ForwardTuple {
            source: parsed.source,
            destination: parsed.destination,
            protocol: parsed.protocol,
            source_id: ids.source,
            destination_id: ids.destination,
            link_instance: link.instance(),
            circuit_id,
        };
        let now = Instant::now();
        let mut state = self.state.lock().expect("return-flow state lock");
        prune(&mut state, now);
        if let Some(reverse_key) = state.forward.get(&forward).copied()
            && let Some(flow) = state.reverse.get_mut(&reverse_key)
        {
            flow.expires = now + return_flow_ttl();
            if flow.fake_destination != fake_destination {
                return Err("FakeIP metadata changed for an existing return flow");
            }
            if reverse_key.local_id != ids.source {
                ids.rewrite(packet, reverse_key.local_id);
            }
            return Ok(ids.field_offset.is_some());
        }
        if state.reverse.len() >= MAX_RETURN_FLOWS {
            return Err("return-flow capacity exhausted");
        }
        let base = FlowTuple {
            remote: parsed.destination,
            local: parsed.source,
            protocol: parsed.protocol,
            remote_id: ids.destination,
            local_id: ids.source,
        };
        let translated = if !state.reverse.contains_key(&base) {
            ids.source
        } else if ids.field_offset.is_some() {
            let State {
                reverse, next_id, ..
            } = &mut *state;
            allocate_id(next_id, base, |candidate| reverse.contains_key(&candidate))
                .ok_or("transport identifier space exhausted")?
        } else {
            return Err("ambiguous protocol without a rewritable identifier");
        };
        let reverse_key = FlowTuple {
            local_id: translated,
            ..base
        };
        if translated != ids.source {
            ids.rewrite(packet, translated);
        }
        state.forward.insert(forward.clone(), reverse_key);
        state.reverse.insert(
            reverse_key,
            Flow {
                forward,
                original_local_id: ids.source,
                fake_destination,
                target: ReturnTarget { link, circuit_id },
                expires: now + return_flow_ttl(),
            },
        );
        self.active.store(true, Ordering::Release);
        Ok(ids.field_offset.is_some())
    }

    /// Match and restore a kernel return packet before ordinary route lookup.
    pub fn translate_return(&self, packet: &mut [u8]) -> Option<ReturnTranslation> {
        if !self.active.load(Ordering::Acquire) {
            return None;
        }
        let parsed = ParsedPacket::parse(packet)?;
        let ids = parsed.transport_ids(packet, Direction::Return)?;
        let key = FlowTuple {
            remote: parsed.source,
            local: parsed.destination,
            protocol: parsed.protocol,
            remote_id: ids.source,
            local_id: ids.destination,
        };
        let now = Instant::now();
        let mut state = self.state.lock().expect("return-flow state lock");
        prune(&mut state, now);
        if state.reverse.is_empty() {
            self.active.store(false, Ordering::Release);
            return None;
        }
        let flow = state.reverse.get_mut(&key)?;
        flow.expires = now + return_flow_ttl();
        let original = flow.original_local_id;
        let target = flow.target.clone();
        let fake_destination = flow.fake_destination;
        if original != ids.destination {
            ids.rewrite(packet, original);
        }
        Some(ReturnTranslation {
            target,
            fake_destination,
        })
    }

    pub fn remove_link(&self, link_instance: u64) {
        let mut state = self.state.lock().expect("return-flow state lock");
        state
            .reverse
            .retain(|_, flow| flow.forward.link_instance != link_instance);
        let State {
            reverse, forward, ..
        } = &mut *state;
        forward.retain(|_, key| reverse.contains_key(key));
        state
            .senders
            .retain(|(instance, _), _| *instance != link_instance);
        state
            .dns_senders
            .retain(|(instance, _), _| *instance != link_instance);
        state
            .keys
            .retain(|(instance, _), _| *instance != link_instance);
        self.active
            .store(!state.reverse.is_empty(), Ordering::Release);
    }

    pub fn remove_circuit(&self, link_instance: u64, circuit_id: CircuitId) {
        let mut state = self.state.lock().expect("return-flow state lock");
        state.reverse.retain(|_, flow| {
            flow.forward.link_instance != link_instance || flow.forward.circuit_id != circuit_id
        });
        let State {
            reverse, forward, ..
        } = &mut *state;
        forward.retain(|_, key| reverse.contains_key(key));
        state.senders.remove(&(link_instance, circuit_id));
        state.dns_senders.remove(&(link_instance, circuit_id));
        state.keys.remove(&(link_instance, circuit_id));
        self.active
            .store(!state.reverse.is_empty(), Ordering::Release);
    }
}

fn allocate_id(
    next_id: &mut u16,
    template: FlowTuple,
    occupied: impl Fn(FlowTuple) -> bool,
) -> Option<u16> {
    for _ in 0..u16::MAX {
        *next_id = next_id.wrapping_add(1).max(1);
        let candidate = FlowTuple {
            local_id: *next_id,
            ..template
        };
        if !occupied(candidate) {
            return Some(*next_id);
        }
    }
    None
}

fn prune(state: &mut State, now: Instant) {
    state.reverse.retain(|_, flow| flow.expires > now);
    let reverse = &state.reverse;
    state.forward.retain(|_, key| reverse.contains_key(key));
}

#[derive(Clone, Copy)]
enum Direction {
    Forward,
    Return,
}

#[derive(Clone, Copy)]
struct TransportIds {
    source: u16,
    destination: u16,
    field_offset: Option<usize>,
    checksum_offset: Option<usize>,
    preserve_zero_checksum: bool,
}

impl TransportIds {
    fn rewrite(self, packet: &mut [u8], replacement: u16) {
        let Some(field) = self.field_offset else {
            return;
        };
        let old = u16::from_be_bytes([packet[field], packet[field + 1]]);
        let Some(checksum) = self.checksum_offset else {
            packet[field..field + 2].copy_from_slice(&replacement.to_be_bytes());
            return;
        };
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

struct ParsedPacket {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    transport_offset: usize,
    ipv4: bool,
}

impl ParsedPacket {
    fn parse(packet: &[u8]) -> Option<Self> {
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => {
                let ihl = usize::from(packet.first()? & 0x0f) * 4;
                if ihl < 20 || packet.len() < ihl {
                    return None;
                }
                let fragment = u16::from_be_bytes([packet[6], packet[7]]);
                if fragment & 0x1fff != 0 {
                    return None;
                }
                Some(Self {
                    source: IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
                    destination: IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(&packet[16..20]).ok()?,
                    )),
                    protocol: packet[9],
                    transport_offset: ihl,
                    ipv4: true,
                })
            }
            Some(6) if packet.len() >= 40 => {
                let (transport_offset, protocol) = ipv6_transport(packet)?;
                Some(Self {
                    source: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
                    destination: IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&packet[24..40]).ok()?,
                    )),
                    protocol,
                    transport_offset,
                    ipv4: false,
                })
            }
            _ => None,
        }
    }

    fn transport_ids(&self, packet: &[u8], direction: Direction) -> Option<TransportIds> {
        let offset = self.transport_offset;
        match self.protocol {
            6 if packet.len() >= offset + 20 => Some(TransportIds {
                source: read_u16(packet, offset)?,
                destination: read_u16(packet, offset + 2)?,
                field_offset: Some(match direction {
                    Direction::Forward => offset,
                    Direction::Return => offset + 2,
                }),
                checksum_offset: Some(offset + 16),
                preserve_zero_checksum: false,
            }),
            17 if packet.len() >= offset + 8 => Some(TransportIds {
                source: read_u16(packet, offset)?,
                destination: read_u16(packet, offset + 2)?,
                field_offset: Some(match direction {
                    Direction::Forward => offset,
                    Direction::Return => offset + 2,
                }),
                checksum_offset: Some(offset + 6),
                preserve_zero_checksum: self.ipv4,
            }),
            1 if self.ipv4 && packet.len() >= offset + 8 => {
                let expected = match direction {
                    Direction::Forward => 8,
                    Direction::Return => 0,
                };
                (packet[offset] == expected).then(|| TransportIds {
                    source: read_u16(packet, offset + 4).unwrap_or(0),
                    destination: 0,
                    field_offset: Some(offset + 4),
                    checksum_offset: Some(offset + 2),
                    preserve_zero_checksum: false,
                })
            }
            58 if !self.ipv4 && packet.len() >= offset + 8 => {
                let expected = match direction {
                    Direction::Forward => 128,
                    Direction::Return => 129,
                };
                (packet[offset] == expected).then(|| TransportIds {
                    source: read_u16(packet, offset + 4).unwrap_or(0),
                    destination: 0,
                    field_offset: Some(offset + 4),
                    checksum_offset: Some(offset + 2),
                    preserve_zero_checksum: false,
                })
            }
            _ => None,
        }
        .map(|mut ids| {
            if matches!(direction, Direction::Return) && matches!(self.protocol, 1 | 58) {
                std::mem::swap(&mut ids.source, &mut ids.destination);
            }
            ids
        })
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
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

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier::Link;

    async fn connected_full_quic_links() -> (Arc<Link>, Arc<Link>) {
        let client_key = crate::identity::generate();
        let server_key = crate::identity::generate();
        let server_public = crate::identity::encode_public(&server_key.verifying_key());
        let (server, _) = crate::carrier::endpoint_with_options_and_bare(
            crate::config::CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &crate::config::LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let peers = std::collections::BTreeMap::from([(
            "client".to_owned(),
            crate::config::Peer {
                public_key: crate::identity::encode_public(&client_key.verifying_key()),
                endpoints: vec![],
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: vec![],
                routes: vec![],
                paths: vec![],
            },
        )]);
        let server_task = tokio::spawn(async move {
            crate::carrier::accept_with_bare(
                &server,
                None,
                crate::config::CarrierProtocol::QuicFull,
                &peers,
                false,
                "server",
                &server_key,
            )
            .await
            .unwrap()
        });
        let (client, _) = crate::carrier::endpoint_with_options_and_bare(
            crate::config::CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &crate::config::LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let client_link = Arc::new(
            crate::carrier::connect_with_link_health_and_bare(
                &client,
                None,
                address,
                crate::config::CarrierProtocol::QuicFull,
                "server",
                &server_public,
                "client",
                &client_key,
                &crate::config::LinkHealthConfig::default(),
            )
            .await
            .unwrap(),
        );
        let server_link = Arc::new(server_task.await.unwrap());
        (client_link, server_link)
    }

    fn udp(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    #[test]
    fn transport_identifier_rewrite_keeps_udp_zero_checksum() {
        let mut packet = udp([10, 0, 0, 1], [192, 0, 2, 1], 40_000, 53);
        let parsed = ParsedPacket::parse(&packet).unwrap();
        let ids = parsed.transport_ids(&packet, Direction::Forward).unwrap();
        ids.rewrite(&mut packet, 1234);
        assert_eq!(read_u16(&packet, 20), Some(1234));
        assert_eq!(read_u16(&packet, 26), Some(0));
    }

    #[test]
    fn parses_echo_identifier_in_both_directions() {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&77_u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        assert_eq!(
            parsed
                .transport_ids(&packet, Direction::Forward)
                .unwrap()
                .source,
            77
        );
        packet[20] = 0;
        assert_eq!(
            parsed
                .transport_ids(&packet, Direction::Return)
                .unwrap()
                .destination,
            77
        );
    }

    #[test]
    fn colliding_circuits_allocate_a_distinct_return_identifier() {
        let template = FlowTuple {
            remote: "192.0.2.1".parse().unwrap(),
            local: "198.18.0.1".parse().unwrap(),
            protocol: 17,
            remote_id: 53,
            local_id: 40_000,
        };
        let occupied = std::collections::HashSet::from([template]);
        let mut next = 39_999;
        let allocated = allocate_id(&mut next, template, |key| occupied.contains(&key)).unwrap();
        assert_ne!(allocated, template.local_id);
    }

    #[test]
    fn return_cipher_is_created_lazily_from_installed_circuit_key() {
        let table = ReturnFlowTable::default();
        let circuit_id = CircuitId([7; 16]);
        let key = chacha20poly1305::Key::from([9; 32]);
        table.install_circuit(11, circuit_id, key);
        assert!(table.state.lock().unwrap().dns_senders.is_empty());
        let frame = table
            .encrypt_dns_return(11, circuit_id, b"response")
            .unwrap();
        assert_eq!(table.state.lock().unwrap().dns_senders.len(), 1);
        let source = crate::identity::generate();
        let mut receiver = crate::crypto::ReceiverSessions::default();
        receiver.install_return(circuit_id, source.verifying_key(), key);
        let (_, direction, _, payload) = receiver.open_data(&frame).unwrap();
        assert_eq!(direction, crate::crypto::DataDirection::DnsReturn);
        assert_eq!(payload, b"response");
    }

    #[test]
    fn removing_a_link_drops_return_flow_cipher_state() {
        let table = ReturnFlowTable::default();
        let circuit_id = CircuitId([8; 16]);
        let key = chacha20poly1305::Key::from([10; 32]);
        table.install_circuit(12, circuit_id, key);
        assert!(
            table
                .encrypt_dns_return(12, circuit_id, b"response")
                .is_some()
        );
        {
            let mut state = table.state.lock().unwrap();
            state.senders.insert(
                (12, circuit_id),
                crate::crypto::SenderSession::return_from_key(circuit_id, key),
            );
            assert_eq!(state.keys.len(), 1);
            assert_eq!(state.senders.len(), 1);
            assert_eq!(state.dns_senders.len(), 1);
        }

        table.remove_link(12);

        let state = table.state.lock().unwrap();
        assert!(state.keys.is_empty());
        assert!(state.senders.is_empty());
        assert!(state.dns_senders.is_empty());
        assert!(!table.active.load(Ordering::Acquire));
    }

    #[test]
    fn rewrites_tcp_identifier_and_updates_checksum() {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[36..38].copy_from_slice(&0x1234_u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        let ids = parsed.transport_ids(&packet, Direction::Forward).unwrap();
        ids.rewrite(&mut packet, 1234);
        assert_eq!(read_u16(&packet, 20), Some(1234));
        assert_ne!(read_u16(&packet, 36), Some(0x1234));
    }

    #[test]
    fn rewrites_ipv6_udp_after_extension_header() {
        let mut packet = vec![0; 56];
        packet[0] = 0x60;
        packet[6] = 0; // Hop-by-Hop options.
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = 17;
        packet[41] = 0;
        packet[48..50].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[50..52].copy_from_slice(&53_u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        assert_eq!(parsed.transport_offset, 48);
        let ids = parsed.transport_ids(&packet, Direction::Forward).unwrap();
        ids.rewrite(&mut packet, 1234);
        assert_eq!(read_u16(&packet, 48), Some(1234));
    }

    #[test]
    fn rejects_invalid_packets_and_non_matching_transport_headers() {
        assert!(ParsedPacket::parse(&[]).is_none());
        assert!(ParsedPacket::parse(&[0x45; 19]).is_none());

        let mut fragmented = udp([10, 0, 0, 1], [192, 0, 2, 1], 40_000, 53);
        fragmented[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(ParsedPacket::parse(&fragmented).is_none());

        let mut unknown = udp([10, 0, 0, 1], [192, 0, 2, 1], 40_000, 53);
        unknown[9] = 47;
        let parsed = ParsedPacket::parse(&unknown).unwrap();
        assert!(parsed.transport_ids(&unknown, Direction::Forward).is_none());

        let mut wrong_icmp = udp([10, 0, 0, 1], [192, 0, 2, 1], 40_000, 53);
        wrong_icmp[9] = 1;
        wrong_icmp[20] = 0;
        let wrong_icmp_parsed = ParsedPacket::parse(&wrong_icmp).unwrap();
        assert!(
            wrong_icmp_parsed
                .transport_ids(&wrong_icmp, Direction::Forward)
                .is_none()
        );
    }

    #[test]
    fn parses_ipv6_echo_identifier_and_rejects_non_initial_fragments() {
        let mut packet = vec![0; 48];
        packet[0] = 0x60;
        packet[6] = 58;
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = 128;
        packet[44..46].copy_from_slice(&77_u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&packet).unwrap();
        assert_eq!(
            parsed
                .transport_ids(&packet, Direction::Forward)
                .unwrap()
                .source,
            77
        );

        let mut fragmented = vec![0; 48];
        fragmented[0] = 0x60;
        fragmented[6] = 44;
        fragmented[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        fragmented[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        fragmented[40] = 58;
        fragmented[42..44].copy_from_slice(&8_u16.to_be_bytes());
        assert!(ParsedPacket::parse(&fragmented).is_none());
    }

    #[tokio::test]
    async fn tracks_collisions_restores_returns_and_reclaims_circuit_state() {
        let (link, _peer) = connected_full_quic_links().await;
        let table = ReturnFlowTable::default();
        let circuit_id = CircuitId([31; 16]);
        let fake_destination = Some("198.18.0.10".parse().unwrap());

        let mut first = udp([10, 0, 0, 1], [192, 0, 2, 1], 40_000, 53);
        assert!(
            table
                .track_forward(&mut first, fake_destination, link.clone(), circuit_id,)
                .unwrap()
        );
        assert_eq!(read_u16(&first, 20), Some(40_000));

        let mut collision = udp([10, 0, 0, 1], [192, 0, 2, 1], 40_000, 53);
        let second_circuit = CircuitId([32; 16]);
        assert!(
            table
                .track_forward(
                    &mut collision,
                    fake_destination,
                    link.clone(),
                    second_circuit,
                )
                .unwrap()
        );
        let translated_port = read_u16(&collision, 20).unwrap();
        assert_ne!(translated_port, 40_000);

        let mut returned = udp([192, 0, 2, 1], [10, 0, 0, 1], 53, translated_port);
        let translation = table.translate_return(&mut returned).unwrap();
        assert_eq!(translation.target.circuit_id, second_circuit);
        assert_eq!(translation.fake_destination, fake_destination);
        assert_eq!(read_u16(&returned, 22), Some(40_000));

        assert!(
            table
                .track_forward(&mut first, fake_destination, link.clone(), circuit_id,)
                .unwrap()
        );
        assert!(
            table
                .track_forward(
                    &mut first,
                    Some("198.18.0.11".parse().unwrap()),
                    link.clone(),
                    circuit_id,
                )
                .is_err()
        );

        table.install_circuit(1, circuit_id, chacha20poly1305::Key::from([41; 32]));
        assert!(
            table
                .encrypt_return(
                    &ReturnTarget {
                        link: link.clone(),
                        circuit_id,
                    },
                    &first
                )
                .is_none()
        );
        table.install_circuit(
            link.instance(),
            circuit_id,
            chacha20poly1305::Key::from([41; 32]),
        );
        assert!(
            table
                .encrypt_return(
                    &ReturnTarget {
                        link: link.clone(),
                        circuit_id,
                    },
                    &first,
                )
                .is_some()
        );

        table.remove_circuit(link.instance(), second_circuit);
        let mut removed_return = udp([192, 0, 2, 1], [10, 0, 0, 1], 53, translated_port);
        assert!(table.translate_return(&mut removed_return).is_none());
        table.remove_link(link.instance());
        assert!(table.translate_return(&mut first).is_none());
    }

    #[tokio::test]
    async fn rejects_ambiguous_and_unsupported_transports_and_refreshes_duplicate_flows() {
        let (link, _peer) = connected_full_quic_links().await;
        let table = ReturnFlowTable::default();
        let circuit_id = CircuitId([42; 16]);

        let mut ah = udp([10, 0, 0, 1], [192, 0, 2, 1], 1, 2);
        ah[9] = 51;
        assert_eq!(
            table.track_forward(&mut ah, None, link.clone(), circuit_id),
            Err("AH cannot be return-path translated")
        );

        let mut malformed_udp = udp([10, 0, 0, 1], [192, 0, 2, 1], 1, 2);
        malformed_udp.truncate(25);
        assert_eq!(
            table.track_forward(&mut malformed_udp, None, link.clone(), circuit_id),
            Err("supported transport header is unavailable")
        );

        let mut opaque = udp([10, 0, 0, 1], [192, 0, 2, 1], 1, 2);
        opaque[9] = 47;
        assert_eq!(
            table.track_forward(&mut opaque, None, link.clone(), circuit_id),
            Ok(false)
        );

        let mut duplicate = udp([10, 0, 0, 1], [192, 0, 2, 1], 1, 2);
        assert!(
            table
                .track_forward(&mut duplicate, None, link.clone(), circuit_id)
                .unwrap()
        );
        // A collision with the same forward tuple is refreshed in place.
        assert!(
            table
                .track_forward(&mut duplicate, None, link.clone(), circuit_id)
                .unwrap()
        );
        let mut changed = duplicate.clone();
        assert_eq!(
            table.track_forward(
                &mut changed,
                Some("198.18.0.2".parse().unwrap()),
                link,
                circuit_id,
            ),
            Err("FakeIP metadata changed for an existing return flow")
        );
    }

    #[test]
    fn low_level_tuple_helpers_cover_noop_checksum_and_ipv6_extension_boundaries() {
        let mut packet = [0_u8; 4];
        TransportIds {
            source: 1,
            destination: 2,
            field_offset: None,
            checksum_offset: None,
            preserve_zero_checksum: false,
        }
        .rewrite(&mut packet, 3);
        assert_eq!(packet, [0; 4]);

        let mut packet = [0_u8; 4];
        TransportIds {
            source: 1,
            destination: 2,
            field_offset: Some(0),
            checksum_offset: None,
            preserve_zero_checksum: false,
        }
        .rewrite(&mut packet, 3);
        assert_eq!(read_u16(&packet, 0), Some(3));

        let mut packet = [0_u8; 4];
        packet[0..2].copy_from_slice(&1_u16.to_be_bytes());
        packet[2..4].copy_from_slice(&0xffff_u16.to_be_bytes());
        TransportIds {
            source: 1,
            destination: 2,
            field_offset: Some(0),
            checksum_offset: Some(2),
            preserve_zero_checksum: false,
        }
        .rewrite(&mut packet, 1);
        assert_eq!(read_u16(&packet, 2), Some(0xffff));
        assert_eq!(read_u16(&[1, 2], 1), None);

        let mut with_fragment = vec![0_u8; 56];
        with_fragment[6] = 44;
        with_fragment[40] = 17;
        assert_eq!(ipv6_transport(&with_fragment), Some((48, 17)));

        let mut chained = vec![0_u8; 40 + 8 * 8];
        chained[6] = 0;
        for offset in (40..chained.len()).step_by(8) {
            chained[offset] = 0;
            chained[offset + 1] = 0;
        }
        assert_eq!(ipv6_transport(&chained), None);
    }

    #[test]
    fn tuple_allocation_reports_exhaustion_without_reusing_an_occupied_id() {
        let template = FlowTuple {
            remote: "192.0.2.1".parse().unwrap(),
            local: "198.18.0.1".parse().unwrap(),
            protocol: 17,
            remote_id: 53,
            local_id: 1,
        };
        let mut next = 0;
        assert_eq!(allocate_id(&mut next, template, |_| true), None);
    }

    #[tokio::test]
    async fn return_flow_capacity_is_bounded() {
        let (link, _peer) = connected_full_quic_links().await;
        let table = ReturnFlowTable::default();
        let circuit_id = CircuitId([43; 16]);
        {
            let mut state = table.state.lock().unwrap();
            for index in 0..MAX_RETURN_FLOWS {
                state.reverse.insert(
                    FlowTuple {
                        remote: "192.0.2.1".parse().unwrap(),
                        local: "198.18.0.1".parse().unwrap(),
                        protocol: 17,
                        remote_id: 1,
                        local_id: index as u16,
                    },
                    Flow {
                        forward: ForwardTuple {
                            source: "10.0.0.1".parse().unwrap(),
                            destination: "198.18.0.1".parse().unwrap(),
                            protocol: 17,
                            source_id: index as u16,
                            destination_id: 1,
                            link_instance: link.instance(),
                            circuit_id,
                        },
                        original_local_id: index as u16,
                        fake_destination: None,
                        target: ReturnTarget {
                            link: link.clone(),
                            circuit_id,
                        },
                        expires: Instant::now() + Duration::from_secs(60),
                    },
                );
            }
        }
        let mut packet = udp([10, 0, 0, 1], [198, 18, 0, 1], 40_001, 53);
        assert_eq!(
            table.track_forward(&mut packet, None, link, circuit_id),
            Err("return-flow capacity exhausted")
        );
    }

    #[tokio::test]
    async fn ambiguous_opaque_flow_is_rejected_on_second_collision() {
        let (link, _peer) = connected_full_quic_links().await;
        let table = ReturnFlowTable::default();
        let first_circuit = CircuitId([44; 16]);
        let second_circuit = CircuitId([45; 16]);
        let mut opaque = udp([10, 0, 0, 1], [192, 0, 2, 1], 1, 2);
        opaque[9] = 47;
        assert_eq!(
            table.track_forward(&mut opaque, None, link.clone(), first_circuit),
            Ok(false)
        );
        // A different circuit reuses the same flow tuple: the base key is
        // already in the reverse table and the protocol has no rewritable
        // identifier, so the collision cannot be disambiguated.
        assert_eq!(
            table.track_forward(&mut opaque, None, link, second_circuit),
            Err("ambiguous protocol without a rewritable identifier")
        );
    }

    #[test]
    fn translate_return_on_empty_table_is_none() {
        let table = ReturnFlowTable::default();
        let mut packet = udp([192, 0, 2, 1], [10, 0, 0, 1], 53, 40_000);
        assert!(table.translate_return(&mut packet).is_none());
    }

    #[test]
    fn tcp_and_icmpv6_return_directions_parse_identifiers() {
        let mut tcp = vec![0u8; 40];
        tcp[0] = 0x45;
        tcp[9] = 6;
        tcp[12..16].copy_from_slice(&[10, 0, 0, 1]);
        tcp[16..20].copy_from_slice(&[192, 0, 2, 1]);
        tcp[20..22].copy_from_slice(&40_000u16.to_be_bytes());
        tcp[22..24].copy_from_slice(&53u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&tcp).unwrap();
        let ids = parsed.transport_ids(&tcp, Direction::Return).unwrap();
        assert_eq!(ids.source, 40_000);
        assert_eq!(ids.destination, 53);

        let mut reply = vec![0u8; 48];
        reply[0] = 0x60;
        reply[4..6].copy_from_slice(&8u16.to_be_bytes());
        reply[6] = 58;
        reply[7] = 64;
        reply[8..24].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        reply[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        reply[40] = 129;
        reply[44..46].copy_from_slice(&99u16.to_be_bytes());
        let parsed = ParsedPacket::parse(&reply).unwrap();
        let ids = parsed.transport_ids(&reply, Direction::Return).unwrap();
        // Echo identifiers are read into `source` and swapped into
        // `destination` for the return direction.
        assert_eq!(ids.destination, 99);
    }
}
