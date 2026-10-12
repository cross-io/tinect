#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! A TUN-free, packet-oriented fake TCP codec for carrying QUIC datagrams.
//!
//! The crate is deliberately transport-agnostic: it serializes and validates
//! complete IP packets but never creates devices, sockets, routes, or firewall
//! rules.  A caller supplies the privileged/raw transport at its own boundary.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::Instant;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
/// SYN options: MSS + SACK-permitted + Timestamp + NOP + Window Scale (20 bytes).
const SYN_TCP_OPTION_LEN: usize = 20;
/// Established segments: NOP + NOP + Timestamp (12 bytes).
const DATA_TCP_OPTION_LEN: usize = 12;
/// TCP MD5 Signature (kind 19, 18 bytes) plus two NOPs for alignment.
const RST_TCP_OPTION_LEN: usize = 20;
const TCP_PROTOCOL: u8 = 6;
/// Ethernet-class MSS advertisements used on SYN for middlebox familiarity.
const IPV4_ADVERTISED_MSS: u16 = 1460;
const IPV6_ADVERTISED_MSS: u16 = 1440;

/// Library callers that do not explicitly supply a key ignore every inbound
/// RST. The daemon supplies its configured key through the keyed constructors.
const RESET_KEY: Option<&[u8]> = None;

/// TCP flags used by the minimal fake TCP state machine.
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

/// Errors from packet validation or an invalid state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    AddressFamilyMismatch,
    PacketTooShort,
    InvalidIpVersion,
    InvalidIpHeader,
    InvalidTcpHeader,
    NotTcp,
    FragmentedIpv4,
    InvalidChecksum,
    PacketLengthMismatch,
    UnexpectedPeer,
    InvalidTransition,
    NotEstablished,
    PayloadTooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fake TCP error: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Parsed fake TCP packet. `payload` is the original QUIC UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
    /// TCP Timestamp option values when present (`TSval`, `TSecr`).
    pub timestamp: Option<(u32, u32)>,
    /// TCP MD5 Signature option carried only by an authenticated RST.
    pub reset_auth: Option<[u8; 16]>,
}

/// A serialized packet that the caller may inject through its own raw-IP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    pub bytes: Vec<u8>,
    pub packet: Packet,
}

/// TCP-like connection state, intentionally without TCP reliability behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
    Reset,
}

/// Result of consuming one inbound IP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEvent {
    /// A QUIC datagram delivered by a valid established peer packet.
    pub datagram: Option<Vec<u8>>,
    /// Immediate acknowledgement or handshake response, if one is required.
    pub reply: Option<OutboundPacket>,
    pub state: State,
}

/// A minimum TCP-shaped session. It does not retransmit or reorder payloads.
#[derive(Clone)]
pub struct FakeTcpSession {
    local: SocketAddr,
    remote: SocketAddr,
    state: State,
    send_next: u32,
    receive_next: u32,
    /// Last peer TSval echoed as TSecr (PAWS-friendly middlebox path).
    ts_recent: u32,
    /// `true` for the active opener, so reset authentication canonicalizes
    /// the tuple identically at both endpoints.
    client: bool,
    client_initial_sequence: u32,
    server_initial_sequence: Option<u32>,
    reset_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for FakeTcpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeTcpSession")
            .field("local", &self.local)
            .field("remote", &self.remote)
            .field("state", &self.state)
            .field("send_next", &self.send_next)
            .field("receive_next", &self.receive_next)
            .field("client", &self.client)
            .field("reset_auth_enabled", &self.reset_key.is_some())
            .finish()
    }
}

impl FakeTcpSession {
    /// Installs a reset key for the privileged raw-socket integration fixture.
    /// Production callers should use `*_with_reset_key` constructors instead.
    #[cfg(feature = "raw-test")]
    pub fn set_reset_key_for_test(&mut self, key: [u8; 32]) {
        self.reset_key = Some(key.to_vec());
    }

    /// Makes an active-opening session. `initial_sequence` should be unique per flow.
    pub fn client(
        local: SocketAddr,
        remote: SocketAddr,
        initial_sequence: u32,
    ) -> Result<Self, Error> {
        Self::client_with_reset_key(local, remote, initial_sequence, RESET_KEY)
    }

    /// Makes an active-opening session with an optional RST authentication key.
    pub fn client_with_reset_key(
        local: SocketAddr,
        remote: SocketAddr,
        initial_sequence: u32,
        reset_key: Option<&[u8]>,
    ) -> Result<Self, Error> {
        ensure_family(local, remote)?;
        Ok(Self {
            local,
            remote,
            state: State::Idle,
            send_next: initial_sequence,
            receive_next: 0,
            ts_recent: 0,
            client: true,
            client_initial_sequence: initial_sequence,
            server_initial_sequence: None,
            reset_key: reset_key.map(ToOwned::to_owned),
        })
    }

    /// Creates a passive session from a validated peer SYN and returns its SYN|ACK.
    pub fn accept(
        syn_ip_packet: &[u8],
        initial_sequence: u32,
    ) -> Result<(Self, OutboundPacket), Error> {
        let syn = decode(syn_ip_packet)?;
        Self::accept_packet_with_reset_key(syn, initial_sequence, RESET_KEY)
    }

    /// Creates a passive session with an optional RST authentication key.
    pub fn accept_with_reset_key(
        syn_ip_packet: &[u8],
        initial_sequence: u32,
        reset_key: Option<&[u8]>,
    ) -> Result<(Self, OutboundPacket), Error> {
        let syn = decode(syn_ip_packet)?;
        Self::accept_packet_with_reset_key(syn, initial_sequence, reset_key)
    }

    /// Like [`accept`], but consumes an already-decoded SYN packet.
    pub fn accept_packet(
        syn: Packet,
        initial_sequence: u32,
    ) -> Result<(Self, OutboundPacket), Error> {
        Self::accept_packet_with_reset_key(syn, initial_sequence, RESET_KEY)
    }

    /// Like [`accept_with_reset_key`], but consumes an already-decoded SYN.
    pub fn accept_packet_with_reset_key(
        syn: Packet,
        initial_sequence: u32,
        reset_key: Option<&[u8]>,
    ) -> Result<(Self, OutboundPacket), Error> {
        if syn.flags != flags::SYN {
            return Err(Error::InvalidTransition);
        }
        let mut session = Self {
            local: syn.destination,
            remote: syn.source,
            state: State::SynReceived,
            send_next: initial_sequence,
            receive_next: syn.sequence.wrapping_add(1),
            ts_recent: syn.timestamp.map(|(tsval, _)| tsval).unwrap_or(0),
            client: false,
            client_initial_sequence: syn.sequence,
            server_initial_sequence: Some(initial_sequence),
            reset_key: reset_key.map(ToOwned::to_owned),
        };
        let reply = session.emit(flags::SYN | flags::ACK, &[])?;
        session.send_next = session.send_next.wrapping_add(1);
        Ok((session, reply))
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Produces the initial SYN. Repeated calls are rejected rather than silently reopening.
    pub fn start(&mut self) -> Result<OutboundPacket, Error> {
        if self.state != State::Idle {
            return Err(Error::InvalidTransition);
        }
        let syn = self.emit(flags::SYN, &[])?;
        self.send_next = self.send_next.wrapping_add(1);
        self.state = State::SynSent;
        Ok(syn)
    }

    /// Wraps exactly one QUIC UDP datagram in a PSH|ACK fake TCP IP packet.
    ///
    /// Real stacks set PSH on application writes; bare ACK-only data segments
    /// are a common middlebox fingerprint for tunnels.
    pub fn encapsulate(&mut self, quic_datagram: &[u8]) -> Result<OutboundPacket, Error> {
        if self.state != State::Established {
            return Err(Error::NotEstablished);
        }
        let packet = self.emit(flags::ACK | flags::PSH, quic_datagram)?;
        self.send_next = self.send_next.wrapping_add(quic_datagram.len() as u32);
        Ok(packet)
    }

    /// Validates a packet, advances the minimal state machine, and returns any response.
    pub fn handle_inbound(&mut self, ip_packet: &[u8]) -> Result<SessionEvent, Error> {
        self.handle_packet(decode(ip_packet)?)
    }

    /// Like [`handle_inbound`], but consumes an already-decoded packet (avoids a
    /// second `decode` on the quicp receive hot path).
    pub fn handle_packet(&mut self, packet: Packet) -> Result<SessionEvent, Error> {
        if packet.source != self.remote || packet.destination != self.local {
            return Err(Error::UnexpectedPeer);
        }
        if let Some((tsval, _)) = packet.timestamp {
            self.ts_recent = tsval;
        }
        // A raw fake-TCP listener can observe the host TCP stack's RST in
        // response to its own handshake packets.  A reset is therefore only
        // authoritative after the handshake, with normal TCP sequence fields
        // and a valid TCP-MD5-shaped authentication option.
        if self.authenticates_reset(&packet) {
            self.state = State::Reset;
            return Ok(SessionEvent {
                datagram: None,
                reply: None,
                state: self.state,
            });
        }
        if packet.flags & flags::RST != 0 {
            return Err(Error::InvalidTransition);
        }
        match self.state {
            State::SynSent
                if packet.flags == (flags::SYN | flags::ACK)
                    && packet.acknowledgement == self.send_next =>
            {
                self.receive_next = packet.sequence.wrapping_add(1);
                self.server_initial_sequence = Some(packet.sequence);
                self.state = State::Established;
                let reply = self.emit(flags::ACK, &[])?;
                Ok(SessionEvent {
                    datagram: None,
                    reply: Some(reply),
                    state: self.state,
                })
            }
            State::SynReceived
                if is_ack_segment(packet.flags) && packet.acknowledgement == self.send_next =>
            {
                self.state = State::Established;
                self.note_payload_sequence(packet.sequence, packet.payload.len());
                let datagram = (!packet.payload.is_empty()).then_some(packet.payload);
                // First post-handshake payload: pure ACK so the peer completes
                // without waiting for reverse application data.
                let reply = if datagram.is_some() {
                    Some(self.emit(flags::ACK, &[])?)
                } else {
                    None
                };
                Ok(SessionEvent {
                    reply,
                    datagram,
                    state: self.state,
                })
            }
            State::Established if packet.flags & flags::SYN == 0 => {
                let has_payload = !packet.payload.is_empty();
                let reply = if has_payload {
                    // Always deliver payload to QUIC (it handles reordering/dups).
                    // Do not coalesce pure ACKs: ACK every data segment so reverse
                    // path looks like a living host stack under one-way bulk flow.
                    self.note_payload_sequence(packet.sequence, packet.payload.len());
                    Some(self.emit(flags::ACK, &[])?)
                } else {
                    None
                };
                Ok(SessionEvent {
                    datagram: has_payload.then_some(packet.payload),
                    reply,
                    state: self.state,
                })
            }
            _ => Err(Error::InvalidTransition),
        }
    }

    /// Builds an explicit RST and marks the session reset.  Until a reset key
    /// is provisioned, this is an unauthenticated wire hint which peers ignore;
    /// local teardown still proceeds and idle expiry is the remote fallback.
    pub fn reset(&mut self) -> Result<OutboundPacket, Error> {
        let packet = self.emit_reset()?;
        self.state = State::Reset;
        Ok(packet)
    }

    fn note_payload_sequence(&mut self, sequence: u32, payload_len: usize) {
        if payload_len == 0 || sequence != self.receive_next {
            return;
        }
        self.receive_next = self.receive_next.wrapping_add(payload_len as u32);
    }

    fn emit(&self, tcp_flags: u8, payload: &[u8]) -> Result<OutboundPacket, Error> {
        let tsval = tcp_timestamp_now();
        let timestamp = Some((tsval, self.ts_recent));
        // Wire owns the only payload copy. `packet.payload` stays empty so the
        // send hot path does not allocate a second Vec for the same bytes;
        // callers that need the datagram re-decode `bytes` or use the input.
        let bytes = encode_with_payload(
            self.local,
            self.remote,
            self.send_next,
            self.receive_next,
            tcp_flags,
            timestamp,
            payload,
        )?;
        Ok(OutboundPacket {
            packet: Packet {
                source: self.local,
                destination: self.remote,
                sequence: self.send_next,
                acknowledgement: self.receive_next,
                flags: tcp_flags,
                payload: Vec::new(),
                timestamp,
                reset_auth: None,
            },
            bytes,
        })
    }

    fn emit_reset(&self) -> Result<OutboundPacket, Error> {
        let reset_auth = self.reset_auth_tag(self.send_next, self.receive_next);
        let bytes = encode_with_payload_and_reset_auth(
            TcpPacketFields {
                source: self.local,
                destination: self.remote,
                sequence: self.send_next,
                acknowledgement: self.receive_next,
                flags: flags::RST | flags::ACK,
                timestamp: None,
                reset_auth,
            },
            &[],
        )?;
        Ok(OutboundPacket {
            packet: Packet {
                source: self.local,
                destination: self.remote,
                sequence: self.send_next,
                acknowledgement: self.receive_next,
                flags: flags::RST | flags::ACK,
                payload: Vec::new(),
                timestamp: None,
                reset_auth,
            },
            bytes,
        })
    }

    fn authenticates_reset(&self, packet: &Packet) -> bool {
        packet.flags == (flags::RST | flags::ACK)
            && self.state == State::Established
            && packet.sequence == self.receive_next
            && packet.acknowledgement == self.send_next
            && packet.reset_auth.is_some_and(|tag| {
                self.reset_auth_tag(packet.sequence, packet.acknowledgement) == Some(tag)
            })
    }

    fn reset_auth_tag(&self, sequence: u32, acknowledgement: u32) -> Option<[u8; 16]> {
        let key = self.reset_key.as_deref()?;
        let server_initial_sequence = self.server_initial_sequence?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(b"tinect/fake-tcp/rst/v1");
        // Do not bind the raw tuple: stateful NAT legitimately rewrites it
        // between peers.  The pair of per-connection initial sequences binds
        // this tag to one session; callers must supply unpredictable ISNs.
        mac.update(&[u8::from(self.local.is_ipv6())]);
        mac.update(&self.client_initial_sequence.to_be_bytes());
        mac.update(&server_initial_sequence.to_be_bytes());
        mac.update(&sequence.to_be_bytes());
        mac.update(&acknowledgement.to_be_bytes());
        mac.update(&[flags::RST | flags::ACK]);
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(&mac.finalize().into_bytes()[..16]);
        Some(tag)
    }
}

fn is_ack_segment(tcp_flags: u8) -> bool {
    tcp_flags & flags::ACK != 0 && tcp_flags & !(flags::ACK | flags::PSH) == 0
}

fn tcp_timestamp_now() -> u32 {
    // Instant is vdso-backed on Linux; avoid SystemTime syscalls on the hot path.
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    (start.elapsed().as_millis() as u32).max(1)
}

fn option_len_for(flags: u8, reset_auth: Option<[u8; 16]>) -> usize {
    if flags & flags::SYN != 0 {
        SYN_TCP_OPTION_LEN
    } else if flags & flags::RST != 0 {
        reset_auth.map_or(0, |_| RST_TCP_OPTION_LEN)
    } else {
        // Established data and pure ACKs carry Timestamp for realism.
        DATA_TCP_OPTION_LEN
    }
}

/// Encodes a full IPv4/IPv6 packet.
///
/// SYN segments advertise MSS, SACK-permitted, Timestamp and window scale.
/// Established segments carry Timestamp options and, for application data,
/// PSH (set by the caller via flags).
pub fn encode(packet: &Packet) -> Result<Vec<u8>, Error> {
    encode_with_payload_and_reset_auth(
        TcpPacketFields {
            source: packet.source,
            destination: packet.destination,
            sequence: packet.sequence,
            acknowledgement: packet.acknowledgement,
            flags: packet.flags,
            timestamp: packet.timestamp,
            reset_auth: packet.reset_auth,
        },
        &packet.payload,
    )
}

/// Like [`encode`], but takes the payload as a borrowed slice so the hot path
/// can build the wire image without first allocating a `Packet.payload` copy.
pub fn encode_with_payload(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgement: u32,
    tcp_flags: u8,
    timestamp: Option<(u32, u32)>,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    encode_with_payload_and_reset_auth(
        TcpPacketFields {
            source,
            destination,
            sequence,
            acknowledgement,
            flags: tcp_flags,
            timestamp,
            reset_auth: None,
        },
        payload,
    )
}

#[derive(Clone, Copy)]
struct TcpPacketFields {
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    timestamp: Option<(u32, u32)>,
    reset_auth: Option<[u8; 16]>,
}

fn encode_with_payload_and_reset_auth(
    fields: TcpPacketFields,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let TcpPacketFields {
        source,
        destination,
        sequence,
        acknowledgement,
        flags: tcp_flags,
        timestamp,
        reset_auth,
    } = fields;
    ensure_family(source, destination)?;
    let ip_len = if source.is_ipv4() {
        IPV4_HEADER_LEN
    } else {
        IPV6_HEADER_LEN
    };
    let option_len = option_len_for(tcp_flags, reset_auth);
    let tcp_header_len = TCP_HEADER_LEN + option_len;
    let tcp_len = tcp_header_len
        .checked_add(payload.len())
        .ok_or(Error::PayloadTooLarge)?;
    let total = ip_len.checked_add(tcp_len).ok_or(Error::PayloadTooLarge)?;
    if (source.is_ipv4() && total > u16::MAX as usize) || tcp_len > u16::MAX as usize {
        return Err(Error::PayloadTooLarge);
    }
    let mut out = vec![0_u8; total];
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            out[0] = 0x45;
            out[1] = 0;
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            out[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
            out[8] = 64;
            out[9] = TCP_PROTOCOL;
            out[12..16].copy_from_slice(&src.octets());
            out[16..20].copy_from_slice(&dst.octets());
            let sum = checksum(&out[..IPV4_HEADER_LEN]);
            out[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            out[0] = 0x60;
            out[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            out[6] = TCP_PROTOCOL;
            out[7] = 64;
            out[8..24].copy_from_slice(&src.octets());
            out[24..40].copy_from_slice(&dst.octets());
        }
        _ => return Err(Error::AddressFamilyMismatch),
    }
    let offset = ip_len;
    out[offset..offset + 2].copy_from_slice(&source.port().to_be_bytes());
    out[offset + 2..offset + 4].copy_from_slice(&destination.port().to_be_bytes());
    out[offset + 4..offset + 8].copy_from_slice(&sequence.to_be_bytes());
    out[offset + 8..offset + 12].copy_from_slice(&acknowledgement.to_be_bytes());
    out[offset + 12] = ((tcp_header_len / 4) as u8) << 4;
    out[offset + 13] = tcp_flags;
    out[offset + 14..offset + 16].copy_from_slice(&u16::MAX.to_be_bytes());
    let (tsval, tsecr) = timestamp.unwrap_or((tcp_timestamp_now(), 0));
    if let Some(tag) = (tcp_flags & flags::RST != 0)
        .then_some(reset_auth)
        .flatten()
    {
        out[offset + TCP_HEADER_LEN..offset + tcp_header_len].copy_from_slice(&[
            19, 18, // TCP MD5 Signature option
            tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7], tag[8], tag[9],
            tag[10], tag[11], tag[12], tag[13], tag[14], tag[15], 1, 1, // NOP NOP
        ]);
    } else if option_len == SYN_TCP_OPTION_LEN {
        let mss = if source.is_ipv4() {
            IPV4_ADVERTISED_MSS
        } else {
            IPV6_ADVERTISED_MSS
        };
        let [mss_hi, mss_lo] = mss.to_be_bytes();
        let [v0, v1, v2, v3] = tsval.to_be_bytes();
        let [e0, e1, e2, e3] = tsecr.to_be_bytes();
        // Layout mirrors a common Linux SYN option order (20 bytes):
        // MSS, SACK-permitted, Timestamp, NOP, Window Scale.
        out[offset + TCP_HEADER_LEN..offset + tcp_header_len].copy_from_slice(&[
            2, 4, mss_hi, mss_lo, // MSS
            4, 2, // SACK permitted
            8, 10, v0, v1, v2, v3, e0, e1, e2, e3, // Timestamp
            1,  // NOP
            3, 3, 7, // Window Scale shift=7
        ]);
    } else if option_len == DATA_TCP_OPTION_LEN {
        let [v0, v1, v2, v3] = tsval.to_be_bytes();
        let [e0, e1, e2, e3] = tsecr.to_be_bytes();
        out[offset + TCP_HEADER_LEN..offset + tcp_header_len].copy_from_slice(&[
            1, 1, // NOP NOP
            8, 10, v0, v1, v2, v3, e0, e1, e2, e3, // Timestamp
        ]);
    }
    out[offset + tcp_header_len..].copy_from_slice(payload);
    let tcp_sum = transport_checksum(source.ip(), destination.ip(), &out[offset..]);
    out[offset + 16..offset + 18].copy_from_slice(&tcp_sum.to_be_bytes());
    Ok(out)
}

/// Decodes and verifies a complete, unfragmented IPv4/IPv6 TCP packet.
pub fn decode(bytes: &[u8]) -> Result<Packet, Error> {
    let version = *bytes.first().ok_or(Error::PacketTooShort)? >> 4;
    let (ip_len, source, destination, tcp_len) = match version {
        4 => {
            if bytes.len() < IPV4_HEADER_LEN {
                return Err(Error::PacketTooShort);
            }
            let header_len = usize::from(bytes[0] & 0x0f) * 4;
            if header_len < IPV4_HEADER_LEN || bytes.len() < header_len {
                return Err(Error::InvalidIpHeader);
            }
            let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if total != bytes.len() || bytes[9] != TCP_PROTOCOL {
                return Err(if bytes[9] == TCP_PROTOCOL {
                    Error::PacketLengthMismatch
                } else {
                    Error::NotTcp
                });
            }
            if u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0 {
                return Err(Error::FragmentedIpv4);
            }
            if checksum(&bytes[..header_len]) != 0 {
                return Err(Error::InvalidChecksum);
            }
            (
                header_len,
                IpAddr::from([bytes[12], bytes[13], bytes[14], bytes[15]]),
                IpAddr::from([bytes[16], bytes[17], bytes[18], bytes[19]]),
                total - header_len,
            )
        }
        6 => {
            if bytes.len() < IPV6_HEADER_LEN {
                return Err(Error::PacketTooShort);
            }
            let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            if bytes.len() != IPV6_HEADER_LEN + payload_len {
                return Err(Error::PacketLengthMismatch);
            }
            if bytes[6] != TCP_PROTOCOL {
                return Err(Error::NotTcp);
            }
            let mut src = [0; 16];
            src.copy_from_slice(&bytes[8..24]);
            let mut dst = [0; 16];
            dst.copy_from_slice(&bytes[24..40]);
            (
                IPV6_HEADER_LEN,
                IpAddr::from(src),
                IpAddr::from(dst),
                payload_len,
            )
        }
        _ => return Err(Error::InvalidIpVersion),
    };
    if tcp_len < TCP_HEADER_LEN {
        return Err(Error::InvalidTcpHeader);
    }
    let tcp = &bytes[ip_len..];
    let tcp_header_len = usize::from(tcp[12] >> 4) * 4;
    if tcp_header_len < TCP_HEADER_LEN || tcp_header_len > tcp.len() {
        return Err(Error::InvalidTcpHeader);
    }
    if transport_checksum(source, destination, tcp) != 0 {
        return Err(Error::InvalidChecksum);
    }
    let timestamp = parse_timestamp_option(&tcp[TCP_HEADER_LEN..tcp_header_len]);
    let reset_auth = parse_reset_auth_option(&tcp[TCP_HEADER_LEN..tcp_header_len]);
    Ok(Packet {
        source: SocketAddr::new(source, u16::from_be_bytes([tcp[0], tcp[1]])),
        destination: SocketAddr::new(destination, u16::from_be_bytes([tcp[2], tcp[3]])),
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        acknowledgement: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
        payload: tcp[tcp_header_len..].to_vec(),
        timestamp,
        reset_auth,
    })
}

fn parse_reset_auth_option(options: &[u8]) -> Option<[u8; 16]> {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => break,
            1 => i += 1,
            kind => {
                if i + 1 >= options.len() {
                    break;
                }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() {
                    break;
                }
                if kind == 19 && len == 18 {
                    let mut tag = [0_u8; 16];
                    tag.copy_from_slice(&options[i + 2..i + 18]);
                    return Some(tag);
                }
                i += len;
            }
        }
    }
    None
}

fn parse_timestamp_option(options: &[u8]) -> Option<(u32, u32)> {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => break,  // EOL
            1 => i += 1, // NOP
            kind => {
                if i + 1 >= options.len() {
                    break;
                }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() {
                    break;
                }
                if kind == 8 && len == 10 {
                    let tsval = u32::from_be_bytes([
                        options[i + 2],
                        options[i + 3],
                        options[i + 4],
                        options[i + 5],
                    ]);
                    let tsecr = u32::from_be_bytes([
                        options[i + 6],
                        options[i + 7],
                        options[i + 8],
                        options[i + 9],
                    ]);
                    return Some((tsval, tsecr));
                }
                i += len;
            }
        }
    }
    None
}

fn ensure_family(a: SocketAddr, b: SocketAddr) -> Result<(), Error> {
    if a.is_ipv4() == b.is_ipv4() {
        Ok(())
    } else {
        Err(Error::AddressFamilyMismatch)
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    finalize(sum_words(0, bytes))
}
fn transport_checksum(source: IpAddr, destination: IpAddr, tcp: &[u8]) -> u16 {
    let mut sum = 0_u32;
    match (source, destination) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            sum = sum_words(sum, &a.octets());
            sum = sum_words(sum, &b.octets());
            sum += u32::from(TCP_PROTOCOL);
            sum += tcp.len() as u32;
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            sum = sum_words(sum, &a.octets());
            sum = sum_words(sum, &b.octets());
            sum = sum_words(sum, &(tcp.len() as u32).to_be_bytes());
            sum += u32::from(TCP_PROTOCOL);
        }
        _ => return 0,
    }
    finalize(sum_words(sum, tcp))
}
fn sum_words(mut sum: u32, bytes: &[u8]) -> u32 {
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    sum
}
fn finalize(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    fn v4(a: &str) -> SocketAddr {
        a.parse().unwrap()
    }
    fn strip_ts(mut p: Packet) -> Packet {
        p.timestamp = None;
        p
    }
    #[test]
    fn ipv4_round_trip_and_df() {
        let p = Packet {
            source: v4("192.0.2.1:9"),
            destination: v4("198.51.100.2:443"),
            sequence: 1,
            acknowledgement: 2,
            flags: flags::ACK | flags::PSH,
            payload: b"quic".to_vec(),
            timestamp: Some((10, 20)),
            reset_auth: None,
        };
        let wire = encode(&p).unwrap();
        assert_eq!(wire[6] & 0x40, 0x40);
        // data offset (20+12)/4 = 8
        assert_eq!(wire[20 + 12] >> 4, 8);
        let decoded = decode(&wire).unwrap();
        assert_eq!(decoded.flags, p.flags);
        assert_eq!(decoded.payload, p.payload);
        assert_eq!(decoded.timestamp, Some((10, 20)));
    }
    #[test]
    fn ipv6_round_trip() {
        let p = Packet {
            source: "[2001:db8::1]:9".parse().unwrap(),
            destination: "[2001:db8::2]:443".parse().unwrap(),
            sequence: 1,
            acknowledgement: 2,
            flags: flags::ACK,
            payload: vec![3; 50],
            timestamp: Some((1, 2)),
            reset_auth: None,
        };
        let decoded = decode(&encode(&p).unwrap()).unwrap();
        assert_eq!(strip_ts(decoded.clone()).payload, p.payload);
        assert_eq!(decoded.timestamp, Some((1, 2)));
    }

    #[test]
    fn established_data_header_overhead_is_exact_for_both_families() {
        let payload = vec![7; 128];
        let cases = [
            (v4("192.0.2.1:9"), v4("198.51.100.2:443"), 20 + 32),
            (
                "[2001:db8::1]:9".parse().unwrap(),
                "[2001:db8::2]:443".parse().unwrap(),
                40 + 32,
            ),
        ];
        for (source, destination, expected_overhead) in cases {
            let packet = Packet {
                source,
                destination,
                sequence: 1,
                acknowledgement: 2,
                flags: flags::ACK | flags::PSH,
                payload: payload.clone(),
                timestamp: Some((10, 20)),
                reset_auth: None,
            };
            let wire = encode(&packet).unwrap();
            assert_eq!(wire.len() - payload.len(), expected_overhead);
        }
    }
    #[test]
    fn corrupt_packet_is_rejected() {
        let p = Packet {
            source: v4("192.0.2.1:9"),
            destination: v4("198.51.100.2:443"),
            sequence: 1,
            acknowledgement: 2,
            flags: flags::ACK,
            payload: vec![],
            timestamp: Some((1, 0)),
            reset_auth: None,
        };
        let mut wire = encode(&p).unwrap();
        wire[10] ^= 1;
        assert_eq!(decode(&wire), Err(Error::InvalidChecksum));
    }

    #[test]
    fn ignores_untrusted_reset_and_accepts_authenticated_reset() {
        let local = v4("192.0.2.1:40000");
        let remote = v4("198.51.100.2:443");
        let mut client = FakeTcpSession::client(local, remote, 100).unwrap();
        let syn = client.start().unwrap();

        // This is the shape of a kernel RST|ACK to a raw SYN.  Its ACK is
        // plausible, but there is no established fake-TCP sequence context
        // to authenticate it against.
        let kernel_rst = Packet {
            source: remote,
            destination: local,
            sequence: 0,
            acknowledgement: 101,
            flags: flags::RST | flags::ACK,
            payload: vec![],
            timestamp: None,
            reset_auth: None,
        };
        assert_eq!(
            client.handle_inbound(&encode(&kernel_rst).unwrap()),
            Err(Error::InvalidTransition)
        );
        assert_eq!(client.state(), State::SynSent);

        let (mut server, syn_ack) = FakeTcpSession::accept(&syn.bytes, 200).unwrap();
        let ack = client
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        server.handle_inbound(&ack.bytes).unwrap();

        let unauthenticated_reset = Packet {
            source: remote,
            destination: local,
            sequence: client.receive_next,
            acknowledgement: client.send_next,
            flags: flags::RST | flags::ACK,
            payload: vec![],
            timestamp: None,
            reset_auth: None,
        };
        assert_eq!(
            client.handle_inbound(&encode(&unauthenticated_reset).unwrap()),
            Err(Error::InvalidTransition)
        );
        assert_eq!(client.state(), State::Established);

        // Reset authentication is deliberately disabled in production until
        // reset-key provisioning is configured.  Unit tests exercise the
        // future enabled path without changing that safe default.
        let key = [42_u8; 32];
        client.reset_key = Some(key.to_vec());
        server.reset_key = Some(key.to_vec());
        let reset = server.reset().unwrap();
        assert!(reset.packet.reset_auth.is_some());
        assert_eq!(reset.bytes[20 + 12] >> 4, 10);
        assert_eq!(&reset.bytes[20 + 20..20 + 22], &[19, 18]);

        let mut tampered = reset.bytes.clone();
        tampered[20 + 22] ^= 1;
        tampered[20 + 16..20 + 18].fill(0);
        let checksum = transport_checksum(remote.ip(), local.ip(), &tampered[20..]);
        tampered[20 + 16..20 + 18].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            client.handle_inbound(&tampered),
            Err(Error::InvalidTransition)
        );
        assert_eq!(client.state(), State::Established);

        let event = client.handle_inbound(&reset.bytes).unwrap();
        assert_eq!(event.state, State::Reset);
        assert_eq!(client.state(), State::Reset);
    }
    #[test]
    fn syn_advertises_mss_sack_timestamp_and_window_scale() {
        let p = Packet {
            source: v4("192.0.2.1:40000"),
            destination: v4("198.51.100.2:443"),
            sequence: 1,
            acknowledgement: 0,
            flags: flags::SYN,
            payload: vec![],
            timestamp: Some((0x1111_2222, 0)),
            reset_auth: None,
        };
        let wire = encode(&p).unwrap();
        // data offset = (20+20)/4 = 10
        assert_eq!(wire[20 + 12] >> 4, 10);
        let options = &wire[20 + 20..20 + 40];
        assert_eq!(&options[0..4], &[2, 4, 0x05, 0xb4]); // MSS 1460
        assert_eq!(&options[4..6], &[4, 2]); // SACK permitted
        assert_eq!(&options[6..8], &[8, 10]); // Timestamp
        assert_eq!(&options[8..12], &0x1111_2222_u32.to_be_bytes());
        assert_eq!(&options[16], &1); // NOP
        assert_eq!(&options[17..20], &[3, 3, 7]); // WScale
    }
    #[test]
    fn handshake_and_datagram_delivery() {
        let mut client =
            FakeTcpSession::client(v4("192.0.2.1:40000"), v4("198.51.100.2:443"), 100).unwrap();
        let syn = client.start().unwrap();
        assert_eq!(syn.bytes[20 + 12] >> 4, 10);
        assert!(syn.packet.timestamp.is_some());
        let (mut server, syn_ack) = FakeTcpSession::accept(&syn.bytes, 200).unwrap();
        assert!(syn_ack.packet.timestamp.is_some());
        // Server echoes client TSval as TSecr.
        assert_eq!(
            syn_ack.packet.timestamp.unwrap().1,
            syn.packet.timestamp.unwrap().0
        );
        let ack = client
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        assert_eq!(
            server.handle_inbound(&ack.bytes).unwrap().state,
            State::Established
        );
        let outbound = client.encapsulate(b"quic datagram").unwrap();
        assert_eq!(
            outbound.packet.flags,
            flags::ACK | flags::PSH,
            "application data should look PSH-pushed"
        );
        assert_eq!(outbound.bytes[20 + 12] >> 4, 8); // data + timestamp
        let event = server.handle_inbound(&outbound.bytes).unwrap();
        assert_eq!(event.datagram.as_deref(), Some(b"quic datagram".as_slice()));
        // Every data segment gets an immediate pure ACK (no delayed coalesce).
        assert!(event.reply.is_some());
        assert_eq!(
            event.reply.as_ref().unwrap().packet.acknowledgement,
            100 + 1 + b"quic datagram".len() as u32
        );
        let second = client.encapsulate(b"xx").unwrap();
        let event2 = server.handle_inbound(&second.bytes).unwrap();
        assert!(event2.reply.is_some());
        assert_eq!(
            event2.reply.as_ref().unwrap().packet.acknowledgement,
            100 + 1 + b"quic datagram".len() as u32 + 2
        );
    }

    #[test]
    fn handshake_ack_can_carry_first_datagram() {
        let mut client =
            FakeTcpSession::client(v4("192.0.2.1:40000"), v4("198.51.100.2:443"), 100).unwrap();
        let syn = client.start().unwrap();
        let (mut server, syn_ack) = FakeTcpSession::accept(&syn.bytes, 200).unwrap();
        let ack = client
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        let first = client.encapsulate(b"first").unwrap();
        // Wire is authoritative for payload; re-decode then adjust ACK fields.
        let mut piggybacked = decode(&first.bytes).unwrap();
        piggybacked.acknowledgement = ack.packet.acknowledgement;
        piggybacked.flags = flags::ACK;
        let wire = encode(&piggybacked).unwrap();
        let event = server.handle_inbound(&wire).unwrap();
        assert_eq!(event.state, State::Established);
        assert_eq!(event.datagram.as_deref(), Some(b"first".as_slice()));
        // First post-handshake payload always ACKs immediately.
        assert_eq!(
            event.reply.as_ref().unwrap().packet.acknowledgement,
            100 + 1 + 5
        );
    }

    #[test]
    fn reordered_payload_does_not_regress_ack() {
        let mut client =
            FakeTcpSession::client(v4("192.0.2.1:40000"), v4("198.51.100.2:443"), 100).unwrap();
        let syn = client.start().unwrap();
        let (mut server, syn_ack) = FakeTcpSession::accept(&syn.bytes, 200).unwrap();
        let ack = client
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        assert_eq!(
            server.handle_inbound(&ack.bytes).unwrap().state,
            State::Established
        );
        let first = client.encapsulate(b"aaaa").unwrap();
        let second = client.encapsulate(b"bbbb").unwrap();
        let late = server.handle_inbound(&second.bytes).unwrap();
        assert_eq!(late.datagram.as_deref(), Some(b"bbbb".as_slice()));
        // Reorder still pure-ACKs the current receive_next (no ACK regression).
        assert_eq!(late.reply.as_ref().unwrap().packet.acknowledgement, 101);
        let in_order = server.handle_inbound(&first.bytes).unwrap();
        assert_eq!(in_order.datagram.as_deref(), Some(b"aaaa".as_slice()));
        // In-order data also pure-ACKs; receive_next advanced only for "aaaa".
        assert_eq!(
            in_order.reply.as_ref().unwrap().packet.acknowledgement,
            101 + 4
        );
    }

    #[test]
    fn every_data_segment_emits_pure_ack() {
        let mut client =
            FakeTcpSession::client(v4("192.0.2.1:40000"), v4("198.51.100.2:443"), 100).unwrap();
        let syn = client.start().unwrap();
        let (mut server, syn_ack) = FakeTcpSession::accept(&syn.bytes, 200).unwrap();
        let ack = client
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        assert_eq!(
            server.handle_inbound(&ack.bytes).unwrap().state,
            State::Established
        );
        let first = client.encapsulate(b"aaaa").unwrap();
        let e1 = server.handle_inbound(&first.bytes).unwrap();
        assert_eq!(e1.reply.as_ref().unwrap().packet.acknowledgement, 101 + 4);
        let second = client.encapsulate(b"bbbb").unwrap();
        let e2 = server.handle_inbound(&second.bytes).unwrap();
        assert_eq!(e2.reply.as_ref().unwrap().packet.acknowledgement, 101 + 8);
    }

    #[test]
    fn ipv6_handshake_and_datagram_delivery() {
        let local: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        let remote: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let mut client = FakeTcpSession::client(local, remote, 100).unwrap();
        let syn = client.start().unwrap();
        // IPv6 SYN: 40 IP + 40 TCP = 80 bytes
        assert_eq!(syn.bytes.len(), 80);
        let options = &syn.bytes[40 + 20..40 + 40];
        assert_eq!(&options[0..4], &[2, 4, 0x05, 0xa0]); // MSS 1440
        assert_eq!(&options[4..6], &[4, 2]); // SACK
        let (mut server, syn_ack) = FakeTcpSession::accept(&syn.bytes, 200).unwrap();
        let ack = client
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        assert_eq!(
            server.handle_inbound(&ack.bytes).unwrap().state,
            State::Established
        );
        let outbound = client.encapsulate(b"quic datagram").unwrap();
        let event = server.handle_inbound(&outbound.bytes).unwrap();
        assert_eq!(event.datagram.as_deref(), Some(b"quic datagram".as_slice()));
        assert!(event.reply.is_some());
        let second = client.encapsulate(b"yy").unwrap();
        let event2 = server.handle_inbound(&second.bytes).unwrap();
        assert!(event2.reply.is_some());
    }
    #[test]
    fn rejects_payload_before_handshake() {
        let mut c = FakeTcpSession::client(v4("192.0.2.1:1"), v4("198.51.100.2:2"), 0).unwrap();
        assert_eq!(c.encapsulate(b"x"), Err(Error::NotEstablished));
    }

    #[test]
    fn constructors_accessors_and_state_transitions_cover_rejections() {
        let local = v4("192.0.2.1:40000");
        let remote = v4("198.51.100.2:443");
        assert!(matches!(
            FakeTcpSession::client(local, "[2001:db8::2]:443".parse().unwrap(), 1),
            Err(Error::AddressFamilyMismatch)
        ));
        let mut client =
            FakeTcpSession::client_with_reset_key(local, remote, 10, Some(b"key")).unwrap();
        assert_eq!(client.local_addr(), local);
        assert_eq!(client.remote_addr(), remote);
        assert!(format!("{client:?}").contains("reset_auth_enabled: true"));
        let syn = client.start().unwrap();
        assert_eq!(syn.packet.flags, flags::SYN);
        assert!(matches!(client.start(), Err(Error::InvalidTransition)));

        let invalid_syn = Packet {
            source: remote,
            destination: local,
            sequence: 1,
            acknowledgement: 0,
            flags: flags::ACK,
            payload: Vec::new(),
            timestamp: None,
            reset_auth: None,
        };
        assert!(matches!(
            FakeTcpSession::accept_packet(invalid_syn.clone(), 20),
            Err(Error::InvalidTransition)
        ));
        assert!(FakeTcpSession::accept_packet(syn.packet.clone(), 21).is_ok());
        let (mut server, syn_ack) =
            FakeTcpSession::accept_with_reset_key(&syn.bytes, 20, Some(b"key")).unwrap();
        let ack = client.handle_packet(syn_ack.packet).unwrap().reply.unwrap();
        assert_eq!(
            server.handle_packet(ack.packet).unwrap().state,
            State::Established
        );
        assert!(FakeTcpSession::accept_with_reset_key(&[], 20, Some(b"key")).is_err());
        let invalid_established = Packet {
            source: local,
            destination: remote,
            flags: flags::SYN,
            ..invalid_syn
        };
        assert_eq!(
            server.handle_packet(invalid_established).unwrap_err(),
            Error::InvalidTransition
        );
    }

    #[test]
    fn decoder_and_option_parsers_cover_malformed_wire_boundaries() {
        let packet = Packet {
            source: v4("192.0.2.1:40000"),
            destination: v4("198.51.100.2:443"),
            sequence: 1,
            acknowledgement: 2,
            flags: flags::ACK,
            payload: Vec::new(),
            timestamp: Some((1, 2)),
            reset_auth: None,
        };
        assert_eq!(decode(&[]), Err(Error::PacketTooShort));
        let mut wire = encode(&packet).unwrap();

        let mut short = vec![0x45; IPV4_HEADER_LEN - 1];
        assert_eq!(decode(&short), Err(Error::PacketTooShort));
        short.resize(IPV4_HEADER_LEN, 0);
        short[0] = 0x44;
        assert_eq!(decode(&short), Err(Error::InvalidIpHeader));

        let mut not_tcp = wire.clone();
        not_tcp[9] = 17;
        assert_eq!(decode(&not_tcp), Err(Error::NotTcp));
        let mut wrong_length = wire.clone();
        wrong_length[2..4].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(decode(&wrong_length), Err(Error::PacketLengthMismatch));
        let mut fragmented = wire.clone();
        fragmented[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(decode(&fragmented), Err(Error::FragmentedIpv4));
        wire[20 + 12] = 0x40;
        assert_eq!(decode(&wire), Err(Error::InvalidTcpHeader));

        let mut ipv6 = encode(&Packet {
            source: "[2001:db8::1]:1".parse().unwrap(),
            destination: "[2001:db8::2]:2".parse().unwrap(),
            ..packet.clone()
        })
        .unwrap();
        assert_eq!(
            decode(&ipv6[..IPV6_HEADER_LEN - 1]),
            Err(Error::PacketTooShort)
        );
        ipv6[4..6].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(decode(&ipv6), Err(Error::PacketLengthMismatch));
        ipv6 = encode(&Packet {
            source: "[2001:db8::1]:1".parse().unwrap(),
            destination: "[2001:db8::2]:2".parse().unwrap(),
            ..Packet {
                flags: flags::ACK,
                timestamp: Some((1, 2)),
                ..packet
            }
        })
        .unwrap();
        ipv6[6] = 17;
        assert_eq!(decode(&ipv6), Err(Error::NotTcp));
        assert_eq!(
            encode_with_payload(
                v4("192.0.2.1:1"),
                "[2001:db8::2]:2".parse().unwrap(),
                0,
                0,
                flags::ACK,
                None,
                &[]
            ),
            Err(Error::AddressFamilyMismatch)
        );
        assert_eq!(
            encode_with_payload(
                v4("192.0.2.1:1"),
                v4("198.51.100.2:2"),
                0,
                0,
                flags::ACK,
                None,
                &vec![0; u16::MAX as usize]
            ),
            Err(Error::PayloadTooLarge)
        );

        assert_eq!(parse_reset_auth_option(&[]), None);
        assert_eq!(parse_reset_auth_option(&[1, 0]), None);
        assert_eq!(parse_reset_auth_option(&[19]), None);
        assert_eq!(parse_reset_auth_option(&[19, 1]), None);
        assert_eq!(parse_reset_auth_option(&[19, 18, 7, 1]), None);
        assert_eq!(parse_timestamp_option(&[0, 8, 10]), None);
        assert_eq!(parse_timestamp_option(&[1, 8, 10]), None);
        assert_eq!(parse_timestamp_option(&[8]), None);
        assert_eq!(parse_timestamp_option(&[8, 1]), None);
        assert_eq!(parse_timestamp_option(&[8, 10, 0, 0]), None);
        assert!(is_ack_segment(flags::ACK));
        assert!(is_ack_segment(flags::ACK | flags::PSH));
        assert!(!is_ack_segment(flags::SYN | flags::ACK));
        assert_eq!(
            transport_checksum(
                "192.0.2.1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                &[]
            ),
            0
        );
        assert_eq!(option_len_for(flags::SYN, None), SYN_TCP_OPTION_LEN);
        assert_eq!(option_len_for(flags::RST, None), 0);
        assert_eq!(
            option_len_for(flags::RST, Some([0; 16])),
            RST_TCP_OPTION_LEN
        );
    }

    #[cfg(feature = "raw-test")]
    #[test]
    fn test_reset_key_mutator_is_available_for_raw_fixtures() {
        let mut session =
            FakeTcpSession::client(v4("192.0.2.1:1"), v4("198.51.100.2:2"), 1).unwrap();
        session.set_reset_key_for_test([9; 32]);
        assert!(format!("{session:?}").contains("reset_auth_enabled: true"));
    }

    #[test]
    fn error_display_and_mixed_family_encoding_are_covered() {
        let error = Error::InvalidChecksum;
        assert!(format!("{error}").contains("fake TCP error"));

        let packet = Packet {
            source: v4("192.0.2.1:9"),
            destination: "[2001:db8::1]:9".parse().unwrap(),
            sequence: 1,
            acknowledgement: 2,
            flags: flags::ACK,
            payload: Vec::new(),
            timestamp: None,
            reset_auth: None,
        };
        assert_eq!(encode(&packet), Err(Error::AddressFamilyMismatch));
    }

    #[test]
    fn handle_packet_rejects_unexpected_peers() {
        let mut client =
            FakeTcpSession::client(v4("192.0.2.1:40000"), v4("198.51.100.2:443"), 10).unwrap();
        let foreign = Packet {
            source: v4("198.51.100.9:443"),
            destination: v4("192.0.2.1:40000"),
            sequence: 1,
            acknowledgement: 2,
            flags: flags::SYN,
            payload: Vec::new(),
            timestamp: None,
            reset_auth: None,
        };
        assert_eq!(client.handle_packet(foreign), Err(Error::UnexpectedPeer));
    }

    #[test]
    fn decode_rejects_invalid_ip_versions() {
        let p = Packet {
            source: v4("192.0.2.1:9"),
            destination: v4("198.51.100.2:443"),
            sequence: 1,
            acknowledgement: 2,
            flags: flags::ACK,
            payload: vec![],
            timestamp: None,
            reset_auth: None,
        };
        let mut wire = encode(&p).unwrap();
        wire[0] = 0x30;
        assert_eq!(decode(&wire), Err(Error::InvalidIpVersion));
        wire[0] = 0x50;
        assert_eq!(decode(&wire), Err(Error::InvalidIpVersion));
    }
}
