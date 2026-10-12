//! Linux conntrack cleanup used by direct fallback reinjection.
//!
//! A packet routed into TUN has already created a zone-zero conntrack entry.
//! Before reinjecting that packet in a dedicated directional zone, remove the
//! first-pass entry with an ID-guarded ctnetlink delete.  The ID guard prevents
//! a delayed request from deleting a newer flow that reused the same tuple.

use super::PlatformError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use tokio::sync::{mpsc, oneshot};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConntrackFlowKey(ConntrackTuple);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConntrackTuple {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    transport: TransportTuple,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TransportTuple {
    Ports { source: u16, destination: u16 },
    Icmp { id: u16, kind: u8, code: u8 },
    None,
}

impl ConntrackTuple {
    fn parse(packet: &[u8]) -> Option<Self> {
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => Self::parse_ipv4(packet),
            Some(6) => Self::parse_ipv6(packet),
            _ => None,
        }
    }

    fn parse_ipv4(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if header_len < 20 || packet.len() < header_len {
            return None;
        }
        // Conntrack defragmentation normally makes the TUN packet whole.  Do
        // not guess a tuple if a platform configuration exposes fragments.
        if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
            return None;
        }
        let protocol = packet[9];
        let source = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let destination = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        Some(Self {
            source,
            destination,
            protocol,
            transport: parse_transport(packet, header_len, protocol, false)?,
        })
    }

    fn parse_ipv6(packet: &[u8]) -> Option<Self> {
        if packet.len() < 40 {
            return None;
        }
        let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
        let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
        let mut protocol = packet[6];
        let mut offset = 40_usize;
        for _ in 0..8 {
            match protocol {
                // Hop-by-Hop, Routing, and Destination Options.
                0 | 43 | 60 => {
                    let header = packet.get(offset..offset + 2)?;
                    protocol = header[0];
                    offset = offset.checked_add((usize::from(header[1]) + 1) * 8)?;
                    if offset > packet.len() {
                        return None;
                    }
                }
                // Fragment Header.  See the IPv4 comment above.
                44 => return None,
                // Authentication Header length is in 32-bit words minus two.
                51 => {
                    let header = packet.get(offset..offset + 2)?;
                    protocol = header[0];
                    offset = offset.checked_add((usize::from(header[1]) + 2) * 4)?;
                    if offset > packet.len() {
                        return None;
                    }
                }
                _ => break,
            }
        }
        Some(Self {
            source,
            destination,
            protocol,
            transport: parse_transport(packet, offset, protocol, true)?,
        })
    }
}

fn parse_transport(
    packet: &[u8],
    offset: usize,
    protocol: u8,
    ipv6: bool,
) -> Option<TransportTuple> {
    match protocol {
        IPPROTO_TCP | IPPROTO_UDP | IPPROTO_DCCP | IPPROTO_SCTP => {
            let header = packet.get(offset..offset + 4)?;
            Some(TransportTuple::Ports {
                source: u16::from_be_bytes([header[0], header[1]]),
                destination: u16::from_be_bytes([header[2], header[3]]),
            })
        }
        protocol if (protocol == IPPROTO_ICMP && !ipv6) || (protocol == IPPROTO_ICMPV6 && ipv6) => {
            let header = packet.get(offset..offset + 8)?;
            Some(TransportTuple::Icmp {
                id: u16::from_be_bytes([header[4], header[5]]),
                kind: header[0],
                code: header[1],
            })
        }
        _ => Some(TransportTuple::None),
    }
}

#[cfg(target_os = "linux")]
const WORK_QUEUE_CAPACITY: usize = 1024;

#[cfg(target_os = "linux")]
enum WorkerRequest {
    Delete {
        tuple: ConntrackTuple,
        zone: u16,
        response: oneshot::Sender<Result<(), PlatformError>>,
    },
}

#[cfg(target_os = "linux")]
struct Worker {
    sender: Mutex<Option<mpsc::Sender<WorkerRequest>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[cfg(target_os = "linux")]
impl Drop for Worker {
    fn drop(&mut self) {
        self.sender
            .get_mut()
            .expect("conntrack sender mutex poisoned")
            .take();
        if let Some(thread) = self
            .thread
            .get_mut()
            .expect("conntrack thread mutex poisoned")
            .take()
        {
            let _ = thread.join();
        }
    }
}

/// A bounded, single-socket ctnetlink worker for direct fallback.
#[derive(Clone)]
pub struct DirectConntrack {
    zone: u16,
    #[cfg(target_os = "linux")]
    worker: Arc<Worker>,
}

impl DirectConntrack {
    pub fn open(zone: u16) -> Result<Self, PlatformError> {
        if zone == 0 {
            return Err(PlatformError::Command(
                "direct fallback conntrack zone must be non-zero".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let (sender, mut receiver) = mpsc::channel(WORK_QUEUE_CAPACITY);
            let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
            let thread = std::thread::Builder::new()
                .name("tinect-ctnetlink".into())
                .spawn(move || {
                    let mut socket = match ConntrackSocket::open() {
                        Ok(socket) => socket,
                        Err(error) => {
                            let _ = started_tx.send(Err(error));
                            return;
                        }
                    };
                    if let Err(error) = socket.flush_zone(zone) {
                        let _ = started_tx.send(Err(error));
                        return;
                    }
                    if started_tx.send(Ok(())).is_err() {
                        return;
                    }
                    while let Some(request) = receiver.blocking_recv() {
                        match request {
                            WorkerRequest::Delete {
                                tuple,
                                zone,
                                response,
                            } => {
                                let _ = response.send(socket.delete_tuple(&tuple, zone));
                            }
                        }
                    }
                    if let Err(error) = socket.flush_zone(zone) {
                        tracing::warn!(%zone, %error, "failed to flush direct fallback conntrack zone during shutdown");
                    }
                })
                .map_err(|error| {
                    PlatformError::Command(format!("starting ctnetlink worker: {error}"))
                })?;
            started_rx.recv().map_err(|_| {
                PlatformError::Command("ctnetlink worker stopped during startup".into())
            })??;
            Ok(Self {
                zone,
                worker: Arc::new(Worker {
                    sender: Mutex::new(Some(sender)),
                    thread: Mutex::new(Some(thread)),
                }),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(PlatformError::Unsupported(std::env::consts::OS.into()))
        }
    }

    pub fn flow_key(&self, packet: &[u8]) -> Option<ConntrackFlowKey> {
        ConntrackTuple::parse(packet).map(ConntrackFlowKey)
    }

    pub async fn delete_default(&self, packet: &[u8]) -> Result<ConntrackFlowKey, PlatformError> {
        let key = self.flow_key(packet).ok_or_else(|| {
            PlatformError::Command("packet has no deletable conntrack tuple".into())
        })?;
        self.delete(key.clone(), 0).await?;
        Ok(key)
    }

    pub async fn delete_fallback(&self, key: ConntrackFlowKey) -> Result<(), PlatformError> {
        self.delete(key, self.zone).await
    }

    async fn delete(&self, key: ConntrackFlowKey, zone: u16) -> Result<(), PlatformError> {
        #[cfg(target_os = "linux")]
        {
            let sender = self
                .worker
                .sender
                .lock()
                .map_err(|_| PlatformError::Command("ctnetlink worker lock poisoned".into()))?
                .as_ref()
                .cloned()
                .ok_or_else(|| PlatformError::Command("ctnetlink worker stopped".into()))?;
            let (response, result) = oneshot::channel();
            sender
                .send(WorkerRequest::Delete {
                    tuple: key.0,
                    zone,
                    response,
                })
                .await
                .map_err(|_| PlatformError::Command("ctnetlink worker stopped".into()))?;
            result
                .await
                .map_err(|_| PlatformError::Command("ctnetlink worker stopped".into()))?
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (key, zone);
            Err(PlatformError::Unsupported(std::env::consts::OS.into()))
        }
    }
}

#[cfg(target_os = "linux")]
const NLA_F_NESTED: u16 = 1 << 15;
#[cfg(target_os = "linux")]
const NLM_F_REQUEST: u16 = 1;
#[cfg(target_os = "linux")]
const NLM_F_ACK: u16 = 4;
#[cfg(target_os = "linux")]
const NLMSG_ERROR: u16 = 2;
#[cfg(target_os = "linux")]
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
#[cfg(target_os = "linux")]
const IPCTNL_MSG_CT_GET: u16 = 1;
#[cfg(target_os = "linux")]
const IPCTNL_MSG_CT_DELETE: u16 = 2;
#[cfg(target_os = "linux")]
const CTA_TUPLE_ORIG: u16 = 1;
#[cfg(target_os = "linux")]
const CTA_TUPLE_REPLY: u16 = 2;
#[cfg(target_os = "linux")]
const CTA_ID: u16 = 12;
#[cfg(target_os = "linux")]
const CTA_ZONE: u16 = 18;
#[cfg(target_os = "linux")]
const CTA_TUPLE_IP: u16 = 1;
#[cfg(target_os = "linux")]
const CTA_TUPLE_PROTO: u16 = 2;
#[cfg(target_os = "linux")]
const CTA_IP_V4_SRC: u16 = 1;
#[cfg(target_os = "linux")]
const CTA_IP_V4_DST: u16 = 2;
#[cfg(target_os = "linux")]
const CTA_IP_V6_SRC: u16 = 3;
#[cfg(target_os = "linux")]
const CTA_IP_V6_DST: u16 = 4;
#[cfg(target_os = "linux")]
const CTA_PROTO_NUM: u16 = 1;
#[cfg(target_os = "linux")]
const CTA_PROTO_SRC_PORT: u16 = 2;
#[cfg(target_os = "linux")]
const CTA_PROTO_DST_PORT: u16 = 3;
#[cfg(target_os = "linux")]
const CTA_PROTO_ICMP_ID: u16 = 4;
#[cfg(target_os = "linux")]
const CTA_PROTO_ICMP_TYPE: u16 = 5;
#[cfg(target_os = "linux")]
const CTA_PROTO_ICMP_CODE: u16 = 6;
#[cfg(target_os = "linux")]
const CTA_PROTO_ICMPV6_ID: u16 = 7;
#[cfg(target_os = "linux")]
const CTA_PROTO_ICMPV6_TYPE: u16 = 8;
#[cfg(target_os = "linux")]
const CTA_PROTO_ICMPV6_CODE: u16 = 9;

#[cfg(target_os = "linux")]
struct ConntrackSocket {
    socket: mnl::Socket,
    sequence: u32,
    buffer: Vec<u32>,
}

#[cfg(target_os = "linux")]
impl ConntrackSocket {
    fn open() -> Result<Self, PlatformError> {
        use std::os::fd::AsRawFd;

        let socket = mnl::Socket::new(mnl::Bus::Netfilter).map_err(conntrack_error)?;
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::from_ref(&timeout).cast(),
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(conntrack_error(std::io::Error::last_os_error()));
        }
        Ok(Self {
            socket,
            sequence: 0,
            // u32 storage guarantees nlmsghdr alignment while exposing bytes
            // to libmnl below.
            buffer: vec![0; 16 * 1024],
        })
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        self.sequence
    }

    fn delete_tuple(&mut self, tuple: &ConntrackTuple, zone: u16) -> Result<(), PlatformError> {
        for direction in [CTA_TUPLE_ORIG, CTA_TUPLE_REPLY] {
            let attributes = encode_lookup_attributes(tuple, direction, zone, None);
            let Some(id) = self.request_id(IPCTNL_MSG_CT_GET, tuple.family(), attributes)? else {
                continue;
            };
            let attributes = encode_lookup_attributes(tuple, direction, zone, Some(id));
            match self.request_ack(IPCTNL_MSG_CT_DELETE, tuple.family(), attributes) {
                Ok(()) => return Ok(()),
                Err(NetlinkRequestError::Errno(libc::ENOENT)) => continue,
                Err(error) => return Err(error.into_platform("deleting conntrack entry")),
            }
        }
        // No entry is a successful idempotent cleanup.  The first packet can
        // legitimately be untracked by an operator rule or expire meanwhile.
        Ok(())
    }

    fn flush_zone(&mut self, zone: u16) -> Result<(), PlatformError> {
        let mut attributes = Vec::new();
        push_attr(&mut attributes, CTA_ZONE, &zone.to_be_bytes());
        match self.request_ack(IPCTNL_MSG_CT_DELETE, libc::AF_UNSPEC as u8, attributes) {
            Ok(()) | Err(NetlinkRequestError::Errno(libc::ENOENT)) => Ok(()),
            Err(error) => Err(error.into_platform("flushing conntrack zone")),
        }
    }

    fn request_id(
        &mut self,
        operation: u16,
        family: u8,
        attributes: Vec<u8>,
    ) -> Result<Option<u32>, PlatformError> {
        let sequence = self.next_sequence();
        let request = encode_request(operation, family, sequence, attributes);
        self.socket.send(&request).map_err(conntrack_error)?;
        let mut id = None;
        loop {
            let received = self.recv_bytes()?;
            for message in NetlinkMessages::new(received) {
                let message = message.map_err(|error| error.into_platform("reading conntrack"))?;
                if message.sequence != sequence {
                    continue;
                }
                if message.kind == NLMSG_ERROR {
                    let error = message.error()?;
                    return match error {
                        0 => Ok(id),
                        value if value == -libc::ENOENT => Ok(None),
                        value => Err(PlatformError::Command(format!(
                            "querying conntrack entry failed with errno {}",
                            -value
                        ))),
                    };
                }
                if let Some(found) = find_attribute(message.payload_after_nfgen()?, CTA_ID)? {
                    if found.len() != 4 {
                        return Err(PlatformError::Command(
                            "conntrack CTA_ID has invalid length".into(),
                        ));
                    }
                    id = Some(u32::from_be_bytes(
                        found.try_into().expect("checked length"),
                    ));
                }
            }
        }
    }

    fn request_ack(
        &mut self,
        operation: u16,
        family: u8,
        attributes: Vec<u8>,
    ) -> Result<(), NetlinkRequestError> {
        let sequence = self.next_sequence();
        let request = encode_request(operation, family, sequence, attributes);
        self.socket
            .send(&request)
            .map_err(NetlinkRequestError::Io)?;
        loop {
            let received = self.recv_bytes().map_err(NetlinkRequestError::Platform)?;
            for message in NetlinkMessages::new(received) {
                let message = message?;
                if message.sequence != sequence || message.kind != NLMSG_ERROR {
                    continue;
                }
                let error = message.error().map_err(NetlinkRequestError::Platform)?;
                return if error == 0 {
                    Ok(())
                } else {
                    Err(NetlinkRequestError::Errno(-error))
                };
            }
        }
    }

    fn recv_bytes(&mut self) -> Result<&[u8], PlatformError> {
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                self.buffer.as_mut_ptr().cast::<u8>(),
                self.buffer.len() * std::mem::size_of::<u32>(),
            )
        };
        let length = self.socket.recv_raw(bytes).map_err(conntrack_error)?;
        Ok(&bytes[..length])
    }
}

#[cfg(target_os = "linux")]
impl ConntrackTuple {
    fn family(&self) -> u8 {
        match self.source {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum NetlinkRequestError {
    Io(std::io::Error),
    Platform(PlatformError),
    Errno(i32),
}

#[cfg(target_os = "linux")]
impl NetlinkRequestError {
    fn into_platform(self, operation: &str) -> PlatformError {
        match self {
            Self::Io(error) => conntrack_error(error),
            Self::Platform(error) => error,
            Self::Errno(errno) => {
                PlatformError::Command(format!("{operation} failed with errno {errno}"))
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl From<PlatformError> for NetlinkRequestError {
    fn from(value: PlatformError) -> Self {
        Self::Platform(value)
    }
}

#[cfg(target_os = "linux")]
fn conntrack_error(error: impl std::fmt::Display) -> PlatformError {
    PlatformError::Command(format!("ctnetlink: {error}"))
}

#[cfg(target_os = "linux")]
fn encode_lookup_attributes(
    tuple: &ConntrackTuple,
    direction: u16,
    zone: u16,
    id: Option<u32>,
) -> Vec<u8> {
    let mut attributes = Vec::new();
    let mut tuple_attributes = Vec::new();
    let mut ip = Vec::new();
    match (tuple.source, tuple.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            push_attr(&mut ip, CTA_IP_V4_SRC, &source.octets());
            push_attr(&mut ip, CTA_IP_V4_DST, &destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            push_attr(&mut ip, CTA_IP_V6_SRC, &source.octets());
            push_attr(&mut ip, CTA_IP_V6_DST, &destination.octets());
        }
        _ => unreachable!("conntrack tuple address families match"),
    }
    push_nested(&mut tuple_attributes, CTA_TUPLE_IP, &ip);

    let mut protocol = Vec::new();
    push_attr(&mut protocol, CTA_PROTO_NUM, &[tuple.protocol]);
    match tuple.transport {
        TransportTuple::Ports {
            source,
            destination,
        } => {
            push_attr(&mut protocol, CTA_PROTO_SRC_PORT, &source.to_be_bytes());
            push_attr(
                &mut protocol,
                CTA_PROTO_DST_PORT,
                &destination.to_be_bytes(),
            );
        }
        TransportTuple::Icmp { id, kind, code } => {
            let (id_attr, type_attr, code_attr) = if tuple.protocol == IPPROTO_ICMPV6 {
                (
                    CTA_PROTO_ICMPV6_ID,
                    CTA_PROTO_ICMPV6_TYPE,
                    CTA_PROTO_ICMPV6_CODE,
                )
            } else {
                (CTA_PROTO_ICMP_ID, CTA_PROTO_ICMP_TYPE, CTA_PROTO_ICMP_CODE)
            };
            push_attr(&mut protocol, id_attr, &id.to_be_bytes());
            push_attr(&mut protocol, type_attr, &[kind]);
            push_attr(&mut protocol, code_attr, &[code]);
        }
        TransportTuple::None => {}
    }
    push_nested(&mut tuple_attributes, CTA_TUPLE_PROTO, &protocol);
    push_nested(&mut attributes, direction, &tuple_attributes);
    if zone != 0 {
        push_attr(&mut attributes, CTA_ZONE, &zone.to_be_bytes());
    }
    if let Some(id) = id {
        push_attr(&mut attributes, CTA_ID, &id.to_be_bytes());
    }
    attributes
}

#[cfg(target_os = "linux")]
fn encode_request(operation: u16, family: u8, sequence: u32, attributes: Vec<u8>) -> Vec<u8> {
    let length = 16 + 4 + attributes.len();
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(&(length as u32).to_ne_bytes());
    message.extend_from_slice(&((NFNL_SUBSYS_CTNETLINK << 8) | operation).to_ne_bytes());
    message.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.push(family);
    message.push(0); // NFNETLINK_V0
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&attributes);
    message
}

#[cfg(target_os = "linux")]
fn push_nested(target: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    push_attr(target, kind | NLA_F_NESTED, payload);
}

#[cfg(target_os = "linux")]
fn push_attr(target: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let length = 4 + payload.len();
    target.extend_from_slice(&(length as u16).to_ne_bytes());
    target.extend_from_slice(&kind.to_ne_bytes());
    target.extend_from_slice(payload);
    target.resize(target.len() + (4 - length % 4) % 4, 0);
}

#[cfg(target_os = "linux")]
struct NetlinkMessage<'a> {
    kind: u16,
    sequence: u32,
    bytes: &'a [u8],
}

#[cfg(target_os = "linux")]
impl NetlinkMessage<'_> {
    fn error(&self) -> Result<i32, PlatformError> {
        let bytes = self
            .bytes
            .get(16..20)
            .ok_or_else(|| PlatformError::Command("truncated ctnetlink error response".into()))?;
        Ok(i32::from_ne_bytes(
            bytes.try_into().expect("checked length"),
        ))
    }

    fn payload_after_nfgen(&self) -> Result<&[u8], PlatformError> {
        self.bytes
            .get(20..)
            .ok_or_else(|| PlatformError::Command("truncated ctnetlink response header".into()))
    }
}

#[cfg(target_os = "linux")]
struct NetlinkMessages<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[cfg(target_os = "linux")]
impl<'a> NetlinkMessages<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

#[cfg(target_os = "linux")]
impl<'a> Iterator for NetlinkMessages<'a> {
    type Item = Result<NetlinkMessage<'a>, NetlinkRequestError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        let Some(header) = self.bytes.get(self.offset..self.offset + 16) else {
            self.offset = self.bytes.len();
            return Some(Err(NetlinkRequestError::Platform(PlatformError::Command(
                "truncated ctnetlink message header".into(),
            ))));
        };
        let length = u32::from_ne_bytes(header[0..4].try_into().expect("checked length")) as usize;
        if length < 16 || self.offset + length > self.bytes.len() {
            self.offset = self.bytes.len();
            return Some(Err(NetlinkRequestError::Platform(PlatformError::Command(
                "invalid ctnetlink message length".into(),
            ))));
        }
        let kind = u16::from_ne_bytes(header[4..6].try_into().expect("checked length"));
        let sequence = u32::from_ne_bytes(header[8..12].try_into().expect("checked length"));
        let bytes = &self.bytes[self.offset..self.offset + length];
        self.offset += (length + 3) & !3;
        Some(Ok(NetlinkMessage {
            kind,
            sequence,
            bytes,
        }))
    }
}

#[cfg(target_os = "linux")]
fn find_attribute(bytes: &[u8], wanted: u16) -> Result<Option<&[u8]>, PlatformError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset + 4)
            .ok_or_else(|| PlatformError::Command("truncated ctnetlink attribute".into()))?;
        let length = u16::from_ne_bytes(header[0..2].try_into().expect("checked length")) as usize;
        if length < 4 || offset + length > bytes.len() {
            return Err(PlatformError::Command(
                "invalid ctnetlink attribute length".into(),
            ));
        }
        let kind = u16::from_ne_bytes(header[2..4].try_into().expect("checked length")) & 0x3fff;
        if kind == wanted {
            return Ok(Some(&bytes[offset + 4..offset + length]));
        }
        offset += (length + 3) & !3;
    }
    Ok(None)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn ipv4_udp_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet
    }

    fn ipv4_packet(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20 + transport.len()];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet[20..].copy_from_slice(transport);
        packet
    }

    fn ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[8..24].copy_from_slice(&"fd00:64::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        packet[40..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn parses_ipv4_udp_conntrack_tuple() {
        assert_eq!(
            ConntrackTuple::parse(&ipv4_udp_packet()),
            Some(ConntrackTuple {
                source: "10.64.0.1".parse().unwrap(),
                destination: "198.51.100.7".parse().unwrap(),
                protocol: IPPROTO_UDP,
                transport: TransportTuple::Ports {
                    source: 40000,
                    destination: 443,
                },
            })
        );
    }

    #[test]
    fn parses_ipv6_extensions_and_icmp_tuple() {
        let mut packet = vec![0_u8; 56];
        packet[0] = 0x60;
        packet[6] = 60;
        packet[8..24].copy_from_slice(&"fd00:64::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = IPPROTO_ICMPV6;
        packet[41] = 0;
        packet[48] = 128;
        packet[52..54].copy_from_slice(&1234_u16.to_be_bytes());
        assert_eq!(
            ConntrackTuple::parse(&packet).unwrap().transport,
            TransportTuple::Icmp {
                id: 1234,
                kind: 128,
                code: 0,
            }
        );
    }

    #[test]
    fn rejects_fragments_and_truncated_transport_headers() {
        let mut fragment = ipv4_udp_packet();
        fragment[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(ConntrackTuple::parse(&fragment).is_none());
        assert!(ConntrackTuple::parse(&ipv4_udp_packet()[..22]).is_none());
    }

    #[test]
    fn parses_all_port_protocols_and_unknown_payloads() {
        let transport = [0x9c, 0x40, 0x01, 0xbb];
        for protocol in [IPPROTO_TCP, IPPROTO_UDP, IPPROTO_DCCP, IPPROTO_SCTP] {
            assert_eq!(
                ConntrackTuple::parse(&ipv4_packet(protocol, &transport))
                    .unwrap()
                    .transport,
                TransportTuple::Ports {
                    source: 40_000,
                    destination: 443,
                }
            );
        }
        assert_eq!(
            ConntrackTuple::parse(&ipv4_packet(47, &[1, 2, 3]))
                .unwrap()
                .transport,
            TransportTuple::None
        );
    }

    #[test]
    fn parses_complete_ipv4_options_before_the_transport_header() {
        let mut packet = vec![0_u8; 32];
        packet[0] = 0x46;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet[24..26].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[26..28].copy_from_slice(&443_u16.to_be_bytes());

        assert_eq!(
            ConntrackTuple::parse(&packet).unwrap().transport,
            TransportTuple::Ports {
                source: 40_000,
                destination: 443,
            }
        );
    }

    #[test]
    fn parses_icmpv4_and_rejects_wrong_family_icmpv6() {
        let mut icmp = ipv4_packet(IPPROTO_ICMP, &[8, 0, 0, 0, 0x12, 0x34, 0, 0]);
        assert_eq!(
            ConntrackTuple::parse(&icmp).unwrap().transport,
            TransportTuple::Icmp {
                id: 0x1234,
                kind: 8,
                code: 0,
            }
        );
        icmp[9] = IPPROTO_ICMPV6;
        assert_eq!(
            ConntrackTuple::parse(&icmp).unwrap().transport,
            TransportTuple::None
        );
    }

    #[test]
    fn rejects_malformed_ipv4_and_ipv6_headers() {
        assert!(ConntrackTuple::parse(&[]).is_none());
        assert!(ConntrackTuple::parse(&[0x45; 19]).is_none());

        let mut invalid_ihl = ipv4_udp_packet();
        invalid_ihl[0] = 0x44;
        assert!(ConntrackTuple::parse(&invalid_ihl).is_none());

        let mut options = ipv4_packet(IPPROTO_UDP, &[0; 8]);
        options[0] = 0x46;
        options.truncate(24);
        options[2..4].copy_from_slice(&24_u16.to_be_bytes());
        assert!(ConntrackTuple::parse(&options).is_none());

        let mut extension = ipv6_packet(0, &[17, 1, 0, 0]);
        assert!(ConntrackTuple::parse(&extension).is_none());
        extension = ipv6_packet(44, &[0; 8]);
        assert!(ConntrackTuple::parse(&extension).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn encodes_nested_tuple_zone_and_id() {
        let tuple = ConntrackTuple::parse(&ipv4_udp_packet()).unwrap();
        let encoded = encode_lookup_attributes(&tuple, CTA_TUPLE_ORIG, 32123, Some(0x12345678));
        let tuple_attr = find_attribute(&encoded, CTA_TUPLE_ORIG)
            .unwrap()
            .expect("tuple attribute");
        assert!(find_attribute(tuple_attr, CTA_TUPLE_IP).unwrap().is_some());
        assert!(
            find_attribute(tuple_attr, CTA_TUPLE_PROTO)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            find_attribute(&encoded, CTA_ZONE).unwrap(),
            Some(32123_u16.to_be_bytes().as_slice())
        );
        assert_eq!(
            find_attribute(&encoded, CTA_ID).unwrap(),
            Some(0x12345678_u32.to_be_bytes().as_slice())
        );
    }

    #[test]
    fn encodes_ipv6_icmp_attributes_without_zone_or_id_when_absent() {
        let tuple = ConntrackTuple {
            source: "fd00:64::1".parse().unwrap(),
            destination: "2001:db8::7".parse().unwrap(),
            protocol: IPPROTO_ICMPV6,
            transport: TransportTuple::Icmp {
                id: 9,
                kind: 128,
                code: 0,
            },
        };
        let encoded = encode_lookup_attributes(&tuple, CTA_TUPLE_REPLY, 0, None);
        let outer = find_attribute(&encoded, CTA_TUPLE_REPLY).unwrap().unwrap();
        let ip = find_attribute(outer, CTA_TUPLE_IP).unwrap().unwrap();
        assert_eq!(
            find_attribute(ip, CTA_IP_V6_SRC).unwrap().unwrap().len(),
            16
        );
        let protocol = find_attribute(outer, CTA_TUPLE_PROTO).unwrap().unwrap();
        assert_eq!(
            find_attribute(protocol, CTA_PROTO_ICMPV6_ID)
                .unwrap()
                .unwrap(),
            9_u16.to_be_bytes().as_slice()
        );
        assert!(find_attribute(&encoded, CTA_ZONE).unwrap().is_none());
        assert!(find_attribute(&encoded, CTA_ID).unwrap().is_none());
    }

    #[test]
    fn encodes_ipv4_icmp_and_unknown_protocol_attributes_without_port_fields() {
        let icmp = ConntrackTuple {
            source: "10.64.0.1".parse().unwrap(),
            destination: "198.51.100.7".parse().unwrap(),
            protocol: IPPROTO_ICMP,
            transport: TransportTuple::Icmp {
                id: 1234,
                kind: 8,
                code: 0,
            },
        };
        let encoded = encode_lookup_attributes(&icmp, CTA_TUPLE_ORIG, 0, None);
        let outer = find_attribute(&encoded, CTA_TUPLE_ORIG).unwrap().unwrap();
        let protocol = find_attribute(outer, CTA_TUPLE_PROTO).unwrap().unwrap();
        assert_eq!(
            find_attribute(protocol, CTA_PROTO_ICMP_ID)
                .unwrap()
                .unwrap(),
            1234_u16.to_be_bytes().as_slice()
        );
        assert!(
            find_attribute(protocol, CTA_PROTO_SRC_PORT)
                .unwrap()
                .is_none()
        );

        let unknown = ConntrackTuple {
            protocol: 47,
            transport: TransportTuple::None,
            ..icmp
        };
        let encoded = encode_lookup_attributes(&unknown, CTA_TUPLE_ORIG, 0, None);
        let outer = find_attribute(&encoded, CTA_TUPLE_ORIG).unwrap().unwrap();
        let protocol = find_attribute(outer, CTA_TUPLE_PROTO).unwrap().unwrap();
        assert!(
            find_attribute(protocol, CTA_PROTO_SRC_PORT)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_netlink_attributes_and_messages_are_rejected() {
        assert!(find_attribute(&[3, 0, 1, 0], 1).is_err());
        assert!(find_attribute(&[4, 0, 1], 1).is_err());
        assert_eq!(find_attribute(&[4, 0, 9, 0], 1).unwrap(), None);

        let mut valid = Vec::new();
        push_attr(&mut valid, 7, &[1, 2, 3]);
        assert_eq!(find_attribute(&valid, 7).unwrap(), Some(&[1, 2, 3][..]));
        assert_eq!(find_attribute(&valid, 8).unwrap(), None);

        let mut messages = NetlinkMessages::new(&[0; 15]);
        assert!(messages.next().unwrap().is_err());

        let mut invalid = vec![0_u8; 16];
        invalid[..4].copy_from_slice(&15_u32.to_ne_bytes());
        assert!(NetlinkMessages::new(&invalid).next().unwrap().is_err());

        let message = NetlinkMessage {
            kind: NLMSG_ERROR,
            sequence: 1,
            bytes: &[0; 16],
        };
        assert!(message.error().is_err());
        assert!(message.payload_after_nfgen().is_err());

        let mut valid_message = vec![0_u8; 24];
        valid_message[..4].copy_from_slice(&24_u32.to_ne_bytes());
        valid_message[4..6].copy_from_slice(&9_u16.to_ne_bytes());
        valid_message[8..12].copy_from_slice(&7_u32.to_ne_bytes());
        valid_message[16..20].copy_from_slice(&0_i32.to_ne_bytes());
        let mut messages = NetlinkMessages::new(&valid_message);
        let message = messages.next().unwrap().unwrap();
        assert_eq!(message.kind, 9);
        assert_eq!(message.sequence, 7);
        assert_eq!(message.error().unwrap(), 0);
        assert_eq!(message.payload_after_nfgen().unwrap(), &valid_message[20..]);
        assert!(messages.next().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conntrack_request_headers_and_error_conversions_are_stable() {
        let tuple = ConntrackTuple::parse(&ipv4_udp_packet()).unwrap();
        let attributes = encode_lookup_attributes(&tuple, CTA_TUPLE_ORIG, 0, None);
        let request = encode_request(IPCTNL_MSG_CT_GET, libc::AF_INET as u8, 11, attributes);
        assert_eq!(
            u32::from_ne_bytes(request[0..4].try_into().unwrap()),
            request.len() as u32
        );
        assert_eq!(
            u16::from_ne_bytes(request[4..6].try_into().unwrap()),
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
        );
        assert_eq!(
            u16::from_ne_bytes(request[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(u32::from_ne_bytes(request[8..12].try_into().unwrap()), 11);
        assert_eq!(request[16], libc::AF_INET as u8);

        assert!(matches!(
            NetlinkRequestError::Errno(libc::ENOENT).into_platform("delete"),
            PlatformError::Command(message) if message.contains("delete failed with errno")
        ));
        assert!(matches!(
            NetlinkRequestError::Platform(PlatformError::Permission).into_platform("query"),
            PlatformError::Permission
        ));
        assert!(matches!(
            NetlinkRequestError::Io(std::io::Error::other("socket"))
                .into_platform("query"),
            PlatformError::Command(message) if message.contains("ctnetlink: socket")
        ));
    }

    #[test]
    fn parses_ipv6_routing_and_authentication_headers() {
        // Routing header (43): one 8-byte segment, then an ICMPv6 echo request.
        let routing = ipv6_packet(
            43,
            &[
                IPPROTO_ICMPV6,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                128,
                0,
                0,
                0,
                0x04,
                0xd2,
                0,
                0,
            ],
        );
        assert_eq!(
            ConntrackTuple::parse(&routing).unwrap().transport,
            TransportTuple::Icmp {
                id: 1234,
                kind: 128,
                code: 0,
            }
        );

        // AH (51): payload length 0 means an 8-byte header.
        let auth = ipv6_packet(
            51,
            &[
                IPPROTO_ICMPV6,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                128,
                0,
                0,
                0,
                0x04,
                0xd2,
                0,
                0,
            ],
        );
        assert_eq!(
            ConntrackTuple::parse(&auth).unwrap().transport,
            TransportTuple::Icmp {
                id: 1234,
                kind: 128,
                code: 0,
            }
        );
    }

    #[test]
    fn rejects_ipv6_authentication_header_past_end_of_packet() {
        // AH payload length 255 would place the transport header far past the
        // end of the packet.
        let packet = ipv6_packet(51, &[IPPROTO_ICMPV6, 0xff, 0, 0, 0, 0, 0, 0]);
        assert!(ConntrackTuple::parse(&packet).is_none());
    }

    #[test]
    fn direct_conntrack_rejects_zero_zone() {
        let error = DirectConntrack::open(0)
            .err()
            .expect("zero zone is rejected");
        assert!(error.to_string().contains("must be non-zero"));
    }

    #[tokio::test]
    async fn direct_conntrack_without_worker_reports_stopped_errors() {
        let conntrack = DirectConntrack {
            zone: 1,
            worker: Arc::new(Worker {
                sender: Mutex::new(None),
                thread: Mutex::new(None),
            }),
        };
        let packet = ipv4_udp_packet();
        let key = conntrack.flow_key(&packet).expect("valid packet parses");
        assert_eq!(
            key,
            ConntrackFlowKey(ConntrackTuple::parse(&packet).unwrap())
        );
        assert!(conntrack.flow_key(&[]).is_none());

        let error = conntrack
            .delete_default(&[0xff, 0, 0, 0])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no deletable conntrack tuple"));

        let error = conntrack.delete_default(&packet).await.unwrap_err();
        assert!(error.to_string().contains("ctnetlink worker stopped"));
        let error = conntrack.delete_fallback(key).await.unwrap_err();
        assert!(error.to_string().contains("ctnetlink worker stopped"));
    }

    #[test]
    fn conntrack_tuple_family_matches_address_type() {
        let v4 = ConntrackTuple::parse(&ipv4_udp_packet()).unwrap();
        assert_eq!(v4.family(), libc::AF_INET as u8);
        let v6 = ConntrackTuple {
            source: "fd00:64::1".parse().unwrap(),
            destination: "2001:db8::7".parse().unwrap(),
            protocol: IPPROTO_UDP,
            transport: TransportTuple::Ports {
                source: 1,
                destination: 2,
            },
        };
        assert_eq!(v6.family(), libc::AF_INET6 as u8);
    }

    #[test]
    fn netlink_messages_align_trailing_message_padding() {
        // First message has a non-aligned length; the iterator must skip the
        // trailing padding and still surface the second message.
        let mut bytes = vec![0_u8; 17];
        bytes[..4].copy_from_slice(&17_u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&1_u16.to_ne_bytes());
        bytes[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        bytes.extend_from_slice(&[0_u8; 3]); // padding to a 4-byte boundary
        let second_offset = bytes.len();
        bytes.extend_from_slice(&[0_u8; 16]);
        bytes[second_offset..second_offset + 4].copy_from_slice(&16_u32.to_ne_bytes());
        bytes[second_offset + 4..second_offset + 6].copy_from_slice(&2_u16.to_ne_bytes());
        bytes[second_offset + 8..second_offset + 12].copy_from_slice(&2_u32.to_ne_bytes());

        let mut messages = NetlinkMessages::new(&bytes);
        let first = messages.next().unwrap().unwrap();
        assert_eq!(first.kind, 1);
        let second = messages.next().unwrap().unwrap();
        assert_eq!(second.kind, 2);
        assert!(messages.next().is_none());
    }

    #[test]
    fn rejects_truncated_ipv6_extension_headers() {
        // One byte of a Hop-by-Hop or Authentication header remains: the
        // two-byte header read fails before any length arithmetic.
        assert!(ConntrackTuple::parse(&ipv6_packet(0, &[IPPROTO_UDP])).is_none());
        assert!(ConntrackTuple::parse(&ipv6_packet(51, &[IPPROTO_UDP])).is_none());
    }

    #[test]
    fn rejects_truncated_icmp_transport_headers() {
        assert!(
            ConntrackTuple::parse(&ipv4_packet(IPPROTO_ICMP, &[8, 0, 0, 0, 0x12, 0x34, 0]))
                .is_none()
        );
        assert!(
            ConntrackTuple::parse(&ipv6_packet(IPPROTO_ICMPV6, &[128, 0, 0, 0, 0x04, 0xd2, 0]))
                .is_none()
        );
    }

    #[test]
    fn rejects_short_ipv6_and_unknown_version_packets() {
        assert!(ConntrackTuple::parse(&[0x60; 39]).is_none());
        assert!(ConntrackTuple::parse(&[0x55; 20]).is_none());
    }

    #[test]
    fn parses_up_to_eight_chained_ipv6_extension_headers() {
        // Eight Hop-by-Hop headers, the last pointing at UDP.
        let mut payload = Vec::new();
        for index in 0..8 {
            let next = if index == 7 { IPPROTO_UDP } else { 0 };
            payload.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
        }
        payload.extend_from_slice(&40000_u16.to_be_bytes());
        payload.extend_from_slice(&443_u16.to_be_bytes());
        payload.extend_from_slice(&[0; 4]);
        assert_eq!(
            ConntrackTuple::parse(&ipv6_packet(0, &payload))
                .unwrap()
                .transport,
            TransportTuple::Ports {
                source: 40000,
                destination: 443,
            }
        );

        // A ninth chained header exceeds the extension walk bound; the tuple
        // is still returned with an opaque transport.
        let mut payload = vec![0_u8; 9 * 8];
        payload.extend_from_slice(&40000_u16.to_be_bytes());
        payload.extend_from_slice(&443_u16.to_be_bytes());
        assert_eq!(
            ConntrackTuple::parse(&ipv6_packet(0, &payload))
                .unwrap()
                .transport,
            TransportTuple::None
        );
    }

    #[test]
    fn rejects_oversized_netlink_attribute_and_message_lengths() {
        // Attribute claims more bytes than remain in the buffer.
        assert!(find_attribute(&[8, 0, 1, 0, 0, 0], 1).is_err());

        // Message claims more bytes than remain in the buffer.
        let mut oversized = vec![0_u8; 16];
        oversized[..4].copy_from_slice(&32_u32.to_ne_bytes());
        assert!(NetlinkMessages::new(&oversized).next().unwrap().is_err());
    }

    #[test]
    fn worker_drop_closes_channel_and_joins_thread() {
        let (sender, mut receiver) = mpsc::channel::<WorkerRequest>(1);
        let thread = std::thread::spawn(move || while receiver.blocking_recv().is_some() {});
        let worker = Worker {
            sender: Mutex::new(Some(sender)),
            thread: Mutex::new(Some(thread)),
        };
        // Dropping the worker closes the channel, letting the thread exit so
        // the join completes.
        drop(worker);
    }

    #[tokio::test]
    async fn delete_reports_worker_stopped_when_queue_is_closed() {
        let (sender, receiver) = mpsc::channel(WORK_QUEUE_CAPACITY);
        drop(receiver);
        let conntrack = DirectConntrack {
            zone: 1,
            worker: Arc::new(Worker {
                sender: Mutex::new(Some(sender)),
                thread: Mutex::new(None),
            }),
        };
        let key = conntrack.flow_key(&ipv4_udp_packet()).unwrap();
        let error = conntrack.delete_fallback(key).await.unwrap_err();
        assert!(error.to_string().contains("ctnetlink worker stopped"));
    }

    #[tokio::test]
    async fn delete_reports_worker_stopped_when_response_is_dropped() {
        let (sender, mut receiver) = mpsc::channel(WORK_QUEUE_CAPACITY);
        let conntrack = DirectConntrack {
            zone: 1,
            worker: Arc::new(Worker {
                sender: Mutex::new(Some(sender)),
                thread: Mutex::new(None),
            }),
        };
        // A worker that accepts requests but never answers drops the oneshot
        // sender, which must surface as a stopped-worker error.
        let drainer = tokio::spawn(async move { while receiver.recv().await.is_some() {} });
        let key = conntrack.flow_key(&ipv4_udp_packet()).unwrap();
        let error = conntrack.delete_fallback(key).await.unwrap_err();
        assert!(error.to_string().contains("ctnetlink worker stopped"));
        drop(conntrack);
        drainer.await.unwrap();
    }

    #[tokio::test]
    async fn delete_reports_lock_poisoned() {
        let conntrack = DirectConntrack {
            zone: 1,
            worker: Arc::new(Worker {
                sender: Mutex::new(None),
                thread: Mutex::new(None),
            }),
        };
        let worker = conntrack.worker.clone();
        let _ = std::thread::spawn(move || {
            let _guard = worker.sender.lock().unwrap();
            panic!("poison the sender mutex for the test");
        })
        .join();
        let key = conntrack.flow_key(&ipv4_udp_packet()).unwrap();
        let error = conntrack.delete_fallback(key).await.unwrap_err();
        assert!(error.to_string().contains("lock poisoned"));
        // Clear the poison so the worker's Drop does not panic on the
        // deliberately poisoned mutex.
        conntrack.worker.sender.clear_poison();
    }

    #[tokio::test]
    async fn direct_conntrack_worker_opens_flushes_and_deletes_idempotently() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let conntrack = DirectConntrack::open(32124).unwrap();
        let key = conntrack.delete_default(&ipv4_udp_packet()).await.unwrap();
        assert_eq!(key, conntrack.flow_key(&ipv4_udp_packet()).unwrap());
        conntrack.delete_fallback(key).await.unwrap();

        let mut socket = ConntrackSocket::open().unwrap();
        assert_eq!(socket.next_sequence(), 1);
        socket.sequence = u32::MAX;
        assert_eq!(socket.next_sequence(), 1);
        assert_eq!(socket.next_sequence(), 2);
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_platform_tests {
    use super::*;

    fn ipv4_udp_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet
    }

    #[test]
    fn open_rejects_zero_zone_and_unsupported_platform() {
        let error = DirectConntrack::open(0)
            .err()
            .expect("zero zone is rejected");
        assert!(error.to_string().contains("must be non-zero"));
        assert!(matches!(
            DirectConntrack::open(1),
            Err(PlatformError::Unsupported(os)) if os == std::env::consts::OS
        ));
    }

    #[tokio::test]
    async fn delete_reports_unsupported_platform() {
        let conntrack = DirectConntrack { zone: 7 };
        let packet = ipv4_udp_packet();
        let key = conntrack.flow_key(&packet).expect("valid packet parses");

        let error = conntrack
            .delete_default(&[0xff, 0, 0, 0])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no deletable conntrack tuple"));

        assert!(matches!(
            conntrack.delete_default(&packet).await,
            Err(PlatformError::Unsupported(_))
        ));
        assert!(matches!(
            conntrack.delete_fallback(key).await,
            Err(PlatformError::Unsupported(_))
        ));
    }
}
