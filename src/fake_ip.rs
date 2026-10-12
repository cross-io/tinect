//! Source-side FakeIP DNS and target-address translation.

use crate::{
    config::{DnsServer, FakeIpConfig},
    observability::Observability,
    route_sets::{RouteSetRegistry, SetId},
    runtime::TaskGroup,
};
use anyhow::{Context, Result, anyhow};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use ipnet::IpNet;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Notify, OwnedMutexGuard, Semaphore, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

mod packet;
#[cfg(test)]
use packet::checksum;
use packet::{FlowDirection, allocate, flow_ids, packet_addresses, rewrite_addresses};

type DnsQueryKey = (String, u16);
type InflightDns = Arc<Mutex<HashMap<DnsQueryKey, Arc<tokio::sync::Mutex<()>>>>>;

/// Registers one participant in an identical-query single-flight group.
///
/// The map owns one strong reference and each participant owns another. A
/// participant removes the entry only when no lock future, acquired guard, or
/// other participant still references it. This makes cancellation cleanup
/// automatic without letting a late query create a second lock while an
/// earlier waiter is still active.
struct InflightQuery {
    queries: InflightDns,
    key: DnsQueryKey,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl InflightQuery {
    fn register(queries: &InflightDns, key: DnsQueryKey) -> Self {
        let lock = queries
            .lock()
            .expect("FakeIP in-flight query lock")
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        Self {
            queries: queries.clone(),
            key,
            lock,
        }
    }

    async fn acquire(&self) -> OwnedMutexGuard<()> {
        self.lock.clone().lock_owned().await
    }
}

impl Drop for InflightQuery {
    fn drop(&mut self) {
        let mut queries = self.queries.lock().expect("FakeIP in-flight query lock");
        if queries
            .get(&self.key)
            .is_some_and(|lock| Arc::ptr_eq(lock, &self.lock))
            && Arc::strong_count(&self.lock) == 2
        {
            queries.remove(&self.key);
        }
    }
}

/// Encrypted payload marker for FakeIP metadata.
///
/// An IP packet starts with version nibble 4 or 6, so zero cannot be the
/// first byte of an ordinary inner packet.  The following byte is the address
/// length (4 or 16), followed by the FakeIP destination itself.  This header
/// is inside the authenticated data session and is therefore invisible to
/// relays and intermediate nodes.
pub const FAKE_IP_ENVELOPE_TAG: u8 = 0;

pub fn fake_ip_envelope_len(fake_destination: IpAddr) -> usize {
    2 + if fake_destination.is_ipv4() { 4 } else { 16 }
}

/// Maximum per-packet overhead reserved by the FakeIP envelope.
///
/// The TUN MTU is shared by ordinary and FakeIP traffic, so a node with
/// domain routes must reserve the largest enabled address form globally.
pub fn max_fake_ip_envelope_len(disable_ipv6: bool) -> usize {
    if disable_ipv6 {
        fake_ip_envelope_len(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    } else {
        fake_ip_envelope_len(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }
}

pub fn encode_fake_ip_envelope(packet: &[u8], fake_destination: IpAddr) -> Vec<u8> {
    let address = match fake_destination {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let mut payload = Vec::with_capacity(2 + address.len() + packet.len());
    payload.push(FAKE_IP_ENVELOPE_TAG);
    payload.push(u8::try_from(address.len()).expect("IP address length fits in u8"));
    payload.extend_from_slice(&address);
    payload.extend_from_slice(packet);
    payload
}

pub fn decode_fake_ip_envelope(packet: &mut Vec<u8>) -> Result<Option<IpAddr>, &'static str> {
    if packet.first().copied() != Some(FAKE_IP_ENVELOPE_TAG) {
        return Ok(None);
    }
    let address_len = usize::from(*packet.get(1).ok_or("truncated FakeIP envelope")?);
    let end = 2 + address_len;
    let address = packet
        .get(2..end)
        .ok_or("truncated FakeIP envelope address")?;
    let fake_destination = match address_len {
        4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(address).expect("validated IPv4 address length"),
        )),
        16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(address).expect("validated IPv6 address length"),
        )),
        _ => return Err("invalid FakeIP envelope address length"),
    };
    packet.drain(..end);
    Ok(Some(fake_destination))
}

#[derive(Debug, Clone)]
struct Mapping {
    domain: String,
    preferred_route: Option<RoutePreference>,
    real: Vec<IpAddr>,
    expires: Instant,
    next_real: usize,
}

#[derive(Debug, Clone)]
struct CachedDns {
    response: Message,
    preferred_route: Option<RoutePreference>,
    expires: Instant,
}

#[derive(Debug, Clone)]
struct SourceFlow {
    original_source: IpAddr,
    wire_source: IpAddr,
    fake_destination: IpAddr,
    real_destination: IpAddr,
    original_local_id: u16,
    wire_local_id: u16,
    expires: Instant,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct SourceFlowKey {
    source: IpAddr,
    fake_destination: IpAddr,
    wire_source: IpAddr,
    protocol: u8,
    local_id: u16,
    remote_id: u16,
}

#[derive(Debug, Clone, Copy)]
enum OutboundWireSource {
    NodeAddress,
    DirectFakeAddress,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct WireFlowKey {
    real_destination: IpAddr,
    local_source: IpAddr,
    protocol: u8,
    remote_id: u16,
    local_id: u16,
}

#[derive(Debug, Default)]
struct State {
    by_name: HashMap<(String, bool), IpAddr>,
    mappings: HashMap<IpAddr, Mapping>,
    source_flows: HashMap<SourceFlowKey, SourceFlow>,
    wire_flows: HashMap<WireFlowKey, SourceFlowKey>,
    next_fake_v4: u128,
    next_fake_v6: u128,
    next_flow_id: u16,
    dns_cache: HashMap<DnsQueryKey, CachedDns>,
    last_prune: Option<Instant>,
}

const FLOW_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CONCURRENT_DNS_TASKS: usize = 256;
const DNS_TCP_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TCP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

async fn join_dns_listeners(
    mut listeners: TaskGroup<Result<()>>,
    cancellation: CancellationToken,
) -> Result<()> {
    let first = tokio::select! {
        result = listeners.join_next() => result,
        _ = cancellation.cancelled() => None,
    };
    listeners.cancel();

    let mut first_error = match first {
        Some(Ok(result)) => result.err(),
        Some(Err(error)) => Some(anyhow!("FakeIP DNS listener task failed: {error}")),
        None => None,
    };
    while let Some(result) = listeners.join_next().await {
        let error = match result {
            Ok(result) => result.err(),
            Err(error) => Some(anyhow!("FakeIP DNS listener task failed: {error}")),
        };
        if first_error.is_none() {
            first_error = error;
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[derive(Clone)]
pub struct FakeIpRuntime {
    config: FakeIpConfig,
    registry: Arc<RouteSetRegistry>,
    domain_sites: Arc<Vec<SetId>>,
    local_addresses: Arc<Vec<IpAddr>>,
    state: Arc<Mutex<State>>,
    metrics: Arc<Observability>,
    inflight: InflightDns,
    overlay_dns: Arc<Mutex<Option<mpsc::Sender<OverlayDnsRequest>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRouteHint {
    pub domain: String,
    pub preferred_route: Option<RoutePreference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutePreference {
    Exit(String),
    Direct,
}

pub struct OverlayDnsRequest {
    pub domain: String,
    pub wire: Vec<u8>,
    pub upstreams: Vec<DnsServer>,
    pub response: oneshot::Sender<Result<OverlayDnsResponse, String>>,
}

pub struct OverlayDnsResponse {
    pub wire: Vec<u8>,
    pub preferred_route: RoutePreference,
}

impl FakeIpRuntime {
    pub fn new(
        config: FakeIpConfig,
        registry: Arc<RouteSetRegistry>,
        domain_sites: Vec<SetId>,
        local_addresses: Vec<IpAddr>,
        metrics: Arc<Observability>,
    ) -> Self {
        Self {
            config,
            registry,
            domain_sites: Arc::new(domain_sites),
            local_addresses: Arc::new(local_addresses),
            state: Arc::new(Mutex::new(State::default())),
            metrics,
            inflight: Arc::new(Mutex::new(HashMap::new())),
            overlay_dns: Arc::new(Mutex::new(None)),
        }
    }

    pub fn install_overlay_dns(&self, sender: mpsc::Sender<OverlayDnsRequest>) {
        *self.overlay_dns.lock().expect("FakeIP overlay DNS lock") = Some(sender);
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        self.domain_sites.iter().any(|id| {
            self.registry
                .site(*id)
                .is_some_and(|set| set.matches_domain(domain))
        })
    }

    pub fn route_hint_for_fake(&self, address: IpAddr) -> Option<FakeRouteHint> {
        let mut state = self.state.lock().expect("FakeIP state lock");
        let now = Instant::now();
        let mapping = state.mappings.get_mut(&address)?;
        if mapping.expires <= now {
            return None;
        }
        mapping.expires = now + self.max_ttl();
        Some(FakeRouteHint {
            domain: mapping.domain.clone(),
            preferred_route: mapping.preferred_route.clone(),
        })
    }

    pub fn fake_prefixes(&self) -> Vec<IpNet> {
        let mut result = vec![self.config.ipv4_pool];
        if !self.config.disable_ipv6 {
            result.push(self.config.ipv6_pool);
        }
        result
    }

    pub fn max_envelope_len(&self) -> usize {
        max_fake_ip_envelope_len(self.config.disable_ipv6)
    }

    pub fn is_fake_destination(&self, packet: &[u8]) -> bool {
        packet_addresses(packet)
            .is_some_and(|(_, destination)| self.contains_fake_address(destination))
    }

    pub fn contains_fake_address(&self, address: IpAddr) -> bool {
        self.config.ipv4_pool.contains(&address)
            || (!self.config.disable_ipv6 && self.config.ipv6_pool.contains(&address))
    }

    pub fn translate_outbound(&self, packet: &mut [u8]) -> bool {
        self.translate_outbound_with_source(packet, OutboundWireSource::NodeAddress)
    }

    /// Translate a FakeIP packet for the local direct path.
    ///
    /// The FakeIP source is only a node-local NAT return anchor. The direct
    /// POSTROUTING rule masquerades the packet before it reaches the
    /// underlay, so neither this address nor the FakeIP destination is used
    /// by a remote node or path selector.
    pub fn translate_outbound_direct(&self, packet: &mut [u8]) -> bool {
        self.translate_outbound_with_source(packet, OutboundWireSource::DirectFakeAddress)
    }

    fn translate_outbound_with_source(
        &self,
        packet: &mut [u8],
        source_mode: OutboundWireSource,
    ) -> bool {
        let Some((source, fake)) = packet_addresses(packet) else {
            return false;
        };
        let Some(ids) = flow_ids(packet, FlowDirection::Forward) else {
            return false;
        };
        let now = Instant::now();
        let mut state = self.state.lock().expect("FakeIP state lock");
        let force_prune = state.source_flows.len() >= self.config.max_entries;
        prune_if_due(&mut state, now, force_prune);
        let Some(mapping) = state.mappings.get_mut(&fake) else {
            return false;
        };
        if mapping.expires <= now || mapping.real.is_empty() {
            return false;
        }
        mapping.expires = now + self.max_ttl();
        let mut real = mapping.real[mapping.next_real % mapping.real.len()];
        let wire_source = match source_mode {
            OutboundWireSource::NodeAddress => self
                .local_addresses
                .iter()
                .copied()
                .find(|address| address.is_ipv4() == source.is_ipv4()),
            OutboundWireSource::DirectFakeAddress => Some(fake),
        };
        let Some(mut wire_source) = wire_source else {
            return false;
        };
        if source.is_ipv4() != real.is_ipv4() {
            return false;
        }
        let key = SourceFlowKey {
            source,
            fake_destination: fake,
            wire_source,
            protocol: ids.protocol,
            local_id: ids.local,
            remote_id: ids.remote,
        };
        if state
            .source_flows
            .get(&key)
            .is_some_and(|flow| flow.expires <= now)
            && let Some(flow) = state.source_flows.remove(&key)
        {
            state.wire_flows.remove(&WireFlowKey {
                real_destination: flow.real_destination,
                local_source: flow.wire_source,
                protocol: key.protocol,
                remote_id: key.remote_id,
                local_id: flow.wire_local_id,
            });
        }
        let wire_local_id;
        if let Some(flow) = state.source_flows.get_mut(&key) {
            flow.expires = now + self.max_ttl();
            real = flow.real_destination;
            wire_source = flow.wire_source;
            wire_local_id = flow.wire_local_id;
        } else {
            if let Some(mapping) = state.mappings.get_mut(&fake) {
                mapping.next_real = mapping.next_real.wrapping_add(1);
            }
            if state.source_flows.len() >= self.config.max_entries {
                return false;
            }
            let base = WireFlowKey {
                real_destination: real,
                local_source: wire_source,
                protocol: ids.protocol,
                remote_id: ids.remote,
                local_id: ids.local,
            };
            wire_local_id = if !state.wire_flows.contains_key(&base) {
                ids.local
            } else if ids.field_offset.is_some() {
                let mut allocated = None;
                for _ in 0..u16::MAX {
                    state.next_flow_id = state.next_flow_id.wrapping_add(1).max(1);
                    let candidate = WireFlowKey {
                        local_id: state.next_flow_id,
                        ..base
                    };
                    if !state.wire_flows.contains_key(&candidate) {
                        allocated = Some(state.next_flow_id);
                        break;
                    }
                }
                let Some(allocated) = allocated else {
                    return false;
                };
                allocated
            } else {
                return false;
            };
            state.wire_flows.insert(
                WireFlowKey {
                    local_id: wire_local_id,
                    ..base
                },
                key,
            );
            state.source_flows.insert(
                key,
                SourceFlow {
                    original_source: source,
                    wire_source,
                    fake_destination: fake,
                    real_destination: real,
                    original_local_id: ids.local,
                    wire_local_id,
                    expires: now + self.max_ttl(),
                },
            );
        }
        let pool_usage = (state.mappings.len(), state.source_flows.len());
        drop(state);
        self.metrics.fake_ip_pool_usage(pool_usage.0, pool_usage.1);
        if wire_local_id != ids.local {
            ids.rewrite(packet, wire_local_id);
        }
        rewrite_addresses(packet, source, fake, wire_source, real)
    }

    pub fn translate_inbound(
        &self,
        packet: &mut [u8],
        metadata_fake_destination: Option<IpAddr>,
    ) -> bool {
        let Some((real_source, local_destination)) = packet_addresses(packet) else {
            return false;
        };
        let Some(ids) = flow_ids(packet, FlowDirection::Return) else {
            return false;
        };
        let now = Instant::now();
        let mut state = self.state.lock().expect("FakeIP state lock");
        prune_if_due(&mut state, now, false);
        let wire = WireFlowKey {
            real_destination: real_source,
            local_source: local_destination,
            protocol: ids.protocol,
            remote_id: ids.remote,
            local_id: ids.local,
        };
        let Some(source_key) = state.wire_flows.get(&wire).copied() else {
            return false;
        };
        if state
            .source_flows
            .get(&source_key)
            .is_none_or(|flow| flow.expires <= now)
        {
            state.source_flows.remove(&source_key);
            state.wire_flows.remove(&wire);
            return false;
        }
        let Some(flow) = state.source_flows.get_mut(&source_key) else {
            return false;
        };
        if metadata_fake_destination.is_some_and(|fake| fake != flow.fake_destination) {
            return false;
        }
        flow.expires = now + self.max_ttl();
        let original_source = flow.original_source;
        let original_local_id = flow.original_local_id;
        let fake = flow.fake_destination;
        if ids.local != original_local_id {
            ids.rewrite(packet, original_local_id);
        }
        rewrite_addresses(
            packet,
            real_source,
            local_destination,
            fake,
            original_source,
        )
    }

    pub async fn bind(&self) -> Result<(UdpSocket, TcpListener)> {
        let udp = UdpSocket::bind(self.config.listen).await?;
        let tcp = TcpListener::bind(self.config.listen).await?;
        Ok((udp, tcp))
    }

    pub async fn serve_bound(
        self: Arc<Self>,
        udp: UdpSocket,
        tcp: TcpListener,
        cancellation: CancellationToken,
    ) -> Result<()> {
        let mut listeners = TaskGroup::<Result<()>>::new();
        let listener_cancellation = listeners.token();
        let udp = Arc::new(udp);
        let udp_runtime = self.clone();
        let udp_cancel = listener_cancellation.clone();
        let dns_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_TASKS));
        let udp_limit = dns_limit.clone();
        listeners.spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (size, peer) = tokio::select! {
                    _ = udp_cancel.cancelled() => {
                        while tasks.join_next().await.is_some() {}
                        return Ok::<(), anyhow::Error>(());
                    }
                    completed = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(error)) = completed {
                            tracing::debug!(%error, "FakeIP DNS UDP request task failed");
                        }
                        continue;
                    }
                    result = udp.recv_from(&mut buffer) => result?,
                };
                let request = buffer[..size].to_vec();
                let socket = udp.clone();
                let runtime = udp_runtime.clone();
                let cancellation = udp_cancel.clone();
                let Ok(permit) = udp_limit.clone().try_acquire_owned() else {
                    tracing::debug!("dropping FakeIP DNS UDP request at concurrency limit");
                    continue;
                };
                tasks.spawn(async move {
                    let _permit = permit;
                    tokio::select! {
                        _ = cancellation.cancelled() => {}
                        result = runtime.answer(&request) => {
                            if let Ok(response) = result {
                                let _ = socket.send_to(&response, peer).await;
                            }
                        }
                    }
                });
            }
        });
        let tcp_runtime = self.clone();
        let tcp_cancel = listener_cancellation.clone();
        let tcp_limit = dns_limit;
        listeners.spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = tokio::select! {
                    _ = tcp_cancel.cancelled() => {
                        while tasks.join_next().await.is_some() {}
                        return Ok::<(), anyhow::Error>(());
                    }
                    completed = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(error)) = completed {
                            tracing::debug!(%error, "FakeIP DNS TCP connection task failed");
                        }
                        continue;
                    }
                    result = tcp.accept() => result?,
                };
                let runtime = tcp_runtime.clone();
                let cancellation = tcp_cancel.clone();
                let Ok(permit) = tcp_limit.clone().try_acquire_owned() else {
                    tracing::debug!("dropping FakeIP DNS TCP connection at concurrency limit");
                    continue;
                };
                tasks.spawn(async move {
                    let _permit = permit;
                    tokio::select! {
                        _ = cancellation.cancelled() => {}
                        result = runtime.serve_tcp(stream) => {
                            let _ = result;
                        }
                    }
                });
            }
        });
        join_dns_listeners(listeners, cancellation).await
    }

    async fn serve_tcp(&self, mut stream: TcpStream) -> Result<()> {
        self.serve_tcp_with_timeouts(
            &mut stream,
            DNS_TCP_FRAME_READ_TIMEOUT,
            DNS_TCP_RESPONSE_TIMEOUT,
        )
        .await
    }

    async fn serve_tcp_with_timeouts(
        &self,
        stream: &mut TcpStream,
        frame_read_timeout: Duration,
        response_timeout: Duration,
    ) -> Result<()> {
        loop {
            let frame = tokio::time::timeout(frame_read_timeout, async {
                let length = stream.read_u16().await?;
                let mut request = vec![0u8; usize::from(length)];
                stream.read_exact(&mut request).await?;
                Ok::<_, std::io::Error>(request)
            })
            .await
            .context("FakeIP TCP DNS frame read timeout")?;
            let request = match frame {
                Ok(request) => request,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            tokio::time::timeout(response_timeout, async {
                let response = self.answer(&request).await?;
                stream.write_u16(u16::try_from(response.len())?).await?;
                stream.write_all(&response).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("FakeIP TCP DNS response timeout")??;
        }
    }

    async fn answer(&self, wire: &[u8]) -> Result<Vec<u8>> {
        let request = Message::from_vec(wire)?;
        let Some(query) = request.queries.first() else {
            return Ok(Message::error_msg(
                request.metadata.id,
                request.metadata.op_code,
                ResponseCode::FormErr,
            )
            .to_vec()?);
        };
        let domain = query
            .name
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let matched = self.matches_domain(&domain);
        self.metrics.fake_ip_dns_query(matched);
        let qtype = query.query_type;
        if self.config.disable_ipv6
            && matches!(
                qtype,
                RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
            )
            || matched
                && matches!(
                    qtype,
                    RecordType::HTTPS | RecordType::SVCB | RecordType::ANY
                )
        {
            return self.nodata(&request);
        }
        let query_key = (domain.clone(), u16::from(qtype));
        let inflight_query = InflightQuery::register(&self.inflight, query_key.clone());
        let _query_guard = inflight_query.acquire().await;
        let (mut upstream, preferred_route, fetched) = if let Some(cached) =
            self.cached_dns(&query_key, request.metadata.id)
        {
            (cached.0, cached.1, false)
        } else {
            let resolved = if matched {
                self.forward_overlay(&domain, wire).await
            } else {
                self.forward(wire).await.map(|response| (response, None))
            };
            match resolved {
                Ok((response, preferred_route)) => (response, preferred_route, true),
                Err(error) => {
                    self.metrics.fake_ip_dns_failure();
                    tracing::debug!(%error, %domain, ?qtype, "FakeIP upstream DNS query failed");
                    let mut response = Message::error_msg(
                        request.metadata.id,
                        request.metadata.op_code,
                        ResponseCode::ServFail,
                    );
                    response.queries = request.queries.clone();
                    return Ok(response.to_vec()?);
                }
            }
        };
        if self.config.disable_ipv6 {
            strip_ipv6_hints(&mut upstream);
        }
        clamp_ttls(
            &mut upstream,
            self.config.min_cache_ttl_secs,
            self.config.max_cache_ttl_secs,
        );
        if fetched {
            self.cache_dns(query_key.clone(), &upstream, preferred_route.clone());
        }
        if !matched || !matches!(qtype, RecordType::A | RecordType::AAAA) {
            return Ok(upstream.to_vec()?);
        }
        if upstream.metadata.response_code != ResponseCode::NoError {
            return Ok(upstream.to_vec()?);
        }
        let real = upstream
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(value) if qtype == RecordType::A => Some(IpAddr::V4(value.0)),
                RData::AAAA(value) if qtype == RecordType::AAAA => Some(IpAddr::V6(value.0)),
                _ => None,
            })
            .collect::<Vec<_>>();
        if real.is_empty() {
            return Ok(upstream.to_vec()?);
        }
        let Some(fake) =
            self.allocate_fake(&domain, qtype == RecordType::AAAA, real, preferred_route)
        else {
            self.metrics.fake_ip_dns_failure();
            let mut response = Message::error_msg(
                request.metadata.id,
                request.metadata.op_code,
                ResponseCode::ServFail,
            );
            response.queries = request.queries.clone();
            return Ok(response.to_vec()?);
        };
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.queries = request.queries.clone();
        let ttl = upstream
            .answers
            .iter()
            .filter(|record| record.record_type() == qtype)
            .map(|record| record.ttl)
            .min()
            .unwrap_or(self.config.min_cache_ttl_secs)
            .clamp(
                self.config.min_cache_ttl_secs,
                self.config.max_cache_ttl_secs,
            )
            .max(1);
        let data = match fake {
            IpAddr::V4(value) => RData::A(A(value)),
            IpAddr::V6(value) => RData::AAAA(AAAA(value)),
        };
        response
            .answers
            .push(Record::from_rdata(query.name.clone(), ttl, data));
        Ok(response.to_vec()?)
    }

    fn nodata(&self, request: &Message) -> Result<Vec<u8>> {
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.queries = request.queries.clone();
        Ok(response.to_vec()?)
    }

    fn allocate_fake(
        &self,
        domain: &str,
        ipv6: bool,
        real: Vec<IpAddr>,
        preferred_route: Option<RoutePreference>,
    ) -> Option<IpAddr> {
        let now = Instant::now();
        let mut state = self.state.lock().expect("FakeIP state lock");
        let force_prune = state.mappings.len() >= self.config.max_entries;
        prune_if_due(&mut state, now, force_prune);
        let key = (domain.to_owned(), ipv6);
        if let Some(fake) = state.by_name.get(&key).copied()
            && let Some(mapping) = state.mappings.get_mut(&fake)
            && mapping.expires > now
        {
            mapping.real = real;
            mapping.preferred_route = preferred_route;
            mapping.expires = now + self.max_ttl();
            return Some(fake);
        }
        if state.mappings.len() >= self.config.max_entries {
            return None;
        }
        let pool = if ipv6 {
            self.config.ipv6_pool
        } else {
            self.config.ipv4_pool
        };
        let mut next = if ipv6 {
            state.next_fake_v6
        } else {
            state.next_fake_v4
        };
        let fake = allocate(pool, &mut next, |candidate| {
            state.mappings.contains_key(&candidate)
        })?;
        if ipv6 {
            state.next_fake_v6 = next;
        } else {
            state.next_fake_v4 = next;
        }
        state.by_name.insert(key, fake);
        state.mappings.insert(
            fake,
            Mapping {
                domain: domain.to_owned(),
                preferred_route,
                real,
                expires: now + self.max_ttl(),
                next_real: 0,
            },
        );
        let pool_usage = (state.mappings.len(), state.source_flows.len());
        drop(state);
        self.metrics.fake_ip_pool_usage(pool_usage.0, pool_usage.1);
        Some(fake)
    }

    async fn forward(&self, wire: &[u8]) -> Result<Message> {
        let mut errors = Vec::new();
        for server in &self.config.upstream_dns {
            match query_upstream(server, wire).await {
                Ok(response) => return Ok(response),
                Err(error) => errors.push(error.to_string()),
            }
        }
        Err(anyhow!(
            "all FakeIP upstream DNS servers failed: {}",
            errors.join(" | ")
        ))
    }

    async fn forward_overlay(
        &self,
        domain: &str,
        wire: &[u8],
    ) -> Result<(Message, Option<RoutePreference>)> {
        let sender = self
            .overlay_dns
            .lock()
            .expect("FakeIP overlay DNS lock")
            .clone()
            .ok_or_else(|| anyhow!("FakeIP overlay DNS resolver is not ready"))?;
        let (response_tx, response_rx) = oneshot::channel();
        sender
            .send(OverlayDnsRequest {
                domain: domain.to_owned(),
                wire: wire.to_vec(),
                upstreams: self.config.upstream_dns.clone(),
                response: response_tx,
            })
            .await
            .map_err(|_| anyhow!("FakeIP overlay DNS resolver stopped"))?;
        let response = response_rx
            .await
            .map_err(|_| anyhow!("FakeIP overlay DNS response was canceled"))?
            .map_err(anyhow::Error::msg)?;
        let message = Message::from_vec(&response.wire)?;
        validate_dns_response(wire, &message)?;
        Ok((message, Some(response.preferred_route)))
    }

    fn max_ttl(&self) -> Duration {
        Duration::from_secs(u64::from(self.config.max_cache_ttl_secs))
    }

    fn cached_dns(
        &self,
        key: &DnsQueryKey,
        request_id: u16,
    ) -> Option<(Message, Option<RoutePreference>)> {
        let mut state = self.state.lock().expect("FakeIP state lock");
        let cached = state.dns_cache.get(key)?;
        if cached.expires <= Instant::now() {
            state.dns_cache.remove(key);
            return None;
        }
        let mut response = cached.response.clone();
        response.metadata.id = request_id;
        Some((response, cached.preferred_route.clone()))
    }

    fn cache_dns(
        &self,
        key: DnsQueryKey,
        response: &Message,
        preferred_route: Option<RoutePreference>,
    ) {
        let ttl = response
            .answers
            .iter()
            .chain(&response.authorities)
            .filter(|record| record.record_type() != RecordType::OPT)
            .map(|record| record.ttl)
            .min()
            .unwrap_or(self.config.min_cache_ttl_secs)
            .clamp(
                self.config.min_cache_ttl_secs,
                self.config.max_cache_ttl_secs,
            );
        let now = Instant::now();
        let mut state = self.state.lock().expect("FakeIP state lock");
        let new_entry = !state.dns_cache.contains_key(&key);
        if new_entry && state.dns_cache.len() >= self.config.max_entries {
            state.dns_cache.retain(|_, cached| cached.expires > now);
            if state.dns_cache.len() >= self.config.max_entries
                && let Some(evicted) = state.dns_cache.keys().next().cloned()
            {
                state.dns_cache.remove(&evicted);
            }
        }
        state.dns_cache.insert(
            key,
            CachedDns {
                response: response.clone(),
                preferred_route,
                expires: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }
}

pub(crate) async fn query_upstream(server: &DnsServer, wire: &[u8]) -> Result<Message> {
    match forward_udp(server, wire, upstream_udp_pool()).await {
        Ok(response) if !response.metadata.truncation => Ok(response),
        Ok(_) => forward_tcp(server, wire).await,
        Err(error) => Err(error),
    }
}

const MAX_UPSTREAM_UDP_SOCKETS: usize = 4;

/// A small process-local pool of connected UDP sockets. Each socket is
/// serialized while a request is in flight, which preserves the response
/// matching guarantees of the original one-socket-per-query implementation;
/// multiple slots still allow concurrent upstream queries.
#[derive(Default)]
struct UdpSocketPool {
    slots: tokio::sync::Mutex<HashMap<SocketAddr, Vec<UdpSocketSlot>>>,
    available: Arc<Notify>,
}

struct UdpSocketSlot {
    socket: Arc<tokio::sync::Mutex<UdpSocket>>,
    gate: Arc<tokio::sync::Mutex<()>>,
    next_id: Arc<AtomicU32>,
}

struct UdpSocketLease {
    socket: Arc<tokio::sync::Mutex<UdpSocket>>,
    next_id: Arc<AtomicU32>,
    _gate: OwnedMutexGuard<()>,
    available: Arc<Notify>,
}

impl Drop for UdpSocketLease {
    fn drop(&mut self) {
        self.available.notify_one();
    }
}

impl UdpSocketPool {
    async fn acquire(&self, server: SocketAddr) -> Result<UdpSocketLease> {
        loop {
            let notified = self.available.notified();
            let can_create = {
                let slots = self.slots.lock().await;
                let server_slots = slots.get(&server);
                if let Some(server_slots) = server_slots {
                    for slot in server_slots {
                        if let Ok(gate) = slot.gate.clone().try_lock_owned() {
                            return Ok(UdpSocketLease {
                                socket: slot.socket.clone(),
                                next_id: slot.next_id.clone(),
                                _gate: gate,
                                available: self.available.clone(),
                            });
                        }
                    }
                    server_slots.len() < MAX_UPSTREAM_UDP_SOCKETS
                } else {
                    true
                }
            };
            if !can_create {
                notified.await;
                continue;
            }

            // Socket creation can involve asynchronous OS work. Keep it outside
            // the pool lock so an unavailable upstream does not block other
            // servers from acquiring their sockets.
            let bind = if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(server).await?;
            let slot = UdpSocketSlot {
                socket: Arc::new(tokio::sync::Mutex::new(socket)),
                gate: Arc::new(tokio::sync::Mutex::new(())),
                next_id: Arc::new(AtomicU32::new(1)),
            };
            let gate = slot.gate.clone().lock_owned().await;

            let mut slots = self.slots.lock().await;
            let server_slots = slots.entry(server).or_default();
            // Another task may have installed a slot while this socket was being
            // created. Prefer an idle existing slot, and never exceed the cap.
            for existing in server_slots.iter() {
                if let Ok(existing_gate) = existing.gate.clone().try_lock_owned() {
                    return Ok(UdpSocketLease {
                        socket: existing.socket.clone(),
                        next_id: existing.next_id.clone(),
                        _gate: existing_gate,
                        available: self.available.clone(),
                    });
                }
            }
            if server_slots.len() < MAX_UPSTREAM_UDP_SOCKETS {
                let socket = slot.socket.clone();
                let next_id = slot.next_id.clone();
                server_slots.push(slot);
                return Ok(UdpSocketLease {
                    socket,
                    next_id,
                    _gate: gate,
                    available: self.available.clone(),
                });
            }
            drop(slots);
            // The newly-created slot lost a capacity race. Its gate and socket
            // are dropped here; wait for a real slot to become available.
            drop(gate);
            notified.await;
        }
    }
}

fn upstream_udp_pool() -> &'static UdpSocketPool {
    static POOL: OnceLock<UdpSocketPool> = OnceLock::new();
    POOL.get_or_init(UdpSocketPool::default)
}

async fn forward_udp(server: &DnsServer, wire: &[u8], pool: &UdpSocketPool) -> Result<Message> {
    let request = Message::from_vec(wire)?;
    let lease = pool.acquire(server.socket_addr()).await?;
    let socket = lease.socket.lock().await;
    let mut response = vec![0u8; 65_535];
    // A pooled socket can still contain a duplicate or delayed response from
    // its previous request. Drain it, then use a socket-local upstream ID so
    // the client-controlled DNS ID cannot make that response look current.
    while socket.try_recv(&mut response).is_ok() {}
    let upstream_id = loop {
        let id = lease.next_id.fetch_add(1, Ordering::Relaxed) as u16;
        if id != 0 {
            break id;
        }
    };
    let mut upstream_wire = wire.to_vec();
    upstream_wire[..2].copy_from_slice(&upstream_id.to_be_bytes());
    socket.send(&upstream_wire).await?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("upstream DNS UDP timeout"));
        }
        let size = tokio::time::timeout(remaining, socket.recv(&mut response))
            .await
            .context("upstream DNS UDP timeout")??;
        let response = Message::from_vec(&response[..size])?;
        if response.metadata.id != upstream_id || response.queries != request.queries {
            continue;
        }
        let mut response = response;
        response.metadata.id = request.metadata.id;
        return Ok(response);
    }
}

async fn forward_tcp(server: &DnsServer, wire: &[u8]) -> Result<Message> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(server.socket_addr()).await?;
        stream.write_u16(u16::try_from(wire.len())?).await?;
        stream.write_all(wire).await?;
        let size = usize::from(stream.read_u16().await?);
        let mut response = vec![0u8; size];
        stream.read_exact(&mut response).await?;
        let response = Message::from_vec(&response)?;
        validate_dns_response(wire, &response)?;
        Ok(response)
    })
    .await
    .context("upstream DNS TCP exchange timeout")?
}

fn validate_dns_response(request: &[u8], response: &Message) -> Result<()> {
    let request = Message::from_vec(request)?;
    if response.metadata.id != request.metadata.id || response.queries != request.queries {
        return Err(anyhow!("upstream DNS response does not match its request"));
    }
    Ok(())
}

fn clamp_ttls(message: &mut Message, min: u32, max: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(&mut message.authorities)
        .chain(&mut message.additionals)
    {
        if record.record_type() != RecordType::OPT {
            record.ttl = record.ttl.clamp(min, max);
        }
    }
}

fn strip_ipv6_hints(message: &mut Message) {
    // AAAA can appear as glue even when the question itself is not AAAA.
    // SVCB/HTTPS may carry ipv6hint inside their RDATA, so conservatively
    // remove those records as well when IPv6 recording is disabled.
    for section in [
        &mut message.answers,
        &mut message.authorities,
        &mut message.additionals,
    ] {
        section.retain(|record| {
            !matches!(
                record.record_type(),
                RecordType::AAAA | RecordType::SVCB | RecordType::HTTPS
            )
        });
    }
}

fn prune_if_due(state: &mut State, now: Instant, force: bool) {
    let due = state
        .last_prune
        .is_none_or(|last| now.saturating_duration_since(last) >= FLOW_PRUNE_INTERVAL);
    if force || due {
        prune(state, now);
        state.last_prune = Some(now);
    }
}

fn prune(state: &mut State, now: Instant) {
    state.source_flows.retain(|_, flow| flow.expires > now);
    state
        .wire_flows
        .retain(|_, key| state.source_flows.contains_key(key));
    let active_fakes = state
        .source_flows
        .values()
        .map(|flow| flow.fake_destination)
        .collect::<HashSet<_>>();
    state
        .mappings
        .retain(|fake, mapping| mapping.expires > now || active_fakes.contains(fake));
    state
        .by_name
        .retain(|_, fake| state.mappings.contains_key(fake));
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_sets::RouteSetLoader;
    use hickory_proto::{op::Query, rr::Name};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn dns_listener_task_limit_is_bounded() {
        let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_TASKS));
        let permits = (0..MAX_CONCURRENT_DNS_TASKS)
            .map(|_| limit.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        assert!(limit.try_acquire().is_err());
        drop(permits);
        assert!(limit.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn cancelled_singleflight_waiter_keeps_then_releases_the_shared_entry() {
        let queries = InflightDns::default();
        let first = InflightQuery::register(&queries, ("example.test".into(), 1));
        let first_guard = first.acquire().await;
        let second = InflightQuery::register(&queries, ("example.test".into(), 1));
        let waiter = tokio::spawn(async move {
            let _guard = second.acquire().await;
        });
        tokio::task::yield_now().await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert_eq!(queries.lock().unwrap().len(), 1);

        drop(first_guard);
        drop(first);
        assert!(queries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_dns_listener_cancels_and_joins_its_sibling() {
        let parent = CancellationToken::new();
        let mut listeners = TaskGroup::<Result<()>>::new();
        let children = listeners.token();
        listeners.spawn(async { Err(anyhow!("UDP listener failed")) });
        let sibling_cancelled = Arc::new(AtomicBool::new(false));
        let sibling_flag = sibling_cancelled.clone();
        let sibling_token = children.clone();
        listeners.spawn(async move {
            sibling_token.cancelled().await;
            sibling_flag.store(true, Ordering::Release);
            Ok(())
        });

        let error = join_dns_listeners(listeners, parent).await.unwrap_err();
        assert!(error.to_string().contains("UDP listener failed"));
        assert!(sibling_cancelled.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn incomplete_tcp_dns_frame_hits_the_read_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let error = runtime()
            .serve_tcp_with_timeouts(
                &mut server,
                Duration::from_millis(20),
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("frame read timeout"));
        drop(client);
    }

    fn runtime() -> FakeIpRuntime {
        runtime_with_upstream("1.1.1.1")
    }

    fn runtime_with_upstream(upstream: &str) -> FakeIpRuntime {
        FakeIpRuntime::new(
            FakeIpConfig {
                listen: "127.0.0.1:5354".parse().unwrap(),
                upstream_dns: vec![serde_yaml::from_str(upstream).unwrap()],
                disable_ipv6: true,
                ipv4_pool: "198.18.0.0/15".parse().unwrap(),
                ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
                min_cache_ttl_secs: 60,
                max_cache_ttl_secs: 3600,
                max_entries: 32,
            },
            Default::default(),
            Vec::new(),
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        )
    }

    #[test]
    fn fake_ip_envelope_round_trips_and_rejects_truncation() {
        let packet = vec![0x45, 0, 0, 20, 1, 2, 3, 4];
        let fake_v4: IpAddr = "198.18.0.9".parse().unwrap();
        assert_eq!(max_fake_ip_envelope_len(true), 6);
        assert_eq!(max_fake_ip_envelope_len(false), 18);
        let mut encoded = encode_fake_ip_envelope(&packet, fake_v4);
        assert_eq!(fake_ip_envelope_len(fake_v4), 6);
        assert_eq!(decode_fake_ip_envelope(&mut encoded), Ok(Some(fake_v4)));
        assert_eq!(encoded, packet);

        let fake_v6: IpAddr = "fd74:696e:6563:7400::9".parse().unwrap();
        let mut encoded = encode_fake_ip_envelope(&packet, fake_v6);
        assert_eq!(fake_ip_envelope_len(fake_v6), 18);
        assert_eq!(decode_fake_ip_envelope(&mut encoded), Ok(Some(fake_v6)));
        assert_eq!(encoded, packet);

        let mut truncated = vec![FAKE_IP_ENVELOPE_TAG, 16, 1, 2, 3];
        assert!(decode_fake_ip_envelope(&mut truncated).is_err());
        assert_eq!(decode_fake_ip_envelope(&mut vec![1, 2, 3]), Ok(None));
        assert!(decode_fake_ip_envelope(&mut vec![FAKE_IP_ENVELOPE_TAG]).is_err());
        assert!(decode_fake_ip_envelope(&mut vec![FAKE_IP_ENVELOPE_TAG, 3, 1, 2, 3]).is_err());
    }

    #[tokio::test]
    async fn concurrent_identical_queries_share_one_upstream_request() {
        let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let server_socket = upstream.clone();
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            let mut wire = vec![0_u8; 512];
            let (size, peer) = server_socket.recv_from(&mut wire).await.unwrap();
            server_requests.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(50)).await;
            let request = Message::from_vec(&wire[..size]).unwrap();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.queries = request.queries;
            server_socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let runtime = Arc::new(runtime_with_upstream(
            &upstream.local_addr().unwrap().to_string(),
        ));
        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("uncached.test.").unwrap(),
            RecordType::A,
        ));
        let wire = request.to_vec().unwrap();
        let first = {
            let runtime = runtime.clone();
            let wire = wire.clone();
            tokio::spawn(async move { runtime.answer(&wire).await.unwrap() })
        };
        let second = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.answer(&wire).await.unwrap() })
        };
        let _ = tokio::join!(first, second);
        server.await.unwrap();
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn truncated_udp_upstream_falls_back_to_tcp() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(address).await.unwrap();
        let udp_task = tokio::spawn(async move {
            let mut wire = vec![0_u8; 512];
            let (size, peer) = udp.recv_from(&mut wire).await.unwrap();
            let request = Message::from_vec(&wire[..size]).unwrap();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.metadata.truncation = true;
            response.queries = request.queries;
            udp.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let size = usize::from(stream.read_u16().await.unwrap());
            let mut wire = vec![0_u8; size];
            stream.read_exact(&mut wire).await.unwrap();
            let request = Message::from_vec(&wire).unwrap();
            let name = request.queries[0].name.clone();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.queries = request.queries;
            response.answers.push(Record::from_rdata(
                name,
                300,
                RData::A(A("192.0.2.53".parse().unwrap())),
            ));
            let response = response.to_vec().unwrap();
            stream
                .write_u16(u16::try_from(response.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("fallback.test.").unwrap(),
            RecordType::A,
        ));
        let response = query_upstream(
            &DnsServer::from_socket_addr(address),
            &request.to_vec().unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(response.answers[0].data, RData::A(_)));
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
    }

    #[tokio::test]
    async fn upstream_udp_queries_reuse_a_socket_for_the_same_server() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let (peer_tx, mut peer_rx) = mpsc::channel(2);
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut wire = vec![0_u8; 512];
                let (size, peer) = upstream.recv_from(&mut wire).await.unwrap();
                peer_tx.send(peer).await.unwrap();
                let request = Message::from_vec(&wire[..size]).unwrap();
                let mut response = Message::response(request.metadata.id, request.metadata.op_code);
                response.queries = request.queries;
                upstream
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        for id in [1, 2] {
            let mut request = Message::query();
            request.metadata.id = id;
            request.queries.push(Query::query(
                Name::from_ascii("reuse.test.").unwrap(),
                RecordType::A,
            ));
            query_upstream(
                &DnsServer::from_socket_addr(address),
                &request.to_vec().unwrap(),
            )
            .await
            .unwrap();
        }
        let first = peer_rx.recv().await.unwrap();
        let second = peer_rx.recv().await.unwrap();
        assert_eq!(first, second);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn upstream_udp_queries_ignore_delayed_responses_on_reused_socket() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut wire = vec![0_u8; 512];
            let (size, peer) = upstream.recv_from(&mut wire).await.unwrap();
            let first = Message::from_vec(&wire[..size]).unwrap();
            let first_id = first.metadata.id;
            let mut first_response = Message::response(first_id, first.metadata.op_code);
            first_response.queries = first.queries;
            first_response.answers.push(Record::from_rdata(
                Name::from_ascii("stale.test.").unwrap(),
                60,
                RData::A(A("192.0.2.1".parse().unwrap())),
            ));
            upstream
                .send_to(&first_response.to_vec().unwrap(), peer)
                .await
                .unwrap();

            let (size, peer) = upstream.recv_from(&mut wire).await.unwrap();
            let second = Message::from_vec(&wire[..size]).unwrap();
            assert_ne!(first_id, second.metadata.id);
            let mut stale_response = Message::response(first_id, second.metadata.op_code);
            stale_response.queries = second.queries.clone();
            stale_response.answers.push(Record::from_rdata(
                Name::from_ascii("stale.test.").unwrap(),
                60,
                RData::A(A("192.0.2.9".parse().unwrap())),
            ));
            upstream
                .send_to(&stale_response.to_vec().unwrap(), peer)
                .await
                .unwrap();
            let mut second_response =
                Message::response(second.metadata.id, second.metadata.op_code);
            second_response.queries = second.queries;
            second_response.answers.push(Record::from_rdata(
                Name::from_ascii("stale.test.").unwrap(),
                60,
                RData::A(A("192.0.2.2".parse().unwrap())),
            ));
            upstream
                .send_to(&second_response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });

        let mut request = Message::query();
        request.metadata.id = 4242;
        request.queries.push(Query::query(
            Name::from_ascii("stale.test.").unwrap(),
            RecordType::A,
        ));
        let wire = request.to_vec().unwrap();
        query_upstream(&DnsServer::from_socket_addr(address), &wire)
            .await
            .unwrap();
        let response = query_upstream(&DnsServer::from_socket_addr(address), &wire)
            .await
            .unwrap();
        assert_eq!(response.metadata.id, request.metadata.id);
        assert!(matches!(
            &response.answers[0].data,
            RData::A(address) if address.0 == "192.0.2.2".parse::<Ipv4Addr>().unwrap()
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_dns_frontend_accepts_length_prefixed_queries() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut wire = vec![0_u8; 512];
            let (size, peer) = upstream.recv_from(&mut wire).await.unwrap();
            let request = Message::from_vec(&wire[..size]).unwrap();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.queries = request.queries;
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let runtime = Arc::new(runtime_with_upstream(&upstream_address.to_string()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let frontend = listener.local_addr().unwrap();
        let runtime_task = runtime.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            runtime_task.serve_tcp(stream).await.unwrap();
        });
        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("tcp.test.").unwrap(),
            RecordType::A,
        ));
        let request = request.to_vec().unwrap();
        let mut client = TcpStream::connect(frontend).await.unwrap();
        client
            .write_u16(u16::try_from(request.len()).unwrap())
            .await
            .unwrap();
        client.write_all(&request).await.unwrap();
        let size = usize::from(client.read_u16().await.unwrap());
        let mut response = vec![0_u8; size];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().queries.len(), 1);
        drop(client);
        upstream_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn answer_handles_empty_queries_cache_and_overlay_routes() {
        let runtime = runtime();
        let empty = Message::query().to_vec().unwrap();
        let empty_response = Message::from_vec(&runtime.answer(&empty).await.unwrap()).unwrap();
        assert_eq!(empty_response.metadata.response_code, ResponseCode::FormErr);

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut wire = [0_u8; 512];
            let (size, peer) = upstream.recv_from(&mut wire).await.unwrap();
            let request = Message::from_vec(&wire[..size]).unwrap();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.queries = request.queries.clone();
            response.answers.push(Record::from_rdata(
                response.queries[0].name.clone(),
                1,
                RData::A(A("192.0.2.44".parse().unwrap())),
            ));
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let runtime = runtime_with_upstream(&upstream_address.to_string());
        let mut request = Message::query();
        request.metadata.id = 100;
        request.queries.push(Query::query(
            Name::from_ascii("plain.test.").unwrap(),
            RecordType::A,
        ));
        let wire = request.to_vec().unwrap();
        let first = Message::from_vec(&runtime.answer(&wire).await.unwrap()).unwrap();
        assert_eq!(first.metadata.id, 100);
        assert_eq!(first.answers.len(), 1);
        request.metadata.id = 101;
        let cached =
            Message::from_vec(&runtime.answer(&request.to_vec().unwrap()).await.unwrap()).unwrap();
        assert_eq!(cached.metadata.id, 101);
        upstream_task.await.unwrap();

        let mut loader = RouteSetLoader::new(".");
        let site_id = loader.load_inline("overlay.test").unwrap();
        let overlay = FakeIpRuntime::new(
            runtime.config.clone(),
            Arc::new(loader.finish()),
            vec![site_id],
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        );
        let (requests, mut requests_rx) = mpsc::channel(1);
        overlay.install_overlay_dns(requests);
        let responder = tokio::spawn(async move {
            let request = requests_rx.recv().await.unwrap();
            let original = Message::from_vec(&request.wire).unwrap();
            let mut response = Message::response(original.metadata.id, original.metadata.op_code);
            response.queries = original.queries;
            response.answers.push(Record::from_rdata(
                response.queries[0].name.clone(),
                300,
                RData::A(A("192.0.2.45".parse().unwrap())),
            ));
            assert!(
                request
                    .response
                    .send(Ok(OverlayDnsResponse {
                        wire: response.to_vec().unwrap(),
                        preferred_route: RoutePreference::Exit("exit".into()),
                    }))
                    .is_ok()
            );
        });
        let mut query = Message::query();
        query.metadata.id = 102;
        query.queries.push(Query::query(
            Name::from_ascii("overlay.test.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_vec(&overlay.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.answers.len(), 1);
        assert!(overlay.matches_domain("www.overlay.test"));
        responder.await.unwrap();
    }

    #[test]
    fn translation_rejects_invalid_capacity_and_reuses_expired_flow_slots() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.12".parse().unwrap();
        let real: IpAddr = "192.0.2.12".parse().unwrap();
        install_mapping(&runtime, fake, real);

        let mut packet = udp_packet([10, 0, 0, 1], [198, 18, 0, 12], 40_000);
        let original = packet.clone();
        assert!(runtime.translate_outbound(&mut packet));
        let first_wire_port = u16::from_be_bytes([packet[20], packet[21]]);
        let mut reused = original.clone();
        assert!(runtime.translate_outbound(&mut reused));
        assert_eq!(
            u16::from_be_bytes([reused[20], reused[21]]),
            first_wire_port
        );

        let key = SourceFlowKey {
            source: "10.0.0.1".parse().unwrap(),
            fake_destination: fake,
            wire_source: "10.64.0.1".parse().unwrap(),
            protocol: 17,
            local_id: 40_000,
            remote_id: 53,
        };
        runtime
            .state
            .lock()
            .unwrap()
            .source_flows
            .get_mut(&key)
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        let mut rebuilt = udp_packet([10, 0, 0, 1], [198, 18, 0, 12], 40_000);
        assert!(runtime.translate_outbound(&mut rebuilt));

        let mut malformed = vec![0_u8; 2];
        assert!(!runtime.translate_outbound(&mut malformed));
        let mut empty_real = udp_packet([10, 0, 0, 2], [198, 18, 0, 12], 40_001);
        runtime
            .state
            .lock()
            .unwrap()
            .mappings
            .get_mut(&fake)
            .unwrap()
            .real
            .clear();
        assert!(!runtime.translate_outbound(&mut empty_real));
        runtime
            .state
            .lock()
            .unwrap()
            .mappings
            .get_mut(&fake)
            .unwrap()
            .real = vec![real];

        let mut wrong_family = vec![0_u8; 48];
        wrong_family[0] = 0x60;
        wrong_family[4..6].copy_from_slice(&8_u16.to_be_bytes());
        wrong_family[6] = 17;
        wrong_family[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        wrong_family[24..40].copy_from_slice(
            &"fd74:696e:6563:7400::12"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        wrong_family[40..42].copy_from_slice(&40_002_u16.to_be_bytes());
        wrong_family[42..44].copy_from_slice(&53_u16.to_be_bytes());
        wrong_family[44..46].copy_from_slice(&8_u16.to_be_bytes());
        assert!(!runtime.translate_outbound(&mut wrong_family));
    }

    #[test]
    fn translation_rejects_missing_expired_and_family_mismatched_state() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.20".parse().unwrap();
        let real: IpAddr = "192.0.2.20".parse().unwrap();
        install_mapping(&runtime, fake, real);

        let mut missing = udp_packet([10, 0, 0, 1], [198, 18, 0, 21], 40_000);
        assert!(!runtime.translate_outbound(&mut missing));

        runtime
            .state
            .lock()
            .unwrap()
            .mappings
            .get_mut(&fake)
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        let mut expired = udp_packet([10, 0, 0, 1], [198, 18, 0, 20], 40_001);
        assert!(!runtime.translate_outbound(&mut expired));

        runtime
            .state
            .lock()
            .unwrap()
            .mappings
            .get_mut(&fake)
            .unwrap()
            .expires = Instant::now() + Duration::from_secs(60);
        let no_source_runtime = FakeIpRuntime::new(
            runtime.config.clone(),
            runtime.registry.clone(),
            runtime.domain_sites.to_vec(),
            Vec::new(),
            runtime.metrics.clone(),
        );
        install_mapping(&no_source_runtime, fake, real);
        let mut no_source_packet = udp_packet([10, 0, 0, 1], [198, 18, 0, 20], 40_002);
        assert!(!no_source_runtime.translate_outbound(&mut no_source_packet));

        runtime
            .state
            .lock()
            .unwrap()
            .mappings
            .get_mut(&fake)
            .unwrap()
            .real = vec!["2001:db8::20".parse().unwrap()];
        let mut family_mismatch = udp_packet([10, 0, 0, 1], [198, 18, 0, 20], 40_003);
        assert!(!runtime.translate_outbound(&mut family_mismatch));

        let mut no_flow = udp_packet([192, 0, 2, 20], [10, 64, 0, 1], 53);
        assert!(!runtime.translate_inbound(&mut no_flow, None));
        assert!(!runtime.translate_inbound(&mut [0; 2], None));
    }

    #[test]
    fn expired_inbound_flow_is_removed_and_cache_entries_are_replaced() {
        let flow_runtime = runtime();
        let fake: IpAddr = "198.18.0.22".parse().unwrap();
        let real: IpAddr = "192.0.2.22".parse().unwrap();
        install_mapping(&flow_runtime, fake, real);
        let mut outbound = udp_packet([10, 0, 0, 1], [198, 18, 0, 22], 40_004);
        assert!(flow_runtime.translate_outbound(&mut outbound));
        let wire_port = u16::from_be_bytes([outbound[20], outbound[21]]);
        flow_runtime
            .state
            .lock()
            .unwrap()
            .source_flows
            .values_mut()
            .next()
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        let mut inbound = udp_packet([192, 0, 2, 22], [10, 64, 0, 1], 53);
        inbound[22..24].copy_from_slice(&wire_port.to_be_bytes());
        assert!(!flow_runtime.translate_inbound(&mut inbound, None));

        let name = Name::from_ascii("cache.test.").unwrap();
        let response = Message::response(1, hickory_proto::op::OpCode::Query);
        let mut cache_runtime = runtime();
        cache_runtime.config.max_entries = 1;
        cache_runtime.cache_dns((name.to_ascii(), 1), &response, None);
        let (cached, _) = cache_runtime.cached_dns(&(name.to_ascii(), 1), 9).unwrap();
        assert_eq!(cached.metadata.id, 9);
        cache_runtime.cache_dns(("other.test".into(), 1), &response, None);
        assert!(cache_runtime.cached_dns(&(name.to_ascii(), 1), 9).is_none());
        cache_runtime
            .state
            .lock()
            .unwrap()
            .dns_cache
            .get_mut(&("other.test".into(), 1))
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert!(
            cache_runtime
                .cached_dns(&("other.test".into(), 1), 9)
                .is_none()
        );
    }

    #[tokio::test]
    async fn dns_response_validation_and_overlay_readiness_fail_closed() {
        let request = Message::query();
        let mut response = Message::response(2, hickory_proto::op::OpCode::Query);
        assert!(validate_dns_response(&request.to_vec().unwrap(), &response).is_err());
        response.metadata.id = request.metadata.id;
        response.queries.push(Query::query(
            Name::from_ascii("different.test.").unwrap(),
            RecordType::A,
        ));
        assert!(validate_dns_response(&request.to_vec().unwrap(), &response).is_err());
        assert!(validate_dns_response(&[1, 2, 3], &response).is_err());

        let mut loader = RouteSetLoader::new(".");
        let site_id = loader.load_inline("overlay.test").unwrap();
        let runtime = FakeIpRuntime::new(
            runtime().config,
            Arc::new(loader.finish()),
            vec![site_id],
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        );
        let error = runtime
            .forward_overlay("overlay.test", &[])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not ready"));
    }

    #[tokio::test]
    async fn bound_dns_listeners_stop_cleanly_on_cancellation() {
        let runtime = Arc::new(runtime());
        let (udp, tcp) = runtime.bind().await.unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        runtime.serve_bound(udp, tcp, cancellation).await.unwrap();
    }

    #[test]
    fn ttl_clamping_applies_to_all_dns_sections() {
        let name = Name::from_ascii("ttl.test.").unwrap();
        let mut response = Message::response(1, hickory_proto::op::OpCode::Query);
        response.answers.push(Record::from_rdata(
            name.clone(),
            1,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        response.authorities.push(Record::from_rdata(
            name,
            10_000,
            RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        ));
        clamp_ttls(&mut response, 60, 300);
        assert_eq!(response.answers[0].ttl, 60);
        assert_eq!(response.authorities[0].ttl, 300);
    }

    #[test]
    fn active_fake_mapping_capacity_is_not_reused() {
        let mut runtime = runtime();
        runtime.config.max_entries = 1;
        let first =
            runtime.allocate_fake("one.test", false, vec!["192.0.2.1".parse().unwrap()], None);
        let second =
            runtime.allocate_fake("two.test", false, vec!["192.0.2.2".parse().unwrap()], None);
        assert!(first.is_some());
        assert!(second.is_none());
    }

    #[test]
    fn pruning_keeps_mappings_with_live_flows_and_removes_expired_state() {
        let now = Instant::now();
        let active_fake: IpAddr = "198.18.0.1".parse().unwrap();
        let expired_fake: IpAddr = "198.18.0.2".parse().unwrap();
        let active_key = SourceFlowKey {
            source: "10.0.0.1".parse().unwrap(),
            fake_destination: active_fake,
            wire_source: "10.0.0.2".parse().unwrap(),
            protocol: 17,
            local_id: 100,
            remote_id: 53,
        };
        let mut state = State::default();
        for (fake, domain) in [(active_fake, "active.test"), (expired_fake, "expired.test")] {
            state.mappings.insert(
                fake,
                Mapping {
                    domain: domain.into(),
                    preferred_route: None,
                    real: vec!["192.0.2.1".parse().unwrap()],
                    expires: now - Duration::from_secs(1),
                    next_real: 0,
                },
            );
            state.by_name.insert((domain.into(), false), fake);
        }
        state.source_flows.insert(
            active_key,
            SourceFlow {
                original_source: "10.0.0.1".parse().unwrap(),
                wire_source: "10.0.0.2".parse().unwrap(),
                fake_destination: active_fake,
                real_destination: "192.0.2.1".parse().unwrap(),
                original_local_id: 100,
                wire_local_id: 100,
                expires: now + Duration::from_secs(1),
            },
        );
        state.wire_flows.insert(
            WireFlowKey {
                real_destination: "192.0.2.1".parse().unwrap(),
                local_source: "10.0.0.2".parse().unwrap(),
                protocol: 17,
                remote_id: 53,
                local_id: 100,
            },
            active_key,
        );

        prune(&mut state, now);

        assert!(state.mappings.contains_key(&active_fake));
        assert!(!state.mappings.contains_key(&expired_fake));
        assert!(state.by_name.values().all(|fake| *fake == active_fake));
        assert_eq!(state.source_flows.len(), 1);
        assert_eq!(state.wire_flows.len(), 1);
    }

    #[test]
    fn forced_pruning_removes_expired_state_before_capacity_reuse() {
        let now = Instant::now();
        let fake: IpAddr = "198.18.0.3".parse().unwrap();
        let mut state = State {
            last_prune: Some(now),
            ..State::default()
        };
        state.mappings.insert(
            fake,
            Mapping {
                domain: "expired.test".into(),
                preferred_route: None,
                real: vec!["192.0.2.3".parse().unwrap()],
                expires: now - Duration::from_secs(1),
                next_real: 0,
            },
        );
        state.by_name.insert(("expired.test".into(), false), fake);

        prune_if_due(&mut state, now + Duration::from_millis(100), true);

        assert!(state.mappings.is_empty());
        assert!(state.by_name.is_empty());
    }

    #[tokio::test]
    async fn disabled_ipv6_returns_nodata_without_contacting_upstream() {
        let runtime = runtime();
        for qtype in [RecordType::AAAA, RecordType::HTTPS, RecordType::SVCB] {
            let mut request = Message::query();
            request
                .queries
                .push(Query::query(Name::from_ascii("ipv6.test.").unwrap(), qtype));
            let response =
                Message::from_vec(&runtime.answer(&request.to_vec().unwrap()).await.unwrap())
                    .unwrap();
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.answers.is_empty());
        }
    }

    #[test]
    fn address_inside_pool_is_fake_even_without_a_live_mapping() {
        let runtime = runtime();
        assert!(runtime.contains_fake_address("198.18.0.42".parse().unwrap()));
        assert!(
            runtime
                .route_hint_for_fake("198.18.0.42".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn ipv4_address_rewrite_updates_header_checksum() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 18, 0, 1]);
        let header_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        assert!(rewrite_addresses(
            &mut packet,
            "10.0.0.1".parse().unwrap(),
            "198.18.0.1".parse().unwrap(),
            "100.64.0.1".parse().unwrap(),
            "192.0.2.1".parse().unwrap()
        ));
        assert_eq!(checksum(&packet[..20]), 0);
    }

    #[test]
    fn ipv6_udp_address_rewrite_updates_pseudo_header_checksum() {
        let old_source: Ipv6Addr = "fd00::1".parse().unwrap();
        let old_destination: Ipv6Addr = "fd74:696e:6563:7400::1".parse().unwrap();
        let new_source: Ipv6Addr = old_destination;
        let new_destination: Ipv6Addr = "2001:db8::53".parse().unwrap();
        let mut packet = vec![0_u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&old_source.octets());
        packet[24..40].copy_from_slice(&old_destination.octets());
        packet[40..42].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53_u16.to_be_bytes());
        packet[44..46].copy_from_slice(&8_u16.to_be_bytes());
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&old_source.octets());
        pseudo.extend_from_slice(&old_destination.octets());
        pseudo.extend_from_slice(&8_u32.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&packet[40..]);
        packet[46..48].copy_from_slice(&checksum(&pseudo).to_be_bytes());

        assert!(rewrite_addresses(
            &mut packet,
            old_source.into(),
            old_destination.into(),
            new_source.into(),
            new_destination.into(),
        ));
        let mut rewritten = Vec::new();
        rewritten.extend_from_slice(&new_source.octets());
        rewritten.extend_from_slice(&new_destination.octets());
        rewritten.extend_from_slice(&8_u32.to_be_bytes());
        rewritten.extend_from_slice(&[0, 0, 0, 17]);
        rewritten.extend_from_slice(&packet[40..]);
        assert_eq!(checksum(&rewritten), 0);
    }

    #[test]
    fn protocol_independent_flow_round_trip_restores_addresses() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.9".parse().unwrap();
        let real: IpAddr = "192.0.2.9".parse().unwrap();
        runtime.state.lock().unwrap().mappings.insert(
            fake,
            Mapping {
                domain: "target.test".into(),
                preferred_route: None,
                real: vec![real],
                expires: Instant::now() + Duration::from_secs(60),
                next_real: 0,
            },
        );
        let mut outbound = vec![0u8; 24];
        outbound[0] = 0x45;
        outbound[2..4].copy_from_slice(&24u16.to_be_bytes());
        outbound[9] = 99;
        outbound[12..16].copy_from_slice(&[10, 64, 0, 1]);
        outbound[16..20].copy_from_slice(&[198, 18, 0, 9]);
        assert!(runtime.translate_outbound(&mut outbound));
        assert_eq!(
            packet_addresses(&outbound).unwrap().0,
            "10.64.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(packet_addresses(&outbound).unwrap().1, real);

        let mut inbound = outbound;
        inbound[12..16].copy_from_slice(&[192, 0, 2, 9]);
        inbound[16..20].copy_from_slice(&[10, 64, 0, 1]);
        assert!(!runtime.translate_inbound(&mut inbound, Some("198.18.0.10".parse().unwrap())));
        assert!(runtime.translate_inbound(&mut inbound, Some(fake)));
        assert_eq!(
            packet_addresses(&inbound),
            Some((fake, "10.64.0.1".parse().unwrap()))
        );
    }

    #[test]
    fn direct_and_circuit_flows_have_distinct_wire_sources() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.11".parse().unwrap();
        let real: IpAddr = "192.0.2.11".parse().unwrap();
        install_mapping(&runtime, fake, real);

        let mut circuit = vec![0u8; 24];
        circuit[0] = 0x45;
        circuit[2..4].copy_from_slice(&24u16.to_be_bytes());
        circuit[9] = 99;
        circuit[12..16].copy_from_slice(&[10, 64, 0, 1]);
        circuit[16..20].copy_from_slice(&[198, 18, 0, 11]);
        let mut direct = circuit.clone();

        assert!(runtime.translate_outbound(&mut circuit));
        assert!(runtime.translate_outbound_direct(&mut direct));
        assert_eq!(
            packet_addresses(&circuit),
            Some(("10.64.0.1".parse().unwrap(), real))
        );
        assert_eq!(packet_addresses(&direct), Some((fake, real)));

        circuit[12..16].copy_from_slice(&[192, 0, 2, 11]);
        circuit[16..20].copy_from_slice(&[10, 64, 0, 1]);
        assert!(runtime.translate_inbound(&mut circuit, None));
        assert_eq!(
            packet_addresses(&circuit),
            Some((fake, "10.64.0.1".parse().unwrap()))
        );

        direct[12..16].copy_from_slice(&[192, 0, 2, 11]);
        direct[16..20].copy_from_slice(&[198, 18, 0, 11]);
        assert!(runtime.translate_inbound(&mut direct, None));
        assert_eq!(
            packet_addresses(&direct),
            Some((fake, "10.64.0.1".parse().unwrap()))
        );
    }

    fn install_mapping(runtime: &FakeIpRuntime, fake: IpAddr, real: IpAddr) {
        runtime.state.lock().unwrap().mappings.insert(
            fake,
            Mapping {
                domain: "target.test".into(),
                preferred_route: None,
                real: vec![real],
                expires: Instant::now() + Duration::from_secs(60),
                next_real: 0,
            },
        );
    }

    fn udp_packet(source: [u8; 4], destination: [u8; 4], source_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
        let header = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet
    }

    #[test]
    fn overlapping_clients_get_distinct_ports_and_round_trip() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.10".parse().unwrap();
        let real: IpAddr = "192.0.2.10".parse().unwrap();
        install_mapping(&runtime, fake, real);
        let mut first = udp_packet([10, 0, 0, 1], [198, 18, 0, 10], 40_000);
        let mut second = udp_packet([10, 0, 0, 2], [198, 18, 0, 10], 40_000);
        assert!(runtime.translate_outbound(&mut first));
        assert!(runtime.translate_outbound(&mut second));
        assert_eq!(
            packet_addresses(&first).unwrap().0,
            "10.64.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            packet_addresses(&second).unwrap().0,
            "10.64.0.1".parse::<IpAddr>().unwrap()
        );
        let first_wire = u16::from_be_bytes([first[20], first[21]]);
        let second_wire = u16::from_be_bytes([second[20], second[21]]);
        assert_ne!(first_wire, second_wire);

        for (wire, original) in [(first_wire, [10, 0, 0, 1]), (second_wire, [10, 0, 0, 2])] {
            let mut reply = udp_packet([192, 0, 2, 10], [198, 18, 0, 10], 53);
            reply[16..20].copy_from_slice(&[10, 64, 0, 1]);
            reply[22..24].copy_from_slice(&wire.to_be_bytes());
            assert!(runtime.translate_inbound(&mut reply, Some(fake)));
            assert_eq!(packet_addresses(&reply).unwrap().0, fake);
            assert_eq!(
                packet_addresses(&reply).unwrap().1,
                IpAddr::V4(original.into())
            );
            assert_eq!(u16::from_be_bytes([reply[22], reply[23]]), 40_000);
        }
    }

    #[test]
    fn authentication_header_is_rejected() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[9] = 51;
        assert!(!rewrite_addresses(
            &mut packet,
            "10.0.0.1".parse().unwrap(),
            "198.18.0.1".parse().unwrap(),
            "100.64.0.1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
        ));
    }

    #[test]
    fn ipv6_records_and_service_hints_are_removed_from_forwarded_answers() {
        let name = Name::from_ascii("target.test.").unwrap();
        let mut response = Message::response(1, hickory_proto::op::OpCode::Query);
        response.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        response.additionals.push(Record::from_rdata(
            name,
            300,
            RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        ));
        strip_ipv6_hints(&mut response);
        assert_eq!(response.answers.len(), 1);
        assert!(response.additionals.is_empty());
    }

    #[test]
    fn fake_prefixes_and_helpers_cover_ipv6_when_enabled() {
        let v6_runtime = FakeIpRuntime::new(
            FakeIpConfig {
                listen: "127.0.0.1:5354".parse().unwrap(),
                upstream_dns: vec![serde_yaml::from_str("1.1.1.1").unwrap()],
                disable_ipv6: false,
                ipv4_pool: "198.18.0.0/15".parse().unwrap(),
                ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
                min_cache_ttl_secs: 60,
                max_cache_ttl_secs: 3600,
                max_entries: 32,
            },
            Default::default(),
            Vec::new(),
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        );
        assert_eq!(v6_runtime.fake_prefixes().len(), 2);
        assert_eq!(v6_runtime.max_envelope_len(), 18);
        assert!(v6_runtime.contains_fake_address("fd74:696e:6563:7400::9".parse().unwrap()));
        let mut packet = vec![0u8; 24];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&24u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 18, 0, 9]);
        assert!(v6_runtime.is_fake_destination(&packet));
        assert!(!v6_runtime.is_fake_destination(&[0, 1, 2]));

        let v4_only = runtime();
        assert_eq!(
            v4_only.fake_prefixes(),
            vec!["198.18.0.0/15".parse().unwrap()]
        );
        assert_eq!(v4_only.max_envelope_len(), 6);
        assert!(!v4_only.contains_fake_address("fd74:696e:6563:7400::9".parse().unwrap()));
    }

    #[test]
    fn route_hint_for_expired_mapping_is_none() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.7".parse().unwrap();
        runtime.state.lock().unwrap().mappings.insert(
            fake,
            Mapping {
                domain: "expired.test".into(),
                preferred_route: None,
                real: vec!["192.0.2.7".parse().unwrap()],
                expires: Instant::now() - Duration::from_secs(1),
                next_real: 0,
            },
        );
        assert!(runtime.route_hint_for_fake(fake).is_none());
    }

    #[test]
    fn translate_outbound_rejects_ah_and_full_flow_tables() {
        let mut runtime = runtime();
        let fake: IpAddr = "198.18.0.13".parse().unwrap();
        let real: IpAddr = "192.0.2.13".parse().unwrap();
        install_mapping(&runtime, fake, real);

        // AH is not a trackable flow.
        let mut ah = vec![0u8; 20];
        ah[0] = 0x45;
        ah[2..4].copy_from_slice(&20u16.to_be_bytes());
        ah[9] = 51;
        ah[12..16].copy_from_slice(&[10, 64, 0, 1]);
        ah[16..20].copy_from_slice(&[198, 18, 0, 13]);
        assert!(!runtime.translate_outbound(&mut ah));

        // A full source-flow table rejects new flows.
        runtime.config.max_entries = 1;
        let mut first = udp_packet([10, 0, 0, 5], [198, 18, 0, 13], 40_001);
        let mut second = udp_packet([10, 0, 0, 6], [198, 18, 0, 13], 40_001);
        assert!(runtime.translate_outbound(&mut first));
        assert!(!runtime.translate_outbound(&mut second));
    }

    #[test]
    fn same_base_flow_collisions_allocate_a_new_wire_id_or_fail() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.14".parse().unwrap();
        let real: IpAddr = "192.0.2.14".parse().unwrap();
        install_mapping(&runtime, fake, real);

        // Two flows from the same source with different local ports collide on
        // the base key; the second one is assigned a fresh wire port.
        let mut first = udp_packet([10, 0, 0, 7], [198, 18, 0, 14], 40_002);
        let mut second = udp_packet([10, 0, 0, 7], [198, 18, 0, 14], 40_003);
        assert!(runtime.translate_outbound(&mut first));
        assert!(runtime.translate_outbound(&mut second));
        assert_ne!(
            u16::from_be_bytes([first[20], first[21]]),
            u16::from_be_bytes([second[20], second[21]])
        );

        // A protocol without a writable ID field cannot host a second flow on
        // the same base key.
        let mut opaque = vec![0u8; 24];
        opaque[0] = 0x45;
        opaque[2..4].copy_from_slice(&24u16.to_be_bytes());
        opaque[9] = 99;
        opaque[12..16].copy_from_slice(&[10, 0, 0, 7]);
        opaque[16..20].copy_from_slice(&[198, 18, 0, 14]);
        assert!(runtime.translate_outbound(&mut opaque));
        assert!(!runtime.translate_outbound(&mut opaque));
    }

    #[test]
    fn translate_inbound_requires_an_unexpired_wire_flow() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.15".parse().unwrap();
        let real: IpAddr = "192.0.2.15".parse().unwrap();
        install_mapping(&runtime, fake, real);

        // No outbound flow was recorded.
        let mut reply = udp_packet([192, 0, 2, 15], [198, 18, 0, 15], 53);
        reply[16..20].copy_from_slice(&[10, 64, 0, 1]);
        assert!(!runtime.translate_inbound(&mut reply, Some(fake)));

        // An expired source flow is removed on the inbound path.
        let mut outbound = udp_packet([10, 0, 0, 8], [198, 18, 0, 15], 40_004);
        assert!(runtime.translate_outbound(&mut outbound));
        {
            let mut state = runtime.state.lock().unwrap();
            let source_key = *state.wire_flows.values().next().unwrap();
            let flow = state.source_flows.get_mut(&source_key).unwrap();
            flow.expires = Instant::now() - Duration::from_secs(1);
        }
        let mut reply = udp_packet([192, 0, 2, 15], [198, 18, 0, 15], 53);
        reply[16..20].copy_from_slice(&[10, 64, 0, 1]);
        assert!(!runtime.translate_inbound(&mut reply, Some(fake)));
    }

    #[test]
    fn allocate_fake_renews_live_mappings_and_allocates_ipv6() {
        let runtime = FakeIpRuntime::new(
            FakeIpConfig {
                listen: "127.0.0.1:5354".parse().unwrap(),
                upstream_dns: vec![serde_yaml::from_str("1.1.1.1").unwrap()],
                disable_ipv6: false,
                ipv4_pool: "198.18.0.0/15".parse().unwrap(),
                ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
                min_cache_ttl_secs: 60,
                max_cache_ttl_secs: 3600,
                max_entries: 32,
            },
            Default::default(),
            Vec::new(),
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        );
        let real = vec!["192.0.2.16".parse().unwrap()];
        let first = runtime
            .allocate_fake("renew.test", false, real.clone(), None)
            .expect("first allocation succeeds");
        assert!(runtime.contains_fake_address(first));
        let second = runtime
            .allocate_fake("renew.test", false, real.clone(), None)
            .expect("live mapping is renewed in place");
        assert_eq!(first, second);

        let v6 = runtime
            .allocate_fake(
                "ipv6.test",
                true,
                vec!["2001:db8::16".parse().unwrap()],
                None,
            )
            .expect("ipv6 allocation succeeds");
        assert!(v6.is_ipv6());
    }

    #[test]
    fn route_hint_for_live_mapping_refreshes_expiry() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.8".parse().unwrap();
        runtime.state.lock().unwrap().mappings.insert(
            fake,
            Mapping {
                domain: "live.test".into(),
                preferred_route: None,
                real: vec!["192.0.2.8".parse().unwrap()],
                expires: Instant::now() + Duration::from_secs(60),
                next_real: 0,
            },
        );
        let hint = runtime
            .route_hint_for_fake(fake)
            .expect("live mapping yields a hint");
        assert_eq!(hint.domain, "live.test");
        assert!(hint.preferred_route.is_none());
    }

    #[test]
    fn translate_inbound_requires_the_source_flow_record() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.16".parse().unwrap();
        let real: IpAddr = "192.0.2.16".parse().unwrap();
        install_mapping(&runtime, fake, real);
        let mut outbound = udp_packet([10, 0, 0, 9], [198, 18, 0, 16], 40_005);
        assert!(runtime.translate_outbound(&mut outbound));
        // Drop the source-flow record while keeping the wire-flow lookup.
        {
            let mut state = runtime.state.lock().unwrap();
            let source_key = *state.wire_flows.values().next().unwrap();
            state.source_flows.remove(&source_key);
        }
        let mut reply = udp_packet([192, 0, 2, 16], [198, 18, 0, 16], 53);
        reply[16..20].copy_from_slice(&[10, 64, 0, 1]);
        assert!(!runtime.translate_inbound(&mut reply, Some(fake)));
    }

    #[tokio::test]
    async fn answer_allocates_fake_addresses_from_overlay_a_and_aaaa_records() {
        let mut loader = RouteSetLoader::new(".");
        let site_id = loader.load_inline("alloc.test\n").unwrap();
        let v6_runtime = FakeIpRuntime::new(
            FakeIpConfig {
                listen: "127.0.0.1:5354".parse().unwrap(),
                upstream_dns: vec![serde_yaml::from_str("1.1.1.1").unwrap()],
                disable_ipv6: false,
                ipv4_pool: "198.18.0.0/15".parse().unwrap(),
                ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
                min_cache_ttl_secs: 60,
                max_cache_ttl_secs: 3600,
                max_entries: 32,
            },
            Arc::new(loader.finish()),
            vec![site_id],
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        );

        // IPv4: the overlay resolver returns a real A record and the runtime
        // answers with a FakeIP address from the pool.
        let (requests, mut requests_rx) = mpsc::channel(1);
        v6_runtime.install_overlay_dns(requests);
        let responder = tokio::spawn(async move {
            let request = requests_rx.recv().await.unwrap();
            let original = Message::from_vec(&request.wire).unwrap();
            let mut response = Message::response(original.metadata.id, original.metadata.op_code);
            response.queries = original.queries;
            response.answers.push(Record::from_rdata(
                response.queries[0].name.clone(),
                300,
                RData::A(A("192.0.2.53".parse().unwrap())),
            ));
            assert!(
                request
                    .response
                    .send(Ok(OverlayDnsResponse {
                        wire: response.to_vec().unwrap(),
                        preferred_route: RoutePreference::Exit("exit".into()),
                    }))
                    .is_ok()
            );
        });
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("alloc.test.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_vec(&v6_runtime.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
        assert!(matches!(
            &response.answers[0].data,
            RData::A(answer) if v6_runtime.contains_fake_address(IpAddr::V4(answer.0))
        ));
        responder.await.unwrap();

        // IPv6: an AAAA answer is rewritten into the IPv6 FakeIP pool.
        let (requests, mut requests_rx) = mpsc::channel(1);
        v6_runtime.install_overlay_dns(requests);
        let responder = tokio::spawn(async move {
            let request = requests_rx.recv().await.unwrap();
            let original = Message::from_vec(&request.wire).unwrap();
            let mut response = Message::response(original.metadata.id, original.metadata.op_code);
            response.queries = original.queries;
            response.answers.push(Record::from_rdata(
                response.queries[0].name.clone(),
                300,
                RData::AAAA(AAAA("2001:db8::53".parse().unwrap())),
            ));
            assert!(
                request
                    .response
                    .send(Ok(OverlayDnsResponse {
                        wire: response.to_vec().unwrap(),
                        preferred_route: RoutePreference::Exit("exit".into()),
                    }))
                    .is_ok()
            );
        });
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("alloc.test.").unwrap(),
            RecordType::AAAA,
        ));
        let response =
            Message::from_vec(&v6_runtime.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
        assert!(matches!(
            &response.answers[0].data,
            RData::AAAA(answer) if v6_runtime.contains_fake_address(IpAddr::V6(answer.0))
        ));
        responder.await.unwrap();

        // An overlay response without matching address records is returned
        // unchanged instead of being rewritten.
        let (requests, mut requests_rx) = mpsc::channel(1);
        v6_runtime.install_overlay_dns(requests);
        let responder = tokio::spawn(async move {
            let request = requests_rx.recv().await.unwrap();
            let original = Message::from_vec(&request.wire).unwrap();
            let mut response = Message::response(original.metadata.id, original.metadata.op_code);
            response.queries = original.queries;
            assert!(
                request
                    .response
                    .send(Ok(OverlayDnsResponse {
                        wire: response.to_vec().unwrap(),
                        preferred_route: RoutePreference::Exit("exit".into()),
                    }))
                    .is_ok()
            );
        });
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("empty.alloc.test.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_vec(&v6_runtime.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
        assert!(response.answers.is_empty());
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn answer_returns_servfail_when_upstream_is_unreachable() {
        let runtime = runtime_with_upstream("127.0.0.1:9");
        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("unreachable.test.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_vec(&runtime.answer(&request.to_vec().unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn join_dns_listeners_reports_join_and_drain_errors() {
        // A listener task that fails to start (JoinError) becomes the headline
        // error while its sibling is cancelled and joined.
        let parent = CancellationToken::new();
        let mut listeners = TaskGroup::<Result<()>>::new();
        let token = listeners.token();
        listeners.spawn(async { panic!("listener crashed") });
        listeners.spawn(async move {
            token.cancelled().await;
            Ok(())
        });
        let error = join_dns_listeners(listeners, parent).await.unwrap_err();
        assert!(error.to_string().contains("listener task failed"));

        // Cancellation before any task finishes drains the rest and reports
        // the first drained failure, including later JoinErrors.
        let parent = CancellationToken::new();
        parent.cancel();
        let mut listeners = TaskGroup::<Result<()>>::new();
        listeners.spawn(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Err(anyhow!("late failure"))
        });
        listeners.spawn(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            panic!("late panic");
        });
        let error = join_dns_listeners(listeners, parent).await.unwrap_err();
        assert!(error.to_string().contains("late failure"));
    }

    #[tokio::test]
    async fn bound_listeners_answer_udp_and_tcp_queries() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            loop {
                let mut wire = vec![0_u8; 512];
                let (size, peer) = upstream.recv_from(&mut wire).await.unwrap();
                let request = Message::from_vec(&wire[..size]).unwrap();
                let mut response = Message::response(request.metadata.id, request.metadata.op_code);
                response.queries = request.queries.clone();
                response.answers.push(Record::from_rdata(
                    response.queries[0].name.clone(),
                    300,
                    RData::A(A("192.0.2.77".parse().unwrap())),
                ));
                upstream
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let runtime = Arc::new(FakeIpRuntime::new(
            FakeIpConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream_dns: vec![DnsServer::from_socket_addr(upstream_address)],
                disable_ipv6: true,
                ipv4_pool: "198.18.0.0/15".parse().unwrap(),
                ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
                min_cache_ttl_secs: 60,
                max_cache_ttl_secs: 3600,
                max_entries: 32,
            },
            Default::default(),
            Vec::new(),
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        ));
        let (udp, tcp) = runtime.bind().await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        let tcp_address = tcp.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let serve = {
            let runtime = runtime.clone();
            let cancellation = cancellation.clone();
            tokio::spawn(async move { runtime.serve_bound(udp, tcp, cancellation).await })
        };

        let mut query = Message::query();
        query.metadata.id = 77;
        query.queries.push(Query::query(
            Name::from_ascii("bound.test.").unwrap(),
            RecordType::A,
        ));
        let wire = query.to_vec().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // A malformed datagram is answered with nothing and must not take the
        // listener down.
        client.send_to(&[1, 2, 3], udp_address).await.unwrap();
        client.send_to(&wire, udp_address).await.unwrap();
        let mut buffer = vec![0_u8; 512];
        let (size, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&buffer[..size]).unwrap();
        assert_eq!(response.metadata.id, 77);
        assert!(matches!(
            &response.answers[0].data,
            RData::A(answer) if answer.0 == "192.0.2.77".parse::<Ipv4Addr>().unwrap()
        ));

        let mut stream = TcpStream::connect(tcp_address).await.unwrap();
        stream
            .write_u16(u16::try_from(wire.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&wire).await.unwrap();
        let size = usize::from(
            tokio::time::timeout(Duration::from_secs(5), stream.read_u16())
                .await
                .unwrap()
                .unwrap(),
        );
        let mut response = vec![0_u8; size];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().metadata.id, 77);

        // Closing the client lets the connection task finish on its own, so
        // the listener loop reaps it before shutdown.
        drop(stream);
        tokio::time::sleep(Duration::from_millis(50)).await;

        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn overlay_forwarding_reports_channel_and_response_failures() {
        let runtime = runtime();
        let mut query = Message::query();
        query.metadata.id = 42;
        query.queries.push(Query::query(
            Name::from_ascii("broken.test.").unwrap(),
            RecordType::A,
        ));
        let wire = query.to_vec().unwrap();

        // The resolver channel is gone.
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        runtime.install_overlay_dns(sender);
        let error = runtime
            .forward_overlay("broken.test", &wire)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("stopped"));

        // The resolver drops the request without responding.
        let (sender, mut receiver) = mpsc::channel(1);
        runtime.install_overlay_dns(sender);
        let responder = tokio::spawn(async move {
            drop(receiver.recv().await.unwrap());
        });
        let error = runtime
            .forward_overlay("broken.test", &wire)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("canceled"));
        responder.await.unwrap();

        // The resolver reports an upstream failure.
        let (sender, mut receiver) = mpsc::channel(1);
        runtime.install_overlay_dns(sender);
        let responder = tokio::spawn(async move {
            let request = receiver.recv().await.unwrap();
            assert!(request.response.send(Err("resolver boom".into())).is_ok());
        });
        let error = runtime
            .forward_overlay("broken.test", &wire)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("resolver boom"));
        responder.await.unwrap();

        // The resolver returns a response that is not a DNS message.
        let (sender, mut receiver) = mpsc::channel(1);
        runtime.install_overlay_dns(sender);
        let responder = tokio::spawn(async move {
            let request = receiver.recv().await.unwrap();
            assert!(
                request
                    .response
                    .send(Ok(OverlayDnsResponse {
                        wire: vec![1, 2, 3],
                        preferred_route: RoutePreference::Direct,
                    }))
                    .is_ok()
            );
        });
        assert!(runtime.forward_overlay("broken.test", &wire).await.is_err());
        responder.await.unwrap();

        // The resolver returns a response that does not match the request.
        let (sender, mut receiver) = mpsc::channel(1);
        runtime.install_overlay_dns(sender);
        let responder = tokio::spawn(async move {
            let request = receiver.recv().await.unwrap();
            let response = Message::response(43, hickory_proto::op::OpCode::Query);
            assert!(
                request
                    .response
                    .send(Ok(OverlayDnsResponse {
                        wire: response.to_vec().unwrap(),
                        preferred_route: RoutePreference::Direct,
                    }))
                    .is_ok()
            );
        });
        let error = runtime
            .forward_overlay("broken.test", &wire)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn matched_answers_pass_through_or_fail_closed_on_edge_cases() {
        let mut loader = RouteSetLoader::new(".");
        let site_id = loader
            .load_inline("nx.test\nforeign.test\nany.test\nfull.test")
            .unwrap();
        let config = FakeIpConfig {
            listen: "127.0.0.1:5354".parse().unwrap(),
            upstream_dns: vec![serde_yaml::from_str("1.1.1.1").unwrap()],
            disable_ipv6: false,
            ipv4_pool: "198.18.0.0/15".parse().unwrap(),
            ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
            min_cache_ttl_secs: 60,
            max_cache_ttl_secs: 3600,
            max_entries: 32,
        };
        let runtime = FakeIpRuntime::new(
            config.clone(),
            Arc::new(loader.finish()),
            vec![site_id],
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        );
        let (sender, mut receiver) = mpsc::channel(8);
        runtime.install_overlay_dns(sender);
        let responder = tokio::spawn(async move {
            while let Some(request) = receiver.recv().await {
                let original = Message::from_vec(&request.wire).unwrap();
                let mut response =
                    Message::response(original.metadata.id, original.metadata.op_code);
                response.queries = original.queries;
                match request.domain.as_str() {
                    "nx.test" => {
                        response.metadata.response_code = ResponseCode::NXDomain;
                    }
                    "foreign.test" => {
                        // An AAAA question answered with only A records has no
                        // usable real address and is returned unchanged.
                        response.answers.push(Record::from_rdata(
                            response.queries[0].name.clone(),
                            300,
                            RData::A(A("192.0.2.88".parse().unwrap())),
                        ));
                    }
                    other => unreachable!("unexpected overlay domain {other}"),
                }
                assert!(
                    request
                        .response
                        .send(Ok(OverlayDnsResponse {
                            wire: response.to_vec().unwrap(),
                            preferred_route: RoutePreference::Direct,
                        }))
                        .is_ok()
                );
            }
        });

        // NXDOMAIN answers are passed through without allocating a FakeIP.
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("nx.test.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_vec(&runtime.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(runtime.state.lock().unwrap().mappings.is_empty());

        // A matched ANY query is answered with NODATA locally.
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("any.test.").unwrap(),
            RecordType::ANY,
        ));
        let response =
            Message::from_vec(&runtime.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());

        // Records of a different type than the question pass through unchanged.
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("foreign.test.").unwrap(),
            RecordType::AAAA,
        ));
        let response =
            Message::from_vec(&runtime.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
        assert!(matches!(&response.answers[0].data, RData::A(_)));
        assert!(runtime.state.lock().unwrap().mappings.is_empty());

        // An exhausted FakeIP pool fails closed with SERVFAIL.
        let mut exhausted = FakeIpRuntime::new(
            config,
            runtime.registry.clone(),
            runtime.domain_sites.to_vec(),
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(Observability::new(0)),
        );
        exhausted.config.max_entries = 0;
        let (sender, mut receiver) = mpsc::channel(1);
        exhausted.install_overlay_dns(sender);
        let full_responder = tokio::spawn(async move {
            let request = receiver.recv().await.unwrap();
            let original = Message::from_vec(&request.wire).unwrap();
            let mut response = Message::response(original.metadata.id, original.metadata.op_code);
            response.queries = original.queries;
            response.answers.push(Record::from_rdata(
                response.queries[0].name.clone(),
                300,
                RData::A(A("192.0.2.90".parse().unwrap())),
            ));
            assert!(
                request
                    .response
                    .send(Ok(OverlayDnsResponse {
                        wire: response.to_vec().unwrap(),
                        preferred_route: RoutePreference::Direct,
                    }))
                    .is_ok()
            );
        });
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("full.test.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_vec(&exhausted.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        full_responder.await.unwrap();

        drop(runtime);
        tokio::time::timeout(Duration::from_secs(5), responder)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn cache_dns_eviction_prefers_expired_entries() {
        let mut runtime = runtime();
        runtime.config.max_entries = 1;
        let response = Message::response(1, hickory_proto::op::OpCode::Query);
        runtime.cache_dns(("old.test".into(), 1), &response, None);
        runtime
            .state
            .lock()
            .unwrap()
            .dns_cache
            .get_mut(&("old.test".into(), 1))
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        runtime.cache_dns(("new.test".into(), 1), &response, None);
        assert!(runtime.cached_dns(&("old.test".into(), 1), 1).is_none());
        assert!(runtime.cached_dns(&("new.test".into(), 1), 1).is_some());
    }

    #[test]
    fn translate_inbound_rejects_untrackable_protocols() {
        let runtime = runtime();
        let mut ah = vec![0u8; 20];
        ah[0] = 0x45;
        ah[2..4].copy_from_slice(&20u16.to_be_bytes());
        ah[9] = 51;
        ah[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ah[16..20].copy_from_slice(&[10, 64, 0, 1]);
        assert!(!runtime.translate_inbound(&mut ah, None));
    }

    #[test]
    fn wire_id_allocation_skips_occupied_candidates() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.30".parse().unwrap();
        let real: IpAddr = "192.0.2.30".parse().unwrap();
        install_mapping(&runtime, fake, real);

        // Occupy the first candidate the allocator will probe so the scan has
        // to skip it. Pin the prune clock so the orphan entry survives.
        {
            let mut state = runtime.state.lock().unwrap();
            state.wire_flows.insert(
                WireFlowKey {
                    real_destination: real,
                    local_source: "10.64.0.1".parse().unwrap(),
                    protocol: 17,
                    remote_id: 53,
                    local_id: 1,
                },
                SourceFlowKey {
                    source: "10.9.9.9".parse().unwrap(),
                    fake_destination: fake,
                    wire_source: "10.64.0.1".parse().unwrap(),
                    protocol: 17,
                    local_id: 1,
                    remote_id: 53,
                },
            );
            state.last_prune = Some(Instant::now());
        }

        let mut first = udp_packet([10, 0, 0, 1], [198, 18, 0, 30], 40_000);
        let mut second = udp_packet([10, 0, 0, 2], [198, 18, 0, 30], 40_000);
        assert!(runtime.translate_outbound(&mut first));
        assert_eq!(u16::from_be_bytes([first[20], first[21]]), 40_000);
        assert!(runtime.translate_outbound(&mut second));
        assert_eq!(u16::from_be_bytes([second[20], second[21]]), 2);
    }

    #[test]
    fn flows_without_writable_ids_cannot_share_a_wire_key() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.32".parse().unwrap();
        let real: IpAddr = "192.0.2.32".parse().unwrap();
        install_mapping(&runtime, fake, real);

        // Protocol 99 has no transport identifier to rewrite, so two sources
        // collapsing onto the same wire key cannot coexist.
        let opaque = |source: [u8; 4]| {
            let mut packet = vec![0u8; 24];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&24u16.to_be_bytes());
            packet[9] = 99;
            packet[12..16].copy_from_slice(&source);
            packet[16..20].copy_from_slice(&[198, 18, 0, 32]);
            packet
        };
        let mut first = opaque([10, 0, 0, 7]);
        let mut second = opaque([10, 0, 0, 8]);
        assert!(runtime.translate_outbound(&mut first));
        assert!(!runtime.translate_outbound(&mut second));
    }

    #[test]
    fn wire_id_allocation_fails_when_all_candidates_are_occupied() {
        let runtime = runtime();
        let fake: IpAddr = "198.18.0.31".parse().unwrap();
        let real: IpAddr = "192.0.2.31".parse().unwrap();
        install_mapping(&runtime, fake, real);
        let mut first = udp_packet([10, 0, 0, 1], [198, 18, 0, 31], 40_000);
        assert!(runtime.translate_outbound(&mut first));

        {
            let mut state = runtime.state.lock().unwrap();
            let wire_source: IpAddr = "10.64.0.1".parse().unwrap();
            let orphan = SourceFlowKey {
                source: "10.9.9.9".parse().unwrap(),
                fake_destination: fake,
                wire_source,
                protocol: 17,
                local_id: 0,
                remote_id: 0,
            };
            for local_id in 1..=u16::MAX {
                state.wire_flows.insert(
                    WireFlowKey {
                        real_destination: real,
                        local_source: wire_source,
                        protocol: 17,
                        remote_id: 53,
                        local_id,
                    },
                    orphan,
                );
            }
            state.last_prune = Some(Instant::now());
        }

        let mut second = udp_packet([10, 0, 0, 2], [198, 18, 0, 31], 40_000);
        assert!(!runtime.translate_outbound(&mut second));
    }

    #[tokio::test]
    async fn udp_socket_pool_reuses_idle_slots_and_waits_for_capacity() {
        let pool = Arc::new(UdpSocketPool::default());
        let server: SocketAddr = "127.0.0.1:9".parse().unwrap();

        // An IPv6 upstream binds an IPv6 wildcard socket.
        drop(pool.acquire("[::1]:9".parse().unwrap()).await.unwrap());

        let first = pool.acquire(server).await.unwrap();
        // The only slot is busy, so a second lease creates another slot.
        let second = pool.acquire(server).await.unwrap();
        assert_eq!(pool.slots.lock().await[&server].len(), 2);
        // Dropping a lease makes its slot reusable instead of creating more.
        drop(second);
        let reused = pool.acquire(server).await.unwrap();
        assert_eq!(pool.slots.lock().await[&server].len(), 2);
        drop(reused);

        // With every slot busy at capacity, acquirers wait for a release.
        let mut leases = vec![first];
        while leases.len() < MAX_UPSTREAM_UDP_SOCKETS {
            leases.push(pool.acquire(server).await.unwrap());
        }
        let waiting = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire(server).await.unwrap() })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());
        drop(leases.pop());
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn forward_udp_skips_wrapping_zero_ids_and_rejects_garbage() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut wire = vec![0_u8; 512];
            let (size, peer) = upstream.recv_from(&mut wire).await.unwrap();
            let request = Message::from_vec(&wire[..size]).unwrap();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.queries = request.queries;
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let pool = UdpSocketPool::default();
        let server = DnsServer::from_socket_addr(address);
        let mut request = Message::query();
        request.metadata.id = 555;
        request.queries.push(Query::query(
            Name::from_ascii("wrap.test.").unwrap(),
            RecordType::A,
        ));
        let wire = request.to_vec().unwrap();

        // Seed the pool, then force the next upstream ID to wrap through zero.
        drop(pool.acquire(address).await.unwrap());
        pool.slots.lock().await[&address][0]
            .next_id
            .store(0xffff_0000, Ordering::Relaxed);
        let response = forward_udp(&server, &wire, &pool).await.unwrap();
        assert_eq!(response.metadata.id, request.metadata.id);
        server_task.await.unwrap();

        assert!(forward_udp(&server, &[1, 2, 3], &pool).await.is_err());
    }

    #[tokio::test]
    async fn tcp_upstream_exchange_reports_connect_failures() {
        // Nothing listens on the loopback discard port.
        let server = DnsServer::from_socket_addr("127.0.0.1:9".parse().unwrap());
        let mut request = Message::query();
        request.queries.push(Query::query(
            Name::from_ascii("refused.test.").unwrap(),
            RecordType::A,
        ));
        assert!(
            forward_tcp(&server, &request.to_vec().unwrap())
                .await
                .is_err()
        );
    }
}
