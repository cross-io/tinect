use super::*;

#[derive(Clone)]
pub struct SecureRoute {
    pub prefix: IpNet,
    pub exit: String,
    pub priority: u32,
    /// Outgoing send capability only. Physical receive and Link lifecycle
    /// stay on the concrete carrier Link; see `TunRouter::attach_link`.
    pub link: LinkRef,
    pub circuit_id: CircuitId,
    pub data_key: chacha20poly1305::Key,
    pub destination_key: VerifyingKey,
    pub healthy: Arc<std::sync::atomic::AtomicBool>,
    pub mtu: u16,
    pub lease_epoch: u64,
    pub send_gate: Arc<std::sync::atomic::AtomicBool>,
    pub send_budget: Arc<AtomicUsize>,
}

/// Immutable source-side routing state. Route matching and secure bindings
/// are replaced together so a packet can never observe priorities from one
/// snapshot with bindings from another.
pub struct RouteSnapshot {
    pub bindings: Vec<SecureRoute>,
    pub imports: Vec<RouteImport>,
    prefix_choices: HashMap<IpNet, PrefixRouteChoice>,
    domain_bindings: Vec<DomainSecureRoute>,
    domain_binding_indices: BTreeMap<crate::route_sets::SetId, Vec<usize>>,
    domain_imports: Vec<crate::config::DomainRouteImport>,
    route_sets: Arc<crate::route_sets::RouteSetRegistry>,
    direct_prefix_routes: Vec<(IpNet, u32)>,
    direct_domain_routes: Vec<(crate::route_sets::SetId, u32)>,
}

#[derive(Clone, Copy)]
pub(super) enum RouteSelection<'a> {
    Secure(&'a SecureRoute),
    Direct,
}

pub(super) enum DomainResolutionCandidate {
    Secure {
        binding: Box<SecureRoute>,
        upstream_dns: Arc<[crate::config::DnsServer]>,
    },
    Direct {
        priority: u32,
    },
}

pub(super) fn direct_beats_secure(direct_priority: u32, secure_priority: u32) -> bool {
    direct_priority > secure_priority
}

impl DomainResolutionCandidate {
    fn priority(&self) -> u32 {
        match self {
            Self::Secure { binding, .. } => binding.priority,
            Self::Direct { priority } => *priority,
        }
    }
}

struct DomainSecureRoute {
    set_id: crate::route_sets::SetId,
    binding: SecureRoute,
    upstream_dns: Arc<[crate::config::DnsServer]>,
}

/// A route import with its currently usable bindings resolved by index. This
/// is rebuilt only when a RouteSnapshot changes, keeping source-side packet
/// selection free of binding-index construction on the packet path.
#[derive(Default)]
struct PrefixRouteChoice {
    bindings: Vec<usize>,
    direct_priority: Option<u32>,
}

const DNS_QUERY_MAGIC: &[u8; 4] = b"TDQ1";
const DNS_RESPONSE_MAGIC: &[u8; 4] = b"TDR1";
pub(super) const DNS_RESPONSE_CHUNK: usize = 900;
/// Upper bound for in-flight source-side Circuit DNS queries. `pending` is
/// otherwise unbounded per client instance and keyed by wrapping token.
pub(super) const MAX_PENDING_DNS_QUERIES: usize = 256;
/// Upper bound for response chunks per query and bytes per chunk. Real DNS
/// responses are ~73x900B; anything larger is a malicious or corrupt exit.
/// (64 chunks x 900B = 57,600B, so `MAX_DNS_RESPONSE_BYTES` below is a
/// ceiling that reassembly provably cannot reach -- no separate accounting
/// needed on the hot path.)
pub(super) const MAX_DNS_RESPONSE_CHUNKS: u16 = 64;
pub(super) const MAX_DNS_RESPONSE_BYTES: usize = 65535;

pub(super) struct PendingDnsQuery {
    pub(super) link_instance: u64,
    pub(super) circuit_id: CircuitId,
    pub(super) sender: Option<oneshot::Sender<Result<Vec<u8>, String>>>,
    pub(super) chunks: Vec<Option<Vec<u8>>>,
}

#[derive(Default)]
pub(super) struct CircuitDnsState {
    next_token: u64,
    senders: HashMap<(u64, CircuitId), crypto::SenderSession>,
    pub(super) pending: HashMap<u64, PendingDnsQuery>,
    /// Insertion-ordered tokens for oldest-first eviction. Entries go stale
    /// when queries complete or time out; eviction skips missing tokens.
    /// (Token order is not wall-clock order across a `u64` wrap, but eviction
    /// only needs *an* oldest-first approximation under pressure.)
    order: std::collections::VecDeque<u64>,
}

/// Source-side request correlation for DNS carried inside authenticated
/// Circuits. State is shared across route snapshots, so changing priorities
/// does not duplicate keys or pending responses.
#[derive(Clone, Default)]
pub struct CircuitDnsClient {
    pub(super) state: Arc<std::sync::Mutex<CircuitDnsState>>,
}

/// Removes request correlation when its query future is dropped. A timeout
/// already removes the token explicitly, but callers can also cancel the
/// future while a Circuit response is in flight (for example during DNS
/// listener shutdown).
pub(super) struct PendingDnsRegistration {
    state: Arc<std::sync::Mutex<CircuitDnsState>>,
    token: u64,
}

impl PendingDnsRegistration {
    pub(super) fn new(state: Arc<std::sync::Mutex<CircuitDnsState>>, token: u64) -> Self {
        Self { state, token }
    }
}

impl Drop for PendingDnsRegistration {
    fn drop(&mut self) {
        self.state
            .lock()
            .expect("Circuit DNS state lock")
            .pending
            .remove(&self.token);
    }
}

impl CircuitDnsClient {
    pub(super) async fn query(
        &self,
        binding: &SecureRoute,
        upstream: &crate::config::DnsServer,
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !binding.healthy.load(Ordering::Acquire) || !binding.send_gate.load(Ordering::Acquire) {
            return Err("Circuit DNS candidate is no longer healthy".into());
        }
        let (token, receiver, frame) = {
            let mut state = self.state.lock().expect("Circuit DNS state lock");
            state.next_token = state.next_token.wrapping_add(1).max(1);
            let token = state.next_token;
            if state.pending.len() >= MAX_PENDING_DNS_QUERIES {
                // Evict oldest-first; tell the victim its query is gone
                // instead of leaving it hanging until timeout.
                while let Some(oldest) = state.order.pop_front() {
                    if let Some(victim) = state.pending.remove(&oldest) {
                        if let Some(sender) = victim.sender {
                            let _ =
                                sender.send(Err("Circuit DNS query evicted under pressure".into()));
                        }
                        break;
                    }
                }
            }
            // The order queue goes stale as queries complete or time out
            // (their tokens are removed from `pending` elsewhere). Compact it
            // so eviction scans stay O(cap), not O(history).
            if state.order.len() > 2 * MAX_PENDING_DNS_QUERIES {
                let live: HashSet<u64> = state.pending.keys().copied().collect();
                state.order.retain(|token| live.contains(token));
            }
            let payload = encode_dns_query(token, upstream, wire)?;
            if !user_packet_fits_current_budget(
                payload.len(),
                binding.send_budget.load(Ordering::Acquire),
            ) {
                return Err("DNS query exceeds the active Circuit MTU".into());
            }
            let (sender, receiver) = oneshot::channel();
            state.pending.insert(
                token,
                PendingDnsQuery {
                    link_instance: binding.link.instance(),
                    circuit_id: binding.circuit_id,
                    sender: Some(sender),
                    chunks: Vec::new(),
                },
            );
            state.order.push_back(token);
            let sender = state
                .senders
                .entry((binding.link.instance(), binding.circuit_id))
                .or_insert_with(|| {
                    crypto::SenderSession::dns_from_key(binding.circuit_id, binding.data_key)
                });
            let frame = sender
                .encrypt(&payload)
                .map_err(|error| error.to_string())?
                .to_vec();
            (token, receiver, frame)
        };
        let _pending = PendingDnsRegistration::new(self.state.clone(), token);
        if let Err(error) = binding.link.send_forward(&frame) {
            return Err(error.to_string());
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("Circuit DNS response was canceled".into()),
            Err(_) => Err("Circuit DNS response timed out".into()),
        }
    }

    pub(super) fn complete(&self, payload: &[u8]) -> Result<(), String> {
        let (token, status, index, total, chunk) = decode_dns_response(payload)?;
        let mut state = self.state.lock().expect("Circuit DNS state lock");
        let Some(pending) = state.pending.get_mut(&token) else {
            return Err("unknown or expired Circuit DNS token".into());
        };
        if status != 0 {
            let error = String::from_utf8_lossy(chunk).into_owned();
            if let Some(sender) = pending.sender.take() {
                let _ = sender.send(Err(error));
            }
            state.pending.remove(&token);
            return Ok(());
        }
        if total == 0
            || total > MAX_DNS_RESPONSE_CHUNKS
            || index >= total
            || chunk.len() > DNS_RESPONSE_CHUNK
        {
            // Keep state for recovery: DATAGRAMs are unreliable and
            // unordered, so a corrupt chunk must not kill a query that later
            // valid chunks can still assemble (`try_recv` stays pending and
            // the 5s query timeout bounds the wait). See
            // `dns_response_range_and_count_errors_keep_state_for_recovery`.
            return Err("invalid Circuit DNS response chunk range".into());
        }
        if pending.chunks.is_empty() {
            pending.chunks.resize(usize::from(total), None);
        } else if pending.chunks.len() != usize::from(total) {
            // Same recovery rationale as above: an inconsistent count may be
            // a stale/duplicate chunk, not a dead query.
            return Err("inconsistent Circuit DNS response chunk count".into());
        }
        pending.chunks[usize::from(index)] = Some(chunk.to_vec());
        debug_assert!(
            pending.chunks.iter().flatten().map(Vec::len).sum::<usize>() <= MAX_DNS_RESPONSE_BYTES,
            "chunk/total caps bound reassembly below the byte ceiling"
        );
        if pending.chunks.iter().all(Option::is_some) {
            let mut response = Vec::new();
            for chunk in &mut pending.chunks {
                response.extend(chunk.take().expect("all chunks were checked"));
            }
            if let Some(sender) = pending.sender.take() {
                let _ = sender.send(Ok(response));
            }
            state.pending.remove(&token);
        }
        Ok(())
    }

    pub fn remove_link(&self, link_instance: u64) {
        let mut state = self.state.lock().expect("Circuit DNS state lock");
        state
            .senders
            .retain(|(instance, _), _| *instance != link_instance);
        fail_pending(&mut state, |query| query.link_instance == link_instance);
    }

    pub fn remove_circuit(&self, link_instance: u64, circuit_id: CircuitId) {
        let mut state = self.state.lock().expect("Circuit DNS state lock");
        state.senders.remove(&(link_instance, circuit_id));
        fail_pending(&mut state, |query| {
            query.link_instance == link_instance && query.circuit_id == circuit_id
        });
    }
}

fn fail_pending(state: &mut CircuitDnsState, matches: impl Fn(&PendingDnsQuery) -> bool) {
    let tokens = state
        .pending
        .iter()
        .filter_map(|(token, query)| matches(query).then_some(*token))
        .collect::<Vec<_>>();
    for token in tokens {
        if let Some(mut query) = state.pending.remove(&token)
            && let Some(sender) = query.sender.take()
        {
            let _ = sender.send(Err("Circuit closed before DNS response".into()));
        }
    }
}

pub(super) fn encode_dns_query(
    token: u64,
    upstream: &crate::config::DnsServer,
    wire: &[u8],
) -> Result<Vec<u8>, String> {
    let mut payload = Vec::with_capacity(31 + wire.len());
    payload.extend_from_slice(DNS_QUERY_MAGIC);
    payload.extend_from_slice(&token.to_be_bytes());
    match upstream.ip() {
        IpAddr::V4(address) => {
            payload.push(4);
            payload.extend_from_slice(&[0; 12]);
            payload.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            payload.push(6);
            payload.extend_from_slice(&address.octets());
        }
    }
    payload.extend_from_slice(&upstream.port().to_be_bytes());
    payload.extend_from_slice(wire);
    Ok(payload)
}

pub(super) fn decode_dns_query(
    payload: &[u8],
) -> Result<(u64, crate::config::DnsServer, &[u8]), String> {
    if payload.len() < 31 || &payload[..4] != DNS_QUERY_MAGIC {
        return Err("malformed Circuit DNS query".into());
    }
    let token = u64::from_be_bytes(payload[4..12].try_into().expect("token length"));
    let ip = match payload[12] {
        4 => IpAddr::V4(Ipv4Addr::new(
            payload[25],
            payload[26],
            payload[27],
            payload[28],
        )),
        6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&payload[13..29]).expect("IPv6 length"),
        )),
        _ => return Err("invalid Circuit DNS upstream address family".into()),
    };
    let port = u16::from_be_bytes([payload[29], payload[30]]);
    if port == 0 {
        return Err("invalid Circuit DNS upstream port".into());
    }
    Ok((
        token,
        crate::config::DnsServer::from_socket_addr(std::net::SocketAddr::new(ip, port)),
        &payload[31..],
    ))
}

pub(super) fn encode_dns_response(
    token: u64,
    status: u8,
    index: u16,
    total: u16,
    chunk: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(17 + chunk.len());
    payload.extend_from_slice(DNS_RESPONSE_MAGIC);
    payload.extend_from_slice(&token.to_be_bytes());
    payload.push(status);
    payload.extend_from_slice(&index.to_be_bytes());
    payload.extend_from_slice(&total.to_be_bytes());
    payload.extend_from_slice(chunk);
    payload
}

pub(super) fn decode_dns_response(payload: &[u8]) -> Result<(u64, u8, u16, u16, &[u8]), String> {
    if payload.len() < 17 || &payload[..4] != DNS_RESPONSE_MAGIC {
        return Err("malformed Circuit DNS response".into());
    }
    Ok((
        u64::from_be_bytes(payload[4..12].try_into().expect("token length")),
        payload[12],
        u16::from_be_bytes([payload[13], payload[14]]),
        u16::from_be_bytes([payload[15], payload[16]]),
        &payload[17..],
    ))
}

impl RouteSnapshot {
    pub fn all_bindings(&self) -> impl Iterator<Item = &SecureRoute> {
        self.bindings
            .iter()
            .chain(self.domain_bindings.iter().map(|route| &route.binding))
    }

    pub fn has_healthy_domain_binding(&self) -> bool {
        !self.direct_domain_routes.is_empty()
            || self
                .domain_bindings
                .iter()
                .any(|route| route.binding.healthy.load(Ordering::Relaxed))
    }

    pub fn healthy_prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.bindings
            .iter()
            .filter(|binding| binding.healthy.load(Ordering::Acquire))
            .map(|binding| binding.prefix)
            .chain(self.direct_prefix_routes.iter().map(|(prefix, _)| *prefix))
    }

    pub fn new(bindings: Vec<SecureRoute>, imports: Vec<RouteImport>) -> Self {
        let prefix_choices = {
            let mut binding_indices = HashMap::new();
            for (index, binding) in bindings.iter().enumerate() {
                binding_indices
                    .entry((binding.prefix, binding.exit.as_str()))
                    .or_insert(index);
            }
            let mut choices = HashMap::<IpNet, PrefixRouteChoice>::new();
            for route in &imports {
                let choice = choices.entry(route.prefix).or_default();
                for candidate in &route.candidates {
                    let Some(index) = binding_indices
                        .get(&(route.prefix, candidate.node.as_str()))
                        .copied()
                    else {
                        continue;
                    };
                    if !choice.bindings.contains(&index) {
                        choice.bindings.push(index);
                    }
                }
            }
            choices
        };
        Self {
            bindings,
            imports,
            prefix_choices,
            domain_bindings: Vec::new(),
            domain_binding_indices: BTreeMap::new(),
            domain_imports: Vec::new(),
            route_sets: Default::default(),
            direct_prefix_routes: Vec::new(),
            direct_domain_routes: Vec::new(),
        }
    }

    pub fn new_with_domains(
        bindings: Vec<SecureRoute>,
        imports: Vec<RouteImport>,
        domain_bindings: Vec<(
            crate::route_sets::SetId,
            SecureRoute,
            Arc<[crate::config::DnsServer]>,
        )>,
        domain_imports: Vec<crate::config::DomainRouteImport>,
        route_sets: Arc<crate::route_sets::RouteSetRegistry>,
    ) -> Self {
        let mut snapshot = Self::new(bindings, imports);
        snapshot.domain_bindings = domain_bindings
            .into_iter()
            .map(|(set_id, binding, upstream_dns)| DomainSecureRoute {
                set_id,
                binding,
                upstream_dns,
            })
            .collect();
        for (index, route) in snapshot.domain_bindings.iter().enumerate() {
            snapshot
                .domain_binding_indices
                .entry(route.set_id)
                .or_default()
                .push(index);
        }
        snapshot.domain_imports = domain_imports;
        snapshot.route_sets = route_sets;
        snapshot
    }

    pub fn with_direct_routes(
        mut self,
        prefix_routes: Vec<(IpNet, u32)>,
        domain_routes: Vec<(crate::route_sets::SetId, u32)>,
    ) -> Self {
        for choice in self.prefix_choices.values_mut() {
            choice.direct_priority = None;
        }
        self.prefix_choices
            .retain(|_, choice| !choice.bindings.is_empty());
        self.direct_prefix_routes = prefix_routes;
        self.direct_domain_routes = domain_routes;
        for (prefix, priority) in &self.direct_prefix_routes {
            let choice = self.prefix_choices.entry(*prefix).or_default();
            choice.direct_priority = Some(
                choice
                    .direct_priority
                    .map_or(*priority, |current| current.max(*priority)),
            );
        }
        self
    }

    fn matching_prefix_choice(&self, destination: IpAddr) -> Option<&PrefixRouteChoice> {
        let max_prefix = if destination.is_ipv4() { 32 } else { 128 };
        (0..=max_prefix).rev().find_map(|prefix_len| {
            let prefix = IpNet::new(destination, prefix_len)
                .expect("address-family prefix length is always valid")
                .trunc();
            self.prefix_choices.get(&prefix)
        })
    }

    pub(super) fn select_route(
        &self,
        destination: IpAddr,
        hint: Option<&crate::fake_ip::FakeRouteHint>,
    ) -> Option<RouteSelection<'_>> {
        if let Some(hint) = hint {
            if hint.preferred_route == Some(crate::fake_ip::RoutePreference::Direct) {
                return Some(RouteSelection::Direct);
            }
            let candidates = self.matching_domain_bindings(&hint.domain);
            if let Some(crate::fake_ip::RoutePreference::Exit(preferred)) =
                hint.preferred_route.as_ref()
                && let Some(binding) = candidates
                    .iter()
                    .copied()
                    .find(|route| route.binding.exit == *preferred)
            {
                return Some(RouteSelection::Secure(&binding.binding));
            }
            let secure = candidates.first().map(|route| &route.binding);
            let direct_priority = self.direct_domain_priority(&hint.domain);
            return match (secure, direct_priority) {
                (Some(binding), Some(priority))
                    if direct_beats_secure(priority, binding.priority) =>
                {
                    Some(RouteSelection::Direct)
                }
                (Some(binding), _) => Some(RouteSelection::Secure(binding)),
                (None, Some(_)) => Some(RouteSelection::Direct),
                (None, None) => None,
            };
        }
        let choice = self.matching_prefix_choice(destination)?;
        let mut secure = None;
        for index in &choice.bindings {
            let Some(binding) = self.bindings.get(*index) else {
                continue;
            };
            if !binding.healthy.load(Ordering::Relaxed) {
                continue;
            }
            if secure.is_none_or(|current: &SecureRoute| binding.priority >= current.priority) {
                secure = Some(binding);
            }
        }
        match (secure, choice.direct_priority) {
            (Some(binding), Some(priority)) if direct_beats_secure(priority, binding.priority) => {
                Some(RouteSelection::Direct)
            }
            (Some(binding), _) => Some(RouteSelection::Secure(binding)),
            (None, Some(_)) => Some(RouteSelection::Direct),
            (None, None) => None,
        }
    }

    fn matching_domain_bindings(&self, domain: &str) -> Vec<&DomainSecureRoute> {
        let mut by_exit = BTreeMap::<&str, &DomainSecureRoute>::new();
        for (set_id, indices) in &self.domain_binding_indices {
            if !self
                .route_sets
                .site(*set_id)
                .is_some_and(|set| set.matches_domain(domain))
            {
                continue;
            }
            for index in indices {
                let route = &self.domain_bindings[*index];
                if !route.binding.healthy.load(Ordering::Relaxed) {
                    continue;
                }
                by_exit
                    .entry(&route.binding.exit)
                    .and_modify(|current| {
                        if route.binding.priority > current.binding.priority {
                            *current = route;
                        }
                    })
                    .or_insert(route);
            }
        }
        let mut candidates = by_exit.into_values().collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .binding
                .priority
                .cmp(&left.binding.priority)
                .then_with(|| left.binding.exit.cmp(&right.binding.exit))
        });
        candidates
    }

    pub(super) fn domain_candidates(&self, domain: &str) -> Vec<DomainResolutionCandidate> {
        let mut candidates = self
            .matching_domain_bindings(domain)
            .into_iter()
            .map(|route| DomainResolutionCandidate::Secure {
                binding: Box::new(route.binding.clone()),
                upstream_dns: route.upstream_dns.clone(),
            })
            .collect::<Vec<_>>();
        if let Some(priority) = self.direct_domain_priority(domain) {
            candidates.push(DomainResolutionCandidate::Direct { priority });
        }
        candidates.sort_by_key(|candidate| {
            (
                std::cmp::Reverse(candidate.priority()),
                matches!(candidate, DomainResolutionCandidate::Direct { .. }),
            )
        });
        candidates
    }

    pub(super) fn direct_domain_priority(&self, domain: &str) -> Option<u32> {
        self.direct_domain_routes
            .iter()
            .filter(|(set_id, _)| {
                self.route_sets
                    .site(*set_id)
                    .is_some_and(|set| set.matches_domain(domain))
            })
            .map(|(_, priority)| *priority)
            .max()
    }

    pub(super) fn ensure_candidates(
        &self,
        destination: IpAddr,
        hint: Option<&crate::fake_ip::FakeRouteHint>,
    ) -> Vec<&str> {
        if let Some(hint) = hint {
            return self
                .domain_imports
                .iter()
                .filter(|route| {
                    self.route_sets
                        .site(route.set_id)
                        .is_some_and(|set| set.matches_domain(&hint.domain))
                })
                .flat_map(|route| {
                    route
                        .candidates
                        .iter()
                        .map(|candidate| candidate.node.as_str())
                })
                .collect();
        }
        self.imports
            .iter()
            .filter(|route| route.prefix.contains(&destination))
            .flat_map(|route| {
                route
                    .candidates
                    .iter()
                    .map(|candidate| candidate.node.as_str())
            })
            .collect()
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    async fn authenticated_test_link() -> (Arc<crate::carrier::Link>, quinn::Endpoint) {
        let client_key = crate::identity::generate();
        let server_key = crate::identity::generate();
        let server_public = crate::identity::encode_public(&server_key.verifying_key());
        let (server, server_bare) = crate::carrier::endpoint_with_options_and_bare(
            crate::config::CarrierProtocol::Quic,
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
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: Vec::new(),
            },
        )]);
        let server_task = tokio::spawn(async move {
            crate::carrier::accept_with_bare(
                &server,
                server_bare.as_ref(),
                crate::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
            )
            .await
            .unwrap()
        });
        let (client, client_bare) = crate::carrier::endpoint_with_options_and_bare(
            crate::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &crate::config::LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = crate::carrier::connect_with_link_health_and_bare(
            &client,
            client_bare.as_ref(),
            address,
            crate::config::CarrierProtocol::Quic,
            "server",
            &server_public,
            "client",
            &client_key,
            &crate::config::LinkHealthConfig::default(),
        )
        .await
        .unwrap();
        let _server_link = server_task.await.unwrap();
        (Arc::new(link), client)
    }

    #[test]
    fn empty_and_direct_route_snapshots_cover_selection_boundaries() {
        let prefix: IpNet = "192.0.2.0/24".parse().unwrap();
        let imports = vec![crate::config::RouteImport {
            prefix,
            candidates: vec![crate::config::RouteCandidate {
                node: "exit".into(),
                priority: 100,
            }],
        }];
        let empty = RouteSnapshot::new(Vec::new(), imports.clone());
        assert!(
            empty
                .select_route("192.0.2.7".parse().unwrap(), None)
                .is_none()
        );
        assert_eq!(
            empty.ensure_candidates("192.0.2.7".parse().unwrap(), None),
            vec!["exit"]
        );
        assert!(empty.healthy_prefixes().next().is_none());
        assert!(!empty.has_healthy_domain_binding());
        assert!(empty.domain_candidates("example.com").is_empty());

        let direct = empty.with_direct_routes(vec![(prefix, 100)], Vec::new());
        assert!(matches!(
            direct.select_route("192.0.2.7".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
        assert_eq!(direct.healthy_prefixes().collect::<Vec<_>>(), vec![prefix]);
        assert!(matches!(
            direct.select_route(
                "203.0.113.7".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "example.com".into(),
                    preferred_route: Some(crate::fake_ip::RoutePreference::Direct),
                })
            ),
            Some(RouteSelection::Direct)
        ));
        assert!(
            direct
                .ensure_candidates("203.0.113.7".parse().unwrap(), None)
                .is_empty()
        );
        assert!(direct_beats_secure(101, 100));
        assert!(!direct_beats_secure(100, 100));
    }

    #[test]
    fn domain_route_snapshots_match_site_sets_and_direct_candidates() {
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.com\n").unwrap();
        let registry = Arc::new(loader.finish());
        let snapshot = RouteSnapshot::new_with_domains(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![crate::config::DomainRouteImport {
                set_id,
                candidates: vec![crate::config::RouteCandidate {
                    node: "exit".into(),
                    priority: 90,
                }],
            }],
            registry,
        )
        .with_direct_routes(Vec::new(), vec![(set_id, 100)]);
        assert!(snapshot.has_healthy_domain_binding());
        assert_eq!(
            snapshot.direct_domain_priority("www.example.com"),
            Some(100)
        );
        assert_eq!(snapshot.direct_domain_priority("other.test"), None);
        assert_eq!(
            snapshot.ensure_candidates(
                "203.0.113.1".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "www.example.com".into(),
                    preferred_route: None,
                }),
            ),
            vec!["exit"]
        );
        assert!(matches!(
            snapshot.select_route(
                "203.0.113.1".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "www.example.com".into(),
                    preferred_route: None,
                }),
            ),
            Some(RouteSelection::Direct)
        ));
        assert!(matches!(
            snapshot.domain_candidates("www.example.com").as_slice(),
            [DomainResolutionCandidate::Direct { priority: 100 }]
        ));
    }

    #[test]
    fn dns_codecs_cover_both_address_families_and_rejections() {
        let v4 = crate::config::DnsServer::from_socket_addr("192.0.2.53:53".parse().unwrap());
        let v6 = crate::config::DnsServer::from_socket_addr("[2001:db8::53]:5353".parse().unwrap());
        let v4_payload = encode_dns_query(7, &v4, b"query").unwrap();
        assert_eq!(
            decode_dns_query(&v4_payload).unwrap(),
            (7, v4, &b"query"[..])
        );
        let v6_payload = encode_dns_query(8, &v6, b"query6").unwrap();
        assert_eq!(
            decode_dns_query(&v6_payload).unwrap(),
            (8, v6, &b"query6"[..])
        );

        assert!(decode_dns_query(&[]).is_err());
        assert!(decode_dns_query(b"bad").is_err());
        let mut invalid_family = v4_payload.clone();
        invalid_family[12] = 5;
        assert!(decode_dns_query(&invalid_family).is_err());
        let mut invalid_port = v4_payload;
        invalid_port[29..31].copy_from_slice(&0_u16.to_be_bytes());
        assert!(decode_dns_query(&invalid_port).is_err());

        let response = encode_dns_response(9, 0, 1, 2, b"chunk");
        assert_eq!(
            decode_dns_response(&response).unwrap(),
            (9, 0, 1, 2, &b"chunk"[..])
        );
        assert!(decode_dns_response(&[]).is_err());
        assert!(decode_dns_response(b"bad").is_err());
    }

    #[test]
    fn dns_response_chunks_are_bounded_but_keep_state_for_recovery() {
        let client = CircuitDnsClient::default();
        let (sender, mut receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            7,
            PendingDnsQuery {
                link_instance: 1,
                circuit_id: CircuitId([7; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );
        // More chunks than any real DNS response may carry.
        assert!(
            client
                .complete(&encode_dns_response(
                    7,
                    0,
                    0,
                    MAX_DNS_RESPONSE_CHUNKS + 1,
                    b"x"
                ))
                .is_err()
        );
        // Range errors keep state: the DATAGRAM channel is unreliable, so a
        // corrupt chunk must not kill a query that later valid chunks can
        // still assemble. The waiter stays pending...
        assert!(client.state.lock().unwrap().pending.contains_key(&7));
        assert!(receiver.try_recv().is_err());
        // ...and a subsequent error-status chunk still resolves it.
        assert!(
            client
                .complete(&encode_dns_response(7, 1, 0, 1, b"upstream failed"))
                .is_ok()
        );
        assert_eq!(
            receiver.blocking_recv().unwrap().unwrap_err(),
            "upstream failed"
        );
        assert!(!client.state.lock().unwrap().pending.contains_key(&7));

        // A chunk larger than the encoder ever emits is rejected the same
        // way: error reported, state kept.
        let (sender, _receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            8,
            PendingDnsQuery {
                link_instance: 1,
                circuit_id: CircuitId([8; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );
        let big = vec![0u8; DNS_RESPONSE_CHUNK + 1];
        assert!(
            client
                .complete(&encode_dns_response(8, 0, 0, 1, &big))
                .is_err()
        );
        assert!(client.state.lock().unwrap().pending.contains_key(&8));
    }

    #[test]
    fn dns_completion_reassembles_errors_and_cleans_up_closed_circuits() {
        let client = CircuitDnsClient::default();
        let (sender, receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            9,
            PendingDnsQuery {
                link_instance: 1,
                circuit_id: CircuitId([9; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );
        assert!(
            client
                .complete(&encode_dns_response(9, 0, 1, 2, b" world"))
                .is_ok()
        );
        assert!(
            client
                .complete(&encode_dns_response(9, 0, 0, 2, b"hello"))
                .is_ok()
        );
        assert_eq!(receiver.blocking_recv().unwrap().unwrap(), b"hello world");
        assert!(
            client
                .complete(&encode_dns_response(9, 0, 0, 1, b"late"))
                .is_err()
        );

        let (sender, receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            10,
            PendingDnsQuery {
                link_instance: 2,
                circuit_id: CircuitId([10; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );
        assert!(
            client
                .complete(&encode_dns_response(10, 1, 0, 1, b"upstream failed"))
                .is_ok()
        );
        assert_eq!(
            receiver.blocking_recv().unwrap().unwrap_err(),
            "upstream failed"
        );

        let (sender, _receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            11,
            PendingDnsQuery {
                link_instance: 3,
                circuit_id: CircuitId([11; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );
        assert!(
            client
                .complete(&encode_dns_response(11, 0, 0, 0, b""))
                .is_err()
        );
        assert!(
            client
                .complete(&encode_dns_response(11, 0, 1, 1, b""))
                .is_err()
        );
        assert!(
            client
                .complete(&encode_dns_response(11, 0, 0, 2, b"a"))
                .is_ok()
        );
        assert!(
            client
                .complete(&encode_dns_response(11, 0, 1, 3, b"b"))
                .is_err()
        );

        let mut receivers = Vec::new();
        for (token, link_instance, circuit_id) in [
            (20, 7, CircuitId([20; 16])),
            (21, 7, CircuitId([21; 16])),
            (22, 8, CircuitId([22; 16])),
        ] {
            let (sender, receiver) = oneshot::channel();
            receivers.push(receiver);
            client.state.lock().unwrap().pending.insert(
                token,
                PendingDnsQuery {
                    link_instance,
                    circuit_id,
                    sender: Some(sender),
                    chunks: Vec::new(),
                },
            );
        }
        client.remove_circuit(7, CircuitId([20; 16]));
        assert!(receivers.remove(0).blocking_recv().unwrap().is_err());
        client.remove_link(7);
        assert!(receivers.remove(0).blocking_recv().unwrap().is_err());
        client.remove_circuit(8, CircuitId([22; 16]));
        assert!(receivers.remove(0).blocking_recv().unwrap().is_err());
    }

    #[tokio::test]
    async fn route_selection_covers_secure_direct_and_domain_precedence() {
        let (link, endpoint) = authenticated_test_link().await;
        let prefix: IpNet = "192.0.2.0/24".parse().unwrap();
        let make_binding = |exit: &str, priority: u32, healthy: bool, id: u8| SecureRoute {
            prefix,
            exit: exit.into(),
            priority,
            link: link.clone(),
            circuit_id: CircuitId([id; 16]),
            data_key: chacha20poly1305::Key::from([id; 32]),
            destination_key: crate::identity::generate().verifying_key(),
            healthy: Arc::new(std::sync::atomic::AtomicBool::new(healthy)),
            mtu: 1200,
            lease_epoch: u64::from(id),
            send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            send_budget: Arc::new(std::sync::atomic::AtomicUsize::new(1200)),
        };
        let exit = make_binding("exit", 100, true, 1);
        let backup = make_binding("backup", 120, true, 2);
        let imports = vec![crate::config::RouteImport {
            prefix,
            candidates: vec![
                crate::config::RouteCandidate {
                    node: "exit".into(),
                    priority: 100,
                },
                crate::config::RouteCandidate {
                    node: "backup".into(),
                    priority: 120,
                },
                crate::config::RouteCandidate {
                    node: "missing".into(),
                    priority: 200,
                },
            ],
        }];
        let snapshot = RouteSnapshot::new(vec![exit.clone(), backup.clone()], imports);
        assert_eq!(snapshot.all_bindings().count(), 2);
        assert_eq!(snapshot.healthy_prefixes().count(), 2);
        assert!(matches!(
            snapshot.select_route("192.0.2.1".parse().unwrap(), None),
            Some(RouteSelection::Secure(binding)) if binding.exit == "backup"
        ));
        backup.healthy.store(false, Ordering::Release);
        assert!(matches!(
            snapshot.select_route("192.0.2.1".parse().unwrap(), None),
            Some(RouteSelection::Secure(binding)) if binding.exit == "exit"
        ));
        let direct =
            RouteSnapshot::new(vec![exit.clone(), backup.clone()], snapshot.imports.clone())
                .with_direct_routes(vec![(prefix, 101)], Vec::new());
        assert!(matches!(
            direct.select_route("192.0.2.1".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
        let tie = RouteSnapshot::new(vec![exit.clone(), backup.clone()], snapshot.imports.clone())
            .with_direct_routes(vec![(prefix, 100)], Vec::new());
        assert!(matches!(
            tie.select_route("192.0.2.1".parse().unwrap(), None),
            Some(RouteSelection::Secure(_))
        ));
        assert!(
            tie.select_route(
                "203.0.113.1".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "unused.example".into(),
                    preferred_route: Some(crate::fake_ip::RoutePreference::Exit("exit".into())),
                }),
            )
            .is_none()
        );

        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.com\n").unwrap();
        let registry = Arc::new(loader.finish());
        let domain = RouteSnapshot::new_with_domains(
            vec![exit],
            Vec::new(),
            vec![(
                set_id,
                make_binding("exit", 90, true, 3),
                Arc::from([crate::config::DnsServer::from_socket_addr(
                    "192.0.2.53:53".parse().unwrap(),
                )]),
            )],
            Vec::new(),
            registry,
        )
        .with_direct_routes(Vec::new(), vec![(set_id, 80)]);
        assert!(domain.has_healthy_domain_binding());
        assert!(matches!(
            domain.select_route(
                "203.0.113.2".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "www.example.com".into(),
                    preferred_route: Some(crate::fake_ip::RoutePreference::Exit("exit".into())),
                }),
            ),
            Some(RouteSelection::Secure(binding)) if binding.exit == "exit"
        ));
        assert!(matches!(
            domain.select_route(
                "203.0.113.2".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "www.example.com".into(),
                    preferred_route: Some(crate::fake_ip::RoutePreference::Direct),
                }),
            ),
            Some(RouteSelection::Direct)
        ));
        assert_eq!(
            domain.ensure_candidates(
                "203.0.113.2".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "www.example.com".into(),
                    preferred_route: None,
                }),
            ),
            Vec::<&str>::new()
        );
        assert_eq!(domain.domain_candidates("other.test").len(), 0);
        endpoint.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn dns_query_rejects_unhealthy_gated_and_oversized_bindings() {
        let (link, endpoint) = authenticated_test_link().await;
        let binding = SecureRoute {
            prefix: "192.0.2.0/24".parse().unwrap(),
            exit: "exit".into(),
            priority: 100,
            link,
            circuit_id: CircuitId([31; 16]),
            data_key: chacha20poly1305::Key::from([31; 32]),
            destination_key: crate::identity::generate().verifying_key(),
            healthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            mtu: 1200,
            lease_epoch: 1,
            send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            send_budget: Arc::new(std::sync::atomic::AtomicUsize::new(1200)),
        };
        let upstream = crate::config::DnsServer::from_socket_addr("192.0.2.53:53".parse().unwrap());
        let client = CircuitDnsClient::default();
        assert!(client.query(&binding, &upstream, b"query").await.is_err());
        binding.healthy.store(true, Ordering::Release);
        binding.send_gate.store(false, Ordering::Release);
        assert!(client.query(&binding, &upstream, b"query").await.is_err());
        binding.send_gate.store(true, Ordering::Release);
        binding.send_budget.store(1, Ordering::Release);
        assert!(client.query(&binding, &upstream, b"query").await.is_err());
        endpoint.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn dns_query_reports_carrier_send_failures() {
        let (link, endpoint) = authenticated_test_link().await;
        let binding = SecureRoute {
            prefix: "192.0.2.0/24".parse().unwrap(),
            exit: "exit".into(),
            priority: 100,
            link: link.clone(),
            circuit_id: CircuitId([32; 16]),
            data_key: chacha20poly1305::Key::from([32; 32]),
            destination_key: crate::identity::generate().verifying_key(),
            healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            mtu: 1200,
            lease_epoch: 1,
            send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            send_budget: Arc::new(std::sync::atomic::AtomicUsize::new(1200)),
        };
        let upstream = crate::config::DnsServer::from_socket_addr("192.0.2.53:53".parse().unwrap());
        let client = CircuitDnsClient::default();
        link.close("dns query carrier failure");
        let error = client
            .query(&binding, &upstream, b"query")
            .await
            .unwrap_err();
        assert!(!error.is_empty());
        assert!(client.state.lock().unwrap().pending.is_empty());
        endpoint.close(0u32.into(), b"test complete");
    }

    #[test]
    fn direct_prefix_routes_keep_the_highest_priority() {
        let prefix: IpNet = "192.0.2.0/24".parse().unwrap();
        let snapshot = RouteSnapshot::new(Vec::new(), Vec::new())
            .with_direct_routes(vec![(prefix, 90), (prefix, 95)], Vec::new());
        assert_eq!(
            snapshot
                .prefix_choices
                .get(&prefix)
                .unwrap()
                .direct_priority,
            Some(95)
        );
        assert!(matches!(
            snapshot.select_route("192.0.2.1".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
        assert_eq!(
            snapshot.healthy_prefixes().collect::<Vec<_>>(),
            vec![prefix, prefix]
        );
    }

    #[tokio::test]
    async fn domain_snapshot_upgrades_same_exit_priority_and_sorts_candidates() {
        let (link, endpoint) = authenticated_test_link().await;
        let prefix: IpNet = "192.0.2.0/24".parse().unwrap();
        let dns: Arc<[crate::config::DnsServer]> =
            Arc::from([crate::config::DnsServer::from_socket_addr(
                "192.0.2.53:53".parse().unwrap(),
            )]);
        let make_binding = |exit: &str, priority: u32, id: u8| SecureRoute {
            prefix,
            exit: exit.into(),
            priority,
            link: link.clone(),
            circuit_id: CircuitId([id; 16]),
            data_key: chacha20poly1305::Key::from([id; 32]),
            destination_key: crate::identity::generate().verifying_key(),
            healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            mtu: 1200,
            lease_epoch: u64::from(id),
            send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            send_budget: Arc::new(std::sync::atomic::AtomicUsize::new(1200)),
        };
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.com\n").unwrap();
        let registry = Arc::new(loader.finish());
        let snapshot = RouteSnapshot::new_with_domains(
            Vec::new(),
            Vec::new(),
            vec![
                (set_id, make_binding("exit", 100, 1), dns.clone()),
                (set_id, make_binding("exit", 200, 2), dns.clone()),
                (set_id, make_binding("backup", 200, 3), dns.clone()),
            ],
            Vec::new(),
            registry,
        );
        // matching_domain_bindings keeps only the highest-priority binding
        // per exit and orders equal priorities by exit name.
        let candidates = snapshot.domain_candidates("www.example.com");
        let exits = candidates
            .iter()
            .map(|candidate| match candidate {
                DomainResolutionCandidate::Secure { binding, .. } => binding.exit.as_str(),
                DomainResolutionCandidate::Direct { .. } => "direct",
            })
            .collect::<Vec<_>>();
        assert_eq!(exits, vec!["backup", "exit"]);
        // The same-exit upgrade makes the preferred exit resolve at the
        // higher priority.
        assert!(matches!(
            snapshot.select_route(
                "203.0.113.1".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "www.example.com".into(),
                    preferred_route: Some(crate::fake_ip::RoutePreference::Exit("exit".into())),
                }),
            ),
            Some(RouteSelection::Secure(binding)) if binding.priority == 200
        ));
        // A direct route outranking every secure binding sorts first.
        let with_direct = snapshot.with_direct_routes(Vec::new(), vec![(set_id, 250)]);
        let candidates = with_direct.domain_candidates("www.example.com");
        assert!(matches!(
            candidates.as_slice(),
            [DomainResolutionCandidate::Direct { .. }, ..]
        ));
        endpoint.close(0u32.into(), b"test complete");
    }
}
