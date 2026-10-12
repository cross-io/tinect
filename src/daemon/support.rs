//! Small, deterministic helpers shared by daemon workers.
//!
//! Keeping these helpers next to the daemon modules makes their dependencies
//! explicit.  They are deliberately not a second runtime or service layer:
//! the functions only translate validated configuration and current Link
//! state into values needed by workers.

use anyhow::Result;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};
#[cfg(target_os = "linux")]
use tinect::dataplane::RouteSnapshot;
use tinect::{
    carrier::Link, config::Config, dataplane, dns::DnsResolver, runtime::LinkRegistry,
    status::DaemonState,
};

pub(crate) const MAX_TOPOLOGY_SYNC_MESSAGE: usize = u16::MAX as usize + 3;
pub(crate) const MAX_TOPOLOGY_SNAPSHOT_CHUNKS: usize = 256;
pub(crate) const MAX_TOPOLOGY_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_TOPOLOGY_SNAPSHOT_LSAS: usize = 65_536;
pub(crate) const MAX_TOPOLOGY_SNAPSHOT_NEIGHBORS: usize = 262_144;
pub(crate) const TOPOLOGY_ACK_SEND_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const MAX_TOPOLOGY_ACK_SEND_ATTEMPTS: u8 = 3;
pub(crate) const MAX_TOPOLOGY_SNAPSHOT_RECOVERY_ATTEMPTS: u8 = 3;
pub(crate) const RECENT_COMPLETED_TOPOLOGY_SNAPSHOTS: usize = 16;
pub(crate) const RECENT_SUPERSEDED_TOPOLOGY_SNAPSHOTS: usize = 16;

pub(crate) fn topology_snapshot_reassembly_timeout() -> Duration {
    tinect::timing::active().topology_snapshot_reassembly_timeout
}

pub(crate) fn topology_snapshot_ack_timeout() -> Duration {
    tinect::timing::active().topology_snapshot_ack_timeout
}

pub(crate) fn min_topology_snapshot_request_interval() -> Duration {
    tinect::timing::active().min_topology_snapshot_request_interval
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(target_os = "linux")]
pub(crate) fn healthy_route_prefixes(
    snapshot: &RouteSnapshot,
    fake_ip: Option<&tinect::fake_ip::FakeIpRuntime>,
) -> HashSet<ipnet::IpNet> {
    let mut prefixes = snapshot.healthy_prefixes().collect::<HashSet<_>>();
    if snapshot.has_healthy_domain_binding()
        && let Some(runtime) = fake_ip
    {
        prefixes.extend(runtime.fake_prefixes());
    }
    prefixes
}

#[cfg(test)]
pub(crate) fn path_inner_mtu_from_hops(
    first_hop: u16,
    remaining_hops: impl IntoIterator<Item = u16>,
) -> u16 {
    remaining_hops
        .into_iter()
        .fold(first_hop, |minimum, mtu| minimum.min(mtu))
}

pub(crate) fn physical_idle_deadline(idle_timeout: Duration, keepalive: Duration) -> Duration {
    idle_timeout.saturating_add(keepalive)
}

pub(crate) fn link_inner_mtu(link: &Link) -> u16 {
    link.confirmed_user_ip_capacity()
        .map(|(mtu, _)| mtu)
        .unwrap_or(tinect::mtu::user_ip_capacity_from_physical_with_fec(
            tinect::mtu::INITIAL_QUIC_DATAGRAM_SIZE,
            link.fec_enabled(),
        ) as u16)
}

/// A TUN starts at the smallest capacity that an asynchronously established
/// carrier can provide.  Later route bindings may raise the effective path
/// capacity, but startup must never inject an oversized packet.
pub(crate) fn initial_tun_mtu(c: &Config) -> u16 {
    initial_user_ip_limit_with_fec(
        c.has_bare_carrier(),
        c.has_full_quic_carrier(),
        c.fec_possible(),
    )
    .min(c.tun.mtu)
}

#[cfg(test)]
pub(crate) fn initial_user_ip_limit(has_bare_carrier: bool, has_full_quic_carrier: bool) -> u16 {
    initial_user_ip_limit_with_fec(has_bare_carrier, has_full_quic_carrier, false)
}

pub(crate) fn initial_user_ip_limit_with_fec(
    has_bare_carrier: bool,
    has_full_quic_carrier: bool,
    fec_enabled: bool,
) -> u16 {
    let bare_limit = tinect::mtu::user_ip_capacity_from_physical_with_fec(
        tinect::mtu::INITIAL_BARE_PHYSICAL_SIZE,
        fec_enabled,
    );
    let full_quic_limit = tinect::mtu::user_ip_capacity_from_physical_with_fec(
        tinect::mtu::INITIAL_QUIC_DATAGRAM_SIZE,
        fec_enabled,
    );
    (match (has_bare_carrier, has_full_quic_carrier) {
        (true, true) => bare_limit.min(full_quic_limit),
        (true, false) => bare_limit,
        (false, true) | (false, false) => full_quic_limit,
    }) as u16
}

#[cfg(test)]
pub(crate) fn initial_tun_mtu_from_limits(configured_tun_mtu: u16) -> u16 {
    initial_user_ip_limit(false, true).min(configured_tun_mtu)
}

pub(crate) fn wire_identity(c: &Config, name: &str) -> Option<String> {
    if name == c.id {
        c.local_identity().ok()
    } else {
        c.peer_identity(name)
    }
}

/// Resolves a wire identity for operator-facing output only.  This mapping is
/// local configuration and is never used for routing or authorization.
pub(crate) fn observable_name(c: &Config, identity: &str) -> Option<String> {
    c.peer_name_by_identity(identity)
        .map(str::to_owned)
        .or_else(|| (c.local_identity().ok().as_deref() == Some(identity)).then(|| c.id.clone()))
}

pub(crate) fn observable_node_names(c: &Config) -> HashMap<String, String> {
    let mut names = c
        .peers
        .keys()
        .filter_map(|name| {
            c.peer_identity(name)
                .map(|identity| (identity, name.clone()))
        })
        .collect::<HashMap<_, _>>();
    if let Ok(identity) = c.local_identity() {
        names.insert(identity, c.id.clone());
    }
    names
}

pub(crate) fn display_path(c: &Config, path: &[String]) -> String {
    path.iter()
        .map(|identity| observable_name(c, identity).unwrap_or_else(|| identity.clone()))
        .collect::<Vec<_>>()
        .join("->")
}

pub(crate) fn wire_paths(c: &Config) -> BTreeMap<String, Vec<Vec<String>>> {
    c.peers
        .iter()
        .filter(|(_, peer)| !peer.paths.is_empty())
        .filter_map(|(destination, peer)| {
            Some((
                wire_identity(c, destination)?,
                peer.paths
                    .iter()
                    .map(|configured| {
                        configured
                            .path
                            .iter()
                            .filter_map(|name| wire_identity(c, name))
                            .collect()
                    })
                    .collect(),
            ))
        })
        .collect()
}

pub(crate) async fn resolve_quic_endpoint(
    url: &str,
    dns: &DnsResolver,
) -> Result<Vec<std::net::SocketAddr>> {
    let endpoint = tinect::config::CarrierEndpoint::parse(url, "endpoint")?;
    dns.resolve_socket_addrs(&endpoint.address).await
}

pub(crate) async fn collect_underlay_endpoints(
    c: &Config,
    dns: &DnsResolver,
) -> Vec<std::net::IpAddr> {
    let endpoints = c
        .peers
        .values()
        .flat_map(|peer| peer.endpoints.iter().cloned())
        .collect::<Vec<_>>();
    let mut tasks = tokio::task::JoinSet::new();
    for endpoint in endpoints {
        let dns = dns.clone();
        tasks.spawn(async move { resolve_quic_endpoint(&endpoint, &dns).await });
    }
    let mut result = Vec::new();
    while let Some(resolved) = tasks.join_next().await {
        if let Ok(Ok(addresses)) = resolved {
            result.extend(addresses.into_iter().map(|address| address.ip()));
        }
    }
    result.sort_unstable();
    result.dedup();
    result
}

pub(crate) async fn mark_link(
    state: &tokio::sync::RwLock<DaemonState>,
    peer: &str,
    healthy: bool,
    error: Option<String>,
) {
    if let Some(link) = state
        .write()
        .await
        .status
        .links
        .iter_mut()
        .find(|link| link.peer == peer)
    {
        link.healthy = healthy;
        link.last_error = error;
    }
}

pub(crate) async fn mark_current_link(
    state: &tokio::sync::RwLock<DaemonState>,
    links: &LinkRegistry,
    peer: &str,
    instance: u64,
    healthy: bool,
    error: Option<String>,
    opens: &dataplane::CircuitOpenManager,
) {
    let current = links.lock().expect("link registry lock").get(peer).cloned();
    if current
        .as_ref()
        .is_some_and(|current| current.instance() != instance)
    {
        tracing::debug!(%peer, instance, "discarding stale link health event");
        return;
    }
    if let Some(current) = current {
        let was_healthy = current.is_healthy();
        current.set_healthy(healthy);
        let effective_healthy = current.is_healthy();
        let changed = was_healthy != effective_healthy;
        mark_link(state, peer, effective_healthy, error).await;
        if changed {
            opens.request_reconcile();
        }
        return;
    }
    mark_link(state, peer, healthy, error).await;
}

pub(crate) async fn mark_unbound_link(
    state: &tokio::sync::RwLock<DaemonState>,
    links: &LinkRegistry,
    peer: &str,
    error: Option<String>,
) {
    if links.lock().expect("link registry lock").contains_key(peer) {
        tracing::debug!(%peer, "discarding link-attempt failure for a currently registered Link");
        return;
    }
    mark_link(state, peer, false, error).await;
}
