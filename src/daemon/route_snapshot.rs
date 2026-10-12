//! Route binding snapshots derived from currently active circuits.
//!
//! Callers keep responsibility for applying the returned snapshot to TUN,
//! platform routes, and nftables.

use super::{
    circuit_resolution::{active_path_has_valid_proof, is_configured_circuit_destination},
    path_resolution::{PathEvidence, path_evidence},
};
use std::{collections::HashMap, sync::Arc};
use tinect::{
    config::Config,
    dataplane, identity,
    runtime::{LinkRegistry, SharedTopology},
};

pub(crate) async fn build_route_snapshot(
    c: &Config,
    links: &LinkRegistry,
    topology: &SharedTopology,
    circuit_opens: &dataplane::CircuitOpenManager,
) -> dataplane::RouteSnapshot {
    let connected = links
        .lock()
        .expect("link registry lock")
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let active_circuits = circuit_opens
        .active_circuits()
        .await
        .into_iter()
        .collect::<HashMap<_, _>>();
    let active_path_overrides = active_circuits
        .iter()
        .map(|(destination, active)| (destination.clone(), active.route_overrides.clone()))
        .collect::<HashMap<_, _>>();
    let imports = c.effective_route_imports_for_active_leases(&active_path_overrides);
    let domain_imports = c.effective_domain_route_imports_for_active_leases(&active_path_overrides);
    let domain_placeholder = c
        .fake_ip
        .as_ref()
        .map(|fake| fake.ipv4_pool)
        .unwrap_or_else(|| "198.18.0.0/15".parse().expect("valid placeholder"));
    let route_specs = imports
        .iter()
        .flat_map(|route| {
            route
                .candidates
                .iter()
                .map(move |candidate| (None, route.prefix, candidate))
        })
        .chain(domain_imports.iter().flat_map(|route| {
            route
                .candidates
                .iter()
                .map(move |candidate| (Some(route.set_id), domain_placeholder, candidate))
        }))
        .collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut domain_result = Vec::new();
    let mut evidence_cache = HashMap::<(Vec<String>, u64), PathEvidence>::new();
    // Only domain routing constructs this map. Ordinary IP-only nodes never
    // clone or allocate FakeIP upstream state.
    let mut domain_upstreams = HashMap::<String, Arc<[tinect::config::DnsServer]>>::new();
    for (domain_site, prefix, candidate) in route_specs {
        if !is_configured_circuit_destination(c, &candidate.node) {
            continue;
        }
        let Some(peer) = c.peers.get(&candidate.node) else {
            continue;
        };
        let Ok(destination_key) = identity::decode_public(&peer.public_key) else {
            continue;
        };
        let Some(active) = active_circuits.get(&candidate.node) else {
            continue;
        };
        let Some(next_hop) = active.path.get(1) else {
            continue;
        };
        let Some(link) = connected.iter().find(|link| {
            link.instance() == active.link_instance && link.peer_identity == *next_hop
        }) else {
            continue;
        };
        let path = &active.path;
        let configured_inner_mtu = c.tun.mtu;
        let evidence_key = (path.clone(), link.instance());
        let evidence = if let Some(evidence) = evidence_cache.get(&evidence_key) {
            Some(evidence.clone())
        } else {
            let evidence = path_evidence(path, link, topology).await;
            if let Some(evidence) = evidence.as_ref() {
                evidence_cache.insert(evidence_key, evidence.clone());
            }
            evidence
        };
        if let Some(evidence) = evidence {
            let capacity_vector = evidence.capacity_vector;
            let verified_inner_mtu = capacity_vector
                .capacity()
                .unwrap_or(tinect::mtu::user_ip_capacity_from_physical(
                    tinect::mtu::INITIAL_QUIC_DATAGRAM_SIZE,
                ) as u16);
            if !circuit_opens
                .update_active_budget_for_lease(
                    (&candidate.node, active.circuit_id, path, link.instance()),
                    configured_inner_mtu,
                    verified_inner_mtu,
                    capacity_vector,
                )
                .await
            {
                continue;
            }
        } else if !active_path_has_valid_proof(active, links, topology).await {
            // A missing downstream capacity proof is safe to bridge only
            // while the active lease's existing proof remains valid.
            continue;
        }
        let Some(current) = active_circuits
            .get(&candidate.node)
            .filter(|current| current.link_instance == link.instance() && current.path == *path)
        else {
            continue;
        };
        let lease_epoch = current.lease_epoch;
        let send_gate = current.send_gate.clone();
        let send_budget = current.send_budget.clone();
        let mtu = u16::try_from(send_budget.load(std::sync::atomic::Ordering::Acquire))
            .unwrap_or(u16::MAX);
        let secure = dataplane::SecureRoute {
            prefix,
            exit: candidate.node.clone(),
            priority: candidate.priority,
            link: link.clone(),
            circuit_id: current.circuit_id,
            data_key: current.data_key,
            destination_key,
            healthy: Arc::new(std::sync::atomic::AtomicBool::new(link.is_healthy())),
            mtu,
            lease_epoch,
            send_gate,
            send_budget,
        };
        if let Some(set_id) = domain_site {
            let upstream_dns = domain_upstreams
                .entry(candidate.node.clone())
                .or_insert_with(|| {
                    c.upstream_dns_for_wire(&candidate.node, &active.path)
                        .into()
                })
                .clone();
            domain_result.push((set_id, secure, upstream_dns));
        } else {
            result.push(secure);
        }
    }
    dataplane::RouteSnapshot::new_with_domains(
        result,
        imports,
        domain_result,
        domain_imports,
        c.route_sets.clone(),
    )
    .with_direct_routes(c.direct_prefix_routes(), c.direct_domain_routes())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::circuit_resolution::tests::link_pair_with_client_key;
    use std::{collections::HashMap, sync::Arc};
    use tinect::identity;
    use tinect::topology::Topology;

    fn config_with_exit_route(
        exit_key: &ed25519_dalek::SigningKey,
        routes: Vec<tinect::config::PeerRoute>,
    ) -> Config {
        let mut config = crate::daemon::test_support::minimal_config();
        config.identity_key = Some(identity::encode_secret(&identity::generate()));
        config.identity_key_path = None;
        config.peers.insert(
            "exit".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&exit_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes,
                paths: Vec::new(),
            },
        );
        config
    }

    fn ip_route(prefix: &str) -> tinect::config::PeerRoute {
        // serde fills the crate-private interning fields with their defaults.
        serde_yaml::from_str(&format!("ip_cidr: {prefix}\npriority: 100")).unwrap()
    }

    #[tokio::test]
    async fn empty_active_snapshot_has_no_secure_or_domain_bindings() {
        let config = crate::daemon::test_support::minimal_config();
        let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let opens = dataplane::CircuitOpenManager::default();

        let snapshot = build_route_snapshot(&config, &links, &topology, &opens).await;

        assert_eq!(snapshot.all_bindings().count(), 0);
        assert!(!snapshot.has_healthy_domain_binding());
    }

    #[tokio::test]
    async fn active_ip_routes_are_bound_with_capacity_evidence_cached_per_link() {
        let pair = link_pair_with_client_key(identity::generate()).await;
        let config = config_with_exit_route(
            &pair.client_key,
            vec![ip_route("198.51.100.0/24"), ip_route("198.51.101.0/24")],
        );
        let local = config.local_identity().unwrap();
        let exit = config.peer_identity("exit").unwrap();
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".to_owned(),
            pair.server_link.clone(),
        )])));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let opens = dataplane::CircuitOpenManager::default();
        opens
            .activate(
                "exit".into(),
                tinect::circuit::CircuitId([9; 16]),
                chacha20poly1305::Key::from([9; 32]),
                pair.server_link.instance(),
                (vec![local, exit.clone()], 1200),
            )
            .await;

        let snapshot = build_route_snapshot(&config, &links, &topology, &opens).await;
        let bindings = snapshot.all_bindings().collect::<Vec<_>>();
        assert_eq!(bindings.len(), 2);
        // Bindings name the configured peer, not the wire identity.
        assert!(bindings.iter().all(|binding| binding.exit == "exit"));
        assert!(
            bindings
                .iter()
                .all(|binding| { binding.circuit_id == tinect::circuit::CircuitId([9; 16]) })
        );
    }

    #[tokio::test]
    async fn route_snapshot_skips_bad_peer_keys_and_leases_without_active_circuits() {
        let pair = link_pair_with_client_key(identity::generate()).await;
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let opens = dataplane::CircuitOpenManager::default();

        // An undeciperable peer public key cannot name the destination key.
        let mut bad_key =
            config_with_exit_route(&pair.client_key, vec![ip_route("198.51.100.0/24")]);
        bad_key.peers.get_mut("exit").unwrap().public_key = "not-a-key".into();
        let snapshot = build_route_snapshot(&bad_key, &links, &topology, &opens).await;
        assert_eq!(snapshot.all_bindings().count(), 0);

        // A valid route import with no active lease for the exit is skipped.
        let config = config_with_exit_route(&pair.client_key, vec![ip_route("198.51.100.0/24")]);
        let snapshot = build_route_snapshot(&config, &links, &topology, &opens).await;
        assert_eq!(snapshot.all_bindings().count(), 0);
    }

    #[tokio::test]
    async fn route_snapshot_skips_leases_without_next_hop_or_matching_link() {
        let pair = link_pair_with_client_key(identity::generate()).await;
        let config = config_with_exit_route(&pair.client_key, vec![ip_route("198.51.100.0/24")]);
        let local = config.local_identity().unwrap();
        let exit = config.peer_identity("exit").unwrap();
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));

        // A one-hop lease has no second hop to bridge.
        let opens = dataplane::CircuitOpenManager::default();
        opens
            .activate(
                "exit".into(),
                tinect::circuit::CircuitId([1; 16]),
                chacha20poly1305::Key::from([1; 32]),
                pair.server_link.instance(),
                (vec![local.clone()], 1200),
            )
            .await;
        let snapshot = build_route_snapshot(&config, &links, &topology, &opens).await;
        assert_eq!(snapshot.all_bindings().count(), 0);

        // A lease whose link instance is not registered has no bridge Link.
        let opens = dataplane::CircuitOpenManager::default();
        opens
            .activate(
                "exit".into(),
                tinect::circuit::CircuitId([2; 16]),
                chacha20poly1305::Key::from([2; 32]),
                999,
                (vec![local, exit], 1200),
            )
            .await;
        let snapshot = build_route_snapshot(&config, &links, &topology, &opens).await;
        assert_eq!(snapshot.all_bindings().count(), 0);
    }

    #[tokio::test]
    async fn route_snapshot_skips_leases_without_valid_downstream_proof() {
        let relay_key = identity::generate();
        let pair = link_pair_with_client_key(relay_key.clone()).await;
        let relay = identity::node_id(&relay_key.verifying_key());
        let exit_key = identity::generate();
        let mut config = config_with_exit_route(&exit_key, vec![ip_route("198.51.100.0/24")]);
        config.peers.insert(
            "relay".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&relay_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: Vec::new(),
            },
        );
        let local = config.local_identity().unwrap();
        let exit = config.peer_identity("exit").unwrap();
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".to_owned(),
            pair.server_link.clone(),
        )])));
        // The empty topology has no relay -> exit advertisement, so neither
        // path evidence nor an existing proof is available.
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let opens = dataplane::CircuitOpenManager::default();
        opens
            .activate(
                "exit".into(),
                tinect::circuit::CircuitId([3; 16]),
                chacha20poly1305::Key::from([3; 32]),
                pair.server_link.instance(),
                (vec![local, relay, exit], 1200),
            )
            .await;
        let snapshot = build_route_snapshot(&config, &links, &topology, &opens).await;
        assert_eq!(snapshot.all_bindings().count(), 0);
    }

    #[tokio::test]
    async fn domain_route_imports_bind_domain_bindings_with_upstreams() {
        let peer_key = identity::generate();
        let pair = link_pair_with_client_key(peer_key.clone()).await;
        let directory = tempfile::tempdir().unwrap();
        let yaml = format!(
            "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\nfake_ip:\n  listen: 127.0.0.1:5354\n  upstream_dns: [1.1.1.1]\n  disable_ipv6: true\npeers:\n  exit:\n    public_key: {}\n    endpoints: []\n    routes: [{{domain: example.test, priority: 100}}]\n",
            identity::encode_public(&peer_key.verifying_key())
        );
        let path = directory.path().join("node.yaml");
        std::fs::write(&path, yaml).unwrap();
        let mut config = Config::load(&path).unwrap();
        config.identity_key = Some(identity::encode_secret(&identity::generate()));
        config.identity_key_path = None;
        assert!(!config.domain_route_imports().is_empty());
        let local = config.local_identity().unwrap();
        let exit = config.peer_identity("exit").unwrap();
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".to_owned(),
            pair.server_link.clone(),
        )])));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let opens = dataplane::CircuitOpenManager::default();
        opens
            .activate(
                "exit".into(),
                tinect::circuit::CircuitId([4; 16]),
                chacha20poly1305::Key::from([4; 32]),
                pair.server_link.instance(),
                (vec![local, exit], 1200),
            )
            .await;
        // The binding's health snapshot mirrors the Link's current health.
        pair.server_link.set_healthy(true);

        let snapshot = build_route_snapshot(&config, &links, &topology, &opens).await;
        assert_eq!(snapshot.all_bindings().count(), 1);
        assert!(snapshot.has_healthy_domain_binding());
    }
}
