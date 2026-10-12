//! Read-only circuit resolution used by the circuit reconciler.
//!
//! This module turns the immutable configuration plus a point-in-time link and
//! topology view into a desired circuit state.  It deliberately does not send
//! control frames or mutate `CircuitOpenManager`; the reconciler applies the
//! resulting decision in a separate step.

use super::path_resolution::{path_evidence, path_proof_valid_until, resolve_paths};
use super::support::unix_now;
use std::sync::Arc;
use tinect::{
    carrier,
    config::Config,
    dataplane,
    runtime::{LinkRegistry, SharedTopology},
};

pub(crate) fn is_configured_circuit_destination(c: &Config, destination: &str) -> bool {
    c.peers
        .get(destination)
        .is_some_and(|peer| !peer.paths.is_empty())
        || c.path_policies.contains_key(destination)
        || c.route_imports().into_iter().any(|route| {
            route
                .candidates
                .into_iter()
                .any(|candidate| candidate.node == destination)
        })
        || c.domain_route_imports().into_iter().any(|route| {
            route
                .candidates
                .into_iter()
                .any(|candidate| candidate.node == destination)
        })
}

pub(crate) async fn active_path_proof_valid_until(
    active: &dataplane::ActiveCircuit,
    links: &LinkRegistry,
    topology: &SharedTopology,
) -> Option<u64> {
    let first_hop = active.path.get(1)?;
    let first_link_valid = links
        .lock()
        .expect("link registry lock")
        .values()
        .any(|link| link.instance() == active.link_instance && link.peer_identity == *first_hop);
    if !first_link_valid {
        return None;
    }
    path_proof_valid_until(&active.path, topology).await
}

pub(crate) async fn active_path_has_valid_proof(
    active: &dataplane::ActiveCircuit,
    links: &LinkRegistry,
    topology: &SharedTopology,
) -> bool {
    active_path_proof_valid_until(active, links, topology)
        .await
        .is_some()
}

fn resolved_active_path(
    destination: &str,
    active: &dataplane::ActiveCircuit,
    proof_valid_until: u64,
) -> tinect::reconcile::ResolvedPath {
    let verified_inner_mtu = active.capacity_vector.capacity().unwrap_or_else(|| {
        active
            .send_budget
            .load(std::sync::atomic::Ordering::Acquire) as u16
    });
    tinect::reconcile::ResolvedPath {
        destination: destination.to_owned(),
        ordered_path: active.path.clone(),
        first_hop_link_instance: active.link_instance,
        candidate_rank: usize::MAX,
        verified_inner_mtu,
        capacity_vector: active.capacity_vector.clone(),
        proof_valid_until,
    }
}

#[derive(Clone)]
pub(crate) struct ResolvedCandidate {
    pub path: tinect::reconcile::ResolvedPath,
    pub link: Arc<carrier::Link>,
}

pub(crate) struct DestinationResolution {
    /// All ready candidates in configured priority order. `preferred` remains
    /// the first item because migration/status semantics refer to it even
    /// while a lower-priority path temporarily carries traffic.
    pub candidates: Vec<ResolvedCandidate>,
    pub preferred: Option<ResolvedCandidate>,
    pub desired: tinect::reconcile::DesiredResolution,
}

/// Resolve every ready candidate once, including the exact Link instance,
/// proof expiry and capacity vector used by OPEN and route publication.
/// Consumers must not independently reconstruct these facts from raw paths.
async fn resolve_candidates(
    c: &Config,
    destination: &str,
    links: &LinkRegistry,
    topology: &SharedTopology,
) -> Vec<ResolvedCandidate> {
    let paths = resolve_paths(c, destination, topology).await;
    let connected = links
        .lock()
        .expect("link registry lock")
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for (candidate_rank, path) in paths.into_iter().enumerate() {
        let Some(next_hop) = path.get(1) else {
            continue;
        };
        let Some(link) = connected
            .iter()
            .find(|link| link.peer_identity == *next_hop && link.topology_ready())
            .cloned()
        else {
            continue;
        };
        let Some(evidence) = path_evidence(&path, &link, topology).await else {
            continue;
        };
        let Some(proof_valid_until) = evidence.proof_valid_until else {
            continue;
        };
        let capacity_vector = evidence.capacity_vector;
        let Some(verified_inner_mtu) = capacity_vector.capacity() else {
            continue;
        };
        if verified_inner_mtu > 0 {
            candidates.push(ResolvedCandidate {
                path: tinect::reconcile::ResolvedPath {
                    destination: destination.to_owned(),
                    ordered_path: path,
                    first_hop_link_instance: link.instance(),
                    candidate_rank,
                    verified_inner_mtu,
                    capacity_vector,
                    proof_valid_until,
                },
                link,
            });
        }
    }
    candidates
}

pub(crate) async fn resolve_destination(
    c: &Config,
    destination: &str,
    links: &LinkRegistry,
    topology: &SharedTopology,
    active: Option<&dataplane::ActiveCircuit>,
    config_generation: u64,
    resolution_generation: u64,
) -> DestinationResolution {
    let candidates = resolve_candidates(c, destination, links, topology).await;
    let preferred = candidates.first().cloned();
    let desired = if let Some(candidate) = preferred.as_ref() {
        tinect::reconcile::DesiredResolution {
            generation: resolution_generation,
            config_generation,
            path: Some(candidate.path.clone()),
            availability: tinect::reconcile::Availability::Ready,
            resolved_at: std::time::SystemTime::now(),
        }
    } else if let Some(active) = active {
        if let Some(proof_valid_until) =
            active_path_proof_valid_until(active, links, topology).await
        {
            tinect::reconcile::DesiredResolution {
                generation: resolution_generation,
                config_generation,
                path: Some(resolved_active_path(destination, active, proof_valid_until)),
                availability: tinect::reconcile::Availability::ProofStale {
                    valid_until: proof_valid_until,
                },
                resolved_at: std::time::SystemTime::now(),
            }
        } else {
            tinect::reconcile::DesiredResolution {
                generation: resolution_generation,
                config_generation,
                path: None,
                availability: tinect::reconcile::Availability::HardRevoked {
                    generation: resolution_generation,
                    reason: "active path proof expired or was removed".into(),
                },
                resolved_at: std::time::SystemTime::now(),
            }
        }
    } else {
        tinect::reconcile::DesiredResolution {
            generation: resolution_generation,
            config_generation,
            path: None,
            availability: tinect::reconcile::Availability::TemporarilyUnavailable {
                reason: "no ready candidate".into(),
                retry_at: unix_now().saturating_add(1),
            },
            resolved_at: std::time::SystemTime::now(),
        }
    };
    DestinationResolution {
        candidates,
        preferred,
        desired,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::fs;
    use tinect::identity;
    use tinect::topology::Topology;

    /// A live loopback QUIC link pair. `server_link` is the link under test
    /// (its peer is "client"); `client_link` keeps the connection alive and
    /// can be closed to force send/receive failures on the server side.
    pub(crate) struct LinkPair {
        pub(crate) server_link: Arc<carrier::Link>,
        pub(crate) client_link: Arc<carrier::Link>,
        pub(crate) client_key: SigningKey,
        pub(crate) client_endpoint: quinn::Endpoint,
    }

    /// Create a fresh link pair with a random client identity. The server
    /// link's `peer_identity` is the client identity's node id.
    pub(crate) async fn link_pair() -> LinkPair {
        link_pair_with_client_key(identity::generate()).await
    }

    /// Create a fresh link pair whose client identity is `client_key`, so a
    /// test config can name that peer and match the server link's
    /// `peer_identity`.
    pub(crate) async fn link_pair_with_client_key(client_key: SigningKey) -> LinkPair {
        link_pair_inner(client_key, 0).await
    }

    /// Like [`link_pair_with_client_key`], but with FEC workers enabled on
    /// both sides (repair rate 100/1000).
    pub(crate) async fn link_pair_with_fec(client_key: SigningKey) -> LinkPair {
        link_pair_inner(client_key, 100).await
    }

    async fn link_pair_inner(client_key: SigningKey, repair_rate: u16) -> LinkPair {
        crate::daemon::test_support::backdate_monotonic_epoch();
        let server_key = identity::generate();
        let server_public = identity::encode_public(&server_key.verifying_key());
        let (server_endpoint, server_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &tinect::config::LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let server_address = server_endpoint.local_addr().unwrap();
        let peers = std::collections::BTreeMap::from([(
            "client".to_owned(),
            tinect::config::Peer {
                public_key: identity::encode_public(&client_key.verifying_key()),
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
        let accept_key = server_key.clone();
        let server_task = tokio::spawn(async move {
            carrier::accept_with_bare_and_fec(
                &server_endpoint,
                server_bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &accept_key,
                repair_rate,
            )
            .await
            .unwrap()
        });
        let (client_endpoint, client_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &tinect::config::LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let client_link = Arc::new(
            carrier::connect_with_link_health_and_bare_and_fec(
                &client_endpoint,
                client_bare.as_ref(),
                server_address,
                tinect::config::CarrierProtocol::Quic,
                "server",
                &server_public,
                "client",
                &client_key,
                &tinect::config::LinkHealthConfig::default(),
                repair_rate,
            )
            .await
            .unwrap(),
        );
        let server_link = Arc::new(server_task.await.unwrap());
        LinkPair {
            server_link,
            client_link,
            client_key,
            client_endpoint,
        }
    }

    pub(crate) fn active_circuit(
        path: Vec<String>,
        link_instance: u64,
    ) -> dataplane::ActiveCircuit {
        dataplane::ActiveCircuit {
            circuit_id: tinect::circuit::CircuitId([1; 16]),
            data_key: chacha20poly1305::Key::from([2; 32]),
            link_instance,
            renewal_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            path,
            route_overrides: Vec::new(),
            path_inner_mtu: 1200,
            circuit_ceiling: 1200,
            configured_inner_mtu: 1200,
            capacity_vector: tinect::reconcile::CapacityVector::default(),
            config_generation: 0,
            lease_epoch: 1,
            send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            send_budget: Arc::new(std::sync::atomic::AtomicUsize::new(900)),
        }
    }

    /// A config whose local identity resolves and whose "exit" peer is backed
    /// by `client_key` (so its wire identity equals the server link's
    /// `peer_identity`), with optional manual paths.
    pub(crate) fn config_with_client_peer(
        client_key: &SigningKey,
        manual_paths: Vec<Vec<&str>>,
    ) -> Config {
        let mut config = crate::daemon::test_support::minimal_config();
        config.identity_key = Some(identity::encode_secret(&identity::generate()));
        config.identity_key_path = None;
        config.peers.insert(
            "exit".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&client_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: manual_paths
                    .into_iter()
                    .map(|path| tinect::config::ConfiguredPath {
                        path: path.into_iter().map(str::to_owned).collect(),
                        override_routes: Vec::new(),
                        override_upstream_dns: None,
                    })
                    .collect(),
            },
        );
        config
    }

    #[test]
    fn configured_destination_detection_covers_paths_policies_and_imports() {
        let mut config = crate::daemon::test_support::minimal_config();
        assert!(!is_configured_circuit_destination(&config, "exit"));
        config
            .path_policies
            .insert("exit".into(), Default::default());
        assert!(is_configured_circuit_destination(&config, "exit"));
        config.path_policies.clear();
        let key = identity::generate();
        config.peers.insert(
            "exit".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&key.verifying_key()),
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
        assert!(!is_configured_circuit_destination(&config, "exit"));
        config
            .peers
            .get_mut("exit")
            .unwrap()
            .paths
            .push(tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            });
        assert!(is_configured_circuit_destination(&config, "exit"));
    }

    #[test]
    fn configured_destination_detection_includes_domain_route_imports() {
        let dir = tempfile::tempdir().unwrap();
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\nfake_ip:\n  listen: 127.0.0.1:5354\n  upstream_dns: [1.1.1.1]\n  disable_ipv6: true\npeers:\n  exit:\n    public_key: {key}\n    endpoints: []\n    routes: [{{domain: example.test, priority: 100}}]\n"
        );
        fs::write(dir.path().join("node.yaml"), yaml).unwrap();
        let config = Config::load(dir.path().join("node.yaml")).unwrap();

        assert!(config.route_imports().is_empty());
        assert!(!config.domain_route_imports().is_empty());
        assert!(is_configured_circuit_destination(&config, "exit"));
    }

    #[test]
    fn resolved_active_path_uses_capacity_or_send_budget_and_marks_it_as_active() {
        let active = dataplane::ActiveCircuit {
            circuit_id: tinect::circuit::CircuitId([1; 16]),
            data_key: chacha20poly1305::Key::from([2; 32]),
            link_instance: 7,
            renewal_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            path: vec!["source".into(), "relay".into(), "exit".into()],
            route_overrides: Vec::new(),
            path_inner_mtu: 1200,
            circuit_ceiling: 1200,
            configured_inner_mtu: 1200,
            capacity_vector: tinect::reconcile::CapacityVector {
                edges: vec![tinect::reconcile::CapacityEdge {
                    from: "source".into(),
                    to: "relay".into(),
                    capacity: 1100,
                    generation: 1,
                }],
            },
            config_generation: 0,
            lease_epoch: 1,
            send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            send_budget: Arc::new(std::sync::atomic::AtomicUsize::new(900)),
        };
        let resolved = resolved_active_path("exit", &active, 123);
        assert_eq!(resolved.destination, "exit");
        assert_eq!(resolved.verified_inner_mtu, 1100);
        assert_eq!(resolved.candidate_rank, usize::MAX);
        assert_eq!(resolved.proof_valid_until, 123);
    }

    #[tokio::test]
    async fn empty_resolution_is_temporarily_unavailable_without_an_active_lease() {
        let config = crate::daemon::test_support::minimal_config();
        let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let result = resolve_destination(&config, "missing", &links, &topology, None, 4, 9).await;
        assert!(result.candidates.is_empty());
        assert!(result.preferred.is_none());
        assert!(matches!(
            result.desired.availability,
            tinect::reconcile::Availability::TemporarilyUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn active_path_proof_requires_the_exact_registered_first_hop_link() {
        let pair = link_pair().await;
        let config = config_with_client_peer(&pair.client_key, Vec::new());
        let local = config.local_identity().unwrap();
        let exit = config.peer_identity("exit").unwrap();
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".to_owned(),
            pair.server_link.clone(),
        )])));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));

        let active = active_circuit(
            vec![local.clone(), exit.clone()],
            pair.server_link.instance(),
        );
        assert_eq!(
            active_path_proof_valid_until(&active, &links, &topology).await,
            Some(u64::MAX)
        );
        assert!(active_path_has_valid_proof(&active, &links, &topology).await);

        // A path without a second hop has no proof window at all.
        let one_hop = active_circuit(vec![local], pair.server_link.instance());
        assert!(
            active_path_proof_valid_until(&one_hop, &links, &topology)
                .await
                .is_none()
        );
        assert!(!active_path_has_valid_proof(&one_hop, &links, &topology).await);

        // The active link instance is not served by any registered Link.
        let stale = active_circuit(vec!["source".into(), exit], 999);
        assert!(
            active_path_proof_valid_until(&stale, &links, &topology)
                .await
                .is_none()
        );
        assert!(!active_path_has_valid_proof(&stale, &links, &topology).await);
    }

    #[test]
    fn resolved_active_path_falls_back_to_send_budget_without_capacity() {
        let active = active_circuit(vec!["source".into(), "exit".into()], 7);
        let resolved = resolved_active_path("exit", &active, 42);
        assert_eq!(resolved.verified_inner_mtu, 900);
        assert_eq!(resolved.proof_valid_until, 42);
        assert_eq!(resolved.candidate_rank, usize::MAX);
    }

    #[tokio::test]
    async fn resolve_candidates_skips_manual_paths_without_a_matching_link() {
        let pair = link_pair().await;
        let relay_key = identity::generate();
        let mut config =
            config_with_client_peer(&pair.client_key, vec![vec!["a", "relay", "exit"]]);
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
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let result = resolve_destination(&config, "exit", &links, &topology, None, 1, 1).await;
        // The manual path resolves to [local, relay, exit], but no registered
        // Link serves the relay first hop, so no candidate can be built.
        assert!(result.candidates.is_empty());
        assert!(matches!(
            result.desired.availability,
            tinect::reconcile::Availability::TemporarilyUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn resolve_candidates_skips_manual_paths_without_downstream_evidence() {
        let relay_key = identity::generate();
        let pair = link_pair_with_client_key(relay_key.clone()).await;
        let relay = identity::node_id(&relay_key.verifying_key());
        let mut config =
            config_with_client_peer(&identity::generate(), vec![vec!["a", "relay", "exit"]]);
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
        // The relay first hop is served by a topology-ready Link, but the
        // topology carries no relay -> exit advertisement, so path_evidence
        // fails and the candidate is skipped.
        assert_eq!(pair.server_link.peer_identity, relay);
        pair.server_link.mark_topology_snapshot_received();
        pair.server_link.mark_topology_snapshot_acknowledged();
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".to_owned(),
            pair.server_link.clone(),
        )])));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let result = resolve_destination(&config, "exit", &links, &topology, None, 1, 1).await;
        assert!(result.candidates.is_empty());
    }

    #[tokio::test]
    async fn resolve_destination_keeps_active_lease_as_proof_stale_without_candidates() {
        let pair = link_pair().await;
        let config = config_with_client_peer(&pair.client_key, Vec::new());
        let local = config.local_identity().unwrap();
        let exit = config.peer_identity("exit").unwrap();
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".to_owned(),
            pair.server_link.clone(),
        )])));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let active = active_circuit(vec![local, exit], pair.server_link.instance());
        let resolution =
            resolve_destination(&config, "exit", &links, &topology, Some(&active), 3, 7).await;
        assert!(resolution.candidates.is_empty());
        assert!(matches!(
            resolution.desired.availability,
            tinect::reconcile::Availability::ProofStale {
                valid_until: u64::MAX
            }
        ));
        let path = resolution.desired.path.expect("active path preserved");
        assert_eq!(path.first_hop_link_instance, pair.server_link.instance());
        assert_eq!(path.proof_valid_until, u64::MAX);
        assert_eq!(path.candidate_rank, usize::MAX);
    }
}
