//! Topology-backed path and capacity proof resolution for circuit workers.

use super::support::{link_inner_mtu, unix_now, wire_identity};
use std::sync::Arc;
use tinect::{carrier, config::Config, topology::Topology};

#[derive(Clone)]
pub(crate) struct PathEvidence {
    pub(crate) capacity_vector: tinect::reconcile::CapacityVector,
    pub(crate) proof_valid_until: Option<u64>,
}

/// Resolve capacity and proof from one topology snapshot and one timestamp.
///
/// Circuit reconciliation and route publication both need these two facts to
/// describe the same topology generation. Keeping them together also avoids
/// taking two read locks for every candidate path.
pub(crate) async fn path_evidence(
    path: &[String],
    link: &carrier::Link,
    topology: &Arc<tokio::sync::RwLock<Topology>>,
) -> Option<PathEvidence> {
    let first_capacity = link_inner_mtu(link);
    let first_generation = link
        .confirmed_user_ip_capacity()
        .map_or(0, |(_, generation)| generation);
    let mut edges = Vec::with_capacity(path.len().saturating_sub(1));
    if let Some(first_hop) = path.get(1) {
        edges.push(tinect::reconcile::CapacityEdge {
            from: path[0].clone(),
            to: first_hop.clone(),
            capacity: first_capacity,
            generation: first_generation,
        });
    }
    let now = unix_now();
    let snapshot = topology.read().await;
    let mut proof_valid_until = Some(u64::MAX);
    for edge in path.windows(2).skip(1) {
        let (capacity, generation) =
            snapshot.link_inner_mtu_with_generation(&edge[0], &edge[1], now)?;
        edges.push(tinect::reconcile::CapacityEdge {
            from: edge[0].clone(),
            to: edge[1].clone(),
            capacity,
            generation,
        });
        proof_valid_until = proof_valid_until.and_then(|valid_until| {
            snapshot
                .link_proof_valid_until(&edge[0], &edge[1], now)
                .map(|expires_at| valid_until.min(expires_at))
        });
    }
    Some(PathEvidence {
        capacity_vector: tinect::reconcile::CapacityVector { edges },
        proof_valid_until,
    })
}

pub(crate) async fn path_proof_valid_until(
    path: &[String],
    topology: &Arc<tokio::sync::RwLock<Topology>>,
) -> Option<u64> {
    let snapshot = topology.read().await;
    let now = unix_now();
    path.windows(2)
        .skip(1)
        .try_fold(u64::MAX, |valid_until, edge| {
            snapshot
                .link_proof_valid_until(&edge[0], &edge[1], now)
                .map(|expires_at| valid_until.min(expires_at))
        })
}

pub(crate) async fn resolve_paths(
    config: &Config,
    destination: &str,
    topology: &Arc<tokio::sync::RwLock<Topology>>,
) -> Vec<Vec<String>> {
    if let Some(peer) = config.peers.get(destination)
        && !peer.paths.is_empty()
    {
        return peer
            .paths
            .iter()
            .filter(|configured| configured.path.len() >= 2)
            .map(|configured| {
                configured
                    .path
                    .iter()
                    .filter_map(|name| wire_identity(config, name))
                    .collect()
            })
            .collect();
    }
    let mut policy = config
        .path_policies
        .get(destination)
        .cloned()
        .unwrap_or_default();
    policy.prefer_via = policy
        .prefer_via
        .iter()
        .filter_map(|name| wire_identity(config, name))
        .collect();
    policy.require_via = policy
        .require_via
        .iter()
        .filter_map(|name| wire_identity(config, name))
        .collect();
    policy.avoid = policy
        .avoid
        .iter()
        .filter_map(|name| wire_identity(config, name))
        .collect();
    let Some(local) = wire_identity(config, &config.id) else {
        return Vec::new();
    };
    let Some(destination) = wire_identity(config, destination) else {
        return Vec::new();
    };
    topology
        .read()
        .await
        .best_path(&local, &destination, &policy, unix_now())
        .map(|path| path.nodes)
        .into_iter()
        .collect()
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::circuit_resolution::tests::link_pair;
    use tinect::identity;
    use tinect::topology::LinkMetric;

    fn lsa_for(
        origin_key: &ed25519_dalek::SigningKey,
        node: &str,
        inner_mtu: u16,
        expires_at: u64,
    ) -> tinect::topology::LinkStateAdvertisement {
        tinect::topology::LinkStateAdvertisement::new(
            identity::node_id(&origin_key.verifying_key()),
            origin_key,
            1,
            expires_at,
            vec![LinkMetric {
                node: node.to_owned(),
                cost: 1,
                inner_mtu,
            }],
        )
    }

    fn config_with_identity() -> Config {
        let mut config = crate::daemon::test_support::minimal_config();
        let key = identity::generate();
        config.identity_key = Some(identity::encode_secret(&key));
        config.identity_key_path = None;
        let peer_key = identity::generate();
        config.peers.insert(
            "exit".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&peer_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: vec![
                    tinect::config::ConfiguredPath {
                        path: vec!["a".into()],
                        override_routes: Vec::new(),
                        override_upstream_dns: None,
                    },
                    tinect::config::ConfiguredPath {
                        path: vec!["a".into(), "exit".into()],
                        override_routes: Vec::new(),
                        override_upstream_dns: None,
                    },
                ],
            },
        );
        config
    }

    #[tokio::test]
    async fn manual_paths_filter_short_paths_and_translate_names_to_wire_ids() {
        let config = config_with_identity();
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let paths = resolve_paths(&config, "exit", &topology).await;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 2);
        assert_eq!(paths[0][0], config.local_identity().unwrap());
        assert_eq!(paths[0][1], config.peer_identity("exit").unwrap());
    }

    #[tokio::test]
    async fn unknown_destination_and_empty_topology_have_no_path() {
        let config = config_with_identity();
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        assert!(
            resolve_paths(&config, "missing", &topology)
                .await
                .is_empty()
        );
        let mut config = config;
        config.peers.get_mut("exit").unwrap().paths.clear();
        assert!(resolve_paths(&config, "exit", &topology).await.is_empty());
    }

    #[tokio::test]
    async fn automatic_paths_honor_wire_identity_and_policy_constraints() {
        let mut config = config_with_identity();
        let local_key = identity::decode_secret(config.identity_key.as_deref().unwrap()).unwrap();
        let relay_key = identity::generate();
        let exit_key = identity::decode_public(&config.peers["exit"].public_key).unwrap();
        let relay = identity::node_id(&relay_key.verifying_key());
        let exit = identity::node_id(&exit_key);
        config.peers.insert(
            "relay".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&relay_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: Some(true),
                allow_relay: Some(true),
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: Vec::new(),
            },
        );
        config.peers.get_mut("exit").unwrap().paths.clear();
        config.path_policies.insert(
            "exit".into(),
            tinect::topology::PathConstraint {
                prefer_via: vec!["relay".into(), "unknown-name".into()],
                require_via: vec!["relay".into()],
                avoid: vec!["unknown-name".into()],
                max_hops: Some(4),
            },
        );
        let local = config.local_identity().unwrap();
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let now = unix_now();
        topology
            .write()
            .await
            .apply(
                tinect::topology::LinkStateAdvertisement::new(
                    local.clone(),
                    &local_key,
                    1,
                    now + 60,
                    vec![tinect::topology::LinkMetric {
                        node: relay.clone(),
                        cost: 1,
                        inner_mtu: 1200,
                    }],
                ),
                now,
            )
            .unwrap();
        topology
            .write()
            .await
            .apply(
                tinect::topology::LinkStateAdvertisement::new(
                    relay.clone(),
                    &relay_key,
                    1,
                    now + 60,
                    vec![tinect::topology::LinkMetric {
                        node: exit.clone(),
                        cost: 1,
                        inner_mtu: 1100,
                    }],
                ),
                now,
            )
            .unwrap();

        let paths = resolve_paths(&config, "exit", &topology).await;
        assert_eq!(paths, vec![vec![local, relay, exit]]);
    }

    #[tokio::test]
    async fn path_evidence_resolves_downstream_edges_and_proof_from_topology() {
        let pair = link_pair().await;
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let now = unix_now();
        let relay_key = identity::generate();
        let relay = identity::node_id(&relay_key.verifying_key());
        let exit = "11".repeat(16);
        let expires_at = now + 60;
        topology
            .write()
            .await
            .apply(lsa_for(&relay_key, &exit, 1100, expires_at), now)
            .unwrap();
        let path = vec!["local".into(), relay.clone(), exit];

        let evidence = path_evidence(&path, &pair.server_link, &topology)
            .await
            .expect("topology-backed evidence");
        assert_eq!(evidence.capacity_vector.edges.len(), 2);
        assert_eq!(evidence.capacity_vector.edges[0].from, "local");
        assert_eq!(evidence.capacity_vector.edges[0].to, relay);
        assert_eq!(evidence.capacity_vector.edges[1].from, relay);
        assert_eq!(evidence.capacity_vector.edges[1].capacity, 1100);
        assert_eq!(evidence.proof_valid_until, Some(expires_at));

        // A missing downstream edge invalidates the whole evidence.
        let empty = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        assert!(
            path_evidence(&path, &pair.server_link, &empty)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn path_proof_valid_until_folds_edge_expiries() {
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let now = unix_now();
        let a = "aa".repeat(16);
        let relay_key = identity::generate();
        let relay = identity::node_id(&relay_key.verifying_key());
        let exit = "bb".repeat(16);
        let expires_at = now + 90;
        topology
            .write()
            .await
            .apply(lsa_for(&relay_key, &exit, 1100, expires_at), now)
            .unwrap();

        // Paths with fewer than three hops have no downstream edge to fold.
        assert_eq!(
            path_proof_valid_until(&[a.clone(), relay.clone()], &topology).await,
            Some(u64::MAX)
        );
        assert_eq!(
            path_proof_valid_until(std::slice::from_ref(&a), &topology).await,
            Some(u64::MAX)
        );
        // The relay -> exit proof expires with the advertisement.
        assert_eq!(
            path_proof_valid_until(&[a.clone(), relay.clone(), exit.clone()], &topology).await,
            Some(expires_at)
        );
        // A missing downstream edge has no proof at all.
        let empty = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        assert_eq!(
            path_proof_valid_until(&[a, relay, exit], &empty).await,
            None
        );
    }
}
