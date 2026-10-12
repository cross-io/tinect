use super::support::{link_inner_mtu, physical_idle_deadline, unix_now};
use std::sync::Arc;
use tinect::{
    config::Config,
    control::ControlMessage,
    identity,
    physical::PhysicalPayload,
    runtime::DaemonSupervisor,
    status::DaemonState,
    topology::{LinkMetric, LinkStateAdvertisement, Topology},
};

pub(crate) async fn start_topology_advertisements(
    config: &Config,
    key: &Arc<ed25519_dalek::SigningKey>,
    links: tinect::runtime::LinkRegistry,
    topology: Arc<tokio::sync::RwLock<Topology>>,
    state: Arc<tokio::sync::RwLock<DaemonState>>,
    supervisor: DaemonSupervisor,
) {
    let node_identity = identity::node_id(&key.verifying_key());
    let key = key.clone();
    let node = config.clone();
    let keepalive_supervisor = supervisor.clone();
    supervisor
        .spawn(async move {
            let mut sequence = 0_u64;
            let keepalive = std::time::Duration::from_secs(node.link_health.keepalive_secs);
            let mut interval = tokio::time::interval(keepalive);
            loop {
                interval.tick().await;
                sequence = sequence.wrapping_add(1);
                let peers = links
                    .lock()
                    .expect("link registry lock")
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                let advertisement = LinkStateAdvertisement::new(
                    node_identity.clone(),
                    &key,
                    sequence,
                    unix_now() + tinect::timing::active().topology_advertisement_ttl_secs,
                    peers
                        .iter()
                        .map(|link| LinkMetric {
                            node: link.peer_identity.clone(),
                            cost: 1,
                            inner_mtu: link_inner_mtu(link),
                        })
                        .collect(),
                );
                let now = unix_now();
                let (nodes, generation) = {
                    let mut database = topology.write().await;
                    database.prune(now);
                    database.insert_local(advertisement.clone());
                    (database.node_count(now), database.generation())
                };
                let idle_timeout =
                    std::time::Duration::from_secs(node.link_health.idle_timeout_secs);
                for link in &peers {
                    let link = link.clone();
                    let advertisement = advertisement.clone();
                    keepalive_supervisor.spawn_background(async move {
                        if link.tx_idle_for() >= keepalive
                            && let Err(error) = link.send_physical(PhysicalPayload::Keepalive)
                        {
                            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "physical keepalive send failed");
                        }
                        let _ = link.send_control(&ControlMessage::Ping).await;
                        if link.rx_idle_for() >= physical_idle_deadline(idle_timeout, keepalive) {
                            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, "physical link received no authenticated payload before idle timeout");
                            link.close("physical payload idle timeout");
                            return;
                        }
                        if !link.queue_topology_deltas(vec![advertisement]).await {
                            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, "reliable topology Delta outbox is full");
                            link.mark_topology_unsynchronized();
                            link.close("reliable topology Delta outbox full");
                        }
                    });
                }
                let mut status = state.write().await;
                status.status.topology_nodes = nodes;
                status.status.topology_generation = generation;
            }
        })
        .await;
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tinect::observability::Observability;

    #[tokio::test]
    async fn advertisement_worker_publishes_an_empty_local_snapshot() {
        let config = crate::daemon::test_support::minimal_config();
        let key = Arc::new(identity::generate());
        let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let state = Arc::new(tokio::sync::RwLock::new(
            tinect::runtime::initial_daemon_state(&config, Arc::new(Observability::new(0))),
        ));
        let supervisor = DaemonSupervisor::default();

        start_topology_advertisements(
            &config,
            &key,
            links,
            topology,
            state.clone(),
            supervisor.clone(),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let state = state.read().await;
        assert_eq!(state.status.topology_nodes, 1);
        assert_eq!(state.status.topology_generation, 1);
        drop(state);
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn advertisement_worker_publishes_link_metrics_and_queues_deltas() {
        let client_key = identity::generate();
        let server_key = identity::generate();
        let server_public = identity::encode_public(&server_key.verifying_key());
        let (server, server_bare) = tinect::carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &tinect::config::LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
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
        let server_task = tokio::spawn(async move {
            tinect::carrier::accept_with_bare(
                &server,
                server_bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
            )
            .await
            .unwrap()
        });
        let (client, client_bare) = tinect::carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &tinect::config::LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = Arc::new(
            tinect::carrier::connect_with_link_health_and_bare(
                &client,
                client_bare.as_ref(),
                server_addr,
                tinect::config::CarrierProtocol::Quic,
                "server",
                &server_public,
                "client",
                &client_key,
                &tinect::config::LinkHealthConfig::default(),
            )
            .await
            .unwrap(),
        );
        server_task.await.unwrap();

        let mut config = crate::daemon::test_support::minimal_config();
        config.link_health.keepalive_secs = 1;
        config.link_health.idle_timeout_secs = 5;
        let key = Arc::new(identity::generate());
        let links = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".into(),
            link.clone(),
        )])));
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let state = Arc::new(tokio::sync::RwLock::new(
            tinect::runtime::initial_daemon_state(&config, Arc::new(Observability::new(0))),
        ));
        let supervisor = DaemonSupervisor::default();
        start_topology_advertisements(
            &config,
            &key,
            links,
            topology,
            state.clone(),
            supervisor.clone(),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        assert_eq!(state.read().await.status.topology_nodes, 1);
        assert_eq!(link.take_topology_deltas().await.len(), 1);

        link.close("test complete");
        client.close(0u32.into(), b"test complete");
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }
}
