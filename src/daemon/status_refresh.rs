use super::support::{observable_node_names, unix_now};
use std::{collections::HashMap, sync::Arc};
use tinect::{
    config::Config,
    observability::Observability,
    runtime::{DaemonSupervisor, LinkRegistry, SharedDaemonState, SharedTopology},
    status::DaemonState,
    topology::Topology,
};

pub(crate) async fn refresh_status_snapshot(
    state: &SharedDaemonState,
    links: &LinkRegistry,
    topology: &SharedTopology,
    observability: &Observability,
    node_names: &HashMap<String, String>,
    rendered_topology_generation: &mut Option<u64>,
    supervisor: &DaemonSupervisor,
) {
    let metrics = links
        .lock()
        .expect("link registry lock")
        .iter()
        .map(|(peer, link)| (peer.clone(), link.metrics()))
        .collect::<HashMap<_, _>>();
    let (dot, nodes, generation) = {
        let graph = topology.read().await;
        let now = unix_now();
        let generation = graph.generation();
        let dot = (*rendered_topology_generation != Some(generation))
            .then(|| graph.dot_with_names(now, |identity| node_names.get(identity).cloned()));
        *rendered_topology_generation = Some(generation);
        (dot, graph.node_count(now), generation)
    };
    let observed = observability.snapshot();
    {
        let mut daemon = state.write().await;
        daemon.status.supervised_tasks = supervisor.task_count();
        daemon.status.shutting_down = supervisor.is_shutting_down();
        for link in &mut daemon.status.links {
            link.metrics = metrics.get(&link.peer).cloned();
        }
        daemon.status.circuit_traffic = observed.circuits;
        daemon.status.acl_rejections = observed.acl_rejections;
        daemon.status.topology_nodes = nodes;
        daemon.status.topology_generation = generation;
        if let Some(dot) = dot {
            daemon.topology_dot = dot;
        }
    }
    // Notify outside the write lock: tokio RwLock is not re-entrant, and
    // reading the state here would deadlock the refresher (and every other
    // status writer behind it).
    state.read().await.status_refresh_done.notify_waiters();
}

pub(crate) async fn start_status_refresh(
    state: Arc<tokio::sync::RwLock<DaemonState>>,
    links: tinect::runtime::LinkRegistry,
    topology: Arc<tokio::sync::RwLock<Topology>>,
    observability: Arc<Observability>,
    config: Config,
    supervisor: DaemonSupervisor,
) {
    let node_names = observable_node_names(&config);
    let status_supervisor = supervisor.clone();
    supervisor
        .spawn(async move {
            let mut rendered_topology_generation = None;
            let mut last_refresh: Option<std::time::Instant> = None;
            loop {
                // Register before checking the pending flag so a request
                // that lands between the check and the wait cannot be lost.
                let requested = state.read().await.status_refresh_requested.clone();
                let notified = requested.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if !state
                    .read()
                    .await
                    .status_refresh_pending
                    .swap(false, std::sync::atomic::Ordering::Acquire)
                {
                    notified.await;
                }
                // Coalesce high-frequency management queries: refresh at most
                // once per second even when callers poll faster.  Requests
                // that arrive during the quiet period stay pending and are
                // served by the next refresh; their waiters time out and
                // serve the previous snapshot, matching the old 1s polling
                // freshness without a fixed background timer.
                if let Some(previous) = last_refresh {
                    let elapsed = previous.elapsed();
                    if elapsed < STATUS_REFRESH_MIN_INTERVAL {
                        tokio::time::sleep(STATUS_REFRESH_MIN_INTERVAL - elapsed).await;
                    }
                }
                refresh_status_snapshot(
                    &state,
                    &links,
                    &topology,
                    &observability,
                    &node_names,
                    &mut rendered_topology_generation,
                    &status_supervisor,
                )
                .await;
                last_refresh = Some(std::time::Instant::now());
            }
        })
        .await;
}

const STATUS_REFRESH_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use tinect::identity;

    fn minimal_config() -> Config {
        Config {
            id: "a".into(),
            accept_connections: true,
            allow_transit: true,
            identity_key: None,
            identity_key_path: Some("unused".into()),
            listen: "quic://127.0.0.1:1".into(),
            fake_tcp_reset_key: Default::default(),
            fwmark: None,
            managed_routes: true,
            carrier_interface: None,
            dns_servers: Default::default(),
            fake_ip: None,
            route_sets: Default::default(),
            nft_healthy_set: None,
            direct: None,
            post_up: None,
            pre_down: None,
            tun: tinect::config::TunConfig {
                enabled: true,
                name: "tinea".into(),
                addresses: vec!["10.64.0.1/32".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            runtime: Default::default(),
            link_health: Default::default(),
            path_migration: Default::default(),
            peers: Default::default(),
            connect_to: Default::default(),
            repair_rate: 0.0,
            path_policies: Default::default(),
            allowed_routes: Default::default(),
            allowed_local_ports: Default::default(),
        }
    }

    #[tokio::test]
    async fn refresh_request_round_trip_completes_without_deadlock() {
        let config = minimal_config();
        let state = Arc::new(tokio::sync::RwLock::new(
            tinect::runtime::initial_daemon_state(&config, Arc::new(Observability::new(0))),
        ));
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let supervisor = DaemonSupervisor::default();
        let node_names = observable_node_names(&config);

        let refresher_state = state.clone();
        let refresher_links = links.clone();
        let refresher_topology = topology.clone();
        let refresher_observability = Arc::new(Observability::new(0));
        let refresher_names = node_names.clone();
        let refresher_supervisor = supervisor.clone();
        let refresher = tokio::spawn(async move {
            let mut rendered = None;
            loop {
                let requested = refresher_state
                    .read()
                    .await
                    .status_refresh_requested
                    .clone();
                let notified = requested.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if !refresher_state
                    .read()
                    .await
                    .status_refresh_pending
                    .swap(false, std::sync::atomic::Ordering::Acquire)
                {
                    notified.await;
                }
                refresh_status_snapshot(
                    &refresher_state,
                    &refresher_links,
                    &refresher_topology,
                    &refresher_observability,
                    &refresher_names,
                    &mut rendered,
                    &refresher_supervisor,
                )
                .await;
            }
        });

        // Mirror the management-handler handshake.  A refresh that reads the
        // state while still holding its write lock deadlocks every status
        // writer, so this round trip must complete within the timeout.
        let done = {
            let daemon = state.read().await;
            daemon.status_refresh_done.clone()
        };
        let notified = done.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        state
            .read()
            .await
            .status_refresh_pending
            .store(true, std::sync::atomic::Ordering::Release);
        state.read().await.status_refresh_requested.notify_waiters();
        tokio::time::timeout(std::time::Duration::from_secs(2), notified)
            .await
            .expect("status refresh round trip deadlocked");
        refresher.abort();
    }

    #[tokio::test]
    async fn high_frequency_refresh_requests_are_throttled() {
        let config = minimal_config();
        let state = Arc::new(tokio::sync::RwLock::new(
            tinect::runtime::initial_daemon_state(&config, Arc::new(Observability::new(0))),
        ));
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let supervisor = DaemonSupervisor::default();
        let node_names = observable_node_names(&config);
        let refreshes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let refresher_state = state.clone();
        let refresher_links = links.clone();
        let refresher_topology = topology.clone();
        let refresher_observability = Arc::new(Observability::new(0));
        let refresher_names = node_names.clone();
        let refresher_supervisor = supervisor.clone();
        let refresher_count = refreshes.clone();
        let refresher = tokio::spawn(async move {
            let mut rendered = None;
            let mut last_refresh: Option<std::time::Instant> = None;
            loop {
                let requested = refresher_state
                    .read()
                    .await
                    .status_refresh_requested
                    .clone();
                let notified = requested.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if !refresher_state
                    .read()
                    .await
                    .status_refresh_pending
                    .swap(false, std::sync::atomic::Ordering::Acquire)
                {
                    notified.await;
                }
                if let Some(previous) = last_refresh {
                    let elapsed = previous.elapsed();
                    if elapsed < STATUS_REFRESH_MIN_INTERVAL {
                        tokio::time::sleep(STATUS_REFRESH_MIN_INTERVAL - elapsed).await;
                    }
                }
                refresh_status_snapshot(
                    &refresher_state,
                    &refresher_links,
                    &refresher_topology,
                    &refresher_observability,
                    &refresher_names,
                    &mut rendered,
                    &refresher_supervisor,
                )
                .await;
                refresher_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                last_refresh = Some(std::time::Instant::now());
            }
        });

        // 1.2s of 10 Hz requests must not produce one refresh per request.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1200);
        while std::time::Instant::now() < deadline {
            state
                .read()
                .await
                .status_refresh_pending
                .store(true, std::sync::atomic::Ordering::Release);
            state.read().await.status_refresh_requested.notify_waiters();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        // Let the final throttled refresh finish.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let count = refreshes.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            (1..=3).contains(&count),
            "expected ~1 refresh/sec, got {count}"
        );
        refresher.abort();
    }

    #[tokio::test]
    async fn refresh_attaches_live_link_metrics_to_status_links() {
        let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
        let mut config = minimal_config();
        config.peers.insert(
            "client".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&pair.client_key.verifying_key()),
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
        let state = Arc::new(tokio::sync::RwLock::new(
            tinect::runtime::initial_daemon_state(&config, Arc::new(Observability::new(0))),
        ));
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".to_owned(),
            pair.server_link.clone(),
        )])));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let supervisor = DaemonSupervisor::default();
        let node_names = observable_node_names(&config);
        let mut rendered = None;
        refresh_status_snapshot(
            &state,
            &links,
            &topology,
            &Arc::new(Observability::new(0)),
            &node_names,
            &mut rendered,
            &supervisor,
        )
        .await;
        let daemon = state.read().await;
        let entry = daemon
            .status
            .links
            .iter()
            .find(|link| link.peer == "client")
            .expect("status entry for the configured peer");
        assert!(entry.metrics.is_some());
        assert_eq!(daemon.status.supervised_tasks, supervisor.task_count());
        assert_eq!(daemon.status.topology_nodes, 0);
    }

    #[tokio::test]
    async fn start_status_refresh_throttles_repeated_requests() {
        let config = minimal_config();
        let state = Arc::new(tokio::sync::RwLock::new(
            tinect::runtime::initial_daemon_state(&config, Arc::new(Observability::new(0))),
        ));
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology: SharedTopology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let observability = Arc::new(Observability::new(0));
        let supervisor = DaemonSupervisor::default();
        start_status_refresh(
            state.clone(),
            links.clone(),
            topology.clone(),
            observability.clone(),
            config,
            supervisor.clone(),
        )
        .await;

        let done = state.read().await.status_refresh_done.clone();
        let first = done.notified();
        tokio::pin!(first);
        first.as_mut().enable();
        state
            .read()
            .await
            .status_refresh_pending
            .store(true, std::sync::atomic::Ordering::Release);
        state.read().await.status_refresh_requested.notify_waiters();
        tokio::time::timeout(std::time::Duration::from_secs(2), &mut first)
            .await
            .expect("first refresh round trip");

        // The second request lands inside the 1s minimum interval and must
        // still be served by a throttled refresh, not dropped.
        let second = done.notified();
        tokio::pin!(second);
        second.as_mut().enable();
        state
            .read()
            .await
            .status_refresh_pending
            .store(true, std::sync::atomic::Ordering::Release);
        state.read().await.status_refresh_requested.notify_waiters();
        tokio::time::timeout(std::time::Duration::from_secs(3), &mut second)
            .await
            .expect("throttled second refresh round trip");
        supervisor
            .shutdown(std::time::Duration::from_secs(2))
            .await
            .unwrap();
    }
}
