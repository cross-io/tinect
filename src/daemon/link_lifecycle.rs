use super::circuit_reconciler::secure_dataplane_required;
use super::control_handler::{
    ControlHandlerContext, notify_broken, spawn as spawn_control_handler,
};
use super::link_helpers::{
    outbound_attempt_timeout, outbound_bind_address, reconnect_delay_with_jitter,
    reconnect_jitter_seed, register_link, remove_link_if_current,
};
use super::support::{mark_current_link, mark_unbound_link, resolve_quic_endpoint, wire_paths};
use anyhow::Result;
use std::sync::Arc;
use tinect::{
    carrier,
    circuit::Router,
    config::Config,
    identity,
    runtime::{DaemonSupervisor, Runtime},
};

pub(crate) async fn start_links(
    c: &Config,
    runtime: &Runtime,
    supervisor: DaemonSupervisor,
    key: &Arc<ed25519_dalek::SigningKey>,
) -> Result<(Arc<Router>, std::net::SocketAddr)> {
    let links = runtime.links.clone();
    let state = runtime.state.clone();
    let control_plane = runtime.circuits.clone();
    let dns = runtime.dns.clone();
    let key = key.clone();
    let (carrier_protocol, listen_addr) = c.listen_endpoint()?;
    let (endpoint, bare_socket) = carrier::endpoint_with_options_and_bare(
        carrier_protocol,
        listen_addr,
        &c.link_health,
        c.fwmark,
        c.carrier_interface.as_deref(),
        c.fake_tcp_reset_key.as_bytes(),
    )?;
    let listen_addr = endpoint.local_addr()?;
    let accept_endpoint = endpoint.clone();
    let accept_bare_socket = bare_socket.clone();
    let peers = c.peers.clone();
    let accept_connections = c.accept_connections;
    let accept_repair_rate = tinect::config::repair_rate_milli(c.repair_rate);
    let local_id = c.id.clone();
    let accept_key = key.clone();
    let accept_state = state.clone();
    let accept_links = links.clone();
    let accept_supervisor = supervisor.clone();
    let transit = tinect::policy::TransitPolicy::new(
        c.allow_transit,
        c.peers
            .iter()
            .map(|(name, peer)| {
                (
                    c.peer_identity(name).expect("validated peer key"),
                    Some(peer.allows_transit(c.allow_transit)),
                )
            })
            .collect(),
    );
    let local_identity = identity::node_id(&key.verifying_key());
    let mut router = Router::with_paths(local_identity, transit, links.clone(), wire_paths(c));
    router.set_secure_dataplane(secure_dataplane_required(c));
    let router = Arc::new(router);
    router
        .set_relay_permissions(
            c.peers
                .iter()
                .map(|(name, peer)| {
                    (
                        c.peer_identity(name).expect("validated peer key"),
                        peer.allows_relay(),
                    )
                })
                .collect(),
        )
        .await;
    router
        .set_known_sources(
            c.peers
                .values()
                .filter_map(|peer| identity::decode_public(&peer.public_key).ok())
                .map(|key| identity::node_id(&key))
                .collect(),
        )
        .await;
    let accept_router = router.clone();
    let accept_runtime = runtime.clone();
    let accept_control_plane = control_plane.clone();
    supervisor.spawn(async move {
        loop {
            let accepted = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                carrier::accept_with_bare_and_fec(
                    &accept_endpoint,
                    accept_bare_socket.as_ref(),
                    carrier_protocol,
                    &peers,
                    accept_connections,
                    &local_id,
                    accept_key.as_ref(),
                    accept_repair_rate,
                ),
            )
            .await;
            match accepted {
                Err(_) => {
                    tracing::debug!("inbound QUIC handshake timed out; continuing accept loop");
                }
                Ok(Ok(link)) => {
                    let link = Arc::new(link);
                    if !register_link(&accept_links, link.clone()).await {
                        tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, "duplicate inbound QUIC link discarded");
                        link.close("duplicate QUIC link");
                        continue;
                    }
                    tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, "inbound QUIC link authenticated");
                    mark_current_link(
                        &accept_state,
                        &accept_links,
                        &link.peer,
                        link.instance(),
                        true,
                        None,
                        &accept_control_plane.opens,
                    )
                    .await;
                    accept_control_plane.opens.request_reconcile();
                    spawn_control_handler(
                        link.clone(),
                        ControlHandlerContext {
                            router: accept_router.clone(),
                            runtime: accept_runtime.clone(),
                            identity: accept_key.clone(),
                            supervisor: accept_supervisor.clone(),
                        },
                    );
                }
                // `Endpoint::accept` returns `None` once the local endpoint
                // is closed during shutdown. This is terminal, not an
                // authentication rejection; retrying it would spin and flood
                // logs until Tokio tears down the task.
                Ok(Err(carrier::CarrierError::EndpointClosed)) => {
                    tracing::debug!("QUIC endpoint closed; stopping inbound accept loop");
                    break;
                }
                Ok(Err(error)) => tracing::warn!(error = %error, "inbound QUIC link rejected"),
            }
        }
    }).await;
    for target in &c.connect_to {
        // Config validation guarantees the target and its first endpoint.
        let peer_name = target.peer_name().to_owned();
        let active_repair_rate = target.repair_rate_milli();
        let peer = &c.peers[&peer_name];
        let endpoint_url = &peer.endpoints[0];
        let endpoint_url = endpoint_url.clone();
        let outbound_protocol =
            tinect::config::CarrierEndpoint::parse(&endpoint_url, "peer endpoint")?.protocol;
        let public_key = peer.public_key.clone();
        let outbound_key = key.clone();
        let local_id = c.id.clone();
        let outbound_state = state.clone();
        let outbound_links = links.clone();
        let outbound_router = router.clone();
        let outbound_runtime = runtime.clone();
        let outbound_control_plane = control_plane.clone();
        let link_health = c.link_health.clone();
        let outbound_fwmark = c.fwmark;
        let outbound_interface = c.carrier_interface.clone();
        let fake_tcp_reset_key = c.fake_tcp_reset_key.clone();
        let dns = dns.clone();
        let outbound_supervisor = supervisor.clone();
        supervisor.spawn(async move {
            let mut failure_streak = 0u32;
            loop {
                // Either endpoint may proactively dial. Once an inbound or
                // outbound connection is registered, stop dialing until it
                // closes; simultaneous dials are reconciled below. A closed
                // Link can briefly remain in the registry while its handler
                // unwinds, so reclaim it here instead of suppressing retries
                // forever.
                let registered_link = outbound_links
                    .lock()
                    .expect("link registry lock")
                    .get(&peer_name)
                    .cloned();
                if let Some(link) = registered_link {
                    if link.close_reason().is_some() {
                        failure_streak = failure_streak.saturating_add(1);
                        remove_link_if_current(
                            &outbound_links,
                            &outbound_state,
                            &peer_name,
                            link.instance(),
                            &outbound_control_plane.opens,
                        )
                        .await;
                        let retry_delay = reconnect_delay_with_jitter(
                            link_health.reconnect_interval_secs,
                            failure_streak,
                            reconnect_jitter_seed(&peer_name, &endpoint_url),
                        );
                        tracing::debug!(peer = %peer_name, retry_ms = retry_delay.as_millis(), failure_streak, "closed outbound link scheduled for reconnect");
                        tokio::time::sleep(retry_delay).await;
                        continue;
                    }
                    // The Link is healthy and was registered (possibly by the
                    // peer's dial).  Wait for its close event instead of
                    // polling the registry, then back off once before
                    // rechecking: with bidirectional dialers an immediate
                    // redial after a superseded close can spin replace-and-
                    // redial instead of letting the peer's registration win.
                    link.wait_closed().await;
                    tokio::time::sleep(std::time::Duration::from_secs(
                        link_health.reconnect_interval_secs,
                    ))
                    .await;
                    continue;
                }
                let outcome = match tokio::time::timeout(
                    outbound_attempt_timeout(&link_health),
                    async {
                        let addresses = resolve_quic_endpoint(&endpoint_url, &dns).await?;
                        let mut errors = Vec::new();
                        for addr in addresses {
                            // Every active dial gets a fresh client endpoint and an
                            // ephemeral local port. Keep the endpoint and its bare
                            // socket together so QUIC streams and bare Physical
                            // traffic continue to share one underlay socket.
                            let (dial_endpoint, dial_bare_socket) =
                                carrier::endpoint_with_options_and_bare(
                                    outbound_protocol,
                                    outbound_bind_address(listen_addr, addr),
                                    &link_health,
                                    outbound_fwmark,
                                    outbound_interface.as_deref(),
                                    fake_tcp_reset_key.as_bytes(),
                                )?;
                            match carrier::connect_with_link_health_and_bare_and_fec(
                                &dial_endpoint,
                                dial_bare_socket.as_ref(),
                                addr,
                                outbound_protocol,
                                &peer_name,
                                &public_key,
                                &local_id,
                                outbound_key.as_ref(),
                                &link_health,
                                active_repair_rate,
                            )
                            .await
                            {
                                Ok(link) => return Ok((link, dial_endpoint)),
                                Err(error) => errors.push(format!("{addr}: {error}")),
                            }
                        }
                        Err(anyhow::anyhow!(
                            "all resolved addresses for {endpoint_url} failed: {}",
                            errors.join(" | ")
                        ))
                    },
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => Err(anyhow::anyhow!(
                        "outbound connection attempt exceeded {} seconds",
                        outbound_attempt_timeout(&link_health).as_secs()
                    )),
                };
                match outcome {
                    Ok((link, dial_endpoint_guard)) => {
                        // Keep this per-attempt client endpoint alive for the
                        // whole Link lifetime. A reconnect creates a new one.
                        let _dial_endpoint_guard = dial_endpoint_guard;
                        failure_streak = 0;
                        let link = Arc::new(link);
                        if !register_link(&outbound_links, link.clone()).await {
                            tracing::info!(peer_name = %peer_name, peer_identity = %link.peer_identity, "duplicate outbound QUIC link discarded");
                            link.close("duplicate QUIC link");
                            continue;
                        }
                        tracing::info!(peer_name = %peer_name, peer_identity = %link.peer_identity, endpoint = %endpoint_url, "outbound QUIC link authenticated");
                        mark_current_link(
                            &outbound_state,
                            &outbound_links,
                            &peer_name,
                            link.instance(),
                            true,
                            None,
                            &outbound_control_plane.opens,
                        )
                        .await;
                        outbound_control_plane.opens.request_reconcile();
                        spawn_control_handler(
                            link.clone(),
                            ControlHandlerContext {
                                router: outbound_router.clone(),
                                runtime: outbound_runtime.clone(),
                                identity: outbound_key.clone(),
                                supervisor: outbound_supervisor.clone(),
                            },
                        );
                        link.wait_closed().await;
                        // The control handler normally performs this cleanup,
                        // but a replaced outbound Link can be observed here
                        // before its stream task has unwound.  Remove all
                        // state that points at this Link immediately so old
                        // relay labels cannot forward DATAGRAMs into a
                        // closed connection after reconnect.
                        outbound_router
                            .authorizations()
                            .remove_link(link.instance())
                            .await;
                        outbound_control_plane.sessions.remove_link(link.instance()).await;
                        outbound_control_plane.return_flows.remove_link(link.instance());
                        outbound_control_plane.circuit_dns.remove_link(link.instance());
                        outbound_control_plane
                            .opens
                            .remove_link(link.instance(), link.lifecycle_token())
                            .await;
                        outbound_router.remove_relay_labels(link.instance());
                        outbound_router
                            .remove_relay_labels_for_outgoing(link.instance());
                        let broken = outbound_router.remove_bindings(link.instance());
                        notify_broken(&outbound_links, outbound_key.as_ref(), broken).await;
                        remove_link_if_current(
                            &outbound_links,
                            &outbound_state,
                            &peer_name,
                            link.instance(),
                            &outbound_control_plane.opens,
                        )
                        .await;
                    }
                    Err(error) => {
                        failure_streak = failure_streak.saturating_add(1);
                        let retry_delay =
                            reconnect_delay_with_jitter(
                                link_health.reconnect_interval_secs,
                                failure_streak,
                                reconnect_jitter_seed(&peer_name, &endpoint_url),
                            );
                        tracing::warn!(peer = %peer_name, endpoint = %endpoint_url, error = %error, retry_secs = retry_delay.as_secs(), failure_streak, "outbound QUIC link attempt failed");
                        mark_unbound_link(
                            &outbound_state,
                            &outbound_links,
                            &peer_name,
                            Some(error.to_string()),
                        )
                        .await;
                        tokio::time::sleep(retry_delay).await;
                        continue;
                    }
                }
                let retry_delay = reconnect_delay_with_jitter(
                    link_health.reconnect_interval_secs,
                    failure_streak.max(1),
                    reconnect_jitter_seed(&peer_name, &endpoint_url),
                );
                tokio::time::sleep(retry_delay).await;
            }
        }).await;
    }
    Ok((router, listen_addr))
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::time::Duration;
    use tinect::config::CarrierProtocol;

    fn peer_config(key: &SigningKey, endpoints: Vec<String>) -> tinect::config::Peer {
        tinect::config::Peer {
            public_key: identity::encode_public(&key.verifying_key()),
            endpoints,
            upstream_dns: None,
            accept_connections: None,
            allow_transit: None,
            allow_relay: None,
            bind_addresses: Vec::new(),
            routes: Vec::new(),
            paths: Vec::new(),
        }
    }

    fn loopback_config(id: &str) -> Config {
        let mut config = crate::daemon::test_support::minimal_config();
        config.id = id.into();
        config.listen = "quic://127.0.0.1:0".into();
        config
    }

    fn registered_link(runtime: &Runtime, peer: &str) -> Option<Arc<carrier::Link>> {
        runtime
            .links
            .lock()
            .expect("link registry lock")
            .get(peer)
            .cloned()
    }

    async fn link_last_error(runtime: &Runtime, peer: &str) -> Option<String> {
        runtime
            .state
            .read()
            .await
            .status
            .links
            .iter()
            .find(|link| link.peer == peer)
            .and_then(|link| link.last_error.clone())
    }

    async fn link_is_healthy(runtime: &Runtime, peer: &str) -> bool {
        runtime
            .state
            .read()
            .await
            .status
            .links
            .iter()
            .find(|link| link.peer == peer)
            .is_some_and(|link| link.healthy)
    }

    async fn wait_until<F, Fut>(mut condition: F, timeout: Duration, description: &str)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = std::time::Instant::now() + timeout;
        while !condition().await {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {description}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Reserve a loopback UDP port and retain the socket so it cannot be
    /// reused before the caller has finished constructing its test config.
    fn unused_udp_port() -> (std::net::UdpSocket, u16) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        (socket, port)
    }

    /// Dial `server_key`'s node (expected peer name "b") from an ephemeral
    /// loopback endpoint, returning the endpoint so the caller can keep the
    /// connection alive or close it.
    async fn dial_peer(
        addr: std::net::SocketAddr,
        server_key: &SigningKey,
        dial_key: &SigningKey,
        local_id: &str,
    ) -> (
        quinn::Endpoint,
        std::result::Result<carrier::Link, carrier::CarrierError>,
    ) {
        let health = tinect::config::LinkHealthConfig::default();
        let (endpoint, bare) = carrier::endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &health,
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let result = carrier::connect_with_link_health_and_bare_and_fec(
            &endpoint,
            bare.as_ref(),
            addr,
            CarrierProtocol::Quic,
            "b",
            &identity::encode_public(&server_key.verifying_key()),
            local_id,
            dial_key,
            &health,
            0,
        )
        .await;
        (endpoint, result)
    }

    #[tokio::test]
    async fn rejects_a_listen_url_with_an_unknown_scheme() {
        let key = Arc::new(identity::generate());
        let mut config = crate::daemon::test_support::minimal_config();
        config.listen = "http://127.0.0.1:0".into();
        let runtime = Runtime::new(config.clone()).unwrap();
        let error = match start_links(&config, &runtime, DaemonSupervisor::default(), &key).await {
            Ok(_) => panic!("an unknown listen scheme must fail"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("listen"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn fails_when_the_listen_port_is_already_bound() {
        let blocker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = blocker.local_addr().unwrap().port();
        let key = Arc::new(identity::generate());
        let mut config = crate::daemon::test_support::minimal_config();
        config.listen = format!("quic://127.0.0.1:{port}");
        let runtime = Runtime::new(config.clone()).unwrap();
        let result = start_links(&config, &runtime, DaemonSupervisor::default(), &key).await;
        drop(blocker);
        assert!(result.is_err(), "binding an in-use port must fail");
    }

    #[tokio::test]
    async fn rejects_a_connect_target_with_an_unknown_endpoint_scheme() {
        let key = Arc::new(identity::generate());
        let peer_key = identity::generate();
        let mut config = loopback_config("a");
        config.peers.insert(
            "b".into(),
            peer_config(&peer_key, vec!["http://127.0.0.1:9".into()]),
        );
        config.connect_to = vec!["b".into()];
        let runtime = Runtime::new(config.clone()).unwrap();
        let error = match start_links(&config, &runtime, DaemonSupervisor::default(), &key).await {
            Ok(_) => panic!("an unknown peer endpoint scheme must fail"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("peer endpoint"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn derives_a_wildcard_listen_address_from_the_connect_target() {
        let key = Arc::new(identity::generate());
        let peer_key = identity::generate();
        let mut config = loopback_config("a");
        config.listen = String::new();
        config.peers.insert(
            "b".into(),
            peer_config(&peer_key, vec!["quic://127.0.0.1:9".into()]),
        );
        config.connect_to = vec!["b".into()];
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        let (_router, listen_addr) = start_links(&config, &runtime, supervisor.clone(), &key)
            .await
            .unwrap();
        assert_eq!(
            listen_addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        );
        assert_ne!(listen_addr.port(), 0);
        supervisor.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn starts_accept_loop_with_peers_and_no_connect_targets() {
        let key = Arc::new(identity::generate());
        let mut config = loopback_config("a");
        // Peers exercise the transit policy, relay permission, known-source,
        // and wire-path wiring performed during startup.
        let relay_key = identity::generate();
        let mut relay_peer = peer_config(&relay_key, Vec::new());
        relay_peer.allow_relay = Some(true);
        relay_peer.allow_transit = Some(false);
        let dest_key = identity::generate();
        let mut dest_peer = peer_config(&dest_key, Vec::new());
        dest_peer.paths = vec![tinect::config::ConfiguredPath {
            path: vec!["relay".into()],
            override_routes: Vec::new(),
            override_upstream_dns: None,
        }];
        config.peers.insert("relay".into(), relay_peer);
        config.peers.insert("dest".into(), dest_peer);
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        let (_router, listen_addr) = start_links(&config, &runtime, supervisor.clone(), &key)
            .await
            .unwrap();
        assert_eq!(
            listen_addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_ne!(listen_addr.port(), 0);
        assert_eq!(supervisor.task_count(), 1);
        supervisor.shutdown(Duration::from_secs(2)).await.unwrap();
        assert_eq!(supervisor.task_count(), 0);
    }

    #[tokio::test]
    async fn dialer_marks_an_unreachable_peer_unbound() {
        let key = Arc::new(identity::generate());
        let peer_key = identity::generate();
        let mut config = loopback_config("a");
        let (_unused_port, port) = unused_udp_port();
        config.peers.insert(
            "b".into(),
            peer_config(&peer_key, vec![format!("quic://127.0.0.1:{port}")]),
        );
        config.connect_to = vec![tinect::config::ConnectTarget::Configured(
            tinect::config::ConnectTargetConfig {
                peer: "b".into(),
                repair_rate: 0.1,
            },
        )];
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        start_links(&config, &runtime, supervisor.clone(), &key)
            .await
            .unwrap();
        wait_until(
            || async { link_last_error(&runtime, "b").await.is_some() },
            Duration::from_secs(15),
            "unreachable peer to be marked unbound",
        )
        .await;
        assert!(registered_link(&runtime, "b").is_none());
        assert!(!link_is_healthy(&runtime, "b").await);
        supervisor.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn dialer_reclaims_a_closed_registered_link() {
        let key = Arc::new(identity::generate());
        let peer_key = identity::generate();
        let mut config = loopback_config("a");
        let (_unused_port, port) = unused_udp_port();
        config.peers.insert(
            "b".into(),
            peer_config(&peer_key, vec![format!("quic://127.0.0.1:{port}")]),
        );
        config.connect_to = vec!["b".into()];
        let runtime = Runtime::new(config.clone()).unwrap();
        // A link that closed while still registered must be reclaimed by the
        // dialer instead of suppressing retries forever.
        let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
        pair.client_link.close("superseded test link");
        runtime
            .links
            .lock()
            .expect("link registry lock")
            .insert("b".into(), pair.client_link.clone());
        let supervisor = DaemonSupervisor::default();
        start_links(&config, &runtime, supervisor.clone(), &key)
            .await
            .unwrap();
        wait_until(
            || async { registered_link(&runtime, "b").is_none() },
            Duration::from_secs(10),
            "closed registered link to be reclaimed",
        )
        .await;
        // After reclaiming, the dialer resumes connection attempts.
        wait_until(
            || async {
                link_last_error(&runtime, "b")
                    .await
                    .is_some_and(|error| error != "QUIC connection closed")
            },
            Duration::from_secs(15),
            "dialer to resume attempts after reclaiming the closed link",
        )
        .await;
        supervisor.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn dialer_waits_for_a_healthy_registered_link_to_close() {
        let key = Arc::new(identity::generate());
        let peer_key = identity::generate();
        let mut config = loopback_config("a");
        let (_unused_port, port) = unused_udp_port();
        config.peers.insert(
            "b".into(),
            peer_config(&peer_key, vec![format!("quic://127.0.0.1:{port}")]),
        );
        config.connect_to = vec!["b".into()];
        let runtime = Runtime::new(config.clone()).unwrap();
        // A healthy link registered before the dialer starts suppresses
        // dialing until the link closes.
        let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
        runtime
            .links
            .lock()
            .expect("link registry lock")
            .insert("b".into(), pair.client_link.clone());
        let supervisor = DaemonSupervisor::default();
        start_links(&config, &runtime, supervisor.clone(), &key)
            .await
            .unwrap();
        // While the healthy link is registered no dial failure is recorded;
        // the status keeps its initial "carrier not connected" placeholder.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            link_last_error(&runtime, "b").await.as_deref(),
            Some("carrier not connected")
        );
        pair.client_link.close("test close");
        // After the close event the dialer backs off once, then reclaims the
        // closed link on the next pass and resumes dialing.
        wait_until(
            || async { registered_link(&runtime, "b").is_none() },
            Duration::from_secs(15),
            "dialer to reclaim the link after it closed",
        )
        .await;
        supervisor.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn outbound_link_connects_and_reconnects_after_close() {
        let key_b = Arc::new(identity::generate());
        let key_a = Arc::new(identity::generate());

        let mut config_b = loopback_config("b");
        config_b
            .peers
            .insert("a".into(), peer_config(&key_a, Vec::new()));
        let runtime_b = Runtime::new(config_b.clone()).unwrap();
        let supervisor_b = DaemonSupervisor::default();
        let (_router_b, addr_b) = start_links(&config_b, &runtime_b, supervisor_b.clone(), &key_b)
            .await
            .unwrap();

        let mut config_a = loopback_config("a");
        config_a.peers.insert(
            "b".into(),
            peer_config(&key_b, vec![format!("quic://{addr_b}")]),
        );
        config_a.connect_to = vec!["b".into()];
        let runtime_a = Runtime::new(config_a.clone()).unwrap();
        let supervisor_a = DaemonSupervisor::default();
        start_links(&config_a, &runtime_a, supervisor_a.clone(), &key_a)
            .await
            .unwrap();

        wait_until(
            || async {
                registered_link(&runtime_a, "b").is_some()
                    && registered_link(&runtime_b, "a").is_some()
            },
            Duration::from_secs(10),
            "the outbound link to be registered on both nodes",
        )
        .await;
        assert!(link_is_healthy(&runtime_a, "b").await);
        assert!(link_is_healthy(&runtime_b, "a").await);

        // Closing the active link drives the outbound cleanup path, after
        // which the dialer re-establishes the link.
        let established = registered_link(&runtime_a, "b").unwrap();
        let first_instance = established.instance();
        established.close("test close");
        wait_until(
            || async { registered_link(&runtime_a, "b").is_none() },
            Duration::from_secs(10),
            "the closed link to be cleaned up",
        )
        .await;
        wait_until(
            || async {
                registered_link(&runtime_a, "b")
                    .is_some_and(|link| link.instance() != first_instance)
            },
            Duration::from_secs(10),
            "the link to reconnect",
        )
        .await;
        wait_until(
            || link_is_healthy(&runtime_a, "b"),
            Duration::from_secs(10),
            "the reconnected link to be marked healthy",
        )
        .await;
        wait_until(
            || async { registered_link(&runtime_b, "a").is_some() },
            Duration::from_secs(10),
            "the reconnected link to be accepted inbound",
        )
        .await;

        supervisor_a.shutdown(Duration::from_secs(2)).await.unwrap();
        supervisor_b.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn accept_loop_keeps_serving_after_a_rejected_handshake() {
        let key_b = Arc::new(identity::generate());
        let key_a = identity::generate();
        let mut config = loopback_config("b");
        config
            .peers
            .insert("a".into(), peer_config(&key_a, Vec::new()));
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        let (_router, addr) = start_links(&config, &runtime, supervisor.clone(), &key_b)
            .await
            .unwrap();

        // An unknown identity is rejected without killing the accept loop.
        let stranger = identity::generate();
        let (stranger_endpoint, rejected) = dial_peer(addr, &key_b, &stranger, "stranger").await;
        assert!(rejected.is_err(), "unknown peer must be rejected");
        stranger_endpoint.close(0u32.into(), b"done");

        // A configured peer is still accepted afterwards.
        let (client_endpoint, accepted) = dial_peer(addr, &key_b, &key_a, "a").await;
        let link = accepted.unwrap();
        wait_until(
            || async { registered_link(&runtime, "a").is_some() },
            Duration::from_secs(10),
            "the accepted link to be registered",
        )
        .await;
        assert!(link_is_healthy(&runtime, "a").await);
        link.close("test done");
        client_endpoint.close(0u32.into(), b"done");
        supervisor.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn dialer_bounds_an_attempt_that_never_completes() {
        // A bound but silent UDP socket absorbs QUIC Initial packets without
        // answering, so the attempt can only end through the attempt timeout.
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sink.local_addr().unwrap().port();
        let key = Arc::new(identity::generate());
        let peer_key = identity::generate();
        let mut config = loopback_config("a");
        config.peers.insert(
            "b".into(),
            peer_config(&peer_key, vec![format!("quic://127.0.0.1:{port}")]),
        );
        config.connect_to = vec!["b".into()];
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        start_links(&config, &runtime, supervisor.clone(), &key)
            .await
            .unwrap();
        wait_until(
            || async {
                link_last_error(&runtime, "b")
                    .await
                    .is_some_and(|error| error.contains("exceeded"))
            },
            Duration::from_secs(20),
            "the connection attempt to hit its timeout",
        )
        .await;
        drop(sink);
        supervisor.shutdown(Duration::from_secs(2)).await.unwrap();
    }
}
