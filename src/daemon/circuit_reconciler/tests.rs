use super::*;

fn identity(destination: &str, hop: u64) -> tinect::reconcile::CircuitIdentity {
    tinect::reconcile::CircuitIdentity {
        destination: destination.into(),
        ordered_path: vec!["source".into(), destination.into()],
        first_hop_link_instance: hop,
    }
}

#[test]
fn secure_dataplane_is_required_by_each_route_source() {
    let mut config = crate::daemon::test_support::minimal_config();
    assert!(!secure_dataplane_required(&config));

    config.direct = Some(tinect::config::DirectConfig {
        fallback: false,
        dscp: 0,
        fwmark: None,
        conntrack_zone: 1,
        routes: Vec::new(),
    });
    assert!(secure_dataplane_required(&config));

    config.direct = None;
    config
        .allowed_local_ports
        .push(tinect::config::AllowedLocalPort {
            allow: vec![tinect::config::PortSelector::All],
            deny: Vec::new(),
            r#for: tinect::config::RouteSourceSelector::Keyword("any_known".into()),
        });
    assert!(secure_dataplane_required(&config));

    config.allowed_local_ports.clear();
    config.allowed_routes.push(tinect::config::AllowedRoute {
        allow: vec!["192.0.2.0/24".parse().unwrap()],
        deny: Vec::new(),
        r#for: tinect::config::RouteSourceSelector::Keyword("any_known".into()),
    });
    config
        .path_policies
        .insert("exit".into(), tinect::topology::PathConstraint::default());
    config.peers.insert(
        "exit".into(),
        tinect::config::Peer {
            public_key: identity::encode_public(&identity::generate().verifying_key()),
            endpoints: Vec::new(),
            upstream_dns: None,
            accept_connections: None,
            allow_transit: None,
            allow_relay: None,
            bind_addresses: Vec::new(),
            routes: Vec::new(),
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    assert!(secure_dataplane_required(&config));
    assert!(configured_circuit_destinations(&config).contains("exit"));
}

#[test]
fn configured_destinations_include_paths_policies_and_imported_routes() {
    let mut config = crate::daemon::test_support::minimal_config();
    let peer_key = identity::generate();
    config.peers.insert(
        "path-exit".into(),
        tinect::config::Peer {
            public_key: identity::encode_public(&peer_key.verifying_key()),
            endpoints: Vec::new(),
            upstream_dns: None,
            accept_connections: None,
            allow_transit: None,
            allow_relay: None,
            bind_addresses: Vec::new(),
            routes: Vec::new(),
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "path-exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    config
        .path_policies
        .insert("policy-exit".into(), Default::default());

    let destinations = configured_circuit_destinations(&config);
    assert_eq!(destinations.len(), 2);
    assert!(destinations.contains("path-exit"));
    assert!(destinations.contains("policy-exit"));

    let route_key = identity::generate();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    std::fs::write(
            &path,
            format!(
                "id: a\nidentity_key_path: unused\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  route-exit:\n    public_key: {}\n    endpoints: []\n    routes:\n      - {{ip_cidr: 198.51.100.0/24, priority: 80}}\n",
                identity::encode_public(&route_key.verifying_key())
            ),
        )
        .unwrap();
    let loaded = tinect::config::Config::load(&path).unwrap();
    let destinations = configured_circuit_destinations(&loaded);
    assert_eq!(destinations, HashSet::from(["route-exit".into()]));
}

#[test]
fn retry_delays_are_bounded_deterministic_and_jittered() {
    let first = circuit_open_retry_delay("exit", 0);
    let capped = circuit_open_retry_delay("exit", 99);
    assert!(first >= std::time::Duration::from_millis(225));
    assert!(first <= std::time::Duration::from_millis(275));
    assert!(capped >= std::time::Duration::from_millis(4_500));
    assert!(capped <= std::time::Duration::from_millis(5_500));
    assert_eq!(first, circuit_open_retry_delay("exit", 0));
    assert_ne!(
        circuit_open_retry_delay("exit", 0),
        circuit_open_retry_delay("other", 0)
    );
    assert!(candidate_failure_delay("exit", 6) >= std::time::Duration::from_secs(60));
}

#[test]
fn renewal_failure_grace_uses_one_long_lease_and_then_expires() {
    let started = Instant::now();
    let deadline = renewal_failure_grace_deadline(started);
    assert_eq!(
        deadline.duration_since(started),
        tinect::circuit::circuit_lease()
    );
    assert!(!renewal_failure_grace_expired(
        deadline,
        deadline
            .checked_sub(std::time::Duration::from_millis(1))
            .unwrap()
    ));
    assert!(renewal_failure_grace_expired(deadline, deadline));
}

#[tokio::test]
async fn renewal_failure_grace_does_not_follow_a_replacement_lease() {
    let opens = dataplane::CircuitOpenManager::default();
    opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([21; 16]),
            chacha20poly1305::Key::from([21; 32]),
            7,
            (vec!["source".into(), "exit".into()], 1200),
        )
        .await;
    let first = opens
        .active_for_destination("exit")
        .await
        .expect("first lease");
    let grace = RenewalFailureGrace::for_active(&first, Instant::now());

    opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([22; 16]),
            chacha20poly1305::Key::from([22; 32]),
            7,
            (vec!["source".into(), "exit".into()], 1200),
        )
        .await;
    let replacement = opens
        .active_for_destination("exit")
        .await
        .expect("replacement lease");
    assert_ne!(first.lease_epoch, replacement.lease_epoch);
    assert!(!grace.belongs_to(&replacement));
}

#[tokio::test]
async fn renewal_failure_grace_is_cleared_when_the_active_lease_is_gone() {
    let runtime = Runtime::new(crate::daemon::test_support::minimal_config()).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let mut grace = Some(RenewalFailureGrace {
        circuit_id: tinect::circuit::CircuitId([24; 16]),
        lease_epoch: 24,
        deadline: Instant::now(),
    });

    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::Inactive
    );
    assert!(grace.is_none());
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn renewal_failure_grace_starts_for_an_unconfirmed_active_lease() {
    let runtime = Runtime::new(crate::daemon::test_support::minimal_config()).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let circuit_id = tinect::circuit::CircuitId([25; 16]);
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            circuit_id,
            chacha20poly1305::Key::from([25; 32]),
            25,
            (vec!["source".into(), "exit".into()], 1200),
        )
        .await;
    let active = runtime
        .circuits
        .opens
        .active_for_destination("exit")
        .await
        .expect("active circuit");
    let mut grace = Some(RenewalFailureGrace {
        circuit_id: tinect::circuit::CircuitId([26; 16]),
        lease_epoch: active.lease_epoch,
        deadline: Instant::now() + std::time::Duration::from_secs(60),
    });

    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::FailedWithinGrace
    );
    assert!(grace.is_some_and(|grace| grace.belongs_to(&active)));
    grace.as_mut().unwrap().deadline = Instant::now();
    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::Revoked
    );
    assert!(grace.is_none());
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn renewal_without_the_registered_first_hop_deactivates_the_lease() {
    let mut config = crate::daemon::test_support::minimal_config();
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
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config.clone()).unwrap();
    let circuit_id = tinect::circuit::CircuitId([27; 16]);
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            circuit_id,
            chacha20poly1305::Key::from([27; 32]),
            999,
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;
    assert!(
        !renew_active_circuit_once(
            &config,
            "exit",
            &runtime.links,
            &runtime.circuits.opens,
            &identity::generate(),
        )
        .await
    );
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn unconfigured_circuit_worker_exits_before_resolving_topology() {
    let config = crate::daemon::test_support::minimal_config();
    let runtime = Runtime::new(config).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    open_configured_circuit(&context, "removed").await.unwrap();
    assert_eq!(supervisor.task_count(), 0);
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn expired_renewal_grace_performs_complete_local_revoke() {
    let config = crate::daemon::test_support::minimal_config();
    let runtime = Runtime::new(config).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let circuit_id = tinect::circuit::CircuitId([23; 16]);
    let circuit_key = chacha20poly1305::Key::from([23; 32]);
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            circuit_id,
            circuit_key,
            23,
            (vec!["source".into(), "exit".into()], 1200),
        )
        .await;
    runtime
        .circuits
        .return_flows
        .install_circuit(23, circuit_id, circuit_key);
    let source = identity::generate();
    runtime
        .circuits
        .sessions
        .install_open(23, circuit_id, source.verifying_key(), circuit_key)
        .await;
    let mut sender = tinect::crypto::SenderSession::from_key(circuit_id, circuit_key);
    let frame = sender.encrypt(b"payload").expect("session frame").to_vec();
    let active = runtime
        .circuits
        .opens
        .active_for_destination("exit")
        .await
        .expect("active circuit");
    let mut grace = Some(RenewalFailureGrace {
        circuit_id: active.circuit_id,
        lease_epoch: active.lease_epoch,
        deadline: Instant::now() - std::time::Duration::from_secs(1),
    });

    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::Revoked
    );
    assert!(grace.is_none());
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
    assert_eq!(
        runtime.circuits.sessions.open_data(23, &frame).await,
        Err(tinect::crypto::CryptoError::UnknownSession)
    );
    assert!(
        runtime
            .circuits
            .return_flows
            .encrypt_dns_return(23, circuit_id, b"dns")
            .is_none()
    );
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[test]
fn candidate_failures_increment_attempts_and_keep_a_future_deadline() {
    let mut failures = HashMap::new();
    let path = identity("exit", 7);
    record_candidate_failure(&mut failures, "exit", path.clone());
    assert_eq!(failures[&path].attempts, 1);
    assert!(failures[&path].retry_at > Instant::now());
    record_candidate_failure(&mut failures, "exit", path.clone());
    assert_eq!(failures[&path].attempts, 2);
}

#[test]
fn nonretryable_rejection_wait_clears_on_path_change_or_expiry() {
    let path = identity("exit", 1);
    let now = Instant::now();
    let mut rejection = Some((path.clone(), now + std::time::Duration::from_secs(5)));
    assert!(nonretryable_rejection_wait(&mut rejection, Some(&path), now).is_some());
    let other = identity("exit", 2);
    assert!(nonretryable_rejection_wait(&mut rejection, Some(&other), now).is_none());
    assert!(rejection.is_none());

    rejection = Some((path.clone(), now - std::time::Duration::from_secs(1)));
    assert!(nonretryable_rejection_wait(&mut rejection, Some(&path), now).is_none());
    assert!(rejection.is_none());
}

#[test]
fn desired_resolution_reports_ready_or_cooling_down_candidates() {
    let path = tinect::reconcile::ResolvedPath {
        destination: "exit".into(),
        ordered_path: vec!["source".into(), "exit".into()],
        first_hop_link_instance: 4,
        candidate_rank: 0,
        verified_inner_mtu: 1200,
        capacity_vector: Default::default(),
        proof_valid_until: 99,
    };
    let resolution = DestinationResolution {
        candidates: Vec::new(),
        preferred: None,
        desired: tinect::reconcile::DesiredResolution {
            generation: 1,
            config_generation: 2,
            path: Some(path.clone()),
            availability: tinect::reconcile::Availability::Ready,
            resolved_at: std::time::SystemTime::now(),
        },
    };
    let ready = desired_resolution_for_candidate(&resolution, None);
    assert!(ready.is_ready());
    assert_eq!(ready.path.unwrap().ordered_path, path.ordered_path);

    let unavailable = DestinationResolution {
        desired: tinect::reconcile::DesiredResolution {
            generation: 1,
            config_generation: 2,
            path: None,
            availability: tinect::reconcile::Availability::TemporarilyUnavailable {
                reason: "unavailable".into(),
                retry_at: 100,
            },
            resolved_at: std::time::SystemTime::now(),
        },
        ..resolution
    };
    assert!(matches!(
        desired_resolution_for_candidate(&unavailable, None).availability,
        tinect::reconcile::Availability::TemporarilyUnavailable { .. }
    ));
}

#[tokio::test]
async fn configured_destination_without_a_ready_path_starts_one_worker() {
    let mut config = crate::daemon::test_support::minimal_config();
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
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    open_configured_circuits(&context).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(supervisor.task_count() >= 1);
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn removed_destination_worker_exits_before_path_resolution() {
    let runtime = Runtime::new(crate::daemon::test_support::minimal_config()).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    open_configured_circuit(&context, "removed").await.unwrap();
    assert!(runtime.circuits.opens.active_circuits().await.is_empty());
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn renewal_rejects_missing_active_state_peer_and_link() {
    let mut config = crate::daemon::test_support::minimal_config();
    let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let opens = dataplane::CircuitOpenManager::default();
    let key = identity::generate();
    assert!(!renew_active_circuit_once(&config, "exit", &links, &opens, &key).await);

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
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([9; 16]),
            chacha20poly1305::Key::from([9; 32]),
            99,
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;
    assert!(!renew_active_circuit_once(&config, "exit", &links, &opens, &key).await);
    assert!(opens.active_for_destination("exit").await.is_none());
}

#[tokio::test]
async fn renewal_round_trip_accepts_the_matching_signed_acknowledgement() {
    let source_key = identity::generate();
    let destination_key = identity::generate();
    let destination_public = identity::encode_public(&destination_key.verifying_key());
    let (server_endpoint, _) = tinect::carrier::endpoint_with_options_and_bare(
        tinect::config::CarrierProtocol::QuicFull,
        "127.0.0.1:0".parse().unwrap(),
        &tinect::config::LinkHealthConfig::default(),
        None,
        None,
        Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let client_public = identity::encode_public(&source_key.verifying_key());
    let accept_peers = std::collections::BTreeMap::from([(
        "source".to_owned(),
        tinect::config::Peer {
            public_key: client_public,
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
    let accept_key = destination_key.clone();
    let server_task = tokio::spawn(async move {
        tinect::carrier::accept_with_bare(
            &server_endpoint,
            None,
            tinect::config::CarrierProtocol::QuicFull,
            &accept_peers,
            false,
            "destination",
            &accept_key,
        )
        .await
        .unwrap()
    });
    let (client_endpoint, _) = tinect::carrier::endpoint_with_options_and_bare(
        tinect::config::CarrierProtocol::QuicFull,
        "127.0.0.1:0".parse().unwrap(),
        &tinect::config::LinkHealthConfig::default(),
        None,
        None,
        Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let source_link = Arc::new(
        tinect::carrier::connect_with_link_health_and_bare(
            &client_endpoint,
            None,
            server_address,
            tinect::config::CarrierProtocol::QuicFull,
            "destination",
            &destination_public,
            "source",
            &source_key,
            &tinect::config::LinkHealthConfig::default(),
        )
        .await
        .unwrap(),
    );
    let destination_link = Arc::new(server_task.await.unwrap());
    source_link.mark_topology_snapshot_received();
    source_link.mark_topology_snapshot_acknowledged();

    let mut config = crate::daemon::test_support::minimal_config();
    config.id = "source".into();
    config.identity_key = Some(identity::encode_secret(&source_key));
    config.identity_key_path = None;
    config.peers.insert(
        "destination".into(),
        tinect::config::Peer {
            public_key: destination_public.clone(),
            endpoints: Vec::new(),
            upstream_dns: None,
            accept_connections: None,
            allow_transit: None,
            allow_relay: None,
            bind_addresses: Vec::new(),
            routes: Vec::new(),
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["source".into(), "destination".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("destination".into(), source_link.clone());
    let circuit_id = tinect::circuit::CircuitId([31; 16]);
    runtime
        .circuits
        .opens
        .activate(
            "destination".into(),
            circuit_id,
            chacha20poly1305::Key::from([32; 32]),
            source_link.instance(),
            (vec!["source".into(), "destination".into()], 1200),
        )
        .await;

    let renew_link = destination_link.clone();
    let renew_server_key = destination_key.clone();
    let server_responder = tokio::spawn(async move {
        let message = renew_link.recv_control().await.unwrap();
        let ControlMessage::CircuitRenew {
            circuit_id,
            counter,
            ..
        } = message
        else {
            panic!("expected CircuitRenew");
        };
        renew_link
            .send_control(&ControlMessage::circuit_renew_ack(
                &renew_server_key,
                circuit_id,
                counter,
            ))
            .await
            .unwrap();
    });
    let resolve_link = source_link.clone();
    let resolve_opens = runtime.circuits.opens.clone();
    let resolve_public = destination_public.clone();
    let source_responder = tokio::spawn(async move {
        let message = resolve_link.recv_control().await.unwrap();
        let ControlMessage::CircuitRenewAck {
            circuit_id,
            counter,
            ..
        } = message
        else {
            panic!("expected CircuitRenewAck");
        };
        assert!(
            resolve_opens
                .resolve(
                    resolve_link.instance(),
                    circuit_id,
                    &resolve_public,
                    dataplane::OpenResult::RenewAcknowledged { counter },
                )
                .await
        );
    });

    assert!(
        renew_active_circuit_once(
            runtime.config.as_ref(),
            "destination",
            &runtime.links,
            &runtime.circuits.opens,
            &source_key,
        )
        .await
    );
    server_responder.await.unwrap();
    source_responder.await.unwrap();
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("destination")
            .await
            .is_some()
    );
    source_link.close("renewal test complete");
    destination_link.close("renewal test complete");
    client_endpoint.close(0u32.into(), b"renewal test complete");
}

#[tokio::test]
async fn configured_circuit_commits_a_signed_open_and_installs_fake_ip_return_state() {
    let source_key = identity::generate();
    let destination_key = identity::generate();
    let destination_public = identity::encode_public(&destination_key.verifying_key());
    let (server_endpoint, _) = tinect::carrier::endpoint_with_options_and_bare(
        tinect::config::CarrierProtocol::QuicFull,
        "127.0.0.1:0".parse().unwrap(),
        &tinect::config::LinkHealthConfig::default(),
        None,
        None,
        Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let accept_peers = std::collections::BTreeMap::from([(
        "source".to_owned(),
        tinect::config::Peer {
            public_key: identity::encode_public(&source_key.verifying_key()),
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
    let accept_key = destination_key.clone();
    let server_task = tokio::spawn(async move {
        tinect::carrier::accept_with_bare(
            &server_endpoint,
            None,
            tinect::config::CarrierProtocol::QuicFull,
            &accept_peers,
            false,
            "destination",
            &accept_key,
        )
        .await
        .unwrap()
    });
    let (client_endpoint, _) = tinect::carrier::endpoint_with_options_and_bare(
        tinect::config::CarrierProtocol::QuicFull,
        "127.0.0.1:0".parse().unwrap(),
        &tinect::config::LinkHealthConfig::default(),
        None,
        None,
        Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let source_link = Arc::new(
        tinect::carrier::connect_with_link_health_and_bare(
            &client_endpoint,
            None,
            server_address,
            tinect::config::CarrierProtocol::QuicFull,
            "destination",
            &destination_public,
            "source",
            &source_key,
            &tinect::config::LinkHealthConfig::default(),
        )
        .await
        .unwrap(),
    );
    let destination_link = Arc::new(server_task.await.unwrap());
    source_link.mark_topology_snapshot_received();
    source_link.mark_topology_snapshot_acknowledged();

    let mut config = crate::daemon::test_support::minimal_config();
    config.id = "source".into();
    config.identity_key = Some(identity::encode_secret(&source_key));
    config.identity_key_path = None;
    config.fake_ip = Some(
        serde_yaml::from_str("listen: 127.0.0.1:0\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true")
            .unwrap(),
    );
    config.peers.insert(
        "destination".into(),
        tinect::config::Peer {
            public_key: destination_public.clone(),
            endpoints: Vec::new(),
            upstream_dns: None,
            accept_connections: None,
            allow_transit: None,
            allow_relay: None,
            bind_addresses: Vec::new(),
            routes: Vec::new(),
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["source".into(), "destination".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("destination".into(), source_link.clone());
    let resolve_link = source_link.clone();
    let resolve_opens = runtime.circuits.opens.clone();
    let resolve_public = destination_public.clone();
    let source_responder = tokio::spawn(async move {
        let message = resolve_link.recv_control().await.unwrap();
        let ControlMessage::OpenAck { circuit_id, .. } = message else {
            panic!("expected OpenAck");
        };
        assert!(
            resolve_opens
                .resolve(
                    resolve_link.instance(),
                    circuit_id,
                    &resolve_public,
                    dataplane::OpenResult::Acknowledged,
                )
                .await
        );
    });
    let acknowledge_link = destination_link.clone();
    let acknowledge_key = destination_key.clone();
    let server_responder = tokio::spawn(async move {
        let message = acknowledge_link.recv_control().await.unwrap();
        let ControlMessage::Open(request) = message else {
            panic!("expected Open");
        };
        acknowledge_link
            .send_control(&ControlMessage::open_ack(
                &acknowledge_key,
                request.circuit_id,
            ))
            .await
            .unwrap();
    });

    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(source_key.clone()), supervisor.clone());
    let worker =
        tokio::spawn(async move { open_configured_circuit(&context, "destination").await });
    let active = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(active) = runtime
                .circuits
                .opens
                .active_for_destination("destination")
                .await
            {
                break active;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(active.path.len(), 2);
    assert_eq!(active.path[0], runtime.config.local_identity().unwrap());
    assert_eq!(
        active.path[1],
        runtime.config.peer_identity("destination").unwrap()
    );

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    runtime
        .circuits
        .opens
        .deactivate("destination", active.circuit_id)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    worker.abort();
    let _ = worker.await;
    source_responder.abort();
    let _ = source_responder.await;
    server_responder.await.unwrap();

    runtime
        .circuits
        .opens
        .deactivate("destination", active.circuit_id)
        .await;
    let reject_source_link = source_link.clone();
    let reject_opens = runtime.circuits.opens.clone();
    let reject_public = destination_public.clone();
    let reject_source_responder = tokio::spawn(async move {
        let message = reject_source_link.recv_control().await.unwrap();
        assert!(message.verify_result());
        let ControlMessage::OpenReject {
            circuit_id,
            retryable,
            reason_code,
            public_key,
            ..
        } = &message
        else {
            panic!("expected OpenReject");
        };
        assert!(
            reject_opens
                .resolve(
                    reject_source_link.instance(),
                    *circuit_id,
                    &reject_public,
                    dataplane::OpenResult::Rejected {
                        retryable: *retryable,
                        reason: format!("code:{reason_code}"),
                    },
                )
                .await
        );
        assert_eq!(public_key, &reject_public);
    });
    let reject_destination_link = destination_link.clone();
    let reject_key = destination_key.clone();
    let reject_server_responder = tokio::spawn(async move {
        let message = reject_destination_link.recv_control().await.unwrap();
        let ControlMessage::Open(request) = message else {
            panic!("expected Open for rejection");
        };
        reject_destination_link
            .send_control(&ControlMessage::open_reject(
                &reject_key,
                request.circuit_id,
                false,
                crate::daemon::control_handler::OPEN_REJECT_REASON_GENERIC,
            ))
            .await
            .unwrap();
    });
    let rejection_context =
        CircuitReconcileContext::new(&runtime, Arc::new(source_key.clone()), supervisor.clone());
    let rejection_worker =
        tokio::spawn(
            async move { open_configured_circuit(&rejection_context, "destination").await },
        );
    reject_server_responder.await.unwrap();
    reject_source_responder.await.unwrap();
    rejection_worker.abort();
    let _ = rejection_worker.await;
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("destination")
            .await
            .is_none()
    );

    source_link.close("open test complete");
    destination_link.close("open test complete");
    client_endpoint.close(0u32.into(), b"open test complete");
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn reconciliation_revokes_stale_generation_and_removed_destinations() {
    let mut config = crate::daemon::test_support::minimal_config();
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
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([10; 16]),
            chacha20poly1305::Key::from([10; 32]),
            10,
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;
    runtime.circuits.opens.bump_config_generation();
    open_configured_circuits(&context).await.unwrap();
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();

    let removed_runtime = Runtime::new(crate::daemon::test_support::minimal_config()).unwrap();
    let removed_supervisor = DaemonSupervisor::default();
    let removed_context = CircuitReconcileContext::new(
        &removed_runtime,
        Arc::new(identity::generate()),
        removed_supervisor.clone(),
    );
    removed_runtime
        .circuits
        .opens
        .activate(
            "removed".into(),
            tinect::circuit::CircuitId([11; 16]),
            chacha20poly1305::Key::from([11; 32]),
            11,
            (vec!["a".into(), "removed".into()], 1200),
        )
        .await;
    open_configured_circuits(&removed_context).await.unwrap();
    assert!(
        removed_runtime
            .circuits
            .opens
            .active_for_destination("removed")
            .await
            .is_none()
    );
    removed_supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[test]
fn unix_timestamp_secs_returns_a_real_timestamp() {
    assert!(unix_timestamp_secs() > 1_000_000_000);
}

#[test]
fn secure_dataplane_is_required_by_route_imports_overrides_and_domains() {
    let route_key = identity::generate();
    let domain_key = identity::generate();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    std::fs::write(
            &path,
            format!(
                "id: a\nidentity_key_path: unused\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\nfake_ip:\n  listen: 127.0.0.1:5354\n  upstream_dns: [1.1.1.1]\n  disable_ipv6: true\npeers:\n  route-exit:\n    public_key: {}\n    endpoints: []\n    routes:\n      - {{ip_cidr: 198.51.100.0/24, priority: 80}}\n  domain-exit:\n    public_key: {}\n    endpoints: []\n    routes:\n      - {{domain: example.test, priority: 100}}\n",
                identity::encode_public(&route_key.verifying_key()),
                identity::encode_public(&domain_key.verifying_key())
            ),
        )
        .unwrap();
    let loaded = tinect::config::Config::load(&path).unwrap();
    assert!(!loaded.route_imports().is_empty());
    assert!(!loaded.domain_site_ids().is_empty());
    assert!(secure_dataplane_required(&loaded));
    let destinations = configured_circuit_destinations(&loaded);
    assert!(destinations.contains("route-exit"));
    assert!(destinations.contains("domain-exit"));

    // Path override routes alone also require the secure dataplane.
    let mut config = crate::daemon::test_support::minimal_config();
    config.peers.insert(
        "exit".into(),
        tinect::config::Peer {
            public_key: identity::encode_public(&route_key.verifying_key()),
            endpoints: Vec::new(),
            upstream_dns: None,
            accept_connections: None,
            allow_transit: None,
            allow_relay: None,
            bind_addresses: Vec::new(),
            routes: Vec::new(),
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: vec![{
                    let mut override_route = tinect::config::RouteOverride::default();
                    override_route.ip_cidr = Some("203.0.113.0/24".parse().unwrap());
                    override_route.priority = Some(40);
                    override_route
                }],
                override_upstream_dns: None,
            }],
        },
    );
    assert!(!config.override_route_prefixes().is_empty());
    assert!(secure_dataplane_required(&config));
}

#[test]
fn nonretryable_rejection_wait_without_a_rejection_never_waits() {
    let path = identity("exit", 1);
    let now = Instant::now();
    assert!(nonretryable_rejection_wait(&mut None, Some(&path), now).is_none());
    assert!(nonretryable_rejection_wait(&mut None, None, now).is_none());
}

#[tokio::test]
async fn desired_resolution_marks_a_candidate_ready_or_reports_cooldown() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let path = tinect::reconcile::ResolvedPath {
        destination: "exit".into(),
        ordered_path: vec!["source".into(), "exit".into()],
        first_hop_link_instance: pair.server_link.instance(),
        candidate_rank: 0,
        verified_inner_mtu: 1200,
        capacity_vector: Default::default(),
        proof_valid_until: 99,
    };
    let candidate = ResolvedCandidate {
        path: path.clone(),
        link: pair.server_link.clone(),
    };
    let resolution = DestinationResolution {
        candidates: vec![candidate.clone()],
        preferred: Some(candidate.clone()),
        desired: tinect::reconcile::DesiredResolution {
            generation: 1,
            config_generation: 1,
            path: None,
            availability: tinect::reconcile::Availability::TemporarilyUnavailable {
                reason: "no ready candidate".into(),
                retry_at: 1,
            },
            resolved_at: std::time::SystemTime::now(),
        },
    };

    let ready = desired_resolution_for_candidate(&resolution, Some(&candidate));
    assert!(ready.is_ready());
    assert_eq!(
        ready.path.expect("candidate path").identity(),
        path.identity()
    );

    // A preferred path whose candidates all cool down reports a bounded
    // retry instead of publishing a path.
    let cooling = desired_resolution_for_candidate(&resolution, None);
    assert!(cooling.path.is_none());
    assert!(matches!(
        cooling.availability,
        tinect::reconcile::Availability::TemporarilyUnavailable { .. }
    ));
    pair.client_link.close("test complete");
    pair.server_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn migration_status_updates_only_the_matching_circuit() {
    let mut config = crate::daemon::test_support::minimal_config();
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
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config).unwrap();
    let config = runtime.config.clone();

    // Unknown destinations are ignored entirely.
    update_migration_status(
        &runtime.state,
        &config,
        "missing",
        &["a".into(), "missing".into()],
        MigrationState::MigrationOverdue,
        Some(9),
        Some("ignored".into()),
    )
    .await;
    assert!(
        runtime
            .state
            .read()
            .await
            .status
            .circuits
            .iter()
            .all(|circuit| circuit.migration_state == MigrationState::Stable
                && circuit.migration_last_error.is_none())
    );

    update_migration_status(
        &runtime.state,
        &config,
        "exit",
        &["a".into(), "exit".into()],
        MigrationState::MigrationPending,
        Some(7),
        Some("boom".into()),
    )
    .await;
    let state = runtime.state.read().await;
    let circuit = state
        .status
        .circuits
        .iter()
        .find(|circuit| circuit.destination == "exit")
        .expect("circuit status");
    assert_eq!(circuit.migration_state, MigrationState::MigrationPending);
    assert_eq!(
        circuit.preferred_path,
        vec!["a".to_string(), "exit".to_string()]
    );
    assert_eq!(circuit.migration_started_at, Some(7));
    assert_eq!(circuit.migration_last_error.as_deref(), Some("boom"));
}

#[tokio::test]
async fn migration_failure_logging_requires_a_started_migration() {
    let config = crate::daemon::test_support::minimal_config();
    let opens = dataplane::CircuitOpenManager::default();
    // No migration record at all: nothing to log.
    log_migration_failure(&config, "exit", &opens, "no migration").await;

    let target = identity("exit", 3);
    assert!(
        opens
            .migration_readiness("exit", &target, true, std::time::Duration::from_secs(60),)
            .await
            .is_some()
    );
    // A readiness record without a start timestamp is not a failed
    // migration attempt yet.
    log_migration_failure(&config, "exit", &opens, "not started").await;

    assert!(opens.begin_migration("exit").await.is_some());
    log_migration_failure(&config, "exit", &opens, "open failed").await;
    let (_, started, _) = opens.migration_snapshot("exit").await.expect("migration");
    assert!(started.is_some());
}

#[tokio::test]
async fn hard_revoke_with_a_registered_link_sends_a_best_effort_close() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let runtime = Runtime::new(crate::daemon::test_support::minimal_config()).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let circuit_id = tinect::circuit::CircuitId([41; 16]);
    let circuit_key = chacha20poly1305::Key::from([41; 32]);
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            circuit_id,
            circuit_key,
            pair.server_link.instance(),
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;
    runtime
        .circuits
        .sessions
        .install_open(
            pair.server_link.instance(),
            circuit_id,
            pair.client_key.verifying_key(),
            circuit_key,
        )
        .await;
    runtime.circuits.return_flows.install_circuit(
        pair.server_link.instance(),
        circuit_id,
        circuit_key,
    );
    let active = runtime
        .circuits
        .opens
        .active_for_destination("exit")
        .await
        .expect("active circuit");
    let close_link = pair.client_link.clone();
    let close_receiver = tokio::spawn(async move { close_link.recv_control().await.unwrap() });

    let supervisor = DaemonSupervisor::default();
    hard_revoke_active_circuit(
        &runtime.circuits.opens,
        &runtime.circuits.sessions,
        &runtime.circuits.return_flows,
        &runtime.circuits.circuit_dns,
        "exit",
        &active,
        &runtime.links,
        &identity::generate(),
        &supervisor,
        "test revoke",
    )
    .await;

    // Local state is removed synchronously before the CLOSE attempt.
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
    let mut sender = tinect::crypto::SenderSession::from_key(circuit_id, circuit_key);
    let frame = sender.encrypt(b"payload").expect("session frame").to_vec();
    assert_eq!(
        runtime
            .circuits
            .sessions
            .open_data(pair.server_link.instance(), &frame)
            .await,
        Err(tinect::crypto::CryptoError::UnknownSession)
    );
    assert!(
        runtime
            .circuits
            .return_flows
            .encrypt_dns_return(pair.server_link.instance(), circuit_id, b"dns")
            .is_none()
    );
    let message = tokio::time::timeout(std::time::Duration::from_secs(2), close_receiver)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(message, ControlMessage::CircuitClose { .. }));

    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    pair.client_link.close("test complete");
    pair.server_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn renewal_without_a_configured_peer_keeps_the_lease() {
    let config = crate::daemon::test_support::minimal_config();
    let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let opens = dataplane::CircuitOpenManager::default();
    opens
        .activate(
            "ghost".into(),
            tinect::circuit::CircuitId([8; 16]),
            chacha20poly1305::Key::from([8; 32]),
            8,
            (vec!["a".into(), "ghost".into()], 1200),
        )
        .await;
    // A vanished peer entry fails the renewal but must not withdraw the
    // lease: only a missing first-hop Link authorizes deactivation.
    assert!(
        !renew_active_circuit_once(&config, "ghost", &links, &opens, &identity::generate()).await
    );
    assert!(opens.active_for_destination("ghost").await.is_some());
}

#[tokio::test]
async fn renewal_send_failure_on_a_closed_link_keeps_the_lease() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        Vec::new(),
    );
    let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
        "client".to_owned(),
        pair.server_link.clone(),
    )])));
    let opens = dataplane::CircuitOpenManager::default();
    let circuit_id = tinect::circuit::CircuitId([42; 16]);
    opens
        .activate(
            "exit".into(),
            circuit_id,
            chacha20poly1305::Key::from([42; 32]),
            pair.server_link.instance(),
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;
    pair.server_link.close("renewal send failure test");
    assert!(
        !renew_active_circuit_once(&config, "exit", &links, &opens, &identity::generate()).await
    );
    // A transient control-stream failure retracts the waiter but retains
    // the active lease.
    assert!(opens.active_for_destination("exit").await.is_some());
    pair.client_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn renewal_rejection_clears_the_waiter_but_keeps_the_active_lease() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        Vec::new(),
    );
    let active_path = vec![
        config.local_identity().unwrap(),
        config.peer_identity("exit").unwrap(),
    ];
    let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
        "client".to_owned(),
        pair.server_link.clone(),
    )])));
    let opens = dataplane::CircuitOpenManager::default();
    let base_runtime = Runtime::new(config.clone()).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context = CircuitReconcileContext {
        config: Arc::new(config.clone()),
        links: links.clone(),
        topology: base_runtime.topology.clone(),
        state: base_runtime.state.clone(),
        circuit_opens: opens.clone(),
        sessions: base_runtime.circuits.sessions.clone(),
        return_flows: base_runtime.circuits.return_flows.clone(),
        circuit_dns: base_runtime.circuits.circuit_dns.clone(),
        supervisor: supervisor.clone(),
        source_key: Arc::new(identity::generate()),
    };
    let circuit_id = tinect::circuit::CircuitId([47; 16]);
    opens
        .activate(
            "exit".into(),
            circuit_id,
            chacha20poly1305::Key::from([47; 32]),
            pair.server_link.instance(),
            (active_path, 1200),
        )
        .await;
    let resolver_link = pair.client_link.clone();
    let resolver_opens = opens.clone();
    let resolver_instance = pair.server_link.instance();
    let resolver_public = config.peers["exit"].public_key.clone();
    let responder = tokio::spawn(async move {
        let ControlMessage::CircuitRenew {
            circuit_id,
            counter,
            ..
        } = resolver_link.recv_control().await.unwrap()
        else {
            panic!("expected CircuitRenew");
        };
        assert!(
            resolver_opens
                .resolve(
                    resolver_instance,
                    circuit_id,
                    &resolver_public,
                    dataplane::OpenResult::Rejected {
                        retryable: false,
                        reason: format!("rejected counter {counter}"),
                    },
                )
                .await
        );
    });
    assert!(
        !renew_active_circuit_once(&config, "exit", &links, &opens, &identity::generate(),).await
    );
    responder.await.unwrap();
    assert!(opens.active_for_destination("exit").await.is_some());

    // Let the failure grace expire while the control response is in
    // flight. This covers the post-renewal expiry check, which is
    // distinct from the fast-path check made before sending Renew.
    let active = opens
        .active_for_destination("exit")
        .await
        .expect("active lease remains within grace");
    let mut grace = Some(RenewalFailureGrace {
        circuit_id: active.circuit_id,
        lease_epoch: active.lease_epoch,
        deadline: Instant::now() + std::time::Duration::from_millis(1),
    });
    let resolver_link = pair.client_link.clone();
    let resolver_opens = opens.clone();
    let resolver_public = config.peers["exit"].public_key.clone();
    let responder = tokio::spawn(async move {
        let ControlMessage::CircuitRenew {
            circuit_id,
            counter,
            ..
        } = resolver_link.recv_control().await.unwrap()
        else {
            panic!("expected delayed CircuitRenew");
        };
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(
            resolver_opens
                .resolve(
                    resolver_instance,
                    circuit_id,
                    &resolver_public,
                    dataplane::OpenResult::Rejected {
                        retryable: false,
                        reason: format!("delayed rejection {counter}"),
                    },
                )
                .await
        );
    });
    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::Revoked
    );
    assert!(grace.is_none());
    responder.await.unwrap();
    assert!(opens.active_for_destination("exit").await.is_none());
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    pair.client_link.close("test complete");
    pair.server_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn failed_renewal_without_a_link_clears_the_grace_and_reports_inactive() {
    let mut config = crate::daemon::test_support::minimal_config();
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
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([43; 16]),
            chacha20poly1305::Key::from([43; 32]),
            999,
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;
    let active = runtime
        .circuits
        .opens
        .active_for_destination("exit")
        .await
        .expect("active circuit");
    // A grace record belonging to a retired circuit must be dropped, not
    // charged against the current lease.
    let mut grace = Some(RenewalFailureGrace {
        circuit_id: tinect::circuit::CircuitId([44; 16]),
        lease_epoch: active.lease_epoch,
        deadline: Instant::now() + std::time::Duration::from_secs(60),
    });
    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::Inactive
    );
    assert!(grace.is_none());
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn renewal_with_grace_acknowledges_a_matching_signed_renewal() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        Vec::new(),
    );
    let client_public = identity::encode_public(&pair.client_key.verifying_key());
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([45; 16]),
            chacha20poly1305::Key::from([45; 32]),
            pair.server_link.instance(),
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;

    let renew_link = pair.client_link.clone();
    let renew_key = pair.client_key.clone();
    let renew_responder = tokio::spawn(async move {
        let message = renew_link.recv_control().await.unwrap();
        let ControlMessage::CircuitRenew {
            circuit_id,
            counter,
            ..
        } = message
        else {
            panic!("expected CircuitRenew");
        };
        renew_link
            .send_control(&ControlMessage::circuit_renew_ack(
                &renew_key, circuit_id, counter,
            ))
            .await
            .unwrap();
    });
    let resolve_link = pair.server_link.clone();
    let resolve_opens = runtime.circuits.opens.clone();
    let ack_resolver = tokio::spawn(async move {
        let message = resolve_link.recv_control().await.unwrap();
        let ControlMessage::CircuitRenewAck {
            circuit_id,
            counter,
            ..
        } = message
        else {
            panic!("expected CircuitRenewAck");
        };
        assert!(
            resolve_opens
                .resolve(
                    resolve_link.instance(),
                    circuit_id,
                    &client_public,
                    dataplane::OpenResult::RenewAcknowledged { counter },
                )
                .await
        );
    });

    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    // A grace record for a different circuit is cleared, then the
    // successful renewal is acknowledged.
    let mut grace = Some(RenewalFailureGrace {
        circuit_id: tinect::circuit::CircuitId([46; 16]),
        lease_epoch: 0,
        deadline: Instant::now(),
    });
    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::Acknowledged
    );
    assert!(grace.is_none());
    renew_responder.await.unwrap();
    ack_resolver.await.unwrap();
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    pair.client_link.close("test complete");
    pair.server_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn reconciliation_revokes_a_configured_destination_whose_proof_is_gone() {
    let mut config = crate::daemon::test_support::minimal_config();
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
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config).unwrap();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([12; 16]),
            chacha20poly1305::Key::from([12; 32]),
            999,
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;
    open_configured_circuits(&context).await.unwrap();
    // The unprovable active path is hard-revoked, and the resulting
    // hard-revoked desired resolution blocks any new OPEN worker.
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
    assert!(
        runtime.circuits.opens.desired_is_hard_revoked("exit").await,
        "revoked destination must publish a hard-revoked desired state"
    );
    assert_eq!(supervisor.task_count(), 0);
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn reconciliation_keeps_a_matching_active_circuit_and_clears_its_migration() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    let local = config.local_identity().unwrap();
    let exit = config.peer_identity("exit").unwrap();
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([13; 16]),
            chacha20poly1305::Key::from([13; 32]),
            pair.server_link.instance(),
            (vec![local, exit], 1200),
        )
        .await;
    let stale_target = identity("exit", 77);
    assert!(
        runtime
            .circuits
            .opens
            .migration_readiness(
                "exit",
                &stale_target,
                true,
                std::time::Duration::from_secs(60)
            )
            .await
            .is_some()
    );
    // Hold the worker claim so the reconciler cannot spawn a competing
    // OPEN worker for this destination.
    let _claim = runtime
        .circuits
        .opens
        .claim_worker("exit")
        .expect("worker claim");
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    open_configured_circuits(&context).await.unwrap();
    // The active circuit already matches the resolved desired identity:
    // it stays, its stale migration marker is cleared, and no new worker
    // could be spawned while the claim was held.
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_some()
    );
    assert!(
        runtime
            .circuits
            .opens
            .migration_snapshot("exit")
            .await
            .is_none()
    );
    assert_eq!(supervisor.task_count(), 0);
    drop(_claim);
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    pair.client_link.close("test complete");
    pair.server_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn reconciliation_retains_a_live_circuit_while_a_new_preferred_path_is_pending() {
    let active_pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let candidate_pair = crate::daemon::circuit_resolution::tests::link_pair_with_client_key(
        active_pair.client_key.clone(),
    )
    .await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &active_pair.client_key,
        vec![vec!["a", "exit"]],
    );
    let local = config.local_identity().unwrap();
    let exit = config.peer_identity("exit").unwrap();
    candidate_pair.server_link.mark_topology_snapshot_received();
    candidate_pair
        .server_link
        .mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    {
        let mut links = runtime.links.lock().unwrap();
        links.insert("active".into(), active_pair.server_link.clone());
        links.insert("candidate".into(), candidate_pair.server_link.clone());
    }
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([14; 16]),
            chacha20poly1305::Key::from([14; 32]),
            active_pair.server_link.instance(),
            (vec![local, exit], 1200),
        )
        .await;
    let _claim = runtime
        .circuits
        .opens
        .claim_worker("exit")
        .expect("worker claim");
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    open_configured_circuits(&context).await.unwrap();
    // The preferred candidate uses a different Link instance, but the
    // active path's proof is still valid: a pending migration must keep
    // the old binding forwarding.
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_some()
    );
    drop(_claim);
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    active_pair.client_link.close("test complete");
    active_pair.server_link.close("test complete");
    active_pair
        .client_endpoint
        .close(0u32.into(), b"test complete");
    candidate_pair.client_link.close("test complete");
    candidate_pair.server_link.close("test complete");
    candidate_pair
        .client_endpoint
        .close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn reconciliation_migrates_to_a_ready_preferred_path_and_drains_old_lease() {
    let active_pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let candidate_pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let mut config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &active_pair.client_key,
        vec![vec!["a", "exit"]],
    );
    let relay_name = "relay";
    let relay_identity = identity::node_id(&candidate_pair.client_key.verifying_key());
    let exit_identity = config.peer_identity("exit").unwrap();
    config.peers.insert(
        relay_name.into(),
        tinect::config::Peer {
            public_key: identity::encode_public(&candidate_pair.client_key.verifying_key()),
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
    config.peers.get_mut("exit").unwrap().paths = vec![tinect::config::ConfiguredPath {
        path: vec!["a".into(), relay_name.into(), "exit".into()],
        override_routes: Vec::new(),
        override_upstream_dns: None,
    }];
    config.path_migration.readiness_stability_secs = 0;
    config.path_migration.deadline_secs = 3;
    config.path_migration.drain_timeout_secs = 1;

    active_pair.server_link.mark_topology_snapshot_received();
    active_pair
        .server_link
        .mark_topology_snapshot_acknowledged();
    candidate_pair.server_link.mark_topology_snapshot_received();
    candidate_pair
        .server_link
        .mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    {
        let mut links = runtime.links.lock().unwrap();
        links.insert("active".into(), active_pair.server_link.clone());
        links.insert("candidate".into(), candidate_pair.server_link.clone());
    }
    runtime
        .topology
        .write()
        .await
        .apply(
            tinect::topology::LinkStateAdvertisement::new(
                relay_identity.clone(),
                &candidate_pair.client_key,
                1,
                crate::daemon::support::unix_now().saturating_add(60),
                vec![tinect::topology::LinkMetric {
                    node: exit_identity.clone(),
                    cost: 1,
                    inner_mtu: 1200,
                }],
            ),
            crate::daemon::support::unix_now(),
        )
        .unwrap();
    let local_identity = runtime.config.local_identity().unwrap();
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([15; 16]),
            chacha20poly1305::Key::from([15; 32]),
            active_pair.server_link.instance(),
            (vec![local_identity.clone(), exit_identity.clone()], 1200),
        )
        .await;
    let active = runtime
        .circuits
        .opens
        .active_for_destination("exit")
        .await
        .unwrap();
    let resolution = resolve_destination(
        runtime.config.as_ref(),
        "exit",
        &runtime.links,
        &runtime.topology,
        Some(&active),
        runtime.circuits.opens.config_generation(),
        runtime.topology.read().await.generation(),
    )
    .await;
    let candidate = resolution.preferred.as_ref().expect("preferred path");
    assert_ne!(candidate.path.first_hop_link_instance, active.link_instance);
    assert!(
        runtime
            .circuits
            .opens
            .migration_readiness(
                "exit",
                &candidate.path.identity(),
                true,
                std::time::Duration::ZERO,
            )
            .await
            .is_some()
    );

    let candidate_client_link = candidate_pair.client_link.clone();
    let candidate_key = candidate_pair.client_key.clone();
    let responder = tokio::spawn(async move {
        let ControlMessage::Open(request) = candidate_client_link.recv_control().await.unwrap()
        else {
            panic!("expected migration OPEN");
        };
        candidate_client_link
            .send_control(&ControlMessage::open_ack(
                &candidate_key,
                request.circuit_id,
            ))
            .await
            .unwrap();
    });
    let resolve_link = candidate_pair.server_link.clone();
    let resolve_opens = runtime.circuits.opens.clone();
    let resolve_public = runtime.config.peers["exit"].public_key.clone();
    let resolver = tokio::spawn(async move {
        let ControlMessage::OpenAck { circuit_id, .. } = resolve_link.recv_control().await.unwrap()
        else {
            panic!("expected migration OPEN acknowledgement");
        };
        assert!(
            resolve_opens
                .resolve(
                    resolve_link.instance(),
                    circuit_id,
                    &resolve_public,
                    dataplane::OpenResult::Acknowledged,
                )
                .await
        );
    });

    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let current = runtime
                .circuits
                .opens
                .active_for_destination("exit")
                .await
                .expect("migration keeps an active lease");
            if current.link_instance == candidate_pair.server_link.instance() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        runtime
            .state
            .read()
            .await
            .status
            .circuits
            .iter()
            .find(|circuit| circuit.destination == "exit")
            .unwrap()
            .migration_state,
        MigrationState::Stable
    );
    worker.abort();
    let _ = worker.await;
    responder.await.unwrap();
    resolver.await.unwrap();
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    active_pair.server_link.close("test complete");
    active_pair.client_link.close("test complete");
    active_pair
        .client_endpoint
        .close(0u32.into(), b"test complete");
    candidate_pair.server_link.close("test complete");
    candidate_pair.client_link.close("test complete");
    candidate_pair
        .client_endpoint
        .close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn reconciler_worker_reconciles_on_active_generation_changes() {
    let mut config = crate::daemon::test_support::minimal_config();
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
            paths: vec![tinect::config::ConfiguredPath {
                path: vec!["a".into(), "exit".into()],
                override_routes: Vec::new(),
                override_upstream_dns: None,
            }],
        },
    );
    let runtime = Runtime::new(config).unwrap();
    let supervisor = DaemonSupervisor::default();
    start(&runtime, Arc::new(identity::generate()), supervisor.clone()).await;
    // A Link/lease lifecycle event must wake the idle reconciler, which
    // then spawns the per-destination OPEN worker. Keep poking until the
    // worker observes a generation change: a notify_waiters that lands
    // before the reconciler's first wait would otherwise be lost.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            runtime.circuits.opens.request_reconcile();
            if supervisor.task_count() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reconciler spawned the destination worker");
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn open_send_failure_on_a_closed_link_quarantines_the_candidate() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let opens = runtime.circuits.opens.clone();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    pair.server_link.close("open send failure test");
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });
    // The send fails fast; the candidate is quarantined and the worker
    // falls back into the bounded retry loop without a lease.
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(opens.active_for_destination("exit").await.is_none());
    assert!(!worker.is_finished());
    worker.abort();
    let _ = worker.await;
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    pair.client_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test]
async fn open_ack_waiter_cancellation_quarantines_the_candidate() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let opens = runtime.circuits.opens.clone();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    // Let the OPEN reach the peer, then revoke its Link token.  The
    // waiter must resolve as cancelled, clean up the attempt, and record
    // the candidate failure before the worker retries.
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            pair.client_link.recv_control()
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::Open(_)
    ));
    pair.server_link.close("OPEN waiter cancellation");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while opens.active_for_destination("exit").await.is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!worker.is_finished());
    worker.abort();
    let _ = worker.await;
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    pair.client_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

#[tokio::test(start_paused = true)]
async fn open_ack_timeout_quarantines_the_candidate_and_retries() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let opens = runtime.circuits.opens.clone();
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            pair.client_link.recv_control()
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::Open(_)
    ));
    // No OpenAck is sent. The five-second waiter timeout must clean the
    // attempt, quarantine this candidate, and enter bounded retry.
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert!(opens.active_for_destination("exit").await.is_none());
    assert!(!worker.is_finished());
    worker.abort();
    let _ = worker.await;
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    pair.server_link.close("test complete");
    pair.client_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

/// Peer-side responder that acknowledges every OPEN/RENEW arriving on the
/// client end of a link pair.
fn spawn_client_ack_driver(
    pair: &crate::daemon::circuit_resolution::tests::LinkPair,
) -> tokio::task::JoinHandle<()> {
    let client_link = pair.client_link.clone();
    let client_key = pair.client_key.clone();
    tokio::spawn(async move {
        loop {
            match client_link.recv_control().await {
                Ok(ControlMessage::Open(request)) => {
                    if client_link
                        .send_control(&ControlMessage::open_ack(&client_key, request.circuit_id))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(ControlMessage::CircuitRenew {
                    circuit_id,
                    counter,
                    ..
                }) => {
                    if client_link
                        .send_control(&ControlMessage::circuit_renew_ack(
                            &client_key,
                            circuit_id,
                            counter,
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    })
}

/// Source-side resolver that publishes acknowledged OPEN/RENEW results
/// into the open manager, mirroring the control-plane handler.
fn spawn_server_resolve_driver(
    pair: &crate::daemon::circuit_resolution::tests::LinkPair,
    opens: dataplane::CircuitOpenManager,
    destination_public: String,
) -> tokio::task::JoinHandle<()> {
    let server_link = pair.server_link.clone();
    let server_instance = pair.server_link.instance();
    tokio::spawn(async move {
        loop {
            match server_link.recv_control().await {
                Ok(ControlMessage::OpenAck { circuit_id, .. }) => {
                    let _ = opens
                        .resolve(
                            server_instance,
                            circuit_id,
                            &destination_public,
                            dataplane::OpenResult::Acknowledged,
                        )
                        .await;
                }
                Ok(ControlMessage::CircuitRenewAck {
                    circuit_id,
                    counter,
                    ..
                }) => {
                    let _ = opens
                        .resolve(
                            server_instance,
                            circuit_id,
                            &destination_public,
                            dataplane::OpenResult::RenewAcknowledged { counter },
                        )
                        .await;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    })
}

/// Drain one link end without answering anything.
fn spawn_drain_driver(link: &Arc<tinect::carrier::Link>) -> tokio::task::JoinHandle<()> {
    let link = link.clone();
    tokio::spawn(async move {
        loop {
            if link.recv_control().await.is_err() {
                break;
            }
        }
    })
}

fn close_pair(pair: &crate::daemon::circuit_resolution::tests::LinkPair) {
    pair.server_link.close("test complete");
    pair.client_link.close("test complete");
    pair.client_endpoint.close(0u32.into(), b"test complete");
}

/// Poll helper for paused-clock tests where `tokio::time::timeout` cannot
/// fire on its own. The deadline is wall-clock so real network IO can
/// complete while the tokio clock is paused.
async fn wait_for_active_paused(
    opens: &dataplane::CircuitOpenManager,
    destination: &str,
) -> dataplane::ActiveCircuit {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(active) = opens.active_for_destination(destination).await {
            return active;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "circuit for {destination} did not become active"
        );
        tokio::task::yield_now().await;
    }
}

/// Poll with a wall-clock deadline so real network IO can complete even
/// while the tokio clock is paused.
async fn wait_for_circuit_matching(
    opens: &dataplane::CircuitOpenManager,
    destination: &str,
    predicate: impl Fn(&dataplane::ActiveCircuit) -> bool,
) -> dataplane::ActiveCircuit {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(active) = opens.active_for_destination(destination).await
            && predicate(&active)
        {
            return active;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "circuit for {destination} did not reach the expected state"
        );
        tokio::task::yield_now().await;
    }
}

/// Like [`wait_for_circuit_matching`], but also advances the paused tokio
/// clock so the worker's virtual backoff timers can fire.
async fn wait_for_swap_paused(
    opens: &dataplane::CircuitOpenManager,
    destination: &str,
    retired: tinect::circuit::CircuitId,
) -> dataplane::ActiveCircuit {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(active) = opens.active_for_destination(destination).await
            && active.circuit_id != retired
        {
            return active;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "circuit for {destination} was not replaced"
        );
        tokio::time::advance(std::time::Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
    }
}

/// A configured "exit" destination reachable directly through
/// `active_pair` or through the `relay` node backed by `candidate_pair`.
struct MigrationHarness {
    active_pair: crate::daemon::circuit_resolution::tests::LinkPair,
    candidate_pair: crate::daemon::circuit_resolution::tests::LinkPair,
    runtime: Runtime,
    local_identity: String,
    relay_identity: String,
    exit_identity: String,
    exit_public: String,
}

async fn migration_harness(
    exit_paths: Vec<Vec<&str>>,
    readiness_stability_secs: u64,
    deadline_secs: u64,
    drain_timeout_secs: u64,
) -> MigrationHarness {
    let active_pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let candidate_pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let mut config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &active_pair.client_key,
        exit_paths,
    );
    config.peers.insert(
        "relay".into(),
        tinect::config::Peer {
            public_key: identity::encode_public(&candidate_pair.client_key.verifying_key()),
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
    config.path_migration.readiness_stability_secs = readiness_stability_secs;
    config.path_migration.deadline_secs = deadline_secs;
    config.path_migration.drain_timeout_secs = drain_timeout_secs;
    active_pair.server_link.mark_topology_snapshot_received();
    active_pair
        .server_link
        .mark_topology_snapshot_acknowledged();
    candidate_pair.server_link.mark_topology_snapshot_received();
    candidate_pair
        .server_link
        .mark_topology_snapshot_acknowledged();
    let relay_identity = identity::node_id(&candidate_pair.client_key.verifying_key());
    let exit_identity = config.peer_identity("exit").unwrap();
    let exit_public = config.peers["exit"].public_key.clone();
    let local_identity = config.local_identity().unwrap();
    let runtime = Runtime::new(config).unwrap();
    {
        let mut links = runtime.links.lock().unwrap();
        links.insert("active".into(), active_pair.server_link.clone());
        links.insert("candidate".into(), candidate_pair.server_link.clone());
    }
    MigrationHarness {
        active_pair,
        candidate_pair,
        runtime,
        local_identity,
        relay_identity,
        exit_identity,
        exit_public,
    }
}

async fn advertise_relay(harness: &MigrationHarness, sequence: u64) {
    harness
        .runtime
        .topology
        .write()
        .await
        .apply(
            tinect::topology::LinkStateAdvertisement::new(
                harness.relay_identity.clone(),
                &harness.candidate_pair.client_key,
                sequence,
                unix_now().saturating_add(60),
                vec![tinect::topology::LinkMetric {
                    node: harness.exit_identity.clone(),
                    cost: 1,
                    inner_mtu: 1200,
                }],
            ),
            unix_now(),
        )
        .unwrap();
}

async fn activate_direct_circuit(
    harness: &MigrationHarness,
    marker: u8,
) -> dataplane::ActiveCircuit {
    harness
        .runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([marker; 16]),
            chacha20poly1305::Key::from([marker; 32]),
            harness.active_pair.server_link.instance(),
            (
                vec![
                    harness.local_identity.clone(),
                    harness.exit_identity.clone(),
                ],
                1200,
            ),
        )
        .await;
    harness
        .runtime
        .circuits
        .opens
        .active_for_destination("exit")
        .await
        .expect("direct circuit")
}

/// Activate the direct circuit, then resolve the relay path and start a
/// migration record targeting it, so a worker observes an in-flight
/// preferred-path migration. Returns the still-active direct lease.
async fn begin_relay_migration(harness: &MigrationHarness, marker: u8) -> dataplane::ActiveCircuit {
    let active = activate_direct_circuit(harness, marker).await;
    let resolution = resolve_destination(
        harness.runtime.config.as_ref(),
        "exit",
        &harness.runtime.links,
        &harness.runtime.topology,
        Some(&active),
        harness.runtime.circuits.opens.config_generation(),
        harness.runtime.topology.read().await.generation(),
    )
    .await;
    let preferred = resolution.preferred.expect("relay path preferred");
    assert_eq!(
        preferred.path.first_hop_link_instance,
        harness.candidate_pair.server_link.instance()
    );
    assert!(
        harness
            .runtime
            .circuits
            .opens
            .migration_readiness(
                "exit",
                &preferred.path.identity(),
                true,
                std::time::Duration::ZERO,
            )
            .await
            .is_some()
    );
    assert!(
        harness
            .runtime
            .circuits
            .opens
            .begin_migration("exit")
            .await
            .is_some()
    );
    active
}

async fn shutdown_harness(harness: &MigrationHarness, supervisor: &DaemonSupervisor) {
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    close_pair(&harness.active_pair);
    close_pair(&harness.candidate_pair);
}

#[tokio::test]
async fn hard_revoke_with_a_closed_link_reports_the_close_failure() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let runtime = Runtime::new(crate::daemon::test_support::minimal_config()).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let circuit_id = tinect::circuit::CircuitId([51; 16]);
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            circuit_id,
            chacha20poly1305::Key::from([51; 32]),
            pair.server_link.instance(),
            (vec!["a".into(), "exit".into()], 1200),
        )
        .await;
    let active = runtime
        .circuits
        .opens
        .active_for_destination("exit")
        .await
        .expect("active circuit");
    // The best-effort CLOSE cannot be delivered on a closed Link; the
    // failure must be logged without delaying the local revocation.
    pair.server_link.close("link already down");

    let supervisor = DaemonSupervisor::default();
    hard_revoke_active_circuit(
        &runtime.circuits.opens,
        &runtime.circuits.sessions,
        &runtime.circuits.return_flows,
        &runtime.circuits.circuit_dns,
        "exit",
        &active,
        &runtime.links,
        &identity::generate(),
        &supervisor,
        "test revoke with closed link",
    )
    .await;
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
    // Shutdown joins the background CLOSE task and exercises its error
    // branch.
    supervisor
        .shutdown(std::time::Duration::from_secs(2))
        .await
        .unwrap();
    close_pair(&pair);
}

#[tokio::test]
async fn renewal_retries_retryable_local_admission_rejections_then_succeeds() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        Vec::new(),
    );
    let active_path = vec![
        config.local_identity().unwrap(),
        config.peer_identity("exit").unwrap(),
    ];
    let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
        "client".to_owned(),
        pair.server_link.clone(),
    )])));
    let opens = dataplane::CircuitOpenManager::default();
    opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([52; 16]),
            chacha20poly1305::Key::from([52; 32]),
            pair.server_link.instance(),
            (active_path, 1200),
        )
        .await;
    let resolver_link = pair.client_link.clone();
    let resolver_opens = opens.clone();
    let resolver_instance = pair.server_link.instance();
    let resolver_public = config.peers["exit"].public_key.clone();
    let responder = tokio::spawn(async move {
        // Six renewals: local admission backpressure twice, one success,
        // then three more rejections to exhaust the bounded retry budget.
        for round in 0..6 {
            let ControlMessage::CircuitRenew {
                circuit_id,
                counter,
                ..
            } = resolver_link.recv_control().await.unwrap()
            else {
                panic!("expected CircuitRenew");
            };
            let result = if round == 2 {
                dataplane::OpenResult::RenewAcknowledged { counter }
            } else {
                dataplane::OpenResult::Rejected {
                        retryable: true,
                        reason: crate::daemon::control_handler::OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION_TEXT.to_owned(),
                    }
            };
            assert!(
                resolver_opens
                    .resolve(resolver_instance, circuit_id, &resolver_public, result)
                    .await
            );
        }
    });

    // Two transient admission rejections are retried; the third attempt is
    // acknowledged.
    assert!(
        renew_active_circuit_once(&config, "exit", &links, &opens, &identity::generate()).await
    );
    // Exhausting the bounded retry budget fails the renewal without
    // withdrawing the active lease.
    assert!(
        !renew_active_circuit_once(&config, "exit", &links, &opens, &identity::generate()).await
    );
    assert!(opens.active_for_destination("exit").await.is_some());
    responder.await.unwrap();
    close_pair(&pair);
}

#[tokio::test]
async fn renewed_lease_replaced_during_acknowledgement_reports_lease_changed() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        Vec::new(),
    );
    let active_path = vec![
        config.local_identity().unwrap(),
        config.peer_identity("exit").unwrap(),
    ];
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let exit_public = runtime.config.peers["exit"].public_key.clone();
    let server_instance = pair.server_link.instance();
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([53; 16]),
            chacha20poly1305::Key::from([53; 32]),
            server_instance,
            (active_path.clone(), 1200),
        )
        .await;
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());

    // Replace the lease while the renewal acknowledgement is in flight:
    // the confirmation belongs to the retired lease and must not be
    // credited to its replacement.
    let responder_link = pair.client_link.clone();
    let responder_opens = runtime.circuits.opens.clone();
    let responder_public = exit_public.clone();
    let responder_path = active_path.clone();
    let responder = tokio::spawn(async move {
        let ControlMessage::CircuitRenew {
            circuit_id,
            counter,
            ..
        } = responder_link.recv_control().await.unwrap()
        else {
            panic!("expected CircuitRenew");
        };
        responder_opens.deactivate("exit", circuit_id).await;
        responder_opens
            .activate(
                "exit".into(),
                tinect::circuit::CircuitId([54; 16]),
                chacha20poly1305::Key::from([54; 32]),
                server_instance,
                (responder_path, 1200),
            )
            .await;
        assert!(
            responder_opens
                .resolve(
                    server_instance,
                    circuit_id,
                    &responder_public,
                    dataplane::OpenResult::RenewAcknowledged { counter },
                )
                .await
        );
    });
    let mut grace = None;
    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::LeaseChanged
    );
    assert!(grace.is_none());
    responder.await.unwrap();

    // Withdraw the lease entirely while its renewal is in flight: the
    // acknowledged renewal still reports that nothing is active anymore.
    let responder_link = pair.client_link.clone();
    let responder_opens = runtime.circuits.opens.clone();
    let responder_public = exit_public.clone();
    let responder = tokio::spawn(async move {
        let ControlMessage::CircuitRenew {
            circuit_id,
            counter,
            ..
        } = responder_link.recv_control().await.unwrap()
        else {
            panic!("expected CircuitRenew");
        };
        responder_opens.deactivate("exit", circuit_id).await;
        assert!(
            responder_opens
                .resolve(
                    server_instance,
                    circuit_id,
                    &responder_public,
                    dataplane::OpenResult::RenewAcknowledged { counter },
                )
                .await
        );
    });
    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::Inactive
    );
    assert!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .is_none()
    );
    responder.await.unwrap();
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    close_pair(&pair);
}

#[tokio::test]
async fn failed_renewal_for_a_replaced_lease_reports_lease_changed() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        Vec::new(),
    );
    let active_path = vec![
        config.local_identity().unwrap(),
        config.peer_identity("exit").unwrap(),
    ];
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let exit_public = runtime.config.peers["exit"].public_key.clone();
    let server_instance = pair.server_link.instance();
    runtime
        .circuits
        .opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([55; 16]),
            chacha20poly1305::Key::from([55; 32]),
            server_instance,
            (active_path.clone(), 1200),
        )
        .await;
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let active = runtime
        .circuits
        .opens
        .active_for_destination("exit")
        .await
        .expect("active circuit");
    let mut grace = Some(RenewalFailureGrace::for_active(&active, Instant::now()));

    // The rejection belongs to the retired lease; its failure budget must
    // not be charged against the replacement circuit.
    let responder_link = pair.client_link.clone();
    let responder_opens = runtime.circuits.opens.clone();
    let responder = tokio::spawn(async move {
        let ControlMessage::CircuitRenew { circuit_id, .. } =
            responder_link.recv_control().await.unwrap()
        else {
            panic!("expected CircuitRenew");
        };
        responder_opens.deactivate("exit", circuit_id).await;
        responder_opens
            .activate(
                "exit".into(),
                tinect::circuit::CircuitId([56; 16]),
                chacha20poly1305::Key::from([56; 32]),
                server_instance,
                (active_path, 1200),
            )
            .await;
        assert!(
            responder_opens
                .resolve(
                    server_instance,
                    circuit_id,
                    &exit_public,
                    dataplane::OpenResult::Rejected {
                        retryable: false,
                        reason: "retired lease".into(),
                    },
                )
                .await
        );
    });
    assert_eq!(
        renew_active_circuit_with_grace(&context, "exit", &mut grace).await,
        RenewalResult::LeaseChanged
    );
    assert!(grace.is_none());
    responder.await.unwrap();
    assert_eq!(
        runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .expect("replacement lease")
            .circuit_id,
        tinect::circuit::CircuitId([56; 16])
    );
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    close_pair(&pair);
}

#[tokio::test(start_paused = true)]
async fn active_worker_renews_rebuilds_and_follows_lifecycle_events() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let mut config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    config.path_migration.drain_timeout_secs = 0;
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let exit_public = runtime.config.peers["exit"].public_key.clone();
    let opens = runtime.circuits.opens.clone();
    let client_driver = spawn_client_ack_driver(&pair);
    let server_driver = spawn_server_resolve_driver(&pair, opens.clone(), exit_public);
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    let initial = wait_for_active_paused(&opens, "exit").await;
    // The committed worker proves liveness with a signed renewal once the
    // renewal deadline elapses.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while initial.renewal_counter.load(Ordering::Acquire) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "worker did not renew the committed lease"
        );
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    assert!(opens.is_active("exit", initial.circuit_id).await);

    // A sequence-exhaustion rebuild request retires the worker snapshot
    // and re-opens a fresh lease on the same path.
    opens.request_rebuild("exit").await;
    let rebuilt = wait_for_swap_paused(&opens, "exit", initial.circuit_id).await;

    // Withdrawing the lease wakes the worker, which re-opens it.
    opens.deactivate("exit", rebuilt.circuit_id).await;
    let reopened = wait_for_swap_paused(&opens, "exit", rebuilt.circuit_id).await;

    // A newer authorization generation retires the worker's stale context
    // and re-opens under the current generation.
    opens.bump_config_generation();
    opens.request_reconcile();
    let regenerated = wait_for_swap_paused(&opens, "exit", reopened.circuit_id).await;
    assert_eq!(regenerated.config_generation, opens.config_generation());
    assert!(!worker.is_finished());

    worker.abort();
    let _ = worker.await;
    client_driver.abort();
    server_driver.abort();
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    close_pair(&pair);
}

#[tokio::test]
async fn worker_discards_a_stale_open_acknowledgement_and_retries() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let exit_public = runtime.config.peers["exit"].public_key.clone();
    let opens = runtime.circuits.opens.clone();
    let client_driver = spawn_client_ack_driver(&pair);
    // Bump the authorization generation before publishing the first ACK:
    // the commit then observes a stale attempt and the worker must retire
    // the remote binding and retry under the current generation.
    let stale_opens = opens.clone();
    let stale_server = pair.server_link.clone();
    let stale_instance = pair.server_link.instance();
    let stale_public = exit_public.clone();
    let bumped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bumped_driver = bumped.clone();
    let server_driver = tokio::spawn(async move {
        loop {
            match stale_server.recv_control().await {
                Ok(ControlMessage::OpenAck { circuit_id, .. }) => {
                    if !bumped_driver.swap(true, Ordering::AcqRel) {
                        stale_opens.bump_config_generation();
                    }
                    let _ = stale_opens
                        .resolve(
                            stale_instance,
                            circuit_id,
                            &stale_public,
                            dataplane::OpenResult::Acknowledged,
                        )
                        .await;
                }
                Ok(ControlMessage::CircuitRenewAck {
                    circuit_id,
                    counter,
                    ..
                }) => {
                    let _ = stale_opens
                        .resolve(
                            stale_instance,
                            circuit_id,
                            &stale_public,
                            dataplane::OpenResult::RenewAcknowledged { counter },
                        )
                        .await;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    let active = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Some(active) = opens.active_for_destination("exit").await {
                break active;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("circuit committed after the stale acknowledgement was discarded");
    assert!(bumped.load(Ordering::Acquire));
    assert_eq!(active.config_generation, opens.config_generation());

    worker.abort();
    let _ = worker.await;
    client_driver.abort();
    server_driver.abort();
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    close_pair(&pair);
}

#[tokio::test]
async fn a_pending_attempt_defers_duplicate_open_until_cancelled() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let exit_public = runtime.config.peers["exit"].public_key.clone();
    let opens = runtime.circuits.opens.clone();
    // Hold a pending attempt so the worker cannot publish its own OPEN.
    let blocking = opens
        .begin_attempt(
            "exit",
            opens.next_circuit_id().await,
            identity("exit", pair.server_link.instance()),
            opens.config_generation(),
            pair.server_link.instance(),
        )
        .await
        .expect("blocking attempt");
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    // While the foreign attempt is pending, no OPEN may leave the node.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            pair.client_link.recv_control(),
        )
        .await
        .is_err()
    );
    opens.cancel_attempt(&blocking).await;

    let message = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        pair.client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    let ControlMessage::Open(request) = message else {
        panic!("expected Open after the blocking attempt was cancelled");
    };
    pair.client_link
        .send_control(&ControlMessage::open_ack(
            &pair.client_key,
            request.circuit_id,
        ))
        .await
        .unwrap();
    let ack = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        pair.server_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    let ControlMessage::OpenAck { circuit_id, .. } = ack else {
        panic!("expected OpenAck");
    };
    assert!(
        opens
            .resolve(
                pair.server_link.instance(),
                circuit_id,
                &exit_public,
                dataplane::OpenResult::Acknowledged,
            )
            .await
    );
    wait_for_circuit_matching(&opens, "exit", |_| true).await;

    worker.abort();
    let _ = worker.await;
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    close_pair(&pair);
}

#[tokio::test]
async fn worker_migrates_to_a_preferred_path_once_topology_marks_it_ready() {
    let harness =
        migration_harness(vec![vec!["a", "relay", "exit"], vec!["a", "exit"]], 1, 5, 0).await;
    let opens = harness.runtime.circuits.opens.clone();
    let drivers = (
        spawn_client_ack_driver(&harness.active_pair),
        spawn_server_resolve_driver(
            &harness.active_pair,
            opens.clone(),
            harness.exit_public.clone(),
        ),
        spawn_client_ack_driver(&harness.candidate_pair),
        spawn_server_resolve_driver(
            &harness.candidate_pair,
            opens.clone(),
            harness.exit_public.clone(),
        ),
    );
    let supervisor = DaemonSupervisor::default();
    let context = CircuitReconcileContext::new(
        &harness.runtime,
        Arc::new(identity::generate()),
        supervisor.clone(),
    );
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    // Initially only the direct path has a proof.
    let direct = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(active) = opens.active_for_destination("exit").await {
                break active;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("direct circuit");
    assert_eq!(
        direct.link_instance,
        harness.active_pair.server_link.instance()
    );

    // Once the relay advertises reachability, the committed worker
    // observes the topology change, waits out the readiness stability
    // window and starts the bounded migration.
    advertise_relay(&harness, 1).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if opens.migration_snapshot("exit").await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("migration readiness recorded");
    // A topology update landing inside the readiness wait re-evaluates the
    // migration immediately instead of waiting for the renewal cadence.
    advertise_relay(&harness, 2).await;

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(active) = opens.active_for_destination("exit").await
                && active.link_instance == harness.candidate_pair.server_link.instance()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("migration committed on the relay path");
    let migrated = opens
        .active_for_destination("exit")
        .await
        .expect("migrated circuit");
    assert_eq!(
        migrated.path,
        vec![
            harness.local_identity.clone(),
            harness.relay_identity.clone(),
            harness.exit_identity.clone()
        ]
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if opens.migration_snapshot("exit").await.is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("migration state cleared after the new lease became active");
    assert_eq!(
        harness
            .runtime
            .state
            .read()
            .await
            .status
            .circuits
            .iter()
            .find(|circuit| circuit.destination == "exit")
            .unwrap()
            .migration_state,
        MigrationState::Stable
    );

    worker.abort();
    let _ = worker.await;
    drivers.0.abort();
    drivers.1.abort();
    drivers.2.abort();
    drivers.3.abort();
    shutdown_harness(&harness, &supervisor).await;
}

#[tokio::test(start_paused = true)]
async fn migration_open_ack_timeout_marks_overdue_and_retains_old_lease() {
    let harness = migration_harness(vec![vec!["a", "relay", "exit"]], 0, 0, 0).await;
    advertise_relay(&harness, 1).await;
    let direct = begin_relay_migration(&harness, 57).await;
    let opens = harness.runtime.circuits.opens.clone();
    // Nobody answers the migration OPEN or the renewals: the OPEN wait
    // times out immediately (deadline zero) and every renewal fails.
    let drains = (
        spawn_drain_driver(&harness.active_pair.client_link),
        spawn_drain_driver(&harness.active_pair.server_link),
        spawn_drain_driver(&harness.candidate_pair.client_link),
        spawn_drain_driver(&harness.candidate_pair.server_link),
    );
    let supervisor = DaemonSupervisor::default();
    let context = CircuitReconcileContext::new(
        &harness.runtime,
        Arc::new(identity::generate()),
        supervisor.clone(),
    );
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    // The migration deadline already elapsed, so the timed-out OPEN marks
    // the migration overdue while the old lease keeps forwarding.
    let mut observed_overdue = false;
    for _ in 0..40 {
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        let state = harness.runtime.state.read().await;
        let circuit = state
            .status
            .circuits
            .iter()
            .find(|circuit| circuit.destination == "exit")
            .expect("circuit status");
        if circuit.migration_state == MigrationState::MigrationOverdue
            && circuit.migration_last_error.as_deref() == Some("OpenAck timeout")
        {
            observed_overdue = true;
            break;
        }
    }
    assert!(
        observed_overdue,
        "migration marked overdue after OPEN timeout"
    );
    assert!(opens.is_active("exit", direct.circuit_id).await);

    // Replacing the lease while a failure grace is pending must not carry
    // the old lease's failure budget over.
    opens.deactivate("exit", direct.circuit_id).await;
    opens
        .activate(
            "exit".into(),
            tinect::circuit::CircuitId([59; 16]),
            chacha20poly1305::Key::from([59; 32]),
            harness.active_pair.server_link.instance(),
            (
                vec![
                    harness.local_identity.clone(),
                    harness.exit_identity.clone(),
                ],
                1200,
            ),
        )
        .await;
    for _ in 0..10 {
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        tokio::task::yield_now().await;
    }
    assert!(
        opens
            .is_active("exit", tinect::circuit::CircuitId([59; 16]))
            .await,
        "replacement lease survives the retired lease's failure budget"
    );
    assert!(!worker.is_finished());

    worker.abort();
    let _ = worker.await;
    drains.0.abort();
    drains.1.abort();
    drains.2.abort();
    drains.3.abort();
    shutdown_harness(&harness, &supervisor).await;
}

#[tokio::test]
async fn migration_open_send_failure_marks_pending_and_retains_old_lease() {
    let harness = migration_harness(vec![vec!["a", "relay", "exit"]], 0, 60, 0).await;
    advertise_relay(&harness, 1).await;
    let direct = begin_relay_migration(&harness, 60).await;
    let opens = harness.runtime.circuits.opens.clone();
    let drivers = (
        spawn_client_ack_driver(&harness.active_pair),
        spawn_server_resolve_driver(
            &harness.active_pair,
            opens.clone(),
            harness.exit_public.clone(),
        ),
    );
    // The relay Link is down: the migration OPEN fails to send and the
    // candidate is quarantined while the old lease keeps renewing.
    harness.candidate_pair.server_link.close("relay link down");
    let supervisor = DaemonSupervisor::default();
    let context = CircuitReconcileContext::new(
        &harness.runtime,
        Arc::new(identity::generate()),
        supervisor.clone(),
    );
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let state = harness.runtime.state.read().await;
            let circuit = state
                .status
                .circuits
                .iter()
                .find(|circuit| circuit.destination == "exit")
                .expect("circuit status");
            if circuit.migration_state == MigrationState::MigrationPending
                && circuit
                    .migration_last_error
                    .as_deref()
                    .is_some_and(|error| error.starts_with("OPEN send failed: "))
            {
                break;
            }
            drop(state);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("migration marked pending with the send failure");
    assert!(opens.is_active("exit", direct.circuit_id).await);
    assert!(!worker.is_finished());

    worker.abort();
    let _ = worker.await;
    drivers.0.abort();
    drivers.1.abort();
    shutdown_harness(&harness, &supervisor).await;
}

#[tokio::test]
async fn migration_open_rejection_waits_out_the_bounded_retry_before_reopening() {
    let harness = migration_harness(vec![vec!["a", "relay", "exit"]], 0, 60, 0).await;
    advertise_relay(&harness, 1).await;
    let direct = begin_relay_migration(&harness, 62).await;
    let opens = harness.runtime.circuits.opens.clone();
    let drivers = (
        spawn_client_ack_driver(&harness.active_pair),
        spawn_server_resolve_driver(
            &harness.active_pair,
            opens.clone(),
            harness.exit_public.clone(),
        ),
    );
    // The relay rejects every migration OPEN with a non-retryable error.
    let open_attempts = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reject_link = harness.candidate_pair.client_link.clone();
    let reject_key = harness.candidate_pair.client_key.clone();
    let reject_attempts = open_attempts.clone();
    let reject_driver = tokio::spawn(async move {
        loop {
            match reject_link.recv_control().await {
                Ok(ControlMessage::Open(request)) => {
                    reject_attempts.fetch_add(1, Ordering::AcqRel);
                    if reject_link
                        .send_control(&ControlMessage::open_reject(
                            &reject_key,
                            request.circuit_id,
                            false,
                            crate::daemon::control_handler::OPEN_REJECT_REASON_GENERIC,
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    // Publish the rejection and bump the topology generation first so the
    // worker's next iteration re-resolves the same preferred identity and
    // waits out the non-retryable rejection instead of retrying instantly.
    let resolve_link = harness.candidate_pair.server_link.clone();
    let resolve_instance = harness.candidate_pair.server_link.instance();
    let resolve_opens = opens.clone();
    let resolve_public = harness.exit_public.clone();
    let resolve_topology = harness.runtime.topology.clone();
    let relay_identity = harness.relay_identity.clone();
    let relay_key = harness.candidate_pair.client_key.clone();
    let exit_identity = harness.exit_identity.clone();
    let resolve_driver = tokio::spawn(async move {
        let mut sequence = 1_u64;
        loop {
            match resolve_link.recv_control().await {
                Ok(ControlMessage::OpenReject {
                    circuit_id,
                    retryable,
                    reason_code,
                    ..
                }) => {
                    sequence += 1;
                    resolve_topology
                        .write()
                        .await
                        .apply(
                            tinect::topology::LinkStateAdvertisement::new(
                                relay_identity.clone(),
                                &relay_key,
                                sequence,
                                unix_now().saturating_add(60),
                                vec![tinect::topology::LinkMetric {
                                    node: exit_identity.clone(),
                                    cost: 1,
                                    inner_mtu: 1200,
                                }],
                            ),
                            unix_now(),
                        )
                        .unwrap();
                    let _ = resolve_opens
                        .resolve(
                            resolve_instance,
                            circuit_id,
                            &resolve_public,
                            dataplane::OpenResult::Rejected {
                                retryable,
                                reason: format!("code:{reason_code}"),
                            },
                        )
                        .await;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    let supervisor = DaemonSupervisor::default();
    let context = CircuitReconcileContext::new(
        &harness.runtime,
        Arc::new(identity::generate()),
        supervisor.clone(),
    );
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });

    // The bounded non-retryable rejection wait elapses and the worker
    // retries the same preferred path.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if open_attempts.load(Ordering::Acquire) >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("migration OPEN retried after the rejection cooldown");
    let state = harness.runtime.state.read().await;
    let circuit = state
        .status
        .circuits
        .iter()
        .find(|circuit| circuit.destination == "exit")
        .expect("circuit status");
    assert_eq!(circuit.migration_state, MigrationState::MigrationPending);
    assert_eq!(
        circuit.migration_last_error.as_deref(),
        Some(
            format!(
                "code:{}",
                crate::daemon::control_handler::OPEN_REJECT_REASON_GENERIC
            )
            .as_str()
        )
    );
    drop(state);
    assert!(opens.is_active("exit", direct.circuit_id).await);
    assert!(!worker.is_finished());

    worker.abort();
    let _ = worker.await;
    drivers.0.abort();
    drivers.1.abort();
    reject_driver.abort();
    resolve_driver.abort();
    shutdown_harness(&harness, &supervisor).await;
}

#[tokio::test(start_paused = true)]
async fn worker_revokes_the_lease_when_the_first_hop_link_leaves_the_registry() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let exit_public = runtime.config.peers["exit"].public_key.clone();
    let opens = runtime.circuits.opens.clone();
    let client_driver = spawn_client_ack_driver(&pair);
    let server_driver = spawn_server_resolve_driver(&pair, opens.clone(), exit_public);
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });
    let committed = wait_for_active_paused(&opens, "exit").await;

    // Removing the first hop from the registry leaves no ready candidate;
    // the committed worker resets its migration readiness tracking and the
    // next renewal withdraws the unprovable lease.
    runtime.links.lock().unwrap().remove("client");
    opens.request_reconcile();
    let mut revoked = false;
    for _ in 0..60 {
        if opens.active_for_destination("exit").await.is_none() {
            revoked = true;
            break;
        }
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    assert!(revoked, "lease withdrawn once its first hop is gone");
    assert!(!opens.is_active("exit", committed.circuit_id).await);
    assert!(!worker.is_finished());

    worker.abort();
    let _ = worker.await;
    client_driver.abort();
    server_driver.abort();
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    close_pair(&pair);
}

#[tokio::test(start_paused = true)]
async fn renewal_failure_for_a_replaced_lease_retires_the_worker_snapshot() {
    let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
    let config = crate::daemon::circuit_resolution::tests::config_with_client_peer(
        &pair.client_key,
        vec![vec!["a", "exit"]],
    );
    pair.server_link.mark_topology_snapshot_received();
    pair.server_link.mark_topology_snapshot_acknowledged();
    let runtime = Runtime::new(config).unwrap();
    runtime
        .links
        .lock()
        .unwrap()
        .insert("client".into(), pair.server_link.clone());
    let exit_public = runtime.config.peers["exit"].public_key.clone();
    let replacement_path = vec![
        runtime.config.local_identity().unwrap(),
        runtime.config.peer_identity("exit").unwrap(),
    ];
    let opens = runtime.circuits.opens.clone();
    let server_driver = spawn_server_resolve_driver(&pair, opens.clone(), exit_public.clone());
    // The first renewal finds its lease already replaced: reject it so the
    // worker retires the stale snapshot instead of charging the failure
    // against the replacement circuit.
    let client_link = pair.client_link.clone();
    let client_key = pair.client_key.clone();
    let server_instance = pair.server_link.instance();
    let client_opens = opens.clone();
    let client_driver = tokio::spawn(async move {
        let mut replaced = false;
        loop {
            match client_link.recv_control().await {
                Ok(ControlMessage::Open(request)) => {
                    if client_link
                        .send_control(&ControlMessage::open_ack(&client_key, request.circuit_id))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(ControlMessage::CircuitRenew {
                    circuit_id,
                    counter,
                    ..
                }) if replaced => {
                    if client_link
                        .send_control(&ControlMessage::circuit_renew_ack(
                            &client_key,
                            circuit_id,
                            counter,
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(ControlMessage::CircuitRenew { circuit_id, .. }) => {
                    replaced = true;
                    client_opens.deactivate("exit", circuit_id).await;
                    client_opens
                        .activate(
                            "exit".into(),
                            tinect::circuit::CircuitId([64; 16]),
                            chacha20poly1305::Key::from([64; 32]),
                            server_instance,
                            (replacement_path.clone(), 1200),
                        )
                        .await;
                    assert!(
                        client_opens
                            .resolve(
                                server_instance,
                                circuit_id,
                                &exit_public,
                                dataplane::OpenResult::Rejected {
                                    retryable: false,
                                    reason: "retired lease".into(),
                                },
                            )
                            .await
                    );
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    let supervisor = DaemonSupervisor::default();
    let context =
        CircuitReconcileContext::new(&runtime, Arc::new(identity::generate()), supervisor.clone());
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });
    let committed = wait_for_active_paused(&opens, "exit").await;

    // Drive one renewal; the replacement lease is then retired by the
    // worker and a fresh lease is opened. Advance the paused clock so the
    // renewal timer fires, while the wall-clock deadline leaves room for
    // the real control IO.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let reopened = loop {
        if let Some(active) = opens.active_for_destination("exit").await
            && active.circuit_id != committed.circuit_id
            && active.circuit_id != tinect::circuit::CircuitId([64; 16])
        {
            break Some(active);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "worker re-opened after the lease swap"
        );
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    };
    assert!(reopened.is_some());
    assert!(!worker.is_finished());

    worker.abort();
    let _ = worker.await;
    client_driver.abort();
    server_driver.abort();
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    close_pair(&pair);
}

#[tokio::test]
async fn unbounded_readiness_stability_keeps_migration_pending() {
    let harness = migration_harness(
        vec![vec!["a", "relay", "exit"], vec!["a", "exit"]],
        u64::MAX,
        5,
        0,
    )
    .await;
    let opens = harness.runtime.circuits.opens.clone();
    let drivers = (
        spawn_client_ack_driver(&harness.active_pair),
        spawn_server_resolve_driver(
            &harness.active_pair,
            opens.clone(),
            harness.exit_public.clone(),
        ),
        spawn_client_ack_driver(&harness.candidate_pair),
        spawn_server_resolve_driver(
            &harness.candidate_pair,
            opens.clone(),
            harness.exit_public.clone(),
        ),
    );
    let supervisor = DaemonSupervisor::default();
    let context = CircuitReconcileContext::new(
        &harness.runtime,
        Arc::new(identity::generate()),
        supervisor.clone(),
    );
    let worker = tokio::spawn(async move { open_configured_circuit(&context, "exit").await });
    let direct = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(active) = opens.active_for_destination("exit").await {
                break active;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("direct circuit");

    advertise_relay(&harness, 1).await;
    // A readiness deadline beyond the representable instant range stays
    // pending: the migration is tracked but never started.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if opens.migration_snapshot("exit").await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("migration readiness recorded");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (_, started, _) = opens.migration_snapshot("exit").await.expect("migration");
    assert!(
        started.is_none(),
        "migration never starts without a deadline"
    );
    assert!(opens.is_active("exit", direct.circuit_id).await);
    assert!(!worker.is_finished());

    worker.abort();
    let _ = worker.await;
    drivers.0.abort();
    drivers.1.abort();
    drivers.2.abort();
    drivers.3.abort();
    shutdown_harness(&harness, &supervisor).await;
}
