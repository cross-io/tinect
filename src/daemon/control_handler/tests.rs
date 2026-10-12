use super::*;
use std::sync::Mutex;
use tinect::link::{LinkError, LinkFuture};

struct LiveControlHarness {
    client_key: ed25519_dalek::SigningKey,
    server_key: ed25519_dalek::SigningKey,
    client_identity: String,
    server_identity: String,
    client_link: Arc<carrier::Link>,
    server_link: Arc<carrier::Link>,
    client_endpoint: quinn::Endpoint,
    runtime: Runtime,
    supervisor: tinect::runtime::DaemonSupervisor,
    router: Arc<Router>,
}

impl LiveControlHarness {
    async fn new(repair_rate: u16) -> Self {
        Self::new_inner(
            repair_rate,
            tinect::policy::TransitPolicy::new(false, HashMap::new()),
            true,
        )
        .await
    }

    /// Harness whose Router permits the client as a transit source, so a
    /// three-hop OPEN (or a self-relay back to the source) reaches the
    /// relay binding path instead of being denied by transit policy.
    async fn new_with_transit(repair_rate: u16, transit: tinect::policy::TransitPolicy) -> Self {
        Self::new_inner(repair_rate, transit, true).await
    }

    /// Harness without a control handler for the server link, so a test
    /// can close the link before starting the handler (initial Snapshot
    /// send failure) or call helpers directly without handler cleanup
    /// racing the registry.
    async fn new_without_handler(repair_rate: u16) -> Self {
        Self::new_inner(
            repair_rate,
            tinect::policy::TransitPolicy::new(false, HashMap::new()),
            false,
        )
        .await
    }

    async fn new_inner(
        repair_rate: u16,
        transit: tinect::policy::TransitPolicy,
        spawn_handler: bool,
    ) -> Self {
        crate::daemon::test_support::backdate_monotonic_epoch();
        let client_key = identity::generate();
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
        let client_identity = identity::node_id(&client_key.verifying_key());
        let server_identity = identity::node_id(&server_key.verifying_key());

        let mut config = crate::daemon::test_support::minimal_config();
        config.id = "server".into();
        config.peers.insert(
            "client".into(),
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
        );
        let runtime = Runtime::new(config).unwrap();
        runtime
            .links
            .lock()
            .expect("link registry lock")
            .insert("client".into(), server_link.clone());
        let router = Arc::new(Router::new(
            server_identity.clone(),
            transit,
            runtime.links.clone(),
        ));
        let supervisor = tinect::runtime::DaemonSupervisor::default();
        if spawn_handler {
            spawn_control_handler(
                server_link.clone(),
                ControlHandlerContext {
                    router: router.clone(),
                    runtime: runtime.clone(),
                    identity: Arc::new(server_key.clone()),
                    supervisor: supervisor.clone(),
                },
            );
        }

        Self {
            client_key,
            server_key,
            client_identity,
            server_identity,
            client_link,
            server_link,
            client_endpoint,
            runtime,
            supervisor,
            router,
        }
    }

    async fn recv_client_control(&self) -> ControlMessage {
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap()
    }

    async fn acknowledge_initial_snapshot(&self) {
        let initial = self.recv_client_control().await;
        let ControlMessage::TopologySync { sync_id, .. } = initial else {
            panic!("expected initial topology snapshot");
        };
        self.client_link
            .send_control(&ControlMessage::TopologySyncAck { sync_id })
            .await
            .unwrap();
    }

    async fn assert_no_client_control(&self) {
        match tokio::time::timeout(
            std::time::Duration::from_millis(200),
            self.client_link.recv_control(),
        )
        .await
        {
            Err(_) => {}
            Ok(Ok(message)) => panic!("unexpected control message: {message:?}"),
            Ok(Err(error)) => panic!("unexpected control stream closure: {error}"),
        }
    }

    async fn client_status(&self) -> crate::status::LinkStatus {
        self.runtime
            .state
            .read()
            .await
            .status
            .links
            .iter()
            .find(|link| link.peer == "client")
            .cloned()
            .expect("client status entry")
    }

    /// Waits until the handler cleanup has removed the client Link from
    /// the registry, which is the deterministic signal that the handler
    /// loop exited and unwound its per-Link state.
    async fn wait_until_client_unregistered(&self, timeout: std::time::Duration) {
        tokio::time::timeout(timeout, async {
            loop {
                if self
                    .runtime
                    .links
                    .lock()
                    .expect("link registry lock")
                    .get("client")
                    .is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("client link removed from registry");
    }

    async fn shutdown(self) {
        self.client_link.close("control handler harness complete");
        self.server_link.close("control handler harness complete");
        self.client_endpoint
            .close(0u32.into(), b"control handler harness complete");
        self.supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }
}

fn corrupt_signature(signature: &mut String) {
    let replacement = if signature.starts_with('A') { "B" } else { "A" };
    signature.replace_range(..1, replacement);
}

struct ControlTestLink {
    outcomes: Mutex<Vec<Result<(), LinkError>>>,
    messages: Mutex<Vec<ControlMessage>>,
}

impl ControlTestLink {
    fn new(outcomes: impl IntoIterator<Item = Result<(), LinkError>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            messages: Mutex::new(Vec::new()),
        }
    }

    fn messages(&self) -> Vec<ControlMessage> {
        self.messages.lock().expect("messages lock").clone()
    }
}

impl LinkHandle for ControlTestLink {
    fn peer_name(&self) -> &str {
        "test-peer"
    }

    fn peer_identity(&self) -> &str {
        "test-identity"
    }

    fn instance(&self) -> u64 {
        7
    }

    fn is_healthy(&self) -> bool {
        true
    }

    fn set_healthy(&self, _healthy: bool) {}

    fn should_log_dataplane_warning(&self) -> bool {
        true
    }

    fn is_closed(&self) -> bool {
        false
    }

    fn send_forward(&self, _frame: &[u8]) -> Result<(), LinkError> {
        Ok(())
    }

    fn send_control<'a>(&'a self, message: &'a ControlMessage) -> LinkFuture<'a> {
        self.messages
            .lock()
            .expect("messages lock")
            .push(message.clone());
        let outcome = self
            .outcomes
            .lock()
            .expect("outcomes lock")
            .first()
            .cloned()
            .unwrap_or(Ok(()));
        if !self.outcomes.lock().expect("outcomes lock").is_empty() {
            let _ = self.outcomes.lock().expect("outcomes lock").remove(0);
        }
        Box::pin(async move { outcome })
    }
}

#[test]
fn snapshot_requests_merge_and_deadlines_are_selected_by_age() {
    assert!(!merge_topology_snapshot_request(false));
    assert!(merge_topology_snapshot_request(true));
    let empty = HashMap::new();
    assert!(next_snapshot_reassembly_deadline(&empty).is_none());

    let now = Instant::now();
    let mut snapshots = HashMap::new();
    snapshots.insert(
        1,
        SnapshotAssembly {
            chunks: vec![None],
            bytes: 0,
            lsa_count: 0,
            neighbors: 0,
            started: now,
        },
    );
    snapshots.insert(
        2,
        SnapshotAssembly {
            chunks: vec![None],
            bytes: 0,
            lsa_count: 0,
            neighbors: 0,
            started: now + std::time::Duration::from_secs(1),
        },
    );
    let deadline = next_snapshot_reassembly_deadline(&snapshots).unwrap();
    assert!(deadline <= now + topology_snapshot_reassembly_timeout());
}

#[test]
fn superseded_snapshot_assemblies_are_removed_immediately() {
    let mut snapshots = HashMap::new();
    let mut superseded = VecDeque::new();
    for sync_id in [11, 12] {
        snapshots.insert(
            sync_id,
            SnapshotAssembly {
                chunks: vec![None],
                bytes: 0,
                lsa_count: 0,
                neighbors: 0,
                started: Instant::now(),
            },
        );
    }

    retain_current_snapshot_assembly(&mut snapshots, &mut superseded, 12);

    assert_eq!(snapshots.len(), 1);
    assert!(snapshots.contains_key(&12));
    assert_eq!(superseded, VecDeque::from([11]));
}

#[test]
fn expired_snapshot_assemblies_are_added_to_superseded_window() {
    let mut snapshots = HashMap::new();
    let mut superseded = VecDeque::new();
    let started = Instant::now()
        .checked_sub(topology_snapshot_reassembly_timeout() + std::time::Duration::from_secs(1))
        .unwrap();
    snapshots.insert(
        13,
        SnapshotAssembly {
            chunks: vec![None],
            bytes: 0,
            lsa_count: 0,
            neighbors: 0,
            started,
        },
    );

    assert!(prune_expired_snapshot_assemblies(
        &mut snapshots,
        &mut superseded,
    ));
    assert!(snapshots.is_empty());
    assert_eq!(superseded, VecDeque::from([13]));
}

#[test]
fn superseded_snapshot_window_deduplicates_and_evicts_old_ids() {
    let mut superseded = VecDeque::new();
    remember_superseded_snapshot(&mut superseded, 1);
    remember_superseded_snapshot(&mut superseded, 1);
    assert_eq!(superseded, VecDeque::from([1]));
    for sync_id in 2..=(RECENT_SUPERSEDED_TOPOLOGY_SNAPSHOTS as u64 + 2) {
        remember_superseded_snapshot(&mut superseded, sync_id);
    }
    assert_eq!(superseded.len(), RECENT_SUPERSEDED_TOPOLOGY_SNAPSHOTS);
    assert!(!superseded.contains(&1));

    let mut snapshots = HashMap::from([
        (
            20,
            SnapshotAssembly {
                chunks: vec![None],
                bytes: 0,
                lsa_count: 0,
                neighbors: 0,
                started: Instant::now(),
            },
        ),
        (
            21,
            SnapshotAssembly {
                chunks: vec![None],
                bytes: 0,
                lsa_count: 0,
                neighbors: 0,
                started: Instant::now(),
            },
        ),
    ]);
    discard_snapshot_assemblies(&mut snapshots, &mut superseded);
    assert!(snapshots.is_empty());
    assert!(superseded.contains(&20));
    assert!(superseded.contains(&21));

    let mut topology_sync = TopologySyncState::new();
    topology_sync.begin_receive(99);
    invalidate_topology_receive(
        &mut topology_sync,
        &mut snapshots,
        &mut superseded,
        Some(99),
    );
    assert_eq!(topology_sync.rx, TopologyRxState::AwaitingInitial);
    assert!(superseded.contains(&99));
}

#[test]
fn local_admission_errors_and_rejection_reasons_are_classified_precisely() {
    assert!(is_local_control_admission(
        &carrier::CarrierError::AdmissionRejected
    ));
    assert!(is_local_control_admission(
        &carrier::CarrierError::ControlStreamTimeout
    ));
    assert!(!is_local_control_admission(
        &carrier::CarrierError::EndpointClosed
    ));
    assert!(is_local_control_admission_rejection(true, "code:11"));
    assert!(!is_local_control_admission_rejection(false, "code:11"));
    assert!(!is_local_control_admission_rejection(true, "code:7"));
}

#[tokio::test]
async fn control_admission_retry_retries_only_local_transient_failures() {
    let link = ControlTestLink::new([
        Err(LinkError::AdmissionRejected),
        Err(LinkError::ControlStreamTimeout),
        Ok(()),
    ]);
    send_control_with_admission_retry(&link, &ControlMessage::Ping)
        .await
        .unwrap();
    let messages = link.messages();
    assert_eq!(messages.len(), 3);
    assert!(
        messages
            .iter()
            .all(|message| matches!(message, ControlMessage::Ping))
    );

    let terminal = ControlTestLink::new([Err(LinkError::WouldBlock)]);
    assert!(matches!(
        send_control_with_admission_retry(&terminal, &ControlMessage::Pong).await,
        Err(carrier::CarrierError::WouldBlock)
    ));
    assert_eq!(terminal.messages().len(), 1);
}

#[tokio::test]
async fn open_reject_helpers_sign_and_send_retryable_rejections() {
    let identity = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let circuit_id = tinect::circuit::CircuitId([3; 16]);
    let link = ControlTestLink::new([Ok(())]);
    send_retryable_open_reject(&link, &identity, circuit_id).await;
    let messages = link.messages();
    let [
        ControlMessage::OpenReject {
            circuit_id: sent_id,
            retryable,
            reason_code,
            public_key,
            signature,
        },
    ] = messages.as_slice()
    else {
        panic!("expected one signed OPEN rejection");
    };
    assert_eq!(*sent_id, circuit_id);
    assert!(*retryable);
    assert_eq!(*reason_code, OPEN_REJECT_REASON_MISSING_NEXT_HOP);
    assert!(!public_key.is_empty());
    assert!(!signature.is_empty());

    let failed = ControlTestLink::new([Err(LinkError::EndpointClosed)]);
    send_open_reject(
        &failed,
        &identity,
        circuit_id,
        false,
        OPEN_REJECT_REASON_GENERIC,
    )
    .await;
    assert_eq!(failed.messages().len(), 1);
}

#[test]
fn registered_link_lookup_handles_empty_registry() {
    let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
    assert!(registered_link_by_instance(&links, 42).is_none());
}

#[tokio::test]
async fn control_handler_processes_exit_lifecycle_and_rejects_invalid_open() {
    let client_key = identity::generate();
    let server_key = identity::generate();
    let server_public = identity::encode_public(&server_key.verifying_key());
    let (server_endpoint, _) = carrier::endpoint_with_options_and_bare(
        tinect::config::CarrierProtocol::QuicFull,
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
        carrier::accept_with_bare(
            &server_endpoint,
            None,
            tinect::config::CarrierProtocol::QuicFull,
            &peers,
            false,
            "server",
            &accept_key,
        )
        .await
        .unwrap()
    });
    let (client_endpoint, _) = carrier::endpoint_with_options_and_bare(
        tinect::config::CarrierProtocol::QuicFull,
        "127.0.0.1:0".parse().unwrap(),
        &tinect::config::LinkHealthConfig::default(),
        None,
        None,
        Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let client_link = Arc::new(
        carrier::connect_with_link_health_and_bare(
            &client_endpoint,
            None,
            server_address,
            tinect::config::CarrierProtocol::QuicFull,
            "server",
            &server_public,
            "client",
            &client_key,
            &tinect::config::LinkHealthConfig::default(),
        )
        .await
        .unwrap(),
    );
    let server_link = Arc::new(server_task.await.unwrap());
    let server_identity = identity::node_id(&server_key.verifying_key());
    let client_identity = identity::node_id(&client_key.verifying_key());

    let runtime = Runtime::new(crate::daemon::test_support::minimal_config()).unwrap();
    runtime
        .links
        .lock()
        .expect("link registry lock")
        .insert("client".into(), server_link.clone());
    let router = Arc::new(Router::new(
        server_identity.clone(),
        tinect::policy::TransitPolicy::new(false, HashMap::new()),
        runtime.links.clone(),
    ));
    let supervisor = tinect::runtime::DaemonSupervisor::default();
    spawn_control_handler(
        server_link.clone(),
        ControlHandlerContext {
            router,
            runtime: runtime.clone(),
            identity: Arc::new(server_key.clone()),
            supervisor: supervisor.clone(),
        },
    );

    let initial_snapshot = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    let ControlMessage::TopologySync { sync_id, .. } = initial_snapshot.clone() else {
        panic!("expected initial topology snapshot");
    };
    client_link
        .send_control(&ControlMessage::TopologySyncAck { sync_id })
        .await
        .unwrap();

    client_link
        .send_control(&ControlMessage::Ping)
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_link.recv_control()
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::Pong
    ));
    client_link
        .send_control(&ControlMessage::Pong)
        .await
        .unwrap();

    // Exercise the inbound reliable-topology direction independently of
    // the initial outbound Snapshot.  A completed Snapshot may be
    // retransmitted after a lost ACK, while a Delta can be applied once
    // the receive direction is synchronized.
    let client_snapshot = tinect::topology::LinkStateAdvertisement::new(
        client_identity.clone(),
        &client_key,
        1,
        crate::daemon::support::unix_now() + 60,
        Vec::new(),
    );
    let snapshot = ControlMessage::TopologySync {
        mode: tinect::control::TopologySyncMode::Snapshot,
        sync_id: 700,
        chunk_index: 0,
        chunk_count: 1,
        advertisements: vec![client_snapshot.clone()],
    };
    client_link.send_control(&snapshot).await.unwrap();
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_link.recv_control()
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::TopologySyncAck { sync_id: 700 }
    ));
    // The duplicate is intentionally accepted as a retransmission and
    // receives another ACK without applying the LSA a second time.
    client_link.send_control(&snapshot).await.unwrap();
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_link.recv_control()
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::TopologySyncAck { sync_id: 700 }
    ));

    client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 702,
            chunk_index: 0,
            chunk_count: 257,
            advertisements: Vec::new(),
        })
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_link.recv_control()
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::TopologySyncRequest { reason: 1 }
    ));

    client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 704,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![client_snapshot.clone()],
        })
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_link.recv_control()
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::TopologySyncAck { sync_id: 704 }
    ));

    let delta = tinect::topology::LinkStateAdvertisement::new(
        client_identity.clone(),
        &client_key,
        2,
        crate::daemon::support::unix_now() + 60,
        vec![tinect::topology::LinkMetric {
            node: server_identity.clone(),
            cost: 1,
            inner_mtu: 1200,
        }],
    );
    client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Delta,
            sync_id: 701,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![delta],
        })
        .await
        .unwrap();

    // A peer may request a fresh outbound Snapshot after losing its
    // baseline.  The request is served without resetting the already
    // synchronized receive direction.
    client_link
        .send_control(&ControlMessage::TopologySyncRequest { reason: 11 })
        .await
        .unwrap();
    let requested_snapshot = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    let ControlMessage::TopologySync {
        sync_id: requested_sync_id,
        ..
    } = requested_snapshot
    else {
        panic!("expected requested topology snapshot");
    };
    client_link
        .send_control(&ControlMessage::TopologySyncAck {
            sync_id: requested_sync_id,
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !server_link.topology_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("requested topology snapshot is acknowledged");

    // Physical control workers share the authenticated Link.  Keepalive
    // is consumed locally, while an opaque Forward frame is handed to
    // the single-consumer dispatcher queue.
    client_link
        .send_physical(tinect::physical::PhysicalPayload::Keepalive)
        .unwrap();

    let circuit_id = tinect::circuit::CircuitId([121; 16]);
    let open = tinect::circuit::OpenRequest::new(
        client_identity.clone(),
        &client_key,
        server_identity.clone(),
        vec![client_identity.clone(), server_identity.clone()],
        circuit_id,
        [122; 32],
    );
    client_link
        .send_control(&ControlMessage::Open(open))
        .await
        .unwrap();
    let open_ack = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(open_ack, ControlMessage::OpenAck { circuit_id: id, .. } if id == circuit_id));

    client_link
        .send_control(&ControlMessage::circuit_renew(&client_key, circuit_id, 1))
        .await
        .unwrap();
    let renew_ack = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(renew_ack, ControlMessage::CircuitRenewAck { circuit_id: id, counter: 1, .. } if id == circuit_id)
    );

    client_link
        .send_control(&ControlMessage::circuit_close(
            &client_key,
            circuit_id,
            1,
            1,
        ))
        .await
        .unwrap();
    client_link
        .send_control(&ControlMessage::circuit_renew(&client_key, circuit_id, 2))
        .await
        .unwrap();
    let broken = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(broken, ControlMessage::CircuitBroken { circuit_id: id, .. } if id == circuit_id)
    );

    let invalid_id = tinect::circuit::CircuitId([123; 16]);
    let mut invalid = tinect::circuit::OpenRequest::new(
        client_identity,
        &client_key,
        server_identity,
        vec![
            identity::node_id(&client_key.verifying_key()),
            identity::node_id(&server_key.verifying_key()),
        ],
        invalid_id,
        [124; 32],
    );
    corrupt_signature(&mut invalid.signature);
    client_link
        .send_control(&ControlMessage::Open(invalid))
        .await
        .unwrap();
    let rejection = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(rejection, ControlMessage::OpenReject { circuit_id: id, retryable: false, .. } if id == invalid_id)
    );

    // Each signed control variant has its own verifier.  Feed malformed
    // messages through the live handler so a forged control frame is
    // ignored without mutating the circuit state or closing the Link.
    let mut invalid_ack = ControlMessage::open_ack(&client_key, invalid_id);
    if let ControlMessage::OpenAck { signature, .. } = &mut invalid_ack {
        corrupt_signature(signature);
    }
    client_link.send_control(&invalid_ack).await.unwrap();

    let mut invalid_reject =
        ControlMessage::open_reject(&client_key, invalid_id, false, OPEN_REJECT_REASON_GENERIC);
    if let ControlMessage::OpenReject { signature, .. } = &mut invalid_reject {
        corrupt_signature(signature);
    }
    client_link.send_control(&invalid_reject).await.unwrap();

    let mut invalid_close = ControlMessage::circuit_close(&client_key, invalid_id, 1, 1);
    if let ControlMessage::CircuitClose { signature, .. } = &mut invalid_close {
        corrupt_signature(signature);
    }
    client_link.send_control(&invalid_close).await.unwrap();

    let mut invalid_renew = ControlMessage::circuit_renew(&client_key, invalid_id, 1);
    if let ControlMessage::CircuitRenew { signature, .. } = &mut invalid_renew {
        corrupt_signature(signature);
    }
    client_link.send_control(&invalid_renew).await.unwrap();

    let mut invalid_broken = ControlMessage::circuit_broken(&client_key, invalid_id, 1);
    if let ControlMessage::CircuitBroken { signature, .. } = &mut invalid_broken {
        corrupt_signature(signature);
    }
    client_link.send_control(&invalid_broken).await.unwrap();

    // Valid feedback for an unknown circuit exercises the stale-waiter
    // paths without altering the live circuit lifecycle above.
    client_link
        .send_control(&ControlMessage::open_ack(&client_key, invalid_id))
        .await
        .unwrap();
    client_link
        .send_control(&ControlMessage::open_reject(
            &client_key,
            invalid_id,
            false,
            OPEN_REJECT_REASON_GENERIC,
        ))
        .await
        .unwrap();
    client_link
        .send_control(&ControlMessage::circuit_renew_ack(
            &client_key,
            invalid_id,
            1,
        ))
        .await
        .unwrap();
    client_link
        .send_control(&ControlMessage::circuit_broken(&client_key, invalid_id, 1))
        .await
        .unwrap();

    client_link.close("control lifecycle test complete");
    server_link.close("control lifecycle test complete");
    client_endpoint.close(0u32.into(), b"control lifecycle test complete");
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn control_handler_resolves_waiters_and_invalidates_broken_source_circuits() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;

    let client_public = identity::encode_public(&harness.client_key.verifying_key());
    let circuit_id = tinect::circuit::CircuitId([41; 16]);

    let ack_waiter = harness
        .runtime
        .circuits
        .opens
        .register(
            harness.server_link.instance(),
            circuit_id,
            client_public.clone(),
            vec![client_public.clone()],
            None,
            harness.server_link.lifecycle_token(),
        )
        .await;
    harness
        .client_link
        .send_control(&ControlMessage::open_ack(&harness.server_key, circuit_id))
        .await
        .unwrap();
    harness
        .client_link
        .send_control(&ControlMessage::open_ack(&harness.client_key, circuit_id))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), ack_waiter)
            .await
            .unwrap()
            .unwrap(),
        dataplane::OpenResult::Acknowledged
    );
    assert!(
        harness
            .runtime
            .circuits
            .opens
            .is_authorized(harness.server_link.instance(), circuit_id)
            .await
    );

    let rejected_id = tinect::circuit::CircuitId([42; 16]);
    let reject_waiter = harness
        .runtime
        .circuits
        .opens
        .register(
            harness.server_link.instance(),
            rejected_id,
            client_public.clone(),
            vec![client_public.clone()],
            None,
            harness.server_link.lifecycle_token(),
        )
        .await;
    harness
        .client_link
        .send_control(&ControlMessage::open_reject(
            &harness.server_key,
            rejected_id,
            true,
            OPEN_REJECT_REASON_GENERIC,
        ))
        .await
        .unwrap();
    harness
        .client_link
        .send_control(&ControlMessage::open_reject(
            &harness.client_key,
            rejected_id,
            true,
            OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION,
        ))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), reject_waiter)
            .await
            .unwrap()
            .unwrap(),
        dataplane::OpenResult::Rejected {
            retryable: true,
            reason: format!("code:{OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION}"),
        }
    );

    let renewal_id = tinect::circuit::CircuitId([43; 16]);
    let renew_waiter = harness
        .runtime
        .circuits
        .opens
        .register(
            harness.server_link.instance(),
            renewal_id,
            client_public,
            vec![identity::encode_public(&harness.client_key.verifying_key())],
            Some(9),
            harness.server_link.lifecycle_token(),
        )
        .await;
    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew_ack(
            &harness.client_key,
            renewal_id,
            8,
        ))
        .await
        .unwrap();
    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew_ack(
            &harness.client_key,
            renewal_id,
            9,
        ))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), renew_waiter)
            .await
            .unwrap()
            .unwrap(),
        dataplane::OpenResult::RenewAcknowledged { counter: 9 }
    );

    let broken_id = tinect::circuit::CircuitId([44; 16]);
    harness
        .runtime
        .circuits
        .opens
        .activate(
            "client".into(),
            broken_id,
            chacha20poly1305::Key::from([7; 32]),
            harness.server_link.instance(),
            (
                vec![
                    harness.server_identity.clone(),
                    harness.client_identity.clone(),
                ],
                1200,
            ),
        )
        .await;
    harness
        .client_link
        .send_control(&ControlMessage::circuit_broken(
            &harness.server_key,
            broken_id,
            tinect::control::CIRCUIT_BROKEN_REASON_RELAY_FAILURE,
        ))
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert!(
        harness
            .runtime
            .circuits
            .opens
            .active_for_destination("client")
            .await
            .is_some()
    );
    harness
        .client_link
        .send_control(&ControlMessage::circuit_broken(
            &harness.client_key,
            broken_id,
            tinect::control::CIRCUIT_BROKEN_REASON_RELAY_FAILURE,
        ))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if harness
                .runtime
                .circuits
                .opens
                .active_for_destination("client")
                .await
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_ignores_stale_renewals_and_tracks_fec_health_transitions() {
    let harness = LiveControlHarness::new(1_000).await;
    harness.acknowledge_initial_snapshot().await;

    harness.server_link.set_healthy(true);
    mark_link(&harness.runtime.state, "client", true, None).await;
    let initial_status = harness.client_status().await;
    assert!(initial_status.healthy);
    assert!(harness.server_link.fec_enabled());
    assert!(harness.server_link.is_healthy());

    let circuit_id = tinect::circuit::CircuitId([45; 16]);
    let open = tinect::circuit::OpenRequest::new(
        harness.client_identity.clone(),
        &harness.client_key,
        harness.server_identity.clone(),
        vec![
            harness.client_identity.clone(),
            harness.server_identity.clone(),
        ],
        circuit_id,
        [46; 32],
    );
    harness
        .client_link
        .send_control(&ControlMessage::Open(open))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::OpenAck { circuit_id: id, .. } if id == circuit_id
    ));

    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew(
            &harness.client_key,
            circuit_id,
            3,
        ))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::CircuitRenewAck {
            circuit_id: id,
            counter: 3,
            ..
        } if id == circuit_id
    ));

    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew(
            &harness.client_key,
            circuit_id,
            2,
        ))
        .await
        .unwrap();
    harness.assert_no_client_control().await;

    let saturated_report = |report_id| {
        ControlMessage::FecReport(tinect::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm: 1_000_000,
            burst_milli: 1_000,
        })
    };
    for report_id in 1..=3 {
        harness
            .client_link
            .send_control(&saturated_report(report_id))
            .await
            .unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let status = harness.client_status().await;
            if !status.healthy
                && status.last_error.as_deref() == Some("FEC data-plane loss threshold reached")
                && !harness.server_link.is_healthy()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let valid_report = |report_id| {
        ControlMessage::FecReport(tinect::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm: 100_000,
            burst_milli: 1_000,
        })
    };
    for report_id in 4..=5 {
        harness
            .client_link
            .send_control(&valid_report(report_id))
            .await
            .unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let status = harness.client_status().await;
            if status.healthy && status.last_error.is_none() && harness.server_link.is_healthy() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    harness
        .client_link
        .send_control(&ControlMessage::circuit_close(
            &harness.client_key,
            circuit_id,
            1,
            1,
        ))
        .await
        .unwrap();
    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew(
            &harness.client_key,
            circuit_id,
            4,
        ))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::CircuitBroken {
            circuit_id: id,
            reason_code,
            ..
        } if id == circuit_id
            && reason_code == tinect::control::CIRCUIT_RENEW_REJECTED_REASON
    ));

    harness.shutdown().await;
}

fn test_lsa(
    origin: &str,
    key: &ed25519_dalek::SigningKey,
    sequence: u64,
) -> tinect::topology::LinkStateAdvertisement {
    tinect::topology::LinkStateAdvertisement::new(
        origin,
        key,
        sequence,
        crate::daemon::support::unix_now() + 60,
        Vec::new(),
    )
}

async fn recv_control_with_timeout(link: &Arc<carrier::Link>) -> ControlMessage {
    tokio::time::timeout(std::time::Duration::from_secs(2), link.recv_control())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn control_handler_ignores_stale_topology_snapshot_acks() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // No Snapshot is pending; an ACK for an unknown sync id is dropped.
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncAck { sync_id: 9_999 })
        .await
        .unwrap();
    harness.assert_no_client_control().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_requests_recovery_when_delta_precedes_snapshot() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let delta = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Delta,
            sync_id: 701,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![delta],
        })
        .await
        .unwrap();
    // The receive direction is not synchronized yet, so the Delta is
    // rejected and the peer is asked for a fresh Snapshot.
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncRequest { reason: 8 }
    ));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_invalidates_assembly_on_chunk_count_mismatch() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    let chunk = |index: u16, count: u16| ControlMessage::TopologySync {
        mode: tinect::control::TopologySyncMode::Snapshot,
        sync_id: 900,
        chunk_index: index,
        chunk_count: count,
        advertisements: vec![lsa.clone()],
    };
    harness
        .client_link
        .send_control(&chunk(0, 2))
        .await
        .unwrap();
    // A later chunk announces a different chunk_count for the same
    // transfer: the assembly is invalidated and recovery requested.
    harness
        .client_link
        .send_control(&chunk(1, 3))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncRequest { reason: 2 }
    ));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_requests_recovery_when_snapshot_apply_is_rejected() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // An LSA listing itself as a neighbor is rejected by snapshot apply.
    let self_neighbor = tinect::topology::LinkStateAdvertisement::new(
        harness.client_identity.clone(),
        &harness.client_key,
        1,
        crate::daemon::support::unix_now() + 60,
        vec![tinect::topology::LinkMetric {
            node: harness.client_identity.clone(),
            cost: 1,
            inner_mtu: 1200,
        }],
    );
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 910,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![self_neighbor],
        })
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncRequest { reason: 3 }
    ));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_prunes_oversized_snapshot_assemblies() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    // ~500 encoded LSAs fill one bounded control message; 70 chunks push
    // the accumulated byte budget past MAX_TOPOLOGY_SNAPSHOT_BYTES and the
    // transfer is invalidated with a recovery request.
    for index in 0..70u16 {
        harness
            .client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: 920,
                chunk_index: index,
                chunk_count: 70,
                advertisements: vec![lsa.clone(); 500],
            })
            .await
            .unwrap();
    }
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncRequest { reason: 6 }
    ));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_evicts_old_completed_snapshot_ids() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    for sync_id in 1_000..=1_000 + RECENT_COMPLETED_TOPOLOGY_SNAPSHOTS as u64 {
        harness
            .client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: vec![lsa.clone()],
            })
            .await
            .unwrap();
        assert!(matches!(
            harness.recv_client_control().await,
            ControlMessage::TopologySyncAck { sync_id: acked } if acked == sync_id
        ));
    }
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_closes_link_when_recovery_budget_exhausted_by_request() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    for _ in 0..2 {
        harness
            .client_link
            .send_control(&ControlMessage::TopologySyncRequest { reason: 1 })
            .await
            .unwrap();
        let snapshot = harness.recv_client_control().await;
        let ControlMessage::TopologySync { sync_id, .. } = snapshot else {
            panic!("expected requested topology snapshot");
        };
        harness
            .client_link
            .send_control(&ControlMessage::TopologySyncAck { sync_id })
            .await
            .unwrap();
    }
    // The third request arrives after the recovery budget is exhausted:
    // the handler closes the Link instead of sending another Snapshot.
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncRequest { reason: 1 })
        .await
        .unwrap();
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_cleans_up_registry_when_link_closes_during_assembly() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    // Start a partial inbound assembly so the handler waits in the
    // reassembly-deadline branch, then close the Link from the peer side.
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 930,
            chunk_index: 0,
            chunk_count: 2,
            advertisements: vec![lsa],
        })
        .await
        .unwrap();
    // Give the handler one loopback round trip to enter the
    // reassembly-deadline select before the Link closes, so the stream
    // error is observed in that branch deterministically.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    harness.client_link.close("control handler cleanup test");
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_closes_link_when_initial_snapshot_send_fails() {
    let harness = LiveControlHarness::new_without_handler(0).await;
    harness
        .server_link
        .close("initial snapshot send failure test");
    spawn(
        harness.server_link.clone(),
        ControlHandlerContext {
            router: harness.router.clone(),
            runtime: harness.runtime.clone(),
            identity: Arc::new(harness.server_key.clone()),
            supervisor: harness.supervisor.clone(),
        },
    );
    // The failed initial Snapshot send closes the Link and the handler
    // cleanup unregisters it.
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn notify_broken_logs_when_link_send_fails() {
    let harness = LiveControlHarness::new_without_handler(0).await;
    let circuit_id = tinect::circuit::CircuitId([77; 16]);
    let instance = harness.server_link.instance();
    harness.server_link.close("notify broken delivery test");
    notify_broken(
        &harness.runtime.links,
        &harness.server_key,
        vec![(instance, circuit_id)],
    )
    .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn wait_for_any_link_returns_registered_link_or_times_out() {
    let harness = LiveControlHarness::new_without_handler(0).await;
    let opens = harness.runtime.circuits.opens.clone();
    let found = wait_for_any_link(
        &harness.runtime.links,
        &opens,
        std::time::Duration::from_millis(50),
    )
    .await
    .expect("registered link is returned immediately");
    assert_eq!(found.instance(), harness.server_link.instance());

    let empty: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
    assert!(
        wait_for_any_link(&empty, &opens, std::time::Duration::ZERO)
            .await
            .is_none()
    );
    assert!(
        wait_for_any_link(&empty, &opens, std::time::Duration::from_millis(100))
            .await
            .is_none()
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_ignores_invalid_renew_acknowledgements() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let circuit_id = tinect::circuit::CircuitId([151; 16]);
    let mut invalid = ControlMessage::circuit_renew_ack(&harness.client_key, circuit_id, 1);
    if let ControlMessage::CircuitRenewAck { signature, .. } = &mut invalid {
        corrupt_signature(signature);
    }
    harness.client_link.send_control(&invalid).await.unwrap();
    // A valid acknowledgement for an unknown circuit is also ignored.
    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew_ack(
            &harness.client_key,
            circuit_id,
            1,
        ))
        .await
        .unwrap();
    harness.assert_no_client_control().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_forwards_accepted_topology_deltas() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // Synchronize the receive direction with a complete Snapshot.
    let baseline = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 800,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![baseline.clone()],
        })
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncAck { sync_id: 800 }
    ));
    // A newer LSA that adds a neighbor is accepted as a Delta and fans
    // out to the control plane.
    let delta = tinect::topology::LinkStateAdvertisement::new(
        harness.client_identity.clone(),
        &harness.client_key,
        2,
        crate::daemon::support::unix_now() + 60,
        vec![tinect::topology::LinkMetric {
            node: harness.server_identity.clone(),
            cost: 1,
            inner_mtu: 1200,
        }],
    );
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Delta,
            sync_id: 801,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![delta],
        })
        .await
        .unwrap();
    harness.assert_no_client_control().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_ignores_superseded_and_stale_snapshot_chunks() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let lsa_a = test_lsa(&harness.client_identity, &harness.client_key, 1);
    // Start a two-chunk transfer, then let a newer single-chunk Snapshot
    // replace it: the old assembly is invalidated and superseded.
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 900,
            chunk_index: 0,
            chunk_count: 2,
            advertisements: vec![lsa_a.clone()],
        })
        .await
        .unwrap();
    let lsa_b = test_lsa(&harness.client_identity, &harness.client_key, 2);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 901,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![lsa_b],
        })
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncAck { sync_id: 901 }
    ));
    // The late chunk of the superseded transfer is ignored...
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 900,
            chunk_index: 1,
            chunk_count: 2,
            advertisements: vec![lsa_a.clone()],
        })
        .await
        .unwrap();
    // ...and so is a Snapshot older than the applied watermark.
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 899,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![lsa_a],
        })
        .await
        .unwrap();
    harness.assert_no_client_control().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_rejects_conflicting_duplicate_snapshot_chunks() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let first = test_lsa(&harness.client_identity, &harness.client_key, 1);
    let chunk = |advertisements: Vec<_>| ControlMessage::TopologySync {
        mode: tinect::control::TopologySyncMode::Snapshot,
        sync_id: 905,
        chunk_index: 0,
        chunk_count: 2,
        advertisements,
    };
    harness
        .client_link
        .send_control(&chunk(vec![first.clone()]))
        .await
        .unwrap();
    // An identical duplicate chunk is harmless.
    harness
        .client_link
        .send_control(&chunk(vec![first.clone()]))
        .await
        .unwrap();
    // A conflicting duplicate restarts recovery for the transfer.
    let second = test_lsa(&harness.client_identity, &harness.client_key, 2);
    harness
        .client_link
        .send_control(&chunk(vec![second]))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncRequest { reason: 2 }
    ));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_merges_snapshot_request_while_pending() {
    let harness = LiveControlHarness::new(0).await;
    // Read but do not acknowledge the initial Snapshot: a recovery
    // Request arriving while it is pending is merged instead of starting
    // a second transfer.
    let initial = harness.recv_client_control().await;
    let ControlMessage::TopologySync { sync_id, .. } = initial else {
        panic!("expected initial topology snapshot");
    };
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncRequest { reason: 1 })
        .await
        .unwrap();
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncAck { sync_id })
        .await
        .unwrap();
    harness.assert_no_client_control().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_ignores_forged_signed_messages() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let circuit_id = tinect::circuit::CircuitId([161; 16]);
    let mut forged_ack = ControlMessage::open_ack(&harness.client_key, circuit_id);
    if let ControlMessage::OpenAck { signature, .. } = &mut forged_ack {
        corrupt_signature(signature);
    }
    harness.client_link.send_control(&forged_ack).await.unwrap();
    let mut forged_reject = ControlMessage::open_reject(
        &harness.client_key,
        circuit_id,
        false,
        OPEN_REJECT_REASON_GENERIC,
    );
    if let ControlMessage::OpenReject { signature, .. } = &mut forged_reject {
        corrupt_signature(signature);
    }
    harness
        .client_link
        .send_control(&forged_reject)
        .await
        .unwrap();
    let mut forged_close = ControlMessage::circuit_close(&harness.client_key, circuit_id, 1, 1);
    if let ControlMessage::CircuitClose { signature, .. } = &mut forged_close {
        corrupt_signature(signature);
    }
    harness
        .client_link
        .send_control(&forged_close)
        .await
        .unwrap();
    let mut forged_renew = ControlMessage::circuit_renew(&harness.client_key, circuit_id, 1);
    if let ControlMessage::CircuitRenew { signature, .. } = &mut forged_renew {
        corrupt_signature(signature);
    }
    harness
        .client_link
        .send_control(&forged_renew)
        .await
        .unwrap();
    let mut forged_broken = ControlMessage::circuit_broken(&harness.client_key, circuit_id, 1);
    if let ControlMessage::CircuitBroken { signature, .. } = &mut forged_broken {
        corrupt_signature(signature);
    }
    harness
        .client_link
        .send_control(&forged_broken)
        .await
        .unwrap();
    // A valid circuit-broken notification for an unknown circuit is also
    // ignored by the stale-waiter path.
    harness
        .client_link
        .send_control(&ControlMessage::circuit_broken(
            &harness.client_key,
            circuit_id,
            1,
        ))
        .await
        .unwrap();
    harness.assert_no_client_control().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_rejects_relay_open_when_forward_label_table_is_full() {
    let harness = LiveControlHarness::new_with_transit(
        0,
        tinect::policy::TransitPolicy::new(true, HashMap::new()),
    )
    .await;
    harness.acknowledge_initial_snapshot().await;
    harness
        .router
        .set_relay_permissions(HashMap::from([(harness.client_identity.clone(), true)]))
        .await;
    // Fill the incoming Link's relay label table to capacity so the
    // post-OPEN forward label install fails.
    let labels = harness
        .router
        .relay_labels_for(harness.server_link.instance());
    for index in 0..4096u32 {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        labels
            .write()
            .expect("relay label lock")
            .install(
                tinect::circuit::CircuitId(bytes),
                harness.client_link.clone(),
            )
            .expect("label table fill");
    }
    let circuit_id = tinect::circuit::CircuitId([171; 16]);
    let open = tinect::circuit::OpenRequest::new(
        harness.client_identity.clone(),
        &harness.client_key,
        harness.client_identity.clone(),
        vec![
            harness.client_identity.clone(),
            harness.server_identity.clone(),
            harness.client_identity.clone(),
        ],
        circuit_id,
        [172; 32],
    );
    harness
        .client_link
        .send_control(&ControlMessage::Open(open))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::OpenReject { circuit_id: id, retryable: true, .. } if id == circuit_id
    ));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_relays_circuit_lifecycle_messages_back_to_source() {
    let harness = LiveControlHarness::new_with_transit(
        0,
        tinect::policy::TransitPolicy::new(true, HashMap::new()),
    )
    .await;
    harness.acknowledge_initial_snapshot().await;
    harness
        .router
        .set_relay_permissions(HashMap::from([(harness.client_identity.clone(), true)]))
        .await;

    // A three-hop OPEN whose next hop is the source itself exercises the
    // relay binding and forwarding path on the loopback pair.
    let open_circuit = |circuit_id: tinect::circuit::CircuitId, seed: u8| {
        tinect::circuit::OpenRequest::new(
            harness.client_identity.clone(),
            &harness.client_key,
            harness.client_identity.clone(),
            vec![
                harness.client_identity.clone(),
                harness.server_identity.clone(),
                harness.client_identity.clone(),
            ],
            circuit_id,
            [seed; 32],
        )
    };

    let x1 = tinect::circuit::CircuitId([131; 16]);
    harness
        .client_link
        .send_control(&ControlMessage::Open(open_circuit(x1, 132)))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::Open { .. }
    ));

    // OPEN acknowledgement is relayed back through the reverse label.
    harness
        .client_link
        .send_control(&ControlMessage::open_ack(&harness.client_key, x1))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::OpenAck { circuit_id, .. } if circuit_id == x1
    ));

    // Renewal is forwarded to the next hop and its acknowledgement is
    // relayed back.
    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew(&harness.client_key, x1, 1))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::CircuitRenew { circuit_id, .. } if circuit_id == x1
    ));
    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew_ack(
            &harness.client_key,
            x1,
            1,
        ))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::CircuitRenewAck { circuit_id, .. } if circuit_id == x1
    ));

    // Authenticated CLOSE is forwarded to the next hop.
    harness
        .client_link
        .send_control(&ControlMessage::circuit_close(
            &harness.client_key,
            x1,
            1,
            1,
        ))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::CircuitClose { circuit_id, .. } if circuit_id == x1
    ));

    // OPEN rejection from the next hop is relayed back and aborts the
    // binding.
    let x2 = tinect::circuit::CircuitId([133; 16]);
    harness
        .client_link
        .send_control(&ControlMessage::Open(open_circuit(x2, 134)))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::Open { .. }
    ));
    harness
        .client_link
        .send_control(&ControlMessage::open_reject(
            &harness.client_key,
            x2,
            true,
            OPEN_REJECT_REASON_GENERIC,
        ))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::OpenReject { circuit_id, .. } if circuit_id == x2
    ));

    // A circuit-broken notification signed by the first hop is relayed
    // back to the source and the binding is aborted.
    let x3 = tinect::circuit::CircuitId([135; 16]);
    harness
        .client_link
        .send_control(&ControlMessage::Open(open_circuit(x3, 136)))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::Open { .. }
    ));
    harness
        .client_link
        .send_control(&ControlMessage::circuit_broken(
            &harness.client_key,
            x3,
            tinect::control::CIRCUIT_BROKEN_REASON_RELAY_FAILURE,
        ))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::CircuitBroken { circuit_id, .. } if circuit_id == x3
    ));

    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_rejects_relay_open_with_missing_next_hop() {
    let harness = LiveControlHarness::new_with_transit(
        0,
        tinect::policy::TransitPolicy::new(true, HashMap::new()),
    )
    .await;
    harness.acknowledge_initial_snapshot().await;
    harness
        .router
        .set_relay_permissions(HashMap::from([(harness.client_identity.clone(), true)]))
        .await;
    let ghost = "ab".repeat(16);
    let circuit_id = tinect::circuit::CircuitId([81; 16]);
    let open = tinect::circuit::OpenRequest::new(
        harness.client_identity.clone(),
        &harness.client_key,
        ghost.clone(),
        vec![
            harness.client_identity.clone(),
            harness.server_identity.clone(),
            ghost,
        ],
        circuit_id,
        [82; 32],
    );
    harness
        .client_link
        .send_control(&ControlMessage::Open(open))
        .await
        .unwrap();
    // The missing next hop produces a retryable rejection.
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::OpenReject {
            circuit_id: id,
            retryable: true,
            reason_code: OPEN_REJECT_REASON_MISSING_NEXT_HOP,
            ..
        } if id == circuit_id
    ));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_rejects_relay_lifecycle_when_outgoing_link_is_dead() {
    crate::daemon::test_support::backdate_monotonic_epoch();
    let client_key = identity::generate();
    let server_key = identity::generate();
    let downstream_key = identity::generate();
    let client_identity = identity::node_id(&client_key.verifying_key());
    let server_identity = identity::node_id(&server_key.verifying_key());
    let downstream_identity = identity::node_id(&downstream_key.verifying_key());
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
    let server_endpoint = Arc::new(server_endpoint);
    let peer = |name: &str, key: &ed25519_dalek::SigningKey| {
        (
            name.to_owned(),
            tinect::config::Peer {
                public_key: identity::encode_public(&key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: Vec::new(),
            },
        )
    };
    let peers = std::collections::BTreeMap::from([
        peer("client", &client_key),
        peer("downstream", &downstream_key),
    ]);
    let accept_client = tokio::spawn({
        let peers = peers.clone();
        let key = server_key.clone();
        let endpoint = server_endpoint.clone();
        let bare = server_bare.clone();
        async move {
            carrier::accept_with_bare_and_fec(
                &endpoint,
                bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &key,
                0,
            )
            .await
            .unwrap()
        }
    });
    let accept_downstream = tokio::spawn({
        let peers = peers.clone();
        let key = server_key.clone();
        let endpoint = server_endpoint.clone();
        let bare = server_bare.clone();
        async move {
            carrier::accept_with_bare_and_fec(
                &endpoint,
                bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &key,
                0,
            )
            .await
            .unwrap()
        }
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
            0,
        )
        .await
        .unwrap(),
    );
    let (downstream_endpoint, downstream_bare) = carrier::endpoint_with_options_and_bare(
        tinect::config::CarrierProtocol::Quic,
        "127.0.0.1:0".parse().unwrap(),
        &tinect::config::LinkHealthConfig::default(),
        None,
        None,
        Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let downstream_link = Arc::new(
        carrier::connect_with_link_health_and_bare_and_fec(
            &downstream_endpoint,
            downstream_bare.as_ref(),
            server_address,
            tinect::config::CarrierProtocol::Quic,
            "server",
            &server_public,
            "downstream",
            &downstream_key,
            &tinect::config::LinkHealthConfig::default(),
            0,
        )
        .await
        .unwrap(),
    );
    let first_accept = Arc::new(accept_client.await.unwrap());
    let second_accept = Arc::new(accept_downstream.await.unwrap());
    let (server_client_link, server_downstream_link) =
        if first_accept.peer_identity == client_identity {
            (first_accept, second_accept)
        } else {
            (second_accept, first_accept)
        };

    let mut config = crate::daemon::test_support::minimal_config();
    config.id = "server".into();
    config
        .peers
        .insert("client".into(), peer("client", &client_key).1);
    config
        .peers
        .insert("downstream".into(), peer("downstream", &downstream_key).1);
    let runtime = Runtime::new(config).unwrap();
    {
        let mut registered = runtime.links.lock().expect("link registry lock");
        registered.insert("client".into(), server_client_link.clone());
        registered.insert("downstream".into(), server_downstream_link.clone());
    }
    let router = Arc::new(Router::new(
        server_identity.clone(),
        tinect::policy::TransitPolicy::new(
            false,
            HashMap::from([(client_identity.clone(), Some(true))]),
        ),
        runtime.links.clone(),
    ));
    router
        .set_relay_permissions(HashMap::from([(client_identity.clone(), true)]))
        .await;
    let supervisor = tinect::runtime::DaemonSupervisor::default();
    spawn_control_handler(
        server_client_link.clone(),
        ControlHandlerContext {
            router: router.clone(),
            runtime: runtime.clone(),
            identity: Arc::new(server_key.clone()),
            supervisor: supervisor.clone(),
        },
    );

    let initial = recv_control_with_timeout(&client_link).await;
    let ControlMessage::TopologySync { sync_id, .. } = initial else {
        panic!("expected initial topology snapshot");
    };
    client_link
        .send_control(&ControlMessage::TopologySyncAck { sync_id })
        .await
        .unwrap();

    let open = |circuit_id: tinect::circuit::CircuitId, seed: u8| {
        tinect::circuit::OpenRequest::new(
            client_identity.clone(),
            &client_key,
            downstream_identity.clone(),
            vec![
                client_identity.clone(),
                server_identity.clone(),
                downstream_identity.clone(),
            ],
            circuit_id,
            [seed; 32],
        )
    };
    let x1 = tinect::circuit::CircuitId([141; 16]);
    let x2 = tinect::circuit::CircuitId([142; 16]);
    let x3 = tinect::circuit::CircuitId([143; 16]);
    // Fill the downstream Link's reverse label table so the reverse
    // install of a relayed OPEN fails after the forward install.
    let downstream_labels = router.relay_labels_for(server_downstream_link.instance());
    for index in 0..4096u32 {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        downstream_labels
            .write()
            .expect("relay label lock")
            .install(
                tinect::circuit::CircuitId(bytes),
                server_client_link.clone(),
            )
            .expect("reverse label table fill");
    }
    client_link
        .send_control(&ControlMessage::Open(open(x1, 144)))
        .await
        .unwrap();
    assert!(matches!(
        recv_control_with_timeout(&client_link).await,
        ControlMessage::OpenReject { circuit_id, .. } if circuit_id == x1
    ));
    // Drop the full table so the remaining OPENs install normally.
    router.remove_relay_labels(server_downstream_link.instance());
    client_link
        .send_control(&ControlMessage::Open(open(x2, 145)))
        .await
        .unwrap();
    assert!(matches!(
        recv_control_with_timeout(&downstream_link).await,
        ControlMessage::Open { .. }
    ));
    client_link
        .send_control(&ControlMessage::Open(open(x3, 146)))
        .await
        .unwrap();
    assert!(matches!(
        recv_control_with_timeout(&downstream_link).await,
        ControlMessage::Open { .. }
    ));

    // The downstream Link dies but stays registered; the relay bindings
    // still point at it so lifecycle forwards fail deterministically.
    downstream_link.close("dead downstream relay test");
    downstream_endpoint.close(0u32.into(), b"dead downstream relay test");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if server_downstream_link.close_reason().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server observes downstream close");

    // Authenticated CLOSE cannot be forwarded to the dead next hop.
    client_link
        .send_control(&ControlMessage::circuit_close(&client_key, x2, 1, 1))
        .await
        .unwrap();

    // RENEW relay failure aborts the binding and sends a circuit-broken
    // notification toward the previous hop.
    client_link
        .send_control(&ControlMessage::circuit_renew(&client_key, x3, 1))
        .await
        .unwrap();

    // A fresh OPEN whose next hop is dead is rejected as retryable.
    let x4 = tinect::circuit::CircuitId([147; 16]);
    client_link
        .send_control(&ControlMessage::Open(open(x4, 148)))
        .await
        .unwrap();
    assert!(matches!(
        recv_control_with_timeout(&client_link).await,
        ControlMessage::OpenReject {
            circuit_id,
            retryable: true,
            reason_code: OPEN_REJECT_REASON_MISSING_NEXT_HOP,
            ..
        } if circuit_id == x4
    ));

    client_link.close("relay rejection test complete");
    server_client_link.close("relay rejection test complete");
    server_downstream_link.close("relay rejection test complete");
    client_endpoint.close(0u32.into(), b"relay rejection test complete");
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn control_handler_resent_snapshot_after_ack_timeout_and_prunes_expired_assembly() {
    let harness = LiveControlHarness::new(0).await;
    // Read but do NOT acknowledge the initial Snapshot, so the handler's
    // pending Snapshot times out and the recovery path resends it.
    let initial = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        harness.client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    let ControlMessage::TopologySync {
        sync_id: initial_id,
        ..
    } = initial
    else {
        panic!("expected initial topology snapshot");
    };
    // Start a partial inbound assembly while the outbound Snapshot is
    // still pending; its reassembly deadline expires right after the
    // outbound recovery resend.
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 940,
            chunk_index: 0,
            chunk_count: 2,
            advertisements: vec![lsa],
        })
        .await
        .unwrap();
    // The ACK timeout triggers a recovery resend of the current topology
    // snapshot with a fresh sync id.
    let resent = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        harness.client_link.recv_control(),
    )
    .await
    .unwrap()
    .unwrap();
    let ControlMessage::TopologySync {
        sync_id: resent_id,
        mode: tinect::control::TopologySyncMode::Snapshot,
        ..
    } = resent
    else {
        panic!("expected recovery topology snapshot resend");
    };
    assert_ne!(resent_id, initial_id);
    // The expired inbound assembly is pruned and a recovery request is
    // sent once its reassembly deadline passes.
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            harness.client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::TopologySyncRequest { reason: 7 }
    ));
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncAck { sync_id: resent_id })
        .await
        .unwrap();
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_closes_link_when_ack_recovery_budget_is_exhausted() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // One acknowledged recovery request, then a second request whose
    // Snapshot is never acknowledged: its ACK timeout hits the exhausted
    // recovery budget and closes the Link.
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncRequest { reason: 1 })
        .await
        .unwrap();
    let snapshot = harness.recv_client_control().await;
    let ControlMessage::TopologySync { sync_id, .. } = snapshot else {
        panic!("expected requested topology snapshot");
    };
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncAck { sync_id })
        .await
        .unwrap();
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncRequest { reason: 1 })
        .await
        .unwrap();
    let snapshot = harness.recv_client_control().await;
    let ControlMessage::TopologySync { .. } = snapshot else {
        panic!("expected second topology snapshot");
    };
    // Never acknowledged: the ACK timeout hits the exhausted recovery
    // budget and closes the Link.
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(15))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_prunes_expired_assembly_without_pending_snapshot() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 950,
            chunk_index: 0,
            chunk_count: 2,
            advertisements: vec![lsa],
        })
        .await
        .unwrap();
    // The reassembly deadline expires with no outbound Snapshot pending;
    // the assembly is pruned and a recovery request is sent.
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            harness.client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap(),
        ControlMessage::TopologySyncRequest { reason: 7 }
    ));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_admission_retry_surfaces_error_after_exhausting_attempts() {
    let link = ControlTestLink::new([
        Err(LinkError::AdmissionRejected),
        Err(LinkError::ControlStreamTimeout),
        Err(LinkError::AdmissionRejected),
    ]);
    assert!(matches!(
        send_control_with_admission_retry(&link, &ControlMessage::Ping).await,
        Err(carrier::CarrierError::AdmissionRejected)
    ));
    assert_eq!(link.messages().len(), CONTROL_ADMISSION_RETRY_ATTEMPTS);
}

#[tokio::test]
async fn wait_for_any_link_wakes_when_a_link_registers() {
    let harness = LiveControlHarness::new_without_handler(0).await;
    let opens = harness.runtime.circuits.opens.clone();
    let registry: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let registering = tokio::spawn({
        let registry = registry.clone();
        let opens = opens.clone();
        let link = harness.server_link.clone();
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            registry
                .lock()
                .expect("link registry lock")
                .insert("client".into(), link);
            opens.request_reconcile();
        }
    });
    let found = wait_for_any_link(&registry, &opens, std::time::Duration::from_secs(5))
        .await
        .expect("link registration wakes the waiter");
    assert_eq!(found.instance(), harness.server_link.instance());
    registering.await.unwrap();
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_unwinds_when_stream_closes_with_pending_snapshot() {
    let harness = LiveControlHarness::new(0).await;
    // Read but never acknowledge the initial Snapshot, so the handler is
    // parked in the pending-Snapshot recv branch when the stream fails.
    let initial = harness.recv_client_control().await;
    assert!(matches!(initial, ControlMessage::TopologySync { .. }));
    harness.client_link.close("pending snapshot close test");
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_flushes_queued_topology_deltas_once_ready() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // Synchronize the inbound direction so the Link is fully ready.
    let baseline = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 960,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![baseline],
        })
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncAck { sync_id: 960 }
    ));
    // A locally originated LSA queued on the Link is flushed as a Delta
    // at the top of the next handler iteration.  The Ping only exists to
    // wake that iteration; Delta and Pong travel on independent streams,
    // so their arrival order is not asserted.
    let local = test_lsa(&harness.server_identity, &harness.server_key, 2);
    assert!(harness.server_link.queue_topology_deltas(vec![local]).await);
    harness
        .client_link
        .send_control(&ControlMessage::Ping)
        .await
        .unwrap();
    let mut flushed_delta = false;
    let mut pong = false;
    for _ in 0..2 {
        match harness.recv_client_control().await {
            ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Delta,
                ..
            } => flushed_delta = true,
            ControlMessage::Pong => pong = true,
            message => panic!("unexpected control message: {message:?}"),
        }
    }
    assert!(flushed_delta && pong);
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_resends_snapshot_after_inbound_recovery() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // A Ping/Pong round trip guarantees the handler has already processed
    // the initial ACK before the outbound direction is invalidated below;
    // otherwise the ACK would re-set the flag after the test clears it.
    harness
        .client_link
        .send_control(&ControlMessage::Ping)
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::Pong
    ));
    // RFC-0016: a fresh inbound Snapshot while our outbound direction is
    // unsynchronized (and no Snapshot is pending) triggers a one-shot
    // outbound resend so the peer can recover toward us too.
    harness.server_link.mark_topology_outbound_unsynchronized();
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 970,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![lsa],
        })
        .await
        .unwrap();
    // The ACK and the resent Snapshot travel on independent streams.
    let mut acknowledged = false;
    let mut resent = None;
    for _ in 0..2 {
        match harness.recv_client_control().await {
            ControlMessage::TopologySyncAck { sync_id: 970 } => acknowledged = true,
            ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id,
                ..
            } => resent = Some(sync_id),
            message => panic!("unexpected control message: {message:?}"),
        }
    }
    assert!(acknowledged);
    let resent = resent.expect("outbound snapshot resent after inbound recovery");
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncAck { sync_id: resent })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !harness.server_link.topology_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("link returns to topology ready after the resend is acknowledged");
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_closes_when_inbound_recovery_resend_exhausts_budget() {
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // Burn the remaining recovery budget with acknowledged requests.
    for _ in 1..MAX_TOPOLOGY_SNAPSHOT_RECOVERY_ATTEMPTS {
        harness
            .client_link
            .send_control(&ControlMessage::TopologySyncRequest { reason: 1 })
            .await
            .unwrap();
        let snapshot = harness.recv_client_control().await;
        let ControlMessage::TopologySync { sync_id, .. } = snapshot else {
            panic!("expected requested topology snapshot");
        };
        harness
            .client_link
            .send_control(&ControlMessage::TopologySyncAck { sync_id })
            .await
            .unwrap();
    }
    // With the budget exhausted, an inbound Snapshot while outbound is
    // unsynchronized closes the Link instead of resending ours.  The
    // Ping/Pong round trip first guarantees the handler processed the
    // last ACK before the test clears the outbound flag.
    harness
        .client_link
        .send_control(&ControlMessage::Ping)
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::Pong
    ));
    harness.server_link.mark_topology_outbound_unsynchronized();
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 980,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![lsa],
        })
        .await
        .unwrap();
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_ignores_fec_health_for_replaced_links_and_unknown_close() {
    let harness = LiveControlHarness::new(1_000).await;
    harness.acknowledge_initial_snapshot().await;
    harness.server_link.set_healthy(true);
    mark_link(&harness.runtime.state, "client", true, None).await;

    // Replace the registry entry with a different Link instance: FEC
    // health transitions from the stale instance must not touch status.
    harness
        .runtime
        .links
        .lock()
        .expect("link registry lock")
        .insert("client".into(), harness.client_link.clone());
    for report_id in 1..=3u64 {
        harness
            .client_link
            .send_control(&ControlMessage::FecReport(tinect::fec::FecReport {
                report_id,
                samples: 128,
                loss_ppm: 1_000_000,
                burst_milli: 1_000,
            }))
            .await
            .unwrap();
    }
    // The Link itself still degrades (proof the reports were processed),
    // but the status entry keeps the replacement's health untouched.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while harness.server_link.is_healthy() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stale link observes FEC degradation");
    let status = harness.client_status().await;
    assert!(status.healthy && status.last_error.is_none());

    // An authenticated CLOSE for an unknown circuit is a no-op.
    harness
        .client_link
        .send_control(&ControlMessage::circuit_close(
            &harness.client_key,
            tinect::circuit::CircuitId([191; 16]),
            1,
            1,
        ))
        .await
        .unwrap();
    harness.assert_no_client_control().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_notifies_broken_circuits_when_relay_outgoing_link_closes() {
    crate::daemon::test_support::backdate_monotonic_epoch();
    let client_key = identity::generate();
    let server_key = identity::generate();
    let downstream_key = identity::generate();
    let client_identity = identity::node_id(&client_key.verifying_key());
    let server_identity = identity::node_id(&server_key.verifying_key());
    let downstream_identity = identity::node_id(&downstream_key.verifying_key());
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
    let server_endpoint = Arc::new(server_endpoint);
    let peer = |name: &str, key: &ed25519_dalek::SigningKey| {
        (
            name.to_owned(),
            tinect::config::Peer {
                public_key: identity::encode_public(&key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: Vec::new(),
            },
        )
    };
    let peers = std::collections::BTreeMap::from([
        peer("client", &client_key),
        peer("downstream", &downstream_key),
    ]);
    let accept_client = tokio::spawn({
        let peers = peers.clone();
        let key = server_key.clone();
        let endpoint = server_endpoint.clone();
        let bare = server_bare.clone();
        async move {
            carrier::accept_with_bare_and_fec(
                &endpoint,
                bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &key,
                0,
            )
            .await
            .unwrap()
        }
    });
    let accept_downstream = tokio::spawn({
        let peers = peers.clone();
        let key = server_key.clone();
        let endpoint = server_endpoint.clone();
        let bare = server_bare.clone();
        async move {
            carrier::accept_with_bare_and_fec(
                &endpoint,
                bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &key,
                0,
            )
            .await
            .unwrap()
        }
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
            0,
        )
        .await
        .unwrap(),
    );
    let (downstream_endpoint, downstream_bare) = carrier::endpoint_with_options_and_bare(
        tinect::config::CarrierProtocol::Quic,
        "127.0.0.1:0".parse().unwrap(),
        &tinect::config::LinkHealthConfig::default(),
        None,
        None,
        Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let downstream_link = Arc::new(
        carrier::connect_with_link_health_and_bare_and_fec(
            &downstream_endpoint,
            downstream_bare.as_ref(),
            server_address,
            tinect::config::CarrierProtocol::Quic,
            "server",
            &server_public,
            "downstream",
            &downstream_key,
            &tinect::config::LinkHealthConfig::default(),
            0,
        )
        .await
        .unwrap(),
    );
    let first_accept = Arc::new(accept_client.await.unwrap());
    let second_accept = Arc::new(accept_downstream.await.unwrap());
    let (server_client_link, server_downstream_link) =
        if first_accept.peer_identity == client_identity {
            (first_accept, second_accept)
        } else {
            (second_accept, first_accept)
        };

    let mut config = crate::daemon::test_support::minimal_config();
    config.id = "server".into();
    config
        .peers
        .insert("client".into(), peer("client", &client_key).1);
    config
        .peers
        .insert("downstream".into(), peer("downstream", &downstream_key).1);
    let runtime = Runtime::new(config).unwrap();
    {
        let mut registered = runtime.links.lock().expect("link registry lock");
        registered.insert("client".into(), server_client_link.clone());
        registered.insert("downstream".into(), server_downstream_link.clone());
    }
    let router = Arc::new(Router::new(
        server_identity.clone(),
        tinect::policy::TransitPolicy::new(
            false,
            HashMap::from([(client_identity.clone(), Some(true))]),
        ),
        runtime.links.clone(),
    ));
    router
        .set_relay_permissions(HashMap::from([(client_identity.clone(), true)]))
        .await;
    let supervisor = tinect::runtime::DaemonSupervisor::default();
    for link in [&server_client_link, &server_downstream_link] {
        spawn_control_handler(
            link.clone(),
            ControlHandlerContext {
                router: router.clone(),
                runtime: runtime.clone(),
                identity: Arc::new(server_key.clone()),
                supervisor: supervisor.clone(),
            },
        );
    }
    for link in [&client_link, &downstream_link] {
        let initial = recv_control_with_timeout(link).await;
        let ControlMessage::TopologySync { sync_id, .. } = initial else {
            panic!("expected initial topology snapshot");
        };
        link.send_control(&ControlMessage::TopologySyncAck { sync_id })
            .await
            .unwrap();
    }

    // Establish a relay binding client -> server -> downstream.
    let circuit_id = tinect::circuit::CircuitId([201; 16]);
    let open = tinect::circuit::OpenRequest::new(
        client_identity.clone(),
        &client_key,
        downstream_identity.clone(),
        vec![
            client_identity.clone(),
            server_identity.clone(),
            downstream_identity.clone(),
        ],
        circuit_id,
        [202; 32],
    );
    client_link
        .send_control(&ControlMessage::Open(open))
        .await
        .unwrap();
    assert!(matches!(
        recv_control_with_timeout(&downstream_link).await,
        ControlMessage::Open { .. }
    ));

    // Closing the outgoing Link unwinds the binding and notifies the
    // source with a circuit-broken feedback (link-closed reason).
    server_downstream_link.close("relay outgoing close test");
    assert!(matches!(
        recv_control_with_timeout(&client_link).await,
        ControlMessage::CircuitBroken {
            circuit_id: id,
            reason_code,
            ..
        } if id == circuit_id
            && reason_code == tinect::control::CIRCUIT_BROKEN_REASON_LINK_CLOSED
    ));

    client_link.close("broken notification test complete");
    server_client_link.close("broken notification test complete");
    client_endpoint.close(0u32.into(), b"broken notification test complete");
    downstream_endpoint.close(0u32.into(), b"broken notification test complete");
    supervisor
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}

/// Evaluate tracing field expressions so structured-logging arguments on
/// covered paths are exercised instead of skipped as disabled callsites.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
}

/// Fill the peer's pre-accept uni-stream backlog (bounded to 41 by the
/// transport config) so the next control send blocks until the peer
/// reads or the connection closes.  Prior streams (for example an
/// already-read initial Snapshot) may still hold credit, so sends are
/// driven until one cannot complete promptly instead of assuming a fixed
/// count; the cancelled probe never reaches the 5s control-stream send
/// timeout that would close the Link.  The final cap fails loudly if the
/// backlog bound ever disappears instead of silently skipping the
/// blocked-send paths under test.
async fn saturate_control_streams(link: &Arc<carrier::Link>) {
    for _ in 0..64 {
        let probed = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            link.send_control(&ControlMessage::Pong),
        )
        .await;
        match probed {
            Ok(result) => result.unwrap(),
            Err(_) => return,
        }
    }
    panic!("control stream backlog accepted more uni streams than its bound");
}

/// Wait until the handler has both inbound and outbound topology flags
/// set, which also proves a pending outbound Snapshot was acknowledged.
async fn wait_until_topology_ready(link: &Arc<carrier::Link>) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !link.topology_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("link reaches topology ready");
}

#[tokio::test]
async fn control_test_link_handle_exposes_static_metadata() {
    let link = ControlTestLink::new([]);
    assert_eq!(link.peer_name(), "test-peer");
    assert_eq!(link.peer_identity(), "test-identity");
    assert_eq!(link.instance(), 7);
    assert!(link.is_healthy());
    link.send_forward(&[1, 2, 3]).unwrap();
    // With no scripted outcomes left the stub defaults to success.
    link.send_control(&ControlMessage::Ping).await.unwrap();
    assert_eq!(link.messages().len(), 1);
}

#[tokio::test]
async fn control_handler_closes_link_when_delta_flush_fails() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // Synchronize the inbound direction so the Link is fully ready and
    // the Delta outbox is flushed at the top of a handler iteration.
    let baseline = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 990,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![baseline],
        })
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncAck { sync_id: 990 }
    ));
    wait_until_topology_ready(&harness.server_link).await;
    // A single LSA whose neighbor list exceeds the reliable control
    // message limit cannot be chunked: the flush fails before any frame
    // is written and the handler closes the Link.
    let huge = tinect::topology::LinkStateAdvertisement::new(
        harness.server_identity.clone(),
        &harness.server_key,
        2,
        crate::daemon::support::unix_now() + 60,
        vec![
            tinect::topology::LinkMetric {
                node: harness.server_identity.clone(),
                cost: 1,
                inner_mtu: 1200,
            };
            3_000
        ],
    );
    assert!(harness.server_link.queue_topology_deltas(vec![huge]).await);
    // Wake the parked handler so it reaches the flush check.
    harness
        .client_link
        .send_control(&ControlMessage::Ping)
        .await
        .unwrap();
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_marks_inbound_unsynchronized_when_snapshot_reack_fails() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let snapshot = ControlMessage::TopologySync {
        mode: tinect::control::TopologySyncMode::Snapshot,
        sync_id: 991,
        chunk_index: 0,
        chunk_count: 1,
        advertisements: vec![test_lsa(&harness.client_identity, &harness.client_key, 1)],
    };
    harness.client_link.send_control(&snapshot).await.unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::TopologySyncAck { sync_id: 991 }
    ));
    wait_until_topology_ready(&harness.server_link).await;
    saturate_control_streams(&harness.server_link).await;
    // A retransmitted already-completed Snapshot is re-ACKed without a
    // second apply.  With the stream backlog full every bounded ACK
    // attempt times out, and the handler must mark the inbound direction
    // unsynchronized instead of pretending the re-ACK was delivered.
    harness.client_link.send_control(&snapshot).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
        while harness.server_link.topology_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed snapshot re-acknowledgement marks inbound unsynchronized");
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_marks_inbound_unsynchronized_when_snapshot_ack_fails() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    saturate_control_streams(&harness.server_link).await;
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 992,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![lsa],
        })
        .await
        .unwrap();
    // The apply succeeds and the Link briefly reports ready (which also
    // proves the initial outbound Snapshot was already acknowledged, so
    // no outbound Snapshot is pending anymore)...
    wait_until_topology_ready(&harness.server_link).await;
    // ...but the ACK cannot be delivered: after the bounded attempts the
    // inbound direction is marked unsynchronized again.
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
        while harness.server_link.topology_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed snapshot acknowledgement marks inbound unsynchronized");
    harness
        .server_link
        .close("snapshot acknowledgement failure test");
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_closes_when_recovery_resend_after_inbound_recovery_fails() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // A Ping/Pong round trip guarantees the handler processed the initial
    // ACK before the outbound direction is invalidated below (control
    // streams can theoretically reorder).
    harness
        .client_link
        .send_control(&ControlMessage::Ping)
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::Pong
    ));
    // Poison the shared topology so the recovery Snapshot cannot be
    // chunked: enough maximally-sized LSAs to exceed the 256-chunk
    // snapshot bound.  The initial Snapshot already went out, so only
    // the recovery resend below observes the poisoned topology.
    {
        let mut topology = harness.runtime.topology.write().await;
        let now = crate::daemon::support::unix_now();
        for _ in 0..520 {
            let key = identity::generate();
            let origin = identity::node_id(&key.verifying_key());
            let lsa = tinect::topology::LinkStateAdvertisement::new(
                origin,
                &key,
                1,
                now + 60,
                vec![
                    tinect::topology::LinkMetric {
                        node: harness.server_identity.clone(),
                        cost: 1,
                        inner_mtu: 1200,
                    };
                    tinect::topology::MAX_NEIGHBORS_PER_LSA
                ],
            );
            topology.apply(lsa, now).unwrap();
        }
    }
    // RFC-0016: a fresh inbound Snapshot while the outbound direction is
    // unsynchronized (and no Snapshot is pending) triggers a one-shot
    // outbound resend, which fails before any frame is written.
    harness.server_link.mark_topology_outbound_unsynchronized();
    let lsa = test_lsa(&harness.client_identity, &harness.client_key, 1);
    harness
        .client_link
        .send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id: 993,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![lsa],
        })
        .await
        .unwrap();
    // The resend failure closes the Link and unwinds the handler.
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_closes_link_when_requested_snapshot_send_fails() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    // A Ping/Pong round trip guarantees the handler processed the initial
    // ACK (control streams can theoretically reorder), so the recovery
    // Request below is served with a fresh Snapshot instead of merging
    // into the still-pending initial one.
    harness
        .client_link
        .send_control(&ControlMessage::Ping)
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::Pong
    ));
    saturate_control_streams(&harness.server_link).await;
    harness
        .client_link
        .send_control(&ControlMessage::TopologySyncRequest { reason: 1 })
        .await
        .unwrap();
    // The requested Snapshot cannot be written: once the Link closes,
    // the blocked send fails and the handler closes the epoch.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    harness
        .server_link
        .close("requested snapshot send failure test");
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_closes_link_when_ack_timeout_recovery_resend_fails() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    // Read but never acknowledge the initial Snapshot so the handler's
    // ACK timeout fires and the recovery resend blocks behind the
    // saturated stream backlog.  Reading it also frees its stream slot.
    let initial = harness.recv_client_control().await;
    assert!(matches!(initial, ControlMessage::TopologySync { .. }));
    saturate_control_streams(&harness.server_link).await;
    tokio::time::sleep(topology_snapshot_ack_timeout() + std::time::Duration::from_secs(2)).await;
    harness
        .server_link
        .close("ack timeout recovery resend failure test");
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(10))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_logs_exit_open_ack_send_failure() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    saturate_control_streams(&harness.server_link).await;
    let circuit_id = tinect::circuit::CircuitId([181; 16]);
    let open = tinect::circuit::OpenRequest::new(
        harness.client_identity.clone(),
        &harness.client_key,
        harness.server_identity.clone(),
        vec![
            harness.client_identity.clone(),
            harness.server_identity.clone(),
        ],
        circuit_id,
        [182; 32],
    );
    harness
        .client_link
        .send_control(&ControlMessage::Open(open))
        .await
        .unwrap();
    // The exit authorization is installed but its acknowledgement cannot
    // be written to the saturated control stream; the failure is logged
    // and the handler unwinds once the Link closes.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    harness.server_link.close("exit open ack failure test");
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_logs_exit_renew_ack_send_failure() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    let circuit_id = tinect::circuit::CircuitId([183; 16]);
    let open = tinect::circuit::OpenRequest::new(
        harness.client_identity.clone(),
        &harness.client_key,
        harness.server_identity.clone(),
        vec![
            harness.client_identity.clone(),
            harness.server_identity.clone(),
        ],
        circuit_id,
        [184; 32],
    );
    harness
        .client_link
        .send_control(&ControlMessage::Open(open))
        .await
        .unwrap();
    assert!(matches!(
        harness.recv_client_control().await,
        ControlMessage::OpenAck { circuit_id: id, .. } if id == circuit_id
    ));
    saturate_control_streams(&harness.server_link).await;
    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew(
            &harness.client_key,
            circuit_id,
            1,
        ))
        .await
        .unwrap();
    // The exit renewal is accepted but its acknowledgement cannot be
    // written to the saturated control stream.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    harness.server_link.close("exit renew ack failure test");
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_logs_renew_rejection_feedback_send_failure() {
    init_tracing();
    let harness = LiveControlHarness::new(0).await;
    harness.acknowledge_initial_snapshot().await;
    saturate_control_streams(&harness.server_link).await;
    // A well-signed RENEW for an unknown circuit is rejected with a
    // circuit-broken feedback, which cannot be delivered while the
    // control stream backlog is full.
    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew(
            &harness.client_key,
            tinect::circuit::CircuitId([185; 16]),
            1,
        ))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    harness
        .server_link
        .close("renew rejection feedback failure test");
    harness
        .wait_until_client_unregistered(std::time::Duration::from_secs(5))
        .await;
    harness.shutdown().await;
}

#[tokio::test]
async fn notify_broken_retries_send_timeouts_and_logs_terminal_failures() {
    init_tracing();
    let harness = LiveControlHarness::new_without_handler(0).await;
    saturate_control_streams(&harness.server_link).await;
    let circuit_id = tinect::circuit::CircuitId([79; 16]);
    let broken = vec![(harness.server_link.instance(), circuit_id)];
    // Each attempt times out after 500 ms while the stream backlog stays
    // full; three attempts plus backoff bound the notification effort.
    let started = std::time::Instant::now();
    notify_broken(&harness.runtime.links, &harness.server_key, broken.clone()).await;
    let elapsed = started.elapsed();
    assert!(elapsed >= std::time::Duration::from_millis(1_400));
    assert!(elapsed < std::time::Duration::from_secs(10));
    // A closed Link fails immediately instead of consuming the attempts.
    harness
        .server_link
        .close("notify broken terminal failure test");
    let started = std::time::Instant::now();
    notify_broken(&harness.runtime.links, &harness.server_key, broken).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_logs_fec_health_transition_warnings() {
    init_tracing();
    let harness = LiveControlHarness::new(1_000).await;
    harness.acknowledge_initial_snapshot().await;
    harness.server_link.set_healthy(true);
    mark_link(&harness.runtime.state, "client", true, None).await;

    let report = |report_id: u64, loss_ppm: u32| {
        ControlMessage::FecReport(tinect::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm,
            burst_milli: 1_000,
        })
    };
    // Saturating loss degrades the Link and is reflected in the status.
    for report_id in 1..=3u64 {
        harness
            .client_link
            .send_control(&report(report_id, 1_000_000))
            .await
            .unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let status = harness.client_status().await;
            if !status.healthy
                && status.last_error.as_deref() == Some("FEC data-plane loss threshold reached")
                && !harness.server_link.is_healthy()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("saturating FEC loss marks the link unhealthy");
    // Healthy reports recover the Link and clear the status error.
    for report_id in 4..=5u64 {
        harness
            .client_link
            .send_control(&report(report_id, 100_000))
            .await
            .unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let status = harness.client_status().await;
            if status.healthy && status.last_error.is_none() && harness.server_link.is_healthy() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("valid FEC reports mark the link healthy again");
    harness.shutdown().await;
}

/// Client and downstream Links connected to the same server endpoint with
/// no control handlers spawned: each test starts handlers only for the
/// Links it exercises, so closing the other side cannot unwind relay
/// bindings behind the test's back.
struct ThreeNodeHarness {
    client_key: ed25519_dalek::SigningKey,
    downstream_key: ed25519_dalek::SigningKey,
    server_key: ed25519_dalek::SigningKey,
    client_identity: String,
    server_identity: String,
    downstream_identity: String,
    client_link: Arc<carrier::Link>,
    downstream_link: Arc<carrier::Link>,
    server_client_link: Arc<carrier::Link>,
    server_downstream_link: Arc<carrier::Link>,
    client_endpoint: quinn::Endpoint,
    downstream_endpoint: quinn::Endpoint,
    server_endpoint: Arc<quinn::Endpoint>,
    runtime: Runtime,
    router: Arc<Router>,
    supervisor: tinect::runtime::DaemonSupervisor,
}

impl ThreeNodeHarness {
    async fn new() -> Self {
        crate::daemon::test_support::backdate_monotonic_epoch();
        let client_key = identity::generate();
        let server_key = identity::generate();
        let downstream_key = identity::generate();
        let client_identity = identity::node_id(&client_key.verifying_key());
        let server_identity = identity::node_id(&server_key.verifying_key());
        let downstream_identity = identity::node_id(&downstream_key.verifying_key());
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
        let server_endpoint = Arc::new(server_endpoint);
        let peer = |name: &str, key: &ed25519_dalek::SigningKey| {
            (
                name.to_owned(),
                tinect::config::Peer {
                    public_key: identity::encode_public(&key.verifying_key()),
                    endpoints: Vec::new(),
                    upstream_dns: None,
                    accept_connections: Some(true),
                    allow_transit: None,
                    allow_relay: None,
                    bind_addresses: Vec::new(),
                    routes: Vec::new(),
                    paths: Vec::new(),
                },
            )
        };
        let peers = std::collections::BTreeMap::from([
            peer("client", &client_key),
            peer("downstream", &downstream_key),
        ]);
        let accept_client = tokio::spawn({
            let peers = peers.clone();
            let key = server_key.clone();
            let endpoint = server_endpoint.clone();
            let bare = server_bare.clone();
            async move {
                carrier::accept_with_bare_and_fec(
                    &endpoint,
                    bare.as_ref(),
                    tinect::config::CarrierProtocol::Quic,
                    &peers,
                    false,
                    "server",
                    &key,
                    0,
                )
                .await
                .unwrap()
            }
        });
        let accept_downstream = tokio::spawn({
            let peers = peers.clone();
            let key = server_key.clone();
            let endpoint = server_endpoint.clone();
            let bare = server_bare.clone();
            async move {
                carrier::accept_with_bare_and_fec(
                    &endpoint,
                    bare.as_ref(),
                    tinect::config::CarrierProtocol::Quic,
                    &peers,
                    false,
                    "server",
                    &key,
                    0,
                )
                .await
                .unwrap()
            }
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
                0,
            )
            .await
            .unwrap(),
        );
        let (downstream_endpoint, downstream_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &tinect::config::LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let downstream_link = Arc::new(
            carrier::connect_with_link_health_and_bare_and_fec(
                &downstream_endpoint,
                downstream_bare.as_ref(),
                server_address,
                tinect::config::CarrierProtocol::Quic,
                "server",
                &server_public,
                "downstream",
                &downstream_key,
                &tinect::config::LinkHealthConfig::default(),
                0,
            )
            .await
            .unwrap(),
        );
        let first_accept = Arc::new(accept_client.await.unwrap());
        let second_accept = Arc::new(accept_downstream.await.unwrap());
        let (server_client_link, server_downstream_link) =
            if first_accept.peer_identity == client_identity {
                (first_accept, second_accept)
            } else {
                (second_accept, first_accept)
            };

        let mut config = crate::daemon::test_support::minimal_config();
        config.id = "server".into();
        config
            .peers
            .insert("client".into(), peer("client", &client_key).1);
        config
            .peers
            .insert("downstream".into(), peer("downstream", &downstream_key).1);
        let runtime = Runtime::new(config).unwrap();
        {
            let mut registered = runtime.links.lock().expect("link registry lock");
            registered.insert("client".into(), server_client_link.clone());
            registered.insert("downstream".into(), server_downstream_link.clone());
        }
        let router = Arc::new(Router::new(
            server_identity.clone(),
            tinect::policy::TransitPolicy::new(
                false,
                HashMap::from([(client_identity.clone(), Some(true))]),
            ),
            runtime.links.clone(),
        ));
        router
            .set_relay_permissions(HashMap::from([(client_identity.clone(), true)]))
            .await;
        let supervisor = tinect::runtime::DaemonSupervisor::default();

        Self {
            client_key,
            downstream_key,
            server_key,
            client_identity,
            server_identity,
            downstream_identity,
            client_link,
            downstream_link,
            server_client_link,
            server_downstream_link,
            client_endpoint,
            downstream_endpoint,
            server_endpoint,
            runtime,
            router,
            supervisor,
        }
    }

    fn spawn_handler(&self, link: &Arc<carrier::Link>) {
        spawn_control_handler(
            link.clone(),
            ControlHandlerContext {
                router: self.router.clone(),
                runtime: self.runtime.clone(),
                identity: Arc::new(self.server_key.clone()),
                supervisor: self.supervisor.clone(),
            },
        );
    }

    /// Acknowledge the initial Snapshot of the handler running on
    /// `server_link` by receiving it on the peer side.
    async fn acknowledge_initial_snapshot(peer_link: &Arc<carrier::Link>) {
        let initial = recv_control_with_timeout(peer_link).await;
        let ControlMessage::TopologySync { sync_id, .. } = initial else {
            panic!("expected initial topology snapshot");
        };
        peer_link
            .send_control(&ControlMessage::TopologySyncAck { sync_id })
            .await
            .unwrap();
    }

    /// Install a client -> server -> downstream relay binding exactly as
    /// the control handler would after an accepted relay OPEN.
    async fn install_relay_binding(&self, circuit_id: tinect::circuit::CircuitId, seed: u8) {
        let open = tinect::circuit::OpenRequest::new(
            self.client_identity.clone(),
            &self.client_key,
            self.downstream_identity.clone(),
            vec![
                self.client_identity.clone(),
                self.server_identity.clone(),
                self.downstream_identity.clone(),
            ],
            circuit_id,
            [seed; 32],
        );
        let binding = self
            .router
            .handle_open(self.server_client_link.as_ref(), &open)
            .await
            .expect("relay open accepted")
            .expect("relay binding installed");
        self.router
            .relay_labels_for(self.server_client_link.instance())
            .write()
            .expect("relay label lock")
            .install(circuit_id, binding.outgoing.clone())
            .expect("forward label install");
        self.router
            .relay_labels_for(binding.outgoing.instance())
            .write()
            .expect("relay label lock")
            .install(circuit_id, self.server_client_link.clone())
            .expect("reverse label install");
    }

    /// Wait until the relay binding for `circuit_id` has been aborted.
    async fn wait_relay_binding_aborted(&self, circuit_id: tinect::circuit::CircuitId) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if self
                    .router
                    .reverse_relay(self.server_downstream_link.instance(), circuit_id)
                    .await
                    .is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("relay binding aborted");
    }

    async fn wait_until_link_closed(link: &Arc<carrier::Link>) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while link.close_reason().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("server observes link close");
    }

    async fn shutdown(self) {
        self.client_link.close("three-node harness complete");
        self.downstream_link.close("three-node harness complete");
        self.server_client_link.close("three-node harness complete");
        self.server_downstream_link
            .close("three-node harness complete");
        self.client_endpoint
            .close(0u32.into(), b"three-node harness complete");
        self.downstream_endpoint
            .close(0u32.into(), b"three-node harness complete");
        self.server_endpoint
            .close(0u32.into(), b"three-node harness complete");
        self.supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn control_handler_aborts_relay_binding_when_feedback_forward_fails() {
    init_tracing();
    let harness = ThreeNodeHarness::new().await;
    harness.spawn_handler(&harness.server_downstream_link);
    // Keep the downstream handler out of its snapshot recovery loop.
    ThreeNodeHarness::acknowledge_initial_snapshot(&harness.downstream_link).await;

    let ack_circuit = tinect::circuit::CircuitId([221; 16]);
    let reject_circuit = tinect::circuit::CircuitId([222; 16]);
    let renew_ack_circuit = tinect::circuit::CircuitId([223; 16]);
    let broken_circuit = tinect::circuit::CircuitId([224; 16]);
    for (circuit_id, seed) in [
        (ack_circuit, 225u8),
        (reject_circuit, 226),
        (renew_ack_circuit, 227),
        (broken_circuit, 228),
    ] {
        harness.install_relay_binding(circuit_id, seed).await;
    }
    assert!(
        harness
            .router
            .reverse_relay(harness.server_downstream_link.instance(), ack_circuit)
            .await
            .is_some()
    );

    // The source side dies without a handler that could unwind the
    // bindings first, so every relayed feedback must fail to forward.
    harness.client_link.close("relay feedback failure test");
    harness
        .client_endpoint
        .close(0u32.into(), b"relay feedback failure test");
    ThreeNodeHarness::wait_until_link_closed(&harness.server_client_link).await;

    // An OPEN acknowledgement that cannot be relayed aborts the binding;
    // the compensating rejection is dropped with the dead source.
    harness
        .downstream_link
        .send_control(&ControlMessage::open_ack(
            &harness.downstream_key,
            ack_circuit,
        ))
        .await
        .unwrap();
    harness.wait_relay_binding_aborted(ack_circuit).await;

    // An OPEN rejection that cannot be relayed aborts the binding.
    harness
        .downstream_link
        .send_control(&ControlMessage::open_reject(
            &harness.downstream_key,
            reject_circuit,
            true,
            OPEN_REJECT_REASON_GENERIC,
        ))
        .await
        .unwrap();
    harness.wait_relay_binding_aborted(reject_circuit).await;

    // A RENEW acknowledgement that cannot be relayed aborts the binding
    // and the circuit-broken feedback is dropped with the dead source.
    harness
        .downstream_link
        .send_control(&ControlMessage::circuit_renew_ack(
            &harness.downstream_key,
            renew_ack_circuit,
            1,
        ))
        .await
        .unwrap();
    harness.wait_relay_binding_aborted(renew_ack_circuit).await;

    // A first-hop-signed circuit-broken notification that cannot be
    // relayed aborts the binding.
    harness
        .downstream_link
        .send_control(&ControlMessage::circuit_broken(
            &harness.downstream_key,
            broken_circuit,
            tinect::control::CIRCUIT_BROKEN_REASON_RELAY_FAILURE,
        ))
        .await
        .unwrap();
    harness.wait_relay_binding_aborted(broken_circuit).await;

    harness.shutdown().await;
}

#[tokio::test]
async fn control_handler_drops_renewal_when_relay_forward_fails() {
    init_tracing();
    let harness = ThreeNodeHarness::new().await;
    harness.spawn_handler(&harness.server_client_link);
    ThreeNodeHarness::acknowledge_initial_snapshot(&harness.client_link).await;

    let circuit_id = tinect::circuit::CircuitId([231; 16]);
    let open = tinect::circuit::OpenRequest::new(
        harness.client_identity.clone(),
        &harness.client_key,
        harness.downstream_identity.clone(),
        vec![
            harness.client_identity.clone(),
            harness.server_identity.clone(),
            harness.downstream_identity.clone(),
        ],
        circuit_id,
        [232; 32],
    );
    harness
        .client_link
        .send_control(&ControlMessage::Open(open))
        .await
        .unwrap();
    // The relayed OPEN reaches the downstream hop.
    assert!(matches!(
        recv_control_with_timeout(&harness.downstream_link).await,
        ControlMessage::Open(_)
    ));

    // The outgoing Link dies with no handler of its own, so the relay
    // binding is still in place when the RENEW forward fails.
    harness.downstream_link.close("renew relay failure test");
    harness
        .downstream_endpoint
        .close(0u32.into(), b"renew relay failure test");
    ThreeNodeHarness::wait_until_link_closed(&harness.server_downstream_link).await;

    harness
        .client_link
        .send_control(&ControlMessage::circuit_renew(
            &harness.client_key,
            circuit_id,
            1,
        ))
        .await
        .unwrap();
    // The failed forward must not fabricate a RENEW acknowledgement
    // toward the source: its waiter only accepts the exact counter it
    // asked for, so nothing arrives at all.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(300),
            harness.client_link.recv_control(),
        )
        .await
        .is_err(),
        "failed RENEW relay must not acknowledge the source"
    );
    harness.shutdown().await;
}
