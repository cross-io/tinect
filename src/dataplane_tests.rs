use super::*;
use crate::carrier::Link;
use crate::circuit::CircuitId;
use crate::config::{CarrierProtocol, LinkHealthConfig, Peer, TunConfig};
use crate::identity;
use crate::link::{LinkError, LinkFuture, LinkHandle, LinkRef};
use crate::runtime::DaemonSupervisor;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

async fn connected_links() -> (Arc<Link>, Arc<Link>, quinn::Endpoint, quinn::Endpoint) {
    let client_key = identity::generate();
    let server_key = identity::generate();
    let server_public = identity::encode_public(&server_key.verifying_key());
    let (server_endpoint, _) = crate::carrier::endpoint_with_options_and_bare(
        CarrierProtocol::QuicFull,
        "127.0.0.1:0".parse().unwrap(),
        &LinkHealthConfig::default(),
        None,
        None,
        Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let address = server_endpoint.local_addr().unwrap();
    let peers = BTreeMap::from([(
        "client".to_owned(),
        Peer {
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
    let accept_endpoint = server_endpoint.clone();
    let server_task = tokio::spawn(async move {
        crate::carrier::accept_with_bare(
            &accept_endpoint,
            None,
            CarrierProtocol::QuicFull,
            &peers,
            false,
            "server",
            &accept_key,
        )
        .await
        .unwrap()
    });
    let (client_endpoint, _) = crate::carrier::endpoint_with_options_and_bare(
        CarrierProtocol::QuicFull,
        "127.0.0.1:0".parse().unwrap(),
        &LinkHealthConfig::default(),
        None,
        None,
        Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )
    .unwrap();
    let client_link = Arc::new(
        crate::carrier::connect_with_link_health_and_bare(
            &client_endpoint,
            None,
            address,
            CarrierProtocol::QuicFull,
            "server",
            &server_public,
            "client",
            &client_key,
            &LinkHealthConfig::default(),
        )
        .await
        .unwrap(),
    );
    let server_link = Arc::new(server_task.await.unwrap());
    (client_link, server_link, client_endpoint, server_endpoint)
}

fn ipv4_packet() -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 64, 0, 2]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 7]);
    packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
    packet
}

async fn wait_for_rejection(metrics: &Observability, reason: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics
                .snapshot()
                .acl_rejections
                .get(reason)
                .is_some_and(|count| *count != 0)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for rejection {reason}; observed={:?}",
            metrics.snapshot().acl_rejections
        )
    });
}

async fn join_task<T>(mut task: tokio::task::JoinHandle<T>, label: &str) -> Result<(), String> {
    match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(format!("{label} panicked: {error}")),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(format!("{label} timed out and was aborted"))
        }
    }
}

async fn send_encrypted(
    link: &Arc<Link>,
    sender: &mut crate::crypto::SenderSession,
    packet: &[u8],
) {
    let frame = sender.encrypt(packet).unwrap().to_vec();
    link.send_forward(&frame).unwrap();
}

#[derive(Clone, Copy)]
struct TestFakeIpReturnRewriter;

impl FakeIpMode for TestFakeIpReturnRewriter {
    fn runtime(&self) -> Option<&Arc<crate::fake_ip::FakeIpRuntime>> {
        None
    }

    fn restore_circuit_return(
        &self,
        packet: &mut [u8],
        fake_destination: Option<std::net::IpAddr>,
    ) -> bool {
        if fake_destination == Some("198.18.0.2".parse().unwrap()) {
            return false;
        }
        if fake_destination.is_none() {
            return true;
        }
        packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
        true
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn secure_receive_covers_direction_and_admission_rejection_paths() {
    if unsafe { libc::geteuid() } != 0 || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();
    let device = crate::platform::create_tun(&TunConfig {
        enabled: true,
        name: "tinectcvall".into(),
        addresses: vec!["10.64.0.1/32".parse().unwrap()],
        mtu: 1280,
        clamp_mss: true,
    })
    .unwrap();
    let (client_link, server_link, client_endpoint, server_endpoint) = connected_links().await;
    let dispatcher_link = server_link.clone();
    let dispatcher = tokio::spawn(async move {
        loop {
            match dispatcher_link.recv_physical().await {
                Ok(crate::physical::PhysicalPayload::Forward(frame)) => {
                    dispatcher_link.publish_forward(frame);
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });

    let source_key = identity::generate();
    let source_public = identity::encode_public(&source_key.verifying_key());
    let circuit_id = CircuitId([201; 16]);
    let circuit_key = chacha20poly1305::Key::from([202; 32]);
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (size, peer) = upstream.recv_from(&mut buffer).await.unwrap();
        let query = hickory_proto::op::Message::from_vec(&buffer[..size]).unwrap();
        let mut response =
            hickory_proto::op::Message::response(query.metadata.id, query.metadata.op_code);
        response.queries = query.queries;
        upstream
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let authorizations = crate::circuit::CircuitAuthorizations::default();
    authorizations
        .install(server_link.instance(), circuit_id, source_public.clone())
        .await
        .unwrap();
    let sessions = SessionManager::default();
    sessions
        .install_open(
            server_link.instance(),
            circuit_id,
            source_key.verifying_key(),
            circuit_key,
        )
        .await;
    sessions
        .install_return(
            server_link.instance(),
            circuit_id,
            source_key.verifying_key(),
            circuit_key,
        )
        .await;
    let opens = CircuitOpenManager::default();
    let token = crate::link::LinkToken::default();
    let waiter = opens
        .register(
            server_link.instance(),
            circuit_id,
            source_public.clone(),
            Vec::new(),
            None,
            token,
        )
        .await;
    assert!(
        opens
            .resolve(
                server_link.instance(),
                circuit_id,
                &source_public,
                OpenResult::Acknowledged,
            )
            .await
    );
    assert_eq!(waiter.await.unwrap(), OpenResult::Acknowledged);

    let metrics = Arc::new(Observability::new(0));
    let supervisor = DaemonSupervisor::default();
    let return_flows = crate::return_path::ReturnFlowTable::default();
    return_flows.install_circuit(server_link.instance(), circuit_id, circuit_key);
    let egress = crate::dataplane::EgressPolicy {
        names: Arc::new(HashMap::from([(source_public.clone(), "source".into())])),
        allowed_routes: Arc::new(vec![crate::config::AllowedRoute {
            allow: vec!["127.0.0.0/8".parse().unwrap()],
            deny: Vec::new(),
            r#for: crate::config::RouteSourceSelector::Keyword("any_known".into()),
        }]),
        allowed_local_ports: Arc::new(Vec::new()),
        local_addresses: Arc::new(Vec::new()),
        metrics: metrics.clone(),
    };
    let context = SecureReceiveContext {
        identity: Arc::new(identity::generate()),
        egress: Some(egress),
        source_policy: SourceAddressPolicy::from_bindings(
            vec![
                ("10.64.0.2/32".parse().unwrap(), "other".into()),
                ("198.18.0.0/15".parse().unwrap(), "other".into()),
            ],
            metrics.clone(),
        ),
        metrics: metrics.clone(),
        authorizations: authorizations.clone(),
        relay_labels: Default::default(),
        sessions: sessions.clone(),
        circuit_router: Arc::new(crate::circuit::Router::new(
            "receiver",
            crate::policy::TransitPolicy::new(false, HashMap::new()),
            Arc::new(std::sync::Mutex::new(HashMap::new())),
        )),
        circuit_opens: opens,
        return_flows,
        circuit_dns: CircuitDnsClient::default(),
        supervisor: supervisor.clone(),
    };
    let receive_task = tokio::spawn(receive_secure_link(
        device.clone(),
        server_link.clone(),
        context,
        TestFakeIpReturnRewriter,
    ));

    let packet = ipv4_packet();
    // A frame with an authenticated circuit id but the wrong session key is
    // an ordinary cryptographic rejection, distinct from the unknown-session
    // feedback path below.  Restore the valid receiver before continuing.
    sessions
        .install_open(
            server_link.instance(),
            circuit_id,
            source_key.verifying_key(),
            chacha20poly1305::Key::from([222; 32]),
        )
        .await;
    let mut wrong_key =
        crate::crypto::SenderSession::from_key(circuit_id, chacha20poly1305::Key::from([223; 32]));
    send_encrypted(&client_link, &mut wrong_key, &packet).await;
    sessions
        .install_open(
            server_link.instance(),
            circuit_id,
            source_key.verifying_key(),
            circuit_key,
        )
        .await;
    // A truncated locally published frame has no circuit id and must be
    // discarded without attempting circuit-broken feedback.
    server_link.publish_forward(vec![1, 2, 3]);
    tokio::task::yield_now().await;
    let mut short = crate::crypto::SenderSession::from_key(
        CircuitId([203; 16]),
        chacha20poly1305::Key::from([204; 32]),
    );
    send_encrypted(&client_link, &mut short, b"short").await;
    tokio::task::yield_now().await;

    let mut unauthorized = crate::crypto::SenderSession::from_key(
        CircuitId([205; 16]),
        chacha20poly1305::Key::from([206; 32]),
    );
    sessions
        .install_open(
            server_link.instance(),
            CircuitId([205; 16]),
            source_key.verifying_key(),
            chacha20poly1305::Key::from([206; 32]),
        )
        .await;
    send_encrypted(&client_link, &mut unauthorized, &packet).await;
    wait_for_rejection(&metrics, "egress:unopened_circuit").await;

    let mut forged_source = crate::crypto::SenderSession::from_key(circuit_id, circuit_key);
    send_encrypted(&client_link, &mut forged_source, &packet).await;
    wait_for_rejection(&metrics, "source_binding:denied").await;

    send_encrypted(
        &client_link,
        &mut forged_source,
        &crate::fake_ip::encode_fake_ip_envelope(&packet, "198.18.0.1".parse().unwrap()),
    )
    .await;
    wait_for_rejection(&metrics, "source_binding:denied").await;

    send_encrypted(&client_link, &mut forged_source, &[0, 4, 1]).await;
    wait_for_rejection(&metrics, "fake_ip:malformed_envelope").await;

    let mut dns = crate::crypto::SenderSession::dns_from_key(circuit_id, circuit_key);
    send_encrypted(&client_link, &mut dns, b"bad dns query").await;
    wait_for_rejection(&metrics, "dns:malformed_query").await;
    let denied_upstream =
        crate::config::DnsServer::from_socket_addr("192.0.2.53:53".parse().unwrap());
    let query = encode_dns_query(7, &denied_upstream, b"wire").unwrap();
    send_encrypted(&client_link, &mut dns, &query).await;
    wait_for_rejection(&metrics, "egress:dns_allowed_route_denied").await;

    let upstream = crate::config::DnsServer::from_socket_addr(upstream_address);
    let mut wire_message = hickory_proto::op::Message::query();
    wire_message.metadata.id = 8;
    wire_message.queries.push(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_ascii("example.test.").unwrap(),
        hickory_proto::rr::RecordType::A,
    ));
    let wire = wire_message.to_vec().unwrap();
    let query = encode_dns_query(8, &upstream, &wire).unwrap();
    send_encrypted(&client_link, &mut dns, &query).await;
    tokio::time::timeout(Duration::from_secs(2), upstream_task)
        .await
        .unwrap()
        .unwrap();

    send_encrypted(
        &client_link,
        &mut dns,
        &crate::fake_ip::encode_fake_ip_envelope(&query, "198.18.0.1".parse().unwrap()),
    )
    .await;
    wait_for_rejection(&metrics, "fake_ip:envelope_on_dns").await;

    let mut dns_return = crate::crypto::SenderSession::dns_return_from_key(circuit_id, circuit_key);
    send_encrypted(&client_link, &mut dns_return, b"bad dns response").await;
    wait_for_rejection(&metrics, "dns:return_rejected").await;

    // An authenticated but malformed IP packet is rejected by the source
    // binding gate before any egress policy or TUN operation.
    send_encrypted(&client_link, &mut forged_source, &[0x45, 0, 0]).await;
    wait_for_rejection(&metrics, "source_binding:unsupported_or_malformed").await;

    // A valid source identity can still be denied by the exported-route ACL.
    let mut route_denied = ipv4_packet();
    route_denied[12..16].copy_from_slice(&[203, 0, 113, 1]);
    send_encrypted(&client_link, &mut forged_source, &route_denied).await;
    wait_for_rejection(&metrics, "egress:allowed_route_denied").await;

    let mut unauthorized_return = crate::crypto::SenderSession::return_from_key(
        CircuitId([207; 16]),
        chacha20poly1305::Key::from([208; 32]),
    );
    sessions
        .install_return(
            server_link.instance(),
            CircuitId([207; 16]),
            source_key.verifying_key(),
            chacha20poly1305::Key::from([208; 32]),
        )
        .await;
    send_encrypted(&client_link, &mut unauthorized_return, &packet).await;
    wait_for_rejection(&metrics, "return_path:unauthorized_circuit").await;

    let mut authorized_return =
        crate::crypto::SenderSession::return_from_key(circuit_id, circuit_key);
    let mut unbound_packet = packet.clone();
    unbound_packet[12..16].copy_from_slice(&[1, 1, 1, 1]);
    send_encrypted(&client_link, &mut authorized_return, &unbound_packet).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics.snapshot().dataplane.tun_tx_packets >= 1 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    send_encrypted(
        &client_link,
        &mut authorized_return,
        &crate::fake_ip::encode_fake_ip_envelope(&unbound_packet, "198.18.0.1".parse().unwrap()),
    )
    .await;
    wait_for_rejection(&metrics, "source_binding:denied").await;
    send_encrypted(
        &client_link,
        &mut authorized_return,
        &crate::fake_ip::encode_fake_ip_envelope(&unbound_packet, "198.18.0.2".parse().unwrap()),
    )
    .await;
    wait_for_rejection(&metrics, "fake_ip:return_translation_failed").await;
    assert_eq!(metrics.snapshot().dataplane.tun_tx_packets, 1);

    server_link.close("secure receive branch test complete");
    client_link.close("secure receive branch test complete");
    client_endpoint.close(0u32.into(), b"secure receive branch test complete");
    server_endpoint.close(0u32.into(), b"secure receive branch test complete");
    let receive_result = join_task(receive_task, "secure receive task").await;
    let dispatcher_result = join_task(dispatcher, "secure receive dispatcher").await;
    supervisor.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(receive_result.is_ok(), "{receive_result:?}");
    assert!(dispatcher_result.is_ok(), "{dispatcher_result:?}");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn secure_router_reads_tun_and_encrypts_selected_route() {
    if unsafe { libc::geteuid() } != 0 || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();
    let device = crate::platform::create_tun(&TunConfig {
        enabled: true,
        name: "tinectcvrtr".into(),
        addresses: vec!["10.64.0.1/32".parse().unwrap()],
        mtu: 1280,
        clamp_mss: true,
    })
    .unwrap();
    let tun_name = device.name().unwrap();
    crate::platform::configure_tun_addresses(
        &tun_name,
        &[
            "10.64.0.1/32".parse().unwrap(),
            "192.0.2.1/24".parse().unwrap(),
            "fd00:64::1/128".parse().unwrap(),
        ],
    )
    .await
    .unwrap();
    let multicast_routes = vec!["224.0.0.0/4".parse().unwrap(), "ff00::/8".parse().unwrap()];
    crate::platform::install_overlay_routes(&tun_name, &multicast_routes, &[])
        .await
        .unwrap();
    let (client_link, server_link, client_endpoint, _server_endpoint) = connected_links().await;
    let identity = Arc::new(identity::generate());
    let circuit_id = CircuitId([211; 16]);
    let data_key = chacha20poly1305::Key::from([212; 32]);
    let prefix = "192.0.2.0/24".parse().unwrap();
    let destination_key = identity::generate();
    let route = SecureRoute {
        prefix,
        exit: "exit".into(),
        priority: 100,
        link: client_link.clone(),
        circuit_id,
        data_key,
        destination_key: destination_key.verifying_key(),
        healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        mtu: 1200,
        lease_epoch: 1,
        send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        send_budget: Arc::new(std::sync::atomic::AtomicUsize::new(1200)),
    };
    let snapshot = RouteSnapshot::new(
        vec![route],
        vec![crate::config::RouteImport {
            prefix,
            candidates: vec![crate::config::RouteCandidate {
                node: "exit".into(),
                priority: 100,
            }],
        }],
    )
    .with_direct_routes(vec![("192.0.2.8/32".parse().unwrap(), 200)], Vec::new());
    let supervisor = DaemonSupervisor::default();
    let metrics = Arc::new(Observability::new(0));
    let direct = DirectEgress::open(46, 32125, true).unwrap();
    direct.activate();
    let inbound = InboundDispatch {
        identity: identity.clone(),
        authorizations: crate::circuit::CircuitAuthorizations::default(),
        relay_labels: Default::default(),
        sessions: SessionManager::default(),
        cancellation: CancellationToken::new(),
        circuit_opens: CircuitOpenManager::default(),
        circuit_router: Arc::new(crate::circuit::Router::new(
            "receiver",
            crate::policy::TransitPolicy::new(false, HashMap::new()),
            Arc::new(std::sync::Mutex::new(HashMap::new())),
        )),
        circuit_dns: CircuitDnsClient::default(),
    };
    let router = spawn_tun_router_secure(
        device.clone(),
        snapshot,
        vec![client_link.clone()],
        identity.clone(),
        RouterEgress {
            remote: None,
            source_policy: SourceAddressPolicy::default(),
            direct: Some(direct),
            clamp_mss: false,
            fake_ip: None,
            return_flows: crate::return_path::ReturnFlowTable::default(),
        },
        metrics.clone(),
        inbound,
        supervisor.clone(),
    );

    let socket = std::net::UdpSocket::bind("192.0.2.1:0").unwrap();
    socket.send_to(b"coverage", "192.0.2.7:53").unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(2), server_link.recv_physical())
        .await
        .unwrap()
        .unwrap();
    let crate::physical::PhysicalPayload::Forward(frame) = frame else {
        panic!("expected encrypted Forward payload");
    };
    let mut receiver = crate::crypto::ReceiverSessions::default();
    receiver.install(circuit_id, identity.verifying_key(), data_key);
    let inner = receiver.open_data(&frame).unwrap().3;
    assert_eq!(
        inspect_ip_destination(&inner),
        Some("192.0.2.7".parse().unwrap())
    );
    assert!(metrics.snapshot().dataplane.tun_rx_packets >= 1);

    let direct_socket = std::net::UdpSocket::bind("192.0.2.1:0").unwrap();
    direct_socket.send_to(b"direct", "192.0.2.8:443").unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics.snapshot().dataplane.tun_tx_packets >= 1 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    // IPv6 neighbor discovery is kernel-generated control traffic rather than
    // a user flow. It must be dropped before direct fallback asks conntrack
    // to resolve an ICMPv6 tuple that some kernels reject with EINVAL.
    let mut neighbor_solicitation = [0_u8; 48];
    neighbor_solicitation[0] = 0x60;
    neighbor_solicitation[6] = 58;
    neighbor_solicitation[7] = 255;
    neighbor_solicitation[24..40].copy_from_slice(
        &"ff02::1:ff00:2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    neighbor_solicitation[40] = 135;
    let multicast_socket = std::net::UdpSocket::bind("[fd00:64::1]:0").unwrap();
    let tun_rx_packets_before_multicast = metrics.snapshot().dataplane.tun_rx_packets;
    multicast_socket
        .send_to(
            &neighbor_solicitation[40..],
            std::net::SocketAddrV6::new("ff05::1:ff00:2".parse().unwrap(), 135, 0, 0),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics.snapshot().dataplane.tun_rx_packets > tun_rx_packets_before_multicast {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !metrics
            .snapshot()
            .acl_rejections
            .contains_key("route:direct_conntrack_failed")
    );

    router.shutdown().await;
    crate::platform::cleanup_overlay_routes(&tun_name, &multicast_routes)
        .await
        .unwrap();
    client_link.close("secure router test complete");
    server_link.close("secure router test complete");
    client_endpoint.close(0u32.into(), b"secure router test complete");
    supervisor.shutdown(Duration::from_secs(1)).await.unwrap();
}

/// Shared fixture for `run_secure_sender_worker` tests: a spawned worker plus
/// the binding handles the route layer would normally own.
struct SenderWorkerFixture {
    tx: mpsc::Sender<QueuedSecurePacket>,
    healthy: Arc<std::sync::atomic::AtomicBool>,
    send_gate: Arc<std::sync::atomic::AtomicBool>,
    budget: Arc<std::sync::atomic::AtomicUsize>,
    metrics: Arc<Observability>,
    supervisor: DaemonSupervisor,
    worker: tokio::task::JoinHandle<()>,
}

fn spawn_sender_worker(source: &Arc<SigningKey>, healthy: bool) -> SenderWorkerFixture {
    let (tx, rx) = mpsc::channel(64);
    let metrics = Arc::new(Observability::new(0));
    let supervisor = DaemonSupervisor::default();
    let worker = tokio::spawn(run_secure_sender_worker(
        rx,
        source.clone(),
        SessionManager::default(),
        CircuitOpenManager::default(),
        CancellationToken::new(),
        metrics.clone(),
        supervisor.clone(),
    ));
    SenderWorkerFixture {
        tx,
        healthy: Arc::new(std::sync::atomic::AtomicBool::new(healthy)),
        send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        budget: Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX)),
        metrics,
        supervisor,
        worker,
    }
}

fn queued_secure(
    packet: &[u8],
    circuit_id: CircuitId,
    data_key: chacha20poly1305::Key,
    link: LinkRef,
    fixture: &SenderWorkerFixture,
) -> QueuedSecurePacket {
    QueuedSecurePacket {
        packet: packet.to_vec(),
        exit: "exit".into(),
        circuit_id,
        data_key,
        link,
        healthy: fixture.healthy.clone(),
        lease_epoch: 1,
        send_gate: fixture.send_gate.clone(),
        send_budget: fixture.budget.clone(),
    }
}

/// Spawn a task that decrypts every Forward frame arriving on `link` and
/// streams the plaintext back. Draining continuously keeps the bounded
/// physical-to-dataplane queue from dropping the marker frames the tests
/// wait on at the end.
fn spawn_decrypted_payload_reader(
    link: Arc<Link>,
    circuit_id: CircuitId,
    source: &Arc<SigningKey>,
    data_key: chacha20poly1305::Key,
) -> (
    mpsc::UnboundedReceiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
) {
    let (payload_tx, payload_rx) = mpsc::unbounded_channel();
    let mut receiver = crate::crypto::ReceiverSessions::default();
    receiver.install(circuit_id, source.verifying_key(), data_key);
    let reader = tokio::spawn(async move {
        loop {
            match link.recv_physical().await {
                Ok(crate::physical::PhysicalPayload::Forward(frame)) => {
                    if let Ok(opened) = receiver.open_data(&frame) {
                        let _ = payload_tx.send(opened.3);
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    (payload_rx, reader)
}

async fn wait_for_payload(payloads: &mut mpsc::UnboundedReceiver<Vec<u8>>, expected: &[u8]) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(payload) = payloads.recv().await {
            if payload == expected {
                return;
            }
        }
        panic!("payload stream ended before {expected:?} arrived");
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for payload {expected:?}"));
}

struct AdmissionRejectOnceLink {
    attempts: std::sync::atomic::AtomicUsize,
    healthy: std::sync::atomic::AtomicBool,
    frames: mpsc::UnboundedSender<Vec<u8>>,
}

impl LinkHandle for AdmissionRejectOnceLink {
    fn peer_name(&self) -> &str {
        "test-exit"
    }

    fn peer_identity(&self) -> &str {
        "test-exit-identity"
    }

    fn instance(&self) -> u64 {
        1
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(std::sync::atomic::Ordering::Acquire)
    }

    fn set_healthy(&self, healthy: bool) {
        self.healthy
            .store(healthy, std::sync::atomic::Ordering::Release);
    }

    fn should_log_dataplane_warning(&self) -> bool {
        true
    }

    fn is_closed(&self) -> bool {
        false
    }

    fn send_forward(&self, frame: &[u8]) -> Result<(), LinkError> {
        if self
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            == 0
        {
            return Err(LinkError::AdmissionRejected);
        }
        self.frames
            .send(frame.to_vec())
            .map_err(|_| LinkError::EndpointClosed)
    }

    fn send_control<'a>(&'a self, _message: &'a crate::control::ControlMessage) -> LinkFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

/// A local admission rejection drops only that encrypted frame. It must not
/// mark the route unhealthy, and a subsequent frame must still be sent.
#[tokio::test]
async fn secure_sender_drops_frames_on_admission_rejection_without_failing_route() {
    crate::circuit::backdate_monotonic_epoch();
    let source = Arc::new(identity::generate());
    let circuit_id = CircuitId([231; 16]);
    let data_key = chacha20poly1305::Key::from([232; 32]);
    let fixture = spawn_sender_worker(&source, false);
    let (frame_tx, mut frames) = mpsc::unbounded_channel();
    let link: LinkRef = Arc::new(AdmissionRejectOnceLink {
        attempts: std::sync::atomic::AtomicUsize::new(0),
        healthy: std::sync::atomic::AtomicBool::new(false),
        frames: frame_tx,
    });

    fixture
        .tx
        .send(queued_secure(
            b"rejected-frame",
            circuit_id,
            data_key,
            link.clone(),
            &fixture,
        ))
        .await
        .unwrap();
    wait_for_rejection(&fixture.metrics, "queue:admission_rejected").await;
    assert!(!fixture.healthy.load(std::sync::atomic::Ordering::Acquire));
    assert!(frames.try_recv().is_err());

    // Decrypt the next frame to prove the sender worker kept the session
    // usable and delivered the packet after the one-shot rejection.
    let marker = b"admission-recovered";
    fixture
        .tx
        .send(queued_secure(marker, circuit_id, data_key, link, &fixture))
        .await
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv())
        .await
        .unwrap()
        .unwrap();
    let mut receiver = crate::crypto::ReceiverSessions::default();
    receiver.install(circuit_id, source.verifying_key(), data_key);
    assert_eq!(receiver.open_data(&frame).unwrap().3, marker);
    assert!(fixture.healthy.load(std::sync::atomic::Ordering::Acquire));

    drop(fixture.tx);
    fixture.worker.await.unwrap();
    fixture
        .supervisor
        .shutdown(Duration::from_secs(1))
        .await
        .unwrap();
}

/// The worker re-reads the send gate and budget immediately before every
/// carrier attempt, not just once when a packet is dequeued. Flipping the
/// gate while packets flow must drop in-flight frames with the lease reason
/// and must not wedge the worker: reopening the gate resumes delivery.
/// Large payloads widen the encrypt window between the dequeue-time check and
/// the pre-send recheck so the concurrent toggle lands between them; this
/// needs a multi-threaded runtime for the flip to race the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secure_sender_rechecks_send_gate_before_every_carrier_attempt() {
    crate::circuit::backdate_monotonic_epoch();
    let (client_link, server_link, client_endpoint, server_endpoint) = connected_links().await;
    let source = Arc::new(identity::generate());
    let circuit_id = CircuitId([233; 16]);
    let data_key = chacha20poly1305::Key::from([234; 32]);
    let fixture = spawn_sender_worker(&source, false);
    let (mut payloads, reader) =
        spawn_decrypted_payload_reader(server_link, circuit_id, &source, data_key);

    let feeder_stop = CancellationToken::new();
    let feeder = {
        let tx = fixture.tx.clone();
        let link = client_link.clone();
        let healthy = fixture.healthy.clone();
        let send_gate = fixture.send_gate.clone();
        let budget = fixture.budget.clone();
        let stop = feeder_stop.clone();
        tokio::spawn(async move {
            let mut index = 0_u32;
            while !stop.is_cancelled() {
                // Oversized-on-purpose payloads make encryption dominate the
                // dequeue→send path; the frames themselves are dropped as
                // DatagramTooLarge after the gate recheck, which is harmless
                // for this test.
                let mut packet = vec![0_u8; 16384];
                packet[..4].copy_from_slice(&index.to_be_bytes());
                index = index.wrapping_add(1);
                if tx
                    .send(QueuedSecurePacket {
                        packet,
                        exit: "exit".into(),
                        circuit_id,
                        data_key,
                        link: link.clone(),
                        healthy: healthy.clone(),
                        lease_epoch: 1,
                        send_gate: send_gate.clone(),
                        send_budget: budget.clone(),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                // `send` completes immediately while the channel has
                // capacity; yield so the worker and gate flips interleave.
                tokio::task::yield_now().await;
            }
        })
    };
    for _ in 0..200 {
        fixture
            .send_gate
            .store(false, std::sync::atomic::Ordering::Release);
        tokio::time::sleep(Duration::from_millis(1)).await;
        fixture
            .send_gate
            .store(true, std::sync::atomic::Ordering::Release);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    wait_for_rejection(&fixture.metrics, "lease:stale_epoch").await;
    feeder_stop.cancel();
    feeder.abort();

    let marker = b"gate-reopened";
    fixture
        .tx
        .send(queued_secure(
            marker,
            circuit_id,
            data_key,
            client_link.clone(),
            &fixture,
        ))
        .await
        .unwrap();
    wait_for_payload(&mut payloads, marker).await;
    assert!(fixture.healthy.load(std::sync::atomic::Ordering::Acquire));

    drop(fixture.tx);
    fixture.worker.await.unwrap();
    reader.abort();
    client_link.close("send gate recheck test complete");
    client_endpoint.close(0u32.into(), b"send gate recheck test complete");
    server_endpoint.close(0u32.into(), b"send gate recheck test complete");
    fixture
        .supervisor
        .shutdown(Duration::from_secs(1))
        .await
        .unwrap();
}

/// A failed datagram send marks the binding unhealthy and schedules a
/// one-second cool-down probe. The probe belongs to the old Link instance and
/// must not revive a path whose connection is already closed.
#[tokio::test]
async fn secure_sender_health_reset_timer_does_not_revive_a_closed_link() {
    crate::circuit::backdate_monotonic_epoch();
    let (client_link, _server_link, client_endpoint, server_endpoint) = connected_links().await;
    let source = Arc::new(identity::generate());
    let circuit_id = CircuitId([235; 16]);
    let data_key = chacha20poly1305::Key::from([236; 32]);
    let fixture = spawn_sender_worker(&source, true);

    client_link.close("health reset timer test");
    tokio::time::timeout(Duration::from_secs(2), client_link.wait_closed())
        .await
        .unwrap();
    fixture
        .tx
        .send(queued_secure(
            b"lost",
            circuit_id,
            data_key,
            client_link.clone(),
            &fixture,
        ))
        .await
        .unwrap();
    // The send failure flips the binding unhealthy exactly once.
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.healthy.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed send must mark the binding unhealthy");
    // The cool-down timer fires while the Link is closed; reviving the path
    // would resurrect a dead circuit, so health must stay false.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!fixture.healthy.load(std::sync::atomic::Ordering::Acquire));

    drop(fixture.tx);
    fixture.worker.await.unwrap();
    client_endpoint.close(0u32.into(), b"health reset timer test");
    server_endpoint.close(0u32.into(), b"health reset timer test");
    fixture
        .supervisor
        .shutdown(Duration::from_secs(1))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Privileged Linux dataplane tests: real TUN devices inside a private network
// namespace (root + TINECT_RUN_NETFILTER_TESTS=1 only).
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn skip_unless_privileged() -> bool {
    (unsafe { libc::geteuid() }) != 0 || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
}

#[cfg(target_os = "linux")]
fn create_test_tun(name: &str, address: &str) -> crate::platform::TunDevice {
    crate::platform::create_tun(&TunConfig {
        enabled: true,
        name: name.into(),
        addresses: vec![address.parse().unwrap()],
        mtu: 1280,
        clamp_mss: false,
    })
    .unwrap()
}

/// Pump physical Forward payloads into the link's forward queue, like the
/// daemon's per-link physical dispatcher does.
#[cfg(target_os = "linux")]
fn spawn_forward_dispatcher(link: Arc<Link>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match link.recv_physical().await {
                Ok(crate::physical::PhysicalPayload::Forward(frame)) => link.publish_forward(frame),
                Ok(_) => {}
                Err(_) => return,
            }
        }
    })
}

/// Recompute the IPv4 header checksum so the kernel accepts packets that
/// tests write into a real TUN device.
#[cfg(target_os = "linux")]
fn finish_ipv4_header(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let mut sum = 0_u32;
    for chunk in packet[..header_len].as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

#[cfg(target_os = "linux")]
fn ipv4_udp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut packet = vec![0_u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    finish_ipv4_header(&mut packet);
    packet
}

#[cfg(target_os = "linux")]
async fn wait_for_tun_tx(metrics: &Observability, at_least: u64) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics.snapshot().dataplane.tun_tx_packets >= at_least {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed out waiting for TUN writes");
}

/// Read physical payloads until one decrypts; returns its direction and
/// plaintext. Frames that fail authentication belong to other circuits and
/// are skipped.
#[cfg(target_os = "linux")]
async fn recv_decrypted_datagram(
    link: &Arc<Link>,
    receiver: &mut crate::crypto::ReceiverSessions,
) -> (crypto::DataDirection, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = link.recv_physical().await.expect("physical receive failed");
            let crate::physical::PhysicalPayload::Forward(frame) = frame else {
                continue;
            };
            if let Ok((_circuit, direction, _source, packet)) = receiver.open_data(&frame) {
                return (direction, packet);
            }
        }
    })
    .await
    .expect("timed out waiting for an encrypted datagram")
}

#[cfg(target_os = "linux")]
fn test_receive_context(
    metrics: Arc<Observability>,
    supervisor: &DaemonSupervisor,
) -> SecureReceiveContext {
    SecureReceiveContext {
        identity: Arc::new(identity::generate()),
        egress: None,
        source_policy: SourceAddressPolicy::default(),
        metrics,
        authorizations: CircuitAuthorizations::default(),
        relay_labels: RelayLabelTables::default(),
        sessions: SessionManager::default(),
        circuit_router: Arc::new(crate::circuit::Router::new(
            "receiver",
            crate::policy::TransitPolicy::new(false, HashMap::new()),
            Arc::new(std::sync::Mutex::new(HashMap::new())),
        )),
        circuit_opens: CircuitOpenManager::default(),
        return_flows: crate::return_path::ReturnFlowTable::default(),
        circuit_dns: CircuitDnsClient::default(),
        supervisor: supervisor.clone(),
    }
}

#[cfg(target_os = "linux")]
fn test_inbound_dispatch(identity: Arc<SigningKey>) -> InboundDispatch {
    InboundDispatch {
        identity,
        authorizations: CircuitAuthorizations::default(),
        relay_labels: RelayLabelTables::default(),
        sessions: SessionManager::default(),
        cancellation: CancellationToken::new(),
        circuit_opens: CircuitOpenManager::default(),
        circuit_router: Arc::new(crate::circuit::Router::new(
            "receiver",
            crate::policy::TransitPolicy::new(false, HashMap::new()),
            Arc::new(std::sync::Mutex::new(HashMap::new())),
        )),
        circuit_dns: CircuitDnsClient::default(),
    }
}

#[cfg(target_os = "linux")]
fn dns_query_wire(id: u16, domain: &str) -> Vec<u8> {
    let mut query = hickory_proto::op::Message::query();
    query.metadata.id = id;
    query.queries.push(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_ascii(domain).unwrap(),
        hickory_proto::rr::RecordType::A,
    ));
    query.to_vec().unwrap()
}

#[cfg(target_os = "linux")]
fn dns_a_response_wire(request_wire: &[u8], answer: Ipv4Addr) -> Vec<u8> {
    let request = hickory_proto::op::Message::from_vec(request_wire).unwrap();
    let mut response =
        hickory_proto::op::Message::response(request.metadata.id, request.metadata.op_code);
    response.queries = request.queries;
    let name = response.queries[0].name.clone();
    response.answers.push(hickory_proto::rr::Record::from_rdata(
        name,
        300,
        hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(answer)),
    ));
    response.to_vec().unwrap()
}

#[cfg(target_os = "linux")]
async fn query_fake_dns(
    client: &tokio::net::UdpSocket,
    server: std::net::SocketAddr,
    wire: Vec<u8>,
) -> hickory_proto::op::Message {
    client.send_to(&wire, server).await.unwrap();
    let mut buffer = vec![0_u8; 512];
    let size = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    hickory_proto::op::Message::from_vec(&buffer[..size]).unwrap()
}

/// `spawn_tun_link` bridges a TUN to one authenticated Link in both
/// directions: kernel packets leave as Forward frames, inbound frames are
/// source-filtered and written back to the kernel, a Link whose Forward
/// receiver was already claimed does not start a competing receiver, and the
/// sender worker stops when the closed Link rejects a send.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn single_link_tun_bridge_forwards_filters_and_stops() {
    if skip_unless_privileged() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();
    let device = create_test_tun("tncvln1", "10.66.0.1/32");
    let tun_name = device.name().unwrap();
    let overlay_routes = vec!["10.66.0.0/24".parse().unwrap()];
    crate::platform::install_overlay_routes(&tun_name, &overlay_routes, &[])
        .await
        .unwrap();
    let (client_link, server_link, client_endpoint, server_endpoint) = connected_links().await;
    let (claimed_client, claimed_server, claimed_client_endpoint, claimed_server_endpoint) =
        connected_links().await;
    let claimed_device = create_test_tun("tncvln2", "10.69.0.1/32");

    // A Link whose Forward receiver was already claimed keeps its queue for
    // the earlier owner: the spawned receiver worker must exit at once.
    let mut held_receiver = claimed_client.take_forward_receiver().await;
    assert!(held_receiver.is_some());
    let claimed_supervisor = DaemonSupervisor::default();
    spawn_tun_link(
        claimed_device,
        claimed_client.clone(),
        SourceAddressPolicy::default(),
        claimed_supervisor.clone(),
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while claimed_supervisor.task_count() > 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the claimed-receiver worker must exit immediately");
    let claimed_dispatcher = spawn_forward_dispatcher(claimed_client.clone());
    // Forward payloads carry end-to-end frames, so the physical layer rejects
    // anything shorter than the frame overhead; use a padded probe here.
    let probe_frame = vec![7_u8; 64];
    claimed_server.send_forward(&probe_frame).unwrap();
    let forwarded = tokio::time::timeout(Duration::from_secs(2), async {
        held_receiver.as_mut().unwrap().recv().await
    })
    .await
    .expect("the pre-claimed receiver must keep receiving")
    .expect("the forward queue stays open");
    assert_eq!(forwarded, probe_frame);

    let metrics = Arc::new(Observability::new(0));
    let supervisor = DaemonSupervisor::default();
    spawn_tun_link(
        device.clone(),
        client_link.clone(),
        SourceAddressPolicy::from_bindings(
            vec![("10.77.0.0/24".parse().unwrap(), "other".into())],
            metrics.clone(),
        ),
        supervisor.clone(),
    );

    // Kernel-originated packets are forwarded over the Link untouched. The
    // payload keeps the frame above the physical minimum frame length.
    let outbound = std::net::UdpSocket::bind("10.66.0.1:0").unwrap();
    outbound
        .send_to(b"single-out-payload", "10.66.0.7:5300")
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = server_link.recv_physical().await.unwrap();
            let crate::physical::PhysicalPayload::Forward(frame) = frame else {
                continue;
            };
            // The bridge forwards kernel-generated control traffic as well;
            // skip anything that is not the test packet.
            if frame.len() >= 20 && frame[0] >> 4 == 4 && frame[16..20] == [10, 66, 0, 7] {
                break frame;
            }
            eprintln!(
                "skipping kernel control frame ({} bytes): {:02x?}",
                frame.len(),
                &frame[..frame.len().min(40)]
            );
        }
    })
    .await
    .expect("timed out waiting for the outbound test frame");
    assert_eq!(&frame[16..20], &[10, 66, 0, 7]);
    assert!(frame.ends_with(b"single-out-payload"));

    // Inbound frames with an unrestricted source are written back to the TUN
    // and delivered by the kernel to the matching local socket.
    let dispatcher = spawn_forward_dispatcher(client_link.clone());
    let inbound = tokio::net::UdpSocket::bind("10.66.0.1:9900").await.unwrap();
    server_link
        .send_forward(&ipv4_udp_packet(
            [10, 66, 0, 7],
            [10, 66, 0, 1],
            50000,
            9900,
            b"single-in-payload!",
        ))
        .unwrap();
    let mut buffer = [0_u8; 64];
    let (size, peer) = tokio::time::timeout(Duration::from_secs(2), inbound.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..size], b"single-in-payload!");
    assert_eq!(peer, "10.66.0.7:50000".parse().unwrap());

    // A bound prefix owned by another identity is filtered before the TUN.
    server_link
        .send_forward(&ipv4_udp_packet(
            [10, 77, 0, 9],
            [10, 66, 0, 1],
            50001,
            9900,
            b"denied-payload-000",
        ))
        .unwrap();
    wait_for_rejection(&metrics, "source_binding:denied").await;

    // Once the Link is closed, the next outbound packet fails the send and
    // stops the sender worker.
    client_link.close("single-link bridge test complete");
    outbound
        .send_to(b"after-close-payload", "10.66.0.7:5300")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while supervisor.task_count() > 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the sender worker must stop after the Link closed");

    crate::platform::cleanup_overlay_routes(&tun_name, &overlay_routes)
        .await
        .unwrap();
    server_link.close("single-link bridge test complete");
    client_endpoint.close(0u32.into(), b"single-link bridge test complete");
    server_endpoint.close(0u32.into(), b"single-link bridge test complete");
    claimed_client.close("claimed receiver test complete");
    claimed_server.close("claimed receiver test complete");
    claimed_client_endpoint.close(0u32.into(), b"claimed receiver test complete");
    claimed_server_endpoint.close(0u32.into(), b"claimed receiver test complete");
    join_task(dispatcher, "single-link dispatcher")
        .await
        .unwrap();
    join_task(claimed_dispatcher, "claimed-link dispatcher")
        .await
        .unwrap();
    supervisor.shutdown(Duration::from_secs(1)).await.unwrap();
    claimed_supervisor
        .shutdown(Duration::from_secs(1))
        .await
        .unwrap();
}

/// Relayed frames are forwarded opaquely to the next-hop Link and relay
/// failures stay contained; an authenticated frame for a circuit with no
/// installed session produces CircuitBroken feedback on the reverse control
/// stream. A Link with a pre-claimed Forward receiver must not start a
/// working receiver.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn secure_receive_relays_frames_and_reports_unknown_sessions() {
    if skip_unless_privileged() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();
    let device = create_test_tun("tncvr2", "10.68.0.1/32");
    let (client_link, server_link, client_endpoint, server_endpoint) = connected_links().await;
    let (relay_client, relay_server, relay_client_endpoint, relay_server_endpoint) =
        connected_links().await;
    let dispatcher = spawn_forward_dispatcher(server_link.clone());

    let relay_circuit = CircuitId([251; 16]);
    let relay_labels = RelayLabelTables::default();
    let table = Arc::new(std::sync::RwLock::new(LabelTable::default()));
    let outgoing: crate::link::LinkRef = relay_client.clone();
    table
        .write()
        .unwrap()
        .install(relay_circuit, outgoing)
        .unwrap();
    relay_labels
        .write()
        .unwrap()
        .insert(server_link.instance(), table);

    let metrics = Arc::new(Observability::new(0));
    let supervisor = DaemonSupervisor::default();
    let mut context = test_receive_context(metrics.clone(), &supervisor);
    context.relay_labels = relay_labels;
    let receive_task = tokio::spawn(receive_secure_link(
        device.clone(),
        server_link.clone(),
        context,
        FakeIpDisabled,
    ));

    // A frame whose label matches the relay table is forwarded untouched.
    let mut relay_sender =
        crypto::SenderSession::from_key(relay_circuit, chacha20poly1305::Key::from([252; 32]));
    let relay_frame = relay_sender.encrypt(b"relay me").unwrap().to_vec();
    client_link.send_forward(&relay_frame).unwrap();
    let forwarded = tokio::time::timeout(Duration::from_secs(2), relay_server.recv_physical())
        .await
        .unwrap()
        .unwrap();
    let crate::physical::PhysicalPayload::Forward(forwarded) = forwarded else {
        panic!("expected the relayed Forward payload");
    };
    assert_eq!(forwarded, relay_frame);

    // A relay whose outgoing Link is closed keeps the receive loop alive.
    relay_client.close("relay target closed");
    tokio::time::timeout(Duration::from_secs(2), relay_client.wait_closed())
        .await
        .unwrap();
    let lost_frame = relay_sender.encrypt(b"relay lost").unwrap().to_vec();
    client_link.send_forward(&lost_frame).unwrap();

    // A well-formed frame for a circuit with no installed session produces
    // authenticated CircuitBroken feedback to the sender; observing it also
    // proves the loop processed the failed relay send above.
    let unknown_circuit = CircuitId([253; 16]);
    let mut unknown_sender =
        crypto::SenderSession::from_key(unknown_circuit, chacha20poly1305::Key::from([254; 32]));
    send_encrypted(&client_link, &mut unknown_sender, b"no session").await;
    let message = tokio::time::timeout(Duration::from_secs(2), client_link.recv_control())
        .await
        .unwrap()
        .unwrap();
    let crate::control::ControlMessage::CircuitBroken {
        circuit_id,
        reason_code,
        ..
    } = message
    else {
        panic!("expected CircuitBroken feedback, got {message:?}");
    };
    assert_eq!(circuit_id, unknown_circuit);
    assert_eq!(reason_code, crate::control::CIRCUIT_UNKNOWN_SESSION_REASON);

    // A Link whose Forward receiver was claimed elsewhere exits immediately.
    let (claimed_client, claimed_server, claimed_client_endpoint, claimed_server_endpoint) =
        connected_links().await;
    let _held = claimed_server.take_forward_receiver().await;
    let claimed = tokio::time::timeout(
        Duration::from_secs(2),
        receive_secure_link(
            device,
            claimed_server.clone(),
            test_receive_context(metrics.clone(), &supervisor),
            FakeIpDisabled,
        ),
    )
    .await;
    assert!(claimed.is_ok(), "claimed-receiver receive must return");

    server_link.close("relay and feedback test complete");
    client_link.close("relay and feedback test complete");
    client_endpoint.close(0u32.into(), b"relay and feedback test complete");
    server_endpoint.close(0u32.into(), b"relay and feedback test complete");
    relay_server.close("relay and feedback test complete");
    relay_client_endpoint.close(0u32.into(), b"relay and feedback test complete");
    relay_server_endpoint.close(0u32.into(), b"relay and feedback test complete");
    claimed_client.close("claimed receive test complete");
    claimed_client_endpoint.close(0u32.into(), b"claimed receive test complete");
    claimed_server_endpoint.close(0u32.into(), b"claimed receive test complete");
    join_task(receive_task, "relay receive task").await.unwrap();
    join_task(dispatcher, "relay dispatcher").await.unwrap();
    supervisor.shutdown(Duration::from_secs(1)).await.unwrap();
}

/// Exit-side DNS failure handling: upstream errors are reported back as
/// status-1 chunks, a missing return-flow key rejects the answer, and an
/// answer produced after the Link closed is dropped with an explicit
/// rejection. FakeIP forward packets are tracked for the return path before
/// they are written to the TUN.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn secure_receive_dns_failures_and_fake_forward_return_tracking() {
    if skip_unless_privileged() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();
    let device = create_test_tun("tncvr2b", "10.67.0.1/32");
    let tun_name = device.name().unwrap();
    let overlay_routes = vec!["10.67.0.0/24".parse().unwrap()];
    crate::platform::install_overlay_routes(&tun_name, &overlay_routes, &[])
        .await
        .unwrap();
    let (client_link, server_link, client_endpoint, server_endpoint) = connected_links().await;
    let dispatcher = spawn_forward_dispatcher(server_link.clone());

    let source_key = identity::generate();
    let source_public = identity::encode_public(&source_key.verifying_key());
    let metrics = Arc::new(Observability::new(0));
    let supervisor = DaemonSupervisor::default();
    let sessions = SessionManager::default();
    let authorizations = CircuitAuthorizations::default();
    let return_flows = crate::return_path::ReturnFlowTable::default();
    let mut context = test_receive_context(metrics.clone(), &supervisor);
    context.egress = Some(EgressPolicy {
        names: Arc::new(HashMap::from([(source_public.clone(), "source".into())])),
        allowed_routes: Arc::new(vec![crate::config::AllowedRoute {
            allow: vec!["127.0.0.0/8".parse().unwrap()],
            deny: Vec::new(),
            r#for: crate::config::RouteSourceSelector::Keyword("any_known".into()),
        }]),
        allowed_local_ports: Arc::new(Vec::new()),
        local_addresses: Arc::new(vec!["10.67.0.1/32".parse().unwrap()]),
        metrics: metrics.clone(),
    });
    context.sessions = sessions.clone();
    context.authorizations = authorizations.clone();
    context.return_flows = return_flows.clone();
    let receive_task = tokio::spawn(receive_secure_link(
        device.clone(),
        server_link.clone(),
        context,
        FakeIpDisabled,
    ));

    // FakeIP forward packets: a UDP packet without its transport header
    // passes the egress ACL but cannot be tracked for the return path, while
    // a trackable UDP flow is written to the TUN with return-path state
    // installed.
    let local_socket = tokio::net::UdpSocket::bind("10.67.0.1:9999").await.unwrap();
    let track_circuit = CircuitId([161; 16]);
    let track_key = chacha20poly1305::Key::from([162; 32]);
    sessions
        .install_open(
            server_link.instance(),
            track_circuit,
            source_key.verifying_key(),
            track_key,
        )
        .await;
    authorizations
        .install(server_link.instance(), track_circuit, source_public.clone())
        .await
        .unwrap();
    let mut track_sender = crypto::SenderSession::from_key(track_circuit, track_key);
    // The IPv4 header claims UDP but the datagram ends before the transport
    // header: the egress ACL can still authorize it, while return-path
    // tracking cannot extract a flow and must reject it.
    let mut untrackable = ipv4_udp_packet([10, 67, 0, 2], [10, 67, 0, 1], 0, 0, b"");
    untrackable.truncate(20);
    untrackable[2..4].copy_from_slice(&20_u16.to_be_bytes());
    finish_ipv4_header(&mut untrackable);
    send_encrypted(
        &client_link,
        &mut track_sender,
        &crate::fake_ip::encode_fake_ip_envelope(&untrackable, "198.18.0.1".parse().unwrap()),
    )
    .await;
    wait_for_rejection(&metrics, "return_path:track_failed").await;
    let udp_packet = ipv4_udp_packet([10, 67, 0, 2], [10, 67, 0, 1], 40000, 9999, b"tracked");
    send_encrypted(
        &client_link,
        &mut track_sender,
        &crate::fake_ip::encode_fake_ip_envelope(&udp_packet, "198.18.0.1".parse().unwrap()),
    )
    .await;
    let mut buffer = [0_u8; 64];
    let (size, peer) =
        tokio::time::timeout(Duration::from_secs(2), local_socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buffer[..size], b"tracked");
    assert_eq!(peer, "10.67.0.2:40000".parse().unwrap());

    // A failed upstream exchange is reported as a status-1 DNS return chunk.
    let dns_circuit = CircuitId([163; 16]);
    let dns_key = chacha20poly1305::Key::from([164; 32]);
    sessions
        .install_open(
            server_link.instance(),
            dns_circuit,
            source_key.verifying_key(),
            dns_key,
        )
        .await;
    authorizations
        .install(server_link.instance(), dns_circuit, source_public.clone())
        .await
        .unwrap();
    return_flows.install_circuit(server_link.instance(), dns_circuit, dns_key);
    let mut dns_sender = crypto::SenderSession::dns_from_key(dns_circuit, dns_key);
    let dead_upstream =
        crate::config::DnsServer::from_socket_addr("127.0.0.1:15370".parse().unwrap());
    let query = encode_dns_query(41, &dead_upstream, &dns_query_wire(9, "dead.test.")).unwrap();
    send_encrypted(&client_link, &mut dns_sender, &query).await;
    let mut reader = crypto::ReceiverSessions::default();
    reader.install_return(dns_circuit, source_key.verifying_key(), dns_key);
    let opened = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = client_link.recv_physical().await.unwrap();
            let crate::physical::PhysicalPayload::Forward(frame) = frame else {
                continue;
            };
            if let Ok(opened) = reader.open_data(&frame) {
                break opened;
            }
        }
    })
    .await
    .expect("timed out waiting for the DNS error chunk");
    assert_eq!(opened.1, crypto::DataDirection::DnsReturn);
    let (token, status, _index, _total, _chunk) = decode_dns_response(&opened.3).unwrap();
    assert_eq!((token, status), (41, 1));

    // Without an installed return-flow key the DNS answer cannot be
    // encrypted and is rejected.
    let keyless_circuit = CircuitId([165; 16]);
    let keyless_key = chacha20poly1305::Key::from([166; 32]);
    sessions
        .install_open(
            server_link.instance(),
            keyless_circuit,
            source_key.verifying_key(),
            keyless_key,
        )
        .await;
    authorizations
        .install(
            server_link.instance(),
            keyless_circuit,
            source_public.clone(),
        )
        .await
        .unwrap();
    let mut keyless_sender = crypto::SenderSession::dns_from_key(keyless_circuit, keyless_key);
    let query = encode_dns_query(42, &dead_upstream, &dns_query_wire(10, "dead.test.")).unwrap();
    send_encrypted(&client_link, &mut keyless_sender, &query).await;
    wait_for_rejection(&metrics, "dns:return_no_session").await;

    // A DNS answer produced after the Link closed cannot be sent back.
    let slow_socket = tokio::net::UdpSocket::bind("127.0.0.1:15373")
        .await
        .unwrap();
    let (query_seen, query_seen_rx) = oneshot::channel::<()>();
    let slow_upstream = tokio::spawn(async move {
        let mut wire = vec![0_u8; 512];
        let (size, peer) = slow_socket.recv_from(&mut wire).await.unwrap();
        let _ = query_seen.send(());
        tokio::time::sleep(Duration::from_millis(300)).await;
        slow_socket
            .send_to(
                &dns_a_response_wire(&wire[..size], "192.0.2.60".parse().unwrap()),
                peer,
            )
            .await
            .unwrap();
    });
    let closed_circuit = CircuitId([167; 16]);
    let closed_key = chacha20poly1305::Key::from([168; 32]);
    sessions
        .install_open(
            server_link.instance(),
            closed_circuit,
            source_key.verifying_key(),
            closed_key,
        )
        .await;
    authorizations
        .install(
            server_link.instance(),
            closed_circuit,
            source_public.clone(),
        )
        .await
        .unwrap();
    return_flows.install_circuit(server_link.instance(), closed_circuit, closed_key);
    let mut closed_sender = crypto::SenderSession::dns_from_key(closed_circuit, closed_key);
    let slow_upstream_server =
        crate::config::DnsServer::from_socket_addr("127.0.0.1:15373".parse().unwrap());
    let query =
        encode_dns_query(43, &slow_upstream_server, &dns_query_wire(11, "slow.test.")).unwrap();
    send_encrypted(&client_link, &mut closed_sender, &query).await;
    tokio::time::timeout(Duration::from_secs(2), query_seen_rx)
        .await
        .unwrap()
        .unwrap();
    server_link.close("dns return send failure test");
    tokio::time::timeout(Duration::from_secs(2), server_link.wait_closed())
        .await
        .unwrap();
    wait_for_rejection(&metrics, "dns:return_send_failed").await;
    slow_upstream.await.unwrap();

    crate::platform::cleanup_overlay_routes(&tun_name, &overlay_routes)
        .await
        .unwrap();
    client_link.close("dns failure test complete");
    client_endpoint.close(0u32.into(), b"dns failure test complete");
    server_endpoint.close(0u32.into(), b"dns failure test complete");
    join_task(receive_task, "dns failure receive task")
        .await
        .unwrap();
    join_task(dispatcher, "dns failure dispatcher")
        .await
        .unwrap();
    supervisor.shutdown(Duration::from_secs(1)).await.unwrap();
}

/// Source-side router edge paths: fallback gating (not-ready direct egress,
/// DSCP loop guard), fallback-to-secure flow cleanup, unparseable-flow
/// rejection on secure routes, lease/budget rejection before queueing,
/// per-exit worker reuse, return-flow translation outcomes (delivered, FakeIP
/// envelope, missing session, closed target Link), and duplicate attach
/// suppression.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn secure_router_fallback_gates_and_return_flow_edges() {
    if skip_unless_privileged() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();
    let device = create_test_tun("tncvr3", "10.64.0.1/32");
    let tun_name = device.name().unwrap();
    crate::platform::configure_tun_addresses(
        &tun_name,
        &[
            "10.64.0.1/32".parse().unwrap(),
            "192.0.2.1/24".parse().unwrap(),
        ],
    )
    .await
    .unwrap();
    let overlay_routes = vec!["203.0.113.0/24".parse().unwrap()];
    crate::platform::install_overlay_routes(&tun_name, &overlay_routes, &[])
        .await
        .unwrap();

    let (client_link, server_link, client_endpoint, server_endpoint) = connected_links().await;
    let (closed_link, _closed_server, closed_client_endpoint, closed_server_endpoint) =
        connected_links().await;

    let identity = Arc::new(identity::generate());
    let circuit_id = CircuitId([241; 16]);
    let data_key = chacha20poly1305::Key::from([242; 32]);
    let healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let send_gate = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let send_budget = Arc::new(std::sync::atomic::AtomicUsize::new(1500));
    let route = |prefix: &str, circuit: u8, key: u8| SecureRoute {
        prefix: prefix.parse().unwrap(),
        exit: "exit".into(),
        priority: 100,
        link: client_link.clone(),
        circuit_id: CircuitId([circuit; 16]),
        data_key: chacha20poly1305::Key::from([key; 32]),
        destination_key: identity::generate().verifying_key(),
        healthy: healthy.clone(),
        mtu: 1200,
        lease_epoch: 1,
        send_gate: send_gate.clone(),
        send_budget: send_budget.clone(),
    };
    let import = |prefix: &str| crate::config::RouteImport {
        prefix: prefix.parse().unwrap(),
        candidates: vec![crate::config::RouteCandidate {
            node: "exit".into(),
            priority: 100,
        }],
    };
    // The 203.0.113.0/24 import intentionally has no binding yet: it keeps
    // route selection empty while still naming an ensure candidate.
    let snapshot = RouteSnapshot::new(
        vec![route("192.0.2.0/24", 241, 242)],
        vec![import("192.0.2.0/24"), import("203.0.113.0/24")],
    );
    let direct = DirectEgress::open(46, 32129, true).unwrap();
    let metrics = Arc::new(Observability::new(0));
    let return_flows = crate::return_path::ReturnFlowTable::default();
    let supervisor = DaemonSupervisor::default();
    let router = spawn_tun_router_secure(
        device.clone(),
        snapshot,
        vec![client_link.clone()],
        identity.clone(),
        RouterEgress {
            remote: None,
            source_policy: SourceAddressPolicy::default(),
            direct: Some(direct.clone()),
            clamp_mss: false,
            fake_ip: None,
            return_flows: return_flows.clone(),
        },
        metrics.clone(),
        test_inbound_dispatch(identity.clone()),
        supervisor.clone(),
    );
    let mut reader = crypto::ReceiverSessions::default();
    reader.install(circuit_id, identity.verifying_key(), data_key);
    reader.install(
        CircuitId([245; 16]),
        identity.verifying_key(),
        chacha20poly1305::Key::from([246; 32]),
    );
    reader.install_return(circuit_id, identity.verifying_key(), data_key);

    let socket = std::net::UdpSocket::bind("192.0.2.1:0").unwrap();

    // No route and a not-yet-ready direct egress: the packet requests circuit
    // establishment and is rejected with explicit reasons.
    socket.send_to(b"not-ready", "203.0.113.77:53").unwrap();
    wait_for_rejection(&metrics, "route:no_healthy_candidate").await;
    wait_for_rejection(&metrics, "route:direct_not_ready").await;

    // Once ready, direct fallback reinjects the packet into the TUN.
    direct.activate();
    socket.send_to(b"fallback", "203.0.113.77:53").unwrap();
    wait_for_tun_tx(&metrics, 1).await;

    // A packet already carrying the marker DSCP is a reinjection loop and
    // must be dropped instead of forwarded again.
    let loop_socket = std::net::UdpSocket::bind("192.0.2.1:0").unwrap();
    {
        use std::os::fd::AsRawFd;
        let tos: libc::c_int = 46 << 2;
        let result = unsafe {
            libc::setsockopt(
                loop_socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &tos as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&tos) as libc::socklen_t,
            )
        };
        assert_eq!(
            result,
            0,
            "setsockopt IP_TOS: {}",
            std::io::Error::last_os_error()
        );
    }
    loop_socket.send_to(b"loop", "203.0.113.78:53").unwrap();
    wait_for_rejection(&metrics, "route:direct_loop").await;

    // A flow that was fallback-routed is cleaned from conntrack tracking when
    // a secure route appears, and its next packet takes the overlay.
    let recovery_socket = std::net::UdpSocket::bind("192.0.2.1:0").unwrap();
    recovery_socket
        .send_to(b"fallback-first", "203.0.113.8:443")
        .unwrap();
    wait_for_tun_tx(&metrics, 2).await;
    router
        .replace_routes(RouteSnapshot::new(
            vec![
                route("192.0.2.0/24", 241, 242),
                route("203.0.113.8/32", 245, 246),
            ],
            vec![
                import("192.0.2.0/24"),
                import("203.0.113.0/24"),
                import("203.0.113.8/32"),
            ],
        ))
        .await;
    recovery_socket
        .send_to(b"secure-now", "203.0.113.8:443")
        .unwrap();
    let (direction, packet) = recv_decrypted_datagram(&server_link, &mut reader).await;
    assert_eq!(direction, crypto::DataDirection::Forward);
    assert_eq!(&packet[16..20], &[203, 0, 113, 8]);
    assert!(packet.ends_with(b"secure-now"));
    assert!(
        !metrics
            .snapshot()
            .acl_rejections
            .contains_key("route:direct_cleanup_failed")
    );

    // A packet without a parseable transport flow (here AH, injected through
    // a raw socket) matches a secure route but cannot be forwarded or tracked
    // for the return path, so it is rejected before queueing.
    let raw_socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    assert!(
        raw_socket >= 0,
        "raw socket: {}",
        std::io::Error::last_os_error()
    );
    let mut ah_wire = ipv4_udp_packet([192, 0, 2, 1], [192, 0, 2, 7], 0, 0, b"");
    ah_wire.truncate(20);
    ah_wire[2..4].copy_from_slice(&20_u16.to_be_bytes());
    ah_wire[9] = 51;
    finish_ipv4_header(&mut ah_wire);
    let raw_destination = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([192, 0, 2, 7]).to_be(),
        },
        sin_zero: [0; 8],
    };
    let sent = unsafe {
        libc::sendto(
            raw_socket,
            ah_wire.as_ptr().cast(),
            ah_wire.len(),
            0,
            (&raw_destination as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(
        sent,
        ah_wire.len() as isize,
        "raw sendto: {}",
        std::io::Error::last_os_error()
    );
    unsafe { libc::close(raw_socket) };
    wait_for_rejection(&metrics, "packet:unsupported_or_malformed").await;

    // Lease gate and budget rejections happen before the packet is queued.
    send_gate.store(false, Ordering::Release);
    socket.send_to(b"gated", "192.0.2.7:53").unwrap();
    wait_for_rejection(&metrics, "lease:not_ready").await;
    send_gate.store(true, Ordering::Release);
    send_budget.store(10, Ordering::Release);
    socket.send_to(b"over-budget", "192.0.2.7:53").unwrap();
    wait_for_rejection(&metrics, "packet:exceeds_path_mtu").await;
    send_budget.store(1500, Ordering::Release);

    // Healthy packets reuse the per-exit sender worker.
    socket.send_to(b"secure-1", "192.0.2.7:53").unwrap();
    let (direction, packet) = recv_decrypted_datagram(&server_link, &mut reader).await;
    assert_eq!(direction, crypto::DataDirection::Forward);
    assert!(packet.ends_with(b"secure-1"));
    socket.send_to(b"secure-2", "192.0.2.7:53").unwrap();
    let (direction, packet) = recv_decrypted_datagram(&server_link, &mut reader).await;
    assert_eq!(direction, crypto::DataDirection::Forward);
    assert!(packet.ends_with(b"secure-2"));

    // Return-path flows are translated and encrypted before routing. The
    // reply re-entering the TUN is encrypted back onto the originating Link.
    // Keep the fixture above the privileged-port range; some CI runners run
    // root inside a user namespace without CAP_NET_BIND_SERVICE.
    let reply_socket = std::net::UdpSocket::bind("192.0.2.1:15353").unwrap();
    let mut forward_one = ipv4_udp_packet([192, 0, 2, 5], [192, 0, 2, 1], 40000, 15353, b"one");
    return_flows
        .track_forward(&mut forward_one, None, client_link.clone(), circuit_id)
        .unwrap();
    return_flows.install_circuit(client_link.instance(), circuit_id, data_key);
    reply_socket
        .send_to(b"return-one", "192.0.2.5:40000")
        .unwrap();
    let (direction, packet) = recv_decrypted_datagram(&server_link, &mut reader).await;
    assert_eq!(direction, crypto::DataDirection::Return);
    assert_eq!(&packet[16..20], &[192, 0, 2, 5]);
    assert!(packet.ends_with(b"return-one"));

    // A flow tracked with a FakeIP destination wraps the return payload in
    // the FakeIP envelope.
    let mut forward_two = ipv4_udp_packet([192, 0, 2, 6], [192, 0, 2, 1], 40001, 15353, b"two");
    return_flows
        .track_forward(
            &mut forward_two,
            Some("198.18.0.10".parse().unwrap()),
            client_link.clone(),
            circuit_id,
        )
        .unwrap();
    reply_socket
        .send_to(b"return-two", "192.0.2.6:40001")
        .unwrap();
    let (direction, packet) = recv_decrypted_datagram(&server_link, &mut reader).await;
    assert_eq!(direction, crypto::DataDirection::Return);
    let mut envelope = packet;
    assert_eq!(
        crate::fake_ip::decode_fake_ip_envelope(&mut envelope),
        Ok(Some("198.18.0.10".parse().unwrap()))
    );
    assert!(envelope.ends_with(b"return-two"));

    // A flow without an installed circuit key cannot be encrypted.
    let keyless_circuit = CircuitId([247; 16]);
    let mut forward_three = ipv4_udp_packet([192, 0, 2, 9], [192, 0, 2, 1], 40002, 15353, b"three");
    return_flows
        .track_forward(
            &mut forward_three,
            None,
            client_link.clone(),
            keyless_circuit,
        )
        .unwrap();
    reply_socket
        .send_to(b"return-three", "192.0.2.9:40002")
        .unwrap();
    wait_for_rejection(&metrics, "return_path:no_session").await;

    // A flow whose target Link is closed reports the send failure.
    let closed_circuit = CircuitId([248; 16]);
    let closed_key = chacha20poly1305::Key::from([249; 32]);
    let mut forward_four = ipv4_udp_packet([192, 0, 2, 10], [192, 0, 2, 1], 40003, 15353, b"four");
    return_flows
        .track_forward(&mut forward_four, None, closed_link.clone(), closed_circuit)
        .unwrap();
    return_flows.install_circuit(closed_link.instance(), closed_circuit, closed_key);
    closed_link.close("return target closed");
    tokio::time::timeout(Duration::from_secs(2), closed_link.wait_closed())
        .await
        .unwrap();
    reply_socket
        .send_to(b"return-four", "192.0.2.10:40003")
        .unwrap();
    wait_for_rejection(&metrics, "return_path:send_failed").await;

    // Re-attaching an already-installed Link is a no-op. The marker attach is
    // processed after the duplicate (FIFO), so observing two unknown-session
    // rejections proves the duplicate was skipped instead of double-spawning.
    let (dup_client, dup_server, dup_client_endpoint, dup_server_endpoint) =
        connected_links().await;
    let (marker_client, marker_server, marker_client_endpoint, marker_server_endpoint) =
        connected_links().await;
    let dup_dispatcher = spawn_forward_dispatcher(dup_client.clone());
    let marker_dispatcher = spawn_forward_dispatcher(marker_client.clone());
    router.attach_link(dup_client.clone());
    router.attach_link(dup_client.clone());
    router.attach_link(marker_client.clone());
    let mut dup_sender =
        crypto::SenderSession::from_key(CircuitId([250; 16]), chacha20poly1305::Key::from([5; 32]));
    send_encrypted(&dup_server, &mut dup_sender, b"unknown-dup").await;
    send_encrypted(&marker_server, &mut dup_sender, b"unknown-marker").await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics
                .snapshot()
                .acl_rejections
                .get("crypto:no_session")
                .is_some_and(|count| *count >= 2)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both attached links must start receive workers");

    router.shutdown().await;
    crate::platform::cleanup_overlay_routes(&tun_name, &overlay_routes)
        .await
        .unwrap();
    client_link.close("router edge test complete");
    server_link.close("router edge test complete");
    client_endpoint.close(0u32.into(), b"router edge test complete");
    server_endpoint.close(0u32.into(), b"router edge test complete");
    closed_client_endpoint.close(0u32.into(), b"router edge test complete");
    closed_server_endpoint.close(0u32.into(), b"router edge test complete");
    dup_client.close("router edge test complete");
    dup_server.close("router edge test complete");
    dup_client_endpoint.close(0u32.into(), b"router edge test complete");
    dup_server_endpoint.close(0u32.into(), b"router edge test complete");
    marker_client.close("router edge test complete");
    marker_server.close("router edge test complete");
    marker_client_endpoint.close(0u32.into(), b"router edge test complete");
    marker_server_endpoint.close(0u32.into(), b"router edge test complete");
    join_task(dup_dispatcher, "duplicate-link dispatcher")
        .await
        .unwrap();
    join_task(marker_dispatcher, "marker-link dispatcher")
        .await
        .unwrap();
    supervisor.shutdown(Duration::from_secs(1)).await.unwrap();
}

/// FakeIP direct fallback round trip: overlay DNS resolution runs on the
/// router's dispatch task, fake-destination traffic is translated onto the
/// direct path and reinjected, and the reply is restored back onto the
/// original client flow. Multicast-resolved destinations are left to the
/// ordinary drop path and unknown fake addresses are rejected early.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fake_ip_direct_fallback_round_trip_restores_client_flow() {
    if skip_unless_privileged() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();

    // The upstream answers example.test and mc.test, then closes its port so
    // the dead.test query fails.
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:15371")
        .await
        .unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut wire = vec![0_u8; 512];
        for _ in 0..2 {
            let (size, peer) = upstream_socket.recv_from(&mut wire).await.unwrap();
            let request = hickory_proto::op::Message::from_vec(&wire[..size]).unwrap();
            let answer = if request.queries[0].name.to_ascii().starts_with("mc.") {
                "224.0.0.251".parse().unwrap()
            } else {
                "192.0.2.55".parse().unwrap()
            };
            upstream_socket
                .send_to(&dns_a_response_wire(&wire[..size], answer), peer)
                .await
                .unwrap();
        }
    });

    let mut loader = crate::route_sets::RouteSetLoader::new(".");
    let site_id = loader
        .load_inline("example.test\ndead.test\nmc.test")
        .unwrap();
    let registry = Arc::new(loader.finish());
    let metrics = Arc::new(Observability::new(0));
    let runtime = Arc::new(crate::fake_ip::FakeIpRuntime::new(
        crate::config::FakeIpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream_dns: vec![crate::config::DnsServer::from_socket_addr(
                "127.0.0.1:15371".parse().unwrap(),
            )],
            disable_ipv6: true,
            ipv4_pool: "198.18.0.0/15".parse().unwrap(),
            ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
            min_cache_ttl_secs: 60,
            max_cache_ttl_secs: 3600,
            max_entries: 32,
        },
        registry.clone(),
        vec![site_id],
        vec!["10.64.0.1".parse().unwrap()],
        metrics.clone(),
    ));
    let (dns_udp, dns_tcp) = runtime.bind().await.unwrap();
    let dns_address = dns_udp.local_addr().unwrap();
    let dns_cancellation = CancellationToken::new();
    let dns_task = tokio::spawn(runtime.clone().serve_bound(
        dns_udp,
        dns_tcp,
        dns_cancellation.clone(),
    ));

    let device = create_test_tun("tncvf5", "10.64.0.1/32");
    let tun_name = device.name().unwrap();
    crate::platform::configure_tun_addresses(
        &tun_name,
        &[
            "10.64.0.1/32".parse().unwrap(),
            "192.0.2.55/32".parse().unwrap(),
        ],
    )
    .await
    .unwrap();
    let overlay_routes = vec!["198.18.0.0/15".parse().unwrap()];
    crate::platform::install_overlay_routes(&tun_name, &overlay_routes, &[])
        .await
        .unwrap();

    let direct = DirectEgress::open(46, 32130, true).unwrap();
    direct.activate();
    let identity = Arc::new(identity::generate());
    let supervisor = DaemonSupervisor::default();
    let snapshot = RouteSnapshot::new_with_domains(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        registry.clone(),
    )
    .with_direct_routes(Vec::new(), vec![(site_id, 200)]);
    let router = spawn_tun_router_secure(
        device.clone(),
        snapshot,
        // The snapshot carries no bindings, so the old initial-link set was
        // empty as well.
        Vec::new(),
        identity.clone(),
        RouterEgress {
            remote: None,
            source_policy: SourceAddressPolicy::default(),
            direct: Some(direct),
            clamp_mss: false,
            fake_ip: Some(runtime.clone()),
            return_flows: crate::return_path::ReturnFlowTable::default(),
        },
        metrics.clone(),
        test_inbound_dispatch(identity),
        supervisor.clone(),
    );

    let dns_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query_runtime = |wire: Vec<u8>| query_fake_dns(&dns_client, dns_address, wire);

    // Overlay DNS resolution allocates a fake address through the router's
    // dispatch task.
    let response = query_runtime(dns_query_wire(42, "example.test.")).await;
    let Some(hickory_proto::rr::RData::A(fake_record)) =
        response.answers.first().map(|record| &record.data)
    else {
        panic!("expected a fake A record, got {response:?}");
    };
    let fake_address = IpAddr::V4(fake_record.0);
    assert!(runtime.contains_fake_address(fake_address));

    // The multicast-resolved domain still allocates a fake address, but its
    // traffic will not be eligible for direct fallback.
    let response = query_runtime(dns_query_wire(43, "mc.test.")).await;
    let Some(hickory_proto::rr::RData::A(multicast_record)) =
        response.answers.first().map(|record| &record.data)
    else {
        panic!("expected a fake A record, got {response:?}");
    };
    let multicast_fake = IpAddr::V4(multicast_record.0);
    assert!(runtime.contains_fake_address(multicast_fake));
    upstream_task.await.unwrap();

    // A matched domain whose upstream is gone surfaces as ServFail.
    let response = query_runtime(dns_query_wire(44, "dead.test.")).await;
    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::ServFail
    );

    // Fake-destination traffic is translated and reinjected on the direct
    // path; the local "server" socket receives the translated packet with the
    // fake return anchor as its source.
    let mut buffer = vec![0_u8; 512];
    let server = tokio::net::UdpSocket::bind("192.0.2.55:5353")
        .await
        .unwrap();
    let client = tokio::net::UdpSocket::bind("10.64.0.1:0").await.unwrap();
    let client_port = client.local_addr().unwrap().port();
    client
        .send_to(b"fake-out", std::net::SocketAddr::new(fake_address, 5353))
        .await
        .unwrap();
    let (size, from) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..size], b"fake-out");
    assert_eq!(from, std::net::SocketAddr::new(fake_address, client_port));

    // The reply re-enters the TUN, is restored to the original client flow,
    // and reaches the client socket from the fake address.
    server
        .send_to(
            b"fake-in",
            std::net::SocketAddr::new(fake_address, client_port),
        )
        .await
        .unwrap();
    let (size, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..size], b"fake-in");
    assert_eq!(from, std::net::SocketAddr::new(fake_address, 5353));

    // A resolved multicast destination is not reinjected; it is left to the
    // ordinary drop path (observed indirectly: the FIFO packet stream reaches
    // the unknown-fake rejection below only after this packet was handled).
    client
        .send_to(b"mc", std::net::SocketAddr::new(multicast_fake, 5353))
        .await
        .unwrap();
    // Unknown fake destinations never reach route selection.
    client
        .send_to(
            b"unknown",
            std::net::SocketAddr::new("198.18.9.9".parse().unwrap(), 5353),
        )
        .await
        .unwrap();
    wait_for_rejection(&metrics, "fake_ip:unknown_or_expired").await;

    dns_cancellation.cancel();
    router.shutdown().await;
    crate::platform::cleanup_overlay_routes(&tun_name, &overlay_routes)
        .await
        .unwrap();
    dns_task.abort();
    supervisor.shutdown(Duration::from_secs(1)).await.unwrap();
}

/// End-to-end FakeIP-over-circuit loop: an overlay DNS query is forwarded
/// through an authenticated circuit to the exit's upstream, the answer
/// allocates a fake address with an exit preference, and follow-up traffic to
/// the fake address is encrypted, translated, tracked for the return path,
/// and delivered at the exit. Withdrawing the routes turns further fake
/// traffic into an explicit no-candidate rejection.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fake_ip_overlay_dns_over_circuit_and_routes_fake_traffic() {
    if skip_unless_privileged() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();
    // The exit writes packets whose source address belongs to the source-side
    // TUN of this shared namespace; disable reverse-path filtering for the
    // cross-interface test topology.
    std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0").unwrap();
    std::fs::write("/proc/sys/net/ipv4/conf/default/rp_filter", "0").unwrap();
    // In this shared test namespace the translated source (10.64.0.1) is a
    // local address on the source-side TUN, so the exit-side kernel would
    // drop the delivered packet as a local source without this.
    std::fs::write("/proc/sys/net/ipv4/conf/all/accept_local", "1").unwrap();

    let device_a = create_test_tun("tncvf6a", "10.64.0.1/32");
    let tun_a = device_a.name().unwrap();
    let overlay_routes = vec!["198.18.0.0/15".parse().unwrap()];
    crate::platform::install_overlay_routes(&tun_a, &overlay_routes, &[])
        .await
        .unwrap();
    let device_b = create_test_tun("tncvf6b", "192.0.2.55/32");

    let (client_link, server_link, client_endpoint, server_endpoint) = connected_links().await;
    let dispatcher_a = spawn_forward_dispatcher(client_link.clone());
    let dispatcher_b = spawn_forward_dispatcher(server_link.clone());

    let source_key = identity::generate();
    let source_public = identity::encode_public(&source_key.verifying_key());
    let circuit_id = CircuitId([171; 16]);
    let data_key = chacha20poly1305::Key::from([172; 32]);

    // Exit side: decrypt the circuit, serve DNS through the local upstream,
    // and deliver fake-forward packets to the local TUN.
    let metrics_b = Arc::new(Observability::new(0));
    let supervisor_b = DaemonSupervisor::default();
    let sessions_b = SessionManager::default();
    sessions_b
        .install_open(
            server_link.instance(),
            circuit_id,
            source_key.verifying_key(),
            data_key,
        )
        .await;
    let authorizations_b = CircuitAuthorizations::default();
    authorizations_b
        .install(server_link.instance(), circuit_id, source_public.clone())
        .await
        .unwrap();
    let return_flows_b = crate::return_path::ReturnFlowTable::default();
    return_flows_b.install_circuit(server_link.instance(), circuit_id, data_key);
    let mut context_b = test_receive_context(metrics_b.clone(), &supervisor_b);
    context_b.egress = Some(EgressPolicy {
        names: Arc::new(HashMap::from([(source_public.clone(), "source".into())])),
        allowed_routes: Arc::new(vec![crate::config::AllowedRoute {
            allow: vec!["127.0.0.0/8".parse().unwrap()],
            deny: Vec::new(),
            r#for: crate::config::RouteSourceSelector::Keyword("any_known".into()),
        }]),
        allowed_local_ports: Arc::new(Vec::new()),
        local_addresses: Arc::new(vec!["192.0.2.55/32".parse().unwrap()]),
        metrics: metrics_b.clone(),
    });
    context_b.sessions = sessions_b;
    context_b.authorizations = authorizations_b;
    context_b.return_flows = return_flows_b;
    let receive_b = tokio::spawn(receive_secure_link(
        device_b,
        server_link.clone(),
        context_b,
        FakeIpDisabled,
    ));

    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:15372")
        .await
        .unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut wire = vec![0_u8; 512];
        let (size, peer) = upstream_socket.recv_from(&mut wire).await.unwrap();
        upstream_socket
            .send_to(
                &dns_a_response_wire(&wire[..size], "192.0.2.55".parse().unwrap()),
                peer,
            )
            .await
            .unwrap();
    });

    // Source side: FakeIP runtime, a domain binding over the circuit, and an
    // authorized return path for the DNS response frames.
    let mut loader = crate::route_sets::RouteSetLoader::new(".");
    let site_id = loader.load_inline("example.test").unwrap();
    let registry = Arc::new(loader.finish());
    let metrics_a = Arc::new(Observability::new(0));
    let runtime_a = Arc::new(crate::fake_ip::FakeIpRuntime::new(
        crate::config::FakeIpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream_dns: Vec::new(),
            disable_ipv6: true,
            ipv4_pool: "198.18.0.0/15".parse().unwrap(),
            ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
            min_cache_ttl_secs: 60,
            max_cache_ttl_secs: 3600,
            max_entries: 32,
        },
        registry.clone(),
        vec![site_id],
        vec!["10.64.0.1".parse().unwrap()],
        metrics_a.clone(),
    ));
    let (dns_udp, dns_tcp) = runtime_a.bind().await.unwrap();
    let dns_address = dns_udp.local_addr().unwrap();
    let dns_cancellation = CancellationToken::new();
    let dns_task = tokio::spawn(runtime_a.clone().serve_bound(
        dns_udp,
        dns_tcp,
        dns_cancellation.clone(),
    ));

    let identity_a = Arc::new(identity::generate());
    let sessions_a = SessionManager::default();
    sessions_a
        .install_return(
            client_link.instance(),
            circuit_id,
            source_key.verifying_key(),
            data_key,
        )
        .await;
    let opens_a = CircuitOpenManager::default();
    let waiter = opens_a
        .register(
            client_link.instance(),
            circuit_id,
            source_public.clone(),
            Vec::new(),
            None,
            crate::link::LinkToken::default(),
        )
        .await;
    assert!(
        opens_a
            .resolve(
                client_link.instance(),
                circuit_id,
                &source_public,
                OpenResult::Acknowledged,
            )
            .await
    );
    assert_eq!(waiter.await.unwrap(), OpenResult::Acknowledged);

    let upstream_dns: Arc<[crate::config::DnsServer]> =
        Arc::from(vec![crate::config::DnsServer::from_socket_addr(
            "127.0.0.1:15372".parse().unwrap(),
        )]);
    let binding = SecureRoute {
        prefix: "203.0.113.0/24".parse().unwrap(),
        exit: "exit".into(),
        priority: 100,
        link: client_link.clone(),
        circuit_id,
        data_key,
        destination_key: identity::generate().verifying_key(),
        healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        mtu: 1280,
        lease_epoch: 1,
        send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        send_budget: Arc::new(std::sync::atomic::AtomicUsize::new(1500)),
    };
    let snapshot = RouteSnapshot::new_with_domains(
        Vec::new(),
        Vec::new(),
        vec![(site_id, binding, upstream_dns)],
        Vec::new(),
        registry.clone(),
    );
    let mut inbound_a = test_inbound_dispatch(identity_a.clone());
    inbound_a.sessions = sessions_a;
    inbound_a.circuit_opens = opens_a;
    let supervisor_a = DaemonSupervisor::default();
    let router_a = spawn_tun_router_secure(
        device_a.clone(),
        snapshot,
        vec![client_link.clone()],
        identity_a,
        RouterEgress {
            remote: None,
            source_policy: SourceAddressPolicy::default(),
            direct: None,
            clamp_mss: false,
            fake_ip: Some(runtime_a.clone()),
            return_flows: crate::return_path::ReturnFlowTable::default(),
        },
        metrics_a.clone(),
        inbound_a,
        supervisor_a.clone(),
    );

    // The overlay DNS query travels over the circuit and back; the answer
    // allocates a fake address with the exit preference.
    let dns_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    dns_client
        .send_to(&dns_query_wire(77, "example.test."), dns_address)
        .await
        .unwrap();
    let mut buffer = vec![0_u8; 512];
    let size = tokio::time::timeout(Duration::from_secs(5), dns_client.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let response = hickory_proto::op::Message::from_vec(&buffer[..size]).unwrap();
    let Some(hickory_proto::rr::RData::A(fake_record)) =
        response.answers.first().map(|record| &record.data)
    else {
        panic!("expected a fake A record, got {response:?}");
    };
    let fake_address = IpAddr::V4(fake_record.0);
    assert!(runtime_a.contains_fake_address(fake_address));
    upstream_task.await.unwrap();

    // Traffic to the fake address is encrypted over the circuit and delivered
    // at the exit with the translated source.
    let exit_socket = tokio::net::UdpSocket::bind("192.0.2.55:8080")
        .await
        .unwrap();
    let client = tokio::net::UdpSocket::bind("10.64.0.1:0").await.unwrap();
    let client_port = client.local_addr().unwrap().port();
    client
        .send_to(b"fake-data", std::net::SocketAddr::new(fake_address, 8080))
        .await
        .unwrap();
    let (size, from) = tokio::time::timeout(
        Duration::from_secs(5),
        exit_socket.recv_from(&mut buffer),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for exit delivery; source rejections={:?} exit rejections={:?} source dataplane={:?} exit dataplane={:?}",
            metrics_a.snapshot().acl_rejections,
            metrics_b.snapshot().acl_rejections,
            metrics_a.snapshot().dataplane,
            metrics_b.snapshot().dataplane,
        )
    })
    .unwrap();
    assert_eq!(&buffer[..size], b"fake-data");
    assert_eq!(
        from,
        std::net::SocketAddr::new("10.64.0.1".parse().unwrap(), client_port)
    );

    // Withdrawing the routes leaves the fake hint without any candidate.
    router_a
        .replace_routes(RouteSnapshot::new_with_domains(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            registry,
        ))
        .await;
    client
        .send_to(b"orphaned", std::net::SocketAddr::new(fake_address, 8080))
        .await
        .unwrap();
    wait_for_rejection(&metrics_a, "fake_ip:no_healthy_candidate").await;

    dns_cancellation.cancel();
    router_a.shutdown().await;
    crate::platform::cleanup_overlay_routes(&tun_a, &overlay_routes)
        .await
        .unwrap();
    server_link.close("fake-ip circuit test complete");
    client_link.close("fake-ip circuit test complete");
    client_endpoint.close(0u32.into(), b"fake-ip circuit test complete");
    server_endpoint.close(0u32.into(), b"fake-ip circuit test complete");
    dns_task.abort();
    join_task(receive_b, "exit receive task").await.unwrap();
    join_task(dispatcher_a, "source dispatcher").await.unwrap();
    join_task(dispatcher_b, "exit dispatcher").await.unwrap();
    supervisor_a.shutdown(Duration::from_secs(1)).await.unwrap();
    supervisor_b.shutdown(Duration::from_secs(1)).await.unwrap();
}
