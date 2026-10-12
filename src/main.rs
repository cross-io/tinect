#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tinect::{config::Config, identity, status};

mod daemon;
#[cfg(all(test, target_os = "linux"))]
#[path = "privileged_network_tests.rs"]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test_support;
use daemon::application::up;
use daemon::cli_support::*;
#[cfg(test)]
use daemon::control_handler::{ControlHandlerContext, spawn_control_handler};
#[cfg(test)]
use daemon::physical_dispatch::spawn_physical_dispatcher;
#[cfg(test)]
use daemon::topology_sync::*;

const CLI_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (git ",
    env!("VERGEN_GIT_SHA"),
    ")"
);

#[derive(Parser)]
#[command(
    name = "tinect",
    version = CLI_VERSION,
    about = "A static, policy-driven layer-3 overlay network"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    /// Print the public key derived from an Ed25519 private key.
    Pubkey {
        /// Read the Base64 private key from this file.
        #[arg(long, conflicts_with = "secret")]
        key: Option<PathBuf>,
        /// Base64-encoded Ed25519 private key.
        #[arg(long, conflicts_with = "key")]
        secret: Option<String>,
    },
    Check {
        config: PathBuf,
    },
    Status {
        #[command(flatten)]
        target: DaemonTargetArgs,
    },
    Routes {
        #[command(flatten)]
        target: DaemonTargetArgs,
    },
    Topology {
        #[command(flatten)]
        target: DaemonTargetArgs,
    },
    Pcap {
        #[command(flatten)]
        target: DaemonTargetArgs,
        #[arg(long)]
        output: PathBuf,
    },
    Up {
        config: PathBuf,
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let timing = tinect::timing::initialize().map_err(anyhow::Error::msg)?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tinect=info".into()),
        )
        .with_target(true)
        .with_ansi(false)
        .compact()
        .init();
    if timing.name != "production" {
        tracing::warn!(
            profile = timing.name,
            "integration-test timing profile enabled"
        );
    }
    let cli = Cli::parse();
    run_command(cli.command).await
}

async fn run_command(command: Cmd) -> Result<()> {
    match command {
        Cmd::Keygen { output } => {
            let key = identity::generate();
            identity::save_secret(&output, &key)?;
            println!(
                "node_id: {}\npublic_key: {}",
                identity::node_id(&key.verifying_key()),
                identity::encode_public(&key.verifying_key())
            );
        }
        Cmd::Pubkey { key, secret } => {
            let key = load_identity_argument(key, secret)?;
            println!("{}", identity::encode_public(&key.verifying_key()));
        }
        Cmd::Check { config } => {
            let c = Config::load(config)?;
            println!("valid configuration for {}", c.id)
        }
        Cmd::Status { target } => match resolve_daemon_target(target)? {
            DaemonTarget::Config(c) => {
                let fallback = static_state(&c).status;
                print_daemon_or_fallback(c.status_socket(), "status\n", fallback).await?;
            }
            DaemonTarget::Socket(socket) => print_daemon_reply(socket, "status\n").await?,
        },
        Cmd::Routes { target } => match resolve_daemon_target(target)? {
            DaemonTarget::Config(c) => {
                let fallback = static_state(&c).routes;
                print_daemon_or_fallback(c.status_socket(), "routes\n", fallback).await?;
            }
            DaemonTarget::Socket(socket) => print_daemon_reply(socket, "routes\n").await?,
        },
        Cmd::Topology { target } => match resolve_daemon_target(target)? {
            DaemonTarget::Config(c) => {
                let reply = status::request(c.status_socket(), "topology\n")
                    .await
                    .context("requesting topology")?;
                print!("{}", decode_topology_reply(&reply)?);
            }
            DaemonTarget::Socket(socket) => print_daemon_reply(socket, "topology\n").await?,
        },
        Cmd::Pcap { target, output } => {
            let socket = match resolve_daemon_target(target)? {
                DaemonTarget::Config(c) => c.status_socket(),
                DaemonTarget::Socket(socket) => socket,
            };
            let reply = status::request(socket, "pcap\n")
                .await
                .context("requesting packet capture")?;
            std::fs::write(&output, reply)?;
            println!("wrote {}", output.display());
        }
        Cmd::Up { config, dry_run } => up(config, dry_run).await?,
    }
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::daemon::support::healthy_route_prefixes;
    use crate::daemon::{
        circuit_reconciler::{
            candidate_failure_delay, circuit_open_retry_delay, configured_circuit_destinations,
            desired_resolution_for_candidate, hard_revoke_active_circuit, log_migration_failure,
            nonretryable_rejection_wait, open_configured_circuit, open_configured_circuits,
            record_candidate_failure, secure_dataplane_required, unix_timestamp_secs,
            update_migration_status,
        },
        link_lifecycle::start_links,
        route_snapshot::build_route_snapshot,
    };
    use crate::daemon::{
        circuit_resolution::resolve_destination,
        control_handler::{
            OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION_TEXT, is_local_control_admission,
            is_local_control_admission_rejection, merge_topology_snapshot_request,
            next_snapshot_reassembly_deadline, registered_link_by_instance, wait_for_any_link,
        },
        link_helpers::{
            outbound_attempt_timeout, outbound_bind_address, reconnect_delay,
            reconnect_delay_with_jitter, reconnect_jitter_seed, remove_link_if_current,
        },
        support::{
            MAX_TOPOLOGY_ACK_SEND_ATTEMPTS, TOPOLOGY_ACK_SEND_TIMEOUT, collect_underlay_endpoints,
            display_path, initial_tun_mtu, initial_tun_mtu_from_limits, initial_user_ip_limit,
            initial_user_ip_limit_with_fec, mark_current_link, mark_link, mark_unbound_link,
            observable_name, observable_node_names, path_inner_mtu_from_hops,
            physical_idle_deadline, resolve_quic_endpoint, topology_snapshot_reassembly_timeout,
            unix_now, wire_identity, wire_paths,
        },
        topology_sync::allow_topology_snapshot_request,
    };
    use clap::{CommandFactory, Parser};
    use std::net::SocketAddr;
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
        time::Instant,
    };
    use tinect::circuit::Router;
    use tinect::{
        carrier,
        config::LinkHealthConfig,
        control::ControlMessage,
        dataplane,
        observability::Observability,
        physical::PhysicalPayload,
        runtime::{DaemonSupervisor, Runtime},
        status::MigrationState,
        topology::{LinkStateAdvertisement, Topology},
    };

    #[test]
    fn cli_reports_the_package_version() {
        assert_eq!(Cli::command().get_version(), Some(CLI_VERSION));
    }

    #[test]
    fn snapshot_recovery_requests_are_rate_limited_and_active_requests_merge() {
        let now = Instant::now();
        let mut last = None;
        assert!(allow_topology_snapshot_request(&mut last, now));
        assert!(!allow_topology_snapshot_request(
            &mut last,
            now + std::time::Duration::from_secs(9),
        ));
        assert!(allow_topology_snapshot_request(
            &mut last,
            now + std::time::Duration::from_secs(10),
        ));
        assert!(merge_topology_snapshot_request(true));
        assert!(!merge_topology_snapshot_request(false));
    }

    #[test]
    fn snapshot_reassembly_uses_the_earliest_deadline() {
        let now = Instant::now();
        let mut snapshots = HashMap::new();
        for (sync_id, age) in [(1, 2_u64), (2, 6_u64)] {
            snapshots.insert(
                sync_id,
                SnapshotAssembly {
                    chunks: Vec::new(),
                    bytes: 0,
                    lsa_count: 0,
                    neighbors: 0,
                    started: now
                        .checked_sub(std::time::Duration::from_secs(age))
                        .unwrap(),
                },
            );
        }

        assert_eq!(
            next_snapshot_reassembly_deadline(&snapshots),
            Some(
                snapshots[&2]
                    .started
                    .checked_add(topology_snapshot_reassembly_timeout())
                    .unwrap()
            )
        );
    }

    #[test]
    fn topology_ack_retry_backoff_is_short_and_bounded() {
        assert_eq!(
            topology_ack_retry_delay(0),
            std::time::Duration::from_millis(50)
        );
        assert_eq!(
            topology_ack_retry_delay(1),
            std::time::Duration::from_millis(100)
        );
        assert_eq!(
            topology_ack_retry_delay(2),
            std::time::Duration::from_millis(100)
        );
        assert_eq!(MAX_TOPOLOGY_ACK_SEND_ATTEMPTS, 3);
        assert_eq!(TOPOLOGY_ACK_SEND_TIMEOUT.as_secs(), 1);
    }

    #[test]
    fn read_only_commands_accept_config_socket_or_node() {
        let config = Cli::try_parse_from(["tinect", "status", "node.yaml"]).unwrap();
        assert!(matches!(config.command, Cmd::Status { .. }));
        let socket =
            Cli::try_parse_from(["tinect", "topology", "--socket", "/tmp/a.sock"]).unwrap();
        assert!(matches!(socket.command, Cmd::Topology { .. }));
        let node = Cli::try_parse_from(["tinect", "routes", "--node", "a"]).unwrap();
        assert!(matches!(node.command, Cmd::Routes { .. }));
        assert!(Cli::try_parse_from(["tinect", "status", "node.yaml", "--node", "a"]).is_err());
        assert!(Cli::try_parse_from(["tinect", "reload", "node.yaml"]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn omitted_target_discovers_exactly_one_socket() {
        use std::os::unix::net::UnixListener;

        let directory = tempfile::tempdir().unwrap();
        assert!(discover_daemon_socket_in(directory.path()).is_err());
        let first = directory.path().join("a.sock");
        let _first_listener = UnixListener::bind(&first).unwrap();
        assert_eq!(
            discover_daemon_socket_in(directory.path()).unwrap(),
            first.display().to_string()
        );
        let _second_listener = UnixListener::bind(directory.path().join("b.sock")).unwrap();
        assert!(discover_daemon_socket_in(directory.path()).is_err());
    }

    #[test]
    fn node_target_uses_the_default_socket_without_loading_configuration() {
        let target = resolve_daemon_target(DaemonTargetArgs {
            config: None,
            socket: None,
            node: Some("edge-a".into()),
        })
        .unwrap();
        let DaemonTarget::Socket(socket) = target else {
            panic!("expected socket target");
        };
        assert_eq!(socket, Config::default_status_socket("edge-a"));
        assert!(
            resolve_daemon_target(DaemonTargetArgs {
                config: None,
                socket: None,
                node: Some("../unsafe".into()),
            })
            .is_err()
        );
    }

    #[test]
    fn public_key_can_be_derived_from_a_file_or_inline_secret() {
        let signing_key = identity::generate();
        let expected = signing_key.verifying_key();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.key");
        identity::save_secret(&path, &signing_key).unwrap();

        assert_eq!(
            load_identity_argument(Some(path), None)
                .unwrap()
                .verifying_key(),
            expected
        );
        assert_eq!(
            load_identity_argument(None, Some(identity::encode_secret(&signing_key)))
                .unwrap()
                .verifying_key(),
            expected
        );
    }

    #[test]
    fn public_key_requires_exactly_one_private_key_source() {
        assert!(load_identity_argument(None, None).is_err());
        assert!(load_identity_argument(Some(PathBuf::from("key")), Some("secret".into())).is_err());
    }

    #[test]
    fn reconnect_delay_is_bounded_exponential_backoff() {
        assert_eq!(reconnect_delay(2, 0), std::time::Duration::ZERO);
        assert_eq!(reconnect_delay(2, 1), std::time::Duration::from_millis(100));
        assert_eq!(reconnect_delay(2, 2), std::time::Duration::from_millis(250));
        assert_eq!(reconnect_delay(2, 3), std::time::Duration::from_millis(500));
        assert_eq!(reconnect_delay(2, 4).as_secs(), 2);
        assert_eq!(reconnect_delay(2, 7).as_secs(), 5);
        assert_eq!(reconnect_delay(2, 8).as_secs(), 5);
        assert_eq!(reconnect_delay(2, 9).as_secs(), 5);
        assert_eq!(reconnect_delay(30, u32::MAX).as_secs(), 5);
    }

    #[test]
    fn reconnect_jitter_stays_within_ten_percent_and_is_deterministic() {
        for streak in 1..=12 {
            let base = reconnect_delay(2, streak);
            let jittered = reconnect_delay_with_jitter(2, streak, 42);
            let spread = (base.as_millis() / 10).max(1);
            let lower = base.as_millis().saturating_sub(spread);
            let upper = base.as_millis().saturating_add(spread);
            assert!((lower..=upper).contains(&jittered.as_millis()));
            assert_eq!(jittered, reconnect_delay_with_jitter(2, streak, 42));
            assert!(jittered >= std::time::Duration::from_millis(1));
        }
        assert_ne!(
            reconnect_delay_with_jitter(2, 4, 1),
            reconnect_delay_with_jitter(2, 4, 2)
        );
        assert_ne!(
            reconnect_jitter_seed("edge-a", "quic://127.0.0.1:1"),
            reconnect_jitter_seed("edge-b", "quic://127.0.0.1:1")
        );
    }

    #[test]
    fn circuit_open_retry_is_bounded_and_destination_jittered() {
        for attempt in [0, 1, 8, 9, 16, 100, u32::MAX] {
            let delay = circuit_open_retry_delay("exit-a", attempt);
            assert!((225..=5_500).contains(&delay.as_millis()));
            assert_eq!(delay, circuit_open_retry_delay("exit-a", attempt));
        }
        assert_ne!(
            circuit_open_retry_delay("exit-a", 5),
            circuit_open_retry_delay("exit-b", 5)
        );
    }

    #[test]
    fn local_control_admission_is_transient_for_candidate_reconciliation() {
        assert!(is_local_control_admission(
            &carrier::CarrierError::AdmissionRejected
        ));
        assert!(is_local_control_admission(
            &carrier::CarrierError::ControlStreamTimeout
        ));
        assert!(is_local_control_admission_rejection(
            true,
            OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION_TEXT,
        ));
        assert!(!is_local_control_admission_rejection(
            false,
            OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION_TEXT,
        ));
        assert!(!is_local_control_admission_rejection(true, "code:7"));
    }

    #[test]
    fn candidate_failure_quarantine_is_bounded_and_expires() {
        let identity = tinect::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "relay".into(), "exit".into()],
            first_hop_link_instance: 9,
        };
        let mut failures = HashMap::new();
        record_candidate_failure(&mut failures, "exit", identity.clone());
        let first_retry_at = failures.get(&identity).expect("first failure").retry_at;
        assert!(first_retry_at > Instant::now());
        assert_eq!(failures.get(&identity).expect("first failure").attempts, 1);
        record_candidate_failure(&mut failures, "exit", identity.clone());
        let second = failures.get(&identity).expect("second failure");
        assert!(second.retry_at > first_retry_at);
        assert_eq!(second.attempts, 2);
        assert!(candidate_failure_delay("exit", u32::MAX) <= std::time::Duration::from_secs(61));
    }

    #[test]
    fn nonretryable_rejection_waits_only_for_the_same_circuit_identity() {
        let now = Instant::now();
        let identity = tinect::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 7,
        };
        let mut rejection = Some((identity.clone(), now + std::time::Duration::from_secs(3)));
        assert_eq!(
            nonretryable_rejection_wait(&mut rejection, Some(&identity), now),
            Some(std::time::Duration::from_secs(3)),
        );
        assert!(rejection.is_some());

        let replacement = tinect::reconcile::CircuitIdentity {
            first_hop_link_instance: 8,
            ..identity
        };
        assert_eq!(
            nonretryable_rejection_wait(&mut rejection, Some(&replacement), now),
            None,
        );
        assert!(rejection.is_none());

        let mut expired = Some((replacement.clone(), now - std::time::Duration::from_secs(1)));
        assert!(nonretryable_rejection_wait(&mut expired, Some(&replacement), now).is_none());
        assert!(expired.is_none());
    }

    #[test]
    fn outbound_attempt_timeout_bounds_a_stalled_handshake() {
        let health = LinkHealthConfig {
            keepalive_secs: 10,
            idle_timeout_secs: 35,
            reconnect_interval_secs: 2,
        };
        assert_eq!(outbound_attempt_timeout(&health).as_secs(), 5);

        let zero = LinkHealthConfig {
            keepalive_secs: 1,
            idle_timeout_secs: 0,
            reconnect_interval_secs: 1,
        };
        assert_eq!(outbound_attempt_timeout(&zero).as_secs(), 5);
    }

    #[test]
    fn path_mtu_uses_normalized_user_ip_capacity() {
        assert_eq!(tinect::mtu::user_ip_capacity_from_physical(1200), 1134);
        assert_eq!(tinect::mtu::user_ip_capacity_from_physical(1162), 1096);
        assert_eq!(path_inner_mtu_from_hops(1400, [1300, 1200]), 1200);
    }

    #[test]
    fn physical_idle_deadline_allows_in_flight_keepalive_to_be_received() {
        assert_eq!(
            physical_idle_deadline(
                std::time::Duration::from_secs(35),
                std::time::Duration::from_secs(10),
            ),
            std::time::Duration::from_secs(45)
        );
    }

    #[test]
    fn initial_tun_mtu_never_exceeds_quic_initial_datagram_capacity() {
        assert_eq!(initial_tun_mtu_from_limits(1280), 1096);
    }

    #[test]
    fn initial_tun_mtu_uses_the_minimum_of_mixed_carrier_floors() {
        assert_eq!(initial_user_ip_limit(true, false), 1130);
        assert_eq!(initial_user_ip_limit(false, true), 1096);
        assert_eq!(initial_user_ip_limit(true, true), 1096);
        assert!(initial_user_ip_limit_with_fec(true, true, true) < 1096);
        let mut config = crate::daemon::test_support::minimal_config();
        config.tun.mtu = 1000;
        assert_eq!(initial_tun_mtu(&config), 1000);
    }

    #[test]
    fn outbound_bind_address_matches_resolved_remote_family() {
        let ipv4_listener: SocketAddr = "192.0.2.10:4433".parse().unwrap();
        let ipv6_listener: SocketAddr = "[2001:db8::10]:4433".parse().unwrap();
        let ipv4_remote: SocketAddr = "198.51.100.20:4434".parse().unwrap();
        let ipv6_remote: SocketAddr = "[2001:db8::20]:4434".parse().unwrap();

        assert_eq!(
            outbound_bind_address(ipv4_listener, ipv4_remote),
            "192.0.2.10:0".parse().unwrap()
        );
        assert_eq!(
            outbound_bind_address(ipv4_listener, ipv6_remote),
            "[::]:0".parse().unwrap()
        );
        assert_eq!(
            outbound_bind_address(ipv6_listener, ipv4_remote),
            "0.0.0.0:0".parse().unwrap()
        );
        assert_eq!(
            outbound_bind_address(ipv6_listener, ipv6_remote),
            "[2001:db8::10]:0".parse().unwrap()
        );
    }

    #[test]
    fn operator_identity_helpers_preserve_wire_paths_and_fallback_names() {
        let mut config = crate::daemon::test_support::minimal_config();
        let local_key = identity::generate();
        let peer_key = identity::generate();
        config.identity_key = Some(identity::encode_secret(&local_key));
        config.identity_key_path = None;
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
        let local_identity = config.local_identity().unwrap();
        let peer_identity = config.peer_identity("exit").unwrap();
        assert_eq!(wire_identity(&config, "a"), Some(local_identity.clone()));
        assert_eq!(wire_identity(&config, "exit"), Some(peer_identity.clone()));
        assert_eq!(wire_identity(&config, "unknown"), None);
        assert_eq!(observable_name(&config, &local_identity), Some("a".into()));
        assert_eq!(
            observable_name(&config, &peer_identity),
            Some("exit".into())
        );
        assert_eq!(observable_name(&config, "unknown"), None);
        assert_eq!(
            display_path(&config, &[local_identity.clone(), peer_identity.clone()]),
            "a->exit"
        );
        let names = observable_node_names(&config);
        assert_eq!(names.get(&local_identity), Some(&"a".to_owned()));
        assert_eq!(names.get(&peer_identity), Some(&"exit".to_owned()));
        let paths = wire_paths(&config);
        assert_eq!(
            paths[&peer_identity],
            vec![vec![local_identity, peer_identity]]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn healthy_route_prefixes_include_direct_prefixes_without_fake_ip() {
        let snapshot = dataplane::RouteSnapshot::new(Vec::new(), Vec::new())
            .with_direct_routes(vec![("192.0.2.0/24".parse().unwrap(), 100)], Vec::new());
        assert_eq!(
            healthy_route_prefixes(&snapshot, None),
            HashSet::from(["192.0.2.0/24".parse().unwrap()])
        );
    }

    #[test]
    fn unix_timestamps_are_nonzero_and_monotonic_enough_for_status() {
        assert!(unix_now() > 0);
        assert!(unix_timestamp_secs() > 0);
    }

    #[tokio::test]
    async fn single_link_startup_wait_honors_an_expired_deadline_without_polling() {
        let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let opens = dataplane::CircuitOpenManager::default();
        assert!(
            wait_for_any_link(&links, &opens, std::time::Duration::ZERO)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn outbound_endpoint_uses_a_fresh_ephemeral_port() {
        let health = LinkHealthConfig {
            keepalive_secs: 10,
            idle_timeout_secs: 35,
            reconnect_interval_secs: 2,
        };
        let (listener, _) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &health,
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let listener_port = listener_addr.port();
        assert_ne!(listener_port, 0);

        let (outbound, _) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            outbound_bind_address(listener_addr, "198.51.100.20:4433".parse().unwrap()),
            &health,
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let outbound_port = outbound.local_addr().unwrap().port();
        assert_ne!(outbound_port, 0);
        assert_ne!(outbound_port, listener_port);
        assert_eq!(listener.local_addr().unwrap().port(), listener_port);

        listener.close(0u32.into(), b"test complete");
        outbound.close(0u32.into(), b"test complete");
    }

    #[test]
    fn secure_dataplane_and_destination_helpers_cover_empty_and_configured_modes() {
        let mut config = crate::daemon::test_support::minimal_config();
        assert!(!secure_dataplane_required(&config));
        assert!(configured_circuit_destinations(&config).is_empty());

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
        assert!(configured_circuit_destinations(&config).contains("exit"));
        config
            .allowed_local_ports
            .push(tinect::config::AllowedLocalPort {
                allow: vec!["tcp(443)".parse().unwrap()],
                deny: Vec::new(),
                r#for: tinect::config::RouteSourceSelector::Keyword("any_known".into()),
            });
        assert!(secure_dataplane_required(&config));
    }

    #[tokio::test]
    async fn empty_configuration_does_not_start_circuit_workers() {
        let config = crate::daemon::test_support::minimal_config();
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        let context = daemon::circuit_reconciler::CircuitReconcileContext::new(
            &runtime,
            Arc::new(identity::generate()),
            supervisor.clone(),
        );
        open_configured_circuits(&context).await.unwrap();
        assert_eq!(supervisor.task_count(), 0);
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn hard_revoke_cleans_local_lease_without_a_registered_link() {
        let config = crate::daemon::test_support::minimal_config();
        let runtime = Runtime::new(config.clone()).unwrap();
        let circuit_id = tinect::circuit::CircuitId([61; 16]);
        let circuit_key = chacha20poly1305::Key::from([61; 32]);
        runtime
            .circuits
            .opens
            .activate(
                "exit".into(),
                circuit_id,
                circuit_key,
                61,
                (vec!["source".into(), "exit".into()], 1200),
            )
            .await;
        runtime
            .circuits
            .return_flows
            .install_circuit(61, circuit_id, circuit_key);
        let source = identity::generate();
        runtime
            .circuits
            .sessions
            .install_open(61, circuit_id, source.verifying_key(), circuit_key)
            .await;
        let mut sender = tinect::crypto::SenderSession::from_key(circuit_id, circuit_key);
        let frame = sender.encrypt(b"payload").expect("session frame").to_vec();
        assert!(
            runtime
                .circuits
                .sessions
                .open_data(61, &frame)
                .await
                .is_ok()
        );
        assert!(
            runtime
                .circuits
                .return_flows
                .encrypt_dns_return(61, circuit_id, b"dns")
                .is_some()
        );
        let active = runtime
            .circuits
            .opens
            .active_for_destination("exit")
            .await
            .unwrap();
        let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let supervisor = DaemonSupervisor::default();
        hard_revoke_active_circuit(
            &runtime.circuits.opens,
            &runtime.circuits.sessions,
            &runtime.circuits.return_flows,
            &runtime.circuits.circuit_dns,
            "exit",
            &active,
            &links,
            &identity::generate(),
            &supervisor,
            "test revocation",
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
        assert!(
            runtime
                .circuits
                .return_flows
                .encrypt_dns_return(61, circuit_id, b"dns")
                .is_none()
        );
        assert_eq!(
            runtime.circuits.sessions.open_data(61, &frame).await,
            Err(tinect::crypto::CryptoError::UnknownSession)
        );
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn migration_status_and_failure_logging_update_the_local_snapshot() {
        let config = crate::daemon::test_support::minimal_config();
        let state = Arc::new(tokio::sync::RwLock::new(
            tinect::runtime::initial_daemon_state(&config, Arc::new(Observability::new(0))),
        ));
        state
            .write()
            .await
            .status
            .circuits
            .push(status::CircuitStatus {
                destination: "exit".into(),
                destination_identity: None,
                active_path: Vec::new(),
                active_path_names: Vec::new(),
                healthy: true,
                migration_state: MigrationState::Stable,
                preferred_path: Vec::new(),
                preferred_path_names: Vec::new(),
                migration_started_at: None,
                migration_last_error: None,
            });
        update_migration_status(
            &state,
            &config,
            "exit",
            &["unknown".into()],
            MigrationState::MigrationOverdue,
            Some(123),
            Some("failed".into()),
        )
        .await;
        {
            let daemon = state.read().await;
            let circuit = &daemon.status.circuits[0];
            assert_eq!(circuit.migration_state, MigrationState::MigrationOverdue);
            assert_eq!(circuit.preferred_path, vec!["unknown"]);
            assert_eq!(circuit.preferred_path_names, vec![None]);
            assert_eq!(circuit.migration_started_at, Some(123));
            assert_eq!(circuit.migration_last_error.as_deref(), Some("failed"));
        }

        let opens = dataplane::CircuitOpenManager::default();
        let identity = tinect::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 62,
        };
        assert!(matches!(
            opens
                .migration_readiness("exit", &identity, true, std::time::Duration::ZERO)
                .await,
            Some(dataplane::MigrationReadiness::Ready)
        ));
        opens.begin_migration("exit").await;
        log_migration_failure(&config, "exit", &opens, "test failure").await;
    }

    #[tokio::test]
    async fn link_status_helpers_ignore_unbound_and_stale_events() {
        let config = crate::daemon::test_support::minimal_config();
        let state = Arc::new(tokio::sync::RwLock::new(
            tinect::runtime::initial_daemon_state(&config, Arc::new(Observability::new(0))),
        ));
        state.write().await.status.links.push(status::LinkStatus {
            peer: "exit".into(),
            peer_identity: "identity".into(),
            healthy: true,
            last_error: None,
            metrics: None,
        });
        let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let opens = dataplane::CircuitOpenManager::default();
        mark_link(&state, "exit", false, Some("down".into())).await;
        mark_current_link(&state, &links, "exit", 99, true, None, &opens).await;
        mark_unbound_link(&state, &links, "exit", Some("unbound".into())).await;
        remove_link_if_current(&links, &state, "exit", 99, &opens).await;
        assert!(!state.read().await.status.links[0].healthy);
        assert_eq!(
            state.read().await.status.links[0].last_error.as_deref(),
            Some("unbound")
        );
        assert!(registered_link_by_instance(&links, 99).is_none());
    }

    #[tokio::test]
    async fn candidate_resolution_without_a_candidate_preserves_unavailable_state() {
        let config = crate::daemon::test_support::minimal_config();
        let links = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let topology = Arc::new(tokio::sync::RwLock::new(Topology::default()));
        let resolution =
            resolve_destination(&config, "missing", &links, &topology, None, 0, 0).await;
        let desired = desired_resolution_for_candidate(&resolution, None);
        assert!(matches!(
            desired.availability,
            tinect::reconcile::Availability::TemporarilyUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn endpoint_resolution_rejects_invalid_schemes_before_dns() {
        let config = crate::daemon::test_support::minimal_config();
        let runtime = Runtime::new(config.clone()).unwrap();
        assert!(
            resolve_quic_endpoint("not-a-carrier://127.0.0.1:1", &runtime.dns)
                .await
                .is_err()
        );
        assert!(
            collect_underlay_endpoints(&config, &runtime.dns)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn start_links_starts_the_listener_without_creating_a_tun() {
        let mut config = crate::daemon::test_support::minimal_config();
        config.listen = "quic://127.0.0.1:0".into();
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        let (router, _listen_addr) = start_links(
            &config,
            &runtime,
            supervisor.clone(),
            &Arc::new(identity::generate()),
        )
        .await
        .unwrap();
        assert!(!router.has_secure_dataplane());
        assert!(supervisor.task_count() >= 1);
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn start_links_accepts_and_registers_an_authenticated_inbound_link() {
        let client_key = identity::generate();
        let server_key = identity::generate();

        let mut config = crate::daemon::test_support::minimal_config();
        config.id = "server".into();
        config.identity_key = Some(identity::encode_secret(&server_key));
        config.identity_key_path = None;
        config.listen = "quic://127.0.0.1:0".into();
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
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        let (_router, listen_addr) = start_links(
            &config,
            &runtime,
            supervisor.clone(),
            &Arc::new(server_key.clone()),
        )
        .await
        .unwrap();

        let (client_endpoint, client_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let client_link = carrier::connect_with_link_health_and_bare_and_fec(
            &client_endpoint,
            client_bare.as_ref(),
            listen_addr,
            tinect::config::CarrierProtocol::Quic,
            "server",
            &identity::encode_public(&server_key.verifying_key()),
            "client",
            &client_key,
            &LinkHealthConfig::default(),
            0,
        )
        .await
        .unwrap();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Some(link) = runtime
                    .links
                    .lock()
                    .expect("link registry lock")
                    .get("client")
                    .cloned()
                {
                    break link;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(accepted.peer, "client");
        assert!(accepted.is_healthy());

        client_link.close("test complete");
        client_endpoint.close(0u32.into(), b"test complete");
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn start_links_registers_an_outbound_supervisor_for_a_configured_peer() {
        let mut config = crate::daemon::test_support::minimal_config();
        config.listen = "quic://127.0.0.1:0".into();
        let peer_key = identity::generate();
        config.peers.insert(
            "exit".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&peer_key.verifying_key()),
                endpoints: vec!["quic://127.0.0.1:1".into()],
                upstream_dns: None,
                accept_connections: None,
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: Vec::new(),
            },
        );
        config.connect_to.push("exit".into());
        let runtime = Runtime::new(config.clone()).unwrap();
        let supervisor = DaemonSupervisor::default();
        let (_router, _listen_addr) = start_links(
            &config,
            &runtime,
            supervisor.clone(),
            &Arc::new(identity::generate()),
        )
        .await
        .unwrap();
        assert!(supervisor.task_count() >= 2);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dry_run_up_renders_the_linux_plan_without_starting_network_io() {
        let config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/client.yaml");
        up(config, true).await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn command_dispatch_covers_key_management_and_configuration_check() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("node.key");
        run_command(Cmd::Keygen {
            output: key_path.clone(),
        })
        .await
        .unwrap();
        let secret = std::fs::read_to_string(&key_path).unwrap();
        run_command(Cmd::Pubkey {
            key: Some(key_path),
            secret: None,
        })
        .await
        .unwrap();
        run_command(Cmd::Pubkey {
            key: None,
            secret: Some(secret),
        })
        .await
        .unwrap();
        run_command(Cmd::Check {
            config: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/client.yaml"),
        })
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn command_dispatch_uses_static_read_only_fallbacks_and_reports_socket_errors() {
        let config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/client.yaml");
        run_command(Cmd::Status {
            target: DaemonTargetArgs {
                config: Some(config.clone()),
                socket: None,
                node: None,
            },
        })
        .await
        .unwrap();
        run_command(Cmd::Routes {
            target: DaemonTargetArgs {
                config: Some(config.clone()),
                socket: None,
                node: None,
            },
        })
        .await
        .unwrap();
        assert!(
            run_command(Cmd::Topology {
                target: DaemonTargetArgs {
                    config: None,
                    socket: Some("/run/tinect-nonexistent.sock".into()),
                    node: None,
                },
            })
            .await
            .is_err()
        );
        assert!(
            run_command(Cmd::Pcap {
                target: DaemonTargetArgs {
                    config: None,
                    socket: Some("/run/tinect-nonexistent.sock".into()),
                    node: None,
                },
                output: tempfile::tempdir().unwrap().path().join("capture.pcap"),
            })
            .await
            .is_err()
        );
        assert!(
            run_command(Cmd::Status {
                target: DaemonTargetArgs {
                    config: None,
                    socket: Some("/run/tinect-nonexistent.sock".into()),
                    node: None,
                },
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn authenticated_link_drives_physical_dispatch_and_route_snapshot() {
        let source_key = identity::generate();
        let server_key = identity::generate();
        let server_public = identity::encode_public(&server_key.verifying_key());
        let (server_endpoint, server_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let peers = std::collections::BTreeMap::from([(
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
        let accept_key = server_key.clone();
        let server_task = tokio::spawn(async move {
            carrier::accept_with_bare(
                &server_endpoint,
                server_bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &accept_key,
            )
            .await
            .unwrap()
        });
        let (client_endpoint, client_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let client_link = carrier::connect_with_link_health_and_bare(
            &client_endpoint,
            client_bare.as_ref(),
            server_addr,
            tinect::config::CarrierProtocol::Quic,
            "server",
            &server_public,
            "source",
            &source_key,
            &LinkHealthConfig::default(),
        )
        .await
        .unwrap();
        let server_link = Arc::new(server_task.await.unwrap());
        let client_link = Arc::new(client_link);

        let mut config = crate::daemon::test_support::minimal_config();
        config.identity_key = Some(identity::encode_secret(&server_key));
        config.identity_key_path = None;
        config.peers.insert(
            "exit".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&source_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: vec![serde_yaml::from_str("ip_cidr: 10.0.0.0/8").unwrap()],
                paths: Vec::new(),
            },
        );
        let runtime = Runtime::new(config.clone()).unwrap();
        runtime
            .links
            .lock()
            .unwrap()
            .insert("exit".into(), server_link.clone());
        server_link.set_healthy(true);
        let circuit_id = tinect::circuit::CircuitId([7; 16]);
        runtime
            .circuits
            .opens
            .activate(
                "exit".into(),
                circuit_id,
                chacha20poly1305::Key::from([3; 32]),
                server_link.instance(),
                (
                    vec![
                        config.local_identity().unwrap(),
                        identity::node_id(&source_key.verifying_key()),
                    ],
                    1200,
                ),
            )
            .await;
        let snapshot = build_route_snapshot(
            &config,
            &runtime.links,
            &runtime.topology,
            &runtime.circuits.opens,
        )
        .await;
        assert_eq!(snapshot.all_bindings().count(), 1);
        assert_eq!(snapshot.healthy_prefixes().count(), 1);

        let mut receiver = server_link.take_forward_receiver().await.unwrap();
        let supervisor = DaemonSupervisor::default();
        spawn_physical_dispatcher(server_link.clone(), supervisor.clone());
        client_link
            .send_physical(PhysicalPayload::Keepalive)
            .unwrap();
        let payload = vec![0x5a; tinect::crypto::FRAME_OVERHEAD + 3];
        client_link
            .send_physical(PhysicalPayload::Forward(payload.clone()))
            .unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        // A closed registered Link must be removed before the outbound
        // supervisor schedules its reconnect attempt.
        server_link.close("stale link");
        let mut reconnect_config = config.clone();
        reconnect_config.listen = "quic://127.0.0.1:0".into();
        reconnect_config.peers.get_mut("exit").unwrap().endpoints =
            vec!["quic://127.0.0.1:1".into()];
        reconnect_config.connect_to = vec!["exit".into()];
        let (_router, _listen_addr) = start_links(
            &reconnect_config,
            &runtime,
            supervisor.clone(),
            &Arc::new(server_key.clone()),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        client_link.close("test complete");
        server_link.close("test complete");
        client_endpoint.close(0u32.into(), b"test complete");
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn control_handler_drives_topology_and_circuit_lifecycles() {
        let client_key = identity::generate();
        let server_key = identity::generate();
        let server_public = identity::encode_public(&server_key.verifying_key());
        let client_public = identity::encode_public(&client_key.verifying_key());
        let (server_endpoint, server_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let peers = std::collections::BTreeMap::from([(
            "client".to_owned(),
            tinect::config::Peer {
                public_key: client_public.clone(),
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
        let server_addr = server_endpoint.local_addr().unwrap();
        let accept_key = server_key.clone();
        let server_task = tokio::spawn(async move {
            carrier::accept_with_bare(
                &server_endpoint,
                server_bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &accept_key,
            )
            .await
            .unwrap()
        });
        let (client_endpoint, client_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let client_link = Arc::new(
            carrier::connect_with_link_health_and_bare(
                &client_endpoint,
                client_bare.as_ref(),
                server_addr,
                tinect::config::CarrierProtocol::Quic,
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

        let mut config = crate::daemon::test_support::minimal_config();
        config.id = "server".into();
        config.identity_key = Some(identity::encode_secret(&server_key));
        config.identity_key_path = None;
        config.peers.insert(
            "client".into(),
            tinect::config::Peer {
                public_key: client_public,
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
        let runtime = Runtime::new(config.clone()).unwrap();
        runtime
            .links
            .lock()
            .unwrap()
            .insert("client".into(), server_link.clone());
        let next_key = identity::generate();
        let next_public = identity::encode_public(&next_key.verifying_key());
        let (next_endpoint, next_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let next_addr = next_endpoint.local_addr().unwrap();
        let next_peers = std::collections::BTreeMap::from([(
            "server".to_owned(),
            tinect::config::Peer {
                public_key: server_public.clone(),
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
        let next_accept_key = next_key.clone();
        let next_endpoint_for_accept = next_endpoint.clone();
        let next_task = tokio::spawn(async move {
            carrier::accept_with_bare(
                &next_endpoint_for_accept,
                next_bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &next_peers,
                false,
                "next",
                &next_accept_key,
            )
            .await
            .unwrap()
        });
        let (relay_endpoint, relay_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let next_link = Arc::new(
            carrier::connect_with_link_health_and_bare(
                &relay_endpoint,
                relay_bare.as_ref(),
                next_addr,
                tinect::config::CarrierProtocol::Quic,
                "next",
                &next_public,
                "server",
                &server_key,
                &LinkHealthConfig::default(),
            )
            .await
            .unwrap(),
        );
        let next_server_link = Arc::new(next_task.await.unwrap());
        runtime
            .links
            .lock()
            .unwrap()
            .insert("next".into(), next_link.clone());
        let transit = tinect::policy::TransitPolicy::new(true, HashMap::new());
        let router = Arc::new(Router::new(
            identity::node_id(&server_key.verifying_key()),
            transit,
            runtime.links.clone(),
        ));
        router
            .set_known_sources(HashSet::from([identity::node_id(
                &client_key.verifying_key(),
            )]))
            .await;
        let supervisor = DaemonSupervisor::default();
        spawn_control_handler(
            server_link.clone(),
            ControlHandlerContext {
                router: router.clone(),
                runtime: runtime.clone(),
                identity: Arc::new(server_key.clone()),
                supervisor: supervisor.clone(),
            },
        );

        let initial = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap();
        let initial_sync_id = match initial {
            ControlMessage::TopologySync { sync_id, .. } => sync_id,
            other => panic!("unexpected initial control message: {other:?}"),
        };
        client_link
            .send_control(&ControlMessage::TopologySyncAck {
                sync_id: initial_sync_id,
            })
            .await
            .unwrap();

        spawn_control_handler(
            next_link.clone(),
            ControlHandlerContext {
                router,
                runtime: runtime.clone(),
                identity: Arc::new(server_key.clone()),
                supervisor: supervisor.clone(),
            },
        );
        let next_initial = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            next_server_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap();
        let next_initial_sync_id = match next_initial {
            ControlMessage::TopologySync { sync_id, .. } => sync_id,
            other => panic!("unexpected next-link initial message: {other:?}"),
        };
        next_server_link
            .send_control(&ControlMessage::TopologySyncAck {
                sync_id: next_initial_sync_id,
            })
            .await
            .unwrap();

        let sync_id = 10_000;
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::TopologySyncAck { sync_id: received } if received == sync_id
        ));
        // Simulate the ACK delivery failure after the snapshot was already
        // applied. A later retransmission must restore inbound readiness.
        assert!(server_link.topology_ready());
        server_link.mark_topology_inbound_unsynchronized();
        assert!(!server_link.topology_ready());
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::TopologySyncAck { sync_id: received } if received == sync_id
        ));
        assert!(server_link.topology_ready());

        // A recovery Request arriving while a Snapshot is awaiting its ACK
        // must not clear a Delta queued after that Snapshot was fixed. The
        // Delta is newer than the Snapshot and must be flushed once the ACK
        // completes the active transfer.
        client_link
            .send_control(&ControlMessage::TopologySyncRequest { reason: 20 })
            .await
            .unwrap();
        let recovery_snapshot = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap();
        let recovery_id = match recovery_snapshot {
            ControlMessage::TopologySync { sync_id, .. } => sync_id,
            other => panic!("unexpected recovery message: {other:?}"),
        };
        let retained_delta = LinkStateAdvertisement::new(
            identity::node_id(&server_key.verifying_key()),
            &server_key,
            2,
            100,
            Vec::new(),
        );
        assert!(
            server_link
                .queue_topology_deltas(vec![retained_delta.clone()])
                .await
        );
        client_link
            .send_control(&ControlMessage::TopologySyncRequest { reason: 21 })
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::TopologySyncAck {
                sync_id: recovery_id,
            })
            .await
            .unwrap();
        let flushed_delta = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap();
        match flushed_delta {
            ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Delta,
                advertisements,
                ..
            } => assert_eq!(advertisements, vec![retained_delta]),
            other => panic!("unexpected queued delta message: {other:?}"),
        }

        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Delta,
                sync_id: sync_id + 1,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();

        client_link
            .send_control(&ControlMessage::TopologySyncRequest { reason: 9 })
            .await
            .unwrap();
        let recovery_snapshot = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap();
        let recovery_id = match recovery_snapshot {
            ControlMessage::TopologySync { sync_id, .. } => sync_id,
            other => panic!("unexpected recovery message: {other:?}"),
        };
        client_link
            .send_control(&ControlMessage::TopologySyncAck {
                sync_id: recovery_id,
            })
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: sync_id + 2,
                chunk_index: 0,
                chunk_count: 2,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: sync_id + 2,
                chunk_index: 0,
                chunk_count: 2,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: sync_id + 2,
                chunk_index: 0,
                chunk_count: 2,
                advertisements: vec![LinkStateAdvertisement::new(
                    identity::node_id(&client_key.verifying_key()),
                    &client_key,
                    1,
                    100,
                    Vec::new(),
                )],
            })
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client_link.recv_control()
            )
            .await
            .unwrap()
            .unwrap(),
            ControlMessage::TopologySyncRequest { .. }
        ));

        // The conflicting transfer above is a newer RX generation and moved
        // RX back to AwaitingInitial. Replaying the older applied Snapshot
        // may be ACKed, but must not restore readiness across that failed
        // generation.
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::TopologySyncAck { sync_id: received } if received == sync_id
        ));
        assert!(!server_link.topology_ready());

        // A fresh Snapshot is required to recover after the newer generation
        // failed; an old completed Snapshot cannot serve as a rollback.
        let replacement_sync_id = sync_id + 4;
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: replacement_sync_id,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::TopologySyncAck { sync_id: received }
                if received == replacement_sync_id
        ));
        assert!(server_link.topology_ready());

        // A late chunk from a superseded Snapshot must not clear the newer
        // assembly. Otherwise the newer Snapshot can never complete and the
        // old transfer will trigger another recovery timeout later.
        let old_sync_id = 20_000;
        let new_sync_id = 20_001;
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: old_sync_id,
                chunk_index: 0,
                chunk_count: 2,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        // Let the first chunk become the active RX assembly before injecting
        // the superseding transfer, so the test exercises the same ordering
        // as a replacement Snapshot after a partial transfer.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: new_sync_id,
                chunk_index: 0,
                chunk_count: 2,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: old_sync_id,
                chunk_index: 1,
                chunk_count: 2,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: new_sync_id,
                chunk_index: 1,
                chunk_count: 2,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::TopologySyncAck { sync_id } if sync_id == new_sync_id
        ));

        // A snapshot whose declared chunk count changes mid-transfer must
        // be discarded and force recovery rather than being merged into an
        // ambiguous assembly.  The recovery request is rate-limited because
        // the conflicting duplicate above already requested one.
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: sync_id + 3,
                chunk_index: 0,
                chunk_count: 2,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: sync_id + 3,
                chunk_index: 1,
                chunk_count: 3,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        client_link
            .send_control(&ControlMessage::Ping)
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client_link.recv_control()
            )
            .await
            .unwrap()
            .unwrap(),
            ControlMessage::Pong
        ));
        let feedback_circuit_id = tinect::circuit::CircuitId([76; 16]);
        dataplane::send_circuit_broken_feedback(&server_link, &server_key, feedback_circuit_id)
            .await;
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::CircuitBroken { circuit_id, .. }
                if circuit_id == feedback_circuit_id
        ));
        let notified_circuit_id = tinect::circuit::CircuitId([75; 16]);
        daemon::control_handler::notify_broken(
            &runtime.links,
            &server_key,
            vec![(server_link.instance(), notified_circuit_id)],
        )
        .await;
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::CircuitBroken { circuit_id, .. }
                if circuit_id == notified_circuit_id
        ));
        client_link
            .send_control(&ControlMessage::Pong)
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::FecReport(tinect::fec::FecReport {
                report_id: 1,
                samples: 1,
                loss_ppm: 0,
                burst_milli: 1_000,
            }))
            .await
            .unwrap();

        let next_id = identity::node_id(&next_key.verifying_key());
        let relay_circuit_id = tinect::circuit::CircuitId([78; 16]);
        let relay_request = tinect::circuit::OpenRequest::new(
            identity::node_id(&client_key.verifying_key()),
            &client_key,
            next_id,
            vec![
                identity::node_id(&client_key.verifying_key()),
                identity::node_id(&server_key.verifying_key()),
                identity::node_id(&next_key.verifying_key()),
            ],
            relay_circuit_id,
            [8; 32],
        );
        client_link
            .send_control(&ControlMessage::Open(relay_request))
            .await
            .unwrap();
        let forwarded = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            next_server_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap();
        match forwarded {
            ControlMessage::Open(_) => {}
            other => panic!("unexpected forwarded control message: {other:?}"),
        }
        next_server_link
            .send_control(&ControlMessage::open_reject(
                &next_key,
                relay_circuit_id,
                true,
                7,
            ))
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::OpenReject { circuit_id, .. } if circuit_id == relay_circuit_id
        ));

        let client_id = identity::node_id(&client_key.verifying_key());
        let server_id = identity::node_id(&server_key.verifying_key());
        let circuit_id = tinect::circuit::CircuitId([77; 16]);
        let request = tinect::circuit::OpenRequest::new(
            client_id.clone(),
            &client_key,
            server_id,
            vec![
                client_id.clone(),
                identity::node_id(&server_key.verifying_key()),
            ],
            circuit_id,
            [7; 32],
        );
        client_link
            .send_control(&ControlMessage::Open(request.clone()))
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::OpenAck { circuit_id: received, .. } if received == circuit_id
        ));

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
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::CircuitBroken {
                circuit_id: received,
                reason_code,
                ..
            } if received == circuit_id
                && reason_code == tinect::control::CIRCUIT_RENEW_REJECTED_REASON
        ));
        client_link
            .send_control(&ControlMessage::open_ack(&server_key, circuit_id))
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::open_reject(
                &server_key,
                circuit_id,
                true,
                7,
            ))
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::circuit_renew_ack(
                &client_key,
                circuit_id,
                2,
            ))
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::circuit_broken(&client_key, circuit_id, 7))
            .await
            .unwrap();
        client_link
            .send_control(&ControlMessage::circuit_broken(&client_key, circuit_id, 2))
            .await
            .unwrap();

        let mut invalid = request;
        invalid.signature = format!("A{}", &invalid.signature[1..]);
        client_link
            .send_control(&ControlMessage::Open(invalid))
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client_link.recv_control()
            )
            .await
            .unwrap()
            .unwrap(),
            ControlMessage::OpenReject { .. }
        ));

        // Exercise the source-side reconciler against the same authenticated
        // Link. The topology exchange above establishes the Link readiness;
        // the manual path then supplies the complete OPEN candidate without
        // requiring a TUN or a platform route.
        client_link.mark_topology_snapshot_received();
        client_link.mark_topology_snapshot_acknowledged();
        let mut source_config = crate::daemon::test_support::minimal_config();
        source_config.id = "client".into();
        source_config.identity_key = Some(identity::encode_secret(&client_key));
        source_config.identity_key_path = None;
        source_config.peers.insert(
            "server".into(),
            tinect::config::Peer {
                public_key: identity::encode_public(&server_key.verifying_key()),
                endpoints: Vec::new(),
                upstream_dns: None,
                accept_connections: None,
                allow_transit: None,
                allow_relay: None,
                bind_addresses: Vec::new(),
                routes: Vec::new(),
                paths: vec![tinect::config::ConfiguredPath {
                    path: vec!["client".into(), "server".into()],
                    override_routes: Vec::new(),
                    override_upstream_dns: None,
                }],
            },
        );
        let source_runtime = Runtime::new(source_config).unwrap();
        source_runtime
            .links
            .lock()
            .unwrap()
            .insert("server".into(), client_link.clone());
        let source_supervisor = DaemonSupervisor::default();
        let source_context = Arc::new(daemon::circuit_reconciler::CircuitReconcileContext::new(
            &source_runtime,
            Arc::new(client_key.clone()),
            source_supervisor.clone(),
        ));
        let source_router = Arc::new(Router::new(
            client_id,
            tinect::policy::TransitPolicy::new(false, HashMap::new()),
            source_runtime.links.clone(),
        ));
        spawn_control_handler(
            client_link.clone(),
            ControlHandlerContext {
                router: source_router,
                runtime: source_runtime.clone(),
                identity: Arc::new(client_key.clone()),
                supervisor: source_supervisor.clone(),
            },
        );
        let source_worker = tokio::spawn({
            let source_context = source_context.clone();
            async move { open_configured_circuit(source_context.as_ref(), "server").await }
        });
        let opened = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Some(active) = source_runtime
                    .circuits
                    .opens
                    .active_for_destination("server")
                    .await
                {
                    break active.circuit_id;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let opened_id = match opened {
            Ok(active) => active,
            Err(error) if source_worker.is_finished() => {
                let result = source_worker.await;
                panic!("source reconciler exited before OPEN: {error:?}; result={result:?}")
            }
            Err(error) => panic!("source reconciler did not establish OPEN: {error:?}"),
        };
        source_runtime
            .circuits
            .opens
            .request_rebuild("server")
            .await;
        source_runtime
            .circuits
            .opens
            .deactivate("server", opened_id)
            .await;
        source_worker.abort();
        let _ = source_worker.await;
        source_supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();

        server_link.close("test complete");
        dataplane::send_circuit_broken_feedback(
            &server_link,
            &server_key,
            tinect::circuit::CircuitId([74; 16]),
        )
        .await;
        client_link.close("test complete");
        next_link.close("test complete");
        next_server_link.close("test complete");
        client_endpoint.close(0u32.into(), b"test complete");
        relay_endpoint.close(0u32.into(), b"test complete");
        next_endpoint.close(0u32.into(), b"test complete");
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    /// Establish an authenticated client/server Link pair, run the server's
    /// control handler against the client peer, and complete the initial
    /// bidirectional topology Snapshot exchange so both directions are
    /// synchronized.
    #[allow(clippy::type_complexity)]
    async fn topology_link_pair_synced() -> (
        Arc<carrier::Link>,
        Arc<carrier::Link>,
        ed25519_dalek::SigningKey,
        ed25519_dalek::SigningKey,
        Runtime,
        DaemonSupervisor,
    ) {
        let client_key = identity::generate();
        let server_key = identity::generate();
        let server_public = identity::encode_public(&server_key.verifying_key());
        let client_public = identity::encode_public(&client_key.verifying_key());
        let (server_endpoint, server_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let accept_peers = std::collections::BTreeMap::from([(
            "client".to_owned(),
            tinect::config::Peer {
                public_key: client_public.clone(),
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
        let server_addr = server_endpoint.local_addr().unwrap();
        let accept_key = server_key.clone();
        let server_task = tokio::spawn(async move {
            carrier::accept_with_bare(
                &server_endpoint,
                server_bare.as_ref(),
                tinect::config::CarrierProtocol::Quic,
                &accept_peers,
                false,
                "server",
                &accept_key,
            )
            .await
            .unwrap()
        });
        let (client_endpoint, client_bare) = carrier::endpoint_with_options_and_bare(
            tinect::config::CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(tinect::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let client_link = Arc::new(
            carrier::connect_with_link_health_and_bare(
                &client_endpoint,
                client_bare.as_ref(),
                server_addr,
                tinect::config::CarrierProtocol::Quic,
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
        let mut config = crate::daemon::test_support::minimal_config();
        config.id = "server".into();
        config.identity_key = Some(identity::encode_secret(&server_key));
        config.identity_key_path = None;
        config.peers.insert(
            "client".into(),
            tinect::config::Peer {
                public_key: client_public,
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
        let runtime = Runtime::new(config.clone()).unwrap();
        runtime
            .links
            .lock()
            .unwrap()
            .insert("client".into(), server_link.clone());
        let transit = tinect::policy::TransitPolicy::new(true, HashMap::new());
        let router = Arc::new(Router::new(
            identity::node_id(&server_key.verifying_key()),
            transit,
            runtime.links.clone(),
        ));
        let supervisor = DaemonSupervisor::default();
        spawn_control_handler(
            server_link.clone(),
            ControlHandlerContext {
                router,
                runtime: runtime.clone(),
                identity: Arc::new(server_key.clone()),
                supervisor: supervisor.clone(),
            },
        );

        let initial = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap();
        let initial_sync_id = match initial {
            ControlMessage::TopologySync { sync_id, .. } => sync_id,
            other => panic!("unexpected initial control message: {other:?}"),
        };
        client_link
            .send_control(&ControlMessage::TopologySyncAck {
                sync_id: initial_sync_id,
            })
            .await
            .unwrap();
        let inbound_sync_id = 10_000;
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: inbound_sync_id,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::TopologySyncAck { sync_id: received } if received == inbound_sync_id
        ));
        assert!(server_link.topology_ready());
        (
            client_link,
            server_link,
            client_key,
            server_key,
            runtime,
            supervisor,
        )
    }

    /// RFC-0016 regression: the peer only flushes Deltas once it is fully
    /// ready, which already implies our inbound baseline was applied and
    /// ACKed. A Delta arriving while our own outbound Snapshot ACK is still
    /// in flight (different QUIC uni stream) must be applied, not rejected
    /// with a recovery Request that would consume the peer's recovery budget.
    #[tokio::test]
    async fn topology_delta_before_outbound_ack_is_applied_without_recovery() {
        let (client_link, server_link, client_key, _server_key, _runtime, supervisor) =
            topology_link_pair_synced().await;
        // Simulate the peer's ACK of our Snapshot being delayed on its own
        // uni stream while the peer is already fully ready and flushing a
        // Delta.
        server_link.mark_topology_outbound_unsynchronized();
        assert!(!server_link.topology_ready());
        let delta = LinkStateAdvertisement::new(
            identity::node_id(&client_key.verifying_key()),
            &client_key,
            1,
            100,
            Vec::new(),
        );
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Delta,
                sync_id: 10_001,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: vec![delta],
            })
            .await
            .unwrap();
        // The Delta must be applied silently: no recovery Request may be sent
        // back, and the link must stay healthy.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(400),
                client_link.recv_control(),
            )
            .await
            .is_err()
        );
        assert!(server_link.close_reason().is_none());
        client_link.close("test complete");
        server_link.close("test complete");
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    /// RFC-0016 SnapshotRequired recovery is bidirectional: when the peer's
    /// fresh Snapshot repairs our inbound while our own outbound is still
    /// unsynchronized (e.g. its Delta outbox overflowed), the receive path
    /// must re-fix and send our Snapshot so the peer can recover toward us.
    #[tokio::test]
    async fn inbound_recovery_resends_unsynchronized_outbound_snapshot() {
        let (client_link, server_link, _client_key, _server_key, _runtime, supervisor) =
            topology_link_pair_synced().await;
        server_link.mark_topology_outbound_unsynchronized();
        assert!(!server_link.topology_ready());
        let inbound_sync_id = 10_002;
        client_link
            .send_control(&ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: inbound_sync_id,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), client_link.recv_control())
                .await
                .unwrap()
                .unwrap(),
            ControlMessage::TopologySyncAck { sync_id: received } if received == inbound_sync_id
        ));
        // The peer's fresh Snapshot repaired inbound; the outbound resend must
        // carry a NEW sync_id.
        let resent = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client_link.recv_control(),
        )
        .await
        .unwrap()
        .unwrap();
        let resent_sync_id = match resent {
            ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id,
                ..
            } => sync_id,
            other => panic!("expected outbound resend Snapshot, got {other:?}"),
        };
        assert_ne!(resent_sync_id, inbound_sync_id);
        client_link
            .send_control(&ControlMessage::TopologySyncAck {
                sync_id: resent_sync_id,
            })
            .await
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !server_link.topology_ready() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(server_link.topology_ready());
        client_link.close("test complete");
        server_link.close("test complete");
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    /// RFC-0016 backpressure: when a peer's Delta outbox is full, fanout must
    /// enter SnapshotRequired (drop stale Deltas, request recovery) instead of
    /// closing a merely congested Link.
    #[tokio::test]
    async fn topology_fanout_outbox_full_requests_recovery_instead_of_closing() {
        let (client_link, server_link, _client_key, _server_key, _runtime, supervisor) =
            topology_link_pair_synced().await;
        let full = (0..carrier::MAX_PENDING_TOPOLOGY_DELTAS)
            .map(|index| LinkStateAdvertisement {
                origin: format!("{index:032x}"),
                sequence: 1,
                expires_at: 1,
                neighbors: Vec::new(),
                public_key: String::new(),
                signature: String::new(),
            })
            .collect::<Vec<_>>();
        assert!(server_link.queue_topology_deltas(full).await);
        let registry: tinect::runtime::LinkRegistry = Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::from([("peer".into(), server_link.clone())]),
        ));
        let extra = LinkStateAdvertisement {
            origin: "ffffffffffffffffffffffffffffffff".into(),
            sequence: 1,
            expires_at: 1,
            neighbors: Vec::new(),
            public_key: String::new(),
            signature: String::new(),
        };
        // The incoming link is the client side of the connection; the
        // congested peer is the server side, so the fanout must not skip it.
        daemon::topology_sync::fanout_topology_delta(
            client_link.instance(),
            vec![extra],
            &registry,
        )
        .await;
        // The congested Link must survive and request a recovery Snapshot
        // instead of being closed.
        assert!(server_link.close_reason().is_none());
        let leftover = server_link.take_topology_deltas().await;
        assert!(
            leftover.is_empty(),
            "outbox should have been cleared, found {} entries, first: {:?}",
            leftover.len(),
            leftover.first().map(|advertisement| &advertisement.origin),
        );
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client_link.recv_control()
            )
            .await
            .unwrap()
            .unwrap(),
            ControlMessage::TopologySyncRequest { .. }
        ));
        client_link.close("test complete");
        server_link.close("test complete");
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn keygen_fails_when_the_output_directory_does_not_exist() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("missing").join("node.key");
        assert!(run_command(Cmd::Keygen { output }).await.is_err());
    }

    #[tokio::test]
    async fn pubkey_rejects_missing_key_files_and_invalid_inline_secrets() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            run_command(Cmd::Pubkey {
                key: Some(directory.path().join("missing.key")),
                secret: None,
            })
            .await
            .is_err()
        );
        assert!(
            run_command(Cmd::Pubkey {
                key: None,
                secret: Some("not base64 !!!".into()),
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn check_rejects_missing_and_invalid_configuration_files() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            run_command(Cmd::Check {
                config: directory.path().join("missing.yaml"),
            })
            .await
            .is_err()
        );
        let invalid = directory.path().join("invalid.yaml");
        std::fs::write(&invalid, "id: \"\"\n").unwrap();
        assert!(run_command(Cmd::Check { config: invalid }).await.is_err());
    }

    /// Minimal configuration that passes validation and points the management
    /// socket at the given path, so read-only commands can be driven against a
    /// stub daemon.
    #[cfg(unix)]
    fn config_yaml_with_status_socket(socket: &std::path::Path) -> String {
        let secret = identity::encode_secret(&identity::generate());
        format!(
            "id: node\nidentity_key: \"{secret}\"\nlisten: \"quic://127.0.0.1:1\"\ntun:\n  enabled: false\nruntime:\n  status_socket: \"{}\"\n",
            socket.display()
        )
    }

    /// Runs a one-shot management stub: it accepts a single connection, reads
    /// the request header, and replies with one frame carrying `reply_body`.
    /// `reply_opcode_offset` lets a test answer with a mismatched opcode.
    #[cfg(unix)]
    async fn spawn_management_stub(
        reply_body: Vec<u8>,
        reply_opcode_offset: u8,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 3];
            stream.read_exact(&mut header).await.unwrap();
            let opcode = header[0] + reply_opcode_offset;
            let length = u16::try_from(reply_body.len()).unwrap();
            let mut reply = vec![opcode, 0, (length >> 8) as u8, (length & 0xff) as u8];
            reply.extend_from_slice(&reply_body);
            stream.write_all(&reply).await.unwrap();
        });
        (directory, socket, server)
    }

    /// Joins the one-shot stub with a deadline so a missing daemon connection
    /// fails the test instead of hanging it.
    #[cfg(unix)]
    async fn join_management_stub(server: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("management stub was not contacted")
            .expect("management stub panicked");
    }

    #[cfg(unix)]
    fn stub_status_snapshot() -> status::Status {
        status::Status {
            node: "node".into(),
            node_identity: None,
            links: Vec::new(),
            circuits: Vec::new(),
            flow_count: 0,
            topology_nodes: 1,
            topology_generation: 1,
            supervised_tasks: 0,
            shutting_down: false,
            last_shutdown_error: None,
            circuit_traffic: Default::default(),
            acl_rejections: Default::default(),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn routes_socket_target_reports_connection_errors() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            run_command(Cmd::Routes {
                target: DaemonTargetArgs {
                    config: None,
                    socket: Some(directory.path().join("missing.sock")),
                    node: None,
                },
            })
            .await
            .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn topology_config_target_requires_a_reachable_daemon() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("missing.sock");
        let config = directory.path().join("node.yaml");
        std::fs::write(&config, config_yaml_with_status_socket(&socket)).unwrap();
        let error = run_command(Cmd::Topology {
            target: DaemonTargetArgs {
                config: Some(config),
                socket: None,
                node: None,
            },
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("requesting topology"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn status_and_routes_config_targets_prefer_the_live_daemon_reply() {
        let snapshot = stub_status_snapshot();
        let (directory, socket, server) =
            spawn_management_stub(status::encode_status(&snapshot).unwrap(), 0).await;
        let config = directory.path().join("node.yaml");
        std::fs::write(&config, config_yaml_with_status_socket(&socket)).unwrap();
        run_command(Cmd::Status {
            target: DaemonTargetArgs {
                config: Some(config.clone()),
                socket: None,
                node: None,
            },
        })
        .await
        .unwrap();
        join_management_stub(server).await;

        let routes = vec![status::RouteStatus {
            selector: "10.0.0.0/8".into(),
            entries: 1,
            candidates: vec!["node".into()],
        }];
        let (_routes_directory, socket, server) =
            spawn_management_stub(status::encode_routes(&routes).unwrap(), 0).await;
        std::fs::write(&config, config_yaml_with_status_socket(&socket)).unwrap();
        run_command(Cmd::Routes {
            target: DaemonTargetArgs {
                config: Some(config),
                socket: None,
                node: None,
            },
        })
        .await
        .unwrap();
        join_management_stub(server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn topology_config_target_prints_the_dot_graph_and_rejects_malformed_replies() {
        let mut writer = tinect::wire::Writer::new();
        writer.string("digraph topology {}").unwrap();
        let (directory, socket, server) = spawn_management_stub(writer.finish(), 0).await;
        let config = directory.path().join("node.yaml");
        std::fs::write(&config, config_yaml_with_status_socket(&socket)).unwrap();
        run_command(Cmd::Topology {
            target: DaemonTargetArgs {
                config: Some(config),
                socket: None,
                node: None,
            },
        })
        .await
        .unwrap();
        join_management_stub(server).await;

        // A reply with trailing bytes after the dot string fails strict
        // decoding on the socket target path.
        let mut writer = tinect::wire::Writer::new();
        writer.string("digraph {}").unwrap();
        let mut body = writer.finish();
        body.push(0);
        let (_malformed_directory, malformed_socket, server) = spawn_management_stub(body, 0).await;
        assert!(
            run_command(Cmd::Topology {
                target: DaemonTargetArgs {
                    config: None,
                    socket: Some(malformed_socket),
                    node: None,
                },
            })
            .await
            .is_err()
        );
        join_management_stub(server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pcap_writes_the_capture_and_reports_output_write_failures() {
        let capture = b"\xd4\xc3\xb2\xa1 fake pcap bytes".to_vec();
        let (directory, socket, server) = spawn_management_stub(capture.clone(), 0).await;
        let output = directory.path().join("capture.pcap");
        run_command(Cmd::Pcap {
            target: DaemonTargetArgs {
                config: None,
                socket: Some(socket),
                node: None,
            },
            output: output.clone(),
        })
        .await
        .unwrap();
        join_management_stub(server).await;
        assert_eq!(std::fs::read(&output).unwrap(), capture);

        // A reachable daemon with an unwritable output path must surface the
        // write failure after the successful capture request.
        let (_second_directory, socket, server) = spawn_management_stub(Vec::new(), 0).await;
        let missing_output = directory.path().join("missing").join("capture.pcap");
        assert!(
            run_command(Cmd::Pcap {
                target: DaemonTargetArgs {
                    config: None,
                    socket: Some(socket),
                    node: None,
                },
                output: missing_output,
            })
            .await
            .is_err()
        );
        join_management_stub(server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn status_socket_target_rejects_replies_with_a_mismatched_opcode() {
        let (_directory, socket, server) = spawn_management_stub(b"ignored".to_vec(), 1).await;
        assert!(
            run_command(Cmd::Status {
                target: DaemonTargetArgs {
                    config: None,
                    socket: Some(socket),
                    node: None,
                },
            })
            .await
            .is_err()
        );
        join_management_stub(server).await;
    }
}
