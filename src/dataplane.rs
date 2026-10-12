//! Compact circuit-labelled data frames used inside QUIC DATAGRAM payloads.
use crate::config::RouteImport;
use crate::reconcile::{CapacityEdge, CapacityVector};
use crate::{
    carrier::{CarrierError, Link},
    circuit::{CircuitAuthorizations, RelayLabelTables, Router},
    link::{LinkError, LinkRef},
    observability::Observability,
    platform::{ConntrackFlowKey, DirectConntrack, PlatformError, TunDevice},
    policy::Protocol,
    runtime::DaemonSupervisor,
    topology::Topology,
};
use crate::{circuit::CircuitId, crypto, identity::encode_public};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ipnet::IpNet;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use crate::circuit::LabelTable;

mod circuit_open;
mod egress;
mod packet;
mod relay;
mod route;

pub use circuit_open::{
    ActiveCircuit, CircuitOpenManager, CommitError, InboundDispatch, MigrationReadiness,
    OpenAttempt, OpenAttemptInput, OpenResult, SessionManager, WorkerClaim,
    should_report_circuit_broken_feedback,
};
use circuit_open::{CIRCUIT_BROKEN_FEEDBACK_ATTEMPTS, SecureReceiveContext};
#[cfg(test)]
use circuit_open::{MAX_CIRCUIT_BROKEN_FEEDBACKS, circuit_broken_feedback_ttl};
pub use route::{CircuitDnsClient, RouteSnapshot, SecureRoute};
use route::{
    DNS_RESPONSE_CHUNK, DomainResolutionCandidate, RouteSelection, decode_dns_query,
    encode_dns_response,
};
#[cfg(test)]
use route::{
    PendingDnsQuery, PendingDnsRegistration, decode_dns_response, direct_beats_secure,
    encode_dns_query,
};

pub use egress::{EgressPolicy, SourceAddressPolicy};
use packet::clamp_mss_if_enabled;
#[cfg(test)]
use packet::tcp_checksum;
pub use packet::{
    PacketMeta, build_ptb_for_oversize, clamp_tcp_mss, direct_eligible, inspect_ip_destination,
    inspect_ip_source, inspect_ipv4_flow, inspect_packet, packet_dscp, segment_tcp_gso,
    set_packet_dscp,
};
pub use relay::{relay_once, relay_once_with_feedback};

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod rfc8_tests {
    use super::*;

    #[tokio::test]
    async fn withdrawing_active_snapshot_wakes_worker_and_prevents_stale_route_use() {
        let opens = CircuitOpenManager::default();
        let id = CircuitId([6; 16]);
        opens
            .activate(
                "exit".into(),
                id,
                chacha20poly1305::Key::from([1; 32]),
                9,
                (vec!["source".into(), "relay".into(), "exit".into()], 1200),
            )
            .await;
        assert!(opens.is_active("exit", id).await);
        let generation = opens.active_generation();
        let opens_for_wait = opens.clone();
        let changed =
            tokio::spawn(async move { opens_for_wait.wait_active_change(generation).await });
        tokio::task::yield_now().await;
        opens.deactivate("exit", id).await;
        tokio::time::timeout(std::time::Duration::from_millis(10), changed)
            .await
            .expect("withdrawal wakes an idle renewal worker")
            .expect("renewal wait task completes");
        assert!(!opens.is_active("exit", id).await);
        assert!(opens.active_for("exit", 9).await.is_none());
    }

    #[tokio::test]
    async fn circuit_broken_invalidates_only_the_matching_active_lease() {
        let opens = CircuitOpenManager::default();
        let id = CircuitId([7; 16]);
        opens
            .activate(
                "exit".into(),
                id,
                chacha20poly1305::Key::from([2; 32]),
                17,
                (vec!["source".into(), "relay".into(), "exit".into()], 1200),
            )
            .await;

        // The feedback no longer carries the local-only nonce.  The exact
        // first-hop Link instance plus CircuitId is the source-side token.
        assert!(opens.invalidate_circuit(17, id).await);
        assert!(!opens.is_active("exit", id).await);
    }

    #[tokio::test]
    async fn circuit_invalidation_feedback_matches_link_and_circuit_id() {
        let opens = CircuitOpenManager::default();
        let id = CircuitId([18; 16]);
        opens
            .activate(
                "exit".into(),
                id,
                chacha20poly1305::Key::from([3; 32]),
                23,
                (vec!["source".into(), "relay".into(), "exit".into()], 1200),
            )
            .await;
        assert!(!opens.invalidate_circuit(24, id).await);
        assert!(opens.is_active("exit", id).await);
        assert!(opens.invalidate_circuit(23, id).await);
        assert!(!opens.is_active("exit", id).await);
        assert!(!opens.invalidate_circuit(23, id).await);
    }

    #[test]
    fn circuit_broken_feedback_is_deduplicated_and_bounded() {
        let mut seen = HashMap::new();
        let id = CircuitId([8; 16]);
        let now = Instant::now();
        assert!(should_report_circuit_broken_feedback(&mut seen, id, now));
        assert!(!should_report_circuit_broken_feedback(&mut seen, id, now));
        assert!(should_report_circuit_broken_feedback(
            &mut seen,
            id,
            now + circuit_broken_feedback_ttl()
        ));
        for sequence in 0..MAX_CIRCUIT_BROKEN_FEEDBACKS {
            seen.insert(CircuitId((sequence as u128).to_be_bytes()), now);
        }
        assert!(!should_report_circuit_broken_feedback(
            &mut seen,
            CircuitId([0xaa; 16]),
            now
        ));
    }

    #[tokio::test]
    async fn relay_reports_unknown_label_without_touching_payload() {
        let id = CircuitId([21; 16]);
        let mut sender = crypto::SenderSession::from_key(id, chacha20poly1305::Key::from([4; 32]));
        let frame = sender.encrypt(b"opaque").unwrap().to_vec();
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(frame.clone()).await.unwrap();
        let labels = std::sync::RwLock::new(LabelTable::default());
        assert_eq!(
            relay_once_with_feedback(&mut rx, &labels).await.unwrap(),
            Some(id)
        );
        assert_eq!(crypto::frame_circuit_id(&frame).unwrap(), id);
    }

    #[tokio::test]
    async fn active_circuit_retains_path_inner_mtu_bound() {
        let opens = CircuitOpenManager::default();
        opens
            .activate(
                "exit".into(),
                CircuitId([9; 16]),
                chacha20poly1305::Key::from([4; 32]),
                12,
                (vec!["source".into(), "relay".into(), "exit".into()], 1196),
            )
            .await;
        assert_eq!(opens.active_path_inner_mtu("exit", 12).await, Some(1196));
        assert_eq!(opens.active_path_inner_mtu("exit", 13).await, None);
        opens
            .activate(
                "direct-exit".into(),
                CircuitId([10; 16]),
                chacha20poly1305::Key::from([5; 32]),
                12,
                (vec!["source".into(), "exit".into()], 1460),
            )
            .await;
        assert_eq!(
            opens.active_path_inner_mtu("direct-exit", 12).await,
            Some(1460)
        );
    }

    #[tokio::test]
    async fn stale_open_ack_cannot_commit_after_desired_identity_changes() {
        let opens = CircuitOpenManager::default();
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "relay".into(), "exit".into()],
            first_hop_link_instance: 7,
        };
        opens
            .set_desired_guard("exit", Some(identity.clone()), 0, false)
            .await;
        let circuit_id = CircuitId([19; 16]);
        let attempt = opens
            .begin_attempt("exit", circuit_id, identity, 0, 7)
            .await
            .expect("one OPEN attempt is admitted");
        let waiter = opens
            .register(
                7,
                circuit_id,
                "destination-key".into(),
                vec!["destination-key".into()],
                None,
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            opens
                .resolve(7, circuit_id, "destination-key", OpenResult::Acknowledged,)
                .await
        );
        assert_eq!(waiter.await.unwrap(), OpenResult::Acknowledged);
        opens
            .set_desired_guard(
                "exit",
                Some(crate::reconcile::CircuitIdentity {
                    destination: "exit".into(),
                    ordered_path: vec!["source".into(), "exit".into()],
                    first_hop_link_instance: 7,
                }),
                0,
                false,
            )
            .await;
        assert!(matches!(
            opens
                .commit_if_current(
                    &attempt,
                    chacha20poly1305::Key::from([8; 32]),
                    attempt.identity.ordered_path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::StaleAttempt)
        ));
        assert!(!opens.is_active("exit", circuit_id).await);
        assert!(
            opens
                .begin_attempt(
                    "exit",
                    CircuitId([20; 16]),
                    crate::reconcile::CircuitIdentity {
                        destination: "exit".into(),
                        ordered_path: vec!["source".into(), "exit".into()],
                        first_hop_link_instance: 7,
                    },
                    0,
                    7,
                )
                .await
                .is_some()
        );
        assert!(!opens.is_authorized(7, circuit_id).await);
        opens.deactivate("exit", circuit_id).await;
    }

    #[tokio::test]
    async fn older_resolution_cannot_rewind_the_current_desired_guard() {
        let opens = CircuitOpenManager::default();
        let current = crate::reconcile::ResolvedPath {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "relay".into(), "exit".into()],
            first_hop_link_instance: 31,
            candidate_rank: 0,
            verified_inner_mtu: 1300,
            capacity_vector: CapacityVector {
                edges: vec![
                    CapacityEdge {
                        from: "source".into(),
                        to: "relay".into(),
                        capacity: 1300,
                        generation: 8,
                    },
                    CapacityEdge {
                        from: "relay".into(),
                        to: "exit".into(),
                        capacity: 1300,
                        generation: 8,
                    },
                ],
            },
            proof_valid_until: 100,
        };
        opens
            .set_desired_resolution(
                "exit",
                crate::reconcile::DesiredResolution {
                    generation: 8,
                    config_generation: 0,
                    path: Some(current.clone()),
                    availability: crate::reconcile::Availability::Ready,
                    resolved_at: std::time::SystemTime::now(),
                },
            )
            .await;
        let stale = crate::reconcile::DesiredResolution {
            generation: 7,
            config_generation: 0,
            path: Some(crate::reconcile::ResolvedPath {
                ordered_path: vec!["source".into(), "old-relay".into(), "exit".into()],
                ..current.clone()
            }),
            availability: crate::reconcile::Availability::Ready,
            resolved_at: std::time::SystemTime::now(),
        };
        opens.set_desired_resolution("exit", stale).await;
        let attempt = opens
            .begin_attempt("exit", CircuitId([23; 16]), current.identity(), 0, 31)
            .await
            .expect("current desired resolution remains usable");
        let waiter = opens
            .register(
                31,
                attempt.circuit_id,
                "destination-key".into(),
                vec![],
                None,
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            opens
                .resolve(
                    31,
                    attempt.circuit_id,
                    "destination-key",
                    OpenResult::Acknowledged,
                )
                .await
        );
        assert_eq!(waiter.await.unwrap(), OpenResult::Acknowledged);
        let active = opens
            .commit_if_current(
                &attempt,
                chacha20poly1305::Key::from([3; 32]),
                current.ordered_path.clone(),
                1300,
            )
            .await
            .unwrap();
        assert_eq!(active.path, current.ordered_path);
    }

    #[tokio::test]
    async fn active_budget_can_shrink_without_closing_lease() {
        let opens = CircuitOpenManager::default();
        opens
            .activate(
                "exit".into(),
                CircuitId([20; 16]),
                chacha20poly1305::Key::from([9; 32]),
                7,
                (vec!["source".into(), "exit".into()], 1400),
            )
            .await;
        let (epoch, gate, budget) = opens
            .active_send_context("exit", 7)
            .await
            .expect("active snapshot");
        assert!(gate.load(Ordering::Acquire));
        assert_eq!(epoch, 1);
        assert_eq!(budget.load(Ordering::Acquire), 1400);
        assert!(
            opens
                .update_active_budget_with_vector(
                    "exit",
                    7,
                    1500,
                    1100,
                    CapacityVector {
                        edges: vec![CapacityEdge {
                            from: "source".into(),
                            to: "exit".into(),
                            capacity: 1100,
                            generation: 1,
                        }],
                    },
                )
                .await
        );
        assert!(opens.is_active("exit", CircuitId([20; 16])).await);
        assert_eq!(budget.load(Ordering::Acquire), 1100);
        assert!(opens.update_active_budget("exit", 7, 1500, 1500).await);
        assert_eq!(budget.load(Ordering::Acquire), 1100);
        assert!(
            opens
                .update_active_budget_with_vector(
                    "exit",
                    7,
                    1500,
                    1500,
                    CapacityVector {
                        edges: vec![CapacityEdge {
                            from: "source".into(),
                            to: "exit".into(),
                            capacity: 1500,
                            generation: 2,
                        }],
                    },
                )
                .await
        );
        assert_eq!(budget.load(Ordering::Acquire), 1400);
        opens.deactivate("exit", CircuitId([20; 16])).await;
        assert!(!gate.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn config_generation_invalidates_ack_even_when_guard_is_stale() {
        let opens = CircuitOpenManager::default();
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 21,
        };
        opens
            .set_desired_guard("exit", Some(identity.clone()), 0, false)
            .await;
        let attempt = opens
            .begin_attempt("exit", CircuitId([21; 16]), identity, 0, 21)
            .await
            .unwrap();
        opens.bump_config_generation();
        assert!(matches!(
            opens
                .commit_if_current(
                    &attempt,
                    chacha20poly1305::Key::from([1; 32]),
                    attempt.identity.ordered_path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::StaleAttempt)
        ));
    }

    #[tokio::test]
    async fn stale_capacity_event_cannot_raise_or_rewrite_active_budget() {
        let opens = CircuitOpenManager::default();
        opens
            .activate(
                "exit".into(),
                CircuitId([22; 16]),
                chacha20poly1305::Key::from([2; 32]),
                22,
                (vec!["source".into(), "exit".into()], 1400),
            )
            .await;
        let before_capacity_event = opens.active_generation();
        let first = opens.update_active_link_capacity(22, 1100, 4).await;
        assert_eq!(first, 1);
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            opens.wait_active_change(before_capacity_event),
        )
        .await
        .expect("a changed local capacity must wake route refresh");
        assert_eq!(opens.active_path_inner_mtu("exit", 22).await, Some(1100));
        let after_capacity_event = opens.active_generation();
        assert_eq!(opens.update_active_link_capacity(22, 1500, 3).await, 0);
        assert_eq!(opens.active_generation(), after_capacity_event);
        assert_eq!(opens.active_path_inner_mtu("exit", 22).await, Some(1100));
    }

    #[tokio::test]
    async fn binding_health_edges_wake_route_refresh_without_duplicate_notifications() {
        let opens = CircuitOpenManager::default();
        let healthy = AtomicBool::new(true);

        let generation = opens.active_generation();
        assert!(!set_binding_health(&healthy, true, &opens));
        assert_eq!(opens.active_generation(), generation);

        assert!(set_binding_health(&healthy, false, &opens));
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            opens.wait_active_change(generation),
        )
        .await
        .expect("a binding health failure must wake route refresh");

        let unhealthy_generation = opens.active_generation();
        assert!(!set_binding_health(&healthy, false, &opens));
        assert_eq!(opens.active_generation(), unhealthy_generation);

        assert!(set_binding_health(&healthy, true, &opens));
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            opens.wait_active_change(unhealthy_generation),
        )
        .await
        .expect("binding health recovery must wake route refresh");
    }

    #[tokio::test]
    async fn preferred_migration_readiness_is_stable_and_single_flight() {
        let opens = CircuitOpenManager::default();
        let path = vec!["source".into(), "relay".into(), "exit".into()];
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: path.clone(),
            first_hop_link_instance: 7,
        };
        assert!(matches!(
            opens
                .migration_readiness("exit", &identity, true, std::time::Duration::from_millis(2))
                .await,
            Some(MigrationReadiness::PendingUntil(_))
        ));
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        assert_eq!(
            opens
                .migration_readiness("exit", &identity, true, std::time::Duration::from_millis(2))
                .await,
            Some(MigrationReadiness::Ready)
        );
        opens.begin_migration("exit").await;
        assert!(
            opens
                .migration_overdue("exit", std::time::Duration::ZERO)
                .await
        );
        let replacement_identity = crate::reconcile::CircuitIdentity {
            first_hop_link_instance: 8,
            ..identity.clone()
        };
        opens.reset_migration_readiness("exit").await;
        assert!(matches!(
            opens
                .migration_readiness(
                    "exit",
                    &replacement_identity,
                    true,
                    std::time::Duration::from_millis(2),
                )
                .await,
            Some(MigrationReadiness::PendingUntil(_))
        ));
        opens.reset_migration_readiness("exit").await;
        assert!(matches!(
            opens
                .migration_readiness("exit", &identity, true, std::time::Duration::from_millis(2))
                .await,
            Some(MigrationReadiness::PendingUntil(_))
        ));
        assert_eq!(
            opens
                .migration_readiness(
                    "exit",
                    &identity,
                    false,
                    std::time::Duration::from_millis(2),
                )
                .await,
            None
        );
        assert_eq!(
            opens
                .migration_readiness("exit", &identity, true, std::time::Duration::MAX)
                .await,
            Some(MigrationReadiness::Pending)
        );
        let claim = opens.claim_worker("exit").expect("first claim");
        assert!(opens.claim_worker("exit").is_none());
        drop(claim);
        assert!(opens.claim_worker("exit").is_some());
        opens.reset_migration_readiness("exit").await;
        assert!(opens.migration_snapshot("exit").await.is_none());
    }

    #[tokio::test]
    async fn link_removal_wakes_worker_even_if_notification_precedes_wait() {
        let opens = CircuitOpenManager::default();
        let id = CircuitId([7; 16]);
        opens
            .activate(
                "relay".into(),
                id,
                chacha20poly1305::Key::from([2; 32]),
                10,
                (vec!["source".into(), "relay".into()], 1200),
            )
            .await;
        let generation = opens.active_generation();
        opens
            .remove_link(10, crate::link::LinkToken::default())
            .await;
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            opens.wait_active_change(generation),
        )
        .await
        .expect("link removal must not leave an idle worker asleep");
        assert!(!opens.is_active("relay", id).await);
    }

    #[tokio::test]
    async fn link_addition_restarts_pending_reconciliation_without_waiting_backoff() {
        let opens = CircuitOpenManager::default();
        let generation = opens.active_generation();
        opens.request_reconcile();
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            opens.wait_active_change(generation),
        )
        .await
        .expect("new first-hop Link wakes a pending circuit worker");
    }

    #[tokio::test]
    async fn sequence_rebuild_request_is_deduplicated_and_wakes_worker() {
        let opens = CircuitOpenManager::default();
        let generation = opens.active_generation();
        opens.request_rebuild("exit").await;
        assert!(opens.take_rebuild_request("exit").await);
        assert!(!opens.take_rebuild_request("exit").await);
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            opens.wait_active_change(generation),
        )
        .await
        .expect("sequence exhaustion must wake the persistent circuit worker");
    }

    #[tokio::test]
    async fn ensure_requests_are_deduplicated_without_a_growing_queue() {
        let opens = CircuitOpenManager::default();
        opens.request_ensure("exit").await;
        opens.request_ensure("exit").await;
        opens.request_ensure("relay").await;
        let mut requests = opens.wait_for_ensure_requests().await;
        requests.sort();
        assert_eq!(requests, vec!["exit", "relay"]);

        let pending = opens.clone();
        let waiter = tokio::spawn(async move { pending.wait_for_ensure_requests().await });
        opens.request_ensure("exit").await;
        assert_eq!(waiter.await.unwrap(), vec!["exit"]);
    }

    #[tokio::test]
    async fn removing_circuit_drops_its_receiver_session_immediately() {
        let source = crate::identity::generate();
        let sessions = SessionManager::default();
        let id = CircuitId([8; 16]);
        sessions
            .install_open(
                11,
                id,
                source.verifying_key(),
                chacha20poly1305::Key::from([3; 32]),
            )
            .await;
        sessions.remove_circuit(11, id).await;
        let mut frame = vec![0_u8; crypto::FRAME_OVERHEAD];
        frame[..16].copy_from_slice(&id.0);
        assert!(matches!(
            sessions.open_data(11, &frame).await,
            Err(crypto::CryptoError::UnknownSession)
        ));
    }

    #[tokio::test]
    async fn circuit_open_lifecycle_covers_authorization_cleanup_and_active_queries() {
        let opens = CircuitOpenManager::default();
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 41,
        };
        opens
            .set_desired_guard("exit", Some(identity.clone()), 0, true)
            .await;
        assert!(opens.desired_is_hard_revoked("exit").await);
        opens
            .set_desired_guard("ready", Some(identity.clone()), 0, false)
            .await;
        assert!(!opens.desired_is_hard_revoked("ready").await);

        let circuit_id = CircuitId([41; 16]);
        let waiter = opens
            .register(
                41,
                circuit_id,
                "expected".into(),
                vec!["reject".into()],
                None,
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            !opens
                .resolve(41, circuit_id, "wrong", OpenResult::Acknowledged,)
                .await
        );
        assert!(
            !opens
                .resolve(
                    41,
                    circuit_id,
                    "wrong",
                    OpenResult::Rejected {
                        retryable: false,
                        reason: "wrong signer".into(),
                    },
                )
                .await
        );
        assert!(
            opens
                .resolve(
                    41,
                    circuit_id,
                    "reject",
                    OpenResult::Rejected {
                        retryable: true,
                        reason: "temporary".into(),
                    },
                )
                .await
        );
        assert_eq!(
            waiter.await.unwrap(),
            OpenResult::Rejected {
                retryable: true,
                reason: "temporary".into()
            }
        );
        assert!(!opens.is_authorized(41, circuit_id).await);

        let attempt = opens
            .begin_attempt("ready", circuit_id, identity.clone(), 0, 41)
            .await
            .unwrap();
        assert!(
            opens
                .begin_attempt("ready", CircuitId([42; 16]), identity.clone(), 0, 41,)
                .await
                .is_none()
        );
        opens.cancel_attempt(&attempt).await;
        assert!(
            opens
                .begin_attempt("ready", circuit_id, identity, 0, 41)
                .await
                .is_some()
        );

        opens
            .activate(
                "ready".into(),
                circuit_id,
                chacha20poly1305::Key::from([41; 32]),
                41,
                (vec!["source".into(), "exit".into()], 1300),
            )
            .await;
        let active = opens.active_for_destination("ready").await.unwrap();
        assert_eq!(active.circuit_id, circuit_id);
        assert_eq!(opens.active_circuits().await.len(), 1);
        assert!(opens.is_active("ready", circuit_id).await);
        assert!(opens.active_for("ready", 41).await.is_some());
        assert!(opens.active_for("ready", 99).await.is_none());
        assert!(opens.active_send_context("ready", 99).await.is_none());
        assert!(!opens.update_active_budget("ready", 99, 1400, 1400).await);
        assert!(
            !opens
                .update_active_budget_for_lease(
                    ("ready", circuit_id, &["source".into(), "other".into()], 41),
                    1400,
                    1400,
                    CapacityVector::default(),
                )
                .await
        );

        opens
            .remove_link(41, crate::link::LinkToken::default())
            .await;
        assert!(!opens.is_active("ready", circuit_id).await);
        assert!(!opens.is_authorized(41, circuit_id).await);
        assert!(opens.active_for_destination("ready").await.is_none());
    }

    #[tokio::test]
    async fn circuit_open_commit_rejects_hard_revocation_and_unauthorized_attempts() {
        let opens = CircuitOpenManager::default();
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 51,
        };
        opens
            .set_desired_guard("exit", Some(identity.clone()), 0, true)
            .await;
        let attempt = opens
            .begin_attempt("exit", CircuitId([51; 16]), identity, 0, 51)
            .await
            .unwrap();
        assert!(matches!(
            opens
                .commit_if_current(
                    &attempt,
                    chacha20poly1305::Key::from([51; 32]),
                    attempt.identity.ordered_path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::HardRevoked)
        ));

        let identity = crate::reconcile::CircuitIdentity {
            destination: "other".into(),
            ordered_path: vec!["source".into(), "other".into()],
            first_hop_link_instance: 52,
        };
        opens
            .set_desired_guard("other", Some(identity.clone()), 0, false)
            .await;
        let attempt = opens
            .begin_attempt("other", CircuitId([52; 16]), identity, 0, 52)
            .await
            .unwrap();
        assert!(matches!(
            opens
                .commit_if_current(
                    &attempt,
                    chacha20poly1305::Key::from([52; 32]),
                    attempt.identity.ordered_path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::Unauthorized)
        ));
    }
}

/// Optional local and remote egress capabilities installed on a TUN router.
pub struct RouterEgress {
    pub remote: Option<EgressPolicy>,
    pub source_policy: SourceAddressPolicy,
    pub direct: Option<DirectEgress>,
    pub clamp_mss: bool,
    pub fake_ip: Option<Arc<crate::fake_ip::FakeIpRuntime>>,
    pub return_flows: crate::return_path::ReturnFlowTable,
}

/// Direct fallback state shared by the composition root and TUN sender.
///
/// Reinjection stays fail-closed until the nftables zone and mark rules have
/// been installed. The conntrack worker itself is started earlier so it can
/// flush stale entries left by a previous process before traffic resumes.
#[derive(Clone)]
pub struct DirectEgress {
    dscp: u8,
    conntrack: DirectConntrack,
    ready: Arc<AtomicBool>,
    fallback: bool,
}

impl DirectEgress {
    pub fn open(dscp: u8, conntrack_zone: u16, fallback: bool) -> Result<Self, PlatformError> {
        Ok(Self {
            dscp,
            conntrack: DirectConntrack::open(conntrack_zone)?,
            ready: Arc::new(AtomicBool::new(false)),
            fallback,
        })
    }

    pub fn activate(&self) {
        self.ready.store(true, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

const MAX_DIRECT_FALLBACK_FLOWS: usize = 65_536;

/// Per-link TUN output limits. Kept together because both values govern the
/// same packet mutation-and-size check at the data-plane boundary.
#[derive(Clone, Copy)]
pub struct TunLinkOptions {
    pub mtu: u16,
    pub clamp_mss: bool,
}

/// See `crypto` for the authenticated ephemeral-key frame layout.
pub const SECURE_FRAME_OVERHEAD: usize = crypto::FRAME_OVERHEAD;

/// Owns a mutable set of source-side route bindings. Replacing bindings is
/// used after a QUIC reconnect so new flows never keep a closed Link.
pub struct TunRouter {
    routes: Arc<RwLock<Arc<RouteSnapshot>>>,
    receiver_tx: mpsc::UnboundedSender<Arc<Link>>,
    cancellation: CancellationToken,
    sessions: SessionManager,
}

impl TunRouter {
    /// Attach a Link as a possible inbound encrypted-packet source.  This is
    /// intentionally independent from route selection: an exit must be able
    /// to receive a client's first packet even when it has no local
    /// `route_imports` of its own.
    pub fn attach_link(&self, link: Arc<Link>) {
        let _ = self.receiver_tx.send(link);
    }

    pub async fn replace_routes(&self, snapshot: RouteSnapshot) {
        // Route snapshots carry send capabilities only. Inbound receive
        // workers are attached separately from the concrete Link registry
        // via `attach_link`, so route selection never observes transport
        // internals.
        *self.routes.write().await = Arc::new(snapshot);
    }

    /// Stop all router workers and discard cryptographic state that is scoped
    /// to the daemon lifetime. This is safe to call more than once.
    pub async fn shutdown(&self) {
        self.cancellation.cancel();
        self.sessions.clear().await;
    }
}

pub fn frame_fits_current_budget(frame_len: usize, physical_budget: usize) -> bool {
    frame_len.saturating_add(crate::physical::FORWARD_OVERHEAD) <= physical_budget
}

/// Check a complete user payload against the normalized end-to-end capacity.
/// The payload may be an IP packet or a protocol-specific authenticated
/// payload (such as the Circuit DNS request); Tinect and carrier overhead are
/// accounted for by the capacity publisher, not by each caller.
pub fn user_packet_fits_current_budget(packet_len: usize, user_ip_capacity: usize) -> bool {
    packet_len <= user_ip_capacity
}

fn secure_sender_rejection(
    send_gate_open: bool,
    packet_len: usize,
    user_ip_capacity: usize,
) -> Option<&'static str> {
    if !send_gate_open {
        Some("lease:stale_epoch")
    } else if !user_packet_fits_current_budget(packet_len, user_ip_capacity) {
        Some("packet:exceeds_path_mtu")
    } else {
        None
    }
}

/// Classifies the source-side send gate before a packet enters the secure
/// sender queue.  A closed lease gate is a lifecycle condition, not an MTU
/// violation; keeping the two reasons separate prevents route churn from
/// being misdiagnosed as PMTU failure.
pub(crate) fn source_send_rejection(
    send_gate_open: bool,
    packet_len: usize,
    user_ip_capacity: usize,
) -> Option<&'static str> {
    if !send_gate_open {
        Some("lease:not_ready")
    } else if !user_packet_fits_current_budget(packet_len, user_ip_capacity) {
        Some("packet:exceeds_path_mtu")
    } else {
        None
    }
}

/// Apply origin-signed advertisements, then fan accepted deltas out across
/// physical adjacencies. The LSA remains opaque to the carrier layer and is
/// verified before it can be re-advertised.
pub async fn apply_topology(
    incoming: &Link,
    advertisements: Vec<crate::topology::LinkStateAdvertisement>,
    topology: &Arc<RwLock<Topology>>,
) -> Vec<crate::topology::LinkStateAdvertisement> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut accepted = Vec::new();
    {
        let mut database = topology.write().await;
        database.prune(now);
        for advertisement in advertisements {
            let generation_before = database.generation();
            match database.apply(advertisement.clone(), now) {
                // A refreshed LSA with the same neighbor/capacity set only
                // advances the anti-replay sequence.  Reconcile and fanout
                // only for records that actually change the path set, so a
                // keepalive-driven advertisement stream cannot wake the
                // control plane on every tick.
                Ok(true) if database.generation() != generation_before => {
                    accepted.push(advertisement)
                }
                Ok(true) => {}
                Ok(false) => {}
                Err(crate::topology::TopologyError::Replay) => {
                    tracing::debug!(
                        peer_name = %incoming.peer,
                        peer_identity = %incoming.peer_identity,
                        "topology advertisement replayed"
                    )
                }
                Err(error) => {
                    tracing::warn!(peer_name = %incoming.peer, peer_identity = %incoming.peer_identity, error = %error, "topology advertisement rejected")
                }
            }
        }
    }
    accepted
}

/// Snapshot application is all-or-nothing for malformed records. A sender's
/// view cannot delete unrelated local state, while an invalid member cannot
/// leave a partially installed batch behind.
pub async fn apply_topology_snapshot(
    incoming: &Link,
    advertisements: Vec<crate::topology::LinkStateAdvertisement>,
    topology: &Arc<RwLock<Topology>>,
) -> Result<Vec<crate::topology::LinkStateAdvertisement>, crate::topology::TopologyError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut database = topology.write().await;
    database.prune(now);
    database.apply_snapshot(advertisements, now).map_err(|error| {
        tracing::warn!(peer_name = %incoming.peer, peer_identity = %incoming.peer_identity, error = %error, "reliable topology snapshot rejected");
        error
    })
}

/// Connects a TUN device to a single authenticated Link. Routing policy is
/// deliberately supplied by the caller; this primitive never guesses an
/// exit or changes host routes.
pub fn spawn_tun_link(
    device: TunDevice,
    link: Arc<Link>,
    source_policy: SourceAddressPolicy,
    supervisor: DaemonSupervisor,
) {
    let tx_device = device.clone();
    let tx_link = link.clone();
    supervisor.spawn_background(async move {
        let mut packet = vec![0u8; 65535];
        loop {
            let size = match tx_device.recv(&mut packet).await {
                Ok(size) => size,
                Err(error) => {
                    tracing::info!(error = %error, "single-link TUN sender stopped");
                    return;
                }
            };
            if let Err(error) = tx_link.send_forward(&packet[..size]) {
                tracing::info!(error = %error, "single-link physical sender stopped");
                return;
            }
        }
    });
    supervisor.spawn_background(async move {
        let Some(mut receiver) = link.take_forward_receiver().await else {
            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, "single-link Forward receiver was already claimed");
            return;
        };
        loop {
            let Some(frame) = receiver.recv().await else {
                tracing::info!("single-link physical receiver stopped");
                return;
            };
            if !source_policy.authorize(&link.peer_identity, frame.as_ref()) {
                continue;
            }
            if let Err(error) = device.send(frame.as_ref()).await {
                tracing::info!(error = %error, "single-link TUN receiver stopped");
                return;
            }
        }
    });
}

/// Bidirectional TUN bridge for multiple imported routes and exits.
///
/// The outbound side performs longest-prefix selection and per-packet health
/// selection;
/// inbound workers are one-per-link and decrypt packets at the final node.
/// Relays continue to see only the opaque frame and local circuit label.
/// Outbound queue item. Fields are the minimum the sender worker needs so the
/// TUN reader does not clone a full `SecureRoute` on every packet.
struct QueuedSecurePacket {
    packet: Vec<u8>,
    exit: String,
    circuit_id: CircuitId,
    data_key: chacha20poly1305::Key,
    link: LinkRef,
    healthy: Arc<std::sync::atomic::AtomicBool>,
    lease_epoch: u64,
    send_gate: Arc<std::sync::atomic::AtomicBool>,
    send_budget: Arc<AtomicUsize>,
}

fn set_binding_health(
    healthy: &AtomicBool,
    next: bool,
    circuit_opens: &CircuitOpenManager,
) -> bool {
    let changed = healthy.swap(next, Ordering::Relaxed) != next;
    if changed {
        circuit_opens.request_reconcile();
    }
    changed
}

async fn run_secure_sender_worker(
    mut receiver: mpsc::Receiver<QueuedSecurePacket>,
    _identity: Arc<SigningKey>,
    _sessions: SessionManager,
    circuit_opens: CircuitOpenManager,
    cancellation: CancellationToken,
    metrics: Arc<Observability>,
    supervisor: DaemonSupervisor,
) {
    tracing::info!("secure sender worker started");
    let mut sender_sessions =
        HashMap::<(String, u64, CircuitId), (u64, crypto::SenderSession)>::new();
    while let Some(queued) = tokio::select! {
        _ = cancellation.cancelled() => return,
        packet = receiver.recv() => packet,
    } {
        let QueuedSecurePacket {
            packet,
            exit,
            circuit_id,
            data_key,
            link,
            healthy,
            lease_epoch,
            send_gate,
            send_budget,
        } = queued;
        if let Some(reason) = secure_sender_rejection(
            send_gate.load(Ordering::Acquire),
            packet.len(),
            send_budget.load(Ordering::Acquire),
        ) {
            metrics.reject(reason);
            continue;
        }
        // A successful rebuild changes both the lease epoch and circuit id.
        // Stale queued packets are rejected by the send gate above, so old
        // sessions can be discarded once the new binding reaches this worker.
        // This keeps repeated circuit reconstruction from growing the cache
        // without bound.
        sender_sessions.retain(|(session_exit, session_epoch, session_circuit), _| {
            session_exit != &exit
                || (*session_epoch == lease_epoch && *session_circuit == circuit_id)
        });
        let link_instance = link.instance();
        let session = sender_sessions
            .entry((exit.clone(), lease_epoch, circuit_id))
            .or_insert_with(|| {
                (
                    link_instance,
                    crypto::SenderSession::from_key(circuit_id, data_key),
                )
            });
        if session.0 != link_instance {
            *session = (
                link_instance,
                crypto::SenderSession::from_key(circuit_id, data_key),
            );
        }
        let frame = match session.1.encrypt(&packet) {
            Ok(frame) => Some(frame),
            Err(error) => {
                metrics.reject("session:sequence_exhausted");
                tracing::warn!(%exit, error = %error, "circuit data sequence exhausted");
                circuit_opens.request_rebuild(&exit).await;
                None
            }
        };
        let Some(frame) = frame else {
            continue;
        };
        let mut backpressure_retries = 0;
        loop {
            // The packet may have waited in the queue or during a previous
            // retry while the active path budget was reduced.  Re-read both
            // gates immediately before every carrier attempt, including the
            // first attempt after encryption.
            if let Some(reason) = secure_sender_rejection(
                send_gate.load(Ordering::Acquire),
                packet.len(),
                send_budget.load(Ordering::Acquire),
            ) {
                metrics.reject(reason);
                break;
            }
            match link.send_forward(frame) {
                Ok(()) => {
                    link.set_healthy(true);
                    set_binding_health(healthy.as_ref(), link.is_healthy(), &circuit_opens);
                    break;
                }
                Err(LinkError::DatagramTooLarge { .. }) => {
                    metrics.reject("packet:exceeds_datagram_limit");
                    break;
                }
                Err(LinkError::AdmissionRejected) => {
                    // Priority/queue admission is local backpressure, not a
                    // Link failure. Drop this frame and let the next queued
                    // frame try again without triggering circuit recovery.
                    metrics.reject("queue:admission_rejected");
                    break;
                }
                Err(error)
                    if is_transient_datagram_backpressure(&error) && backpressure_retries < 64 =>
                {
                    backpressure_retries += 1;
                    // A full kernel/QUIC transmit queue is normal under load.
                    // Wait for the sender to make progress instead of marking
                    // the route unhealthy and forcing circuit reconstruction.
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Err(error) => {
                    link.set_healthy(false);
                    // Only schedule one cool-down when flipping healthy → unhealthy.
                    // Sustained send failures must not accumulate timer tasks.
                    if set_binding_health(healthy.as_ref(), false, &circuit_opens) {
                        let healthy_reset = healthy.clone();
                        let reset_opens = circuit_opens.clone();
                        let reset_link = link.clone();
                        supervisor.spawn_background(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            // Route snapshots are rebuilt on every health edge.
                            // Restoring only the old snapshot's binding would
                            // leave newly built bindings unhealthy forever.
                            // A disconnected Link must remain unhealthy: this
                            // timer belongs to the old instance and must not
                            // revive a path while reconnect is in progress.
                            if !reset_link.is_closed() {
                                reset_link.set_healthy(true);
                                set_binding_health(
                                    healthy_reset.as_ref(),
                                    reset_link.is_healthy(),
                                    &reset_opens,
                                );
                            }
                        });
                    }
                    tracing::warn!(%exit, error = %error, "QUIC DATAGRAM send failed; route marked unhealthy");
                    break;
                }
            }
        }
    }
}

fn is_transient_datagram_backpressure(error: &LinkError) -> bool {
    matches!(error, LinkError::WouldBlock)
}

async fn resolve_overlay_dns(
    request: crate::fake_ip::OverlayDnsRequest,
    routes: Arc<RwLock<Arc<RouteSnapshot>>>,
    client: CircuitDnsClient,
    opens: CircuitOpenManager,
    allow_fallback: bool,
) {
    let snapshot = routes.read().await.clone();
    let candidates = snapshot.domain_candidates(&request.domain);
    if candidates.is_empty() {
        let hint = crate::fake_ip::FakeRouteHint {
            domain: request.domain.clone(),
            preferred_route: None,
        };
        for destination in
            snapshot.ensure_candidates(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(&hint))
        {
            opens.request_ensure(destination).await;
        }
    }
    let mut errors = Vec::new();
    let mut direct_attempted = false;
    for candidate in candidates {
        match candidate {
            DomainResolutionCandidate::Secure {
                binding,
                upstream_dns,
            } => {
                for upstream in upstream_dns.iter() {
                    match client.query(&binding, upstream, &request.wire).await {
                        Ok(wire) if dns_response_is_success(&wire) => {
                            let _ = request
                                .response
                                .send(Ok(crate::fake_ip::OverlayDnsResponse {
                                    wire,
                                    preferred_route: crate::fake_ip::RoutePreference::Exit(
                                        binding.exit,
                                    ),
                                }));
                            return;
                        }
                        Ok(_) => errors.push(format!(
                            "{} via {} returned an unsuccessful DNS response",
                            upstream.socket_addr(),
                            binding.exit
                        )),
                        Err(error) => errors.push(format!(
                            "{} via {} failed: {error}",
                            upstream.socket_addr(),
                            binding.exit
                        )),
                    }
                }
            }
            DomainResolutionCandidate::Direct { .. } => {
                direct_attempted = true;
                if let Some(wire) = query_direct_dns(&request, &mut errors).await {
                    let _ = request
                        .response
                        .send(Ok(crate::fake_ip::OverlayDnsResponse {
                            wire,
                            preferred_route: crate::fake_ip::RoutePreference::Direct,
                        }));
                    return;
                }
            }
        }
    }
    if allow_fallback
        && !direct_attempted
        && let Some(wire) = query_direct_dns(&request, &mut errors).await
    {
        let _ = request
            .response
            .send(Ok(crate::fake_ip::OverlayDnsResponse {
                wire,
                preferred_route: crate::fake_ip::RoutePreference::Direct,
            }));
        return;
    }
    let reason = if errors.is_empty() {
        "no healthy domain route candidate".to_owned()
    } else {
        errors.join(" | ")
    };
    let _ = request.response.send(Err(reason));
}

async fn query_direct_dns(
    request: &crate::fake_ip::OverlayDnsRequest,
    errors: &mut Vec<String>,
) -> Option<Vec<u8>> {
    for upstream in &request.upstreams {
        match crate::fake_ip::query_upstream(upstream, &request.wire).await {
            Ok(message) => match message.to_vec() {
                Ok(wire) if dns_response_is_success(&wire) => return Some(wire),
                Ok(_) => errors.push(format!(
                    "{} via local direct returned an unsuccessful DNS response",
                    upstream.socket_addr()
                )),
                Err(error) => errors.push(format!(
                    "{} via local direct returned invalid DNS: {error}",
                    upstream.socket_addr()
                )),
            },
            Err(error) => errors.push(format!(
                "{} via local direct failed: {error}",
                upstream.socket_addr()
            )),
        }
    }
    None
}

fn dns_response_is_success(wire: &[u8]) -> bool {
    hickory_proto::op::Message::from_vec(wire).is_ok_and(|message| {
        matches!(
            message.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError | hickory_proto::op::ResponseCode::NXDomain
        )
    })
}

trait FakeIpMode: Clone + Send + Sync + 'static {
    fn runtime(&self) -> Option<&Arc<crate::fake_ip::FakeIpRuntime>>;

    #[inline(always)]
    fn restore_direct_return(&self, _packet: &mut [u8]) -> bool {
        false
    }

    #[inline(always)]
    fn route_hint(&self, _destination: IpAddr) -> Option<crate::fake_ip::FakeRouteHint> {
        None
    }

    #[inline(always)]
    fn contains_fake_address(&self, _destination: IpAddr) -> bool {
        false
    }

    #[inline(always)]
    fn translate_outbound(&self, _packet: &mut [u8]) -> bool {
        false
    }

    #[inline(always)]
    fn translate_outbound_direct(&self, packet: &mut [u8]) -> bool {
        self.translate_outbound(packet)
    }

    #[inline(always)]
    fn restore_circuit_return(&self, _packet: &mut [u8], fake_destination: Option<IpAddr>) -> bool {
        fake_destination.is_none()
    }
}

#[derive(Clone, Copy)]
struct FakeIpDisabled;

impl FakeIpMode for FakeIpDisabled {
    #[inline(always)]
    fn runtime(&self) -> Option<&Arc<crate::fake_ip::FakeIpRuntime>> {
        None
    }
}

#[derive(Clone)]
struct FakeIpEnabled(Arc<crate::fake_ip::FakeIpRuntime>);

impl FakeIpMode for FakeIpEnabled {
    fn runtime(&self) -> Option<&Arc<crate::fake_ip::FakeIpRuntime>> {
        Some(&self.0)
    }

    fn restore_direct_return(&self, packet: &mut [u8]) -> bool {
        self.0.translate_inbound(packet, None)
    }

    fn route_hint(&self, destination: IpAddr) -> Option<crate::fake_ip::FakeRouteHint> {
        self.0.route_hint_for_fake(destination)
    }

    fn contains_fake_address(&self, destination: IpAddr) -> bool {
        self.0.contains_fake_address(destination)
    }

    fn translate_outbound(&self, packet: &mut [u8]) -> bool {
        self.0.translate_outbound(packet)
    }

    fn translate_outbound_direct(&self, packet: &mut [u8]) -> bool {
        self.0.translate_outbound_direct(packet)
    }

    fn restore_circuit_return(&self, packet: &mut [u8], fake_destination: Option<IpAddr>) -> bool {
        fake_destination.is_none() || self.0.translate_inbound(packet, fake_destination)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_tun_router_secure(
    device: TunDevice,
    snapshot: RouteSnapshot,
    receive_links: Vec<Arc<Link>>,
    identity: Arc<SigningKey>,
    mut egress: RouterEgress,
    metrics: Arc<Observability>,
    inbound: InboundDispatch,
    supervisor: DaemonSupervisor,
) -> TunRouter {
    match egress.fake_ip.take() {
        Some(fake_ip) => spawn_tun_router_secure_mode(
            device,
            snapshot,
            receive_links,
            identity,
            egress,
            metrics,
            inbound,
            supervisor,
            FakeIpEnabled(fake_ip),
        ),
        None => spawn_tun_router_secure_mode(
            device,
            snapshot,
            receive_links,
            identity,
            egress,
            metrics,
            inbound,
            supervisor,
            FakeIpDisabled,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_tun_router_secure_mode<F: FakeIpMode>(
    device: TunDevice,
    snapshot: RouteSnapshot,
    receive_links: Vec<Arc<Link>>,
    identity: Arc<SigningKey>,
    egress: RouterEgress,
    metrics: Arc<Observability>,
    inbound: InboundDispatch,
    supervisor: DaemonSupervisor,
    fake_ip: F,
) -> TunRouter {
    let cancellation = inbound.cancellation.clone();
    // Inbound receive workers take the concrete Link: only the physical
    // transport owns the forward receiver and lifecycle. The route snapshot
    // contributes send-only handles.
    let initial_links = receive_links;
    let routes = Arc::new(RwLock::new(Arc::new(snapshot)));
    if let Some(fake_ip) = fake_ip.runtime() {
        let (dns_tx, mut dns_rx) = mpsc::channel(256);
        let allow_fallback = egress.direct.as_ref().is_some_and(|direct| direct.fallback);
        fake_ip.install_overlay_dns(dns_tx);
        let dns_routes = routes.clone();
        let dns_client = inbound.circuit_dns.clone();
        let dns_opens = inbound.circuit_opens.clone();
        let dns_supervisor = supervisor.clone();
        supervisor.spawn_background(async move {
            while let Some(request) = dns_rx.recv().await {
                let routes = dns_routes.clone();
                let client = dns_client.clone();
                let opens = dns_opens.clone();
                dns_supervisor.spawn_background(async move {
                    resolve_overlay_dns(request, routes, client, opens, allow_fallback).await;
                });
            }
        });
    }
    let (receiver_tx, mut receiver_rx) = mpsc::unbounded_channel::<Arc<Link>>();

    let tx_device = device.clone();
    let tx_routes = routes.clone();
    let tx_metrics = metrics.clone();
    let tx_direct = egress.direct;
    let tx_fake_ip = fake_ip.clone();
    let tx_return_flows = egress.return_flows.clone();
    let tx_clamp_mss = egress.clamp_mss;
    let tx_cancellation = cancellation.clone();
    let worker_identity = identity.clone();
    let worker_sessions = inbound.sessions.clone();
    let worker_metrics = metrics.clone();
    let worker_circuit_opens = inbound.circuit_opens.clone();
    let tx_circuit_opens = inbound.circuit_opens.clone();
    let sender_supervisor = supervisor.clone();
    supervisor.spawn_background(async move {
        let mut workers = HashMap::<String, mpsc::Sender<QueuedSecurePacket>>::new();
        // Insertion-ordered fallback flows so a full table evicts the oldest
        // flow in O(log N), not via an O(N) scan or a hash-random victim an
        // attacker could churn.
        let mut direct_flows = HashMap::<ConntrackFlowKey, u64>::new();
        let mut direct_flow_order = BTreeMap::<u64, ConntrackFlowKey>::new();
        let mut direct_flow_seq: u64 = 0;
        let mut packet = vec![0u8; 65535];
        // Rate-limits ICMP Packet-Too-Big messages generated for oversized
        // TUN packets (see the `packet:exceeds_path_mtu` branch below). Without
        // a limit a local sender emitting a burst of oversized packets (or an
        // attacker spoofing source addresses via raw sockets) could turn the
        // TUN into a PTB amplifier. One PTB per 200ms is ample for PMTUD
        // (which needs one per RTT) while bounding amplification to 5/sec.
        let mut last_ptb = Instant::now()
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or_else(Instant::now);
        loop {
            let size = match tokio::select! {
                _ = tx_cancellation.cancelled() => return,
                result = tx_device.recv(&mut packet) => result,
            } {
                Ok(size) => size,
                Err(error) => {
                    tracing::error!(error = %error, "TUN receive stopped");
                    return;
                }
            };
            tx_metrics.tun_rx(size);
            if let Some(translation) = tx_return_flows.translate_return(&mut packet[..size]) {
                let return_payload = if let Some(fake_destination) = translation.fake_destination {
                    crate::fake_ip::encode_fake_ip_envelope(&packet[..size], fake_destination)
                } else {
                    packet[..size].to_vec()
                };
                let Some(frame) = tx_return_flows.encrypt_return(
                    &translation.target,
                    &return_payload,
                ) else {
                    tx_metrics.reject("return_path:no_session");
                    continue;
                };
                if let Err(error) = translation.target.link.send_forward(&frame) {
                    tx_metrics.reject("return_path:send_failed");
                    if translation.target.link.should_log_dataplane_warning() {
                        tracing::warn!(peer_name = %translation.target.link.peer_name(), peer_identity = %translation.target.link.peer_identity(), error = %error, "return-path DATAGRAM send failed");
                    }
                }
                continue;
            }
            // A direct-fallback FakeIP reply reaches the source TUN without
            // an encrypted return frame. Restore it before ordinary domain
            // routing can mistake the FakeIP destination for a new request.
            if tx_fake_ip.restore_direct_return(&mut packet[..size]) {
                tx_metrics.capture(&packet[..size]);
                if let Err(error) = tx_device.send(&packet[..size]).await {
                    tracing::error!(%error, "direct-fallback FakeIP return TUN send stopped");
                    return;
                }
                tx_metrics.tun_tx(size);
                continue;
            }
            let Some(destination) = inspect_ip_destination(&packet[..size]) else {
                tx_metrics.reject("packet:unsupported_or_malformed");
                continue;
            };
            let route_hint = tx_fake_ip.route_hint(destination);
            if tx_fake_ip.contains_fake_address(destination) && route_hint.is_none() {
                tx_metrics.reject("fake_ip:unknown_or_expired");
                continue;
            }
            let snapshot = tx_routes.read().await.clone();
            let route_started = Instant::now();
            let selection = snapshot.select_route(destination, route_hint.as_ref());
            tx_metrics.route_lookup(route_started.elapsed());
            if selection.is_none() {
                tx_metrics.reject("route:no_healthy_candidate");
                for candidate in snapshot.ensure_candidates(destination, route_hint.as_ref()) {
                    tx_circuit_opens.request_ensure(candidate).await;
                }
            }
            let direct_selected = matches!(selection, Some(RouteSelection::Direct));
            if direct_selected || selection.is_none() {
                let Some(direct) = tx_direct.as_ref().filter(|direct| {
                    direct_selected || direct.fallback
                }) else {
                    if route_hint.is_some() {
                        tx_metrics.reject("fake_ip:no_healthy_candidate");
                    }
                    continue;
                };
                if !direct.is_ready() {
                    tx_metrics.reject("route:direct_not_ready");
                    continue;
                }
                let dscp = direct.dscp;
                // A packet that already carries the marker DSCP is a
                // reinjected fallback packet coming back through a local
                // policy route rather than new traffic: dropping it here is
                // what bounds the no-fwmark fallback loop. Healthy overlay
                // traffic is matched before this branch, so a user packet
                // that legitimately uses the marker DSCP is still forwarded
                // over a healthy candidate.
                if packet_dscp(&packet[..size]) == Some(dscp) {
                    tx_metrics.reject("route:direct_loop");
                    continue;
                }
                // Kernel-generated control traffic such as IPv6 neighbor
                // discovery is not eligible for direct fallback. Filter it
                // before querying conntrack; some kernels reject a tuple for
                // these messages with EINVAL instead of reporting no entry.
                if route_hint.is_none()
                    && let Some(destination) = inspect_ip_destination(&packet[..size])
                    && !direct_eligible(destination)
                {
                    continue;
                }
                if let Err(error) = direct
                    .conntrack
                    .delete_default(&packet[..size])
                    .await
                {
                    tx_metrics.reject("route:direct_conntrack_failed");
                    tracing::warn!(%error, "failed to delete first-pass conntrack flow; direct fallback packet dropped");
                    continue;
                }
                if route_hint.is_some()
                    && !tx_fake_ip.translate_outbound_direct(&mut packet[..size])
                {
                    tx_metrics.reject("fake_ip:translation_failed");
                    continue;
                }
                let Some(fallback_destination) = inspect_ip_destination(&packet[..size]) else {
                    tx_metrics.reject("packet:unsupported_or_malformed");
                    continue;
                };
                // The kernel generates link-local multicast control traffic
                // (IPv6 MLD/NS, IPv4 IGMP/ARP-less probes) for the TUN
                // interface itself. Those destinations are never fake-IP
                // traffic, so reinjecting them would only re-mark and re-route
                // local control packets; leave them to the ordinary drop path.
                if !direct_eligible(fallback_destination) {
                    continue;
                }
                let Some(flow_key) = direct.conntrack.flow_key(&packet[..size]) else {
                    tx_metrics.reject("route:direct_conntrack_failed");
                    continue;
                };
                if !direct_flows.contains_key(&flow_key)
                    && direct_flows.len() >= MAX_DIRECT_FALLBACK_FLOWS
                {
                    let (&oldest_seq, oldest) = direct_flow_order
                        .iter()
                        .next()
                        .expect("non-empty fallback flow set at capacity");
                    let oldest = oldest.clone();
                    if let Err(error) = direct.conntrack.delete_fallback(oldest.clone()).await {
                        tx_metrics.reject("route:direct_capacity_cleanup_failed");
                        tracing::warn!(%error, "failed to evict direct fallback conntrack flow; new flow dropped");
                        continue;
                    }
                    direct_flows.remove(&oldest);
                    direct_flow_order.remove(&oldest_seq);
                }
                if !set_packet_dscp(&mut packet[..size], dscp) {
                    tx_metrics.reject("packet:unsupported_or_malformed");
                    continue;
                }
                // FIFO: only mint a sequence for newly tracked flows. Repeat
                // packets must not mint fresh seqs, or the seq/order 1:1
                // invariant breaks (orphaned order entries leak and eviction
                // can delete a live flow's conntrack from under it).
                if !direct_flows.contains_key(&flow_key) {
                    direct_flow_seq = direct_flow_seq.wrapping_add(1).max(1);
                    direct_flows.insert(flow_key.clone(), direct_flow_seq);
                    direct_flow_order.insert(direct_flow_seq, flow_key.clone());
                }
                tx_metrics.capture(&packet[..size]);
                if let Err(error) = tx_device.send(&packet[..size]).await {
                    if let Some(seq) = direct_flows.remove(&flow_key) {
                        direct_flow_order.remove(&seq);
                    }
                    if let Err(cleanup_error) =
                        direct.conntrack.delete_fallback(flow_key).await
                    {
                        tracing::warn!(error = %cleanup_error, "failed to clean direct fallback flow after TUN send failure");
                    }
                    tx_metrics.reject("route:direct_send_failed");
                    tracing::error!(error = %error, "direct fallback TUN reinjection stopped");
                    return;
                }
                tx_metrics.tun_tx(size);
                continue;
            }
            let Some(RouteSelection::Secure(binding)) = selection else {
                unreachable!("direct and empty route selections were handled above")
            };
            if let Some(fallback) = tx_direct.as_ref()
                && let Some(flow_key) = fallback.conntrack.flow_key(&packet[..size])
                && direct_flows.contains_key(&flow_key)
            {
                if let Err(error) = fallback.conntrack.delete_fallback(flow_key.clone()).await {
                    tx_metrics.reject("route:direct_cleanup_failed");
                    tracing::warn!(%error, "failed to remove direct fallback flow before overlay recovery");
                    continue;
                }
                if let Some(seq) = direct_flows.remove(&flow_key) {
                    direct_flow_order.remove(&seq);
                }
            }
            if route_hint.is_none() && inspect_ipv4_flow(&packet[..size]).is_none() {
                tx_metrics.reject("packet:unsupported_or_malformed");
                continue;
            }
            // Save the pre-translation header for PTB: `translate_outbound`
            // rewrites the FakeIP destination to the real upstream address, but
            // the local socket only knows the fake address. A PTB carrying the
            // real address would not match any socket and be ignored.
            let pre_translate_ptb_source: Option<Vec<u8>> = if route_hint.is_some() {
                Some(packet[..size].to_vec())
            } else {
                None
            };
            if route_hint.is_some() && !tx_fake_ip.translate_outbound(&mut packet[..size])
            {
                tx_metrics.reject("fake_ip:translation_failed");
                continue;
            }
            let fake_forward = route_hint.is_some();
            let envelope_overhead = route_hint
                .as_ref()
                .map(|_| crate::fake_ip::fake_ip_envelope_len(destination))
                .unwrap_or(0);
            // Use the live send budget for MSS clamping, not the snapshot-time
            // `binding.mtu` copy. The budget can be tightened by the first-hop
            // fast path (`update_active_link_capacity`) before the next route
            // snapshot rebuilds `binding.mtu`; clamping to the stale copy
            // would advertise an MSS that no longer fits the path, and the
            // subsequent send check (which uses the live budget) would drop
            // the very segments the peer was just told to send. Loading once
            // keeps clamp and drop consistent for this packet.
            let current_budget = binding.send_budget.load(std::sync::atomic::Ordering::Acquire);
            let effective_mtu = u16::try_from(
                current_budget.saturating_sub(envelope_overhead),
            )
            .unwrap_or(u16::MAX);
            clamp_mss_if_enabled(&mut packet[..size], effective_mtu, tx_clamp_mss);
            if let Some(reason) = source_send_rejection(
                binding.send_gate.load(std::sync::atomic::Ordering::Acquire),
                size + envelope_overhead,
                current_budget,
            ) {
                if reason == "packet:exceeds_path_mtu" {
                    // A TCP super-packet (for example a GSO coalesced write
                    // such as a multi-KB hybrid-KEX reply) can exceed the live
                    // budget while each MSS-sized piece would fit. Split it
                    // here so bulk transfer does not stall while small
                    // transfers succeed. Non-TCP oversized still falls through
                    // to the PTB path below. Segmentation success is not
                    // counted as a drop.
                    if let Some(segments) =
                        segment_tcp_gso(&packet[..size], effective_mtu)
                    {
                        tracing::debug!(exit = %binding.exit, packet_bytes = size, segments = segments.len(), user_ip_capacity = current_budget, "segmented TCP super-packet to the live budget");
                        let sender = if let Some(sender) = workers.get(&binding.exit) {
                            sender.clone()
                        } else {
                            let (sender, receiver) = mpsc::channel(256);
                            workers.insert(binding.exit.clone(), sender.clone());
                            sender_supervisor.spawn_background(run_secure_sender_worker(
                                receiver,
                                worker_identity.clone(),
                                worker_sessions.clone(),
                                worker_circuit_opens.clone(),
                                tx_cancellation.clone(),
                                worker_metrics.clone(),
                                sender_supervisor.clone(),
                            ));
                            sender
                        };
                        for segment in segments {
                            tx_metrics.circuit_tx(&binding.exit, segment.len());
                            tx_metrics.capture(&segment);
                            let queued_packet = if fake_forward {
                                crate::fake_ip::encode_fake_ip_envelope(&segment, destination)
                            } else {
                                segment
                            };
                            if sender
                                .try_send(QueuedSecurePacket {
                                    packet: queued_packet,
                                    exit: binding.exit.clone(),
                                    circuit_id: binding.circuit_id,
                                    data_key: binding.data_key,
                                    link: binding.link.clone(),
                                    healthy: binding.healthy.clone(),
                                    lease_epoch: binding.lease_epoch,
                                    send_gate: binding.send_gate.clone(),
                                    send_budget: binding.send_budget.clone(),
                                })
                                .is_err()
                            {
                                tx_metrics.reject("queue:send_drop");
                                tracing::debug!(exit = %binding.exit, "bounded secure sender queue is full");
                                break;
                            }
                        }
                        continue;
                    }
                    tx_metrics.reject(reason);
                    tracing::warn!(exit = %binding.exit, packet_bytes = size, user_ip_capacity = current_budget, "packet exceeds current send budget");
                    // Tell the local stack to shrink its segments instead of
                    // silently dropping every full-size retransmit. This is what
                    // unstalls an established TCP connection after the path MTU
                    // drops below its negotiated MSS (for example a hybrid-KEX
                    // reply that needs full-MSS segments while a smaller
                    // classical-KEX reply still fits): without the PTB the
                    // sender retries the same oversized size forever when
                    // `tcp_mtu_probing` is disabled. The PTB advertises the
                    // live effective budget for this route (inner bytes), not
                    // the stale snapshot copy, and is rate-limited above. For
                    // FakeIP routes the PTB must carry the pre-translation
                    // (fake) addresses the local socket knows.
                    if last_ptb.elapsed() >= std::time::Duration::from_millis(200) {
                        let ptb_source: &[u8] = pre_translate_ptb_source
                            .as_deref()
                            .unwrap_or(&packet[..size]);
                        if let Some(ptb) = build_ptb_for_oversize(ptb_source, effective_mtu) {
                            last_ptb = Instant::now();
                            tx_metrics.capture(&ptb);
                            if let Err(error) = tx_device.send(&ptb).await {
                                tracing::warn!(%error, "PTB TUN send failed");
                            } else {
                                tx_metrics.tun_tx(ptb.len());
                            }
                        }
                    }
                } else {
                    tx_metrics.reject(reason);
                    tracing::debug!(exit = %binding.exit, packet_bytes = size, user_ip_capacity = current_budget, "packet deferred until circuit lease is ready");
                }
                continue;
            }
            tx_metrics.circuit_tx(&binding.exit, size);
            tx_metrics.capture(&packet[..size]);
            let sender = if let Some(sender) = workers.get(&binding.exit) {
                sender.clone()
            } else {
                let (sender, receiver) = mpsc::channel(256);
                workers.insert(binding.exit.clone(), sender.clone());
                sender_supervisor.spawn_background(run_secure_sender_worker(
                    receiver,
                    worker_identity.clone(),
                    worker_sessions.clone(),
                    worker_circuit_opens.clone(),
                    tx_cancellation.clone(),
                    worker_metrics.clone(),
                    sender_supervisor.clone(),
                ));
                sender
            };
            let queued_packet = if fake_forward {
                crate::fake_ip::encode_fake_ip_envelope(&packet[..size], destination)
            } else {
                packet[..size].to_vec()
            };
            if sender
                .try_send(QueuedSecurePacket {
                    packet: queued_packet,
                    exit: binding.exit.clone(),
                    circuit_id: binding.circuit_id,
                    data_key: binding.data_key,
                    link: binding.link.clone(),
                    healthy: binding.healthy.clone(),
                    lease_epoch: binding.lease_epoch,
                    send_gate: binding.send_gate.clone(),
                    send_budget: binding.send_budget.clone(),
                })
                .is_err()
            {
                tx_metrics.reject("queue:send_drop");
                tracing::debug!(exit = %binding.exit, "bounded secure sender queue is full");
            }
        }
    });

    let rx_device = device;
    let receiver_identity = inbound.identity;
    let receiver_relay_labels = inbound.relay_labels;
    let receiver_authorizations = inbound.authorizations;
    let router_sessions = inbound.sessions.clone();
    let receiver_sessions = inbound.sessions;
    let receiver_circuit_router = inbound.circuit_router;
    let receiver_cancellation = cancellation.clone();
    let receiver_fake_ip = fake_ip;
    let receiver_supervisor = supervisor.clone();
    supervisor.spawn_background(async move {
        let mut installed = HashSet::new();
        while let Some(link) = tokio::select! {
            _ = receiver_cancellation.cancelled() => return,
            link = receiver_rx.recv() => link,
        } {
            if !installed.insert(link.instance()) {
                continue;
            }
            let device = rx_device.clone();
            let context = SecureReceiveContext {
                identity: receiver_identity.clone(),
                egress: egress.remote.clone(),
                source_policy: egress.source_policy.clone(),
                metrics: metrics.clone(),
                authorizations: receiver_authorizations.clone(),
                relay_labels: receiver_relay_labels.clone(),
                sessions: receiver_sessions.clone(),
                circuit_router: receiver_circuit_router.clone(),
                circuit_opens: inbound.circuit_opens.clone(),
                return_flows: egress.return_flows.clone(),
                circuit_dns: inbound.circuit_dns.clone(),
                supervisor: receiver_supervisor.clone(),
            };
            let fake_ip = receiver_fake_ip.clone();
            let cancellation = receiver_cancellation.clone();
            receiver_supervisor.spawn_background(async move {
                tokio::select! {
                    _ = cancellation.cancelled() => {}
                    _ = receive_secure_link(device, link, context, fake_ip) => {}
                }
            });
        }
    });
    for link in initial_links {
        let _ = receiver_tx.send(link);
    }
    TunRouter {
        routes,
        receiver_tx,
        cancellation,
        sessions: router_sessions,
    }
}

pub async fn send_circuit_broken_feedback(
    link: &Arc<Link>,
    identity: &SigningKey,
    circuit_id: CircuitId,
) {
    let message = crate::control::ControlMessage::circuit_broken(
        identity,
        circuit_id,
        crate::control::CIRCUIT_UNKNOWN_SESSION_REASON,
    );
    for attempt in 0..CIRCUIT_BROKEN_FEEDBACK_ATTEMPTS {
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            link.send_control(&message),
        )
        .await
        {
            Ok(Ok(())) => return,
            Ok(Err(CarrierError::AdmissionRejected)) | Err(_)
                if attempt + 1 < CIRCUIT_BROKEN_FEEDBACK_ATTEMPTS =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(20 * (attempt as u64 + 1)))
                    .await;
            }
            Ok(Err(error)) => {
                tracing::debug!(
                    peer_name = %link.peer,
                    peer_identity = %link.peer_identity,
                    ?circuit_id,
                    error = %error,
                    "Circuit invalidation feedback could not be delivered"
                );
                return;
            }
            Err(_) => {
                tracing::debug!(
                    peer_name = %link.peer,
                    peer_identity = %link.peer_identity,
                    ?circuit_id,
                    "Circuit invalidation feedback timed out"
                );
                return;
            }
        }
    }
}

async fn receive_secure_link<F: FakeIpMode>(
    device: TunDevice,
    link: Arc<Link>,
    context: SecureReceiveContext,
    fake_ip: F,
) {
    let Some(mut receiver) = link.take_forward_receiver().await else {
        tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, "secure Forward receiver was already claimed");
        return;
    };
    let mut reported_circuit_broken = HashMap::new();
    loop {
        let Some(frame) = (tokio::select! {
            _ = link.wait_closed() => return,
            frame = receiver.recv() => frame,
        }) else {
            tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, "physical payload dispatcher stopped");
            return;
        };
        let circuit_id = crypto::frame_circuit_id(frame.as_ref()).ok();
        let relay = circuit_id.and_then(|circuit_id| {
            context
                .relay_labels
                .read()
                .expect("relay label table lock")
                .get(&link.instance())
                .and_then(|table| table.read().expect("relay label lock").forward(circuit_id))
        });
        if let Some(binding) = relay {
            if let Err(error) = binding.outgoing.send_forward(frame.as_ref())
                && link.should_log_dataplane_warning()
            {
                tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "relay DATAGRAM forwarding failed (further failures are rate-limited)");
            }
            continue;
        }
        let opened = context
            .sessions
            .open_data(link.instance(), frame.as_ref())
            .await;
        let (circuit_id, direction, source, mut packet) = match opened {
            Ok(opened) => opened,
            Err(error @ crypto::CryptoError::UnknownSession) => {
                // Frames from the previous link instance can still be in
                // flight when a QUIC connection reconnects. They are safely
                // discarded until OPEN installs the new receiver state; avoid turning this expected transition into
                // a warning-log I/O hotspot while retaining a metric.
                context.metrics.reject("crypto:no_session");
                if let Some(circuit_id) = circuit_id
                    && should_report_circuit_broken_feedback(
                        &mut reported_circuit_broken,
                        circuit_id,
                        Instant::now(),
                    )
                {
                    // Never block the dataplane receive loop on feedback:
                    // each miss would otherwise spend up to 3x500ms on
                    // control admission while attacker-sprayed circuit IDs
                    // stall legitimate traffic. Background spawns are bounded
                    // by the 4096-entry deduplication table: a full table of
                    // fresh entries suppresses further feedback for one TTL.
                    let feedback_link = link.clone();
                    let feedback_identity = context.identity.clone();
                    context.supervisor.spawn_background(async move {
                        send_circuit_broken_feedback(
                            &feedback_link,
                            &feedback_identity,
                            circuit_id,
                        )
                        .await;
                    });
                }
                tracing::debug!(
                    peer_name = %link.peer,
                    peer_identity = %link.peer_identity,
                    error = %error,
                    "encrypted DATAGRAM dropped before session setup"
                );
                continue;
            }
            Err(error) => {
                if link.should_log_dataplane_warning() {
                    tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "encrypted DATAGRAM rejected (further rejections are rate-limited)");
                }
                continue;
            }
        };
        let fake_destination = match crate::fake_ip::decode_fake_ip_envelope(&mut packet) {
            Ok(fake_destination) => fake_destination,
            Err(reason) => {
                context.metrics.reject("fake_ip:malformed_envelope");
                tracing::debug!(%reason, ?circuit_id, "encrypted DATAGRAM contained a malformed FakeIP envelope");
                continue;
            }
        };
        let source_id = encode_public(&source);
        let fake_forward =
            direction == crypto::DataDirection::Forward && fake_destination.is_some();
        if fake_destination.is_some()
            && matches!(
                direction,
                crypto::DataDirection::DnsForward | crypto::DataDirection::DnsReturn
            )
        {
            context.metrics.reject("fake_ip:envelope_on_dns");
            continue;
        }
        if matches!(
            direction,
            crypto::DataDirection::Return | crypto::DataDirection::DnsReturn
        ) {
            // Return traffic is bound to an established, E2E-authenticated
            // circuit (`is_authorized`) and decrypted with the circuit's
            // directional key. `EgressPolicy` intentionally does not apply
            // here: it authorizes forwarding *to* the internet/local ports at
            // the exit, while return packets travel *back* into the source
            // TUN. Source-address bindings (`bind_addresses`,
            // `routes[].bind`) still apply below via `source_policy`.
            if !context
                .circuit_opens
                .is_authorized(link.instance(), circuit_id)
                .await
            {
                context.metrics.reject("return_path:unauthorized_circuit");
                continue;
            }
            if direction == crypto::DataDirection::DnsReturn {
                if let Err(reason) = context.circuit_dns.complete(&packet) {
                    context.metrics.reject("dns:return_rejected");
                    tracing::debug!(%reason, ?circuit_id, "Circuit DNS response rejected");
                }
                continue;
            }
            if !fake_ip.restore_circuit_return(&mut packet, fake_destination) {
                context.metrics.reject("fake_ip:return_translation_failed");
                continue;
            }
            if !context.source_policy.authorize(&source_id, &packet) {
                continue;
            }
            context.metrics.capture(&packet);
            if let Err(error) = device.send(&packet).await {
                tracing::error!(error = %error, "return-path TUN send stopped");
                return;
            }
            context.metrics.tun_tx(packet.len());
            continue;
        }
        if !context
            .authorizations
            .permits(link.instance(), circuit_id, &source_id)
            .await
        {
            context.metrics.reject("egress:unopened_circuit");
            if link.should_log_dataplane_warning() {
                tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, circuit_id = ?circuit_id, "encrypted DATAGRAM rejected for unopened circuit (further rejections are rate-limited)");
            }
            continue;
        }
        if direction == crypto::DataDirection::Forward
            && !context.source_policy.authorize(&source_id, &packet)
        {
            continue;
        }
        context
            .circuit_router
            .refresh_binding(link.instance(), circuit_id);
        let source_name = context
            .egress
            .as_ref()
            .and_then(|policy| policy.names.get(&source_id))
            .cloned()
            .unwrap_or_else(|| link.peer.clone());
        context.metrics.circuit_rx(&source_name, packet.len());
        if direction == crypto::DataDirection::DnsForward {
            let (token, upstream, wire) = match decode_dns_query(&packet) {
                Ok(query) => query,
                Err(reason) => {
                    context.metrics.reject("dns:malformed_query");
                    tracing::debug!(%reason, ?circuit_id, "Circuit DNS query rejected");
                    continue;
                }
            };
            let Some(policy) = &context.egress else {
                context.metrics.reject("egress:dns_no_allowed_routes");
                continue;
            };
            if !policy.authorize_dns_upstream(&source_id, upstream.ip()) {
                continue;
            }
            let wire = wire.to_vec();
            let response_link = link.clone();
            let return_flows = context.return_flows.clone();
            let metrics = context.metrics.clone();
            context.supervisor.spawn_background(async move {
                let result = crate::fake_ip::query_upstream(&upstream, &wire)
                    .await
                    .and_then(|message| message.to_vec().map_err(Into::into));
                let (status, response) = match result {
                    Ok(response) => (0, response),
                    Err(error) => (1, error.to_string().into_bytes()),
                };
                let total = response.len().div_ceil(DNS_RESPONSE_CHUNK).max(1);
                let Ok(total) = u16::try_from(total) else {
                    metrics.reject("dns:response_too_large");
                    return;
                };
                for index in 0..total {
                    let start = usize::from(index) * DNS_RESPONSE_CHUNK;
                    let end = (start + DNS_RESPONSE_CHUNK).min(response.len());
                    let chunk = if start < response.len() {
                        &response[start..end]
                    } else {
                        &[]
                    };
                    let payload = encode_dns_response(token, status, index, total, chunk);
                    let Some(frame) = return_flows.encrypt_dns_return(
                        response_link.instance(),
                        circuit_id,
                        &payload,
                    ) else {
                        metrics.reject("dns:return_no_session");
                        return;
                    };
                    if response_link.send_forward(&frame).is_err() {
                        metrics.reject("dns:return_send_failed");
                        return;
                    }
                }
            });
            continue;
        }
        context.metrics.capture(&packet);
        if let Some(policy) = &context.egress
            && !policy.authorize(&source_id, &packet).await
        {
            continue;
        }
        if fake_forward
            && let Err(reason) = context.return_flows.track_forward(
                &mut packet,
                fake_destination,
                link.clone(),
                circuit_id,
            )
        {
            context.metrics.reject("return_path:track_failed");
            tracing::debug!(%reason, ?circuit_id, "FakeIP packet rejected before ambiguous return-path state");
            continue;
        }
        if let Err(error) = device.send(&packet).await {
            tracing::error!(error = %error, "TUN send stopped");
            return;
        }
        context.metrics.tun_tx(packet.len());
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod mss_tests {
    use super::*;

    fn ipv4_tcp_checksum_is_valid(packet: &[u8]) -> bool {
        let ip_len = usize::from(packet[0] & 0x0f) * 4;
        let tcp = &packet[ip_len..];
        let mut sum = 0_u32;
        for offset in (12..20).step_by(2) {
            sum += u32::from(u16::from_be_bytes([packet[offset], packet[offset + 1]]));
        }
        sum += 6 + tcp.len() as u32;
        for chunk in tcp.chunks(2) {
            sum += match chunk {
                [high, low] => u32::from(u16::from_be_bytes([*high, *low])),
                [high] => u32::from(*high) << 8,
                _ => 0,
            };
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == u16::MAX
    }

    #[test]
    fn clamps_mss_on_a_syn_with_payload_and_keeps_tcp_checksum_valid() {
        let mut packet = vec![0_u8; 49];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&12345_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 0x60; // 24-byte TCP header
        packet[33] = 0x02; // SYN
        packet[40..44].copy_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460
        packet[44..].copy_from_slice(b"hello"); // TCP Fast Open-style SYN data

        let meta = inspect_packet(&packet).expect("valid IPv4 TCP packet");
        let checksum = tcp_checksum(&packet, &meta);
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
        assert!(ipv4_tcp_checksum_is_valid(&packet));

        assert!(clamp_tcp_mss(&mut packet, 1200));
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), 1156);
        assert!(ipv4_tcp_checksum_is_valid(&packet));
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod acl_tests {
    use super::*;
    use crate::config::{AllowedLocalPort, AllowedRoute, RouteSourceSelector};

    fn ipv4_tcp(destination: [u8; 4], destination_port: u16) -> Vec<u8> {
        ipv4_tcp_from([192, 0, 2, 1], destination, destination_port)
    }

    fn ipv4_tcp_from(source: [u8; 4], destination: [u8; 4], destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    fn ipv6_packet_from(source: &str, destination: &str) -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[6] = 59; // No Next Header.
        packet[8..24].copy_from_slice(&source.parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&destination.parse::<Ipv6Addr>().unwrap().octets());
        packet
    }

    #[test]
    fn source_binding_only_restricts_bound_addresses() {
        let policy = SourceAddressPolicy::from_bindings(
            vec![("10.0.0.1/32".parse().unwrap(), "owner".into())],
            Arc::new(Observability::new(0)),
        );
        assert!(policy.authorize("other", &ipv4_tcp_from([1, 1, 1, 1], [203, 0, 113, 1], 443)));
        assert!(policy.authorize(
            "owner",
            &ipv4_tcp_from([10, 0, 0, 1], [203, 0, 113, 1], 443)
        ));
        assert!(!policy.authorize(
            "other",
            &ipv4_tcp_from([10, 0, 0, 1], [203, 0, 113, 1], 443)
        ));
    }

    #[test]
    fn source_binding_allows_multiple_owners_and_overlapping_cidrs() {
        let policy = SourceAddressPolicy::from_bindings(
            vec![
                ("10.0.0.0/8".parse().unwrap(), "b".into()),
                ("10.0.0.0/8".parse().unwrap(), "c".into()),
                ("10.0.0.0/24".parse().unwrap(), "d".into()),
            ],
            Arc::new(Observability::new(0)),
        );
        let packet = ipv4_tcp_from([10, 0, 0, 1], [203, 0, 113, 1], 443);
        assert!(policy.authorize("b", &packet));
        assert!(policy.authorize("c", &packet));
        assert!(policy.authorize("d", &packet));
        assert!(!policy.authorize("e", &packet));
    }

    #[test]
    fn source_binding_covers_ipv6_unknown_protocol_and_fragments() {
        let policy = SourceAddressPolicy::from_bindings(
            vec![
                ("10.0.0.0/8".parse().unwrap(), "owner".into()),
                ("2001:db8::/32".parse().unwrap(), "owner".into()),
            ],
            Arc::new(Observability::new(0)),
        );
        let mut unknown = ipv4_tcp_from([10, 0, 0, 1], [203, 0, 113, 1], 443);
        unknown[9] = 99;
        assert!(!policy.authorize("other", &unknown));
        unknown[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        assert!(!policy.authorize("other", &unknown));
        let ipv6 = ipv6_packet_from("2001:db8::1", "2001:db8:1::1");
        assert!(policy.authorize("owner", &ipv6));
        assert!(!policy.authorize("other", &ipv6));
    }

    #[test]
    fn source_binding_rejects_malformed_ip_packets() {
        let policy = SourceAddressPolicy::default();
        assert!(!policy.authorize("anyone", &[0x45, 0, 0]));
        assert!(!policy.authorize("anyone", &[0x60; 23]));
        assert!(!policy.authorize("anyone", &[0x50; 40]));
    }

    #[test]
    fn source_binding_accepts_configured_public_key_and_link_identity() {
        let owner_key = crate::identity::generate();
        let public_key = crate::identity::encode_public(&owner_key.verifying_key());
        let config: crate::config::Config = serde_yaml::from_str(&format!(
            "id: receiver\nidentity_key_path: /tmp/receiver.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  owner:\n    public_key: {public_key}\n    endpoints: []\n    bind_addresses: [10.0.0.0/8]\n"
        ))
        .unwrap();
        let policy = SourceAddressPolicy::from_config(&config, Arc::new(Observability::new(0)));
        let packet = ipv4_tcp_from([10, 0, 0, 1], [203, 0, 113, 1], 443);
        assert!(policy.authorize(&public_key, &packet));
        assert!(policy.authorize(
            &crate::identity::node_id(&owner_key.verifying_key()),
            &packet
        ));
    }

    fn local_port_policy() -> EgressPolicy {
        EgressPolicy {
            names: Arc::new(HashMap::from([("source-key".into(), "source".into())])),
            allowed_routes: Arc::new(Vec::new()),
            allowed_local_ports: Arc::new(vec![AllowedLocalPort {
                allow: vec!["tcp(443)".parse().unwrap()],
                deny: Vec::new(),
                r#for: RouteSourceSelector::Nodes(vec!["source".into()]),
            }]),
            local_addresses: Arc::new(vec![
                "100.64.10.1/32".parse().unwrap(),
                "2001:db8::2/128".parse().unwrap(),
            ]),
            metrics: Arc::new(Observability::new(0)),
        }
    }

    #[tokio::test]
    async fn local_port_acl_works_without_route_acl_and_does_not_export() {
        let policy = local_port_policy();
        assert!(
            policy
                .authorize("source-key", &ipv4_tcp([100, 64, 10, 1], 443))
                .await
        );
        assert!(
            !policy
                .authorize("source-key", &ipv4_tcp([100, 64, 10, 1], 22))
                .await
        );
        assert!(
            !policy
                .authorize("source-key", &ipv4_tcp([203, 0, 113, 1], 443))
                .await
        );
    }

    #[tokio::test]
    async fn fragmented_ipv4_cannot_be_authorized_by_forged_ports() {
        let policy = local_port_policy();
        let mut fragment = ipv4_tcp([100, 64, 10, 1], 443);
        // More-fragments flag: these bytes might be the first fragment's TCP
        // header, but must not receive a standalone port authorization.
        fragment[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        assert!(inspect_packet(&fragment).is_none());
        assert!(!policy.authorize("source-key", &fragment).await);

        // Offset one models a non-first fragment whose payload starts with a
        // forged allowed destination port.
        fragment[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(inspect_packet(&fragment).is_none());
        assert!(!policy.authorize("source-key", &fragment).await);
    }

    #[tokio::test]
    async fn fragmented_ipv6_cannot_be_authorized_by_forged_ports() {
        let policy = local_port_policy();
        let mut fragment = vec![0_u8; 56];
        fragment[0] = 0x60;
        fragment[6] = 44; // Fragment Header
        fragment[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        fragment[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        fragment[40] = 6; // TCP after Fragment Header
        fragment[48..50].copy_from_slice(&40_000_u16.to_be_bytes());
        fragment[50..52].copy_from_slice(&443_u16.to_be_bytes());
        assert!(inspect_packet(&fragment).is_none());
        assert!(!policy.authorize("source-key", &fragment).await);
    }

    #[tokio::test]
    async fn local_port_acl_rejects_unknown_source_by_default() {
        let policy = local_port_policy();
        assert!(
            !policy
                .authorize("unknown", &ipv4_tcp([100, 64, 10, 1], 443))
                .await
        );
    }

    #[test]
    fn route_acl_stays_independent_from_local_port_acl() {
        let policy = local_port_policy();
        assert!(policy.allowed_routes.is_empty());
        let route = AllowedRoute {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Nodes(vec!["source".into()]),
        };
        assert!(route.permits("source", "203.0.113.1".parse().unwrap(), true));
    }

    #[test]
    fn remote_dns_uses_route_acl_but_not_local_port_acl() {
        let mut policy = local_port_policy();
        assert!(!policy.authorize_dns_upstream("source-key", "203.0.113.53".parse().unwrap()));
        policy.allowed_routes = Arc::new(vec![AllowedRoute {
            allow: vec!["203.0.113.53/32".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Nodes(vec!["source".into()]),
        }]);
        assert!(policy.authorize_dns_upstream("source-key", "203.0.113.53".parse().unwrap()));
        assert!(!policy.authorize_dns_upstream("source-key", "203.0.113.54".parse().unwrap()));
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod circuit_dns_tests {
    use super::*;

    #[tokio::test]
    async fn dns_response_chunks_reassemble_out_of_order() {
        let client = CircuitDnsClient::default();
        let (sender, receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            7,
            PendingDnsQuery {
                link_instance: 1,
                circuit_id: CircuitId([2; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );
        client
            .complete(&encode_dns_response(7, 0, 1, 2, b"world"))
            .unwrap();
        client
            .complete(&encode_dns_response(7, 0, 0, 2, b"hello "))
            .unwrap();
        assert_eq!(receiver.await.unwrap().unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn cancelled_dns_query_registration_removes_its_pending_token() {
        let client = CircuitDnsClient::default();
        let (sender, _receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            6,
            PendingDnsQuery {
                link_instance: 1,
                circuit_id: CircuitId([1; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );
        let state = client.state.clone();
        let task = tokio::spawn(async move {
            let _registration = PendingDnsRegistration::new(state, 6);
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(client.state.lock().unwrap().pending.is_empty());
    }

    #[test]
    fn dns_query_codec_preserves_upstream_and_wire() {
        let server =
            crate::config::DnsServer::from_socket_addr("[2001:db8::53]:5353".parse().unwrap());
        let payload = encode_dns_query(9, &server, b"query").unwrap();
        let (token, decoded, wire) = decode_dns_query(&payload).unwrap();
        assert_eq!(token, 9);
        assert_eq!(decoded.socket_addr(), server.socket_addr());
        assert_eq!(wire, b"query");
    }

    #[test]
    fn dns_codecs_reject_bad_magic_family_port_and_chunk_headers() {
        let server = crate::config::DnsServer::from_socket_addr("203.0.113.53:53".parse().unwrap());
        let mut query = encode_dns_query(9, &server, b"query").unwrap();
        assert!(decode_dns_query(&query[..30]).is_err());
        query[12] = 9;
        assert!(decode_dns_query(&query).is_err());
        let mut query = encode_dns_query(9, &server, b"query").unwrap();
        query[29] = 0;
        query[30] = 0;
        assert!(decode_dns_query(&query).is_err());
        assert!(decode_dns_query(b"bad").is_err());

        let response = encode_dns_response(9, 0, 0, 1, b"ok");
        assert_eq!(decode_dns_response(&response).unwrap().4, b"ok");
        assert!(decode_dns_response(&response[..16]).is_err());
        assert!(decode_dns_response(b"bad").is_err());
    }

    #[tokio::test]
    async fn dns_response_errors_fail_pending_queries_and_remove_the_token() {
        let client = CircuitDnsClient::default();
        let (sender, receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            11,
            PendingDnsQuery {
                link_instance: 4,
                circuit_id: CircuitId([4; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );

        client
            .complete(&encode_dns_response(11, 1, 0, 1, b"upstream failed"))
            .unwrap();
        assert_eq!(receiver.await.unwrap(), Err("upstream failed".into()));
        assert!(!client.state.lock().unwrap().pending.contains_key(&11));
        assert!(
            client
                .complete(&encode_dns_response(11, 0, 0, 1, b"late"))
                .is_err()
        );
    }

    #[test]
    fn dns_response_range_and_count_errors_keep_state_for_recovery() {
        let client = CircuitDnsClient::default();
        let (sender, mut receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            12,
            PendingDnsQuery {
                link_instance: 5,
                circuit_id: CircuitId([5; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );

        assert!(
            client
                .complete(&encode_dns_response(12, 0, 0, 0, b"bad"))
                .is_err()
        );
        assert!(
            client
                .complete(&encode_dns_response(12, 2, 0, 1, b"bad status"))
                .is_ok()
        );
        assert!(receiver.try_recv().is_ok());

        let (sender, mut receiver) = oneshot::channel();
        client.state.lock().unwrap().pending.insert(
            13,
            PendingDnsQuery {
                link_instance: 6,
                circuit_id: CircuitId([6; 16]),
                sender: Some(sender),
                chunks: Vec::new(),
            },
        );
        client
            .complete(&encode_dns_response(13, 0, 0, 2, b"first"))
            .unwrap();
        assert!(
            client
                .complete(&encode_dns_response(13, 0, 0, 3, b"wrong count"))
                .is_err()
        );
        client.remove_link(6);
        assert_eq!(
            receiver.try_recv().unwrap(),
            Err("Circuit closed before DNS response".into())
        );
    }

    #[test]
    fn dns_pending_queries_are_failed_by_link_or_circuit_cleanup() {
        let client = CircuitDnsClient::default();
        let (link_sender, mut link_receiver) = oneshot::channel();
        let (circuit_sender, mut circuit_receiver) = oneshot::channel();
        let link_id = CircuitId([7; 16]);
        let circuit_id = CircuitId([8; 16]);
        {
            let mut state = client.state.lock().unwrap();
            state.pending.insert(
                14,
                PendingDnsQuery {
                    link_instance: 7,
                    circuit_id: link_id,
                    sender: Some(link_sender),
                    chunks: Vec::new(),
                },
            );
            state.pending.insert(
                15,
                PendingDnsQuery {
                    link_instance: 8,
                    circuit_id,
                    sender: Some(circuit_sender),
                    chunks: Vec::new(),
                },
            );
        }
        client.remove_link(7);
        assert_eq!(
            link_receiver.try_recv().unwrap(),
            Err("Circuit closed before DNS response".into())
        );
        client.remove_circuit(8, circuit_id);
        assert_eq!(
            circuit_receiver.try_recv().unwrap(),
            Err("Circuit closed before DNS response".into())
        );
        assert!(client.state.lock().unwrap().pending.is_empty());
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod route_selection_tests {
    use super::*;

    #[test]
    fn direct_priority_only_beats_secure_on_a_strictly_higher_value() {
        assert!(direct_beats_secure(101, 100));
        assert!(!direct_beats_secure(100, 100));
        assert!(!direct_beats_secure(99, 100));
    }

    #[test]
    fn explicit_direct_prefix_uses_the_longest_matching_prefix() {
        let snapshot = RouteSnapshot::new(Vec::new(), Vec::new()).with_direct_routes(
            vec![
                ("192.0.2.0/24".parse().unwrap(), 80),
                ("192.0.2.128/25".parse().unwrap(), 70),
            ],
            Vec::new(),
        );

        assert!(matches!(
            snapshot.select_route("192.0.2.200".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
        assert!(matches!(
            snapshot.select_route("192.0.2.1".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
        assert!(
            snapshot
                .select_route("198.51.100.1".parse().unwrap(), None)
                .is_none()
        );
    }

    #[test]
    fn replacing_direct_routes_removes_stale_prefix_index_entries() {
        let snapshot = RouteSnapshot::new(Vec::new(), Vec::new())
            .with_direct_routes(vec![("192.0.2.0/24".parse().unwrap(), 80)], Vec::new())
            .with_direct_routes(vec![("198.51.100.0/24".parse().unwrap(), 90)], Vec::new());

        assert!(
            snapshot
                .select_route("192.0.2.1".parse().unwrap(), None)
                .is_none()
        );
        assert!(matches!(
            snapshot.select_route("198.51.100.1".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
    }

    #[test]
    fn indexed_lookup_ignores_large_unrelated_prefix_sets() {
        let mut routes = (0..4096_u32)
            .map(|index| {
                let address = std::net::Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    (index >> 16) as u16,
                    index as u16,
                    0,
                    0,
                    0,
                    0,
                );
                (IpNet::new(address.into(), 64).unwrap(), 1)
            })
            .collect::<Vec<_>>();
        routes.push(("203.0.113.0/24".parse().unwrap(), 100));
        let snapshot =
            RouteSnapshot::new(Vec::new(), Vec::new()).with_direct_routes(routes, Vec::new());

        assert!(matches!(
            snapshot.select_route("203.0.113.9".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
        assert!(
            snapshot
                .select_route("198.51.100.1".parse().unwrap(), None)
                .is_none()
        );
    }

    #[test]
    fn domain_direct_selection_and_candidate_resolution_follow_site_sets() {
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.com\n").unwrap();
        let snapshot = RouteSnapshot::new_with_domains(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![crate::config::DomainRouteImport {
                set_id,
                candidates: vec![crate::config::RouteCandidate {
                    node: "exit".into(),
                    priority: 100,
                }],
            }],
            Arc::new(loader.finish()),
        )
        .with_direct_routes(
            vec![("192.0.2.0/24".parse().unwrap(), 80)],
            vec![(set_id, 90)],
        );

        assert!(matches!(
            snapshot.select_route("192.0.2.1".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
        let direct_hint = crate::fake_ip::FakeRouteHint {
            domain: "www.example.com".into(),
            preferred_route: Some(crate::fake_ip::RoutePreference::Direct),
        };
        assert!(matches!(
            snapshot.select_route("198.51.100.1".parse().unwrap(), Some(&direct_hint)),
            Some(RouteSelection::Direct)
        ));
        let automatic_hint = crate::fake_ip::FakeRouteHint {
            domain: "www.example.com".into(),
            preferred_route: None,
        };
        assert!(matches!(
            snapshot.select_route("198.51.100.1".parse().unwrap(), Some(&automatic_hint)),
            Some(RouteSelection::Direct)
        ));
        assert_eq!(
            snapshot.ensure_candidates("198.51.100.1".parse().unwrap(), Some(&automatic_hint),),
            vec!["exit"]
        );
        assert!(snapshot.domain_candidates("outside.example.net").is_empty());
        assert_eq!(snapshot.direct_domain_priority("outside.example.net"), None);
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AllowedRoute;

    #[tokio::test]
    async fn circuit_ids_share_a_random_prefix_and_monotonic_counter() {
        let opens = CircuitOpenManager::default();
        let first = opens.next_circuit_id().await;
        let second = opens.next_circuit_id().await;
        let third = opens.clone().next_circuit_id().await;

        assert_eq!(&first.0[..8], &second.0[..8]);
        assert_eq!(&second.0[..8], &third.0[..8]);
        let first_counter = u64::from_be_bytes(first.0[8..].try_into().unwrap());
        let second_counter = u64::from_be_bytes(second.0[8..].try_into().unwrap());
        let third_counter = u64::from_be_bytes(third.0[8..].try_into().unwrap());
        assert_eq!(second_counter, first_counter + 1);
        assert_eq!(third_counter, second_counter + 1);
        assert_ne!(first, second);
        assert_ne!(second, third);
    }

    #[test]
    fn direct_priority_must_strictly_exceed_secure_priority() {
        assert!(direct_beats_secure(101, 100));
        assert!(!direct_beats_secure(100, 100));
        assert!(!direct_beats_secure(99, 100));
    }

    #[test]
    fn explicit_direct_prefix_is_a_route_candidate_without_fallback() {
        let snapshot = RouteSnapshot::new(Vec::new(), Vec::new())
            .with_direct_routes(vec![("192.0.2.0/24".parse().unwrap(), 80)], Vec::new());
        assert!(matches!(
            snapshot.select_route("192.0.2.1".parse().unwrap(), None),
            Some(RouteSelection::Direct)
        ));
        assert!(
            snapshot
                .select_route("198.51.100.1".parse().unwrap(), None)
                .is_none()
        );
        assert_eq!(
            snapshot.healthy_prefixes().collect::<Vec<_>>(),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn explicit_direct_domain_is_a_dns_candidate_without_fallback() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("domains.txt"), "example.test\n").unwrap();
        let mut loader = crate::route_sets::RouteSetLoader::new(dir.path());
        let set_id = loader.load("domains.txt").unwrap();
        let snapshot = RouteSnapshot::new_with_domains(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Arc::new(loader.finish()),
        )
        .with_direct_routes(Vec::new(), vec![(set_id, 120)]);

        let candidates = snapshot.domain_candidates("www.example.test");
        assert_eq!(candidates.len(), 1);
        assert!(matches!(
            candidates[0],
            DomainResolutionCandidate::Direct { priority: 120 }
        ));
        assert!(snapshot.has_healthy_domain_binding());
    }

    #[tokio::test]
    async fn preserves_inner_packet() {
        let circuit_id = CircuitId([42; 16]);
        let key = chacha20poly1305::Key::from([3; 32]);
        let mut sender = crypto::SenderSession::from_key(circuit_id, key);
        let frame = sender.encrypt(b"inner-packet").unwrap().to_vec();
        let sessions = SessionManager::default();
        let source = crate::identity::generate();
        sessions
            .install_open(1, circuit_id, source.verifying_key(), key)
            .await;
        let (opened_id, direction, opened_source, packet) =
            sessions.open_data(1, &frame).await.unwrap();
        assert_eq!(opened_id, circuit_id);
        assert_eq!(direction, crypto::DataDirection::Forward);
        assert_eq!(opened_source, source.verifying_key());
        assert_eq!(packet, b"inner-packet");
    }
    #[test]
    fn parses_ipv4_transport_destination() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&50000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&1234u16.to_be_bytes());
        assert_eq!(
            inspect_ipv4_flow(&packet),
            Some(("1.1.1.1".parse().unwrap(), Protocol::Udp, 1234))
        );
    }
    #[test]
    fn parses_ipv6_extension_header_and_destination_port() {
        // IPv6 + Hop-by-Hop header + UDP header.
        let mut packet = vec![0_u8; 56];
        packet[0] = 0x60;
        packet[6] = 0; // Hop-by-Hop
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = 17; // next header UDP
        packet[41] = 0; // 8 bytes total
        packet[48..50].copy_from_slice(&50000u16.to_be_bytes());
        packet[50..52].copy_from_slice(&443u16.to_be_bytes());
        let meta = inspect_packet(&packet).unwrap();
        assert_eq!(meta.destination, "2001:db8::2".parse::<IpAddr>().unwrap());
        assert_eq!(meta.protocol, Protocol::Udp);
        assert_eq!(meta.destination_port, 443);
        assert_eq!(inspect_ipv4_flow(&packet).unwrap().1, Protocol::Udp);
    }
    #[test]
    fn clamps_ipv6_syn_mss() {
        let mut packet = vec![0_u8; 64];
        packet[0] = 0x60;
        packet[6] = 6;
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[52] = 0x60; // TCP 24 bytes
        packet[53] = 0x02; // SYN
        packet[60] = 2;
        packet[61] = 4;
        packet[62..64].copy_from_slice(&1460_u16.to_be_bytes());
        assert!(clamp_tcp_mss(&mut packet, 1280));
        assert_eq!(u16::from_be_bytes([packet[62], packet[63]]), 1216);
        assert_ne!(&packet[56..58], &[0, 0]);
    }
    #[test]
    fn clamps_syn_mss_and_updates_checksum() {
        let mut packet = vec![0_u8; 44];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20 + 12] = 0x60; // 24-byte TCP header
        packet[20 + 13] = 0x02; // SYN
        packet[40] = 2;
        packet[41] = 4;
        packet[42..44].copy_from_slice(&1460_u16.to_be_bytes());
        assert!(clamp_tcp_mss(&mut packet, 1200));
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), 1156);
        assert_ne!(&packet[36..38], &[0, 0]);
    }

    #[test]
    fn disabled_mss_clamp_leaves_syn_unchanged() {
        let mut packet = vec![0_u8; 44];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 2]);
        packet[20 + 12] = 0x60;
        packet[20 + 13] = 0x02;
        packet[40..44].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        let original = packet.clone();
        assert!(!clamp_mss_if_enabled(&mut packet, 1200, false));
        assert_eq!(packet, original);
    }
    #[tokio::test]
    async fn relay_preserves_end_to_end_ciphertext() {
        let source = crate::identity::generate();
        let circuit_id = CircuitId([8; 16]);
        let key = chacha20poly1305::Key::from([9; 32]);
        let mut sender = crate::crypto::SenderSession::from_key(circuit_id, key);
        let mut relayed = sender.encrypt(b"ip-packet").unwrap().to_vec();
        let sessions = SessionManager::default();
        sessions
            .install_open(2, circuit_id, source.verifying_key(), key)
            .await;
        let (_, _, opened_source, plaintext) = sessions.open_data(2, &relayed).await.unwrap();
        assert_eq!(opened_source, source.verifying_key());
        assert_eq!(plaintext, b"ip-packet");
        let last = relayed.len() - 1;
        relayed[last] ^= 1;
        // The sequence is already consumed, so the cheap pre-decrypt replay
        // check fires before the AEAD can report the tamper. Either way the
        // frame is dropped; tamper on a fresh sequence still authenticates.
        assert_eq!(
            sessions.open_data(2, &relayed).await,
            Err(crypto::CryptoError::Replay)
        );
        let mut fresh = sender.encrypt(b"ip-packet-2").unwrap().to_vec();
        let fresh_last = fresh.len() - 1;
        fresh[fresh_last] ^= 1;
        assert_eq!(
            sessions.open_data(2, &fresh).await,
            Err(crypto::CryptoError::Authentication)
        );
    }

    #[test]
    fn allowed_route_requires_source_and_honours_deny() {
        let route = AllowedRoute {
            allow: vec!["10.10.0.0/16".parse().unwrap()],
            deny: vec!["10.10.1.0/24".parse().unwrap()],
            r#for: crate::config::RouteSourceSelector::Nodes(vec!["a".into()]),
        };
        assert!(route.permits("a", "10.10.2.1".parse().unwrap(), true));
        assert!(!route.permits("a", "10.10.1.1".parse().unwrap(), true));
        assert!(!route.permits("b", "10.10.2.1".parse().unwrap(), true));
    }

    #[tokio::test]
    async fn unknown_source_can_reach_a_known_exit_when_explicitly_included() {
        let route = AllowedRoute {
            allow: vec!["10.10.0.0/16".parse().unwrap()],
            deny: vec![],
            r#for: crate::config::RouteSourceSelector::Keyword("any_inc_unknown".into()),
        };
        let ports = crate::config::AllowedLocalPort {
            allow: vec!["icmp".parse().unwrap()],
            deny: vec![],
            r#for: crate::config::RouteSourceSelector::Keyword("any_inc_unknown".into()),
        };
        let policy = EgressPolicy {
            names: Arc::new(HashMap::from([("known-b".into(), "b".into())])),
            allowed_routes: Arc::new(vec![route]),
            allowed_local_ports: Arc::new(vec![ports]),
            local_addresses: Arc::new(vec![]),
            metrics: Arc::new(Observability::new(0)),
        };
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[16..20].copy_from_slice(&[10, 10, 0, 2]);
        assert!(policy.authorize("unknown-x", &packet).await);
    }

    #[tokio::test]
    async fn default_port_policy_does_not_expose_unknown_sources() {
        let route = AllowedRoute {
            allow: vec!["10.10.0.0/16".parse().unwrap()],
            deny: vec![],
            r#for: crate::config::RouteSourceSelector::Keyword("any_inc_unknown".into()),
        };
        let policy = EgressPolicy {
            names: Arc::new(HashMap::new()),
            allowed_routes: Arc::new(vec![route]),
            allowed_local_ports: Arc::new(vec![]),
            local_addresses: Arc::new(vec![]),
            metrics: Arc::new(Observability::new(0)),
        };
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[16..20].copy_from_slice(&[10, 10, 0, 2]);
        assert!(!policy.authorize("unknown-x", &packet).await);
    }

    #[tokio::test]
    async fn local_tun_address_uses_port_policy_without_route_export() {
        let policy = EgressPolicy {
            names: Arc::new(HashMap::from([("a-key".into(), "A".into())])),
            allowed_routes: Arc::new(vec![]),
            allowed_local_ports: Arc::new(vec![crate::config::AllowedLocalPort {
                allow: vec!["icmp".parse().unwrap()],
                deny: vec![],
                r#for: crate::config::RouteSourceSelector::Nodes(vec!["A".into()]),
            }]),
            local_addresses: Arc::new(vec!["100.64.10.3/24".parse().unwrap()]),
            metrics: Arc::new(Observability::new(0)),
        };
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[16..20].copy_from_slice(&[100, 64, 10, 3]);
        assert!(policy.authorize("a-key", &packet).await);
    }

    #[tokio::test]
    async fn reliable_session_setup_installs_before_datagrams_and_acknowledges() {
        let source = crate::identity::generate();
        let circuit_id = CircuitId([77; 16]);
        let key = chacha20poly1305::Key::from([11; 32]);
        let mut sender = crypto::SenderSession::from_key(circuit_id, key);
        let data = sender.encrypt(b"packet").unwrap().to_vec();
        let sessions = SessionManager::default();
        sessions
            .install_open(9, circuit_id, source.verifying_key(), key)
            .await;
        let (opened_id, direction, opened_source, packet) =
            sessions.open_data(9, &data).await.unwrap();
        assert_eq!(opened_id, circuit_id);
        assert_eq!(direction, crypto::DataDirection::Forward);
        assert_eq!(opened_source, source.verifying_key());
        assert_eq!(packet, b"packet");
    }

    #[tokio::test]
    async fn clear_ack_drops_stale_waiter_so_late_ack_is_ignored() {
        let sessions = SessionManager::default();
        let source = crate::identity::generate();
        let first = CircuitId([3; 16]);
        let second = CircuitId([4; 16]);
        let key = chacha20poly1305::Key::from([12; 32]);
        sessions
            .install_open(3, first, source.verifying_key(), key)
            .await;
        sessions
            .install_open(3, second, source.verifying_key(), key)
            .await;
        sessions.remove_circuit(3, first).await;
        let mut sender = crypto::SenderSession::from_key(first, key);
        let stale = sender.encrypt(b"stale").unwrap().to_vec();
        assert_eq!(
            sessions.open_data(3, &stale).await,
            Err(crypto::CryptoError::UnknownSession)
        );
        let mut current_sender = crypto::SenderSession::from_key(second, key);
        let current = current_sender.encrypt(b"current").unwrap().to_vec();
        assert_eq!(sessions.open_data(3, &current).await.unwrap().3, b"current");
    }

    #[tokio::test]
    async fn stale_ack_epoch_does_not_complete_newer_setup() {
        let sessions = SessionManager::default();
        let source = crate::identity::generate();
        let circuit_id = CircuitId([9; 16]);
        let key = chacha20poly1305::Key::from([13; 32]);
        sessions
            .install_open(5, circuit_id, source.verifying_key(), key)
            .await;
        let mut sender = crypto::SenderSession::from_key(circuit_id, key);
        let first = sender.encrypt(b"first").unwrap().to_vec();
        assert_eq!(sessions.open_data(5, &first).await.unwrap().3, b"first");
        sessions.remove_link(5).await;
        let second = sender.encrypt(b"second").unwrap().to_vec();
        assert_eq!(
            sessions.open_data(5, &second).await,
            Err(crypto::CryptoError::UnknownSession)
        );
    }

    #[tokio::test]
    async fn install_init_resend_is_idempotent_and_reackable() {
        let source = crate::identity::generate();
        let circuit_id = CircuitId([42; 16]);
        let key = chacha20poly1305::Key::from([14; 32]);
        let sessions = SessionManager::default();
        sessions
            .install_open(1, circuit_id, source.verifying_key(), key)
            .await;
        sessions
            .install_open(1, circuit_id, source.verifying_key(), key)
            .await;
        let mut sender = crypto::SenderSession::from_key(circuit_id, key);
        let first = sender.encrypt(b"first").unwrap().to_vec();
        let second = sender.encrypt(b"second").unwrap().to_vec();
        assert_eq!(sessions.open_data(1, &first).await.unwrap().3, b"first");
        assert_eq!(sessions.open_data(1, &second).await.unwrap().3, b"second");
    }

    #[tokio::test]
    async fn open_ack_is_bound_to_link_and_circuit_token() {
        let opens = CircuitOpenManager::default();
        let stale_id = CircuitId([11; 16]);
        let current_id = CircuitId([12; 16]);
        let stale = opens
            .register(
                7,
                stale_id,
                "exit-key".into(),
                Vec::new(),
                None,
                crate::link::LinkToken::default(),
            )
            .await;
        opens.clear(7, stale_id).await;
        let current = opens
            .register(
                7,
                current_id,
                "exit-key".into(),
                Vec::new(),
                None,
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            !opens
                .resolve(7, stale_id, "exit-key", OpenResult::Acknowledged)
                .await
        );
        assert!(
            opens
                .resolve(7, current_id, "exit-key", OpenResult::Acknowledged)
                .await
        );
        assert_eq!(current.await.unwrap(), OpenResult::Acknowledged);
        drop(stale);
    }

    #[tokio::test]
    async fn link_token_revocation_blocks_late_ack_without_tombstone_history() {
        let opens = CircuitOpenManager::default();
        let circuit_id = CircuitId([16; 16]);
        let link_token = crate::link::LinkToken::default();
        let waiter = opens
            .register(
                17,
                circuit_id,
                "exit-key".into(),
                Vec::new(),
                None,
                link_token.clone(),
            )
            .await;

        opens.remove_link(17, link_token.clone()).await;
        assert!(waiter.await.is_err());
        assert!(
            !opens
                .resolve(17, circuit_id, "exit-key", OpenResult::Acknowledged)
                .await
        );
        assert!(!opens.is_authorized(17, circuit_id).await);

        // A later Link receives a fresh token and remains independent of the
        // revoked predecessor; no process-lifetime revoked-link set is needed.
        let replacement_token = crate::link::LinkToken::default();
        let replacement = opens
            .register(
                18,
                circuit_id,
                "exit-key".into(),
                Vec::new(),
                None,
                replacement_token,
            )
            .await;
        assert!(
            opens
                .resolve(18, circuit_id, "exit-key", OpenResult::Acknowledged)
                .await
        );
        assert_eq!(replacement.await.unwrap(), OpenResult::Acknowledged);
        assert!(opens.is_authorized(18, circuit_id).await);
    }

    #[tokio::test]
    async fn renew_ack_waiter_requires_the_expected_counter() {
        let opens = CircuitOpenManager::default();
        let circuit_id = CircuitId([15; 16]);
        let waiter = opens
            .register(
                7,
                circuit_id,
                "exit-key".into(),
                Vec::new(),
                Some(2),
                crate::link::LinkToken::default(),
            )
            .await;

        assert!(
            !opens
                .resolve(
                    7,
                    circuit_id,
                    "exit-key",
                    OpenResult::RenewAcknowledged { counter: 1 },
                )
                .await
        );
        assert!(
            opens
                .resolve(
                    7,
                    circuit_id,
                    "exit-key",
                    OpenResult::RenewAcknowledged { counter: 2 },
                )
                .await
        );
        assert_eq!(
            waiter.await.unwrap(),
            OpenResult::RenewAcknowledged { counter: 2 }
        );
    }

    #[tokio::test]
    async fn open_rejection_is_delivered_without_affecting_other_attempts() {
        let opens = CircuitOpenManager::default();
        let first_id = CircuitId([12; 16]);
        let second_id = CircuitId([13; 16]);
        let first = opens
            .register(
                7,
                first_id,
                "exit-key".into(),
                vec!["relay-key".into()],
                None,
                crate::link::LinkToken::default(),
            )
            .await;
        let second = opens
            .register(
                7,
                second_id,
                "exit-key".into(),
                Vec::new(),
                None,
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            opens
                .resolve(
                    7,
                    first_id,
                    "relay-key",
                    OpenResult::Rejected {
                        retryable: true,
                        reason: "next hop unavailable".into(),
                    },
                )
                .await
        );
        assert_eq!(
            first.await.unwrap(),
            OpenResult::Rejected {
                retryable: true,
                reason: "next hop unavailable".into(),
            }
        );
        assert!(
            opens
                .resolve(7, second_id, "exit-key", OpenResult::Acknowledged)
                .await
        );
        assert_eq!(second.await.unwrap(), OpenResult::Acknowledged);
    }

    #[tokio::test]
    async fn fallback_attempt_commits_when_its_candidate_guard_is_current() {
        let opens = CircuitOpenManager::default();
        let circuit_id = CircuitId([42; 16]);
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 7,
        };
        opens
            .set_desired_resolution(
                "exit",
                crate::reconcile::DesiredResolution {
                    generation: 2,
                    config_generation: 0,
                    path: Some(crate::reconcile::ResolvedPath {
                        destination: "exit".into(),
                        ordered_path: identity.ordered_path.clone(),
                        first_hop_link_instance: identity.first_hop_link_instance,
                        candidate_rank: 1,
                        verified_inner_mtu: 1200,
                        capacity_vector: CapacityVector::default(),
                        proof_valid_until: u64::MAX,
                    }),
                    availability: crate::reconcile::Availability::Ready,
                    resolved_at: std::time::SystemTime::now(),
                },
            )
            .await;
        let attempt = opens
            .begin_attempt_with_capacity(OpenAttemptInput {
                destination: "exit".into(),
                circuit_id,
                identity,
                config_generation: 0,
                link_instance: 7,
                capacity_vector: CapacityVector::default(),
                route_overrides: Vec::new(),
            })
            .await
            .expect("fallback attempt is not blocked by the old preferred attempt");
        let waiter = opens
            .register(
                7,
                circuit_id,
                "exit-key".into(),
                Vec::new(),
                None,
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            opens
                .resolve(7, circuit_id, "exit-key", OpenResult::Acknowledged)
                .await
        );
        assert_eq!(waiter.await.unwrap(), OpenResult::Acknowledged);
        let lease = opens
            .commit_if_current(
                &attempt,
                chacha20poly1305::Key::from([7; 32]),
                vec!["source".into(), "exit".into()],
                1200,
            )
            .await
            .expect("current fallback candidate must commit");
        assert_eq!(lease.path, vec!["source", "exit"]);
        assert_eq!(lease.link_instance, 7);
    }

    #[tokio::test]
    async fn circuit_open_state_machine_covers_rebuild_migration_and_budget_edges() {
        let opens = CircuitOpenManager::default();
        assert_eq!(opens.config_generation(), 0);
        assert_eq!(opens.bump_config_generation(), 1);
        assert_eq!(opens.bump_config_generation(), 2);

        opens.request_rebuild("exit").await;
        assert!(opens.take_rebuild_request("exit").await);
        assert!(!opens.take_rebuild_request("exit").await);
        assert!(!opens.take_rebuild_request("unknown").await);
        opens.request_ensure("exit").await;
        assert_eq!(opens.wait_for_ensure_requests().await, vec!["exit"]);

        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 31,
        };
        assert_eq!(opens.migration_snapshot("exit").await, None);
        assert_eq!(
            opens
                .migration_readiness(
                    "exit",
                    &identity,
                    true,
                    std::time::Duration::from_secs(3600)
                )
                .await
                .map(|readiness| matches!(readiness, MigrationReadiness::PendingUntil(_))),
            Some(true)
        );
        assert!(opens.begin_migration("exit").await.is_some());
        opens.migration_error("exit", "replacement timed out").await;
        let (preferred, started, error) = opens.migration_snapshot("exit").await.unwrap();
        assert_eq!(preferred, identity);
        assert!(started.is_some());
        assert_eq!(error.as_deref(), Some("replacement timed out"));
        assert!(
            opens
                .migration_overdue("exit", std::time::Duration::ZERO)
                .await
        );
        assert!(matches!(
            opens
                .migration_readiness("exit", &identity, true, std::time::Duration::ZERO)
                .await,
            Some(MigrationReadiness::Ready)
        ));
        let replacement = crate::reconcile::CircuitIdentity {
            first_hop_link_instance: 32,
            ..identity.clone()
        };
        assert!(matches!(
            opens
                .migration_readiness(
                    "exit",
                    &replacement,
                    true,
                    std::time::Duration::from_secs(3600),
                )
                .await,
            Some(MigrationReadiness::PendingUntil(_))
        ));
        assert_eq!(
            opens
                .migration_readiness("exit", &replacement, false, std::time::Duration::ZERO)
                .await,
            None
        );
        assert!(opens.begin_migration("exit").await.is_none());
        opens.clear_migration("exit").await;
        opens.reset_migration_readiness("exit").await;

        let revoked_identity = crate::reconcile::CircuitIdentity {
            destination: "revoked".into(),
            ..identity.clone()
        };
        opens
            .set_desired_guard("revoked", Some(revoked_identity.clone()), 2, true)
            .await;
        assert!(opens.desired_is_hard_revoked("revoked").await);
        let revoked = opens
            .begin_attempt(
                "revoked",
                CircuitId([61; 16]),
                revoked_identity.clone(),
                2,
                31,
            )
            .await
            .unwrap();
        assert!(matches!(
            opens
                .commit_if_current(
                    &revoked,
                    chacha20poly1305::Key::from([61; 32]),
                    revoked_identity.ordered_path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::HardRevoked)
        ));

        let missing_identity = crate::reconcile::CircuitIdentity {
            destination: "missing".into(),
            ordered_path: vec!["source".into(), "missing".into()],
            first_hop_link_instance: 33,
        };
        let missing = opens
            .begin_attempt(
                "missing",
                CircuitId([62; 16]),
                missing_identity.clone(),
                2,
                33,
            )
            .await
            .unwrap();
        assert!(matches!(
            opens
                .commit_if_current(
                    &missing,
                    chacha20poly1305::Key::from([62; 32]),
                    missing_identity.ordered_path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::StaleAttempt)
        ));

        let unauthorized_identity = crate::reconcile::CircuitIdentity {
            destination: "unauthorized".into(),
            ..identity.clone()
        };
        opens
            .set_desired_guard(
                "unauthorized",
                Some(unauthorized_identity.clone()),
                2,
                false,
            )
            .await;
        let unauthorized = opens
            .begin_attempt(
                "unauthorized",
                CircuitId([63; 16]),
                unauthorized_identity.clone(),
                2,
                31,
            )
            .await
            .unwrap();
        assert!(matches!(
            opens
                .commit_if_current(
                    &unauthorized,
                    chacha20poly1305::Key::from([63; 32]),
                    unauthorized_identity.ordered_path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::Unauthorized)
        ));

        let cancelled = opens
            .begin_attempt("cancelled", CircuitId([64; 16]), identity.clone(), 2, 31)
            .await
            .unwrap();
        opens.cancel_attempt(&cancelled).await;
        opens.cancel_attempt(&cancelled).await;
        assert!(opens.active_for_destination("cancelled").await.is_none());

        let active_id = CircuitId([65; 16]);
        opens
            .activate(
                "budget".into(),
                active_id,
                chacha20poly1305::Key::from([65; 32]),
                65,
                (vec!["source".into(), "exit".into()], 1500),
            )
            .await;
        assert!(opens.active_for_destination("budget").await.is_some());
        assert!(opens.active_for("budget", 65).await.is_some());
        assert_eq!(opens.active_path_inner_mtu("budget", 65).await, Some(1500));
        assert_eq!(opens.active_circuits().await.len(), 1);
        assert!(!opens.update_active_budget("budget", 66, 1400, 1400).await);
        assert!(
            !opens
                .update_active_budget_for_lease(
                    (
                        "budget",
                        CircuitId([66; 16]),
                        &["source".into(), "exit".into()],
                        65
                    ),
                    1400,
                    1400,
                    CapacityVector::default(),
                )
                .await
        );
        assert!(
            opens
                .update_active_budget_for_lease(
                    ("budget", active_id, &["source".into(), "exit".into()], 65),
                    1400,
                    1400,
                    CapacityVector {
                        edges: vec![CapacityEdge {
                            from: "source".into(),
                            to: "exit".into(),
                            capacity: 1300,
                            generation: 1,
                        }],
                    },
                )
                .await
        );
        assert_eq!(opens.active_path_inner_mtu("budget", 65).await, Some(1300));
        assert!(
            !opens
                .update_active_budget_with_vector(
                    "budget",
                    65,
                    1400,
                    1400,
                    CapacityVector {
                        edges: vec![CapacityEdge {
                            from: "source".into(),
                            to: "other".into(),
                            capacity: 1200,
                            generation: 2,
                        }],
                    },
                )
                .await
        );
        assert_eq!(opens.update_active_link_capacity(66, 1200, 1).await, 0);
        assert_eq!(opens.update_active_link_capacity(65, 1200, 1).await, 0);
        assert_eq!(opens.update_active_link_capacity(65, 1400, 2).await, 1);
        assert_eq!(opens.update_active_link_capacity(65, 1400, 2).await, 0);
        assert_eq!(opens.update_active_link_capacity(65, 1300, 1).await, 0);
        assert_eq!(opens.active_path_inner_mtu("budget", 65).await, Some(1400));
        opens.deactivate("budget", active_id).await;
        assert!(opens.active_for_destination("budget").await.is_none());
    }

    #[tokio::test]
    async fn circuit_open_commit_rejects_stale_and_merges_capacity_vectors() {
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 70,
        };
        let path = identity.ordered_path.clone();
        let resolution = |capacity_vector: CapacityVector, verified_inner_mtu| {
            crate::reconcile::DesiredResolution {
                generation: 1,
                config_generation: 0,
                path: Some(crate::reconcile::ResolvedPath {
                    destination: "exit".into(),
                    ordered_path: path.clone(),
                    first_hop_link_instance: 70,
                    candidate_rank: 0,
                    verified_inner_mtu,
                    capacity_vector,
                    proof_valid_until: u64::MAX,
                }),
                availability: crate::reconcile::Availability::Ready,
                resolved_at: std::time::SystemTime::now(),
            }
        };
        let edge = |capacity, generation| CapacityVector {
            edges: vec![CapacityEdge {
                from: "source".into(),
                to: "exit".into(),
                capacity,
                generation,
            }],
        };

        let opens = CircuitOpenManager::default();
        let nonexistent = OpenAttempt {
            destination: "never-created".into(),
            attempt_id: 1,
            circuit_id: CircuitId([70; 16]),
            identity: identity.clone(),
            config_generation: 0,
            link_instance: 70,
            capacity_vector: CapacityVector::default(),
            route_overrides: Vec::new(),
        };
        assert!(matches!(
            opens
                .commit_if_current(
                    &nonexistent,
                    chacha20poly1305::Key::from([70; 32]),
                    path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::StaleAttempt)
        ));
        opens
            .set_desired_resolution("exit", resolution(CapacityVector::default(), 1200))
            .await;
        let cancelled = opens
            .begin_attempt("exit", CircuitId([71; 16]), identity.clone(), 0, 70)
            .await
            .unwrap();
        opens.cancel_attempt(&cancelled).await;
        assert!(matches!(
            opens
                .commit_if_current(
                    &cancelled,
                    chacha20poly1305::Key::from([71; 32]),
                    path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::StaleAttempt)
        ));

        let malformed = opens
            .begin_attempt_with_capacity(OpenAttemptInput {
                destination: "exit".into(),
                circuit_id: CircuitId([72; 16]),
                identity: identity.clone(),
                config_generation: 0,
                link_instance: 70,
                capacity_vector: CapacityVector {
                    edges: vec![CapacityEdge {
                        from: "wrong".into(),
                        to: "exit".into(),
                        capacity: 1200,
                        generation: 1,
                    }],
                },
                route_overrides: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            opens
                .commit_if_current(
                    &malformed,
                    chacha20poly1305::Key::from([72; 32]),
                    path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::StaleAttempt)
        ));

        let attempt_only = opens
            .begin_attempt_with_capacity(OpenAttemptInput {
                destination: "exit".into(),
                circuit_id: CircuitId([73; 16]),
                identity: identity.clone(),
                config_generation: 0,
                link_instance: 70,
                capacity_vector: edge(1100, 1),
                route_overrides: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            opens
                .commit_if_current(
                    &attempt_only,
                    chacha20poly1305::Key::from([73; 32]),
                    path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::Unauthorized)
        ));

        let guard_wins = CircuitOpenManager::default();
        guard_wins
            .set_desired_resolution("exit", resolution(edge(1200, 2), 1400))
            .await;
        let attempt = guard_wins
            .begin_attempt_with_capacity(OpenAttemptInput {
                destination: "exit".into(),
                circuit_id: CircuitId([74; 16]),
                identity: identity.clone(),
                config_generation: 0,
                link_instance: 70,
                capacity_vector: edge(1000, 1),
                route_overrides: Vec::new(),
            })
            .await
            .unwrap();
        let waiter = guard_wins
            .register_for_attempt(
                &attempt,
                "exit-key".into(),
                Vec::new(),
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            guard_wins
                .resolve(
                    70,
                    CircuitId([74; 16]),
                    "exit-key",
                    OpenResult::Acknowledged
                )
                .await
        );
        waiter.await.unwrap();
        let lease = guard_wins
            .commit_if_current(
                &attempt,
                chacha20poly1305::Key::from([74; 32]),
                path.clone(),
                1500,
            )
            .await
            .unwrap();
        assert_eq!(lease.capacity_vector, edge(1200, 2));
        assert!(
            !guard_wins
                .update_active_budget_with_vector("exit", 70, 1400, 1400, edge(1300, 2))
                .await
        );

        let attempt_wins = CircuitOpenManager::default();
        attempt_wins
            .set_desired_resolution("exit", resolution(edge(1000, 1), 1400))
            .await;
        let attempt = attempt_wins
            .begin_attempt_with_capacity(OpenAttemptInput {
                destination: "exit".into(),
                circuit_id: CircuitId([75; 16]),
                identity: identity.clone(),
                config_generation: 0,
                link_instance: 70,
                capacity_vector: edge(1300, 2),
                route_overrides: Vec::new(),
            })
            .await
            .unwrap();
        let waiter = attempt_wins
            .register_for_attempt(
                &attempt,
                "exit-key".into(),
                Vec::new(),
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            attempt_wins
                .resolve(
                    70,
                    CircuitId([75; 16]),
                    "exit-key",
                    OpenResult::Acknowledged
                )
                .await
        );
        waiter.await.unwrap();
        assert_eq!(
            attempt_wins
                .commit_if_current(
                    &attempt,
                    chacha20poly1305::Key::from([75; 32]),
                    path.clone(),
                    1500,
                )
                .await
                .unwrap()
                .capacity_vector,
            edge(1300, 2)
        );

        let conflict = CircuitOpenManager::default();
        conflict
            .set_desired_resolution("exit", resolution(edge(1200, 1), 1400))
            .await;
        let attempt = conflict
            .begin_attempt_with_capacity(OpenAttemptInput {
                destination: "exit".into(),
                circuit_id: CircuitId([76; 16]),
                identity: identity.clone(),
                config_generation: 0,
                link_instance: 70,
                capacity_vector: edge(1300, 1),
                route_overrides: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            conflict
                .commit_if_current(
                    &attempt,
                    chacha20poly1305::Key::from([76; 32]),
                    path.clone(),
                    1200,
                )
                .await,
            Err(CommitError::StaleAttempt)
        ));

        let zero = CircuitOpenManager::default();
        zero.set_desired_resolution("exit", resolution(CapacityVector::default(), 0))
            .await;
        let attempt = zero
            .begin_attempt("exit", CircuitId([77; 16]), identity.clone(), 0, 70)
            .await
            .unwrap();
        assert!(matches!(
            zero.commit_if_current(
                &attempt,
                chacha20poly1305::Key::from([77; 32]),
                path.clone(),
                1200,
            )
            .await,
            Err(CommitError::StaleAttempt)
        ));

        let replacement = CircuitOpenManager::default();
        replacement
            .set_desired_resolution("exit", resolution(CapacityVector::default(), 1200))
            .await;
        let old_id = CircuitId([78; 16]);
        replacement
            .activate(
                "exit".into(),
                old_id,
                chacha20poly1305::Key::from([78; 32]),
                70,
                (vec!["source".into(), "exit".into()], 1200),
            )
            .await;
        let attempt = replacement
            .begin_attempt("exit", CircuitId([79; 16]), identity.clone(), 0, 70)
            .await
            .unwrap();
        let old_gate = replacement.active_send_context("exit", 70).await.unwrap().1;
        let waiter = replacement
            .register_for_attempt(
                &attempt,
                "exit-key".into(),
                Vec::new(),
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            replacement
                .resolve(
                    70,
                    CircuitId([79; 16]),
                    "exit-key",
                    OpenResult::Acknowledged
                )
                .await
        );
        waiter.await.unwrap();
        replacement
            .commit_if_current(
                &attempt,
                chacha20poly1305::Key::from([79; 32]),
                vec!["source".into(), "exit".into()],
                1200,
            )
            .await
            .unwrap();
        assert!(!old_gate.load(Ordering::Acquire));

        let single = CircuitOpenManager::default();
        single
            .activate(
                "single".into(),
                CircuitId([80; 16]),
                chacha20poly1305::Key::from([80; 32]),
                80,
                (vec!["source".into()], 1200),
            )
            .await;
        assert_eq!(single.update_active_link_capacity(80, 1000, 1).await, 0);
    }

    #[tokio::test]
    async fn only_one_open_worker_can_own_a_destination() {
        let opens = CircuitOpenManager::default();
        let claim = opens.claim_worker("exit").expect("first claim");
        assert!(opens.claim_worker("exit").is_none());
        drop(claim);
        assert!(opens.claim_worker("exit").is_some());
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod path_mtu_tests {
    use super::FakeIpMode;
    use super::{
        CircuitDnsClient, DirectEgress, QueuedSecurePacket, RouteSnapshot, SecureRoute, TunRouter,
        apply_topology, apply_topology_snapshot, encode_dns_response, frame_fits_current_budget,
        is_transient_datagram_backpressure, resolve_overlay_dns, run_secure_sender_worker,
        secure_sender_rejection, send_circuit_broken_feedback, source_send_rejection,
        user_packet_fits_current_budget,
    };
    #[cfg(target_os = "linux")]
    use super::{SourceAddressPolicy, spawn_tun_link};
    use crate::carrier::Link;
    use crate::circuit::CircuitId;
    use crate::link::LinkError;
    use crate::physical::FORWARD_OVERHEAD;
    #[cfg(target_os = "linux")]
    use crate::platform;
    use crate::{carrier, config, crypto, identity};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    async fn connected_full_quic_link() -> (Arc<Link>, Arc<Link>, quinn::Endpoint, quinn::Endpoint)
    {
        let client_key = identity::generate();
        let server_key = identity::generate();
        let server_public = identity::encode_public(&server_key.verifying_key());
        let (server, _) = carrier::endpoint_with_options_and_bare(
            config::CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &config::LinkHealthConfig::default(),
            None,
            None,
            Some(config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let server_guard = server.clone();
        let peers = std::collections::BTreeMap::from([(
            "client".to_owned(),
            config::Peer {
                public_key: identity::encode_public(&client_key.verifying_key()),
                endpoints: vec![],
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: vec![],
                routes: vec![],
                paths: vec![],
            },
        )]);
        let server_task = tokio::spawn(async move {
            carrier::accept_with_bare(
                &server,
                None,
                config::CarrierProtocol::QuicFull,
                &peers,
                false,
                "server",
                &server_key,
            )
            .await
            .unwrap()
        });
        let (client, _) = carrier::endpoint_with_options_and_bare(
            config::CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &config::LinkHealthConfig::default(),
            None,
            None,
            Some(config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let client_link = Arc::new(
            carrier::connect_with_link_health_and_bare(
                &client,
                None,
                address,
                config::CarrierProtocol::QuicFull,
                "server",
                &server_public,
                "client",
                &client_key,
                &config::LinkHealthConfig::default(),
            )
            .await
            .unwrap(),
        );
        // Keep the server endpoint alive until the first authenticated
        // physical payload is queued; this mirrors the normal listener
        // lifetime while the helper transfers ownership of the Link.
        client_link
            .send_physical(crate::physical::PhysicalPayload::Keepalive)
            .unwrap();
        client_link
            .send_forward(&[0x3c; crate::crypto::FRAME_OVERHEAD + 7])
            .unwrap();
        let peer = Arc::new(server_task.await.unwrap());
        loop {
            let payload =
                tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv_physical())
                    .await
                    .unwrap()
                    .unwrap();
            if let crate::physical::PhysicalPayload::Forward(frame) = payload {
                assert_eq!(frame.len(), crate::crypto::FRAME_OVERHEAD + 7);
                break;
            }
        }
        (client_link, peer, client, server_guard)
    }

    async fn receive_forward(peer: &Arc<Link>) -> Vec<u8> {
        loop {
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv_physical())
                    .await
                    .unwrap();
            let received = match received {
                Ok(received) => received,
                Err(error) => panic!(
                    "peer physical receive failed: {error:?}, close={:?}",
                    peer.close_reason()
                ),
            };
            match received {
                crate::physical::PhysicalPayload::Forward(frame) => return frame,
                crate::physical::PhysicalPayload::Keepalive
                | crate::physical::PhysicalPayload::Probe { .. }
                | crate::physical::PhysicalPayload::ProbeAck { .. }
                | crate::physical::PhysicalPayload::FecSource { .. }
                | crate::physical::PhysicalPayload::FecRepair { .. } => continue,
            }
        }
    }

    async fn wait_for_rejection(metrics: &crate::observability::Observability, reason: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
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
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    async fn join_task<T>(mut task: tokio::task::JoinHandle<T>, label: &str) -> Result<(), String> {
        match tokio::time::timeout(std::time::Duration::from_secs(2), &mut task).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(format!("{label} panicked: {error}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(format!("{label} timed out and was aborted"))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn queued(
        packet: &[u8],
        exit: &str,
        circuit_id: CircuitId,
        data_key: chacha20poly1305::Key,
        link: Arc<Link>,
        healthy: Arc<AtomicBool>,
        lease_epoch: u64,
        send_gate: Arc<AtomicBool>,
        send_budget: Arc<AtomicUsize>,
    ) -> QueuedSecurePacket {
        QueuedSecurePacket {
            packet: packet.to_vec(),
            exit: exit.into(),
            circuit_id,
            data_key,
            link,
            healthy,
            lease_epoch,
            send_gate,
            send_budget,
        }
    }

    #[test]
    fn relay_guard_accounts_for_physical_forward_overhead() {
        assert!(frame_fits_current_budget(1200 - FORWARD_OVERHEAD, 1200));
        assert!(!frame_fits_current_budget(1201 - FORWARD_OVERHEAD, 1200));
    }

    #[test]
    fn source_guard_uses_normalized_user_ip_capacity() {
        assert!(user_packet_fits_current_budget(1200, 1200));
        assert!(!user_packet_fits_current_budget(1201, 1200));
    }

    #[test]
    fn fake_ip_modes_keep_disabled_and_enabled_translation_contracts_distinct() {
        let disabled = super::FakeIpDisabled;
        let mut packet = vec![0_u8; 20];
        assert!(disabled.runtime().is_none());
        assert!(!disabled.restore_direct_return(&mut packet));
        assert!(disabled.route_hint("198.18.0.1".parse().unwrap()).is_none());
        assert!(!disabled.contains_fake_address("198.18.0.1".parse().unwrap()));
        assert!(!disabled.translate_outbound(&mut packet));
        assert!(!disabled.translate_outbound_direct(&mut packet));
        assert!(disabled.restore_circuit_return(&mut packet, None));
        assert!(!disabled.restore_circuit_return(&mut packet, Some("198.18.0.1".parse().unwrap())));

        let config: config::FakeIpConfig = serde_yaml::from_str(
            "listen: 127.0.0.1:0\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true",
        )
        .unwrap();
        let enabled = super::FakeIpEnabled(Arc::new(crate::fake_ip::FakeIpRuntime::new(
            config,
            Default::default(),
            Vec::new(),
            vec!["10.64.0.1".parse().unwrap()],
            Arc::new(crate::observability::Observability::new(0)),
        )));
        assert!(enabled.runtime().is_some());
        assert!(enabled.route_hint("198.18.0.1".parse().unwrap()).is_none());
        assert!(enabled.contains_fake_address("198.18.0.1".parse().unwrap()));
        assert!(!enabled.restore_direct_return(&mut packet));
        assert!(!enabled.translate_outbound(&mut packet));
        assert!(!enabled.translate_outbound_direct(&mut packet));
        assert!(enabled.restore_circuit_return(&mut packet, None));
        assert!(!enabled.restore_circuit_return(&mut packet, Some("198.18.0.1".parse().unwrap())));
    }

    #[test]
    fn direct_egress_rejects_zero_zone_before_opening_platform_state() {
        assert!(DirectEgress::open(46, 0, true).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn privileged_direct_egress_transitions_from_closed_to_ready() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let egress = DirectEgress::open(46, 32123, true).unwrap();
        assert!(!egress.is_ready());
        egress.activate();
        assert!(egress.is_ready());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_direct_conntrack_cleanup_is_idempotent_for_untracked_packets() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let egress = DirectEgress::open(46, 32124, true).unwrap();
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        let key = egress
            .conntrack
            .flow_key(&packet)
            .expect("valid packet has a conntrack tuple");
        assert!(egress.conntrack.delete_default(&packet).await.is_ok());
        assert!(egress.conntrack.delete_fallback(key).await.is_ok());
    }

    #[test]
    fn source_gate_failure_is_not_reported_as_mtu_failure() {
        assert_eq!(
            source_send_rejection(false, 84, 1460),
            Some("lease:not_ready")
        );
        assert_eq!(source_send_rejection(true, 84, 1460), None);
        assert_eq!(
            source_send_rejection(true, 1400, 1399),
            Some("packet:exceeds_path_mtu")
        );
    }

    #[test]
    fn secure_sender_rechecks_the_live_budget_and_reports_precise_reasons() {
        let budget = AtomicUsize::new(1400);
        assert_eq!(
            secure_sender_rejection(true, 1400, budget.load(Ordering::Acquire)),
            None
        );
        budget.store(1399, Ordering::Release);
        assert_eq!(
            secure_sender_rejection(true, 1400, budget.load(Ordering::Acquire)),
            Some("packet:exceeds_path_mtu")
        );
        assert_eq!(
            secure_sender_rejection(false, 1400, budget.load(Ordering::Acquire)),
            Some("lease:stale_epoch")
        );
    }

    #[test]
    fn transient_datagram_backpressure_does_not_mark_route_unhealthy() {
        assert!(is_transient_datagram_backpressure(&LinkError::WouldBlock));
        assert!(!is_transient_datagram_backpressure(&LinkError::Transport(
            "connection lost".into(),
        )));
    }

    #[tokio::test]
    async fn secure_sender_reuses_and_rebuilds_authenticated_sessions() {
        crate::circuit::backdate_monotonic_epoch();
        let (link, peer, _client_endpoint, _server_endpoint) = connected_full_quic_link().await;
        let (tx, rx) = mpsc::channel(8);
        let cancellation = CancellationToken::new();
        let supervisor = crate::runtime::DaemonSupervisor::default();
        let metrics = Arc::new(crate::observability::Observability::new(0));
        let source = Arc::new(identity::generate());
        let worker = tokio::spawn(run_secure_sender_worker(
            rx,
            source.clone(),
            crate::dataplane::SessionManager::default(),
            crate::dataplane::CircuitOpenManager::default(),
            cancellation.clone(),
            metrics.clone(),
            supervisor.clone(),
        ));
        let healthy = Arc::new(AtomicBool::new(false));
        let send_gate = Arc::new(AtomicBool::new(true));
        let budget = Arc::new(AtomicUsize::new(usize::MAX));
        let first_id = CircuitId([91; 16]);
        let first_key = chacha20poly1305::Key::from([92; 32]);
        tx.send(queued(
            b"first",
            "exit",
            first_id,
            first_key,
            link.clone(),
            healthy.clone(),
            1,
            send_gate.clone(),
            budget.clone(),
        ))
        .await
        .unwrap();
        tx.send(queued(
            b"second",
            "exit",
            first_id,
            first_key,
            link.clone(),
            healthy.clone(),
            1,
            send_gate.clone(),
            budget.clone(),
        ))
        .await
        .unwrap();

        let mut receiver = crypto::ReceiverSessions::default();
        receiver.install(first_id, source.verifying_key(), first_key);
        for expected in [b"first".as_slice(), b"second".as_slice()] {
            let frame = receive_forward(&peer).await;
            assert_eq!(receiver.open_data(&frame).unwrap().3, expected);
        }
        assert!(healthy.load(Ordering::Acquire));

        let second_id = CircuitId([93; 16]);
        let second_key = chacha20poly1305::Key::from([94; 32]);
        receiver.install(second_id, source.verifying_key(), second_key);
        tx.send(queued(
            b"rebuilt",
            "exit",
            second_id,
            second_key,
            link.clone(),
            healthy.clone(),
            2,
            send_gate,
            budget,
        ))
        .await
        .unwrap();
        let frame = receive_forward(&peer).await;
        assert_eq!(receiver.open_data(&frame).unwrap().3, b"rebuilt");
        drop(tx);
        worker.await.unwrap();
        assert!(metrics.snapshot().circuits.is_empty());
    }

    #[tokio::test]
    async fn secure_sender_rejects_stale_oversize_and_closed_paths() {
        crate::circuit::backdate_monotonic_epoch();
        let (link, _peer, _client_endpoint, _server_endpoint) = connected_full_quic_link().await;
        let (tx, rx) = mpsc::channel(8);
        let cancellation = CancellationToken::new();
        let supervisor = crate::runtime::DaemonSupervisor::default();
        let metrics = Arc::new(crate::observability::Observability::new(0));
        let worker = tokio::spawn(run_secure_sender_worker(
            rx,
            Arc::new(identity::generate()),
            crate::dataplane::SessionManager::default(),
            crate::dataplane::CircuitOpenManager::default(),
            cancellation,
            metrics.clone(),
            supervisor.clone(),
        ));
        let healthy = Arc::new(AtomicBool::new(true));
        let send_gate = Arc::new(AtomicBool::new(false));
        let budget = Arc::new(AtomicUsize::new(usize::MAX));
        let id = CircuitId([95; 16]);
        let key = chacha20poly1305::Key::from([96; 32]);
        tx.send(queued(
            b"stale",
            "exit",
            id,
            key,
            link.clone(),
            healthy.clone(),
            1,
            send_gate.clone(),
            budget.clone(),
        ))
        .await
        .unwrap();
        wait_for_rejection(&metrics, "lease:stale_epoch").await;
        send_gate.store(true, Ordering::Release);
        budget.store(1, Ordering::Release);
        tx.send(queued(
            b"too large for budget",
            "exit",
            id,
            key,
            link.clone(),
            healthy.clone(),
            1,
            send_gate.clone(),
            budget.clone(),
        ))
        .await
        .unwrap();
        wait_for_rejection(&metrics, "packet:exceeds_path_mtu").await;
        budget.store(usize::MAX, Ordering::Release);
        let oversized = vec![0_u8; link.max_datagram_size().unwrap_or(1200)];
        tx.send(queued(
            &oversized,
            "exit",
            id,
            key,
            link.clone(),
            healthy.clone(),
            1,
            send_gate.clone(),
            budget.clone(),
        ))
        .await
        .unwrap();
        link.close("worker error path");
        tokio::time::timeout(std::time::Duration::from_secs(2), link.wait_closed())
            .await
            .unwrap();
        tx.send(queued(
            b"closed",
            "exit",
            id,
            key,
            link,
            healthy.clone(),
            1,
            send_gate,
            budget,
        ))
        .await
        .unwrap();
        drop(tx);
        worker.await.unwrap();
        let rejections = metrics.snapshot().acl_rejections;
        assert_eq!(rejections.get("lease:stale_epoch"), Some(&1));
        assert_eq!(rejections.get("packet:exceeds_path_mtu"), Some(&1));
        assert_eq!(rejections.get("packet:exceeds_datagram_limit"), Some(&1));
        assert!(!healthy.load(Ordering::Acquire));
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn secure_sender_rebuilds_session_when_link_instance_changes() {
        crate::circuit::backdate_monotonic_epoch();
        let (first_link, first_peer, first_client, first_server) = connected_full_quic_link().await;
        let (second_link, second_peer, second_client, second_server) =
            connected_full_quic_link().await;
        assert_ne!(first_link.instance(), second_link.instance());
        let (tx, rx) = mpsc::channel(8);
        let cancellation = CancellationToken::new();
        let supervisor = crate::runtime::DaemonSupervisor::default();
        let metrics = Arc::new(crate::observability::Observability::new(0));
        let source = Arc::new(identity::generate());
        let worker = tokio::spawn(run_secure_sender_worker(
            rx,
            source.clone(),
            crate::dataplane::SessionManager::default(),
            crate::dataplane::CircuitOpenManager::default(),
            cancellation.clone(),
            metrics.clone(),
            supervisor.clone(),
        ));
        let healthy = Arc::new(AtomicBool::new(false));
        let send_gate = Arc::new(AtomicBool::new(true));
        let budget = Arc::new(AtomicUsize::new(usize::MAX));
        let id = CircuitId([110; 16]);
        let key = chacha20poly1305::Key::from([111; 32]);
        // Same exit/epoch/circuit on a different Link instance: the cached
        // sender session must be rebuilt instead of reused.
        tx.send(queued(
            b"first",
            "exit",
            id,
            key,
            first_link.clone(),
            healthy.clone(),
            1,
            send_gate.clone(),
            budget.clone(),
        ))
        .await
        .unwrap();
        tx.send(queued(
            b"second",
            "exit",
            id,
            key,
            second_link.clone(),
            healthy.clone(),
            1,
            send_gate,
            budget,
        ))
        .await
        .unwrap();
        let mut receiver = crypto::ReceiverSessions::default();
        receiver.install(id, source.verifying_key(), key);
        let first_frame = receive_forward(&first_peer).await;
        assert_eq!(receiver.open_data(&first_frame).unwrap().3, b"first");
        // Each Link instance owns independent receiver session state, so a
        // second session decrypts the frame rebuilt for the new instance.
        let mut second_receiver = crypto::ReceiverSessions::default();
        second_receiver.install(id, source.verifying_key(), key);
        let second_frame = receive_forward(&second_peer).await;
        assert_eq!(
            second_receiver.open_data(&second_frame).unwrap().3,
            b"second"
        );
        drop(tx);
        worker.await.unwrap();
        assert!(healthy.load(Ordering::Acquire));
        first_link.close("link instance test");
        second_link.close("link instance test");
        first_client.close(0u32.into(), b"link instance test");
        first_server.close(0u32.into(), b"link instance test");
        second_client.close(0u32.into(), b"link instance test");
        second_server.close(0u32.into(), b"link instance test");
    }

    /// Evaluate tracing field expressions so structured-logging arguments on
    /// covered paths are exercised instead of skipped as disabled callsites.
    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
    }

    #[tokio::test]
    async fn circuit_broken_feedback_delivers_and_reports_delivery_failures() {
        init_tracing();
        let (link, peer, client_endpoint, server_endpoint) = connected_full_quic_link().await;
        let identity = Arc::new(identity::generate());
        let circuit_id = CircuitId([112; 16]);
        let deliver_link = link.clone();
        let deliver_identity = identity.clone();
        let deliver = tokio::spawn(async move {
            send_circuit_broken_feedback(&deliver_link, &deliver_identity, circuit_id).await
        });
        let message = tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv_control())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            message,
            crate::control::ControlMessage::CircuitBroken { .. }
        ));
        deliver.await.unwrap();

        // A closed link returns a non-admission error immediately: the
        // feedback is dropped after logging instead of being retried.
        link.close("circuit broken feedback test");
        peer.close("circuit broken feedback test");
        send_circuit_broken_feedback(&link, &identity, circuit_id).await;
        client_endpoint.close(0u32.into(), b"circuit broken feedback test");
        server_endpoint.close(0u32.into(), b"circuit broken feedback test");
    }

    #[tokio::test]
    async fn topology_application_skips_refreshed_lsas_with_unchanged_path_sets() {
        let (link, _peer, _client_endpoint, _server_endpoint) = connected_full_quic_link().await;
        let key = identity::generate();
        let origin = identity::node_id(&key.verifying_key());
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let neighbors = vec![crate::topology::LinkMetric {
            node: identity::node_id(&identity::generate().verifying_key()),
            cost: 5,
            inner_mtu: 1200,
        }];
        let first = crate::topology::LinkStateAdvertisement::new(
            origin.clone(),
            &key,
            1,
            expires_at,
            neighbors.clone(),
        );
        let refreshed = crate::topology::LinkStateAdvertisement::new(
            origin.clone(),
            &key,
            2,
            expires_at,
            neighbors,
        );
        let topology = Arc::new(tokio::sync::RwLock::new(
            crate::topology::Topology::default(),
        ));
        assert_eq!(
            apply_topology(&link, vec![first.clone()], &topology)
                .await
                .len(),
            1
        );
        // A higher sequence with the identical neighbor set only advances
        // anti-replay; it must not fan out to the control plane.
        assert!(
            apply_topology(&link, vec![refreshed], &topology)
                .await
                .is_empty()
        );
        // Replaying the older record is rejected without fanout.
        assert!(
            apply_topology(&link, vec![first], &topology)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn overlay_dns_resolves_secure_candidates_and_reports_upstream_failures() {
        let (link, _peer, _client_endpoint, _server_endpoint) = connected_full_quic_link().await;
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.test\n").unwrap();
        let upstream = crate::config::DnsServer::from_socket_addr("127.0.0.1:1".parse().unwrap());
        let binding = SecureRoute {
            prefix: "198.18.0.0/15".parse().unwrap(),
            exit: "exit".into(),
            priority: 100,
            link: link.clone(),
            circuit_id: CircuitId([113; 16]),
            data_key: chacha20poly1305::Key::from([114; 32]),
            destination_key: identity::generate().verifying_key(),
            healthy: Arc::new(AtomicBool::new(true)),
            mtu: 1200,
            lease_epoch: 1,
            send_gate: Arc::new(AtomicBool::new(true)),
            send_budget: Arc::new(AtomicUsize::new(1200)),
        };
        let routes = Arc::new(tokio::sync::RwLock::new(Arc::new(
            RouteSnapshot::new_with_domains(
                Vec::new(),
                Vec::new(),
                vec![(set_id, binding.clone(), Arc::from([upstream]))],
                Vec::new(),
                Arc::new(loader.finish()),
            ),
        )));
        let make_request = || {
            let (response, receiver) = tokio::sync::oneshot::channel();
            let mut query = hickory_proto::op::Message::query();
            query.queries.push(hickory_proto::op::Query::query(
                hickory_proto::rr::Name::from_ascii("www.example.test.").unwrap(),
                hickory_proto::rr::RecordType::A,
            ));
            (
                crate::fake_ip::OverlayDnsRequest {
                    domain: "www.example.test".into(),
                    wire: query.to_vec().unwrap(),
                    upstreams: Vec::new(),
                    response,
                },
                receiver,
            )
        };

        // A Secure candidate whose Circuit DNS query succeeds is answered
        // with the exit preference.
        let (request, response) = make_request();
        let client = CircuitDnsClient::default();
        let resolver = tokio::spawn(resolve_overlay_dns(
            request,
            routes.clone(),
            client.clone(),
            crate::dataplane::CircuitOpenManager::default(),
            false,
        ));
        let token = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(token) = client.state.lock().unwrap().pending.keys().next().copied() {
                    return token;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut answer = hickory_proto::op::Message::response(0, hickory_proto::op::OpCode::Query);
        answer.queries.push(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("www.example.test.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        client
            .complete(&encode_dns_response(
                token,
                0,
                0,
                1,
                &answer.to_vec().unwrap(),
            ))
            .unwrap();
        let resolved = response.await.unwrap().unwrap();
        assert!(matches!(
            resolved.preferred_route,
            crate::fake_ip::RoutePreference::Exit(exit) if exit == "exit"
        ));
        resolver.await.unwrap();

        // A Secure candidate returning a non-success response (SERVFAIL) is
        // recorded as an error and fails the request.
        let (request, response) = make_request();
        let client = CircuitDnsClient::default();
        let resolver = tokio::spawn(resolve_overlay_dns(
            request,
            routes.clone(),
            client.clone(),
            crate::dataplane::CircuitOpenManager::default(),
            false,
        ));
        let token = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(token) = client.state.lock().unwrap().pending.keys().next().copied() {
                    return token;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut failed = hickory_proto::op::Message::response(0, hickory_proto::op::OpCode::Query);
        failed.metadata.response_code = hickory_proto::op::ResponseCode::ServFail;
        client
            .complete(&encode_dns_response(
                token,
                0,
                0,
                1,
                &failed.to_vec().unwrap(),
            ))
            .unwrap();
        let error = match response.await.unwrap() {
            Ok(_) => panic!("SERVFAIL must fail the overlay DNS request"),
            Err(reason) => reason,
        };
        assert!(error.contains("unsuccessful DNS response"));
        resolver.await.unwrap();

        // A Secure candidate whose Circuit DNS query fails at the carrier
        // (closed link) is reported as an upstream failure.
        link.close("overlay DNS secure candidate failure");
        let (request, response) = make_request();
        resolve_overlay_dns(
            request,
            routes,
            CircuitDnsClient::default(),
            crate::dataplane::CircuitOpenManager::default(),
            false,
        )
        .await;
        let error = match response.await.unwrap() {
            Ok(_) => panic!("carrier failure must fail the overlay DNS request"),
            Err(reason) => reason,
        };
        assert!(error.contains("via exit failed"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_secure_receive_authenticates_unknown_and_authorized_frames() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let device = platform::create_tun(&config::TunConfig {
            enabled: true,
            name: "tinectcvrx".into(),
            addresses: vec!["10.64.0.1/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        })
        .unwrap();
        let (client_link, server_link, client_endpoint, server_endpoint) =
            connected_full_quic_link().await;
        let supervisor = crate::runtime::DaemonSupervisor::default();
        let dispatch_link = server_link.clone();
        let dispatcher = tokio::spawn(async move {
            loop {
                match dispatch_link.recv_physical().await {
                    Ok(crate::physical::PhysicalPayload::Forward(frame)) => {
                        dispatch_link.publish_forward(frame);
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });

        let source_key = identity::generate();
        let circuit_id = CircuitId([101; 16]);
        let circuit_key = chacha20poly1305::Key::from([102; 32]);
        let authorizations = crate::circuit::CircuitAuthorizations::default();
        authorizations
            .install(
                server_link.instance(),
                circuit_id,
                identity::encode_public(&source_key.verifying_key()),
            )
            .await
            .unwrap();
        let sessions = super::SessionManager::default();
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
        let circuit_opens = super::CircuitOpenManager::default();
        circuit_opens
            .activate(
                "exit".into(),
                circuit_id,
                circuit_key,
                server_link.instance(),
                (vec!["source".into(), "exit".into()], 1200),
            )
            .await;
        let authorization_waiter = circuit_opens
            .register(
                server_link.instance(),
                circuit_id,
                "peer".into(),
                Vec::new(),
                None,
                server_link.lifecycle_token(),
            )
            .await;
        assert!(
            circuit_opens
                .resolve(
                    server_link.instance(),
                    circuit_id,
                    "peer",
                    super::OpenResult::Acknowledged,
                )
                .await
        );
        assert!(matches!(
            authorization_waiter.await.unwrap(),
            super::OpenResult::Acknowledged
        ));
        let metrics = Arc::new(crate::observability::Observability::new(0));
        let context = super::SecureReceiveContext {
            identity: Arc::new(identity::generate()),
            egress: None,
            source_policy: SourceAddressPolicy::default(),
            metrics: metrics.clone(),
            authorizations,
            relay_labels: Default::default(),
            sessions: sessions.clone(),
            circuit_router: Arc::new(crate::circuit::Router::new(
                "receiver",
                crate::policy::TransitPolicy::new(false, std::collections::HashMap::new()),
                Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            )),
            circuit_opens,
            return_flows: crate::return_path::ReturnFlowTable::default(),
            circuit_dns: super::CircuitDnsClient::default(),
            supervisor: supervisor.clone(),
        };
        let receive_task = tokio::spawn(super::receive_secure_link(
            device.clone(),
            server_link.clone(),
            context,
            super::FakeIpDisabled,
        ));

        let packet = {
            let mut packet = vec![0_u8; 28];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(28_u16).to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&[10, 64, 0, 2]);
            packet[16..20].copy_from_slice(&[192, 0, 2, 7]);
            packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
            packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
            packet
        };
        let mut unknown_sender = crypto::SenderSession::from_key(
            CircuitId([103; 16]),
            chacha20poly1305::Key::from([104; 32]),
        );
        client_link
            .send_forward(unknown_sender.encrypt(&packet).unwrap())
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client_link.recv_control()
            )
            .await
            .unwrap()
            .unwrap(),
            crate::control::ControlMessage::CircuitBroken { .. }
        ));

        let mut sender = crypto::SenderSession::from_key(circuit_id, circuit_key);
        client_link
            .send_forward(sender.encrypt(&packet).unwrap())
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if metrics.snapshot().dataplane.tun_tx_packets != 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            metrics.snapshot().acl_rejections.get("crypto:no_session"),
            Some(&1)
        );

        // A successfully authenticated frame still needs an installed
        // circuit authorization.  Keep a session without that authorization
        // to exercise the unopened-circuit admission boundary.
        let orphan_id = CircuitId([105; 16]);
        sessions
            .install_open(
                server_link.instance(),
                orphan_id,
                source_key.verifying_key(),
                circuit_key,
            )
            .await;
        let mut orphan_sender = crypto::SenderSession::from_key(orphan_id, circuit_key);
        server_link.publish_forward(orphan_sender.encrypt(&packet).unwrap().to_vec());
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if metrics
                    .snapshot()
                    .acl_rejections
                    .contains_key("egress:unopened_circuit")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        // The envelope tag is reserved for FakeIP.  A truncated envelope is
        // rejected after AEAD authentication rather than reaching the TUN.
        server_link.publish_forward(
            sender
                .encrypt(&[crate::fake_ip::FAKE_IP_ENVELOPE_TAG, 4, 1])
                .unwrap()
                .to_vec(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if metrics
                    .snapshot()
                    .acl_rejections
                    .contains_key("fake_ip:malformed_envelope")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        // Exercise the DNS direction's malformed-wire and no-policy guards.
        let mut dns_sender = crypto::SenderSession::dns_from_key(circuit_id, circuit_key);
        server_link.publish_forward(dns_sender.encrypt(b"bad").unwrap().to_vec());
        let query = super::encode_dns_query(
            9,
            &crate::config::DnsServer::from_socket_addr("203.0.113.53:53".parse().unwrap()),
            b"bad",
        )
        .unwrap();
        server_link.publish_forward(dns_sender.encrypt(&query).unwrap().to_vec());
        server_link.publish_forward(
            dns_sender
                .encrypt(&crate::fake_ip::encode_fake_ip_envelope(
                    &query,
                    "192.0.2.7".parse().unwrap(),
                ))
                .unwrap()
                .to_vec(),
        );

        // Return and DNS-return directions share the same authorization but
        // take different post-decryption paths.
        let mut return_sender = crypto::SenderSession::return_from_key(circuit_id, circuit_key);
        server_link.publish_forward(return_sender.encrypt(&packet).unwrap().to_vec());
        let mut dns_return_sender =
            crypto::SenderSession::dns_return_from_key(circuit_id, circuit_key);
        server_link.publish_forward(dns_return_sender.encrypt(b"bad").unwrap().to_vec());
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let snapshot = metrics.snapshot();
                if snapshot.acl_rejections.contains_key("dns:malformed_query")
                    && snapshot
                        .acl_rejections
                        .contains_key("egress:dns_no_allowed_routes")
                    && snapshot
                        .acl_rejections
                        .contains_key("fake_ip:envelope_on_dns")
                    && snapshot.acl_rejections.contains_key("dns:return_rejected")
                    && snapshot.dataplane.tun_tx_packets >= 2
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        server_link.close("secure receive test complete");
        client_link.close("secure receive test complete");
        client_endpoint.close(0u32.into(), b"secure receive test complete");
        server_endpoint.close(0u32.into(), b"secure receive test complete");
        let receive_result = join_task(receive_task, "secure receive task").await;
        let dispatcher_result = join_task(dispatcher, "secure receive dispatcher").await;
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert!(receive_result.is_ok(), "{receive_result:?}");
        assert!(dispatcher_result.is_ok(), "{dispatcher_result:?}");
    }

    #[tokio::test]
    async fn topology_application_fans_out_only_new_valid_advertisements() {
        let (link, _peer, _client_endpoint, _server_endpoint) = connected_full_quic_link().await;
        let key = identity::generate();
        let origin = identity::node_id(&key.verifying_key());
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let valid = crate::topology::LinkStateAdvertisement::new(
            origin.clone(),
            &key,
            1,
            expires_at,
            Vec::new(),
        );
        let topology = Arc::new(tokio::sync::RwLock::new(
            crate::topology::Topology::default(),
        ));
        assert_eq!(
            apply_topology(&link, vec![valid.clone()], &topology)
                .await
                .len(),
            1
        );
        assert!(
            apply_topology(&link, vec![valid.clone()], &topology)
                .await
                .is_empty()
        );

        let expired =
            crate::topology::LinkStateAdvertisement::new(origin.clone(), &key, 2, 0, Vec::new());
        assert!(
            apply_topology(&link, vec![expired], &topology)
                .await
                .is_empty()
        );

        let refreshed = crate::topology::LinkStateAdvertisement::new(
            origin.clone(),
            &key,
            2,
            expires_at,
            Vec::new(),
        );
        assert!(
            apply_topology_snapshot(&link, vec![refreshed], &topology)
                .await
                .is_ok()
        );
        let identity_mismatch = crate::topology::LinkStateAdvertisement::new(
            "00".repeat(16),
            &key,
            3,
            expires_at,
            Vec::new(),
        );
        assert!(
            apply_topology_snapshot(&link, vec![identity_mismatch], &topology)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn tun_router_replaces_bindings_and_shutdowns_without_leaking_sessions() {
        let (link, _peer, _client_endpoint, _server_endpoint) = connected_full_quic_link().await;
        let (receiver_tx, mut receiver_rx) = mpsc::unbounded_channel();
        let router = TunRouter {
            routes: Arc::new(tokio::sync::RwLock::new(Arc::new(RouteSnapshot::new(
                Vec::new(),
                Vec::new(),
            )))),
            receiver_tx,
            cancellation: CancellationToken::new(),
            sessions: crate::dataplane::SessionManager::default(),
        };
        let route_key = identity::generate();
        let prefix = "192.0.2.0/24".parse().unwrap();
        let secure_route = SecureRoute {
            prefix,
            exit: "exit".into(),
            priority: 100,
            link: link.clone(),
            circuit_id: CircuitId([97; 16]),
            data_key: chacha20poly1305::Key::from([98; 32]),
            destination_key: route_key.verifying_key(),
            healthy: Arc::new(AtomicBool::new(true)),
            mtu: 1200,
            lease_epoch: 1,
            send_gate: Arc::new(AtomicBool::new(true)),
            send_budget: Arc::new(AtomicUsize::new(1200)),
        };
        router
            .replace_routes(RouteSnapshot::new(vec![secure_route.clone()], Vec::new()))
            .await;
        // Route snapshots carry send capabilities only; inbound receive
        // workers are attached explicitly from concrete Links.
        router.attach_link(link.clone());
        assert_eq!(
            receiver_rx.recv().await.unwrap().instance(),
            link.instance()
        );
        let route_import = crate::config::RouteImport {
            prefix,
            candidates: vec![crate::config::RouteCandidate {
                node: "exit".into(),
                priority: 100,
            }],
        };
        let selected = RouteSnapshot::new(vec![secure_route.clone()], vec![route_import.clone()])
            .with_direct_routes(vec![(prefix, 90)], Vec::new());
        assert!(matches!(
            selected.select_route("192.0.2.7".parse().unwrap(), None),
            Some(super::RouteSelection::Secure(binding)) if binding.exit == "exit"
        ));
        assert!(matches!(
            RouteSnapshot::new(vec![secure_route.clone()], vec![route_import.clone()])
                .with_direct_routes(vec![(prefix, 101)], Vec::new())
                .select_route("192.0.2.7".parse().unwrap(), None),
            Some(super::RouteSelection::Direct)
        ));
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.com\n").unwrap();
        let domain_snapshot = RouteSnapshot::new_with_domains(
            Vec::new(),
            Vec::new(),
            vec![(
                set_id,
                secure_route.clone(),
                vec![crate::config::DnsServer::from_socket_addr(
                    "203.0.113.53:53".parse().unwrap(),
                )]
                .into(),
            )],
            vec![crate::config::DomainRouteImport {
                set_id,
                candidates: vec![crate::config::RouteCandidate {
                    node: "exit".into(),
                    priority: 100,
                }],
            }],
            Arc::new(loader.finish()),
        );
        assert!(domain_snapshot.has_healthy_domain_binding());
        assert!(matches!(
            domain_snapshot.select_route(
                "198.51.100.7".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "www.example.com".into(),
                    preferred_route: Some(crate::fake_ip::RoutePreference::Exit("exit".into())),
                }),
            ),
            Some(super::RouteSelection::Secure(binding)) if binding.exit == "exit"
        ));
        assert!(matches!(
            domain_snapshot.select_route(
                "198.51.100.7".parse().unwrap(),
                Some(&crate::fake_ip::FakeRouteHint {
                    domain: "www.example.com".into(),
                    preferred_route: None,
                }),
            ),
            Some(super::RouteSelection::Secure(binding)) if binding.exit == "exit"
        ));
        assert!(matches!(
            domain_snapshot
                .with_direct_routes(Vec::new(), vec![(set_id, 101)])
                .select_route(
                    "198.51.100.7".parse().unwrap(),
                    Some(&crate::fake_ip::FakeRouteHint {
                        domain: "www.example.com".into(),
                        preferred_route: None,
                    }),
                ),
            Some(super::RouteSelection::Direct)
        ));
        secure_route.healthy.store(false, Ordering::Release);
        assert!(matches!(
            RouteSnapshot::new(vec![secure_route], vec![route_import])
                .with_direct_routes(vec![(prefix, 90)], Vec::new())
                .select_route("192.0.2.7".parse().unwrap(), None),
            Some(super::RouteSelection::Direct)
        ));
        router.shutdown().await;
        router.shutdown().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn privileged_single_link_tun_bridge_rejects_bound_source_spoof() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let tun = platform::create_tun(&config::TunConfig {
            enabled: true,
            name: "tinectcvg".into(),
            addresses: vec!["10.64.0.1/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        })
        .unwrap();
        let (client_link, server_link, client_endpoint, server_endpoint) =
            connected_full_quic_link().await;
        let supervisor = crate::runtime::DaemonSupervisor::default();
        let dispatch_link = server_link.clone();
        let dispatcher = tokio::spawn(async move {
            loop {
                match dispatch_link.recv_physical().await {
                    Ok(crate::physical::PhysicalPayload::Forward(frame)) => {
                        dispatch_link.publish_forward(frame);
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });
        let metrics = Arc::new(crate::observability::Observability::new(0));
        let source_policy = SourceAddressPolicy::from_bindings(
            vec![("10.64.0.2/32".parse().unwrap(), "other".into())],
            metrics.clone(),
        );
        spawn_tun_link(tun, server_link.clone(), source_policy, supervisor.clone());
        let mut packet = vec![0_u8; 64];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 59;
        packet[12..16].copy_from_slice(&[10, 64, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        client_link.send_forward(&packet).unwrap();
        wait_for_rejection(&metrics, "source_binding:denied").await;
        tokio::task::yield_now().await;
        client_link.close("single-link bridge test complete");
        server_link.close("single-link bridge test complete");
        tokio::time::timeout(std::time::Duration::from_secs(2), server_link.wait_closed())
            .await
            .unwrap();
        client_endpoint.close(0u32.into(), b"single-link bridge test complete");
        server_endpoint.close(0u32.into(), b"single-link bridge test complete");
        supervisor
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        let dispatcher_result = join_task(dispatcher, "single-link physical dispatcher").await;
        assert!(dispatcher_result.is_ok(), "{dispatcher_result:?}");
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod dns_resolution_tests {
    use super::*;
    use crate::config::DnsServer;
    use crate::fake_ip::{OverlayDnsRequest, RoutePreference};
    use hickory_proto::{op::Query, rr::Name};

    fn query_wire(id: u16) -> Vec<u8> {
        let mut query = hickory_proto::op::Message::query();
        query.metadata.id = id;
        query.queries.push(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        query.to_vec().unwrap()
    }

    fn make_request(
        upstreams: Vec<DnsServer>,
    ) -> (
        OverlayDnsRequest,
        oneshot::Receiver<Result<crate::fake_ip::OverlayDnsResponse, String>>,
    ) {
        let (response, receiver) = oneshot::channel();
        (
            OverlayDnsRequest {
                domain: "example.test".into(),
                wire: query_wire(7),
                upstreams,
                response,
            },
            receiver,
        )
    }

    #[test]
    fn dns_response_success_accepts_noerror_and_nxdomain_only() {
        for code in [
            hickory_proto::op::ResponseCode::NoError,
            hickory_proto::op::ResponseCode::NXDomain,
        ] {
            let message =
                hickory_proto::op::Message::error_msg(1, hickory_proto::op::OpCode::Query, code);
            assert!(dns_response_is_success(&message.to_vec().unwrap()));
        }
        let failure = hickory_proto::op::Message::error_msg(
            1,
            hickory_proto::op::OpCode::Query,
            hickory_proto::op::ResponseCode::ServFail,
        );
        assert!(!dns_response_is_success(&failure.to_vec().unwrap()));
        assert!(!dns_response_is_success(&[1, 2, 3]));
    }

    #[tokio::test]
    async fn overlay_dns_uses_direct_fallback_and_reports_empty_candidates() {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
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
        let routes = Arc::new(RwLock::new(Arc::new(RouteSnapshot::new(
            Vec::new(),
            Vec::new(),
        ))));
        let (request, response) = make_request(vec![DnsServer::from_socket_addr(address)]);
        resolve_overlay_dns(
            request,
            routes.clone(),
            CircuitDnsClient::default(),
            CircuitOpenManager::default(),
            true,
        )
        .await;
        let response = response.await.unwrap().unwrap();
        assert_eq!(response.preferred_route, RoutePreference::Direct);
        upstream_task.await.unwrap();

        let (request, response) = make_request(Vec::new());
        resolve_overlay_dns(
            request,
            routes,
            CircuitDnsClient::default(),
            CircuitOpenManager::default(),
            false,
        )
        .await;
        let result = response.await.unwrap();
        assert!(matches!(
            result,
            Err(reason) if reason == "no healthy domain route candidate"
        ));
    }

    #[tokio::test]
    async fn overlay_dns_reports_unsuccessful_direct_responses() {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (size, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            let query = hickory_proto::op::Message::from_vec(&buffer[..size]).unwrap();
            let mut response =
                hickory_proto::op::Message::response(query.metadata.id, query.metadata.op_code);
            response.queries = query.queries;
            response.metadata.response_code = hickory_proto::op::ResponseCode::ServFail;
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.test\n").unwrap();
        let routes = Arc::new(RwLock::new(Arc::new(
            RouteSnapshot::new_with_domains(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Arc::new(loader.finish()),
            )
            .with_direct_routes(Vec::new(), vec![(set_id, 100)]),
        )));
        let (request, response) = make_request(vec![DnsServer::from_socket_addr(address)]);
        resolve_overlay_dns(
            request,
            routes,
            CircuitDnsClient::default(),
            CircuitOpenManager::default(),
            false,
        )
        .await;
        let result = match response.await.unwrap() {
            Ok(_) => panic!("SERVFAIL must fail the overlay DNS request"),
            Err(reason) => reason,
        };
        assert!(result.contains("unsuccessful DNS response"));
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn overlay_dns_reports_direct_upstream_failures() {
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.test\n").unwrap();
        let routes = Arc::new(RwLock::new(Arc::new(
            RouteSnapshot::new_with_domains(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Arc::new(loader.finish()),
            )
            .with_direct_routes(Vec::new(), vec![(set_id, 100)]),
        )));
        // Nothing listens on this port: the connected UDP socket fails the
        // exchange immediately (or, at worst, at the two-second upstream
        // timeout), which must surface as a direct-upstream failure.
        let (request, response) = make_request(vec![DnsServer::from_socket_addr(
            "127.0.0.1:1".parse().unwrap(),
        )]);
        resolve_overlay_dns(
            request,
            routes,
            CircuitDnsClient::default(),
            CircuitOpenManager::default(),
            false,
        )
        .await;
        let result = match response.await.unwrap() {
            Ok(_) => panic!("an unreachable direct upstream must fail the overlay DNS request"),
            Err(reason) => reason,
        };
        assert!(result.contains("via local direct failed"));
    }

    #[tokio::test]
    async fn overlay_dns_direct_candidate_succeeds_and_missing_candidates_request_ensure() {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
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
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.test\n").unwrap();
        // A direct route candidate is tried before falling back, and its
        // success is reported with the Direct preference.
        let routes = Arc::new(RwLock::new(Arc::new(
            RouteSnapshot::new_with_domains(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Arc::new(loader.finish()),
            )
            .with_direct_routes(Vec::new(), vec![(set_id, 100)]),
        )));
        let (request, response) = make_request(vec![DnsServer::from_socket_addr(address)]);
        resolve_overlay_dns(
            request,
            routes,
            CircuitDnsClient::default(),
            CircuitOpenManager::default(),
            false,
        )
        .await;
        let response = response.await.unwrap().unwrap();
        assert_eq!(response.preferred_route, RoutePreference::Direct);
        upstream_task.await.unwrap();

        // Domain imports without matching bindings leave no candidates, so
        // the resolver requests circuit admission for every import node.
        let mut loader = crate::route_sets::RouteSetLoader::new(".");
        let set_id = loader.load_inline("example.test\n").unwrap();
        let routes = Arc::new(RwLock::new(Arc::new(RouteSnapshot::new_with_domains(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![crate::config::DomainRouteImport {
                set_id,
                candidates: vec![crate::config::RouteCandidate {
                    node: "exit".into(),
                    priority: 100,
                }],
            }],
            Arc::new(loader.finish()),
        ))));
        let opens = CircuitOpenManager::default();
        let (request, response) = make_request(Vec::new());
        resolve_overlay_dns(
            request,
            routes,
            CircuitDnsClient::default(),
            opens.clone(),
            false,
        )
        .await;
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                opens.wait_for_ensure_requests()
            )
            .await
            .unwrap(),
            vec!["exit"]
        );
        let result = response.await.unwrap();
        assert!(matches!(
            result,
            Err(reason) if reason == "no healthy domain route candidate"
        ));
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod router_lifecycle_tests {
    use super::*;

    #[tokio::test]
    async fn empty_route_snapshots_can_be_replaced_and_shutdown_is_idempotent() {
        let (receiver_tx, mut receiver_rx) = mpsc::unbounded_channel();
        let router = TunRouter {
            routes: Arc::new(RwLock::new(Arc::new(RouteSnapshot::new(
                Vec::new(),
                Vec::new(),
            )))),
            receiver_tx,
            cancellation: CancellationToken::new(),
            sessions: SessionManager::default(),
        };

        router
            .replace_routes(RouteSnapshot::new(Vec::new(), Vec::new()))
            .await;
        assert!(receiver_rx.try_recv().is_err());

        router.shutdown().await;
        router.shutdown().await;
        assert!(router.cancellation.is_cancelled());
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "dataplane_tests.rs"]
#[cfg_attr(coverage_nightly, coverage(off))]
mod integration_tests;
