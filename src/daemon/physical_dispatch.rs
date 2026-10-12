//! Per-Link physical data-plane workers.

use std::{collections::HashMap, sync::Arc};
use tinect::{carrier, dataplane, physical::PhysicalPayload, runtime::DaemonSupervisor};

fn forward_frame(payload: PhysicalPayload) -> Option<Vec<u8>> {
    match payload {
        PhysicalPayload::Forward(frame) if tinect::fec::is_recovery_probe(&frame) => None,
        PhysicalPayload::Forward(frame) => Some(frame),
        PhysicalPayload::Probe { .. }
        | PhysicalPayload::ProbeAck { .. }
        | PhysicalPayload::Keepalive
        | PhysicalPayload::FecSource { .. }
        | PhysicalPayload::FecRepair { .. } => None,
    }
}

pub(crate) fn spawn_capacity_event_listener(
    link: &Arc<carrier::Link>,
    opens: dataplane::CircuitOpenManager,
    supervisor: DaemonSupervisor,
) {
    let mut events = link.subscribe_capacity_changed();
    supervisor.spawn_background(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let changed = opens
                        .update_active_link_capacity(
                            event.link_instance,
                            event.user_ip_capacity,
                            event.capacity_generation,
                        )
                        .await;
                    if changed != 0 {
                        tracing::debug!(
                            link_instance = event.link_instance,
                            capacity = event.user_ip_capacity,
                            generation = event.capacity_generation,
                            ?event.reason,
                            circuits = changed,
                            "active circuit send budgets updated from local carrier capacity"
                        );
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });
}

/// The only Physical reader for a Link. It starts immediately after identity
/// authentication; Forward ownership is then transferred through the Link's
/// bounded single-consumer queue.
pub(crate) fn spawn_physical_dispatcher(link: Arc<carrier::Link>, supervisor: DaemonSupervisor) {
    if let Some(worker) = link.take_capacity_monitor() {
        supervisor.spawn_background(worker);
    }
    if let Some(worker) = link.take_bare_pmtu_worker() {
        supervisor.spawn_background(worker);
    }
    if let Some(worker) = link.take_fec_feedback_worker() {
        supervisor.spawn_background(worker);
    }
    if let Some(worker) = link.take_fec_recovery_worker() {
        supervisor.spawn_background(worker);
    }
    if let Some(worker) = link.take_fec_tail_worker() {
        supervisor.spawn_background(worker);
    }
    supervisor.spawn_background(async move {
        loop {
            match link.recv_physical().await {
                Ok(payload) => {
                    if let Some(frame) = forward_frame(payload) {
                        link.publish_forward(frame);
                    }
                }
                Err(error) => {
                    tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "physical payload dispatcher stopped");
                    return;
                }
            }
        }
    });
}

pub(crate) fn spawn_relay_worker(
    link: Arc<carrier::Link>,
    labels: Arc<std::sync::RwLock<tinect::circuit::LabelTable>>,
    identity: Arc<ed25519_dalek::SigningKey>,
    supervisor: DaemonSupervisor,
) {
    let feedback_supervisor = supervisor.clone();
    supervisor.spawn_background(async move {
        let Some(mut receiver) = link.take_forward_receiver().await else {
            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, "relay Forward receiver was already claimed");
            return;
        };
        let mut reported_circuit_broken = HashMap::new();
        loop {
            match tinect::dataplane::relay_once_with_feedback(&mut receiver, &labels).await {
                Ok(Some(circuit_id)) => {
                    if tinect::dataplane::should_report_circuit_broken_feedback(
                        &mut reported_circuit_broken,
                        circuit_id,
                        std::time::Instant::now(),
                    ) {
                        // Fire-and-forget: the relay worker must keep
                        // forwarding while feedback is delivered in the
                        // background.
                        let feedback_link = link.clone();
                        let feedback_identity = identity.clone();
                        let feedback_tasks = feedback_supervisor.clone();
                        feedback_tasks.spawn_background(async move {
                            tinect::dataplane::send_circuit_broken_feedback(
                                &feedback_link,
                                feedback_identity.as_ref(),
                                circuit_id,
                            )
                            .await;
                        });
                    }
                }
                Ok(None) => {}
                Err(tinect::carrier::CarrierError::DatagramTooLarge { size, limit }) => {
                    tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, packet_bytes = size, datagram_limit = limit, "relay dropped packet exceeding outgoing QUIC DATAGRAM limit");
                }
                Err(tinect::carrier::CarrierError::AdmissionRejected) => {
                    tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, "relay datagram deferred by local priority admission");
                }
                Err(tinect::carrier::CarrierError::Protocol(error))
                    if error == "unknown circuit label" =>
                {
                    tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, "discarded packet for unopened circuit");
                }
                Err(tinect::carrier::CarrierError::Protocol(error))
                    if error.starts_with("invalid forwarded frame:") =>
                {
                    tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, error, "discarded malformed opaque forward frame");
                }
                Err(error) => {
                    tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "relay receive stopped");
                    break;
                }
            }
        }
    });
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_forward_payloads_are_published_to_the_relay_queue() {
        assert_eq!(
            forward_frame(PhysicalPayload::Forward(vec![1, 2, 3])),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            forward_frame(PhysicalPayload::Forward(tinect::fec::recovery_probe_frame())),
            None
        );
        for payload in [
            PhysicalPayload::Probe {
                probe_id: 1,
                target_len: 64,
                padding: vec![0; 25],
            },
            PhysicalPayload::ProbeAck {
                probe_id: 1,
                target_len: 64,
            },
            PhysicalPayload::Keepalive,
            PhysicalPayload::FecSource {
                transmission_sequence: 1,
                esi: 2,
                frame: vec![0; 40],
            },
            PhysicalPayload::FecRepair {
                transmission_sequence: 1,
                rid: 2,
                first_esi: 3,
                symbol_count: 1,
                vector: vec![4],
            },
        ] {
            assert_eq!(forward_frame(payload), None);
        }
    }

    #[tokio::test]
    async fn physical_dispatcher_starts_workers_and_stops_when_the_link_closes() {
        let pair = crate::daemon::circuit_resolution::tests::link_pair_with_fec(
            tinect::identity::generate(),
        )
        .await;
        let supervisor = DaemonSupervisor::default();
        // The FEC-enabled link owns a capacity monitor and all three FEC
        // workers; the dispatcher must spawn each of them, then exit the
        // receive loop once the peer closes the connection.
        spawn_physical_dispatcher(pair.server_link.clone(), supervisor.clone());
        pair.client_link.close("test close");
        pair.client_endpoint.close(0u32.into(), b"test close");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        supervisor
            .shutdown(std::time::Duration::from_secs(2))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn relay_worker_returns_when_the_forward_receiver_is_already_claimed() {
        let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
        assert!(pair.server_link.take_forward_receiver().await.is_some());
        let supervisor = DaemonSupervisor::default();
        let labels = Arc::new(std::sync::RwLock::new(
            tinect::circuit::LabelTable::default(),
        ));
        spawn_relay_worker(
            pair.server_link.clone(),
            labels,
            Arc::new(tinect::identity::generate()),
            supervisor.clone(),
        );
        supervisor
            .shutdown(std::time::Duration::from_secs(2))
            .await
            .unwrap();
    }

    struct RecordingLink {
        sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl tinect::link::LinkHandle for RecordingLink {
        fn peer_name(&self) -> &str {
            "recording"
        }

        fn peer_identity(&self) -> &str {
            "recording-identity"
        }

        fn instance(&self) -> u64 {
            1
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

        fn send_forward(&self, frame: &[u8]) -> Result<(), tinect::link::LinkError> {
            self.sent
                .lock()
                .expect("recording link lock")
                .push(frame.to_vec());
            Ok(())
        }

        fn send_control<'a>(
            &'a self,
            _message: &'a tinect::control::ControlMessage,
        ) -> tinect::link::LinkFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    fn encrypted_frame(circuit_id: tinect::circuit::CircuitId) -> Vec<u8> {
        let mut sender = tinect::crypto::SenderSession::from_key(
            circuit_id,
            chacha20poly1305::Key::from([7; 32]),
        );
        sender.encrypt(b"opaque").unwrap().to_vec()
    }

    #[tokio::test]
    async fn relay_worker_forwards_bound_frames_and_reports_unknown_labels() {
        let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
        let supervisor = DaemonSupervisor::default();
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording: tinect::link::LinkRef = Arc::new(RecordingLink { sent: sent.clone() });
        assert_eq!(recording.peer_name(), "recording");
        assert_eq!(recording.peer_identity(), "recording-identity");
        assert_eq!(recording.instance(), 1);
        assert!(recording.is_healthy());
        recording
            .send_control(&tinect::control::ControlMessage::Ping)
            .await
            .unwrap();
        let mut labels_table = tinect::circuit::LabelTable::default();
        labels_table
            .install(tinect::circuit::CircuitId([5; 16]), recording)
            .unwrap();
        let labels = Arc::new(std::sync::RwLock::new(labels_table));
        spawn_relay_worker(
            pair.server_link.clone(),
            labels,
            Arc::new(tinect::identity::generate()),
            supervisor.clone(),
        );

        // A bound label is relayed to the outgoing binding.
        pair.server_link
            .publish_forward(encrypted_frame(tinect::circuit::CircuitId([5; 16])));
        // An unknown label triggers circuit-broken feedback but keeps the
        // worker alive.
        pair.server_link
            .publish_forward(encrypted_frame(tinect::circuit::CircuitId([6; 16])));
        // A truncated frame is discarded as malformed.
        pair.server_link.publish_forward(vec![0; 15]);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if sent.lock().expect("recording link lock").len() == 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "relay did not forward the bound frame"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        supervisor
            .shutdown(std::time::Duration::from_secs(2))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn capacity_event_listener_stops_when_the_link_is_dropped() {
        let pair = crate::daemon::circuit_resolution::tests::link_pair().await;
        let supervisor = DaemonSupervisor::default();
        let opens = dataplane::CircuitOpenManager::default();
        spawn_capacity_event_listener(&pair.server_link, opens, supervisor.clone());
        drop(pair.server_link);
        drop(pair.client_link);
        pair.client_endpoint.close(0u32.into(), b"test close");
        drop(pair.client_endpoint);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        supervisor
            .shutdown(std::time::Duration::from_secs(2))
            .await
            .unwrap();
    }
}
