//! Control-plane message helpers shared by the worker and by tests.
//!
//! The per-Link worker stays in the parent module; this file holds the
//! topology-assist, admission, send and lookup helpers.

use super::*;
pub(crate) fn merge_topology_snapshot_request(has_active_snapshot: bool) -> bool {
    has_active_snapshot
}

pub(crate) fn remember_superseded_snapshot(superseded: &mut VecDeque<u64>, sync_id: u64) {
    if superseded.contains(&sync_id) {
        return;
    }
    if superseded.len() == RECENT_SUPERSEDED_TOPOLOGY_SNAPSHOTS {
        superseded.pop_front();
    }
    superseded.push_back(sync_id);
}

pub(crate) fn discard_snapshot_assemblies(
    snapshots: &mut HashMap<u64, SnapshotAssembly>,
    superseded: &mut VecDeque<u64>,
) {
    for sync_id in snapshots.keys().copied().collect::<Vec<_>>() {
        remember_superseded_snapshot(superseded, sync_id);
    }
    snapshots.clear();
}

pub(crate) fn retain_current_snapshot_assembly(
    snapshots: &mut HashMap<u64, SnapshotAssembly>,
    superseded: &mut VecDeque<u64>,
    sync_id: u64,
) {
    for candidate_sync_id in snapshots
        .keys()
        .copied()
        .filter(|candidate_sync_id| *candidate_sync_id != sync_id)
        .collect::<Vec<_>>()
    {
        remember_superseded_snapshot(superseded, candidate_sync_id);
    }
    snapshots.retain(|candidate_sync_id, _| *candidate_sync_id == sync_id);
}

pub(crate) fn invalidate_topology_receive(
    topology_sync: &mut TopologySyncState,
    snapshots: &mut HashMap<u64, SnapshotAssembly>,
    superseded: &mut VecDeque<u64>,
    sync_id: Option<u64>,
) {
    discard_snapshot_assemblies(snapshots, superseded);
    if let Some(sync_id) = sync_id {
        remember_superseded_snapshot(superseded, sync_id);
    }
    topology_sync.invalidate_rx();
}

pub(crate) fn next_snapshot_reassembly_deadline(
    snapshots: &HashMap<u64, SnapshotAssembly>,
) -> Option<Instant> {
    snapshots
        .values()
        .filter_map(|assembly| {
            assembly
                .started
                .checked_add(topology_snapshot_reassembly_timeout())
        })
        .min()
}

pub(crate) async fn prune_expired_topology_snapshots(
    link: &carrier::Link,
    snapshots: &mut HashMap<u64, SnapshotAssembly>,
    superseded: &mut VecDeque<u64>,
    last_snapshot_request: &mut Option<Instant>,
) -> bool {
    let expired = prune_expired_snapshot_assemblies(snapshots, superseded);
    if expired {
        request_topology_snapshot_recovery(link, last_snapshot_request, 7).await;
    }
    expired
}

pub(crate) fn prune_expired_snapshot_assemblies(
    snapshots: &mut HashMap<u64, SnapshotAssembly>,
    superseded: &mut VecDeque<u64>,
) -> bool {
    let now = Instant::now();
    let expired = snapshots
        .iter()
        .filter_map(|(sync_id, assembly)| {
            (!assembly
                .started
                .checked_add(topology_snapshot_reassembly_timeout())
                .is_some_and(|deadline| deadline > now))
            .then_some(*sync_id)
        })
        .collect::<Vec<_>>();
    for sync_id in &expired {
        remember_superseded_snapshot(superseded, *sync_id);
        snapshots.remove(sync_id);
    }
    !expired.is_empty()
}

pub(crate) async fn notify_broken(
    links: &LinkRegistry,
    identity: &ed25519_dalek::SigningKey,
    broken: Vec<(u64, tinect::circuit::CircuitId)>,
) {
    for (incoming, circuit_id) in broken {
        // Do not keep the registry read lock while waiting for QUIC stream
        // admission.  A saturated control stream must not block link
        // replacement/cleanup, and a single failed notification must not
        // strand the remaining circuits behind it.
        let link = registered_link_by_instance(links, incoming);
        let Some(link) = link else { continue };
        let message = ControlMessage::circuit_broken(
            identity,
            circuit_id,
            tinect::control::CIRCUIT_BROKEN_REASON_LINK_CLOSED,
        );
        const ATTEMPTS: usize = 3;
        for attempt in 0..ATTEMPTS {
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                link.send_control(&message),
            )
            .await;
            match result {
                Ok(Ok(())) => break,
                Ok(Err(carrier::CarrierError::AdmissionRejected)) if attempt + 1 < ATTEMPTS => {
                    tokio::time::sleep(std::time::Duration::from_millis(20 * (attempt as u64 + 1)))
                        .await;
                }
                Ok(Err(error)) => {
                    tracing::debug!(
                        peer_name = %link.peer,
                        peer_identity = %link.peer_identity,
                        ?circuit_id,
                        error = %error,
                        "circuit-broken notification could not be delivered"
                    );
                    break;
                }
                Err(_) if attempt + 1 < ATTEMPTS => {
                    tokio::time::sleep(std::time::Duration::from_millis(20 * (attempt as u64 + 1)))
                        .await;
                }
                Err(_) => {
                    tracing::debug!(
                        peer_name = %link.peer,
                        peer_identity = %link.peer_identity,
                        ?circuit_id,
                        "circuit-broken notification timed out"
                    );
                }
            }
        }
    }
}

pub(crate) fn registered_link_by_instance(
    links: &LinkRegistry,
    instance: u64,
) -> Option<Arc<carrier::Link>> {
    links
        .lock()
        .expect("link registry lock")
        .values()
        .find(|link| link.instance() == instance)
        .cloned()
}

pub(crate) const OPEN_REJECT_REASON_GENERIC: u16 = 1;
pub(crate) const OPEN_REJECT_REASON_MISSING_NEXT_HOP: u16 = 7;
pub(crate) const OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION: u16 = 11;
pub(crate) const OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION_TEXT: &str = "code:11";

pub(crate) fn is_local_control_admission(error: &carrier::CarrierError) -> bool {
    matches!(
        error,
        carrier::CarrierError::AdmissionRejected | carrier::CarrierError::ControlStreamTimeout
    )
}

pub(crate) fn is_local_control_admission_rejection(retryable: bool, reason: &str) -> bool {
    retryable && reason == OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION_TEXT
}

pub(crate) async fn send_open_reject(
    link: &dyn LinkHandle,
    identity: &ed25519_dalek::SigningKey,
    circuit_id: tinect::circuit::CircuitId,
    retryable: bool,
    reason_code: u16,
) {
    let message = ControlMessage::open_reject(identity, circuit_id, retryable, reason_code);
    if let Err(error) = send_control_with_admission_retry(link, &message).await {
        tracing::debug!(
            peer_name = %link.peer_name(),
            ?circuit_id,
            error = %error,
            "retryable circuit OPEN rejection could not be delivered"
        );
    }
}

pub(crate) async fn send_retryable_open_reject(
    link: &dyn LinkHandle,
    identity: &ed25519_dalek::SigningKey,
    circuit_id: tinect::circuit::CircuitId,
) {
    send_open_reject(
        link,
        identity,
        circuit_id,
        true,
        OPEN_REJECT_REASON_MISSING_NEXT_HOP,
    )
    .await;
}

pub(crate) const CONTROL_ADMISSION_RETRY_ATTEMPTS: usize = 3;

pub(crate) async fn send_control_with_admission_retry(
    link: &dyn LinkHandle,
    message: &ControlMessage,
) -> Result<(), carrier::CarrierError> {
    for attempt in 0..CONTROL_ADMISSION_RETRY_ATTEMPTS {
        match link
            .send_control(message)
            .await
            .map_err(carrier::CarrierError::from)
        {
            Ok(()) => return Ok(()),
            Err(error)
                if is_local_control_admission(&error)
                    && attempt + 1 < CONTROL_ADMISSION_RETRY_ATTEMPTS =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1)))
                    .await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("control admission retry loop always returns on its final attempt")
}

/// Wait for the first authenticated Link without repeatedly scanning the
/// registry. Link registration notifies `CircuitOpenManager`, which is also
/// the lifecycle source used by circuit reconciliation.
pub(crate) async fn wait_for_any_link(
    links: &LinkRegistry,
    opens: &dataplane::CircuitOpenManager,
    timeout: std::time::Duration,
) -> Option<Arc<carrier::Link>> {
    let deadline = Instant::now() + timeout;
    loop {
        // Observe the generation before inspecting the registry. If a Link
        // registers concurrently, either this read sees it or the subsequent
        // waiter sees the changed generation; neither outcome loses wakeup.
        let generation = opens.active_generation();
        if let Some(link) = links
            .lock()
            .expect("link registry lock")
            .values()
            .next()
            .cloned()
        {
            return Some(link);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => return None,
            _ = opens.wait_active_change(generation) => {}
        }
    }
}
