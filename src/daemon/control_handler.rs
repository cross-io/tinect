//! Control-stream context, topology synchronization, and Circuit dispatch.
//!
//! This module owns the per-Link control worker. Protocol helpers shared with
//! Circuit reconciliation are imported through the daemon boundary, while wire
//! formats remain defined by `control`.

use super::physical_dispatch::{
    spawn_capacity_event_listener, spawn_physical_dispatcher, spawn_relay_worker,
};
use super::support::{
    MAX_TOPOLOGY_SNAPSHOT_BYTES, MAX_TOPOLOGY_SNAPSHOT_CHUNKS, MAX_TOPOLOGY_SNAPSHOT_LSAS,
    MAX_TOPOLOGY_SNAPSHOT_NEIGHBORS, MAX_TOPOLOGY_SNAPSHOT_RECOVERY_ATTEMPTS,
    RECENT_COMPLETED_TOPOLOGY_SNAPSHOTS, RECENT_SUPERSEDED_TOPOLOGY_SNAPSHOTS, mark_current_link,
    mark_link, topology_snapshot_ack_timeout, topology_snapshot_reassembly_timeout,
};
use super::topology_sync::*;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Instant,
};
use tinect::link::LinkHandle;
use tinect::{
    carrier,
    circuit::Router,
    control::ControlMessage,
    dataplane, identity,
    runtime::{DaemonSupervisor, LinkRegistry, Runtime},
};

#[derive(Clone)]
pub(crate) struct ControlHandlerContext {
    pub(crate) router: Arc<Router>,
    pub(crate) runtime: Runtime,
    pub(crate) identity: Arc<ed25519_dalek::SigningKey>,
    pub(crate) supervisor: DaemonSupervisor,
}

pub(crate) fn spawn_control_handler(link: Arc<carrier::Link>, context: ControlHandlerContext) {
    let ControlHandlerContext {
        router,
        runtime,
        identity,
        supervisor,
    } = context;
    let topology = runtime.topology;
    let links = runtime.links;
    let state = runtime.state;
    let control_plane = runtime.circuits;
    spawn_physical_dispatcher(link.clone(), supervisor.clone());
    spawn_capacity_event_listener(&link, control_plane.opens.clone(), supervisor.clone());
    let labels = router.relay_labels_for(link.instance());
    let relay_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let relay_input = link.clone();
    if !router.has_secure_dataplane()
        && relay_started
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    {
        spawn_relay_worker(
            relay_input.clone(),
            labels.clone(),
            identity.clone(),
            supervisor.clone(),
        );
    }
    supervisor.clone().spawn_background(async move {
        let mut topology_sync = TopologySyncState::new();
        let mut snapshots: HashMap<u64, SnapshotAssembly> = HashMap::new();
        let mut completed_snapshots = VecDeque::with_capacity(RECENT_COMPLETED_TOPOLOGY_SNAPSHOTS);
        let mut superseded_snapshots =
            VecDeque::with_capacity(RECENT_SUPERSEDED_TOPOLOGY_SNAPSHOTS);
        let mut last_snapshot_request = None;
        let mut recovery_attempts = 0u8;
        topology_sync.begin_sending();
        let mut pending_snapshot = match send_current_topology_snapshot(link.as_ref(), &topology)
            .await
        {
            Ok(sync_id) => {
                recovery_attempts = 1;
                topology_sync.begin_snapshot(sync_id);
                Some(PendingSnapshot {
                    sync_id,
                    deadline: Instant::now() + topology_snapshot_ack_timeout(),
                })
            }
            Err(error) => {
                tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "initial reliable topology snapshot send failed");
                link.close("topology snapshot initial send failed");
                None
            }
        };
        loop {
            if pending_snapshot.is_none() && topology_sync.ready() && link.topology_ready() {
                let deltas = link.take_topology_deltas().await;
                if !deltas.is_empty() {
                    if let Err(error) = send_topology_delta(link.as_ref(), deltas).await {
                        tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "reliable topology Delta flush failed");
                        link.mark_topology_unsynchronized();
                        link.close("reliable topology Delta flush failed");
                        break;
                    }
                    continue;
                }
            }
            let reassembly_deadline = next_snapshot_reassembly_deadline(&snapshots);
            let message = if let Some(pending) = pending_snapshot.as_ref() {
                let reassembly_expires_first = reassembly_deadline
                    .is_some_and(|deadline| deadline < pending.deadline);
                let deadline = reassembly_deadline
                    .filter(|deadline| *deadline < pending.deadline)
                    .unwrap_or(pending.deadline);
                let received = tokio::select! {
                    result = tokio::time::timeout_at(
                        tokio::time::Instant::from_std(deadline),
                        link.recv_control(),
                    ) => Some(result),
                };
                let Some(received) = received else {
                    continue;
                };
                match received {
                    Ok(Ok(message)) => message,
                    Ok(Err(error)) => {
                        let reason = link.close_reason();
                        tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, close_reason = ?reason, "control stream closed");
                        break;
                    }
                    Err(_) if reassembly_expires_first => {
                        if prune_expired_topology_snapshots(
                            link.as_ref(),
                            &mut snapshots,
                            &mut superseded_snapshots,
                            &mut last_snapshot_request,
                        )
                        .await {
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                None,
                            );
                        }
                        continue;
                    }
                    Err(_) => {
                        topology_sync.invalidate_tx();
                        link.mark_topology_outbound_unsynchronized();
                        if recovery_attempts >= MAX_TOPOLOGY_SNAPSHOT_RECOVERY_ATTEMPTS {
                            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, link_instance = link.instance(), sync_id = pending_snapshot.as_ref().map(|pending| pending.sync_id), "topology snapshot recovery budget exhausted");
                            link.close("topology_sync_recovery_budget_exhausted");
                            break;
                        }
                        link.clear_topology_deltas().await;
                        topology_sync.begin_sending();
                        pending_snapshot = match send_current_topology_snapshot(
                            link.as_ref(),
                            &topology,
                        )
                        .await
                        {
                            Ok(sync_id) => {
                                recovery_attempts = recovery_attempts.saturating_add(1);
                                topology_sync.begin_snapshot(sync_id);
                                Some(PendingSnapshot {
                                    sync_id,
                                    deadline: Instant::now() + topology_snapshot_ack_timeout(),
                                })
                            }
                            Err(error) => {
                                tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "topology snapshot recovery send failed");
                                link.close("topology snapshot recovery send failed");
                                None
                            }
                        };
                        continue;
                    }
                }
            } else if let Some(deadline) = reassembly_deadline {
                tokio::select! {
                    result = link.recv_control() => match result {
                        Ok(message) => message,
                        Err(error) => {
                            let reason = link.close_reason();
                            tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, close_reason = ?reason, "control stream closed");
                            break;
                        }
                    },
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        if prune_expired_topology_snapshots(
                            link.as_ref(),
                            &mut snapshots,
                            &mut superseded_snapshots,
                            &mut last_snapshot_request,
                        )
                        .await {
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                None,
                            );
                        }
                        continue;
                    }
                }
            } else {
                match link.recv_control().await {
                    Ok(message) => message,
                    Err(error) => {
                        let reason = link.close_reason();
                        tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, close_reason = ?reason, "control stream closed");
                        break;
                    }
                }
            };
            match message {
                ControlMessage::TopologySync {
                    mode,
                    sync_id,
                    chunk_index,
                    chunk_count,
                    advertisements,
                } => match mode {
                    tinect::control::TopologySyncMode::Delta => {
                        // RFC-0016: the peer only flushes Deltas after its own
                        // full readiness, which already implies our inbound
                        // baseline was applied and ACKed. Gate only on the RX
                        // state machine: requiring `link.topology_ready()`
                        // here would additionally demand our own outbound
                        // Snapshot ACK, but that ACK and the peer's Delta
                        // travel on different QUIC uni streams whose arrival
                        // order is not guaranteed, so a legitimate Delta could
                        // spuriously invalidate RX and burn the peer's
                        // recovery budget (RFC-0016 permits Deltas to arrive
                        // and be applied even before the Snapshot completes).
                        if !topology_sync.can_apply_delta() {
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                None,
                            );
                            request_topology_snapshot_recovery(
                                link.as_ref(),
                                &mut last_snapshot_request,
                                8,
                            )
                            .await;
                            continue;
                        }
                        let accepted =
                            dataplane::apply_topology(link.as_ref(), advertisements, &topology)
                                .await;
                        if !accepted.is_empty() {
                            fanout_topology_delta(link.instance(), accepted, &links).await;
                            control_plane.opens.request_reconcile();
                        }
                    }
                    tinect::control::TopologySyncMode::Snapshot => {
                        // A message can win the select at the same instant
                        // as the reassembly deadline. Prune first so an
                        // expired ID is suppressed before its late chunk can
                        // be mistaken for a fresh transfer.
                        if prune_expired_topology_snapshots(
                            link.as_ref(),
                            &mut snapshots,
                            &mut superseded_snapshots,
                            &mut last_snapshot_request,
                        )
                        .await {
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                None,
                            );
                        }
                        if completed_snapshots.contains(&sync_id) {
                            // The sender may be retransmitting because the
                            // first ACK was lost.  Re-ACK an already applied
                            // snapshot instead of silently extending the
                            // sender's recovery loop.
                            if send_topology_snapshot_ack(link.as_ref(), sync_id).await {
                                let restored_rx =
                                    topology_sync.restore_completed_snapshot(sync_id);
                                if topology_sync.can_apply_delta()
                                    && (link.mark_topology_snapshot_received() || restored_rx)
                                {
                                    // The Link flag may already have been set
                                    // by another duplicate, but the local
                                    // state machine still needs a wakeup after
                                    // recovery moved RX back to Synchronized.
                                    control_plane.opens.request_reconcile();
                                }
                            } else {
                                link.mark_topology_inbound_unsynchronized();
                            }
                            continue;
                        }
                        if superseded_snapshots.contains(&sync_id) {
                            // A late chunk from a transfer that was
                            // superseded by a newer Snapshot must not reset
                            // the newer RX assembly.
                            tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, sync_id, "ignored superseded reliable topology snapshot chunk");
                            continue;
                        }
                        if topology_sync.is_stale_snapshot(sync_id) {
                            // The completed-ID window is intentionally
                            // bounded. Once an old completed ID falls out of
                            // that window, the receive watermark still keeps
                            // its delayed chunks from being accepted as a
                            // fresh Snapshot. Check this before replacing a
                            // newer in-flight assembly.
                            tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, sync_id, "ignored stale reliable topology snapshot chunk");
                            continue;
                        }
                        let replaces_snapshot = matches!(
                            topology_sync.rx,
                            TopologyRxState::Assembling { sync_id: current }
                                if current != sync_id
                        );
                        if replaces_snapshot {
                            // A newer transfer takes over the single RX
                            // assembly slot immediately. The current chunk
                            // is valid input for the replacement and must not
                            // be dropped while asking for another recovery.
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                None,
                            );
                        }
                        if !topology_sync.begin_receive(sync_id) {
                            // Applying is synchronous from this handler's
                            // perspective, so this is only a defensive
                            // recovery path for an impossible state.
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                Some(sync_id),
                            );
                            request_topology_snapshot_recovery(
                                link.as_ref(),
                                &mut last_snapshot_request,
                                9,
                            )
                            .await;
                            continue;
                        }
                        // RX can have been invalidated while an older
                        // assembly was still retained (for example after a
                        // recovery request). Once this sync_id is accepted,
                        // only its assembly may remain eligible for a later
                        // timeout.
                        retain_current_snapshot_assembly(
                            &mut snapshots,
                            &mut superseded_snapshots,
                            sync_id,
                        );
                        let count = usize::from(chunk_count);
                        let index = usize::from(chunk_index);
                        if count == 0 || count > MAX_TOPOLOGY_SNAPSHOT_CHUNKS || index >= count {
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                Some(sync_id),
                            );
                            request_topology_snapshot_recovery(
                                link.as_ref(),
                                &mut last_snapshot_request,
                                1,
                            )
                            .await;
                            continue;
                        }
                        let (chunk_bytes, chunk_neighbors) = match topology_sync_chunk_bytes(
                            &advertisements,
                        ) {
                            Ok(accounting) => accounting,
                            Err(error) => {
                                tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "topology snapshot accounting failed");
                                invalidate_topology_receive(
                                    &mut topology_sync,
                                    &mut snapshots,
                                    &mut superseded_snapshots,
                                    Some(sync_id),
                                );
                                request_topology_snapshot_recovery(
                                    link.as_ref(),
                                    &mut last_snapshot_request,
                                    4,
                                )
                                .await;
                                continue;
                            }
                        };
                        // `retain_current_snapshot_assembly` above keeps at
                        // most the current transfer, so this snapshot is the
                        // single in-flight RX assembly by construction.
                        let total_bytes = snapshots
                            .values()
                            .map(|assembly| assembly.bytes)
                            .sum::<usize>()
                            .saturating_add(chunk_bytes);
                        let (entry_count, entry_lsa_count, entry_neighbors, existing_chunk) =
                            snapshots
                                .get(&sync_id)
                                .map(|assembly| {
                                    (
                                        assembly.chunks.len(),
                                        assembly.lsa_count,
                                        assembly.neighbors,
                                        assembly.chunks.get(index).and_then(Option::as_ref),
                                    )
                                })
                                .unwrap_or((count, 0, 0, None));
                        if entry_count != count {
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                Some(sync_id),
                            );
                            request_topology_snapshot_recovery(
                                link.as_ref(),
                                &mut last_snapshot_request,
                                2,
                            )
                                .await;
                            continue;
                        }
                        if let Some(existing_chunk) = existing_chunk {
                            // A duplicate identical chunk is harmless and
                            // must not consume the bounded assembly budget a
                            // second time.  A conflicting duplicate indicates
                            // a malformed/replayed transfer and restarts
                            // recovery for this snapshot.
                            if existing_chunk == &advertisements {
                                continue;
                            }
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                Some(sync_id),
                            );
                            request_topology_snapshot_recovery(
                                link.as_ref(),
                                &mut last_snapshot_request,
                                2,
                            )
                            .await;
                            continue;
                        }
                        if total_bytes > MAX_TOPOLOGY_SNAPSHOT_BYTES
                            || entry_lsa_count.saturating_add(advertisements.len())
                                > MAX_TOPOLOGY_SNAPSHOT_LSAS
                            || entry_neighbors.saturating_add(chunk_neighbors)
                                > MAX_TOPOLOGY_SNAPSHOT_NEIGHBORS
                        {
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                Some(sync_id),
                            );
                            request_topology_snapshot_recovery(
                                link.as_ref(),
                                &mut last_snapshot_request,
                                6,
                            )
                            .await;
                            continue;
                        }
                        let entry = snapshots
                            .entry(sync_id)
                            .or_insert_with(|| SnapshotAssembly {
                                chunks: vec![None; count],
                                bytes: 0,
                                lsa_count: 0,
                                neighbors: 0,
                                started: Instant::now(),
                            });
                        entry.bytes = entry.bytes.saturating_add(chunk_bytes);
                        entry.lsa_count = entry.lsa_count.saturating_add(advertisements.len());
                        entry.neighbors = entry.neighbors.saturating_add(chunk_neighbors);
                        entry.chunks[index] = Some(advertisements);
                        if entry.chunks.iter().any(Option::is_none) {
                            continue;
                        }
                        let complete = snapshots
                            .remove(&sync_id)
                            .expect("existing snapshot")
                            .chunks
                            .into_iter()
                            .flatten()
                            .flatten()
                            .collect::<Vec<_>>();
                        if !topology_sync.begin_apply(sync_id) {
                            invalidate_topology_receive(
                                &mut topology_sync,
                                &mut snapshots,
                                &mut superseded_snapshots,
                                Some(sync_id),
                            );
                            request_topology_snapshot_recovery(
                                link.as_ref(),
                                &mut last_snapshot_request,
                                10,
                            )
                            .await;
                            continue;
                        }
                        match dataplane::apply_topology_snapshot(link.as_ref(), complete, &topology)
                            .await
                        {
                            Ok(accepted) => {
                                topology_sync.applied(sync_id);
                                if completed_snapshots.len() == RECENT_COMPLETED_TOPOLOGY_SNAPSHOTS
                                {
                                    completed_snapshots.pop_front();
                                }
                                completed_snapshots.push_back(sync_id);
                                let became_ready = link.mark_topology_snapshot_received();
                                let topology_changed = !accepted.is_empty();
                                if topology_changed {
                                    fanout_topology_delta(link.instance(), accepted, &links).await;
                                }
                                if became_ready || topology_changed {
                                    control_plane.opens.request_reconcile();
                                }
                                if !send_topology_snapshot_ack(link.as_ref(), sync_id).await {
                                    link.mark_topology_inbound_unsynchronized();
                                } else if !link.topology_ready() && pending_snapshot.is_none() {
                                    // RFC-0016: SnapshotRequired recovery is
                                    // bidirectional. The peer's fresh Snapshot
                                    // just repaired our inbound; if our own
                                    // outbound is still unsynchronized (e.g.
                                    // its Delta outbox overflowed and was
                                    // cleared), re-fix and send our Snapshot
                                    // so the peer can recover toward us too.
                                    if recovery_attempts
                                        >= MAX_TOPOLOGY_SNAPSHOT_RECOVERY_ATTEMPTS
                                    {
                                        tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, "topology snapshot recovery budget exhausted by outbound resend");
                                        link.close("topology_sync_recovery_budget_exhausted");
                                        break;
                                    }
                                    topology_sync.invalidate_tx();
                                    topology_sync.begin_sending();
                                    match send_current_topology_snapshot(link.as_ref(), &topology)
                                        .await
                                    {
                                        Ok(sync_id) => {
                                            recovery_attempts =
                                                recovery_attempts.saturating_add(1);
                                            topology_sync.begin_snapshot(sync_id);
                                            pending_snapshot = Some(PendingSnapshot {
                                                sync_id,
                                                deadline: Instant::now()
                                                    + topology_snapshot_ack_timeout(),
                                            });
                                            tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, sync_id, "outbound topology snapshot resent after inbound recovery");
                                        }
                                        Err(error) => {
                                            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "outbound topology snapshot resend after inbound recovery failed");
                                            link.close("topology snapshot resend after inbound recovery failed");
                                            pending_snapshot = None;
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                invalidate_topology_receive(
                                    &mut topology_sync,
                                    &mut snapshots,
                                    &mut superseded_snapshots,
                                    Some(sync_id),
                                );
                                request_topology_snapshot_recovery(
                                    link.as_ref(),
                                    &mut last_snapshot_request,
                                    3,
                                )
                                .await;
                            }
                        }
                    }
                },
                ControlMessage::TopologySyncAck { sync_id } => {
                    if pending_snapshot
                        .as_ref()
                        .is_some_and(|pending| pending.sync_id == sync_id)
                        && topology_sync.acknowledge(sync_id)
                    {
                        pending_snapshot = None;
                        if link.mark_topology_snapshot_acknowledged() {
                            control_plane.opens.request_reconcile();
                        }
                        tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, sync_id, "reliable topology snapshot acknowledged");
                    } else {
                        tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, sync_id, "ignored stale reliable topology snapshot acknowledgement");
                    }
                }
                ControlMessage::TopologySyncRequest { reason } => {
                    tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, reason, "reliable topology snapshot requested");
                    // The peer requests our outbound Snapshot.  Keep the
                    // already applied inbound Snapshot usable; resetting both
                    // directions can leave the two handlers waiting for each
                    // other's recovery Snapshot.
                    link.mark_topology_outbound_unsynchronized();
                    if merge_topology_snapshot_request(pending_snapshot.is_some()) {
                        // A current Snapshot is already in flight. RFC-0016
                        // requires duplicate Requests to merge rather than
                        // replacing it and resetting its ACK deadline. Keep
                        // Deltas queued after that Snapshot was fixed; they
                        // describe changes not covered by the in-flight
                        // Snapshot and must be flushed after its ACK.
                        continue;
                    }
                    // No Snapshot is active, so the new Snapshot will be
                    // fixed from the current topology. Only Deltas already
                    // represented by that Snapshot may be discarded; changes
                    // queued while it is being generated or sent remain in
                    // the outbox.
                    link.clear_topology_deltas().await;
                    topology_sync.invalidate_tx();
                    if recovery_attempts >= MAX_TOPOLOGY_SNAPSHOT_RECOVERY_ATTEMPTS {
                        tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, "topology snapshot recovery budget exhausted by request");
                        link.close("topology_sync_recovery_budget_exhausted");
                        break;
                    }
                    topology_sync.begin_sending();
                    match send_current_topology_snapshot(link.as_ref(), &topology).await {
                        Ok(sync_id) => {
                            recovery_attempts = recovery_attempts.saturating_add(1);
                            topology_sync.begin_snapshot(sync_id);
                            pending_snapshot = Some(PendingSnapshot {
                                sync_id,
                                deadline: Instant::now() + topology_snapshot_ack_timeout(),
                            });
                        }
                        Err(error) => {
                            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "requested reliable topology snapshot send failed");
                            link.close("topology snapshot recovery send failed");
                            break;
                        }
                    }
                }
                ControlMessage::Open(request) => {
                    let circuit_id = request.circuit_id;
                    match router.handle_open(link.as_ref(), &request).await {
                        Ok(Some(binding)) => {
                            tracing::info!(incoming_peer_name = %link.peer, incoming_peer_identity = %link.peer_identity, outgoing_peer_name = %binding.outgoing.peer_name(), outgoing_peer_identity = %binding.outgoing.peer_identity(), circuit_id = ?binding.circuit_id, "circuit relay installed");
                            let install = {
                                labels
                                    .write()
                                    .expect("relay label lock")
                                    .install(binding.circuit_id, binding.outgoing.clone())
                            };
                            if let Err(error) = install {
                                router
                                    .abort_relay_binding(link.instance(), circuit_id)
                                    .await;
                                tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "circuit relay not installed");
                                state
                                    .read()
                                    .await
                                    .observability
                                    .reject(format!("transit:{error}"));
                                send_retryable_open_reject(
                                    link.as_ref(),
                                    identity.as_ref(),
                                    circuit_id,
                                )
                                .await;
                                continue;
                            }
                            let reverse_labels =
                                router.relay_labels_for(binding.outgoing.instance());
                            let reverse_install = {
                                reverse_labels
                                    .write()
                                    .expect("reverse relay label lock")
                                    .install(binding.circuit_id, link.clone())
                            };
                            if let Err(error) = reverse_install {
                                router
                                    .abort_relay_binding(link.instance(), circuit_id)
                                    .await;
                                tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "reverse circuit relay not installed");
                                send_retryable_open_reject(
                                    link.as_ref(),
                                    identity.as_ref(),
                                    circuit_id,
                                )
                                .await;
                                continue;
                            }
                            let forwarded = match request.forwarded() {
                                Ok(forwarded) => forwarded,
                                Err(error) => {
                                    router
                                        .abort_relay_binding(link.instance(), circuit_id)
                                        .await;
                                    tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit OPEN forwarding rejected");
                                    send_retryable_open_reject(
                                        link.as_ref(),
                                        identity.as_ref(),
                                        circuit_id,
                                    )
                                    .await;
                                    continue;
                                }
                            };
                            let forwarded_message = ControlMessage::Open(forwarded);
                            if let Err(error) = send_control_with_admission_retry(
                                binding.outgoing.as_ref(),
                                &forwarded_message,
                            )
                            .await
                            {
                                router
                                    .abort_relay_binding(link.instance(), circuit_id)
                                    .await;
                                tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit OPEN relay failed");
                                let reason_code = if is_local_control_admission(&error) {
                                    OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION
                                } else {
                                    OPEN_REJECT_REASON_MISSING_NEXT_HOP
                                };
                                send_open_reject(
                                    link.as_ref(),
                                    identity.as_ref(),
                                    circuit_id,
                                    true,
                                    reason_code,
                                )
                                .await;
                                continue;
                            }
                            if !router.has_secure_dataplane()
                                && relay_started
                                    .compare_exchange(
                                        false,
                                        true,
                                        std::sync::atomic::Ordering::AcqRel,
                                        std::sync::atomic::Ordering::Acquire,
                                    )
                                    .is_ok()
                            {
                                spawn_relay_worker(
                                    relay_input.clone(),
                                    labels.clone(),
                                    identity.clone(),
                                    supervisor.clone(),
                                );
                            }
                        }
                        Ok(None) => {
                            let source = match identity::decode_public(&request.public_key) {
                                Ok(source) => source,
                                Err(error) => {
                                    tracing::warn!(%error, "OPEN source key rejected");
                                    continue;
                                }
                            };
                            match tinect::crypto::open_key(
                                identity.as_ref(),
                                &source,
                                circuit_id,
                                request.ephemeral_public_key,
                            ) {
                                Ok(data_key) => {
                                    tracing::info!(incoming_peer_name = %link.peer, incoming_peer_identity = %link.peer_identity, circuit_id = ?circuit_id, "circuit exit authorization installed");
                                    control_plane
                                        .sessions
                                        .install_open(link.instance(), circuit_id, source, data_key)
                                        .await;
                                    control_plane.return_flows.install_circuit(
                                        link.instance(),
                                        circuit_id,
                                        data_key,
                                    );
                                    let acknowledgment = ControlMessage::open_ack(
                                        identity.as_ref(),
                                        circuit_id,
                                    );
                                    if let Err(error) = send_control_with_admission_retry(
                                        link.as_ref(),
                                        &acknowledgment,
                                    )
                                    .await
                                    {
                                        tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit OPEN acknowledgement send failed");
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(circuit_id = ?circuit_id, error = %error, "OPEN key installation rejected")
                                }
                            }
                        }
                        Err(error) => {
                            let retryable =
                                matches!(error, tinect::circuit::RouterError::MissingNextHop(_));
                            tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, error = %error, "circuit OPEN rejected");
                            send_open_reject(
                                link.as_ref(),
                                identity.as_ref(),
                                circuit_id,
                                retryable,
                                if retryable {
                                    OPEN_REJECT_REASON_MISSING_NEXT_HOP
                                } else {
                                    OPEN_REJECT_REASON_GENERIC
                                },
                            )
                            .await;
                            state
                                .read()
                                .await
                                .observability
                                .reject(format!("transit:{error}"));
                        }
                    }
                }
                ref message @ ControlMessage::OpenAck {
                    circuit_id,
                    ref public_key,
                    ..
                } => {
                    if let Some(previous) = router.reverse_relay(link.instance(), circuit_id).await
                    {
                        if let Err(error) =
                            send_control_with_admission_retry(previous.as_ref(), message).await
                        {
                            router
                                .abort_relay_binding_from_outgoing(link.instance(), circuit_id)
                                .await;
                            tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit OPEN acknowledgement relay failed");
                            let reason_code = if is_local_control_admission(&error) {
                                OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION
                            } else {
                                OPEN_REJECT_REASON_MISSING_NEXT_HOP
                            };
                            send_open_reject(
                                previous.as_ref(),
                                identity.as_ref(),
                                circuit_id,
                                true,
                                reason_code,
                            )
                            .await;
                        }
                    } else if !message.verify_result() {
                        tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, "discarded invalid circuit OPEN acknowledgement signature");
                    } else if !control_plane
                        .opens
                        .resolve(
                            link.instance(),
                            circuit_id,
                            public_key,
                            dataplane::OpenResult::Acknowledged,
                        )
                        .await
                    {
                        tracing::debug!(peer_name = %link.peer, circuit_id = ?circuit_id, "ignored stale circuit OPEN acknowledgement");
                    }
                }
                ref message @ ControlMessage::OpenReject {
                    circuit_id,
                    retryable,
                    reason_code,
                    ref public_key,
                    ..
                } => {
                    if let Some(previous) = router.reverse_relay(link.instance(), circuit_id).await
                    {
                        let forwarded =
                            send_control_with_admission_retry(previous.as_ref(), message).await;
                        router
                            .abort_relay_binding_from_outgoing(link.instance(), circuit_id)
                            .await;
                        if let Err(error) = forwarded {
                            tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit OPEN rejection relay failed");
                            let reason_code = if is_local_control_admission(&error) {
                                OPEN_REJECT_REASON_LOCAL_CONTROL_ADMISSION
                            } else {
                                OPEN_REJECT_REASON_MISSING_NEXT_HOP
                            };
                            send_open_reject(
                                previous.as_ref(),
                                identity.as_ref(),
                                circuit_id,
                                true,
                                reason_code,
                            )
                            .await;
                        }
                    } else if !message.verify_result() {
                        tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, "discarded invalid circuit OPEN rejection signature");
                    } else if !control_plane
                        .opens
                        .resolve(
                            link.instance(),
                            circuit_id,
                            public_key,
                            dataplane::OpenResult::Rejected {
                                retryable,
                                reason: format!("code:{reason_code}"),
                            },
                        )
                        .await
                    {
                        tracing::debug!(peer_name = %link.peer, circuit_id = ?circuit_id, "ignored stale circuit OPEN rejection");
                    }
                }
                ref message @ ControlMessage::CircuitClose {
                    circuit_id,
                    counter,
                    ref public_key,
                    ..
                } => {
                    if !message.verify_close() {
                        tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, "discarded invalid circuit CLOSE signature");
                        continue;
                    }
                    if let Some(closed) = router
                        .close_binding(link.instance(), circuit_id, public_key, counter)
                        .await
                    {
                        control_plane
                            .sessions
                            .remove_circuit(link.instance(), circuit_id)
                            .await;
                        control_plane
                            .return_flows
                            .remove_circuit(link.instance(), circuit_id);
                        control_plane
                            .circuit_dns
                            .remove_circuit(link.instance(), circuit_id);
                        if let Some(next) = closed.outgoing
                            && let Err(error) =
                                send_control_with_admission_retry(next.outgoing.as_ref(), message)
                                    .await
                        {
                            tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit CLOSE relay failed");
                        }
                    }
                }
                ref message @ ControlMessage::CircuitRenew {
                    circuit_id,
                    counter,
                    ref public_key,
                    ..
                } => {
                    if !message.verify_renew() {
                        tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, "discarded invalid circuit RENEW signature");
                        continue;
                    }
                    match router.renew_binding(
                        link.instance(),
                        circuit_id,
                        public_key,
                        counter,
                    ) {
                        Ok(Some(next)) => {
                            if let Err(error) =
                                send_control_with_admission_retry(next.as_ref(), message).await
                            {
                                let previous = router.reverse_relay(link.instance(), circuit_id).await;
                                router
                                    .abort_relay_binding_from_outgoing(link.instance(), circuit_id)
                                    .await;
                                if let Some(previous) = previous {
                                    let broken = ControlMessage::circuit_broken(
                                        identity.as_ref(),
                                        circuit_id,
                                        tinect::control::CIRCUIT_BROKEN_REASON_RELAY_FAILURE,
                                    );
                                    let _ = send_control_with_admission_retry(
                                        previous.as_ref(),
                                        &broken,
                                    )
                                    .await;
                                }
                                tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit RENEW relay failed");
                            }
                        }
                        Ok(None) => {
                            let acknowledgment = ControlMessage::circuit_renew_ack(
                                identity.as_ref(),
                                circuit_id,
                                counter,
                            );
                            if let Err(error) =
                                send_control_with_admission_retry(link.as_ref(), &acknowledgment)
                                    .await
                            {
                                tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit RENEW acknowledgement send failed");
                            }
                        }
                        Err(tinect::circuit::CircuitError::StaleRenewal) => {
                            // RFC-0046: older counters are idempotently
                            // ignored. Do not forward, re-ACK, or send a
                            // rejection: the source's waiter only accepts the
                            // exact counter it is waiting for.
                            tracing::debug!(peer_name = %link.peer, circuit_id = ?circuit_id, "ignored stale circuit RENEW")
                        }
                        Err(error) => {
                            let broken = ControlMessage::circuit_broken(
                                identity.as_ref(),
                                circuit_id,
                                tinect::control::CIRCUIT_RENEW_REJECTED_REASON,
                            );
                            if let Err(send_error) =
                                send_control_with_admission_retry(link.as_ref(), &broken).await
                            {
                                tracing::debug!(
                                    peer_name = %link.peer,
                                    circuit_id = ?circuit_id,
                                    error = %send_error,
                                    "circuit RENEW rejection feedback could not be delivered"
                                );
                            }
                            tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit RENEW rejected")
                        }
                    }
                }
                ref message @ ControlMessage::CircuitRenewAck {
                    circuit_id,
                    counter,
                    ref public_key,
                    ..
                } => {
                    // Verify before relaying: otherwise a malicious
                    // downstream can burn upstream bandwidth/processing with
                    // forged acks and probe relay topology.
                    //
                    // Residual: `verify_renew` proves self-signature only.
                    // `reverse_relay` already constrains relay to acks
                    // arriving on the circuit's actual downstream link, and
                    // the source's `resolve` rejects wrong-key/counter acks,
                    // so a forging downstream wastes at most one admitted
                    // forward per relay -- the same bound as relayed RENEW
                    // and CLOSE, which share this property. Checking the ack
                    // against the exit identity would need a path-to-key
                    // lookup the circuit layer does not have.
                    if !message.verify_renew() {
                        tracing::debug!(peer_name = %link.peer, circuit_id = ?circuit_id, "discarded invalid circuit RENEW acknowledgement before relay");
                        continue;
                    }
                    if let Some(previous) = router.reverse_relay(link.instance(), circuit_id).await
                    {
                        if let Err(error) =
                            send_control_with_admission_retry(previous.as_ref(), message).await
                        {
                            router
                                .abort_relay_binding_from_outgoing(link.instance(), circuit_id)
                                .await;
                            let broken = ControlMessage::circuit_broken(
                                identity.as_ref(),
                                circuit_id,
                                tinect::control::CIRCUIT_BROKEN_REASON_RELAY_FAILURE,
                            );
                            let _ = send_control_with_admission_retry(previous.as_ref(), &broken)
                                .await;
                            tracing::warn!(peer_name = %link.peer, circuit_id = ?circuit_id, error = %error, "circuit RENEW acknowledgement relay failed");
                        }
                    } else if !control_plane
                        .opens
                        .resolve(
                            link.instance(),
                            circuit_id,
                            public_key,
                            dataplane::OpenResult::RenewAcknowledged { counter },
                        )
                        .await
                    {
                        tracing::debug!(peer_name = %link.peer, circuit_id = ?circuit_id, "ignored stale circuit RENEW acknowledgement");
                    }
                }
                ref message @ ControlMessage::CircuitBroken {
                    circuit_id,
                    reason_code,
                    ref public_key,
                    ..
                } => {
                    let signer_is_first_hop = identity::decode_public(public_key)
                        .ok()
                        .is_some_and(|key| identity::node_id(&key) == link.peer_identity);
                    if !message.verify_broken() || !signer_is_first_hop {
                        tracing::debug!(peer_name = %link.peer, ?circuit_id, "ignored invalid circuit-broken notification");
                    } else if !matches!(
                        reason_code,
                        tinect::control::CIRCUIT_BROKEN_REASON_LINK_CLOSED
                        | tinect::control::CIRCUIT_UNKNOWN_SESSION_REASON
                        | tinect::control::CIRCUIT_RENEW_REJECTED_REASON
                        | tinect::control::CIRCUIT_BROKEN_REASON_RELAY_FAILURE
                    ) {
                        // `CircuitBroken` is transitively trusted: any
                        // on-path relay re-signs it, so the source cannot
                        // distinguish the origin. Reject unknown reason codes
                        // loudly instead of revoking on opaque input; the
                        // renewal/lease grace still bounds convergence if a
                        // legitimate reason is dropped here.
                        tracing::warn!(peer_name = %link.peer, ?circuit_id, reason_code, "ignored circuit-broken notification with unexpected reason");
                    } else if let Some(previous) = router.reverse_relay(link.instance(), circuit_id).await {
                        let forwarded = ControlMessage::circuit_broken(
                            identity.as_ref(),
                            circuit_id,
                            reason_code,
                        );
                        let send_result =
                            send_control_with_admission_retry(previous.as_ref(), &forwarded).await;
                        router
                            .abort_relay_binding_from_outgoing(link.instance(), circuit_id)
                            .await;
                        if let Err(error) = send_result {
                            tracing::warn!(peer_name = %link.peer, ?circuit_id, error = %error, "circuit-broken feedback relay failed");
                        }
                    } else if control_plane
                        .opens
                        .invalidate_circuit(link.instance(), circuit_id)
                        .await
                    {
                        control_plane
                            .sessions
                            .remove_circuit(link.instance(), circuit_id)
                            .await;
                        control_plane
                            .return_flows
                            .remove_circuit(link.instance(), circuit_id);
                        control_plane
                            .circuit_dns
                            .remove_circuit(link.instance(), circuit_id);
                        tracing::info!(peer_name = %link.peer, ?circuit_id, "downstream circuit failure invalidated source snapshot");
                    } else {
                        tracing::debug!(peer_name = %link.peer, ?circuit_id, "ignored stale circuit-broken notification");
                    }
                }
                ControlMessage::Ping => {
                    let _ = link.send_control(&ControlMessage::Pong).await;
                }
                ControlMessage::Pong => {}
                ControlMessage::FecReport(report) => {
                    let health = link.apply_fec_report(report);
                    let Some((message, error)) = (match health {
                        carrier::FecReportHealth::Degraded => Some((
                            "FEC data-plane loss threshold reached; Link marked unhealthy",
                            Some("FEC data-plane loss threshold reached".to_owned()),
                        )),
                        carrier::FecReportHealth::Recovered => Some((
                            "FEC data-plane health recovered; Link marked healthy",
                            None,
                        )),
                        carrier::FecReportHealth::Unchanged => None,
                    }) else {
                        continue;
                    };
                    tracing::warn!(
                        peer_name = %link.peer,
                        peer_identity = %link.peer_identity,
                        "{message}"
                    );
                    let current = links
                        .lock()
                        .expect("link registry lock")
                        .get(&link.peer)
                        .is_some_and(|current| current.instance() == link.instance());
                    if current {
                        mark_link(&state, &link.peer, link.is_healthy(), error).await;
                        control_plane.opens.request_reconcile();
                    }
                }
            }
        }
        router.authorizations().remove_link(link.instance()).await;
        control_plane.sessions.remove_link(link.instance()).await;
        control_plane.return_flows.remove_link(link.instance());
        control_plane.circuit_dns.remove_link(link.instance());
        control_plane
            .opens
            .remove_link(link.instance(), link.lifecycle_token())
            .await;
        router.remove_relay_labels(link.instance());
        router.remove_relay_labels_for_outgoing(link.instance());
        let broken = router.remove_bindings(link.instance());
        notify_broken(&links, identity.as_ref(), broken).await;
        // Inbound Links do not have the outbound connector's `wait_closed`
        // task.  Remove only this instance: a reconnect may already have
        // replaced it in the registry while this old handler was unwinding.
        let removed = {
            let mut registered = links.lock().expect("link registry lock");
            registered
                .get(&link.peer)
                .is_some_and(|current| current.instance() == link.instance())
                && registered.remove(&link.peer).is_some()
        };
        if removed {
            mark_current_link(
                &state,
                &links,
                &link.peer,
                link.instance(),
                false,
                Some("QUIC connection closed".into()),
                &control_plane.opens,
            )
            .await;
            tracing::info!(peer_name = %link.peer, peer_identity = %link.peer_identity, instance = link.instance(), "inbound QUIC link removed after close");
        }
    });
}

mod helpers;
pub(crate) use helpers::*;
pub(crate) fn spawn(link: Arc<carrier::Link>, context: ControlHandlerContext) {
    spawn_control_handler(link, context);
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests;
