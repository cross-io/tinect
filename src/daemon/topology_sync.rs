//! Reliable topology snapshot and delta transfer helpers.

use super::support::{
    MAX_TOPOLOGY_ACK_SEND_ATTEMPTS, MAX_TOPOLOGY_SNAPSHOT_CHUNKS, MAX_TOPOLOGY_SYNC_MESSAGE,
    TOPOLOGY_ACK_SEND_TIMEOUT, min_topology_snapshot_request_interval, unix_now,
};
use anyhow::{Context, Result};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tinect::{
    carrier,
    control::ControlMessage,
    runtime::LinkRegistry,
    topology::{LinkStateAdvertisement, Topology},
};

static NEXT_SYNC_ID: AtomicU64 = AtomicU64::new(1);

const TOPOLOGY_SYNC_RECOVERY_REQUEST_FAILURE: &str =
    "topology_sync_recovery_request_delivery_failed";

pub(crate) fn next_topology_sync_id() -> u64 {
    // A u64 sync-id space cannot be exhausted in practice. Degrade to a
    // saturated value instead of panicking if it ever is; the state machine
    // treats an unchanged ID as the same transfer, which is benign.
    NEXT_SYNC_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |sync_id| {
            sync_id.checked_add(1).or(Some(u64::MAX))
        })
        .unwrap_or(u64::MAX)
}

/// Fixed overhead of one encoded `TopologySync` message before its LSA body:
/// kind + length (3), mode (1), sync_id (8), chunk_index (2), chunk_count
/// (2), and the LSA count (2).
const TOPOLOGY_SYNC_HEADER_LEN: usize = 18;

/// Exact wire length of one LSA as produced by `LinkStateAdvertisement::
/// encode_wire`: signing bytes (16 + 8 + 8 + 2 + neighbors*22 + 32) plus the
/// 64-byte signature.
fn lsa_wire_len(advertisement: &LinkStateAdvertisement) -> usize {
    advertisement
        .neighbors
        .len()
        .saturating_mul(22)
        .saturating_add(130)
}

pub(crate) fn topology_sync_chunks(
    advertisements: Vec<LinkStateAdvertisement>,
) -> Result<Vec<Vec<LinkStateAdvertisement>>> {
    let mut chunks = Vec::<Vec<LinkStateAdvertisement>>::new();
    let mut current = Vec::new();
    let mut current_len = TOPOLOGY_SYNC_HEADER_LEN;
    for advertisement in advertisements {
        let lsa_len = lsa_wire_len(&advertisement);
        if current.len() == tinect::control::MAX_TOPOLOGY_SYNC_CHUNK_LSAS
            || (current_len.saturating_add(lsa_len) > MAX_TOPOLOGY_SYNC_MESSAGE
                && !current.is_empty())
        {
            chunks.push(std::mem::take(&mut current));
            current_len = TOPOLOGY_SYNC_HEADER_LEN;
        }
        if lsa_len > MAX_TOPOLOGY_SYNC_MESSAGE.saturating_sub(TOPOLOGY_SYNC_HEADER_LEN) {
            anyhow::bail!("single LSA exceeds reliable topology control message limit");
        }
        current_len += lsa_len;
        current.push(advertisement);
    }
    if !current.is_empty() || chunks.is_empty() {
        chunks.push(current);
    }
    if chunks.len() > MAX_TOPOLOGY_SNAPSHOT_CHUNKS {
        anyhow::bail!("topology snapshot exceeds 256 chunks");
    }
    Ok(chunks)
}

pub(crate) async fn send_topology_snapshot(
    link: &carrier::Link,
    advertisements: Vec<LinkStateAdvertisement>,
) -> Result<u64> {
    let sync_id = next_topology_sync_id();
    let chunks = topology_sync_chunks(advertisements)?;
    let chunk_count = u16::try_from(chunks.len()).context("topology snapshot chunk count")?;
    tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, link_instance = link.instance(), sync_id, chunk_count, "reliable topology snapshot send started");
    for (chunk_index, advertisements) in chunks.into_iter().enumerate() {
        link.send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Snapshot,
            sync_id,
            chunk_index: u16::try_from(chunk_index).context("topology snapshot chunk index")?,
            chunk_count,
            advertisements,
        })
        .await
        .with_context(|| {
            format!("topology snapshot sync_id={sync_id} chunk={chunk_index}/{chunk_count}")
        })?;
    }
    tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, link_instance = link.instance(), sync_id, chunk_count, "reliable topology snapshot sent");
    Ok(sync_id)
}

pub(crate) async fn send_topology_delta(
    link: &carrier::Link,
    advertisements: Vec<LinkStateAdvertisement>,
) -> Result<()> {
    for advertisements in topology_sync_chunks(advertisements)? {
        link.send_control(&ControlMessage::TopologySync {
            mode: tinect::control::TopologySyncMode::Delta,
            sync_id: next_topology_sync_id(),
            chunk_index: 0,
            chunk_count: 1,
            advertisements,
        })
        .await?;
    }
    Ok(())
}

pub(crate) fn topology_ack_retry_delay(attempt: u8) -> std::time::Duration {
    std::time::Duration::from_millis(50_u64.saturating_mul(1_u64 << attempt.min(1)))
}

pub(crate) async fn send_topology_snapshot_ack(link: &carrier::Link, sync_id: u64) -> bool {
    let mut last_failure = None;
    for attempt in 0..MAX_TOPOLOGY_ACK_SEND_ATTEMPTS {
        let result = tokio::time::timeout(
            TOPOLOGY_ACK_SEND_TIMEOUT,
            link.send_control(&ControlMessage::TopologySyncAck { sync_id }),
        )
        .await;
        match result {
            Ok(Ok(())) => {
                tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, link_instance = link.instance(), sync_id, attempt = attempt + 1, "reliable topology snapshot acknowledgement sent");
                return true;
            }
            Ok(Err(error)) => {
                last_failure = Some(error.to_string());
                tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, link_instance = link.instance(), sync_id, attempt = attempt + 1, error = %error, "reliable topology snapshot acknowledgement send failed");
            }
            Err(_) => {
                last_failure = Some("timeout".into());
                tracing::debug!(peer_name = %link.peer, peer_identity = %link.peer_identity, link_instance = link.instance(), sync_id, attempt = attempt + 1, "reliable topology snapshot acknowledgement send timed out");
            }
        }
        if link.close_reason().is_some() || attempt + 1 == MAX_TOPOLOGY_ACK_SEND_ATTEMPTS {
            break;
        }
        tokio::time::sleep(topology_ack_retry_delay(attempt)).await;
    }
    tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, link_instance = link.instance(), sync_id, attempts = MAX_TOPOLOGY_ACK_SEND_ATTEMPTS, error = last_failure.as_deref().unwrap_or("unknown"), "reliable topology snapshot acknowledgement delivery exhausted");
    false
}

pub(crate) async fn fanout_topology_delta(
    incoming_instance: u64,
    advertisements: Vec<LinkStateAdvertisement>,
    links: &LinkRegistry,
) {
    if advertisements.is_empty() {
        return;
    }
    let peers = links
        .lock()
        .expect("link registry lock")
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut last_snapshot_request = None;
    for peer in peers {
        if peer.instance() == incoming_instance {
            continue;
        }
        if !peer.queue_topology_deltas(advertisements.clone()).await {
            // The Delta outbox for this peer is full: incremental delivery
            // cannot keep up. RFC-0016 requires entering SnapshotRequired
            // instead of closing a merely congested Link: drop the stale
            // queued Deltas, pause old Delta sending, and re-fix a complete
            // Snapshot. The recovery Request makes the peer re-send its own
            // Snapshot; the receive path then re-sends ours once the peer's
            // fresh Snapshot confirms the round trip.
            tracing::warn!(peer_name = %peer.peer, peer_identity = %peer.peer_identity, "reliable topology Delta outbox is full during fanout; entering SnapshotRequired");
            peer.clear_topology_deltas().await;
            peer.mark_topology_unsynchronized();
            request_topology_snapshot_recovery(&peer, &mut last_snapshot_request, 11).await;
        }
    }
}

pub(crate) struct SnapshotAssembly {
    pub(crate) chunks: Vec<Option<Vec<LinkStateAdvertisement>>>,
    pub(crate) bytes: usize,
    pub(crate) lsa_count: usize,
    pub(crate) neighbors: usize,
    pub(crate) started: Instant,
}

pub(crate) struct PendingSnapshot {
    pub(crate) sync_id: u64,
    pub(crate) deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopologyTxState {
    NeedSnapshot,
    Sending,
    AwaitingAck { sync_id: u64 },
    Synchronized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopologyRxState {
    AwaitingInitial,
    Assembling { sync_id: u64 },
    Applying { sync_id: u64 },
    Synchronized,
}

/// Per-Link topology protocol state.  The two directions are independent:
/// receiving a peer snapshot must not accidentally acknowledge our own
/// snapshot, and a lost ACK must not make an already-applied snapshot apply a
/// second time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TopologySyncState {
    pub(crate) tx: TopologyTxState,
    pub(crate) rx: TopologyRxState,
    /// The greatest Snapshot generation observed by this receive direction.
    /// It survives `invalidate_rx()`: an older completed Snapshot may be
    /// ACKed again while it remains in the completed-ID window, but a Snapshot
    /// below this watermark is never accepted as a new transfer.
    pub(crate) rx_watermark: Option<u64>,
}

impl TopologySyncState {
    pub(crate) const fn new() -> Self {
        Self {
            tx: TopologyTxState::NeedSnapshot,
            rx: TopologyRxState::AwaitingInitial,
            rx_watermark: None,
        }
    }

    pub(crate) fn begin_sending(&mut self) {
        self.tx = TopologyTxState::Sending;
    }

    pub(crate) fn begin_snapshot(&mut self, sync_id: u64) {
        self.tx = TopologyTxState::AwaitingAck { sync_id };
    }

    pub(crate) fn invalidate_tx(&mut self) {
        self.tx = TopologyTxState::NeedSnapshot;
    }

    pub(crate) fn invalidate_rx(&mut self) {
        // Keep rx_watermark across invalidation. Recovery must not make an
        // older Snapshot eligible to replace a newer generation after the
        // newer transfer has failed.
        self.rx = TopologyRxState::AwaitingInitial;
    }

    pub(crate) fn acknowledge(&mut self, sync_id: u64) -> bool {
        if self.tx == (TopologyTxState::AwaitingAck { sync_id }) {
            self.tx = TopologyTxState::Synchronized;
            true
        } else {
            false
        }
    }

    pub(crate) fn begin_receive(&mut self, sync_id: u64) -> bool {
        if self.is_stale_snapshot(sync_id) {
            return false;
        }
        let accepted = match self.rx {
            TopologyRxState::AwaitingInitial => {
                self.rx = TopologyRxState::Assembling { sync_id };
                true
            }
            TopologyRxState::Assembling { sync_id: current } => current == sync_id,
            TopologyRxState::Applying { .. } => false,
            TopologyRxState::Synchronized => {
                self.rx = TopologyRxState::Assembling { sync_id };
                true
            }
        };
        if accepted {
            self.rx_watermark = Some(
                self.rx_watermark
                    .map_or(sync_id, |watermark| watermark.max(sync_id)),
            );
        }
        accepted
    }

    pub(crate) fn is_stale_snapshot(&self, sync_id: u64) -> bool {
        self.rx_watermark
            .is_some_and(|watermark| sync_id < watermark)
    }

    pub(crate) fn begin_apply(&mut self, sync_id: u64) -> bool {
        if self.rx == (TopologyRxState::Assembling { sync_id }) {
            self.rx = TopologyRxState::Applying { sync_id };
            true
        } else {
            false
        }
    }

    pub(crate) fn applied(&mut self, sync_id: u64) -> bool {
        if self.rx == (TopologyRxState::Applying { sync_id }) {
            self.rx = TopologyRxState::Synchronized;
            true
        } else {
            false
        }
    }

    /// Restore receive readiness after a previously applied Snapshot is
    /// retransmitted.  The recovery path may have invalidated RX while the
    /// peer was retransmitting because an earlier ACK or Delta was lost; in
    /// that case `applied()` cannot be used because there is no new assembly
    /// to transition from `Applying`.
    pub(crate) fn restore_completed_snapshot(&mut self, sync_id: u64) -> bool {
        if self.rx_watermark != Some(sync_id) {
            return false;
        }
        match self.rx {
            TopologyRxState::AwaitingInitial => {
                self.rx = TopologyRxState::Synchronized;
                true
            }
            TopologyRxState::Assembling { sync_id: current }
            | TopologyRxState::Applying { sync_id: current }
                if current == sync_id =>
            {
                self.rx = TopologyRxState::Synchronized;
                true
            }
            TopologyRxState::Synchronized => false,
            // Do not let an old completed Snapshot interrupt a newer
            // in-flight transfer.  The caller also uses this result to avoid
            // reasserting the carrier's inbound-ready flag in that case.
            TopologyRxState::Assembling { .. } | TopologyRxState::Applying { .. } => false,
        }
    }

    pub(crate) const fn ready(self) -> bool {
        matches!(self.tx, TopologyTxState::Synchronized)
            && matches!(self.rx, TopologyRxState::Synchronized)
    }

    pub(crate) const fn can_apply_delta(self) -> bool {
        matches!(self.rx, TopologyRxState::Synchronized)
    }
}

pub(crate) async fn request_topology_snapshot_recovery(
    link: &carrier::Link,
    last_request: &mut Option<Instant>,
    reason: u16,
) {
    // This request asks the peer to send its Snapshot, so only the local
    // receive direction is invalid.  Invalidating the outbound ACK state as
    // well can make the two independent Snapshot exchanges wait on one
    // another indefinitely.
    link.mark_topology_inbound_unsynchronized();
    if !allow_topology_snapshot_request(last_request, Instant::now()) {
        return;
    }
    if let Err(error) = link
        .send_control(&ControlMessage::TopologySyncRequest { reason })
        .await
    {
        // A failed Request cannot be recovered by another event in this Link
        // epoch: the peer has no durable indication that it must send a new
        // Snapshot.  Close the epoch so the normal reconnect owner creates a
        // fresh Link and both directions perform their initial Snapshot again.
        tracing::warn!(peer_name = %link.peer, peer_identity = %link.peer_identity, link_instance = link.instance(), reason, error = %error, close_reason = TOPOLOGY_SYNC_RECOVERY_REQUEST_FAILURE, "reliable topology snapshot recovery request delivery failed; closing Link");
        link.close(TOPOLOGY_SYNC_RECOVERY_REQUEST_FAILURE);
    }
}

pub(crate) fn allow_topology_snapshot_request(
    last_request: &mut Option<Instant>,
    now: Instant,
) -> bool {
    if last_request.is_some_and(|previous| {
        now.duration_since(previous) < min_topology_snapshot_request_interval()
    }) {
        return false;
    }
    *last_request = Some(now);
    true
}

pub(crate) async fn send_current_topology_snapshot(
    link: &carrier::Link,
    topology: &Arc<tokio::sync::RwLock<Topology>>,
) -> Result<u64> {
    let advertisements = topology.read().await.active_advertisements(unix_now());
    send_topology_snapshot(link, advertisements).await
}

pub(crate) fn topology_sync_chunk_bytes(
    advertisements: &[LinkStateAdvertisement],
) -> Result<(usize, usize)> {
    let mut encoded = tinect::wire::Writer::new();
    let mut neighbors = 0usize;
    for advertisement in advertisements {
        advertisement
            .encode_wire(&mut encoded)
            .context("encoding topology snapshot accounting")?;
        neighbors = neighbors.saturating_add(advertisement.neighbors.len());
    }
    Ok((encoded.finish().len(), neighbors))
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::circuit_resolution::tests::link_pair;
    use crate::daemon::support::RECENT_COMPLETED_TOPOLOGY_SNAPSHOTS;
    use std::collections::HashMap;
    use tinect::topology::LinkMetric;

    /// A cheap, valid-looking LSA with no neighbors and an empty signature.
    /// Only chunk accounting and outbox queuing inspect these advertisements.
    fn unsigned_lsa(seed: u64) -> LinkStateAdvertisement {
        LinkStateAdvertisement {
            origin: format!("{seed:032x}"),
            sequence: 1,
            expires_at: u64::MAX,
            neighbors: Vec::new(),
            public_key: String::new(),
            signature: String::new(),
        }
    }

    fn lsa(seed: u64, neighbors: usize) -> LinkStateAdvertisement {
        let key = crate::identity::generate();
        let origin = format!("{seed:032x}");
        LinkStateAdvertisement::new(
            origin,
            &key,
            1,
            100,
            (0..neighbors)
                .map(|index| LinkMetric {
                    node: format!("{index:032x}"),
                    cost: 1,
                    inner_mtu: 1200,
                })
                .collect(),
        )
    }

    #[test]
    fn lsa_wire_len_matches_encode_wire() {
        let advertisement = lsa(1, 20);
        let mut writer = tinect::wire::Writer::new();
        advertisement.encode_wire(&mut writer).unwrap();
        assert_eq!(lsa_wire_len(&advertisement), writer.finish().len());
    }

    #[test]
    fn chunk_length_accounting_matches_encoding() {
        let advertisements = (0..40).map(|seed| lsa(seed, 20)).collect::<Vec<_>>();
        let chunks = topology_sync_chunks(advertisements).unwrap();
        let total = chunks.iter().map(Vec::len).sum::<usize>();
        assert_eq!(total, 40);
        for chunk in &chunks {
            let encoded = ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: 1,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: chunk.clone(),
            }
            .encode()
            .unwrap();
            assert!(encoded.len() <= MAX_TOPOLOGY_SYNC_MESSAGE);
        }
    }

    #[test]
    fn large_snapshot_splits_into_bounded_chunks() {
        let advertisements = (0..200).map(|seed| lsa(seed, 20)).collect::<Vec<_>>();
        let chunks = topology_sync_chunks(advertisements).unwrap();
        assert!(chunks.len() > 1);
        assert!(chunks.len() <= MAX_TOPOLOGY_SNAPSHOT_CHUNKS);
        for chunk in &chunks {
            let encoded = ControlMessage::TopologySync {
                mode: tinect::control::TopologySyncMode::Snapshot,
                sync_id: 1,
                chunk_index: 0,
                chunk_count: 1,
                advertisements: chunk.clone(),
            }
            .encode()
            .unwrap();
            assert!(encoded.len() <= MAX_TOPOLOGY_SYNC_MESSAGE);
        }
    }

    #[test]
    fn single_oversized_lsa_is_rejected() {
        // 130 + 22 * 3000 = 66130 > the 65535-byte body budget.
        assert!(topology_sync_chunks(vec![lsa(0, 3000)]).is_err());
    }

    #[test]
    fn empty_snapshots_and_accounting_are_stable() {
        assert_eq!(topology_sync_chunks(Vec::new()).unwrap(), vec![Vec::new()]);
        let advertisements = vec![lsa(7, 3), lsa(8, 0)];
        let (bytes, neighbors) = topology_sync_chunk_bytes(&advertisements).unwrap();
        let mut writer = tinect::wire::Writer::new();
        for advertisement in &advertisements {
            advertisement.encode_wire(&mut writer).unwrap();
        }
        assert_eq!(bytes, writer.finish().len());
        assert_eq!(neighbors, 3);
    }

    #[test]
    fn recovery_requests_are_rate_limited_and_sync_ids_are_unique() {
        let now = Instant::now();
        let mut last = None;
        assert!(allow_topology_snapshot_request(&mut last, now));
        assert!(!allow_topology_snapshot_request(
            &mut last,
            now + std::time::Duration::from_secs(9)
        ));
        assert!(allow_topology_snapshot_request(
            &mut last,
            now + std::time::Duration::from_secs(10)
        ));
        let first = next_topology_sync_id();
        let second = next_topology_sync_id();
        assert_eq!(second, first + 1);
    }

    #[test]
    fn topology_sync_state_requires_both_directions() {
        let mut state = TopologySyncState::new();
        assert!(!state.ready());
        state.begin_snapshot(10);
        assert!(!state.acknowledge(9));
        assert!(state.acknowledge(10));
        assert!(!state.ready());
        assert!(state.begin_receive(20));
        assert!(state.begin_apply(20));
        assert!(state.applied(20));
        assert!(state.ready());
        assert!(state.begin_receive(21));
        assert!(!state.begin_apply(22));
        assert!(!state.begin_receive(22));
        assert!(state.begin_apply(21));
        assert!(!state.begin_receive(22));
        assert!(!state.applied(22));
        assert!(state.applied(21));
        assert!(state.ready());
    }

    #[test]
    fn topology_sync_state_rejects_interleaved_snapshots() {
        let mut state = TopologySyncState::new();
        state.begin_sending();
        state.begin_snapshot(9);
        assert!(state.begin_receive(1));
        assert!(!state.begin_receive(2));
        state.invalidate_rx();
        assert!(state.begin_receive(2));
        assert_eq!(state.tx, TopologyTxState::AwaitingAck { sync_id: 9 });
    }

    #[test]
    fn topology_recovery_keeps_tx_and_rx_independent() {
        let mut state = TopologySyncState::new();
        state.begin_sending();
        state.begin_snapshot(9);
        assert!(state.acknowledge(9));
        assert!(state.begin_receive(10));
        assert!(state.begin_apply(10));
        assert!(state.applied(10));

        state.invalidate_rx();
        assert_eq!(state.tx, TopologyTxState::Synchronized);
        assert_eq!(state.rx, TopologyRxState::AwaitingInitial);
        assert!(state.restore_completed_snapshot(10));
        assert_eq!(state.rx, TopologyRxState::Synchronized);

        state.invalidate_tx();
        assert_eq!(state.tx, TopologyTxState::NeedSnapshot);
        assert_eq!(state.rx, TopologyRxState::Synchronized);
    }

    #[test]
    fn completed_snapshot_restore_does_not_interrupt_another_assembly() {
        let mut state = TopologySyncState::new();
        state.invalidate_rx();
        assert!(state.begin_receive(11));
        assert!(!state.restore_completed_snapshot(10));
        assert_eq!(state.rx, TopologyRxState::Assembling { sync_id: 11 });
    }

    #[test]
    fn completed_snapshot_restore_does_not_cross_a_newer_invalidated_generation() {
        let mut state = TopologySyncState::new();
        assert!(state.begin_receive(10));
        assert!(state.begin_apply(10));
        assert!(state.applied(10));
        assert!(state.begin_receive(11));
        state.invalidate_rx();

        assert!(!state.restore_completed_snapshot(10));
        assert_eq!(state.rx, TopologyRxState::AwaitingInitial);
        assert_eq!(state.rx_watermark, Some(11));
    }

    #[test]
    fn topology_sync_state_rejects_older_generations_without_disrupting_newer_assembly() {
        let mut state = TopologySyncState::new();
        assert!(state.begin_receive(10));
        assert!(state.begin_apply(10));
        assert!(state.applied(10));
        assert!(state.begin_receive(20));

        assert!(state.is_stale_snapshot(10));
        assert!(!state.begin_receive(10));
        assert_eq!(state.rx, TopologyRxState::Assembling { sync_id: 20 });
        assert_eq!(state.rx_watermark, Some(20));

        state.invalidate_rx();
        assert!(!state.begin_receive(10));
        assert_eq!(state.rx, TopologyRxState::AwaitingInitial);
        assert_eq!(state.rx_watermark, Some(20));
        assert!(state.begin_receive(20));
    }

    #[test]
    fn topology_sync_state_rejects_old_snapshot_after_completed_window_moves_on() {
        let mut state = TopologySyncState::new();
        for sync_id in 1..=(RECENT_COMPLETED_TOPOLOGY_SNAPSHOTS as u64 + 1) {
            assert!(state.begin_receive(sync_id));
            assert!(state.begin_apply(sync_id));
            assert!(state.applied(sync_id));
        }

        assert!(state.is_stale_snapshot(1));
        assert!(!state.begin_receive(1));
        assert_eq!(state.rx, TopologyRxState::Synchronized);
        assert_eq!(
            state.rx_watermark,
            Some(RECENT_COMPLETED_TOPOLOGY_SNAPSHOTS as u64 + 1)
        );
    }

    #[test]
    fn topology_sync_state_accepts_the_same_generation_after_invalidation() {
        let mut state = TopologySyncState::new();
        assert!(state.begin_receive(10));
        state.invalidate_rx();

        assert!(!state.is_stale_snapshot(10));
        assert!(state.begin_receive(10));
        assert_eq!(state.rx, TopologyRxState::Assembling { sync_id: 10 });
        assert_eq!(state.rx_watermark, Some(10));
    }

    #[test]
    fn topology_sync_chunks_reject_more_than_256_chunks() {
        // A 0-neighbor LSA is 130 bytes on the wire, so a chunk flushes after
        // 504 LSAs (18 + 504*130 == 65538 == the body budget). 257 chunks
        // therefore need 257 * 504 advertisements and exceed the snapshot
        // chunk limit.
        let advertisements = (0u64..257 * 504).map(unsigned_lsa).collect::<Vec<_>>();
        let error = topology_sync_chunks(advertisements).unwrap_err();
        assert!(error.to_string().contains("exceeds 256 chunks"));
    }

    #[tokio::test]
    async fn snapshot_send_failure_propagates_with_sync_id_context() {
        let pair = link_pair().await;
        pair.client_link.close("test close");
        pair.client_endpoint.close(0u32.into(), b"test close");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            send_topology_snapshot(&pair.server_link, vec![lsa(1, 1)]),
        )
        .await
        .expect("send settles promptly");
        let error = result.unwrap_err();
        assert!(error.to_string().contains("topology snapshot sync_id="));
    }

    #[tokio::test]
    async fn snapshot_ack_reports_false_when_delivery_is_exhausted() {
        let pair = link_pair().await;
        pair.client_link.close("test close");
        pair.client_endpoint.close(0u32.into(), b"test close");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let acknowledged = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            send_topology_snapshot_ack(&pair.server_link, 77),
        )
        .await
        .expect("ack settles promptly");
        assert!(!acknowledged);
    }

    #[tokio::test]
    async fn fanout_skips_empty_deltas_without_touching_links() {
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::new()));
        fanout_topology_delta(0, Vec::new(), &links).await;
    }

    #[tokio::test]
    async fn fanout_full_delta_outbox_enters_snapshot_required() {
        let pair = link_pair().await;
        pair.server_link.mark_topology_snapshot_received();
        pair.server_link.mark_topology_snapshot_acknowledged();
        assert!(pair.server_link.topology_ready());
        // Fill the Delta outbox to capacity with distinct origins, then fan
        // out one brand-new origin: enqueue must reject it and force
        // SnapshotRequired recovery.
        let filled = (0u64..carrier::MAX_PENDING_TOPOLOGY_DELTAS as u64)
            .map(unsigned_lsa)
            .collect::<Vec<_>>();
        assert!(pair.server_link.queue_topology_deltas(filled).await);
        let links: LinkRegistry = Arc::new(std::sync::Mutex::new(HashMap::from([(
            "client".to_owned(),
            pair.server_link.clone(),
        )])));
        fanout_topology_delta(0, vec![unsigned_lsa(u64::MAX)], &links).await;
        assert!(!pair.server_link.topology_ready());
        assert!(pair.server_link.take_topology_deltas().await.is_empty());
    }

    #[tokio::test]
    async fn recovery_request_failure_closes_the_link_epoch() {
        let pair = link_pair().await;
        pair.client_link.close("test close");
        pair.client_endpoint.close(0u32.into(), b"test close");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut last_request = None;
        request_topology_snapshot_recovery(&pair.server_link, &mut last_request, 3).await;
        assert!(pair.server_link.close_reason().is_some());
    }

    #[tokio::test]
    async fn recovery_requests_are_rate_limited_within_the_minimum_interval() {
        let pair = link_pair().await;
        let mut last_request = Some(std::time::Instant::now());
        request_topology_snapshot_recovery(&pair.server_link, &mut last_request, 3).await;
        assert!(pair.server_link.close_reason().is_none());
    }

    #[test]
    fn completed_snapshot_restore_reasserts_synchronized_from_assembly_and_apply() {
        let mut assembling = TopologySyncState::new();
        assert!(assembling.begin_receive(10));
        assert!(assembling.restore_completed_snapshot(10));
        assert_eq!(assembling.rx, TopologyRxState::Synchronized);

        let mut applying = TopologySyncState::new();
        assert!(applying.begin_receive(10));
        assert!(applying.begin_apply(10));
        assert!(applying.restore_completed_snapshot(10));
        assert_eq!(applying.rx, TopologyRxState::Synchronized);
    }
}
