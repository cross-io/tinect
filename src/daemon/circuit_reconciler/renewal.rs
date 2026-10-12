//! Renewal of the active lease with a bounded failure grace.

use super::*;
pub(crate) fn renewal_failure_grace_deadline(started: Instant) -> Instant {
    started + tinect::circuit::circuit_lease()
}

pub(crate) fn renewal_failure_grace_expired(deadline: Instant, now: Instant) -> bool {
    now >= deadline
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RenewalFailureGrace {
    pub(crate) circuit_id: tinect::circuit::CircuitId,
    pub(crate) lease_epoch: u64,
    pub(crate) deadline: Instant,
}

impl RenewalFailureGrace {
    pub(crate) fn for_active(active: &dataplane::ActiveCircuit, started: Instant) -> Self {
        Self {
            circuit_id: active.circuit_id,
            lease_epoch: active.lease_epoch,
            deadline: renewal_failure_grace_deadline(started),
        }
    }

    pub(crate) fn belongs_to(self, active: &dataplane::ActiveCircuit) -> bool {
        self.circuit_id == active.circuit_id && self.lease_epoch == active.lease_epoch
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenewalResult {
    Acknowledged,
    LeaseChanged,
    FailedWithinGrace,
    Inactive,
    Revoked,
}

pub(crate) async fn renew_active_circuit_once(
    config: &Config,
    destination: &str,
    links: &LinkRegistry,
    circuit_opens: &dataplane::CircuitOpenManager,
    key: &ed25519_dalek::SigningKey,
) -> bool {
    let Some(active) = circuit_opens.active_for_destination(destination).await else {
        return false;
    };
    let Some(peer) = config.peers.get(destination) else {
        return false;
    };
    let Some(link) = registered_link_by_instance(links, active.link_instance) else {
        circuit_opens
            .deactivate(destination, active.circuit_id)
            .await;
        return false;
    };
    for attempt in 0..CONTROL_ADMISSION_RETRY_ATTEMPTS {
        let counter = active
            .renewal_counter
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let waiter = circuit_opens
            .register(
                active.link_instance,
                active.circuit_id,
                peer.public_key.clone(),
                active
                    .path
                    .iter()
                    .filter_map(|node| config.peer_by_identity(node))
                    .map(|peer| peer.public_key.clone())
                    .collect(),
                Some(counter),
                link.lifecycle_token(),
            )
            .await;
        let renew = ControlMessage::circuit_renew(key, active.circuit_id, counter);
        let send_result = send_control_with_admission_retry(link.as_ref(), &renew).await;
        let result = match send_result {
            Ok(()) => tokio::time::timeout(std::time::Duration::from_secs(5), waiter).await,
            Err(error) => {
                circuit_opens
                    .clear(active.link_instance, active.circuit_id)
                    .await;
                if is_local_control_admission(&error)
                    && attempt + 1 < CONTROL_ADMISSION_RETRY_ATTEMPTS
                {
                    tokio::time::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1)))
                        .await;
                    continue;
                }
                break;
            }
        };
        let retryable_local_admission = matches!(
            &result,
            Ok(Ok(dataplane::OpenResult::Rejected {
                retryable: true,
                reason,
            })) if is_local_control_admission_rejection(true, reason)
        );
        if matches!(
            &result,
            Ok(Ok(dataplane::OpenResult::RenewAcknowledged {
                counter: acknowledged,
            })) if *acknowledged == counter
        ) {
            return true;
        }
        circuit_opens
            .clear(active.link_instance, active.circuit_id)
            .await;
        if retryable_local_admission && attempt + 1 < CONTROL_ADMISSION_RETRY_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1))).await;
            continue;
        }
        break;
    }
    // Renew is an independent confirmation path, not the lease itself. A
    // transient control-stream failure must not interrupt an active circuit;
    // the long lease, authenticated DATA refresh, Link lifecycle, and the
    // bounded source-side failure grace remain the fallbacks for eventual
    // invalidation.
    circuit_opens
        .clear(active.link_instance, active.circuit_id)
        .await;
    false
}

/// Renew the currently published lease and apply the same bounded failure
/// policy from every keepalive path, including migration fallback. The grace
/// record is deliberately tied to both wire identity and the local lease
/// epoch, so a replacement circuit can never inherit an expired deadline.
pub(crate) async fn renew_active_circuit_with_grace(
    context: &CircuitReconcileContext,
    destination: &str,
    grace: &mut Option<RenewalFailureGrace>,
) -> RenewalResult {
    let Some(active) = context
        .circuit_opens
        .active_for_destination(destination)
        .await
    else {
        *grace = None;
        return RenewalResult::Inactive;
    };

    if grace.is_some_and(|current| !current.belongs_to(&active)) {
        *grace = None;
    }
    if grace.is_some_and(|current| renewal_failure_grace_expired(current.deadline, Instant::now()))
    {
        hard_revoke_active_circuit(
            &context.circuit_opens,
            &context.sessions,
            &context.return_flows,
            &context.circuit_dns,
            destination,
            &active,
            &context.links,
            context.source_key.as_ref(),
            &context.supervisor,
            "circuit renewal failure grace expired",
        )
        .await;
        *grace = None;
        return RenewalResult::Revoked;
    }

    let renewed = renew_active_circuit_once(
        context.config.as_ref(),
        destination,
        &context.links,
        &context.circuit_opens,
        context.source_key.as_ref(),
    )
    .await;
    let current = context
        .circuit_opens
        .active_for_destination(destination)
        .await;
    if renewed {
        *grace = None;
        return match current {
            Some(current)
                if current.circuit_id == active.circuit_id
                    && current.lease_epoch == active.lease_epoch =>
            {
                RenewalResult::Acknowledged
            }
            Some(_) => RenewalResult::LeaseChanged,
            None => RenewalResult::Inactive,
        };
    }

    let Some(current) = current else {
        *grace = None;
        return RenewalResult::Inactive;
    };
    if current.circuit_id != active.circuit_id || current.lease_epoch != active.lease_epoch {
        // The failed response belongs to the retired lease. Never charge the
        // replacement circuit against that lease's failure budget.
        *grace = None;
        return RenewalResult::LeaseChanged;
    }
    if grace.is_some_and(|existing| !existing.belongs_to(&current)) {
        *grace = None;
    }
    let current_grace =
        grace.get_or_insert_with(|| RenewalFailureGrace::for_active(&current, Instant::now()));
    if renewal_failure_grace_expired(current_grace.deadline, Instant::now()) {
        hard_revoke_active_circuit(
            &context.circuit_opens,
            &context.sessions,
            &context.return_flows,
            &context.circuit_dns,
            destination,
            &current,
            &context.links,
            context.source_key.as_ref(),
            &context.supervisor,
            "circuit renewal failure grace expired",
        )
        .await;
        *grace = None;
        RenewalResult::Revoked
    } else {
        RenewalResult::FailedWithinGrace
    }
}
