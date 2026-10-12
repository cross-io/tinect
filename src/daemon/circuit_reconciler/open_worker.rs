//! Per-destination OPEN worker: candidate selection, migration, renewal and retry.
use super::*;
pub(crate) async fn open_configured_circuit(
    context: &CircuitReconcileContext,
    destination: &str,
) -> Result<()> {
    let runtime_config = &context.config;
    let links = &context.links;
    let topology = &context.topology;
    let state = &context.state;
    let circuit_opens = &context.circuit_opens;
    let sessions = &context.sessions;
    let circuit_dns = &context.circuit_dns;
    let key = context.source_key.clone();
    let mut opened = false;
    let mut retry_attempt = 0u32;
    let mut candidate_failures =
        HashMap::<tinect::reconcile::CircuitIdentity, CandidateFailure>::new();
    let mut last_topology_generation = None;
    // A topology Delta can be accepted without changing the selected path.
    // Keep a non-retryable rejection's deadline across those notifications;
    // otherwise every advertisement turns an exponential backoff into a
    // tight OPEN/logging loop. A changed identity still retries immediately.
    let mut nonretryable_rejection =
        None::<(tinect::reconcile::CircuitIdentity, std::time::Instant)>;
    // Preserve the long lease across transient control-plane failures, but
    // keep the source-side failure mode bounded when every Renew/feedback is
    // lost and no authenticated DATA refresh can prove the circuit alive.
    let mut renewal_failure_grace = None::<RenewalFailureGrace>;
    while !opened {
        let config = runtime_config.as_ref();
        if !is_configured_circuit_destination(config, destination) {
            circuit_opens.clear_migration(destination).await;
            circuit_opens.take_rebuild_request(destination).await;
            return Ok(());
        }
        // A sequence-exhausted sender may have requested a rebuild while this
        // worker was between attempts. Consume the request here so a later
        // worker does not inherit an already-handled rebuild trigger.
        circuit_opens.take_rebuild_request(destination).await;
        let c = config;
        let active = circuit_opens.active_for_destination(destination).await;
        if renewal_failure_grace.is_some_and(|grace| {
            active
                .as_ref()
                .is_none_or(|active| !grace.belongs_to(active))
        }) {
            // The previous lease was withdrawn or replaced while this worker
            // was resolving a path. A failure budget is never transferable
            // across CircuitId/lease_epoch boundaries.
            renewal_failure_grace = None;
        }
        let resolution_generation = topology.read().await.generation();
        if last_topology_generation != Some(resolution_generation) {
            candidate_failures.clear();
            last_topology_generation = Some(resolution_generation);
        }
        candidate_failures.retain(|_, failure| failure.retry_at > Instant::now());
        let resolution = resolve_destination(
            c,
            destination,
            links,
            topology,
            active.as_ref(),
            circuit_opens.config_generation(),
            resolution_generation,
        )
        .await;
        // A ready topology proof does not guarantee that OPEN can traverse
        // the complete path. During initial establishment, try the next
        // candidate after a runtime failure. Once an active lease exists, the
        // active worker below owns migration and must not duplicate that
        // already-working path.
        let candidate = if active.is_none() {
            resolution
                .candidates
                .iter()
                .find(|candidate| !candidate_failures.contains_key(&candidate.path.identity()))
                .cloned()
        } else {
            resolution
                .preferred
                .clone()
                .filter(|candidate| !candidate_failures.contains_key(&candidate.path.identity()))
        };
        let desired = if active.is_none() {
            desired_resolution_for_candidate(&resolution, candidate.as_ref())
        } else {
            resolution.desired.clone()
        };
        circuit_opens
            .set_desired_resolution(destination.to_owned(), desired)
            .await;
        let preferred_identity = candidate
            .as_ref()
            .map(|candidate| candidate.path.identity());
        let rejection_identity = nonretryable_rejection
            .as_ref()
            .map(|(identity, _)| identity.clone());
        if rejection_identity
            .as_ref()
            .is_some_and(|identity| preferred_identity.as_ref() != Some(identity))
        {
            // A Link replacement or path change invalidates the remote
            // rejection's context and must be tried without delay.
            nonretryable_rejection = None;
            retry_attempt = 0;
        }
        if let Some(delay) = nonretryable_rejection_wait(
            &mut nonretryable_rejection,
            preferred_identity.as_ref(),
            Instant::now(),
        ) {
            let generation = circuit_opens.active_generation();
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = circuit_opens.wait_active_change(generation) => {}
            }
            continue;
        }
        let has_preferred_candidate = candidate.is_some();
        let migration = circuit_opens.migration_snapshot(destination).await;
        let stale_migration = migration
            .as_ref()
            .and_then(|(identity, started, _)| started.as_ref().map(|_| identity.clone()))
            .is_some_and(|target| {
                resolution
                    .preferred
                    .as_ref()
                    .is_none_or(|candidate| candidate.path.identity() != target)
            });
        if stale_migration {
            // A preferred path can disappear while its migration attempt is
            // waiting for an ACK. Do not keep filtering every retry to that
            // stale path; the current resolver candidates are authoritative.
            circuit_opens.clear_migration(destination).await;
        }
        let migration = if stale_migration { None } else { migration };
        let migration_target = migration
            .as_ref()
            .and_then(|(identity, started, _)| started.map(|_| identity.clone()));
        if let Some((preferred, Some(started), last_error)) = migration.clone()
            && started.elapsed() >= std::time::Duration::from_secs(c.path_migration.deadline_secs)
        {
            update_migration_status(
                state,
                c,
                destination,
                &preferred.ordered_path,
                MigrationState::MigrationOverdue,
                Some(unix_timestamp_secs().saturating_sub(started.elapsed().as_secs())),
                last_error,
            )
            .await;
        }
        if let Some(candidate) = candidate.as_ref() {
            let path = &candidate.path.ordered_path;
            let link = candidate.link.clone();
            let candidate_identity = candidate.path.identity();
            let circuit_id = circuit_opens.next_circuit_id().await;
            let ephemeral = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
            let ephemeral_public_key = PublicKey::from(&ephemeral).to_bytes();
            let destination_key = identity::decode_public(&c.peers[destination].public_key)
                .context("decoding circuit destination key")?;
            let capacity_vector = candidate.path.capacity_vector.clone();
            // Advertise the configured upper ceiling in OPEN.  The current
            // verified path capacity remains the initial send budget, but it
            // may legitimately grow in-place after PMTU convergence; baking
            // the conservative startup capacity into the circuit ceiling
            // would permanently strand the active route at that value.
            let path_inner_mtu = c.tun.mtu;
            let shared =
                ephemeral.diffie_hellman(&tinect::crypto::public_x25519(&destination_key)?);
            let data_key = tinect::crypto::derive_key(
                shared.as_bytes(),
                &key.verifying_key(),
                &destination_key,
                circuit_id,
                &ephemeral_public_key,
            );
            let request = tinect::circuit::OpenRequest::new(
                identity::node_id(&key.verifying_key()),
                &key,
                wire_identity(c, destination).expect("configured destination"),
                path.clone(),
                circuit_id,
                ephemeral_public_key,
            );
            let attempt = match circuit_opens
                .begin_attempt_with_capacity(dataplane::OpenAttemptInput {
                    destination: destination.to_owned(),
                    circuit_id: request.circuit_id,
                    identity: tinect::reconcile::CircuitIdentity {
                        destination: destination.to_owned(),
                        ordered_path: path.clone(),
                        first_hop_link_instance: link.instance(),
                    },
                    config_generation: circuit_opens.config_generation(),
                    link_instance: link.instance(),
                    capacity_vector,
                    route_overrides: c.route_overrides_for_wire(destination, path),
                })
                .await
            {
                Some(attempt) => attempt,
                None => continue,
            };
            let waiter = circuit_opens
                .register_for_attempt(
                    &attempt,
                    c.peers[destination].public_key.clone(),
                    path.iter()
                        .filter_map(|node| c.peer_by_identity(node))
                        .map(|peer| peer.public_key.clone())
                        .collect(),
                    link.lifecycle_token(),
                )
                .await;
            let open_message = ControlMessage::Open(request.clone());
            if let Err(error) =
                send_control_with_admission_retry(link.as_ref(), &open_message).await
            {
                circuit_opens
                    .clear(link.instance(), request.circuit_id)
                    .await;
                circuit_opens.cancel_attempt(&attempt).await;
                let local_admission = is_local_control_admission(&error);
                if !local_admission {
                    record_candidate_failure(
                        &mut candidate_failures,
                        destination,
                        candidate_identity.clone(),
                    );
                    tracing::warn!(dst = %destination, error = %error, "circuit OPEN send failed");
                } else {
                    tracing::debug!(
                        dst = %destination,
                        error = %error,
                        "circuit OPEN send deferred by local control admission"
                    );
                }
                if migration_target.is_some() {
                    let _ = renew_active_circuit_with_grace(
                        context,
                        destination,
                        &mut renewal_failure_grace,
                    )
                    .await;
                }
                if migration_target.is_some() && !local_admission {
                    let reason = format!("OPEN send failed: {error}");
                    circuit_opens
                        .migration_error(destination, reason.clone())
                        .await;
                    log_migration_failure(c, destination, circuit_opens, &reason).await;
                    if let Some((preferred, Some(started), _)) =
                        circuit_opens.migration_snapshot(destination).await
                    {
                        let state_name = if started.elapsed()
                            >= std::time::Duration::from_secs(c.path_migration.deadline_secs)
                        {
                            MigrationState::MigrationOverdue
                        } else {
                            MigrationState::MigrationPending
                        };
                        update_migration_status(
                            state,
                            c,
                            destination,
                            &preferred.ordered_path,
                            state_name,
                            Some(unix_timestamp_secs().saturating_sub(started.elapsed().as_secs())),
                            Some(reason),
                        )
                        .await;
                    }
                }
                // RFC-0008: OPEN failures use bounded exponential backoff.
                // A local RFC-0017 admission rejection is transient
                // backpressure; retrying instantly would only deepen the
                // queue and starve the whole control plane.
                let backoff = circuit_open_retry_delay(destination, retry_attempt);
                retry_attempt = retry_attempt.saturating_add(1);
                tokio::time::sleep(backoff).await;
                continue;
            }
            let ack_timeout = if migration_target.is_some() {
                circuit_opens
                    .migration_snapshot(destination)
                    .await
                    .and_then(|(_, started, _)| started)
                    .map(|started| {
                        std::time::Duration::from_secs(c.path_migration.deadline_secs)
                            .saturating_sub(started.elapsed())
                            .min(std::time::Duration::from_secs(5))
                    })
                    .unwrap_or_else(|| std::time::Duration::from_secs(5))
            } else {
                std::time::Duration::from_secs(5)
            };
            match tokio::time::timeout(ack_timeout, waiter).await {
                Ok(Ok(dataplane::OpenResult::Acknowledged)) => {
                    let old_active = circuit_opens.active_for_destination(destination).await;
                    if let Err(error) = circuit_opens
                        .commit_if_current(&attempt, data_key, path.clone(), path_inner_mtu)
                        .await
                    {
                        circuit_opens.cancel_attempt(&attempt).await;
                        circuit_opens
                            .deactivate(destination, request.circuit_id)
                            .await;
                        let close = ControlMessage::circuit_close(&key, request.circuit_id, 1, 1);
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(1),
                            link.send_control(&close),
                        )
                        .await;
                        tracing::debug!(dst = %destination, ?error, "discarded stale circuit OPEN acknowledgement");
                        continue;
                    }
                    candidate_failures.remove(&candidate_identity);
                    if c.fake_ip.is_some() {
                        sessions
                            .install_return(
                                link.instance(),
                                request.circuit_id,
                                identity::decode_public(
                                    &c.peers
                                        .get(destination)
                                        .expect("configured circuit destination")
                                        .public_key,
                                )
                                .expect("validated circuit destination key"),
                                data_key,
                            )
                            .await;
                    }
                    if let Some(old) = old_active
                        && old.circuit_id != request.circuit_id
                    {
                        // The active reference has already switched atomically;
                        // retain the remote binding for the bounded drain
                        // window so in-flight datagrams can finish without
                        // extending the old route's lifetime indefinitely.
                        tokio::time::sleep(std::time::Duration::from_secs(
                            c.path_migration.drain_timeout_secs,
                        ))
                        .await;
                        let old_link = registered_link_by_instance(links, old.link_instance);
                        if let Some(old_link) = old_link {
                            let close = ControlMessage::circuit_close(&key, old.circuit_id, 1, 1);
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(1),
                                old_link.send_control(&close),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => {
                                    tracing::debug!(dst = %destination, error = %error, "old circuit CLOSE could not be delivered after migration")
                                }
                                Err(_) => {
                                    tracing::debug!(dst = %destination, "old circuit CLOSE timed out after migration")
                                }
                            }
                        }
                        circuit_opens.deactivate(destination, old.circuit_id).await;
                        sessions
                            .remove_circuit(old.link_instance, old.circuit_id)
                            .await;
                        context
                            .return_flows
                            .remove_circuit(old.link_instance, old.circuit_id);
                        circuit_dns.remove_circuit(old.link_instance, old.circuit_id);
                    }
                    circuit_opens.clear_migration(destination).await;
                    // A committed OPEN always owns a fresh lease epoch. Do
                    // not carry a failure budget from a retired circuit or
                    // an earlier migration attempt into this lease.
                    renewal_failure_grace = None;
                    tracing::info!(dst = %destination, path = %display_path(c, path), "circuit OPEN acknowledged");
                    if let Some(circuit) = state
                        .write()
                        .await
                        .status
                        .circuits
                        .iter_mut()
                        .find(|circuit| circuit.destination == destination)
                    {
                        circuit.active_path = path.clone();
                        circuit.active_path_names = path
                            .iter()
                            .map(|identity| observable_name(c, identity))
                            .collect();
                        circuit.healthy = true;
                        circuit.migration_state = MigrationState::Stable;
                        circuit.preferred_path = path.clone();
                        circuit.preferred_path_names = path
                            .iter()
                            .map(|identity| observable_name(c, identity))
                            .collect();
                        circuit.migration_started_at = None;
                        circuit.migration_last_error = None;
                    }
                    // Keep the per-destination worker alive while the
                    // circuit is active. An idle circuit proves liveness by
                    // a signed renewal every 30 seconds; any failure first
                    // retracts its snapshot and then falls back into the
                    // normal persistent OPEN reconciliation loop.
                    let topology_changed = topology.read().await.changed();
                    // RENEW is a protocol timer with an absolute deadline:
                    // frequent topology or lifecycle events must not postpone
                    // it forever by rebuilding a relative sleep every round.
                    let mut next_renewal =
                        std::time::Instant::now() + tinect::circuit::circuit_renew_interval();
                    loop {
                        let config = runtime_config.as_ref();
                        if !is_configured_circuit_destination(config, destination) {
                            circuit_opens.clear_migration(destination).await;
                            circuit_opens.take_rebuild_request(destination).await;
                            opened = false;
                            break;
                        }
                        let c = config;
                        if circuit_opens.take_rebuild_request(destination).await {
                            opened = false;
                            break;
                        }
                        // Snapshot the generation before reading `active`.
                        // If a Link teardown races this loop, either the
                        // subsequent state read sees the withdrawal, or the
                        // waiter observes a newer generation. Reversing
                        // these two reads can miss the withdrawal forever.
                        let active_generation = circuit_opens.active_generation();
                        if !circuit_opens
                            .is_active(destination, request.circuit_id)
                            .await
                        {
                            opened = false;
                            break;
                        }
                        if circuit_opens.config_generation() != attempt.config_generation {
                            // A newer authorization generation invalidates
                            // this worker's context. Leave the active lease in
                            // place so the single-worker reconciler can retire
                            // it safely, but never renew with a stale view.
                            opened = false;
                            break;
                        }
                        // Register before resolving so a topology update that
                        // lands while we compute the capacity vector cannot
                        // be missed; the select below then observes it as an
                        // immediate readiness instead of waiting for the next
                        // renewal tick.
                        let topology_notified = topology_changed.notified();
                        tokio::pin!(topology_notified);
                        topology_notified.as_mut().enable();
                        let active = circuit_opens.active_for_destination(destination).await;
                        let resolution_generation = topology.read().await.generation();
                        let resolution = resolve_destination(
                            c,
                            destination,
                            links,
                            topology,
                            active.as_ref(),
                            circuit_opens.config_generation(),
                            resolution_generation,
                        )
                        .await;
                        if last_topology_generation != Some(resolution_generation) {
                            candidate_failures.clear();
                            last_topology_generation = Some(resolution_generation);
                        }
                        candidate_failures.retain(|_, failure| failure.retry_at > Instant::now());
                        let selected_candidate = resolution
                            .candidates
                            .iter()
                            .find(|candidate| {
                                !candidate_failures.contains_key(&candidate.path.identity())
                            })
                            .cloned();
                        let desired = selected_candidate.as_ref().map_or_else(
                            || resolution.desired.clone(),
                            |candidate| {
                                desired_resolution_for_candidate(&resolution, Some(candidate))
                            },
                        );
                        circuit_opens
                            .set_desired_resolution(destination.to_owned(), desired)
                            .await;
                        let mut migration_ready_at = None;
                        if let Some(preferred_candidate) = selected_candidate.as_ref() {
                            let preferred_resolution = &preferred_candidate.path;
                            let preferred = &preferred_resolution.ordered_path;
                            let preferred_identity = preferred_resolution.identity();
                            let active_identity = tinect::reconcile::CircuitIdentity {
                                destination: destination.to_owned(),
                                ordered_path: path.clone(),
                                first_hop_link_instance: link.instance(),
                            };
                            if preferred_identity == active_identity {
                                circuit_opens.clear_migration(destination).await;
                            } else if let Some(readiness) = circuit_opens
                                .migration_readiness(
                                    destination,
                                    &preferred_identity,
                                    true,
                                    std::time::Duration::from_secs(
                                        c.path_migration.readiness_stability_secs,
                                    ),
                                )
                                .await
                            {
                                match readiness {
                                    dataplane::MigrationReadiness::Ready => {
                                        let started =
                                            circuit_opens.begin_migration(destination).await;
                                        update_migration_status(
                                            state,
                                            c,
                                            destination,
                                            preferred,
                                            MigrationState::MigrationPending,
                                            started.map(|_| unix_timestamp_secs()),
                                            None,
                                        )
                                        .await;
                                        tracing::info!(
                                            dst = %destination,
                                            current = %display_path(c, path),
                                            preferred = %display_path(c, preferred),
                                            migration_started_at = started.map(|_| unix_timestamp_secs()).unwrap_or_default(),
                                            "preferred path ready; starting bounded circuit migration"
                                        );
                                        opened = false;
                                        break;
                                    }
                                    dataplane::MigrationReadiness::PendingUntil(deadline) => {
                                        migration_ready_at = Some(deadline);
                                    }
                                    dataplane::MigrationReadiness::Pending => {}
                                }
                            }
                        } else {
                            circuit_opens.reset_migration_readiness(destination).await;
                        }
                        if let Some(deadline) = migration_ready_at {
                            tokio::select! {
                                // A topology change can affect path preference
                                // and proof validity even when the active Link
                                // stays up, so re-resolve on the event rather
                                // than on the renewal cadence.
                                _ = &mut topology_notified => {
                                    continue;
                                }
                                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(
                                    next_renewal,
                                )) => {
                                    next_renewal = std::time::Instant::now()
                                        + tinect::circuit::circuit_renew_interval();
                                }
                                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => continue,
                                _ = circuit_opens.wait_active_change(active_generation) => {
                                    if !circuit_opens.is_active(destination, request.circuit_id).await {
                                        opened = false;
                                        break;
                                    }
                                    continue;
                                }
                            }
                        } else {
                            tokio::select! {
                                _ = &mut topology_notified => {
                                    continue;
                                }
                                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(
                                    next_renewal,
                                )) => {
                                    next_renewal = std::time::Instant::now()
                                        + tinect::circuit::circuit_renew_interval();
                                }
                                _ = circuit_opens.wait_active_change(active_generation) => {
                                    if !circuit_opens.is_active(destination, request.circuit_id).await {
                                        opened = false;
                                        break;
                                    }
                                    continue;
                                }
                            }
                        }
                        if !circuit_opens
                            .is_active(destination, request.circuit_id)
                            .await
                        {
                            // Configuration/topology reconciliation withdrew
                            // this snapshot and sent CLOSE if possible.
                            opened = false;
                            break;
                        }
                        match renew_active_circuit_with_grace(
                            context,
                            destination,
                            &mut renewal_failure_grace,
                        )
                        .await
                        {
                            RenewalResult::Acknowledged => {
                                tracing::info!(dst = %destination, "circuit renewal acknowledged");
                                continue;
                            }
                            RenewalResult::LeaseChanged => {
                                tracing::debug!(
                                    dst = %destination,
                                    "circuit renewal completed while the active lease was replaced"
                                );
                                continue;
                            }
                            RenewalResult::Revoked | RenewalResult::Inactive => {
                                opened = false;
                                break;
                            }
                            RenewalResult::FailedWithinGrace => {
                                tracing::debug!(
                                    dst = %destination,
                                    "circuit renewal pending; retaining active lease"
                                );
                                continue;
                            }
                        }
                    }
                }
                Ok(Ok(dataplane::OpenResult::RenewAcknowledged { .. })) => {
                    // A RenewAck can never satisfy an OPEN waiter. This is
                    // defensive handling for a future waiter implementation
                    // change: retire the attempt and its remote binding.
                    circuit_opens.cancel_attempt(&attempt).await;
                    circuit_opens
                        .clear(link.instance(), request.circuit_id)
                        .await;
                    let close = ControlMessage::circuit_close(&key, request.circuit_id, 1, 1);
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        link.send_control(&close),
                    )
                    .await;
                    tracing::debug!(dst = %destination, "discarded circuit OPEN waiter matched by a RENEW acknowledgement");
                }
                Ok(Ok(dataplane::OpenResult::Rejected { retryable, reason })) => {
                    circuit_opens.cancel_attempt(&attempt).await;
                    let local_admission = is_local_control_admission_rejection(retryable, &reason);
                    if !local_admission {
                        record_candidate_failure(
                            &mut candidate_failures,
                            destination,
                            candidate_identity.clone(),
                        );
                        tracing::warn!(dst = %destination, retryable, reason, "circuit OPEN rejected");
                    } else {
                        tracing::debug!(
                            dst = %destination,
                            retryable,
                            reason,
                            "circuit OPEN deferred by relay control admission"
                        );
                    }
                    if migration_target.is_some() {
                        let _ = renew_active_circuit_with_grace(
                            context,
                            destination,
                            &mut renewal_failure_grace,
                        )
                        .await;
                    }
                    if migration_target.is_some() && !local_admission {
                        circuit_opens
                            .migration_error(destination, reason.clone())
                            .await;
                        log_migration_failure(c, destination, circuit_opens, &reason).await;
                        if let Some((preferred, Some(started), _)) =
                            circuit_opens.migration_snapshot(destination).await
                        {
                            let state_name = if started.elapsed()
                                >= std::time::Duration::from_secs(c.path_migration.deadline_secs)
                            {
                                MigrationState::MigrationOverdue
                            } else {
                                MigrationState::MigrationPending
                            };
                            update_migration_status(
                                state,
                                c,
                                destination,
                                &preferred.ordered_path,
                                state_name,
                                Some(
                                    unix_timestamp_secs()
                                        .saturating_sub(started.elapsed().as_secs()),
                                ),
                                Some(reason.clone()),
                            )
                            .await;
                        }
                    }
                    if !retryable {
                        nonretryable_rejection = Some((
                            candidate.path.identity(),
                            Instant::now() + circuit_open_retry_delay(destination, retry_attempt),
                        ));
                        retry_attempt = retry_attempt.saturating_add(1);
                        continue;
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    circuit_opens.cancel_attempt(&attempt).await;
                    circuit_opens
                        .clear(link.instance(), request.circuit_id)
                        .await;
                    record_candidate_failure(
                        &mut candidate_failures,
                        destination,
                        candidate_identity,
                    );
                    let close = ControlMessage::circuit_close(&key, request.circuit_id, 1, 1);
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        link.send_control(&close),
                    )
                    .await;
                    tracing::warn!(dst = %destination, "circuit OPEN acknowledgement timed out");
                    if migration_target.is_some() {
                        let _ = renew_active_circuit_with_grace(
                            context,
                            destination,
                            &mut renewal_failure_grace,
                        )
                        .await;
                        let reason = "OpenAck timeout".to_owned();
                        circuit_opens
                            .migration_error(destination, reason.clone())
                            .await;
                        log_migration_failure(c, destination, circuit_opens, &reason).await;
                        if let Some((preferred, Some(started), _)) =
                            circuit_opens.migration_snapshot(destination).await
                        {
                            let state_name = if started.elapsed()
                                >= std::time::Duration::from_secs(c.path_migration.deadline_secs)
                            {
                                MigrationState::MigrationOverdue
                            } else {
                                MigrationState::MigrationPending
                            };
                            update_migration_status(
                                state,
                                c,
                                destination,
                                &preferred.ordered_path,
                                state_name,
                                Some(
                                    unix_timestamp_secs()
                                        .saturating_sub(started.elapsed().as_secs()),
                                ),
                                Some(reason),
                            )
                            .await;
                        }
                    }
                }
            }
        }
        if candidate.is_none() && migration_target.is_some() {
            // A failed preferred OPEN must not make the old active lease go
            // quiet while its candidate quarantine is in effect. The shared
            // renewal counter also prevents a later renewal from being
            // rejected as a replay.
            let _ =
                renew_active_circuit_with_grace(context, destination, &mut renewal_failure_grace)
                    .await;
        }
        if opened {
            break;
        }
        if !has_preferred_candidate {
            tracing::debug!(destination = %destination, "Circuit topology currently has no usable path; continuing reconciliation");
        }
        let generation = circuit_opens.active_generation();
        let delay = circuit_open_retry_delay(destination, retry_attempt).min(
            migration_target
                .as_ref()
                .map_or(std::time::Duration::from_secs(60), |_| {
                    std::time::Duration::from_secs(1)
                }),
        );
        tokio::select! {
            _ = tokio::time::sleep(delay) => {
                retry_attempt = retry_attempt.saturating_add(1);
            }
            _ = circuit_opens.wait_active_change(generation) => {
                // Link/configuration lifecycle changes invalidate the old
                // backoff calculation. Re-resolve the path immediately.
                retry_attempt = 0;
            }
        }
    }
    Ok(())
}
