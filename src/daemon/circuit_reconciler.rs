//! Event-driven reconciliation of configured circuits.

use super::circuit_resolution::{
    DestinationResolution, ResolvedCandidate, active_path_has_valid_proof,
    is_configured_circuit_destination, resolve_destination,
};
use super::control_handler::{
    CONTROL_ADMISSION_RETRY_ATTEMPTS, is_local_control_admission,
    is_local_control_admission_rejection, registered_link_by_instance,
    send_control_with_admission_retry,
};
use super::link_helpers::reconnect_jitter_seed;
use super::support::{display_path, observable_name, unix_now, wire_identity};
use anyhow::{Context, Result};
use getrandom::{SysRng, rand_core::UnwrapErr};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
use tinect::{
    config::Config,
    control::ControlMessage,
    dataplane, identity,
    runtime::{DaemonSupervisor, LinkRegistry, Runtime, SharedDaemonState, SharedTopology},
    status::{DaemonState, MigrationState},
};
use x25519_dalek::{PublicKey, StaticSecret};

/// Start the single circuit reconciliation worker for a daemon runtime.
///
/// The worker owns only scheduling and generation bookkeeping. The actual
/// OPEN/renew/revoke operation remains behind the reconciler entry point so
/// control-plane and startup code do not each grow their own copy of the
/// trigger logic.
pub(crate) async fn start(
    runtime: &Runtime,
    key: Arc<ed25519_dalek::SigningKey>,
    supervisor: DaemonSupervisor,
) {
    let context = CircuitReconcileContext::new(runtime, key, supervisor.clone());
    let opens = context.circuit_opens.clone();
    supervisor
        .spawn(async move {
            let mut previous_links = HashSet::new();
            let mut previous_topology_generation = 0;
            let mut previous_open_generation = opens.active_generation();
            loop {
                // Register for topology changes before reading the generation
                // so an update landing between the read and the wait cannot
                // be lost.
                let topology_changed = context.topology.read().await.changed();
                let topology_notified = topology_changed.notified();
                tokio::pin!(topology_notified);
                topology_notified.as_mut().enable();
                let current_links: HashSet<String> = context
                    .links
                    .lock()
                    .expect("link registry lock")
                    .keys()
                    .cloned()
                    .collect();
                let topology_generation = context.topology.read().await.generation();
                let open_generation = opens.active_generation();
                if current_links != previous_links
                    || topology_generation != previous_topology_generation
                    || open_generation != previous_open_generation
                {
                    if let Err(error) = open_configured_circuits(&context).await {
                        tracing::warn!(error = %error, "circuit supervisor failed to reconcile paths");
                    }
                    previous_links = current_links;
                    previous_topology_generation = topology_generation;
                    previous_open_generation = open_generation;
                }
                let generation = opens.active_generation();
                tokio::select! {
                    _ = &mut topology_notified => {}
                    _ = opens.wait_active_change(generation) => {}
                }
            }
        })
        .await;
}
pub(crate) async fn open_configured_circuits(context: &CircuitReconcileContext) -> Result<()> {
    let runtime_config = &context.config;
    let links = &context.links;
    let topology = &context.topology;
    let circuit_opens = &context.circuit_opens;
    let sessions = &context.sessions;
    let circuit_dns = &context.circuit_dns;
    let supervisor = &context.supervisor;
    let source_key = &context.source_key;
    let c = runtime_config.as_ref();
    let destinations = configured_circuit_destinations(c);
    // Configuration removal is an authoritative lifecycle event. Withdraw
    // the locally published snapshot even when CLOSE cannot be delivered;
    // the peer lease remains the crash/loss fallback.
    let source_key = source_key.clone();
    let config_generation = circuit_opens.config_generation();
    let topology_generation = topology.read().await.generation();
    let mut resolutions = HashMap::new();
    for destination in &destinations {
        let active = circuit_opens.active_for_destination(destination).await;
        let resolution = resolve_destination(
            c,
            destination,
            links,
            topology,
            active.as_ref(),
            config_generation,
            topology_generation,
        )
        .await;
        circuit_opens
            .set_desired_resolution(destination.clone(), resolution.desired.clone())
            .await;
        resolutions.insert(destination.clone(), resolution);
    }
    for (destination, active) in circuit_opens.active_circuits().await {
        if active.config_generation != config_generation {
            hard_revoke_active_circuit(
                circuit_opens,
                sessions,
                &context.return_flows,
                circuit_dns,
                &destination,
                &active,
                links,
                &source_key,
                supervisor,
                "authorization configuration generation changed",
            )
            .await;
            continue;
        }
        let active_identity = tinect::reconcile::CircuitIdentity {
            destination: destination.clone(),
            ordered_path: active.path.clone(),
            first_hop_link_instance: active.link_instance,
        };
        if resolutions
            .get(&destination)
            .and_then(|resolution| resolution.desired.identity())
            .as_ref()
            == Some(&active_identity)
        {
            circuit_opens.clear_migration(&destination).await;
            continue;
        }
        // A configured destination with a still-live circuit is a migration,
        // not a withdrawal. Keep the old binding forwarding until the new
        // preferred OPEN has completed; only removed destinations or broken
        // links are withdrawn here.
        if destinations.contains(&destination) {
            if !active_path_has_valid_proof(&active, links, topology).await {
                hard_revoke_active_circuit(
                    circuit_opens,
                    sessions,
                    &context.return_flows,
                    circuit_dns,
                    &destination,
                    &active,
                    links,
                    &source_key,
                    supervisor,
                    "active path proof expired or was removed",
                )
                .await;
            }
            continue;
        }
        hard_revoke_active_circuit(
            circuit_opens,
            sessions,
            &context.return_flows,
            circuit_dns,
            &destination,
            &active,
            links,
            &source_key,
            supervisor,
            "destination was removed from configuration",
        )
        .await;
    }
    for destination in destinations {
        if circuit_opens.desired_is_hard_revoked(&destination).await {
            continue;
        }
        let Some(worker_claim) = circuit_opens.claim_worker(&destination) else {
            continue;
        };
        let worker_context = context.clone();
        let opens = circuit_opens.clone();
        supervisor
            .spawn(async move {
                let result = open_configured_circuit(&worker_context, &destination).await;
                if let Err(error) = result {
                    tracing::warn!(destination = %destination, error = %error, "circuit OPEN worker failed");
                }
                drop(worker_claim);
                opens.request_reconcile();
            })
            .await;
    }
    Ok(())
}
mod candidate;
mod context;
mod migration;
mod open_worker;
mod renewal;
mod retry;
mod revoke;
pub(crate) use candidate::{
    CandidateFailure, configured_circuit_destinations, desired_resolution_for_candidate,
    record_candidate_failure, secure_dataplane_required,
};
pub(crate) use context::CircuitReconcileContext;
pub(crate) use migration::{log_migration_failure, unix_timestamp_secs, update_migration_status};
pub(crate) use open_worker::open_configured_circuit;
pub(crate) use renewal::{RenewalFailureGrace, RenewalResult, renew_active_circuit_with_grace};
// Test-only helpers: the renewal unit tests and the binary's integration
// tests drive these directly. They are unavailable in non-test builds so the
// re-export does not trigger unused-import warnings there.
#[cfg(test)]
pub(crate) use candidate::candidate_failure_delay;
#[cfg(test)]
pub(crate) use renewal::{
    renew_active_circuit_once, renewal_failure_grace_deadline, renewal_failure_grace_expired,
};
pub(crate) use retry::{circuit_open_retry_delay, nonretryable_rejection_wait};
pub(crate) use revoke::hard_revoke_active_circuit;
#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests;
