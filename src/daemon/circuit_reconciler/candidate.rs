//! OPEN candidate selection, failure backoff and configured destinations.
use super::*;
pub(crate) struct CandidateFailure {
    pub(crate) retry_at: Instant,
    pub(crate) attempts: u32,
}

pub(crate) fn candidate_failure_delay(destination: &str, attempts: u32) -> std::time::Duration {
    // Keep a failed preferred path from starving a working fallback, while
    // still retrying it after topology/Link changes or a bounded cooldown.
    let base = (1_u64 << attempts.min(6)).min(60);
    let jitter = circuit_open_retry_delay(destination, attempts).as_millis() as u64 % 250;
    std::time::Duration::from_secs(base).saturating_add(std::time::Duration::from_millis(jitter))
}

pub(crate) fn record_candidate_failure(
    failures: &mut HashMap<tinect::reconcile::CircuitIdentity, CandidateFailure>,
    destination: &str,
    identity: tinect::reconcile::CircuitIdentity,
) {
    let attempts = failures
        .get(&identity)
        .map_or(0, |failure| failure.attempts)
        .saturating_add(1);
    failures.insert(
        identity,
        CandidateFailure {
            retry_at: Instant::now() + candidate_failure_delay(destination, attempts),
            attempts,
        },
    );
}

pub(crate) fn desired_resolution_for_candidate(
    resolution: &DestinationResolution,
    candidate: Option<&ResolvedCandidate>,
) -> tinect::reconcile::DesiredResolution {
    let mut desired = resolution.desired.clone();
    if let Some(candidate) = candidate {
        desired.path = Some(candidate.path.clone());
        desired.availability = tinect::reconcile::Availability::Ready;
    } else if resolution.preferred.is_some() {
        desired.path = None;
        desired.availability = tinect::reconcile::Availability::TemporarilyUnavailable {
            reason: "all ready candidates are cooling down after OPEN failure".into(),
            retry_at: unix_now().saturating_add(1),
        };
    }
    desired
}

pub(crate) fn secure_dataplane_required(c: &Config) -> bool {
    !c.route_imports().is_empty()
        || !c.domain_site_ids().is_empty()
        || !c.override_route_prefixes().is_empty()
        || !c.allowed_routes.is_empty()
        || !c.allowed_local_ports.is_empty()
        || c.direct.is_some()
}

pub(crate) fn configured_circuit_destinations(c: &Config) -> HashSet<String> {
    c.peers
        .iter()
        .filter(|(_, peer)| !peer.paths.is_empty())
        .map(|(name, _)| name.clone())
        .chain(c.path_policies.keys().cloned())
        .chain(
            c.route_imports()
                .into_iter()
                .flat_map(|route| route.candidates.into_iter().map(|candidate| candidate.node)),
        )
        .chain(
            c.domain_route_imports()
                .into_iter()
                .flat_map(|route| route.candidates.into_iter().map(|candidate| candidate.node)),
        )
        .collect()
}
