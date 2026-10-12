//! Pure state used by the declarative circuit reconciler.
//!
//! This module deliberately contains no sockets, timers, or platform calls.
//! It is the vocabulary shared by path resolution, lease publication, and
//! model tests.  In particular, topology freshness and capacity versions are
//! represented separately from the circuit identity.

use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CircuitIdentity {
    pub destination: String,
    pub ordered_path: Vec<String>,
    pub first_hop_link_instance: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityEdge {
    pub from: String,
    pub to: String,
    pub capacity: u16,
    pub generation: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapacityVector {
    pub edges: Vec<CapacityEdge>,
}

impl CapacityVector {
    pub fn capacity(&self) -> Option<u16> {
        self.edges.iter().map(|edge| edge.capacity).min()
    }

    pub fn is_well_formed(&self) -> bool {
        self.edges.iter().enumerate().all(|(index, edge)| {
            self.edges[index + 1..]
                .iter()
                .all(|other| edge.from != other.from || edge.to != other.to)
        })
    }

    pub fn generation_for(&self, from: &str, to: &str) -> Option<u64> {
        self.edges
            .iter()
            .find(|edge| edge.from == from && edge.to == to)
            .map(|edge| edge.generation)
    }

    pub fn matches_path(&self, path: &[String]) -> bool {
        self.edges.len() == path.len().saturating_sub(1)
            && self
                .edges
                .iter()
                .zip(path.windows(2))
                .all(|(edge, hops)| edge.from == hops[0] && edge.to == hops[1])
    }

    /// Return whether `next` is not older than this vector on any edge.  A
    /// vector with an equal generation but a different capacity is rejected:
    /// the generation is the semantic tie-breaker, so accepting that update
    /// would make an old asynchronous event able to rewrite a newer budget.
    pub fn accepts_update(&self, next: &Self) -> bool {
        if !self.is_well_formed() || !next.is_well_formed() {
            return false;
        }
        // A vector is bound to the CircuitIdentity's ordered path.  Do not
        // let a partial or differently-shaped snapshot drop a low-capacity
        // edge and thereby raise the budget for the same lease.
        if !self.edges.is_empty()
            && (self.edges.len() != next.edges.len()
                || self.edges.iter().any(|current| {
                    !next
                        .edges
                        .iter()
                        .any(|incoming| incoming.from == current.from && incoming.to == current.to)
                }))
        {
            return false;
        }
        next.edges.iter().all(|incoming| {
            self.edges
                .iter()
                .find(|current| current.from == incoming.from && current.to == incoming.to)
                .is_none_or(|current| {
                    incoming.generation > current.generation
                        || (incoming.generation == current.generation
                            && incoming.capacity == current.capacity)
                })
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    pub destination: String,
    pub ordered_path: Vec<String>,
    pub first_hop_link_instance: u64,
    pub candidate_rank: usize,
    /// Verified end-to-end capacity for complete user IP packets, excluding
    /// Tinect and carrier encapsulation.
    pub verified_inner_mtu: u16,
    pub capacity_vector: CapacityVector,
    pub proof_valid_until: u64,
}

impl ResolvedPath {
    pub fn identity(&self) -> CircuitIdentity {
        CircuitIdentity {
            destination: self.destination.clone(),
            ordered_path: self.ordered_path.clone(),
            first_hop_link_instance: self.first_hop_link_instance,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Ready,
    ProofStale { valid_until: u64 },
    TemporarilyUnavailable { reason: String, retry_at: u64 },
    HardRevoked { generation: u64, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileState {
    NoActive,
    Opening,
    Stable,
    Preparing,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredResolution {
    pub generation: u64,
    pub config_generation: u64,
    pub path: Option<ResolvedPath>,
    pub availability: Availability,
    pub resolved_at: SystemTime,
}

impl DesiredResolution {
    pub fn identity(&self) -> Option<CircuitIdentity> {
        self.path.as_ref().map(ResolvedPath::identity)
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.availability, Availability::Ready)
    }
}

pub fn next_state(
    active_identity: Option<&CircuitIdentity>,
    desired: &DesiredResolution,
    active_proof_valid: bool,
) -> ReconcileState {
    let Some(active_identity) = active_identity else {
        return if desired.is_ready() && desired.path.is_some() {
            ReconcileState::Opening
        } else {
            ReconcileState::NoActive
        };
    };
    if matches!(desired.availability, Availability::HardRevoked { .. }) {
        return ReconcileState::NoActive;
    }
    if desired.identity().as_ref() == Some(active_identity) {
        return match desired.availability {
            Availability::Ready => ReconcileState::Stable,
            Availability::ProofStale { .. } | Availability::TemporarilyUnavailable { .. } => {
                if active_proof_valid {
                    ReconcileState::Degraded
                } else {
                    ReconcileState::NoActive
                }
            }
            Availability::HardRevoked { .. } => ReconcileState::NoActive,
        };
    }
    match desired.availability {
        Availability::Ready if desired.path.is_some() => ReconcileState::Preparing,
        Availability::ProofStale { .. } | Availability::TemporarilyUnavailable { .. } => {
            if active_proof_valid {
                ReconcileState::Degraded
            } else {
                ReconcileState::NoActive
            }
        }
        Availability::Ready | Availability::HardRevoked { .. } => ReconcileState::NoActive,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_vector_is_not_part_of_circuit_identity() {
        let first = ResolvedPath {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "relay".into(), "exit".into()],
            first_hop_link_instance: 7,
            candidate_rank: 0,
            verified_inner_mtu: 1200,
            capacity_vector: CapacityVector {
                edges: vec![CapacityEdge {
                    from: "relay".into(),
                    to: "exit".into(),
                    capacity: 1200,
                    generation: 1,
                }],
            },
            proof_valid_until: 100,
        };
        let mut second = first.clone();
        second.verified_inner_mtu = 1400;
        second.capacity_vector.edges[0].capacity = 1400;
        second.capacity_vector.edges[0].generation = 2;
        assert_eq!(first.identity(), second.identity());
    }

    #[test]
    fn hard_revoke_is_distinct_from_temporary_unavailability() {
        let hard = Availability::HardRevoked {
            generation: 4,
            reason: "link closed".into(),
        };
        let temporary = Availability::TemporarilyUnavailable {
            reason: "waiting for topology".into(),
            retry_at: 10,
        };
        assert_ne!(hard, temporary);
    }

    #[test]
    fn reconcile_states_keep_capacity_changes_outside_identity_transitions() {
        let path = ResolvedPath {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 1,
            candidate_rank: 0,
            verified_inner_mtu: 1200,
            capacity_vector: CapacityVector::default(),
            proof_valid_until: 100,
        };
        let resolution = DesiredResolution {
            generation: 1,
            config_generation: 1,
            path: Some(path.clone()),
            availability: Availability::Ready,
            resolved_at: SystemTime::now(),
        };
        assert_eq!(
            next_state(Some(&path.identity()), &resolution, true),
            ReconcileState::Stable
        );
        let mut capacity_only = resolution.clone();
        capacity_only.generation = 2;
        capacity_only.path.as_mut().unwrap().verified_inner_mtu = 1400;
        assert_eq!(
            next_state(Some(&path.identity()), &capacity_only, true),
            ReconcileState::Stable
        );
    }

    #[test]
    fn proof_stale_degrades_only_while_the_active_proof_is_valid() {
        let path = ResolvedPath {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "relay".into(), "exit".into()],
            first_hop_link_instance: 9,
            candidate_rank: 0,
            verified_inner_mtu: 1200,
            capacity_vector: CapacityVector::default(),
            proof_valid_until: 100,
        };
        let desired = DesiredResolution {
            generation: 2,
            config_generation: 1,
            path: Some(path.clone()),
            availability: Availability::ProofStale { valid_until: 100 },
            resolved_at: SystemTime::now(),
        };
        assert_eq!(
            next_state(Some(&path.identity()), &desired, true),
            ReconcileState::Degraded
        );
        assert_eq!(
            next_state(Some(&path.identity()), &desired, false),
            ReconcileState::NoActive
        );
    }

    #[test]
    fn capacity_vector_rejects_older_generation_and_equal_generation_conflict() {
        let current = CapacityVector {
            edges: vec![CapacityEdge {
                from: "a".into(),
                to: "b".into(),
                capacity: 1200,
                generation: 4,
            }],
        };
        assert!(!current.accepts_update(&CapacityVector {
            edges: vec![CapacityEdge {
                from: "a".into(),
                to: "b".into(),
                capacity: 1300,
                generation: 3,
            }],
        }));
        assert!(!current.accepts_update(&CapacityVector {
            edges: vec![CapacityEdge {
                from: "a".into(),
                to: "b".into(),
                capacity: 1300,
                generation: 4,
            }],
        }));
        assert!(current.accepts_update(&CapacityVector {
            edges: vec![CapacityEdge {
                from: "a".into(),
                to: "b".into(),
                capacity: 1300,
                generation: 5,
            }],
        }));
        assert!(!current.accepts_update(&CapacityVector { edges: vec![] }));
        assert!(!current.accepts_update(&CapacityVector {
            edges: vec![current.edges[0].clone(), current.edges[0].clone()],
        }));
    }

    #[test]
    fn capacity_and_state_helpers_cover_empty_partial_and_changed_paths() {
        let empty = CapacityVector::default();
        assert_eq!(empty.capacity(), None);
        assert_eq!(empty.generation_for("a", "b"), None);
        assert!(empty.matches_path(&["a".into()]));
        let edge = CapacityEdge {
            from: "a".into(),
            to: "b".into(),
            capacity: 1200,
            generation: 1,
        };
        let current = CapacityVector {
            edges: vec![edge.clone()],
        };
        assert_eq!(current.capacity(), Some(1200));
        assert_eq!(current.generation_for("a", "b"), Some(1));
        assert!(!current.matches_path(&["a".into(), "c".into()]));
        assert!(empty.accepts_update(&current));
        assert!(current.accepts_update(&current));
        assert!(!current.accepts_update(&CapacityVector {
            edges: vec![CapacityEdge {
                from: "a".into(),
                to: "c".into(),
                capacity: 1200,
                generation: 2,
            }],
        }));

        let path = ResolvedPath {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 1,
            candidate_rank: 0,
            verified_inner_mtu: 1200,
            capacity_vector: empty,
            proof_valid_until: 100,
        };
        let identity = path.identity();
        let ready = DesiredResolution {
            generation: 1,
            config_generation: 1,
            path: Some(path.clone()),
            availability: Availability::Ready,
            resolved_at: SystemTime::now(),
        };
        assert!(ready.is_ready());
        assert_eq!(ready.identity(), Some(identity.clone()));
        assert_eq!(next_state(None, &ready, false), ReconcileState::Opening);
        let temporary = DesiredResolution {
            path: None,
            availability: Availability::TemporarilyUnavailable {
                reason: "no topology".into(),
                retry_at: 9,
            },
            ..ready.clone()
        };
        assert!(!temporary.is_ready());
        assert_eq!(temporary.identity(), None);
        assert_eq!(
            next_state(None, &temporary, false),
            ReconcileState::NoActive
        );
        assert_eq!(
            next_state(
                Some(&identity),
                &DesiredResolution {
                    path: None,
                    availability: Availability::HardRevoked {
                        generation: 2,
                        reason: "closed".into(),
                    },
                    ..ready.clone()
                },
                true,
            ),
            ReconcileState::NoActive
        );
        let changed = CircuitIdentity {
            first_hop_link_instance: 2,
            ..identity.clone()
        };
        assert_eq!(
            next_state(Some(&changed), &ready, true),
            ReconcileState::Preparing
        );
        let changed_stale = DesiredResolution {
            availability: Availability::ProofStale { valid_until: 5 },
            ..ready
        };
        assert_eq!(
            next_state(Some(&changed), &changed_stale, true),
            ReconcileState::Degraded
        );
        assert_eq!(
            next_state(Some(&changed), &changed_stale, false),
            ReconcileState::NoActive
        );
    }
}
