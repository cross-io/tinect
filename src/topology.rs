//! Signed link-state advertisements and deterministic constrained path search.
//! The topology database is intentionally independent from the carrier so it
//! can be tested without sockets and reused by future management APIs.
use crate::identity::{decode_public, encode_public, node_id};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::Notify;

pub const MAX_NEIGHBORS_PER_LSA: usize = 1024;

fn node_bytes(value: &str) -> [u8; 16] {
    let mut out = [0; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("node id");
    }
    out
}
fn node_string(bytes: [u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkMetric {
    pub node: String,
    #[serde(default = "default_cost")]
    pub cost: u32,
    /// Maximum complete user IP packet this node can currently send to `node`.
    /// This is directional and already excludes Tinect's DATA and Physical
    /// Forward envelopes. Carrier-specific headers are normalized by Link.
    pub inner_mtu: u16,
}

fn default_cost() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkStateAdvertisement {
    pub origin: String,
    pub sequence: u64,
    pub expires_at: u64,
    pub neighbors: Vec<LinkMetric>,
    pub public_key: String,
    pub signature: String,
}

impl LinkStateAdvertisement {
    pub fn new(
        origin: impl Into<String>,
        key: &ed25519_dalek::SigningKey,
        sequence: u64,
        expires_at: u64,
        neighbors: Vec<LinkMetric>,
    ) -> Self {
        let mut advertisement = Self {
            origin: origin.into(),
            sequence,
            expires_at,
            neighbors,
            public_key: encode_public(&key.verifying_key()),
            signature: String::new(),
        };
        advertisement.signature =
            STANDARD_NO_PAD.encode(key.sign(&advertisement.signing_bytes()).to_bytes());
        advertisement
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = crate::wire::Writer::new();
        out.bytes(&node_bytes(&self.origin));
        out.u64(self.sequence);
        out.u64(self.expires_at);
        out.u16(u16::try_from(self.neighbors.len()).expect("wire-sized neighbors"));
        for neighbor in &self.neighbors {
            out.bytes(&node_bytes(&neighbor.node));
            out.u32(neighbor.cost);
            out.u16(neighbor.inner_mtu);
        }
        out.bytes(
            &STANDARD_NO_PAD
                .decode(&self.public_key)
                .expect("public key"),
        );
        out.finish()
    }

    pub fn verify(&self) -> Result<(), TopologyError> {
        let key = decode_public(&self.public_key)
            .map_err(|error| TopologyError::Signature(error.to_string()))?;
        let raw = STANDARD_NO_PAD
            .decode(&self.signature)
            .map_err(|error| TopologyError::Signature(error.to_string()))?;
        let signature = ed25519_dalek::Signature::from_slice(&raw)
            .map_err(|error| TopologyError::Signature(error.to_string()))?;
        key.verify(&self.signing_bytes(), &signature)
            .map_err(|error| TopologyError::Signature(error.to_string()))
    }
    pub fn encode_wire(&self, out: &mut crate::wire::Writer) -> Result<(), crate::wire::Error> {
        out.bytes(&self.signing_bytes());
        out.bytes(
            &STANDARD_NO_PAD
                .decode(&self.signature)
                .map_err(|_| crate::wire::Error::Truncated)?,
        );
        Ok(())
    }
    pub fn decode_wire(input: &mut crate::wire::Reader<'_>) -> Result<Self, crate::wire::Error> {
        let origin = node_string(input.fixed()?);
        let sequence = input.u64()?;
        let expires_at = input.u64()?;
        let count = usize::from(input.u16()?);
        if count > MAX_NEIGHBORS_PER_LSA {
            return Err(crate::wire::Error::Length);
        }
        let mut neighbors = Vec::with_capacity(count);
        for _ in 0..count {
            neighbors.push(LinkMetric {
                node: node_string(input.fixed()?),
                cost: input.u32()?,
                inner_mtu: input.u16()?,
            });
        }
        let public_key = STANDARD_NO_PAD.encode(input.fixed::<32>()?);
        let signature = STANDARD_NO_PAD.encode(input.fixed::<64>()?);
        Ok(Self {
            origin,
            sequence,
            expires_at,
            neighbors,
            public_key,
            signature,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathConstraint {
    #[serde(default)]
    pub prefer_via: Vec<String>,
    #[serde(default)]
    pub require_via: Vec<String>,
    #[serde(default)]
    pub avoid: Vec<String>,
    #[serde(default)]
    pub max_hops: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputedPath {
    pub nodes: Vec<String>,
    pub cost: u64,
}

#[derive(Clone, Default)]
pub struct Topology {
    advertisements: HashMap<String, LinkStateAdvertisement>,
    /// Monotonic semantic versions for directional confirmed capacities.
    /// These versions intentionally survive LSA refreshes and expiry so an
    /// old asynchronous capacity event can never move a path budget back.
    capacity_generations: HashMap<(String, String), u64>,
    generation: u64,
    /// Fired whenever the reachable path set may have changed.  Consumers
    /// (circuit workers, the reconciler) wait on this instead of polling the
    /// generation on a timer, so a topology change is an event, not a bus.
    changed: Arc<Notify>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TopologyError {
    #[error("invalid topology signature: {0}")]
    Signature(String),
    #[error("topology advertisement expired")]
    Expired,
    #[error("topology advertisement replayed")]
    Replay,
    #[error("topology origin cannot list itself as a neighbor")]
    SelfNeighbor,
}

impl Topology {
    pub fn insert_local(&mut self, advertisement: LinkStateAdvertisement) {
        let previous = self.advertisements.get(&advertisement.origin).cloned();
        let changed = self
            .advertisements
            .get(&advertisement.origin)
            .is_none_or(|previous| previous.neighbors != advertisement.neighbors);
        self.update_capacity_generations(&advertisement.origin, previous.as_ref(), &advertisement);
        self.advertisements
            .insert(advertisement.origin.clone(), advertisement);
        if changed {
            self.bump_generation();
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// A cloneable change signal for event-driven consumers.  Each `notified`
    /// future registered through this handle wakes once per topology change;
    /// callers that need to close the check-then-wait race must call
    /// `Notified::enable` before inspecting the database.
    pub fn changed(&self) -> Arc<Notify> {
        self.changed.clone()
    }

    fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.changed.notify_waiters();
    }

    pub fn node_count(&self, now: u64) -> usize {
        self.advertisements
            .values()
            .filter(|advertisement| advertisement.expires_at > now)
            .count()
    }

    /// Returns the currently advertised directional user IP capacity for one
    /// topology edge. Expired advertisements are never usable.
    pub fn link_inner_mtu(&self, from: &str, to: &str, now: u64) -> Option<u16> {
        self.advertisements
            .get(from)
            .filter(|advertisement| advertisement.expires_at > now)
            .and_then(|advertisement| {
                advertisement
                    .neighbors
                    .iter()
                    .find(|neighbor| neighbor.node == to)
                    .map(|neighbor| neighbor.inner_mtu)
            })
    }

    /// Returns the accepted directional capacity and its semantic generation.
    /// LSA sequence and expiry are deliberately absent from this value.
    pub fn link_inner_mtu_with_generation(
        &self,
        from: &str,
        to: &str,
        now: u64,
    ) -> Option<(u16, u64)> {
        let capacity = self.link_inner_mtu(from, to, now)?;
        let generation = self
            .capacity_generations
            .get(&(from.to_owned(), to.to_owned()))
            .copied()
            .unwrap_or(0);
        Some((capacity, generation))
    }

    pub fn link_proof_valid_until(&self, from: &str, to: &str, now: u64) -> Option<u64> {
        self.advertisements
            .get(from)
            .filter(|advertisement| advertisement.expires_at > now)
            .and_then(|advertisement| {
                advertisement
                    .neighbors
                    .iter()
                    .find(|neighbor| neighbor.node == to)
                    .map(|_| advertisement.expires_at)
            })
    }

    pub fn capacity_generation(&self, from: &str, to: &str) -> u64 {
        self.capacity_generations
            .get(&(from.to_owned(), to.to_owned()))
            .copied()
            .unwrap_or(0)
    }

    /// Stable, non-expired LSAs that have already passed `apply` validation.
    /// The carrier uses this pure snapshot to construct bounded topology
    /// batches without moving transport concerns into this module.
    pub fn active_advertisements(&self, now: u64) -> Vec<LinkStateAdvertisement> {
        let mut advertisements = self
            .advertisements
            .values()
            .filter(|advertisement| advertisement.expires_at > now)
            .cloned()
            .collect::<Vec<_>>();
        advertisements.sort_by(|left, right| left.origin.cmp(&right.origin));
        advertisements
    }

    /// A deterministic Graphviz view suitable for `tinect topology | dot`.
    pub fn dot(&self, now: u64) -> String {
        self.dot_with_names(now, |_| None)
    }

    /// Renders a graph with an optional local presentation name alongside the
    /// fingerprint. Names are not retained in topology advertisements.
    pub fn dot_with_names<F>(&self, now: u64, name_for_identity: F) -> String
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut output = String::from("digraph tinect {\n  rankdir=LR;\n");
        let mut origins = self.advertisements.keys().collect::<Vec<_>>();
        origins.sort();
        for origin in origins {
            let advertisement = &self.advertisements[origin];
            if advertisement.expires_at <= now {
                continue;
            }
            let origin_label = dot_node_label(origin, name_for_identity(origin).as_deref());
            output.push_str(&format!("  \"{origin_label}\";\n"));
            for neighbor in &advertisement.neighbors {
                let neighbor_label =
                    dot_node_label(&neighbor.node, name_for_identity(&neighbor.node).as_deref());
                output.push_str(&format!(
                    "  \"{origin_label}\" -> \"{neighbor_label}\" [label=\"{}\"];\n",
                    neighbor.cost
                ));
            }
        }
        output.push_str("}\n");
        output
    }

    pub fn apply(
        &mut self,
        advertisement: LinkStateAdvertisement,
        now: u64,
    ) -> Result<bool, TopologyError> {
        advertisement.verify()?;
        let key = decode_public(&advertisement.public_key)
            .map_err(|error| TopologyError::Signature(error.to_string()))?;
        if advertisement.origin != node_id(&key) {
            return Err(TopologyError::Signature(
                "topology origin does not match public key".into(),
            ));
        }
        if advertisement.expires_at <= now {
            return Err(TopologyError::Expired);
        }
        if advertisement
            .neighbors
            .iter()
            .any(|neighbor| neighbor.node == advertisement.origin)
        {
            return Err(TopologyError::SelfNeighbor);
        }
        if advertisement.neighbors.len() > MAX_NEIGHBORS_PER_LSA {
            return Err(TopologyError::Signature(
                "topology advertisement has too many neighbors".into(),
            ));
        }
        if self
            .advertisements
            .get(&advertisement.origin)
            .is_some_and(|previous| previous.sequence >= advertisement.sequence)
        {
            return Err(TopologyError::Replay);
        }
        let previous = self.advertisements.get(&advertisement.origin).cloned();
        let changed = self
            .advertisements
            .get(&advertisement.origin)
            .is_none_or(|previous| previous.neighbors != advertisement.neighbors);
        if let Some(previous) = previous
            .as_ref()
            .filter(|previous| previous.expires_at <= now)
        {
            for neighbor in &previous.neighbors {
                self.bump_capacity_generation(&advertisement.origin, &neighbor.node);
            }
        }
        self.update_capacity_generations(
            &advertisement.origin,
            previous
                .as_ref()
                .filter(|previous| previous.expires_at > now),
            &advertisement,
        );
        self.advertisements
            .insert(advertisement.origin.clone(), advertisement);
        if changed {
            self.bump_generation();
        }
        Ok(true)
    }

    fn update_capacity_generations(
        &mut self,
        origin: &str,
        previous: Option<&LinkStateAdvertisement>,
        next: &LinkStateAdvertisement,
    ) {
        let mut neighbors = HashSet::new();
        if let Some(previous) = previous {
            neighbors.extend(
                previous
                    .neighbors
                    .iter()
                    .map(|neighbor| neighbor.node.clone()),
            );
        }
        neighbors.extend(next.neighbors.iter().map(|neighbor| neighbor.node.clone()));
        for neighbor in neighbors {
            let previous_capacity = previous.and_then(|advertisement| {
                advertisement
                    .neighbors
                    .iter()
                    .find(|candidate| candidate.node == neighbor)
                    .map(|candidate| candidate.inner_mtu)
            });
            let next_capacity = next
                .neighbors
                .iter()
                .find(|candidate| candidate.node == neighbor)
                .map(|candidate| candidate.inner_mtu);
            if previous_capacity != next_capacity {
                self.bump_capacity_generation(origin, &neighbor);
            }
        }
    }

    fn bump_capacity_generation(&mut self, origin: &str, neighbor: &str) {
        let generation = self
            .capacity_generations
            .entry((origin.to_owned(), neighbor.to_owned()))
            .or_insert(0);
        *generation = generation.saturating_add(1).max(1);
    }

    /// Validate and install a complete topology Snapshot as one database
    /// transaction. Expired and replayed records have the same benign
    /// semantics as individual updates; every other error leaves the live
    /// database unchanged.
    pub fn apply_snapshot(
        &mut self,
        advertisements: Vec<LinkStateAdvertisement>,
        now: u64,
    ) -> Result<Vec<LinkStateAdvertisement>, TopologyError> {
        let mut staged = self.clone();
        let mut accepted = Vec::new();
        for advertisement in advertisements {
            let generation_before = staged.generation();
            match staged.apply(advertisement.clone(), now) {
                // Only records that actually change the reachable path set
                // (including capacity) are accepted for fanout and
                // reconciliation.  A refreshed LSA with an identical
                // neighbor/capacity set only advances the anti-replay
                // sequence and must not wake the control plane.
                Ok(true) if staged.generation() != generation_before => {
                    accepted.push(advertisement)
                }
                Ok(true) => {}
                Ok(false) | Err(TopologyError::Expired) | Err(TopologyError::Replay) => {}
                Err(error) => return Err(error),
            }
        }
        *self = staged;
        Ok(accepted)
    }

    pub fn prune(&mut self, now: u64) -> bool {
        let before = self.advertisements.len();
        let expired = self
            .advertisements
            .values()
            .filter(|advertisement| advertisement.expires_at <= now)
            .map(|advertisement| {
                (
                    advertisement.origin.clone(),
                    advertisement
                        .neighbors
                        .iter()
                        .map(|neighbor| neighbor.node.clone())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        for (origin, neighbors) in expired {
            for neighbor in neighbors {
                self.bump_capacity_generation(&origin, &neighbor);
            }
        }
        self.advertisements
            .retain(|_, advertisement| advertisement.expires_at > now);
        let changed = self.advertisements.len() != before;
        if changed {
            self.bump_generation();
        }
        changed
    }

    pub fn best_path(
        &self,
        source: &str,
        destination: &str,
        constraint: &PathConstraint,
        now: u64,
    ) -> Option<ComputedPath> {
        let max_hops = constraint.max_hops.unwrap_or(16).max(1);
        let forbidden = constraint.avoid.iter().cloned().collect::<HashSet<_>>();
        if forbidden.contains(source) || forbidden.contains(destination) {
            return None;
        }
        let mut candidates = Vec::new();
        let mut visited = HashSet::from([source.to_owned()]);
        let mut nodes = vec![source.to_owned()];
        self.walk(
            source,
            destination,
            constraint,
            now,
            max_hops,
            &forbidden,
            &mut visited,
            &mut nodes,
            0,
            &mut candidates,
        );
        candidates.into_iter().min_by_key(|path| {
            let preferred_missing = constraint
                .prefer_via
                .iter()
                .filter(|node| !path.nodes.contains(node))
                .count();
            (
                preferred_missing,
                path.cost,
                path.nodes.len(),
                path.nodes.clone(),
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        &self,
        current: &str,
        destination: &str,
        constraint: &PathConstraint,
        now: u64,
        max_hops: usize,
        forbidden: &HashSet<String>,
        visited: &mut HashSet<String>,
        nodes: &mut Vec<String>,
        cost: u64,
        candidates: &mut Vec<ComputedPath>,
    ) {
        if current == destination {
            if constraint
                .require_via
                .iter()
                .all(|node| nodes.contains(node))
            {
                candidates.push(ComputedPath {
                    nodes: nodes.clone(),
                    cost,
                });
            }
            return;
        }
        if nodes.len().saturating_sub(1) >= max_hops {
            return;
        }
        let Some(advertisement) = self.advertisements.get(current) else {
            return;
        };
        if advertisement.expires_at <= now {
            return;
        }
        for neighbor in &advertisement.neighbors {
            if forbidden.contains(&neighbor.node) || !visited.insert(neighbor.node.clone()) {
                continue;
            }
            nodes.push(neighbor.node.clone());
            self.walk(
                &neighbor.node,
                destination,
                constraint,
                now,
                max_hops,
                forbidden,
                visited,
                nodes,
                cost + u64::from(neighbor.cost),
                candidates,
            );
            nodes.pop();
            visited.remove(&neighbor.node);
        }
    }
}

fn dot_node_label(identity: &str, name: Option<&str>) -> String {
    let escape = |value: &str| value.replace('\\', "\\\\").replace('"', "\\\"");
    match name {
        Some(name) => format!("{}\\n{}", escape(name), escape(identity)),
        None => escape(identity),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_replay_expiry_and_identity_mismatch() {
        let key = crate::identity::generate();
        let identity = node_id(&key.verifying_key());
        let advertisement = LinkStateAdvertisement::new(identity.clone(), &key, 1, 100, vec![]);
        let mut topology = Topology::default();
        assert!(topology.apply(advertisement.clone(), 1).is_ok());
        assert_eq!(topology.apply(advertisement, 1), Err(TopologyError::Replay));
        let expired = LinkStateAdvertisement::new(identity, &key, 2, 1, vec![]);
        assert_eq!(topology.apply(expired, 1), Err(TopologyError::Expired));
        assert!(topology.prune(100));
        assert_eq!(topology.generation(), 2);
    }

    #[tokio::test]
    async fn applied_and_pruned_changes_wake_notified_waiters() {
        let key = crate::identity::generate();
        let identity = node_id(&key.verifying_key());
        let mut topology = Topology::default();
        let changed = topology.changed();

        let applied = changed.notified();
        tokio::pin!(applied);
        applied.as_mut().enable();
        assert!(
            topology
                .apply(
                    LinkStateAdvertisement::new(identity.clone(), &key, 1, 100, vec![]),
                    1
                )
                .is_ok()
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), applied)
            .await
            .expect("an accepted LSA wakes waiters");

        let pruned = changed.notified();
        tokio::pin!(pruned);
        pruned.as_mut().enable();
        assert!(topology.prune(100));
        tokio::time::timeout(std::time::Duration::from_secs(1), pruned)
            .await
            .expect("an expiry that removes state wakes waiters");
    }

    #[test]
    fn constrained_search_prefers_waypoint_and_avoids_nodes() {
        let a = crate::identity::generate();
        let b = crate::identity::generate();
        let c = crate::identity::generate();
        let d = crate::identity::generate();
        let ids = HashMap::from([
            ("a", node_id(&a.verifying_key())),
            ("b", node_id(&b.verifying_key())),
            ("c", node_id(&c.verifying_key())),
            ("d", node_id(&d.verifying_key())),
        ]);
        let mut topology = Topology::default();
        for (name, key, neighbors) in [
            ("a", &a, vec![("b", 1), ("c", 2)]),
            ("b", &b, vec![("d", 1)]),
            ("c", &c, vec![("d", 1)]),
        ] {
            topology
                .apply(
                    LinkStateAdvertisement::new(
                        ids[name].clone(),
                        key,
                        1,
                        100,
                        neighbors
                            .into_iter()
                            .map(|(node, cost)| LinkMetric {
                                node: ids[node].clone(),
                                cost,
                                inner_mtu: 1200,
                            })
                            .collect(),
                    ),
                    1,
                )
                .unwrap();
        }
        let preferred = topology
            .best_path(
                &ids["a"],
                &ids["d"],
                &PathConstraint {
                    prefer_via: vec![ids["c"].clone()],
                    ..Default::default()
                },
                1,
            )
            .unwrap();
        assert_eq!(
            preferred.nodes,
            vec![ids["a"].clone(), ids["c"].clone(), ids["d"].clone()]
        );
        let avoided = topology
            .best_path(
                &ids["a"],
                &ids["d"],
                &PathConstraint {
                    avoid: vec![ids["c"].clone()],
                    ..Default::default()
                },
                1,
            )
            .unwrap();
        assert_eq!(
            avoided.nodes,
            vec![ids["a"].clone(), ids["b"].clone(), ids["d"].clone()]
        );
    }

    #[test]
    fn dot_can_show_a_local_name_alongside_the_wire_identity() {
        let key = crate::identity::generate();
        let identity = node_id(&key.verifying_key());
        let mut topology = Topology::default();
        topology.insert_local(LinkStateAdvertisement::new(
            identity.clone(),
            &key,
            1,
            100,
            vec![],
        ));

        let dot =
            topology.dot_with_names(1, |node| (node == identity).then_some("edge-a".to_owned()));
        assert!(dot.contains(&format!("edge-a\\n{identity}")));
        assert!(topology.dot(1).contains(&identity));
    }

    #[test]
    fn advertised_inner_mtu_is_directional_and_signature_bound() {
        let a = crate::identity::generate();
        let b = crate::identity::generate();
        let a_id = node_id(&a.verifying_key());
        let b_id = node_id(&b.verifying_key());
        let advertisement = LinkStateAdvertisement::new(
            a_id.clone(),
            &a,
            1,
            100,
            vec![LinkMetric {
                node: b_id.clone(),
                cost: 1,
                inner_mtu: 1300,
            }],
        );
        let mut topology = Topology::default();
        topology.apply(advertisement.clone(), 1).unwrap();
        assert_eq!(topology.link_inner_mtu(&a_id, &b_id, 1), Some(1300));
        assert_eq!(topology.link_inner_mtu(&b_id, &a_id, 1), None);
        assert_eq!(topology.link_inner_mtu(&a_id, &b_id, 100), None);

        let mut tampered = advertisement;
        tampered.neighbors[0].inner_mtu = 1400;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn capacity_generation_changes_only_when_directional_capacity_changes() {
        let a = crate::identity::generate();
        let b = crate::identity::generate();
        let a_id = node_id(&a.verifying_key());
        let b_id = node_id(&b.verifying_key());
        let mut topology = Topology::default();
        let advertisement = |sequence, expires_at, inner_mtu| {
            LinkStateAdvertisement::new(
                a_id.clone(),
                &a,
                sequence,
                expires_at,
                vec![LinkMetric {
                    node: b_id.clone(),
                    cost: 1,
                    inner_mtu,
                }],
            )
        };
        assert!(topology.apply(advertisement(1, 100, 1200), 1).unwrap());
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 1);
        assert!(topology.apply(advertisement(2, 120, 1200), 1).unwrap());
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 1);
        assert!(topology.apply(advertisement(3, 140, 1300), 1).unwrap());
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 2);
        assert_eq!(
            topology.link_inner_mtu_with_generation(&a_id, &b_id, 1),
            Some((1300, 2))
        );
    }

    #[test]
    fn removing_and_readding_an_edge_invalidates_old_capacity_events() {
        let a = crate::identity::generate();
        let b = crate::identity::generate();
        let a_id = node_id(&a.verifying_key());
        let b_id = node_id(&b.verifying_key());
        let advertisement = |sequence, expires_at, neighbors| {
            LinkStateAdvertisement::new(a_id.clone(), &a, sequence, expires_at, neighbors)
        };
        let edge = || LinkMetric {
            node: b_id.clone(),
            cost: 1,
            inner_mtu: 1200,
        };
        let mut topology = Topology::default();
        topology
            .apply(advertisement(1, 100, vec![edge()]), 1)
            .unwrap();
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 1);
        topology.apply(advertisement(2, 100, vec![]), 1).unwrap();
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 2);
        topology
            .apply(advertisement(3, 100, vec![edge()]), 1)
            .unwrap();
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 3);
    }

    #[test]
    fn expiring_an_edge_invalidates_events_before_the_same_capacity_returns() {
        let a = crate::identity::generate();
        let b = crate::identity::generate();
        let a_id = node_id(&a.verifying_key());
        let b_id = node_id(&b.verifying_key());
        let edge = || LinkMetric {
            node: b_id.clone(),
            cost: 1,
            inner_mtu: 1200,
        };
        let mut topology = Topology::default();
        topology
            .apply(
                LinkStateAdvertisement::new(a_id.clone(), &a, 1, 2, vec![edge()]),
                1,
            )
            .unwrap();
        assert!(topology.prune(2));
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 2);
        topology
            .apply(
                LinkStateAdvertisement::new(a_id.clone(), &a, 2, 10, vec![edge()]),
                2,
            )
            .unwrap();
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 3);
    }

    #[test]
    fn topology_queries_cover_expiry_constraints_and_rendered_edges() {
        let a = crate::identity::generate();
        let b = crate::identity::generate();
        let a_id = node_id(&a.verifying_key());
        let b_id = node_id(&b.verifying_key());
        let edge = |inner_mtu| LinkMetric {
            node: b_id.clone(),
            cost: 3,
            inner_mtu,
        };
        let mut topology = Topology::default();
        topology
            .apply(
                LinkStateAdvertisement::new(a_id.clone(), &a, 1, 100, vec![edge(1200)]),
                1,
            )
            .unwrap();

        assert_eq!(topology.node_count(1), 1);
        assert_eq!(
            topology.link_inner_mtu_with_generation(&a_id, &b_id, 1),
            Some((1200, 1))
        );
        assert_eq!(topology.link_proof_valid_until(&a_id, &b_id, 1), Some(100));
        assert_eq!(topology.active_advertisements(1).len(), 1);
        let dot =
            topology.dot_with_names(1, |node| (node == a_id).then_some("local\"node".to_owned()));
        assert!(dot.contains("local\\\"node"));
        assert!(dot.contains(&format!("-> \"{b_id}\" [label=\"3\"]")));

        assert!(
            topology
                .best_path(&a_id, &b_id, &PathConstraint::default(), 1)
                .is_some()
        );
        assert!(
            topology
                .best_path(
                    &a_id,
                    &b_id,
                    &PathConstraint {
                        avoid: vec![a_id.clone()],
                        ..Default::default()
                    },
                    1,
                )
                .is_none()
        );
        assert!(
            topology
                .best_path(
                    &a_id,
                    &b_id,
                    &PathConstraint {
                        require_via: vec![a_id.clone()],
                        max_hops: Some(1),
                        ..Default::default()
                    },
                    1,
                )
                .is_some()
        );
        assert!(
            topology
                .best_path(
                    &a_id,
                    &b_id,
                    &PathConstraint {
                        require_via: vec![crate::identity::node_id(
                            &crate::identity::generate().verifying_key(),
                        )],
                        ..Default::default()
                    },
                    1,
                )
                .is_none()
        );

        topology
            .apply(
                LinkStateAdvertisement::new(a_id.clone(), &a, 2, 200, vec![edge(1300)]),
                100,
            )
            .unwrap();
        assert_eq!(topology.capacity_generation(&a_id, &b_id), 3);
        assert_eq!(topology.link_inner_mtu(&a_id, &b_id, 200), None);
        assert!(topology.active_advertisements(200).is_empty());
        assert_eq!(topology.dot(200), "digraph tinect {\n  rankdir=LR;\n}\n");
    }

    #[test]
    fn snapshot_validation_is_atomic() {
        let valid_key = crate::identity::generate();
        let invalid_key = crate::identity::generate();
        let valid_origin = node_id(&valid_key.verifying_key());
        let invalid_origin = node_id(&invalid_key.verifying_key());
        let valid = LinkStateAdvertisement::new(valid_origin, &valid_key, 1, 100, vec![]);
        let invalid = LinkStateAdvertisement::new(
            invalid_origin.clone(),
            &invalid_key,
            1,
            100,
            vec![LinkMetric {
                node: invalid_origin,
                cost: 1,
                inner_mtu: 1200,
            }],
        );
        let mut topology = Topology::default();
        assert_eq!(
            topology.apply_snapshot(vec![valid, invalid], 1),
            Err(TopologyError::SelfNeighbor)
        );
        assert_eq!(topology.node_count(1), 0);
    }

    #[test]
    fn decode_wire_rejects_excessive_neighbor_counts() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0u8; 16]);
        wire.extend_from_slice(&1u64.to_be_bytes());
        wire.extend_from_slice(&100u64.to_be_bytes());
        wire.extend_from_slice(&(MAX_NEIGHBORS_PER_LSA as u16 + 1).to_be_bytes());
        let mut reader = crate::wire::Reader::new(&wire);
        assert_eq!(
            LinkStateAdvertisement::decode_wire(&mut reader),
            Err(crate::wire::Error::Length)
        );
    }

    #[test]
    fn validate_rejects_excessive_neighbor_counts() {
        let key = crate::identity::generate();
        let identity = node_id(&key.verifying_key());
        let neighbors = (0..=MAX_NEIGHBORS_PER_LSA)
            .map(|index| LinkMetric {
                node: format!("{index:032x}"),
                cost: 1,
                inner_mtu: 1200,
            })
            .collect();
        let advertisement = LinkStateAdvertisement::new(identity.clone(), &key, 1, 100, neighbors);
        let mut topology = Topology::default();
        assert_eq!(
            topology.apply(advertisement, 1),
            Err(TopologyError::Signature(
                "topology advertisement has too many neighbors".into()
            ))
        );
    }

    #[test]
    fn path_walk_stops_on_hop_limit_missing_and_expired_advertisements() {
        let a = crate::identity::generate();
        let b = crate::identity::generate();
        let c = crate::identity::generate();
        let d = crate::identity::generate();
        let e = crate::identity::generate();
        let a_id = node_id(&a.verifying_key());
        let b_id = node_id(&b.verifying_key());
        let c_id = node_id(&c.verifying_key());
        let d_id = node_id(&d.verifying_key());
        let e_id = node_id(&e.verifying_key());
        let mut topology = Topology::default();
        // a -> b (expired by the time of the late query), a -> d (transit node
        // without an advertisement), a -> c (direct).
        topology
            .apply(
                LinkStateAdvertisement::new(
                    a_id.clone(),
                    &a,
                    1,
                    5,
                    vec![
                        LinkMetric {
                            node: b_id.clone(),
                            cost: 1,
                            inner_mtu: 1200,
                        },
                        LinkMetric {
                            node: d_id.clone(),
                            cost: 1,
                            inner_mtu: 1200,
                        },
                        LinkMetric {
                            node: c_id.clone(),
                            cost: 1,
                            inner_mtu: 1200,
                        },
                    ],
                ),
                1,
            )
            .unwrap();
        topology
            .apply(
                LinkStateAdvertisement::new(b_id.clone(), &b, 1, 5, vec![]),
                1,
            )
            .unwrap();
        // A hop limit of 1 still reaches the direct neighbor c; the detour
        // through b is cut by the hop limit.
        assert!(
            topology
                .best_path(
                    &a_id,
                    &c_id,
                    &PathConstraint {
                        max_hops: Some(1),
                        ..Default::default()
                    },
                    1,
                )
                .is_some()
        );
        // Expired advertisements are not traversed.
        assert!(
            topology
                .best_path(&a_id, &b_id, &PathConstraint::default(), 100,)
                .is_none()
        );
        // A destination behind a transit node without an advertisement is
        // unreachable.
        assert!(
            topology
                .best_path(&a_id, &e_id, &PathConstraint::default(), 1,)
                .is_none()
        );
    }

    #[test]
    fn default_cost_is_one() {
        assert_eq!(default_cost(), 1);
    }

    #[test]
    fn unchanged_lsa_refresh_is_not_accepted_for_fanout() {
        let key = crate::identity::generate();
        let origin = node_id(&key.verifying_key());
        let mut topology = Topology::default();
        let first = LinkStateAdvertisement::new(origin.clone(), &key, 1, 100, vec![]);
        let refreshed = LinkStateAdvertisement::new(origin, &key, 2, 100, vec![]);
        let accepted = topology.apply_snapshot(vec![first], 1).unwrap();
        assert_eq!(accepted.len(), 1);
        // The refreshed LSA has an identical neighbor/capacity set: it only
        // advances the anti-replay sequence, so it must not be returned for
        // fanout or wake the reconciler.
        let accepted = topology.apply_snapshot(vec![refreshed], 1).unwrap();
        assert!(accepted.is_empty());
        assert_eq!(topology.generation(), 1);
    }
}
