use crate::config::RouteImport;
use ipnet::IpNet;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectedRoute {
    pub prefix: IpNet,
    pub exit: String,
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HealthyPrefixDelta {
    pub added: Vec<IpNet>,
    pub removed: Vec<IpNet>,
}

/// Tracks healthy route candidates independently from route priority. A
/// prefix is present exactly while at least one `(prefix, candidate)` binding
/// is healthy, so duplicate and out-of-order health events are idempotent.
#[derive(Debug, Clone, Default)]
pub struct HealthyPrefixTracker {
    healthy_candidates: HashSet<(IpNet, String)>,
    healthy_prefixes: HashSet<IpNet>,
}

impl HealthyPrefixTracker {
    pub fn apply_candidate(
        &mut self,
        prefix: IpNet,
        candidate: impl Into<String>,
        healthy: bool,
    ) -> HealthyPrefixDelta {
        let key = (prefix, candidate.into());
        let was_healthy = self.healthy_candidates.contains(&key);
        if healthy == was_healthy {
            return HealthyPrefixDelta::default();
        }
        if healthy {
            self.healthy_candidates.insert(key.clone());
            if self.healthy_prefixes.insert(prefix) {
                HealthyPrefixDelta {
                    added: vec![prefix],
                    removed: Vec::new(),
                }
            } else {
                HealthyPrefixDelta::default()
            }
        } else {
            self.healthy_candidates.remove(&key);
            if self
                .healthy_candidates
                .iter()
                .all(|(candidate_prefix, _)| *candidate_prefix != prefix)
            {
                self.healthy_prefixes.remove(&prefix);
                HealthyPrefixDelta {
                    added: Vec::new(),
                    removed: vec![prefix],
                }
            } else {
                HealthyPrefixDelta::default()
            }
        }
    }

    pub fn replace_snapshot<I>(&mut self, candidates: I) -> HealthyPrefixDelta
    where
        I: IntoIterator<Item = (IpNet, String)>,
    {
        let desired = candidates.into_iter().collect::<HashSet<_>>();
        let old = std::mem::replace(&mut self.healthy_candidates, desired.clone());
        self.healthy_prefixes = desired.iter().map(|(prefix, _)| *prefix).collect();
        HealthyPrefixDelta {
            added: self
                .healthy_prefixes
                .difference(&old.iter().map(|(prefix, _)| *prefix).collect())
                .copied()
                .collect(),
            removed: old
                .iter()
                .map(|(prefix, _)| *prefix)
                .collect::<HashSet<_>>()
                .difference(&self.healthy_prefixes)
                .copied()
                .collect(),
        }
    }

    pub fn prefixes(&self) -> &HashSet<IpNet> {
        &self.healthy_prefixes
    }
}

/// The source-side action for a TUN packet. Every packet is selected from the
/// current route snapshot, so a recovered higher-priority candidate takes
/// effect immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Overlay(SelectedRoute),
    Reject,
}

pub trait HealthyRoutes {
    fn is_healthy_for(&self, prefix: &IpNet, node: &str) -> bool;
}

impl HealthyRoutes for HashMap<String, bool> {
    fn is_healthy_for(&self, _prefix: &IpNet, node: &str) -> bool {
        self.get(node).copied().unwrap_or(false)
    }
}

/// Reusable data-plane health aggregation. Entries are retained across
/// packets; a generation marks the first observation for the current packet
/// without clearing or reallocating the backing map.
#[derive(Default)]
pub struct HealthCache {
    entries: HashMap<IpNet, HashMap<String, (u64, bool)>>,
    generation: u64,
}

impl HealthCache {
    pub fn begin_packet(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.entries.clear();
            self.generation = 1;
        }
    }

    pub fn observe(&mut self, prefix: IpNet, node: &str, healthy: bool) {
        let entries = self.entries.entry(prefix).or_default();
        match entries.get_mut(node) {
            Some((generation, value)) if *generation == self.generation => *value |= healthy,
            Some(entry) => *entry = (self.generation, healthy),
            None => {
                entries.insert(node.to_owned(), (self.generation, healthy));
            }
        }
    }
}

impl HealthyRoutes for HealthCache {
    fn is_healthy_for(&self, prefix: &IpNet, node: &str) -> bool {
        self.entries
            .get(prefix)
            .and_then(|entries| entries.get(node))
            .is_some_and(|(generation, healthy)| *generation == self.generation && *healthy)
    }
}

pub fn select_flow_action<H: HealthyRoutes>(
    routes: &[RouteImport],
    dst: IpAddr,
    healthy: &H,
) -> RouteAction {
    match select_flow_route(routes, dst, healthy) {
        Some(route) => RouteAction::Overlay(route),
        None => RouteAction::Reject,
    }
}
pub fn select_route<H: HealthyRoutes>(
    routes: &[RouteImport],
    dst: IpAddr,
    healthy: &H,
) -> Option<SelectedRoute> {
    routes
        .iter()
        .filter(|r| r.prefix.contains(&dst))
        .max_by_key(|r| r.prefix.prefix_len())
        .and_then(|r| {
            r.candidates
                .iter()
                .filter(|c| healthy.is_healthy_for(&r.prefix, &c.node))
                .max_by_key(|c| c.priority)
                .map(|c| SelectedRoute {
                    prefix: r.prefix,
                    exit: c.node.clone(),
                    priority: c.priority,
                })
        })
}

/// Selects the highest-priority healthy candidate for this packet. There is no
/// flow-affinity cache: route recovery and priority changes take effect on the
/// next packet, including for an already-established five-tuple.
pub fn select_flow_route<H: HealthyRoutes>(
    routes: &[RouteImport],
    dst: IpAddr,
    healthy: &H,
) -> Option<SelectedRoute> {
    select_route(routes, dst, healthy)
}
#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteCandidate;

    #[test]
    fn health_is_scoped_to_route_prefix() {
        let default_prefix: IpNet = "0.0.0.0/0".parse().unwrap();
        let host_prefix: IpNet = "192.168.191.30/32".parse().unwrap();
        let routes = vec![
            RouteImport {
                prefix: default_prefix,
                candidates: vec![
                    RouteCandidate {
                        node: "exit".into(),
                        priority: 100,
                    },
                    RouteCandidate {
                        node: "backup".into(),
                        priority: 50,
                    },
                ],
            },
            RouteImport {
                prefix: host_prefix,
                candidates: vec![RouteCandidate {
                    node: "exit".into(),
                    priority: 100,
                }],
            },
        ];
        let mut health = HealthCache::default();
        health.begin_packet();
        health.observe(default_prefix, "exit", false);
        health.observe(default_prefix, "backup", true);
        health.observe(host_prefix, "exit", true);

        assert_eq!(
            select_route(&routes, "1.1.1.1".parse().unwrap(), &health)
                .unwrap()
                .exit,
            "backup"
        );
        assert_eq!(
            select_route(&routes, "192.168.191.30".parse().unwrap(), &health)
                .unwrap()
                .exit,
            "exit"
        );
    }

    #[test]
    fn longest_then_priority() {
        let rs = vec![
            RouteImport {
                prefix: "0.0.0.0/0".parse().unwrap(),
                candidates: vec![RouteCandidate {
                    node: "a".into(),
                    priority: 9,
                }],
            },
            RouteImport {
                prefix: "10.0.0.0/8".parse().unwrap(),
                candidates: vec![RouteCandidate {
                    node: "b".into(),
                    priority: 1,
                }],
            },
        ];
        let h = HashMap::from([("a".into(), true), ("b".into(), true)]);
        assert_eq!(
            select_route(&rs, "10.1.0.1".parse().unwrap(), &h)
                .unwrap()
                .exit,
            "b"
        );
    }

    #[test]
    fn disabled_high_priority_candidate_falls_back_to_backup() {
        let routes = vec![RouteImport {
            prefix: "10.0.0.0/8".parse().unwrap(),
            candidates: vec![
                RouteCandidate {
                    node: "primary".into(),
                    priority: 0,
                },
                RouteCandidate {
                    node: "backup".into(),
                    priority: 50,
                },
            ],
        }];
        let selected = select_route(
            &routes,
            "10.1.2.3".parse().unwrap(),
            &HashMap::from([("primary".into(), true), ("backup".into(), true)]),
        )
        .unwrap();
        assert_eq!(selected.exit, "backup");
    }

    #[test]
    fn every_packet_reselects_the_highest_priority_healthy_candidate() {
        let routes = vec![RouteImport {
            prefix: "0.0.0.0/0".parse().unwrap(),
            candidates: vec![
                RouteCandidate {
                    node: "primary".into(),
                    priority: 100,
                },
                RouteCandidate {
                    node: "backup".into(),
                    priority: 50,
                },
            ],
        }];
        let primary_unavailable =
            HashMap::from([("primary".into(), false), ("backup".into(), true)]);
        assert_eq!(
            select_flow_route(&routes, "1.1.1.1".parse().unwrap(), &primary_unavailable)
                .unwrap()
                .exit,
            "backup"
        );
        let primary_recovered = HashMap::from([("primary".into(), true), ("backup".into(), true)]);
        assert_eq!(
            select_flow_route(&routes, "1.1.1.1".parse().unwrap(), &primary_recovered)
                .unwrap()
                .exit,
            "primary"
        );
    }

    #[test]
    fn unhealthy_routes_are_rejected_until_an_exit_recovers() {
        let routes = vec![RouteImport {
            prefix: "10.0.0.0/8".parse().unwrap(),
            candidates: vec![RouteCandidate {
                node: "exit".into(),
                priority: 100,
            }],
        }];
        assert_eq!(
            select_flow_action(
                &routes,
                "10.1.2.3".parse().unwrap(),
                &HashMap::from([("exit".into(), false)]),
            ),
            RouteAction::Reject
        );
        assert!(matches!(
            select_flow_action(
                &routes,
                "10.1.2.3".parse().unwrap(),
                &HashMap::from([("exit".into(), true)]),
            ),
            RouteAction::Overlay(_)
        ));
        assert_eq!(
            select_flow_action(&routes, "10.1.2.3".parse().unwrap(), &HashMap::new()),
            RouteAction::Reject
        );
        assert_eq!(
            select_flow_action(&[], "10.1.2.3".parse().unwrap(), &HashMap::new()),
            RouteAction::Reject
        );
    }

    #[test]
    fn multicast_without_a_route_is_rejected() {
        assert_eq!(
            select_flow_action(&[], "224.0.0.251".parse().unwrap(), &HashMap::new(),),
            RouteAction::Reject
        );
        assert_eq!(
            select_flow_action(&[], "ff02::fb".parse().unwrap(), &HashMap::new()),
            RouteAction::Reject
        );
    }

    #[test]
    fn healthy_prefixes_use_reference_transitions_not_route_priority() {
        let prefix: IpNet = "10.0.0.0/8".parse().unwrap();
        let mut tracker = HealthyPrefixTracker::default();
        assert_eq!(
            tracker.apply_candidate(prefix, "primary", true).added,
            vec![prefix]
        );
        assert!(
            tracker
                .apply_candidate(prefix, "backup", true)
                .added
                .is_empty()
        );
        assert!(
            tracker
                .apply_candidate(prefix, "primary", false)
                .removed
                .is_empty()
        );
        assert_eq!(
            tracker.apply_candidate(prefix, "backup", false).removed,
            vec![prefix]
        );
        assert!(
            tracker
                .apply_candidate(prefix, "backup", false)
                .removed
                .is_empty()
        );
    }

    #[test]
    fn healthy_snapshot_delta_handles_overlap_and_family_separation() {
        let default_v4: IpNet = "0.0.0.0/0".parse().unwrap();
        let host_v4: IpNet = "192.0.2.1/32".parse().unwrap();
        let default_v6: IpNet = "::/0".parse().unwrap();
        let mut tracker = HealthyPrefixTracker::default();
        let first = tracker.replace_snapshot([
            (default_v4, "a".into()),
            (host_v4, "a".into()),
            (default_v6, "a".into()),
        ]);
        assert_eq!(first.added.len(), 3);
        let second = tracker.replace_snapshot([(default_v4, "b".into()), (default_v6, "a".into())]);
        assert!(second.added.is_empty());
        assert_eq!(second.removed, vec![host_v4]);
        assert!(tracker.prefixes().contains(&default_v4));
        assert!(tracker.prefixes().contains(&default_v6));
    }

    #[test]
    fn health_cache_overwrites_stale_generation_entries_and_ors_within_a_packet() {
        let prefix: IpNet = "0.0.0.0/0".parse().unwrap();
        let mut health = HealthCache::default();
        health.begin_packet();
        health.observe(prefix, "exit", false);
        health.begin_packet();
        health.observe(prefix, "exit", false);
        health.observe(prefix, "exit", true);
        let routes = vec![RouteImport {
            prefix,
            candidates: vec![RouteCandidate {
                node: "exit".into(),
                priority: 100,
            }],
        }];
        assert_eq!(
            select_route(&routes, "1.1.1.1".parse().unwrap(), &health)
                .unwrap()
                .exit,
            "exit"
        );
    }
}
