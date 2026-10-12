//! Application-layer composition root.
//!
//! Domain modules (`routing`, `policy`, `circuit`, `topology`) stay free of
//! daemon concerns. This module owns the shared mutable state needed only by
//! the running process and gives orchestration code a single dependency rather
//! than several unrelated `Arc<RwLock<_>>` parameters.
use crate::{
    carrier::Link,
    config::Config,
    dns::DnsResolver,
    observability::Observability,
    status::{CircuitStatus, DaemonState, LinkStatus, MigrationState, RouteStatus, Status},
    topology::Topology,
};
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::RwLock, task::JoinSet};
use tokio_util::sync::CancellationToken;

mod circuit_runtime;
mod task_group;
pub use circuit_runtime::CircuitRuntime;
pub use task_group::TaskGroup;

// The link registry is touched from the accept loop, dialers, control
// handlers and health/topology tasks. All critical sections are short
// HashMap operations without any await point. A std Mutex makes that boundary
// explicit: accidentally retaining its guard across an await makes a
// supervised Tokio task non-Send and fails compilation instead of stalling
// Link registration at runtime.
pub type LinkRegistry = Arc<StdMutex<HashMap<String, Arc<Link>>>>;
pub type SharedTopology = Arc<RwLock<Topology>>;
pub type SharedDaemonState = Arc<RwLock<DaemonState>>;

/// Owns daemon background work. Every long-lived task observes the same
/// cancellation token, so startup rollback and normal shutdown have one
/// deterministic stopping path.
#[derive(Clone, Default)]
pub struct DaemonSupervisor {
    inner: Arc<SupervisorInner>,
}

struct SupervisorInner {
    cancellation: CancellationToken,
    tasks: StdMutex<JoinSet<()>>,
    active: Arc<AtomicUsize>,
    failures: AtomicUsize,
    shutting_down: AtomicBool,
}

struct ActiveTaskGuard(Arc<AtomicUsize>);

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// A worker normally observes the shared token itself, which lets it finish
// owned child-task cleanup.  This short grace period is a backstop for a
// blocked or legacy worker: allowing it to consume the whole configured
// shutdown deadline would delay every daemon shutdown and network cleanup.
const CANCELLATION_CLEANUP_GRACE: Duration = Duration::from_millis(250);

impl Default for SupervisorInner {
    fn default() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            tasks: StdMutex::new(JoinSet::new()),
            active: Arc::new(AtomicUsize::new(0)),
            failures: AtomicUsize::new(0),
            shutting_down: AtomicBool::new(false),
        }
    }
}

impl DaemonSupervisor {
    pub fn token(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    pub fn task_count(&self) -> usize {
        self.inner.active.load(Ordering::Relaxed)
    }

    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::Acquire)
    }

    pub async fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_background(task);
    }

    /// Registers a long-lived daemon task from synchronous composition code.
    /// It has the same cancellation and join guarantee as [`Self::spawn`].
    pub fn spawn_background<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.is_shutting_down() {
            return;
        }
        let cancellation = self.token();
        let active = self.inner.active.clone();
        let mut tasks = self.inner.tasks.lock().expect("supervisor task lock");
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                self.inner.failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!(%error, "supervised task failed");
            }
        }
        // Recheck under the task registry lock so shutdown cannot complete
        // between the first check and this task's registration.
        if self.is_shutting_down() {
            return;
        }
        self.inner.active.fetch_add(1, Ordering::Relaxed);
        tasks.spawn(async move {
            let _active = ActiveTaskGuard(active);
            tokio::pin!(task);
            tokio::select! {
                // Cancellation is cooperative: give workers that own child
                // task groups a chance to observe the token and join them.
                // Do not let a worker that missed the token consume the full
                // daemon shutdown deadline, though: dropping its future also
                // releases any endpoint or stream it owns.
                _ = cancellation.cancelled() => {
                    if tokio::time::timeout(CANCELLATION_CLEANUP_GRACE, &mut task)
                        .await
                        .is_err()
                    {
                        tracing::warn!("supervised task ignored cancellation and was stopped after cleanup grace");
                    }
                }
                _ = &mut task => {}
            }
        });
    }

    pub async fn shutdown(&self, timeout: Duration) -> Result<(), String> {
        if self.inner.shutting_down.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.inner.cancellation.cancel();
        let mut tasks = {
            let mut registered = self.inner.tasks.lock().expect("supervisor task lock");
            std::mem::take(&mut *registered)
        };
        let previous_failures = self.inner.failures.load(Ordering::Relaxed);
        let wait = async {
            let mut failures = 0usize;
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    failures += 1;
                    tracing::error!(%error, "supervised task failed");
                }
            }
            failures
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(failures) if previous_failures + failures == 0 => Ok(()),
            Ok(failures) => {
                let failures = previous_failures + failures;
                Err(format!(
                    "{failures} supervised task(s) failed before shutdown"
                ))
            }
            Err(_) => {
                let remaining = tasks.len();
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                Err(format!(
                    "shutdown timed out with {remaining} task(s) still running"
                ))
            }
        }
    }
}

/// Long-lived daemon state. The validated startup configuration is immutable
/// for the daemon lifetime; this type owns only runtime coordination state.
#[derive(Clone)]
pub struct Runtime {
    /// The validated configuration used to construct this daemon.
    ///
    /// Keeping the immutable configuration in the runtime composition object
    /// gives long-lived workers one authoritative view. Platform-resolved
    /// values such as an allocated TUN name are tracked separately by the
    /// network resource owner and must not mutate this snapshot.
    pub config: Arc<Config>,
    pub dns: Arc<DnsResolver>,
    pub links: LinkRegistry,
    pub topology: SharedTopology,
    pub state: SharedDaemonState,
    pub observability: Arc<Observability>,
    pub circuits: CircuitRuntime,
}

impl Runtime {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let config = Arc::new(config);
        let observability = Arc::new(Observability::new(config.runtime.pcap_buffer_packets));
        let dns = Arc::new(DnsResolver::new(&config.dns_servers)?);
        let state = Arc::new(RwLock::new(initial_daemon_state(
            config.as_ref(),
            observability.clone(),
        )));
        Ok(Self {
            config,
            dns,
            links: Arc::new(StdMutex::new(HashMap::new())),
            topology: Arc::new(RwLock::new(Topology::default())),
            state,
            observability,
            circuits: CircuitRuntime::default(),
        })
    }
}

/// Builds a queryable status snapshot without starting any sockets or tasks.
/// Keeping this deterministic makes CLI fallback behaviour testable.
pub fn initial_daemon_state(config: &Config, observability: Arc<Observability>) -> DaemonState {
    DaemonState {
        status: Status {
            node: config.id.clone(),
            // Static status fallback must not read an identity-key file.
            node_identity: None,
            links: config
                .peers
                .keys()
                .map(|peer| LinkStatus {
                    peer: peer.clone(),
                    peer_identity: config.peer_identity(peer).unwrap_or_default(),
                    healthy: false,
                    last_error: Some("carrier not connected".into()),
                    metrics: None,
                })
                .collect(),
            circuits: circuit_statuses(config),
            flow_count: 0,
            topology_nodes: 0,
            topology_generation: 0,
            supervised_tasks: 0,
            shutting_down: false,
            last_shutdown_error: None,
            circuit_traffic: Default::default(),
            acl_rejections: Default::default(),
        },
        observability,
        topology_dot: "digraph tinect {}\n".into(),
        routes: configured_route_statuses(config),
        status_refresh_requested: Arc::new(tokio::sync::Notify::new()),
        status_refresh_done: Arc::new(tokio::sync::Notify::new()),
        status_refresh_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

fn configured_route_statuses(config: &Config) -> Vec<RouteStatus> {
    let mut grouped = std::collections::BTreeMap::<String, (usize, Vec<String>)>::new();
    let mut record = |route: &crate::config::PeerRoute, candidate: String| {
        let (selector, entries) = if let Some(ip_cidr) = route.ip_cidr {
            (format!("ip_cidr:{ip_cidr}"), 1)
        } else if let Some(domain) = &route.domain {
            (
                format!("domain:{domain}"),
                route
                    .site_id
                    .map_or(0, |id| config.route_sets.entry_count(id)),
            )
        } else if let Some(path) = &route.site_set {
            (
                format!("site_set:{path}"),
                route
                    .site_id
                    .map_or(0, |id| config.route_sets.entry_count(id)),
            )
        } else {
            return;
        };
        let entry = grouped.entry(selector).or_insert((entries, Vec::new()));
        entry.0 = entry.0.max(entries);
        entry.1.push(candidate);
    };
    for (node, peer) in &config.peers {
        for route in &peer.routes {
            record(route, format!("{node} ({})", route.priority));
        }
    }
    if let Some(direct) = &config.direct {
        for route in &direct.routes {
            record(route, format!("direct ({})", route.priority));
        }
    }
    grouped
        .into_iter()
        .map(|(selector, (entries, candidates))| RouteStatus {
            selector,
            entries,
            candidates,
        })
        .collect()
}

pub fn circuit_statuses(config: &Config) -> Vec<CircuitStatus> {
    let mut destinations = config
        .peers
        .iter()
        .filter(|(_, peer)| !peer.paths.is_empty())
        .map(|(name, _)| name.clone())
        .chain(config.path_policies.keys().cloned())
        .collect::<std::collections::BTreeSet<String>>();
    destinations.extend(
        config
            .route_imports()
            .into_iter()
            .flat_map(|route| route.candidates.into_iter().map(|candidate| candidate.node)),
    );
    destinations
        .into_iter()
        .map(|destination| CircuitStatus {
            destination: destination.clone(),
            destination_identity: config.peer_identity(&destination),
            active_path: Vec::new(),
            active_path_names: Vec::new(),
            preferred_path: config
                .peers
                .get(&destination)
                .and_then(|peer| peer.paths.first())
                .map(|path| path.path.clone())
                .unwrap_or_default(),
            preferred_path_names: config
                .peers
                .get(&destination)
                .and_then(|peer| peer.paths.first())
                .map(|path| path.path.iter().cloned().map(Some).collect())
                .unwrap_or_default(),
            healthy: false,
            migration_state: MigrationState::Stable,
            migration_started_at: None,
            migration_last_error: None,
        })
        .collect()
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TunConfig;

    #[test]
    fn route_status_lists_direct_as_a_candidate() {
        let configured: Config = serde_yaml::from_str(
            "id: a\nidentity_key_path: unused\nlisten: quic://127.0.0.1:1\ntun: {name: tinea, addresses: [10.64.0.1/32]}\ndirect:\n  dscp: 46\n  conntrack_zone: 32123\n  routes:\n    - {ip_cidr: 192.0.2.0/24, priority: 120}\npeers: {}\n",
        )
        .unwrap();

        let routes = configured_route_statuses(&configured);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].selector, "ip_cidr:192.0.2.0/24");
        assert_eq!(routes[0].entries, 1);
        assert_eq!(routes[0].candidates, vec!["direct (120)"]);
    }

    #[test]
    fn initial_state_is_side_effect_free() {
        let config = Config {
            id: "a".into(),
            accept_connections: true,
            allow_transit: true,
            identity_key: None,
            identity_key_path: Some("unused".into()),
            listen: "quic://127.0.0.1:1".into(),
            fake_tcp_reset_key: Default::default(),
            fwmark: None,
            managed_routes: true,
            carrier_interface: None,
            dns_servers: Default::default(),
            fake_ip: None,
            route_sets: Default::default(),
            nft_healthy_set: None,
            direct: None,
            post_up: None,
            pre_down: None,
            tun: TunConfig {
                enabled: true,
                name: "tinea".into(),
                addresses: vec!["10.64.0.1/32".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            runtime: Default::default(),
            link_health: Default::default(),
            path_migration: Default::default(),
            peers: Default::default(),
            connect_to: Default::default(),
            repair_rate: 0.0,
            path_policies: Default::default(),
            allowed_routes: Default::default(),
            allowed_local_ports: Default::default(),
        };
        let runtime = Runtime::new(config).unwrap();
        assert_eq!(runtime.state.blocking_read().status.node, "a");
        assert!(runtime.links.lock().expect("link registry lock").is_empty());
        assert_eq!(runtime.circuits.opens.active_generation(), 0);
    }

    #[tokio::test]
    async fn supervisor_cancels_and_joins_registered_tasks() {
        let supervisor = DaemonSupervisor::default();
        let token = supervisor.token();
        supervisor
            .spawn(async move {
                token.cancelled().await;
            })
            .await;
        let token = supervisor.token();
        supervisor.spawn_background(async move {
            token.cancelled().await;
        });
        assert_eq!(supervisor.task_count(), 2);
        supervisor
            .shutdown(Duration::from_millis(100))
            .await
            .unwrap();
        assert_eq!(supervisor.task_count(), 0);
        assert!(supervisor.is_shutting_down());
        // Shutdown is deliberately idempotent for startup rollback paths.
        supervisor
            .shutdown(Duration::from_millis(100))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn supervisor_rejects_registration_after_shutdown_starts() {
        let supervisor = DaemonSupervisor::default();
        supervisor.spawn_background(async {});
        supervisor
            .shutdown(Duration::from_millis(100))
            .await
            .unwrap();
        // Registration after shutdown is a no-op.
        supervisor.spawn_background(async {});
        assert_eq!(supervisor.task_count(), 0);
    }

    #[test]
    fn route_status_selectors_cover_domain_and_site_set_routes() {
        let configured: Config = serde_yaml::from_str(
            "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {name: tinea, addresses: [10.64.0.1/32]}\nfake_ip:\n  listen: 127.0.0.1:5354\n  upstream_dns: [1.1.1.1]\n  disable_ipv6: true\npeers:\n  b:\n    public_key: deadbeef\n    endpoints: []\n    routes:\n      - {domain: example.test, priority: 90}\n      - {ip_cidr: 192.0.2.0/24, priority: 80}\n",
        )
        .unwrap();
        let statuses = configured_route_statuses(&configured);
        assert_eq!(statuses.len(), 2);
        assert!(
            statuses
                .iter()
                .any(|route| route.selector == "domain:example.test")
        );
        assert!(
            statuses
                .iter()
                .any(|route| route.selector == "ip_cidr:192.0.2.0/24")
        );
    }

    #[tokio::test]
    async fn supervisor_allows_cancelled_tasks_to_finish_cleanup() {
        let supervisor = DaemonSupervisor::default();
        let token = supervisor.token();
        let (cleaned_up, cleanup_finished) = tokio::sync::oneshot::channel();
        supervisor.spawn_background(async move {
            token.cancelled().await;
            tokio::task::yield_now().await;
            let _ = cleaned_up.send(());
        });

        supervisor
            .shutdown(Duration::from_millis(100))
            .await
            .unwrap();
        cleanup_finished.await.unwrap();
    }

    #[tokio::test]
    async fn supervisor_bounds_a_worker_that_does_not_observe_cancellation() {
        let supervisor = DaemonSupervisor::default();
        supervisor.spawn_background(std::future::pending());

        tokio::time::timeout(
            Duration::from_secs(1),
            supervisor.shutdown(Duration::from_secs(1)),
        )
        .await
        .expect("uncooperative worker must not consume the shutdown deadline")
        .unwrap();
        assert_eq!(supervisor.task_count(), 0);
    }

    #[tokio::test]
    async fn supervisor_reaps_completed_short_tasks_during_runtime() {
        let supervisor = DaemonSupervisor::default();
        for _ in 0..128 {
            supervisor.spawn_background(async {});
            tokio::time::timeout(Duration::from_secs(1), async {
                while supervisor.task_count() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(supervisor.inner.tasks.lock().unwrap().len() <= 1);
        }
        supervisor.shutdown(Duration::from_secs(1)).await.unwrap();
        assert!(supervisor.inner.tasks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn supervisor_accounts_for_panicked_tasks_and_reports_the_failure() {
        let supervisor = DaemonSupervisor::default();
        supervisor.spawn_background(async { panic!("worker failed") });
        tokio::time::timeout(Duration::from_secs(1), async {
            while supervisor.task_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let error = supervisor
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(error.contains("1 supervised task(s) failed"));
        assert_eq!(supervisor.task_count(), 0);
    }

    #[tokio::test]
    async fn supervisor_retains_failure_status_after_runtime_reaping() {
        let supervisor = DaemonSupervisor::default();
        supervisor.spawn_background(async { panic!("first worker failed") });
        tokio::time::timeout(Duration::from_secs(1), async {
            while supervisor.task_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        supervisor.spawn_background(async {});

        let error = supervisor
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(error.contains("1 supervised task(s) failed"));
    }
}
