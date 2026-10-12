use super::*;

pub struct InboundDispatch {
    pub identity: Arc<SigningKey>,
    pub authorizations: CircuitAuthorizations,
    pub relay_labels: RelayLabelTables,
    pub sessions: SessionManager,
    pub cancellation: CancellationToken,
    pub circuit_opens: CircuitOpenManager,
    pub circuit_router: Arc<Router>,
    pub circuit_dns: CircuitDnsClient,
}

#[derive(Clone)]
pub(super) struct SecureReceiveContext {
    pub(super) identity: Arc<SigningKey>,
    pub(super) egress: Option<EgressPolicy>,
    pub(super) source_policy: SourceAddressPolicy,
    pub(super) metrics: Arc<Observability>,
    pub(super) authorizations: CircuitAuthorizations,
    pub(super) relay_labels: RelayLabelTables,
    pub(super) sessions: SessionManager,
    pub(super) circuit_router: Arc<Router>,
    pub(super) circuit_opens: CircuitOpenManager,
    pub(super) return_flows: crate::return_path::ReturnFlowTable,
    pub(super) circuit_dns: CircuitDnsClient,
    pub(super) supervisor: DaemonSupervisor,
}

pub(super) const CIRCUIT_BROKEN_FEEDBACK_ATTEMPTS: usize = 3;
pub(super) fn circuit_broken_feedback_ttl() -> std::time::Duration {
    crate::timing::active().no_session_feedback_ttl
}
pub(super) const MAX_CIRCUIT_BROKEN_FEEDBACKS: usize = 4096;

pub fn should_report_circuit_broken_feedback(
    seen: &mut HashMap<CircuitId, Instant>,
    circuit_id: CircuitId,
    now: Instant,
) -> bool {
    // Per-key TTL first, so an expired entry re-reports without waiting for a
    // full-table sweep. Full sweeps are lazy: scanning up to 4096 entries on
    // every unknown-session packet is O(N) per drop.
    if let Some(timestamp) = seen.get(&circuit_id)
        && now
            .checked_duration_since(*timestamp)
            .is_some_and(|age| age < circuit_broken_feedback_ttl())
    {
        return false;
    }
    if !seen.contains_key(&circuit_id) {
        if seen.len() >= MAX_CIRCUIT_BROKEN_FEEDBACKS {
            // Under pressure, reclaim expired entries once before refusing.
            seen.retain(|_, timestamp| {
                now.checked_duration_since(*timestamp)
                    .is_some_and(|age| age < circuit_broken_feedback_ttl())
            });
            if seen.len() >= MAX_CIRCUIT_BROKEN_FEEDBACKS {
                return false;
            }
        } else if seen.len() >= 1024 {
            seen.retain(|_, timestamp| {
                now.checked_duration_since(*timestamp)
                    .is_some_and(|age| age < circuit_broken_feedback_ttl())
            });
        }
    }
    seen.insert(circuit_id, now);
    true
}
struct OpenWaiter {
    attempt_id: Option<u64>,
    expected_public_key: String,
    allowed_reject_public_keys: Vec<String>,
    expected_renewal_counter: Option<u64>,
    link_token: crate::link::LinkToken,
    sender: oneshot::Sender<OpenResult>,
}
type OpenWaiters = Arc<Mutex<HashMap<(u64, CircuitId), OpenWaiter>>>;
type AuthorizedOpenLinks = Arc<Mutex<HashMap<CircuitId, u64>>>;
#[derive(Clone)]
pub struct ActiveCircuit {
    pub circuit_id: CircuitId,
    pub data_key: chacha20poly1305::Key,
    pub link_instance: u64,
    /// Shared across migration attempts so an old active lease can continue
    /// renewing while a preferred replacement OPEN is failing.
    pub renewal_counter: Arc<AtomicU64>,
    pub path: Vec<String>,
    /// Local route overrides selected with this lease. They are lease
    /// metadata, not a route-snapshot cache, so a migration cannot make a
    /// previous path's policy disappear before the replacement commits.
    pub route_overrides: Vec<crate::config::RouteOverride>,
    /// Upper bound carried by the OPEN that established this circuit. Route
    /// refreshes must not grow beyond this live-circuit bound.
    pub path_inner_mtu: u16,
    pub circuit_ceiling: u16,
    pub configured_inner_mtu: u16,
    pub capacity_vector: CapacityVector,
    pub config_generation: u64,
    pub lease_epoch: u64,
    pub send_gate: Arc<std::sync::atomic::AtomicBool>,
    pub send_budget: Arc<AtomicUsize>,
}
#[derive(Clone)]
struct DesiredGuard {
    resolution_generation: u64,
    identity: Option<crate::reconcile::CircuitIdentity>,
    config_generation: u64,
    availability: crate::reconcile::Availability,
    capacity_vector: CapacityVector,
    verified_inner_mtu: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenAttempt {
    pub destination: String,
    pub attempt_id: u64,
    pub circuit_id: CircuitId,
    pub identity: crate::reconcile::CircuitIdentity,
    pub config_generation: u64,
    pub link_instance: u64,
    pub capacity_vector: CapacityVector,
    pub route_overrides: Vec<crate::config::RouteOverride>,
}

pub struct OpenAttemptInput {
    pub destination: String,
    pub circuit_id: CircuitId,
    pub identity: crate::reconcile::CircuitIdentity,
    pub config_generation: u64,
    pub link_instance: u64,
    pub capacity_vector: CapacityVector,
    pub route_overrides: Vec<crate::config::RouteOverride>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    StaleAttempt,
    Unauthorized,
    HardRevoked,
}

#[derive(Clone)]
struct MigrationRecord {
    preferred_identity: crate::reconcile::CircuitIdentity,
    ready_since: Instant,
    started_at: Option<Instant>,
    last_error: Option<String>,
}

/// The migration worker either switches immediately or sleeps only until the
/// preferred path has satisfied its configured stability interval.  Returning
/// the deadline makes that wait explicit instead of requiring callers to poll
/// the same resolution periodically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationReadiness {
    Ready,
    PendingUntil(Instant),
    /// The configured interval cannot be represented by this platform's
    /// monotonic clock. It is still safe to retain the current circuit and
    /// re-evaluate on a state change, but it must not panic the daemon.
    Pending,
}
/// All mutable state that belongs to a source destination.  Keeping this in
/// one slot makes an attempt, desired resolution, active lease and migration
/// a single state transition instead of an update across unrelated maps.
#[derive(Default)]
struct CircuitSlot {
    desired: Option<DesiredGuard>,
    attempt: Option<OpenAttempt>,
    active: Option<ActiveCircuit>,
    migration: Option<MigrationRecord>,
    rebuild_requested: bool,
}

type CircuitSlots = Arc<Mutex<HashMap<String, CircuitSlot>>>;

/// One destination's per-destination worker claim.  Dropping the guard (on
/// any exit path, including a panic unwind) releases the claim, so a worker
/// that dies cannot strand its destination forever.
pub struct WorkerClaim {
    workers: Arc<std::sync::Mutex<HashSet<String>>>,
    destination: String,
}
impl Drop for WorkerClaim {
    fn drop(&mut self) {
        self.workers
            .lock()
            .expect("worker claim lock")
            .remove(&self.destination);
    }
}

/// Coalesced desired-state inputs consumed by source-side circuit workers.
/// Keeping them together makes the boundary between resolution/reconciliation
/// and active lease ownership explicit.
#[derive(Clone, Default)]
struct DesiredCircuitState {
    config_generation: Arc<AtomicU64>,
    ensure_requests: Arc<Mutex<HashSet<String>>>,
    ensure_changed: Arc<tokio::sync::Notify>,
}

/// Result returned only by the final circuit node and relayed unchanged back
/// to the source. CircuitId is the stable per-attempt waiter token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenResult {
    Acknowledged,
    RenewAcknowledged { counter: u64 },
    Rejected { retryable: bool, reason: String },
}

const CIRCUIT_ID_PREFIX_LEN: usize = 8;

/// Process-local CircuitId generator.  The random prefix separates daemon
/// lifetimes, while the counter makes source-side reuse impossible without a
/// process-lifetime set of every ID ever issued.
struct CircuitIdGenerator {
    prefix: [u8; CIRCUIT_ID_PREFIX_LEN],
    next_counter: AtomicU64,
}

impl Default for CircuitIdGenerator {
    fn default() -> Self {
        let mut prefix = [0; CIRCUIT_ID_PREFIX_LEN];
        getrandom::fill(&mut prefix).expect("OS random source unavailable");
        Self {
            prefix,
            next_counter: AtomicU64::new(1),
        }
    }
}

impl CircuitIdGenerator {
    fn next(&self) -> CircuitId {
        let counter = self
            .next_counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
                counter.checked_add(1)
            })
            .expect("CircuitId counter exhausted");
        let mut bytes = [0; 16];
        bytes[..CIRCUIT_ID_PREFIX_LEN].copy_from_slice(&self.prefix);
        bytes[CIRCUIT_ID_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
        CircuitId(bytes)
    }
}

/// Source-side pending OPEN registry. This is deliberately separate from the
/// session ACK registry: circuit establishment and key establishment have
/// different identities and failure semantics.
#[derive(Clone, Default)]
pub struct CircuitOpenManager {
    waiters: OpenWaiters,
    circuit_id_generator: Arc<CircuitIdGenerator>,
    authorized_links: AuthorizedOpenLinks,
    slots: CircuitSlots,
    active_workers: Arc<std::sync::Mutex<HashSet<String>>>,
    active_changed: Arc<tokio::sync::Notify>,
    active_generation: Arc<AtomicU64>,
    next_lease_epoch: Arc<AtomicU64>,
    next_attempt_id: Arc<AtomicU64>,
    desired: DesiredCircuitState,
}
impl CircuitOpenManager {
    /// CircuitId values are prefixed with a process-lifetime random value and
    /// suffixed with a monotonic counter. A node restart is the explicitly
    /// stateless boundary defined by RFC-0008.
    pub async fn next_circuit_id(&self) -> CircuitId {
        self.circuit_id_generator.next()
    }
    async fn register_inner(
        &self,
        key: (u64, CircuitId),
        expected_public_key: String,
        allowed_reject_public_keys: Vec<String>,
        expected_renewal_counter: Option<u64>,
        link_token: crate::link::LinkToken,
        attempt_id: Option<u64>,
    ) -> oneshot::Receiver<OpenResult> {
        let (sender, receiver) = oneshot::channel();
        let mut waiters = self.waiters.lock().await;
        if link_token.is_active() {
            waiters.insert(
                key,
                OpenWaiter {
                    attempt_id,
                    expected_public_key,
                    allowed_reject_public_keys,
                    expected_renewal_counter,
                    link_token,
                    sender,
                },
            );
        }
        receiver
    }
    pub async fn register(
        &self,
        link_instance: u64,
        circuit_id: CircuitId,
        expected_public_key: String,
        allowed_reject_public_keys: Vec<String>,
        expected_renewal_counter: Option<u64>,
        link_token: crate::link::LinkToken,
    ) -> oneshot::Receiver<OpenResult> {
        self.register_inner(
            (link_instance, circuit_id),
            expected_public_key,
            allowed_reject_public_keys,
            expected_renewal_counter,
            link_token,
            None,
        )
        .await
    }
    pub async fn register_for_attempt(
        &self,
        attempt: &OpenAttempt,
        expected_public_key: String,
        allowed_reject_public_keys: Vec<String>,
        link_token: crate::link::LinkToken,
    ) -> oneshot::Receiver<OpenResult> {
        self.register_inner(
            (attempt.link_instance, attempt.circuit_id),
            expected_public_key,
            allowed_reject_public_keys,
            None,
            link_token,
            Some(attempt.attempt_id),
        )
        .await
    }
    pub async fn resolve(
        &self,
        link_instance: u64,
        circuit_id: CircuitId,
        responder_public_key: &str,
        result: OpenResult,
    ) -> bool {
        let key = (link_instance, circuit_id);
        let (waiter, link_token) = {
            let mut waiters = self.waiters.lock().await;
            let permitted = waiters.get(&key).is_some_and(|waiter| match &result {
                OpenResult::Acknowledged => {
                    waiter.link_token.is_active()
                        && waiter.expected_renewal_counter.is_none()
                        && waiter.expected_public_key == responder_public_key
                }
                OpenResult::RenewAcknowledged { counter } => {
                    waiter.link_token.is_active()
                        && waiter.expected_renewal_counter == Some(*counter)
                        && waiter.expected_public_key == responder_public_key
                }
                OpenResult::Rejected { .. } => {
                    waiter.link_token.is_active()
                        && waiter
                            .allowed_reject_public_keys
                            .iter()
                            .any(|key| key == responder_public_key)
                }
            });
            let waiter = permitted.then(|| waiters.remove(&key)).flatten();
            let link_token = waiter.as_ref().map(|waiter| waiter.link_token.clone());
            (waiter, link_token)
        };

        let Some(waiter) = waiter else {
            return false;
        };
        if matches!(&result, OpenResult::Acknowledged)
            && let Some(link_token) = link_token
        {
            // An OPEN waiter is tied to its attempt. Take slots before
            // authorized_links so cancellation cannot clear the attempt and
            // then lose a race with ACK publication. remove_link and
            // commit_if_current use the same order.
            let slots = self.slots.lock().await;
            if let Some(attempt_id) = waiter.attempt_id
                && !slots.values().any(|slot| {
                    slot.attempt.as_ref().is_some_and(|attempt| {
                        attempt.attempt_id == attempt_id
                            && attempt.circuit_id == circuit_id
                            && attempt.link_instance == link_instance
                    })
                })
            {
                return false;
            }

            // remove_link revokes the token before taking this lock. Checking
            // while holding the authorization lock makes teardown and ACK
            // publication linearizable: whichever side wins, a revoked Link
            // cannot leave an authorization behind. Publish authorization
            // before waking the worker, so commit_if_current cannot observe
            // an ACK without its corresponding authorization.
            let mut authorized_links = self.authorized_links.lock().await;
            if link_token.is_active() {
                authorized_links.insert(circuit_id, link_instance);
                let delivered = waiter.sender.send(result).is_ok();
                if !delivered {
                    authorized_links.remove(&circuit_id);
                }
                delivered
            } else {
                false
            }
        } else {
            waiter.sender.send(result).is_ok()
        }
    }
    pub async fn clear(&self, link_instance: u64, circuit_id: CircuitId) {
        self.waiters
            .lock()
            .await
            .remove(&(link_instance, circuit_id));
    }
    pub async fn remove_link(&self, link_instance: u64, link_token: crate::link::LinkToken) {
        link_token.revoke();
        {
            self.waiters
                .lock()
                .await
                .retain(|(instance, _), _| *instance != link_instance);

            // Keep the lock order slots -> authorized_links consistent with
            // commit_if_current. Holding both locks makes Link teardown
            // linearizable with a concurrent OPEN acknowledgement.
            let mut slots = self.slots.lock().await;
            let mut authorized_links = self.authorized_links.lock().await;
            authorized_links.retain(|_, instance| *instance != link_instance);
            for slot in slots.values_mut() {
                if slot
                    .attempt
                    .as_ref()
                    .is_some_and(|attempt| attempt.link_instance == link_instance)
                {
                    slot.attempt = None;
                }
                if slot.desired.as_ref().is_some_and(|guard| {
                    guard
                        .identity
                        .as_ref()
                        .is_some_and(|identity| identity.first_hop_link_instance == link_instance)
                }) {
                    slot.desired = None;
                }
                if slot
                    .active
                    .as_ref()
                    .is_some_and(|circuit| circuit.link_instance == link_instance)
                    && let Some(active) = slot.active.take()
                {
                    active.send_gate.store(false, Ordering::Release);
                }
            }
        }
        // Even when no active lease used this Link, a pending per-destination
        // worker may be waiting on the old attempt or desired guard.  Wake it
        // so Link replacement/removal is reconciled immediately.
        self.notify_active_change();
    }
    pub async fn is_authorized(&self, link_instance: u64, circuit_id: CircuitId) -> bool {
        self.authorized_links
            .lock()
            .await
            .get(&circuit_id)
            .is_some_and(|instance| *instance == link_instance)
    }
    pub async fn activate(
        &self,
        destination: String,
        circuit_id: CircuitId,
        key: chacha20poly1305::Key,
        link_instance: u64,
        path: (Vec<String>, u16),
    ) {
        let (path, path_inner_mtu) = path;
        let mut slots = self.slots.lock().await;
        let slot = slots.entry(destination).or_default();
        if let Some(previous) = &slot.active {
            previous.send_gate.store(false, Ordering::Release);
        }
        let lease_epoch = self.next_lease_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        let send_gate = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let send_budget = Arc::new(AtomicUsize::new(usize::from(path_inner_mtu)));
        slot.active = Some(ActiveCircuit {
            circuit_id,
            data_key: key,
            link_instance,
            renewal_counter: Arc::new(AtomicU64::new(0)),
            path,
            path_inner_mtu,
            circuit_ceiling: path_inner_mtu,
            configured_inner_mtu: path_inner_mtu,
            capacity_vector: CapacityVector::default(),
            route_overrides: Vec::new(),
            config_generation: 0,
            lease_epoch,
            send_gate,
            send_budget,
        });
        self.notify_active_change();
    }
    pub async fn deactivate(&self, destination: &str, circuit_id: CircuitId) {
        // Keep this order aligned with commit_if_current and remove_link.
        // Otherwise a concurrent commit can hold slots while waiting for
        // authorized_links and teardown can hold authorized_links while
        // waiting for slots.
        let removed = {
            let mut slots = self.slots.lock().await;
            let mut authorized_links = self.authorized_links.lock().await;
            authorized_links.remove(&circuit_id);
            slots.get_mut(destination).and_then(|slot| {
                slot.active
                    .take_if(|circuit| circuit.circuit_id == circuit_id)
            })
        };
        if let Some(circuit) = removed {
            circuit.send_gate.store(false, Ordering::Release);
            self.notify_active_change();
        }
    }

    /// Publish the resolver's current guard before starting or completing an
    /// OPEN.  A capacity-only update must leave the identity unchanged.
    pub async fn set_desired_guard(
        &self,
        destination: impl Into<String>,
        identity: Option<crate::reconcile::CircuitIdentity>,
        config_generation: u64,
        hard_revoked: bool,
    ) {
        self.slots
            .lock()
            .await
            .entry(destination.into())
            .or_default()
            .desired = Some(DesiredGuard {
            resolution_generation: 0,
            identity,
            config_generation,
            availability: if hard_revoked {
                crate::reconcile::Availability::HardRevoked {
                    generation: 0,
                    reason: "explicit hard revoke".into(),
                }
            } else {
                crate::reconcile::Availability::Ready
            },
            capacity_vector: CapacityVector::default(),
            verified_inner_mtu: None,
        });
    }

    pub async fn set_desired_resolution(
        &self,
        destination: impl Into<String>,
        resolution: crate::reconcile::DesiredResolution,
    ) {
        let destination = destination.into();
        let capacity_vector = resolution
            .path
            .as_ref()
            .map(|path| path.capacity_vector.clone())
            .unwrap_or_default();
        let verified_inner_mtu = resolution.path.as_ref().map(|path| path.verified_inner_mtu);
        let mut slots = self.slots.lock().await;
        let slot = slots.entry(destination).or_default();
        if slot.desired.as_ref().is_some_and(|current| {
            resolution.config_generation < current.config_generation
                || (resolution.config_generation == current.config_generation
                    && resolution.generation < current.resolution_generation)
        }) {
            return;
        }
        slot.desired = Some(DesiredGuard {
            resolution_generation: resolution.generation,
            identity: resolution.identity(),
            config_generation: resolution.config_generation,
            availability: resolution.availability,
            capacity_vector,
            verified_inner_mtu,
        });
    }

    pub async fn desired_is_hard_revoked(&self, destination: &str) -> bool {
        self.slots
            .lock()
            .await
            .get(destination)
            .and_then(|slot| slot.desired.as_ref())
            .is_some_and(|guard| {
                matches!(
                    guard.availability,
                    crate::reconcile::Availability::HardRevoked { .. }
                )
            })
    }

    pub async fn begin_attempt(
        &self,
        destination: impl Into<String>,
        circuit_id: CircuitId,
        identity: crate::reconcile::CircuitIdentity,
        config_generation: u64,
        link_instance: u64,
    ) -> Option<OpenAttempt> {
        self.begin_attempt_with_capacity(OpenAttemptInput {
            destination: destination.into(),
            circuit_id,
            identity,
            config_generation,
            link_instance,
            capacity_vector: CapacityVector::default(),
            route_overrides: Vec::new(),
        })
        .await
    }

    pub async fn begin_attempt_with_capacity(
        &self,
        input: OpenAttemptInput,
    ) -> Option<OpenAttempt> {
        let destination = input.destination;
        let mut slots = self.slots.lock().await;
        let slot = slots.entry(destination.clone()).or_default();
        if slot.attempt.is_some() {
            return None;
        }
        let attempt = OpenAttempt {
            destination: destination.clone(),
            attempt_id: self.next_attempt_id.fetch_add(1, Ordering::AcqRel) + 1,
            circuit_id: input.circuit_id,
            identity: input.identity,
            config_generation: input.config_generation,
            link_instance: input.link_instance,
            capacity_vector: input.capacity_vector,
            route_overrides: input.route_overrides,
        };
        slot.attempt = Some(attempt.clone());
        Some(attempt)
    }

    pub fn config_generation(&self) -> u64 {
        self.desired.config_generation.load(Ordering::Acquire)
    }

    pub fn bump_config_generation(&self) -> u64 {
        self.desired
            .config_generation
            .fetch_add(1, Ordering::AcqRel)
            + 1
    }

    pub async fn cancel_attempt(&self, attempt: &OpenAttempt) {
        let mut slots = self.slots.lock().await;
        let cancelled = if slots
            .get(&attempt.destination)
            .and_then(|slot| slot.attempt.as_ref())
            .is_some_and(|current| current.attempt_id == attempt.attempt_id)
        {
            slots
                .get_mut(&attempt.destination)
                .expect("slot exists")
                .attempt = None;
            true
        } else {
            false
        };
        if cancelled {
            // Keep authorization cleanup under the same slots ->
            // authorized_links order as commit_if_current and Link teardown.
            self.authorized_links
                .lock()
                .await
                .remove(&attempt.circuit_id);
        }
    }

    /// Request a new source-side lease without competing with the persistent
    /// per-destination OPEN worker. Sequence exhaustion is a worker event, so
    /// the request must wake the existing worker instead of being dropped by
    /// the one-worker claim gate.
    pub async fn request_rebuild(&self, destination: &str) {
        self.slots
            .lock()
            .await
            .entry(destination.to_owned())
            .or_default()
            .rebuild_requested = true;
        self.notify_active_change();
    }

    pub async fn take_rebuild_request(&self, destination: &str) -> bool {
        self.slots
            .lock()
            .await
            .get_mut(destination)
            .is_some_and(|slot| std::mem::take(&mut slot.rebuild_requested))
    }

    /// Coalesce packet-driven recovery requests per destination. A route can
    /// reject many packets while its worker waits for topology; those packets
    /// must not create an unbounded control-plane queue.
    pub async fn request_ensure(&self, destination: &str) {
        self.desired
            .ensure_requests
            .lock()
            .await
            .insert(destination.to_owned());
        self.desired.ensure_changed.notify_waiters();
    }

    pub async fn wait_for_ensure_requests(&self) -> Vec<String> {
        loop {
            let notified = self.desired.ensure_changed.notified();
            let requests = {
                let mut pending = self.desired.ensure_requests.lock().await;
                pending.drain().collect::<Vec<_>>()
            };
            if !requests.is_empty() {
                return requests;
            }
            notified.await;
        }
    }

    /// The sole active-lease linearization point.  The attempt, desired guard,
    /// authorization and old send gate are checked while the active map is
    /// locked; no caller can publish a stale ACK by racing this operation.
    pub async fn commit_if_current(
        &self,
        attempt: &OpenAttempt,
        key: chacha20poly1305::Key,
        path: Vec<String>,
        circuit_ceiling: u16,
    ) -> Result<ActiveCircuit, CommitError> {
        let mut slots = self.slots.lock().await;
        let Some(slot) = slots.get_mut(&attempt.destination) else {
            return Err(CommitError::StaleAttempt);
        };
        if slot.attempt.as_ref() != Some(attempt) {
            return Err(CommitError::StaleAttempt);
        }
        let rejection = if self.config_generation() != attempt.config_generation
            || attempt.identity.destination != attempt.destination
            || attempt.identity.first_hop_link_instance != attempt.link_instance
            || path != attempt.identity.ordered_path
        {
            Some(CommitError::StaleAttempt)
        } else {
            let Some(guard) = slot.desired.as_ref() else {
                slot.attempt = None;
                drop(slots);
                self.authorized_links
                    .lock()
                    .await
                    .remove(&attempt.circuit_id);
                return Err(CommitError::StaleAttempt);
            };
            if (!attempt.capacity_vector.edges.is_empty()
                && !attempt.capacity_vector.matches_path(&path))
                || (!guard.capacity_vector.edges.is_empty()
                    && !guard.capacity_vector.matches_path(&path))
                || !attempt.capacity_vector.is_well_formed()
                || !guard.capacity_vector.is_well_formed()
            {
                Some(CommitError::StaleAttempt)
            } else if matches!(
                guard.availability,
                crate::reconcile::Availability::HardRevoked { .. }
            ) {
                Some(CommitError::HardRevoked)
            } else if !matches!(guard.availability, crate::reconcile::Availability::Ready)
                || guard.config_generation != attempt.config_generation
                || guard.identity.as_ref() != Some(&attempt.identity)
            {
                Some(CommitError::StaleAttempt)
            } else {
                None
            }
        };
        if let Some(error) = rejection {
            slot.attempt = None;
            drop(slots);
            self.authorized_links
                .lock()
                .await
                .remove(&attempt.circuit_id);
            return Err(error);
        }
        let guard = slot
            .desired
            .as_ref()
            .expect("validated desired guard")
            .clone();
        let capacity_vector = match (
            attempt.capacity_vector.edges.is_empty(),
            guard.capacity_vector.edges.is_empty(),
        ) {
            (true, true) => CapacityVector::default(),
            (true, false) => guard.capacity_vector.clone(),
            (false, true) => attempt.capacity_vector.clone(),
            (false, false)
                if attempt
                    .capacity_vector
                    .accepts_update(&guard.capacity_vector) =>
            {
                guard.capacity_vector.clone()
            }
            (false, false)
                if guard
                    .capacity_vector
                    .accepts_update(&attempt.capacity_vector) =>
            {
                attempt.capacity_vector.clone()
            }
            (false, false) => {
                slot.attempt = None;
                drop(slots);
                self.authorized_links
                    .lock()
                    .await
                    .remove(&attempt.circuit_id);
                return Err(CommitError::StaleAttempt);
            }
        };
        let initial_budget = circuit_ceiling
            .min(capacity_vector.capacity().unwrap_or(u16::MAX))
            .min(guard.verified_inner_mtu.unwrap_or(u16::MAX));
        if initial_budget == 0 {
            slot.attempt = None;
            drop(slots);
            self.authorized_links
                .lock()
                .await
                .remove(&attempt.circuit_id);
            return Err(CommitError::StaleAttempt);
        }
        if !self
            .authorized_links
            .lock()
            .await
            .get(&attempt.circuit_id)
            .is_some_and(|instance| *instance == attempt.link_instance)
        {
            slot.attempt = None;
            drop(slots);
            return Err(CommitError::Unauthorized);
        }
        if let Some(previous) = &slot.active {
            previous.send_gate.store(false, Ordering::Release);
        }
        let lease_epoch = self.next_lease_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        let lease = ActiveCircuit {
            circuit_id: attempt.circuit_id,
            data_key: key,
            link_instance: attempt.link_instance,
            renewal_counter: Arc::new(AtomicU64::new(0)),
            path,
            route_overrides: attempt.route_overrides.clone(),
            path_inner_mtu: circuit_ceiling,
            circuit_ceiling,
            configured_inner_mtu: circuit_ceiling,
            capacity_vector,
            config_generation: attempt.config_generation,
            lease_epoch,
            send_gate: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            send_budget: Arc::new(AtomicUsize::new(usize::from(initial_budget))),
        };
        slot.active = Some(lease.clone());
        slot.attempt = None;
        drop(slots);
        self.notify_active_change();
        Ok(lease)
    }

    pub async fn update_active_budget(
        &self,
        destination: &str,
        link_instance: u64,
        configured_inner_mtu: u16,
        verified_inner_mtu: u16,
    ) -> bool {
        self.update_active_budget_with_vector(
            destination,
            link_instance,
            configured_inner_mtu,
            verified_inner_mtu,
            CapacityVector::default(),
        )
        .await
    }

    pub async fn update_active_budget_with_vector(
        &self,
        destination: &str,
        link_instance: u64,
        configured_inner_mtu: u16,
        verified_inner_mtu: u16,
        capacity_vector: CapacityVector,
    ) -> bool {
        let mut slots = self.slots.lock().await;
        let Some(circuit) = slots
            .get_mut(destination)
            .and_then(|slot| slot.active.as_mut())
            .filter(|circuit| circuit.link_instance == link_instance)
        else {
            return false;
        };
        apply_active_budget(
            circuit,
            configured_inner_mtu,
            verified_inner_mtu,
            capacity_vector,
        )
    }

    /// Refresh a route's budget only if the lease observed by the caller is
    /// still the same lease.  This keeps route publication from combining an
    /// old circuit id/key with a replacement lease that reused the first hop.
    pub async fn update_active_budget_for_lease(
        &self,
        (destination, circuit_id, path, link_instance): (&str, CircuitId, &[String], u64),
        configured_inner_mtu: u16,
        verified_inner_mtu: u16,
        capacity_vector: CapacityVector,
    ) -> bool {
        let mut slots = self.slots.lock().await;
        let Some(circuit) = slots
            .get_mut(destination)
            .and_then(|slot| slot.active.as_mut())
            .filter(|circuit| {
                circuit.circuit_id == circuit_id
                    && circuit.link_instance == link_instance
                    && circuit.path == path
            })
        else {
            return false;
        };
        apply_active_budget(
            circuit,
            configured_inner_mtu,
            verified_inner_mtu,
            capacity_vector,
        )
    }
}

fn apply_active_budget(
    circuit: &mut ActiveCircuit,
    configured_inner_mtu: u16,
    verified_inner_mtu: u16,
    capacity_vector: CapacityVector,
) -> bool {
    if (!capacity_vector.edges.is_empty() && !capacity_vector.matches_path(&circuit.path))
        || (!circuit.capacity_vector.edges.is_empty()
            && !circuit.capacity_vector.matches_path(&circuit.path))
        || !capacity_vector.is_well_formed()
        || !circuit.capacity_vector.is_well_formed()
    {
        return false;
    }
    if !capacity_vector.edges.is_empty()
        && !circuit.capacity_vector.accepts_update(&capacity_vector)
    {
        return false;
    }
    let known_capacity = capacity_vector
        .capacity()
        .or_else(|| circuit.capacity_vector.capacity())
        .unwrap_or(verified_inner_mtu);
    let budget = configured_inner_mtu
        .min(known_capacity)
        .min(circuit.circuit_ceiling);
    circuit.configured_inner_mtu = configured_inner_mtu;
    if !capacity_vector.edges.is_empty() {
        circuit.capacity_vector = capacity_vector;
    }
    circuit
        .send_budget
        .store(usize::from(budget), Ordering::Release);
    true
}

impl CircuitOpenManager {
    /// Apply a confirmed capacity event from the first-hop Link without
    /// waiting for an LSA round trip or the route refresher.  Only the exact
    /// active first edge is eligible; a stale generation is ignored.
    pub async fn update_active_link_capacity(
        &self,
        link_instance: u64,
        capacity: u16,
        generation: u64,
    ) -> usize {
        let mut slots = self.slots.lock().await;
        let mut changed = 0;
        for circuit in slots.values_mut().filter_map(|slot| slot.active.as_mut()) {
            if circuit.link_instance != link_instance {
                continue;
            }
            if !circuit.capacity_vector.is_well_formed()
                || (!circuit.capacity_vector.edges.is_empty()
                    && !circuit.capacity_vector.matches_path(&circuit.path))
            {
                continue;
            }
            let Some(next_hop) = circuit.path.get(1) else {
                continue;
            };
            let Some(edge) = circuit
                .capacity_vector
                .edges
                .iter_mut()
                .find(|edge| edge.from == circuit.path[0] && edge.to == *next_hop)
            else {
                circuit.capacity_vector.edges.insert(
                    0,
                    CapacityEdge {
                        from: circuit.path[0].clone(),
                        to: next_hop.clone(),
                        capacity,
                        generation,
                    },
                );
                circuit.send_budget.store(
                    usize::from(
                        circuit
                            .configured_inner_mtu
                            .min(circuit.circuit_ceiling)
                            .min(circuit.capacity_vector.capacity().unwrap_or(capacity)),
                    ),
                    Ordering::Release,
                );
                changed += 1;
                continue;
            };
            if generation < edge.generation
                || (generation == edge.generation && capacity != edge.capacity)
            {
                continue;
            }
            if generation == edge.generation && capacity == edge.capacity {
                continue;
            }
            edge.capacity = capacity;
            edge.generation = generation;
            let budget = circuit
                .configured_inner_mtu
                .min(circuit.circuit_ceiling)
                .min(circuit.capacity_vector.capacity().unwrap_or(capacity));
            circuit
                .send_budget
                .store(usize::from(budget), Ordering::Release);
            changed += 1;
        }
        drop(slots);
        if changed != 0 {
            self.notify_active_change();
        }
        changed
    }
    pub async fn active_for_destination(&self, destination: &str) -> Option<ActiveCircuit> {
        self.slots
            .lock()
            .await
            .get(destination)
            .and_then(|slot| slot.active.clone())
    }
    /// Record preferred-path readiness. Changing the path or losing readiness
    /// resets its timer. A pending result gives the exact time at which the
    /// worker should re-evaluate, avoiding a periodic readiness poll.
    pub async fn migration_readiness(
        &self,
        destination: &str,
        preferred_identity: &crate::reconcile::CircuitIdentity,
        ready: bool,
        stability: std::time::Duration,
    ) -> Option<MigrationReadiness> {
        let mut slots = self.slots.lock().await;
        let slot = slots.entry(destination.to_owned()).or_default();
        if !ready {
            slot.migration = None;
            return None;
        }
        let now = Instant::now();
        let entry = slot.migration.get_or_insert_with(|| MigrationRecord {
            preferred_identity: preferred_identity.clone(),
            ready_since: now,
            started_at: None,
            last_error: None,
        });
        if entry.preferred_identity != *preferred_identity {
            entry.preferred_identity = preferred_identity.clone();
            entry.ready_since = now;
            entry.started_at = None;
            entry.last_error = None;
        }
        Some(match entry.ready_since.checked_add(stability) {
            Some(ready_at) if now >= ready_at => MigrationReadiness::Ready,
            Some(ready_at) => MigrationReadiness::PendingUntil(ready_at),
            None => MigrationReadiness::Pending,
        })
    }
    pub async fn begin_migration(&self, destination: &str) -> Option<Instant> {
        self.slots
            .lock()
            .await
            .get_mut(destination)
            .and_then(|slot| slot.migration.as_mut())
            .map(|entry| *entry.started_at.get_or_insert_with(Instant::now))
    }
    pub async fn migration_snapshot(
        &self,
        destination: &str,
    ) -> Option<(
        crate::reconcile::CircuitIdentity,
        Option<Instant>,
        Option<String>,
    )> {
        self.slots
            .lock()
            .await
            .get(destination)
            .and_then(|slot| slot.migration.as_ref())
            .map(|entry| {
                (
                    entry.preferred_identity.clone(),
                    entry.started_at,
                    entry.last_error.clone(),
                )
            })
    }
    pub async fn migration_error(&self, destination: &str, error: impl Into<String>) {
        if let Some(entry) = self
            .slots
            .lock()
            .await
            .get_mut(destination)
            .and_then(|slot| slot.migration.as_mut())
        {
            entry.last_error = Some(error.into());
        }
    }
    pub async fn migration_overdue(
        &self,
        destination: &str,
        deadline: std::time::Duration,
    ) -> bool {
        self.slots
            .lock()
            .await
            .get(destination)
            .and_then(|slot| slot.migration.as_ref())
            .and_then(|entry| entry.started_at)
            .is_some_and(|started| started.elapsed() >= deadline)
    }
    pub async fn clear_migration(&self, destination: &str) {
        if let Some(slot) = self.slots.lock().await.get_mut(destination) {
            slot.migration = None;
        }
    }
    pub async fn reset_migration_readiness(&self, destination: &str) {
        if let Some(slot) = self.slots.lock().await.get_mut(destination) {
            slot.migration = None;
        }
    }
    /// Invalidate a lease after an authenticated receiver reports an unknown
    /// session/relay label. The source-side CircuitId is daemon-unique and is
    /// matched to the exact first-hop Link instance.
    pub async fn invalidate_circuit(&self, link_instance: u64, circuit_id: CircuitId) -> bool {
        let destination = self
            .slots
            .lock()
            .await
            .iter()
            .find_map(|(destination, slot)| {
                slot.active
                    .as_ref()
                    .filter(|active| {
                        active.link_instance == link_instance && active.circuit_id == circuit_id
                    })
                    .map(|_| destination.clone())
            });
        let Some(destination) = destination else {
            return false;
        };
        self.deactivate(&destination, circuit_id).await;
        self.clear_migration(&destination).await;
        true
    }
    pub async fn active_for(
        &self,
        destination: &str,
        link_instance: u64,
    ) -> Option<(CircuitId, chacha20poly1305::Key)> {
        self.slots
            .lock()
            .await
            .get(destination)
            .and_then(|slot| slot.active.as_ref())
            .filter(|active| active.link_instance == link_instance)
            .map(|active| (active.circuit_id, active.data_key))
    }
    pub async fn active_path_inner_mtu(
        &self,
        destination: &str,
        link_instance: u64,
    ) -> Option<u16> {
        self.slots
            .lock()
            .await
            .get(destination)
            .and_then(|slot| slot.active.as_ref())
            .filter(|active| active.link_instance == link_instance)
            .map(|active| active.send_budget.load(Ordering::Acquire) as u16)
    }
    pub async fn active_send_context(
        &self,
        destination: &str,
        link_instance: u64,
    ) -> Option<(u64, Arc<std::sync::atomic::AtomicBool>, Arc<AtomicUsize>)> {
        self.slots
            .lock()
            .await
            .get(destination)
            .and_then(|slot| slot.active.as_ref())
            .filter(|active| active.link_instance == link_instance)
            .map(|active| {
                (
                    active.lease_epoch,
                    active.send_gate.clone(),
                    active.send_budget.clone(),
                )
            })
    }
    pub async fn active_circuits(&self) -> Vec<(String, ActiveCircuit)> {
        self.slots
            .lock()
            .await
            .iter()
            .filter_map(|(destination, slot)| {
                slot.active
                    .as_ref()
                    .map(|active| (destination.clone(), active.clone()))
            })
            .collect()
    }
    pub async fn is_active(&self, destination: &str, circuit_id: CircuitId) -> bool {
        self.slots
            .lock()
            .await
            .get(destination)
            .and_then(|slot| slot.active.as_ref())
            .is_some_and(|active| active.circuit_id == circuit_id)
    }
    pub fn active_generation(&self) -> u64 {
        self.active_generation.load(Ordering::Acquire)
    }
    /// Wake source reconciliation when a Link instance is added, replaced or
    /// removed. This is distinct from a periodic retry: a first hop that has
    /// just reconnected must make pending destinations retry immediately.
    pub fn request_reconcile(&self) {
        self.notify_active_change();
    }
    /// Register for notification before checking the generation, so a Link
    /// close cannot be lost between the worker's active-state check and its
    /// wait for an early rebuild.
    pub async fn wait_active_change(&self, generation: u64) {
        loop {
            let notified = self.active_changed.notified();
            if self.active_generation() != generation {
                return;
            }
            notified.await;
            if self.active_generation() != generation {
                return;
            }
        }
    }
    fn notify_active_change(&self) {
        self.active_generation.fetch_add(1, Ordering::Release);
        self.active_changed.notify_waiters();
    }
    /// A topology update can arrive while an earlier retry is pending. Keep
    /// exactly one bounded worker per destination to avoid competing OPEN
    /// attempts and control-stream churn.  The returned claim releases itself
    /// when dropped, so a panicking worker cannot leave the destination
    /// permanently unclaimable.
    pub fn claim_worker(&self, destination: &str) -> Option<WorkerClaim> {
        let mut workers = self.active_workers.lock().expect("worker claim lock");
        if !workers.insert(destination.to_owned()) {
            return None;
        }
        Some(WorkerClaim {
            workers: self.active_workers.clone(),
            destination: destination.to_owned(),
        })
    }
}

/// Receiver sessions are installed as part of an authenticated OPEN.
const SESSION_SHARDS: usize = 16;

#[derive(Clone)]
pub struct SessionManager {
    receivers: Arc<Vec<Mutex<HashMap<u64, crypto::ReceiverSessions>>>>,
}
impl Default for SessionManager {
    fn default() -> Self {
        Self {
            receivers: Arc::new(
                (0..SESSION_SHARDS)
                    .map(|_| Mutex::new(HashMap::new()))
                    .collect(),
            ),
        }
    }
}
impl SessionManager {
    fn shard(&self, link_instance: u64) -> &Mutex<HashMap<u64, crypto::ReceiverSessions>> {
        &self.receivers[(link_instance as usize) % SESSION_SHARDS]
    }
    pub async fn install_open(
        &self,
        link_instance: u64,
        circuit_id: CircuitId,
        source: ed25519_dalek::VerifyingKey,
        key: chacha20poly1305::Key,
    ) {
        let mut receivers = self.shard(link_instance).lock().await;
        let sessions = receivers.entry(link_instance).or_default();
        sessions.install(circuit_id, source, key);
    }

    pub async fn install_return(
        &self,
        link_instance: u64,
        circuit_id: CircuitId,
        destination: ed25519_dalek::VerifyingKey,
        key: chacha20poly1305::Key,
    ) {
        let mut receivers = self.shard(link_instance).lock().await;
        let sessions = receivers.entry(link_instance).or_default();
        sessions.install_return(circuit_id, destination, key);
    }
    pub async fn open_data(
        &self,
        link_instance: u64,
        frame: &[u8],
    ) -> Result<
        (
            CircuitId,
            crypto::DataDirection,
            ed25519_dalek::VerifyingKey,
            Vec<u8>,
        ),
        crypto::CryptoError,
    > {
        self.shard(link_instance)
            .lock()
            .await
            .entry(link_instance)
            .or_default()
            .open_data(frame)
    }
    pub async fn remove_link(&self, link_instance: u64) {
        self.shard(link_instance)
            .lock()
            .await
            .remove(&link_instance);
    }
    pub async fn remove_circuit(&self, link_instance: u64, circuit_id: CircuitId) {
        if let Some(sessions) = self
            .shard(link_instance)
            .lock()
            .await
            .get_mut(&link_instance)
        {
            sessions.remove(circuit_id);
        }
    }
    pub async fn clear(&self) {
        for shard in self.receivers.iter() {
            shard.lock().await.clear();
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acknowledged_open_is_not_delivered_before_authorization_is_published() {
        let opens = CircuitOpenManager::default();
        let circuit_id = CircuitId([91; 16]);
        let link_token = crate::link::LinkToken::default();
        let mut receiver = opens
            .register(
                17,
                circuit_id,
                "peer-key".into(),
                Vec::new(),
                None,
                link_token,
            )
            .await;

        let authorization_lock = opens.authorized_links.lock().await;
        let opens_for_resolve = opens.clone();
        let resolve = tokio::spawn(async move {
            opens_for_resolve
                .resolve(17, circuit_id, "peer-key", OpenResult::Acknowledged)
                .await
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut receiver)
                .await
                .is_err(),
            "ACK must wait until its authorization can be published"
        );
        drop(authorization_lock);

        assert!(resolve.await.unwrap());
        assert_eq!(receiver.await.unwrap(), OpenResult::Acknowledged);
        assert!(opens.is_authorized(17, circuit_id).await);
    }

    #[tokio::test]
    async fn revoked_link_drops_ack_after_waiter_is_removed() {
        let opens = CircuitOpenManager::default();
        let circuit_id = CircuitId([92; 16]);
        let link_token = crate::link::LinkToken::default();
        let receiver = opens
            .register(
                18,
                circuit_id,
                "peer-key".into(),
                Vec::new(),
                None,
                link_token.clone(),
            )
            .await;

        let authorization_lock = opens.authorized_links.lock().await;
        let opens_for_resolve = opens.clone();
        let resolve = tokio::spawn(async move {
            opens_for_resolve
                .resolve(18, circuit_id, "peer-key", OpenResult::Acknowledged)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            loop {
                if opens.waiters.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("resolve must remove the waiter before waiting on authorization");

        link_token.revoke();
        drop(authorization_lock);

        assert!(!resolve.await.unwrap());
        assert!(receiver.await.is_err());
    }

    #[tokio::test]
    async fn cancelling_attempt_removes_ack_authorization() {
        let opens = CircuitOpenManager::default();
        let circuit_id = CircuitId([93; 16]);
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 19,
        };
        opens
            .set_desired_guard("exit", Some(identity.clone()), 0, false)
            .await;
        let attempt = opens
            .begin_attempt("exit", circuit_id, identity, 0, 19)
            .await
            .expect("attempt should be registered");
        let receiver = opens
            .register_for_attempt(
                &attempt,
                "peer-key".into(),
                Vec::new(),
                crate::link::LinkToken::default(),
            )
            .await;
        assert!(
            opens
                .resolve(19, circuit_id, "peer-key", OpenResult::Acknowledged)
                .await
        );
        assert!(opens.is_authorized(19, circuit_id).await);

        opens.cancel_attempt(&attempt).await;

        assert!(!opens.is_authorized(19, circuit_id).await);
        drop(receiver);
    }

    #[tokio::test]
    async fn cancelled_open_drops_late_ack_without_authorization() {
        let opens = CircuitOpenManager::default();
        let circuit_id = CircuitId([94; 16]);
        let identity = crate::reconcile::CircuitIdentity {
            destination: "exit".into(),
            ordered_path: vec!["source".into(), "exit".into()],
            first_hop_link_instance: 20,
        };
        opens
            .set_desired_guard("exit", Some(identity.clone()), 0, false)
            .await;
        let attempt = opens
            .begin_attempt("exit", circuit_id, identity, 0, 20)
            .await
            .expect("attempt should be registered");
        let receiver = opens
            .register_for_attempt(
                &attempt,
                "peer-key".into(),
                Vec::new(),
                crate::link::LinkToken::default(),
            )
            .await;

        opens.cancel_attempt(&attempt).await;
        assert!(
            !opens
                .resolve(20, circuit_id, "peer-key", OpenResult::Acknowledged)
                .await
        );
        assert!(receiver.await.is_err());
        assert!(!opens.is_authorized(20, circuit_id).await);
    }
}
