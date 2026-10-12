use crate::{
    identity::{encode_public, node_id},
    link::{LinkDirectory, LinkDirectoryRef, LinkHandle, LinkRef},
    policy::TransitPolicy,
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{Signer, Verifier};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

pub const CIRCUIT_LEASE: Duration = Duration::from_secs(12 * 60 * 60);
/// Active sources periodically prove that every downstream hop still owns the
/// binding.  This is the independent fallback when a Circuit feedback frame
/// is lost or a relay has already reclaimed its label.
pub const CIRCUIT_RENEW_INTERVAL: Duration = Duration::from_secs(30);
/// Traffic refreshes the lease far more often than the 12-hour deadline needs
/// it.  Throttling the deadline rewrite keeps authenticated DATA out of the
/// data-plane writer lock: the fast path below only takes a read lock.
pub fn circuit_lease() -> Duration {
    crate::timing::active().circuit_lease
}

pub fn circuit_renew_interval() -> Duration {
    crate::timing::active().circuit_renew_interval
}

fn lease_refresh_throttle_millis() -> u64 {
    crate::timing::active()
        .lease_refresh_throttle
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Process-local monotonic clock used for lock-free lease refresh throttling.
static MONOTONIC_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

#[cfg(any(test, debug_assertions))]
fn backdate_monotonic_epoch_impl() {
    let _ = MONOTONIC_EPOCH.get_or_init(|| Instant::now() - Duration::from_secs(3600));
}

/// Backdates the process-wide monotonic epoch used by lease-refresh
/// throttling for deterministic renewal tests. If the clock has already been
/// initialized, this is a no-op because `OnceLock` cannot be reset.
#[cfg(test)]
pub(crate) fn backdate_monotonic_epoch() {
    backdate_monotonic_epoch_impl();
}

// The binary target owns the daemon unit tests, so its debug build links the
// library as a normal dependency and cannot see `cfg(test)` items. Keep this
// hidden debug-only bridge; release builds do not expose the test helper.
#[cfg(all(not(test), debug_assertions))]
#[doc(hidden)]
pub fn backdate_monotonic_epoch() {
    backdate_monotonic_epoch_impl();
}

fn monotonic_millis() -> u64 {
    MONOTONIC_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// An indexed deadline heap.  A circuit owns at most one deadline, which is
/// adjusted in place when authenticated traffic refreshes its lease.  This
/// keeps scheduling state bounded by live circuits rather than packet rate.
#[derive(Default)]
struct LeaseDeadlines {
    heap: Vec<LeaseDeadline>,
    positions: HashMap<LeaseKey, usize>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct LeaseKey {
    incoming_instance: u64,
    circuit_id: CircuitId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeaseDeadline {
    at: Instant,
    key: LeaseKey,
    generation: u64,
}
impl LeaseDeadlines {
    fn insert_or_reset(&mut self, key: LeaseKey, at: Instant, generation: u64) {
        if let Some(&index) = self.positions.get(&key) {
            self.heap[index].at = at;
            self.heap[index].generation = generation;
            self.reheap(index);
            return;
        }
        let index = self.heap.len();
        self.heap.push(LeaseDeadline {
            at,
            key,
            generation,
        });
        self.positions.insert(key, index);
        self.sift_up(index);
    }

    fn remove(&mut self, key: LeaseKey) -> bool {
        let Some(index) = self.positions.remove(&key) else {
            return false;
        };
        let last = self.heap.len() - 1;
        self.heap.swap(index, last);
        let removed = self.heap.pop().expect("deadline index is valid");
        debug_assert_eq!(removed.key, key);
        if index < self.heap.len() {
            self.positions.insert(self.heap[index].key, index);
            self.reheap(index);
        }
        true
    }

    fn next(&self) -> Option<Instant> {
        self.heap.first().map(|entry| entry.at)
    }

    fn pop_due(&mut self, now: Instant) -> Vec<LeaseDeadline> {
        let mut due = Vec::new();
        while self.heap.first().is_some_and(|entry| entry.at <= now) {
            let deadline = self.heap[0];
            let removed = self.remove(deadline.key);
            debug_assert!(removed);
            due.push(deadline);
        }
        due
    }

    fn reheap(&mut self, index: usize) {
        if index > 0 && self.heap[index].at < self.heap[(index - 1) / 2].at {
            self.sift_up(index);
        } else {
            self.sift_down(index);
        }
    }

    fn sift_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.heap[parent].at <= self.heap[index].at {
                break;
            }
            self.swap(index, parent);
            index = parent;
        }
    }

    fn sift_down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            let right = left + 1;
            let Some(mut smallest) = (left < self.heap.len()).then_some(left) else {
                return;
            };
            if right < self.heap.len() && self.heap[right].at < self.heap[left].at {
                smallest = right;
            }
            if self.heap[index].at <= self.heap[smallest].at {
                return;
            }
            self.swap(index, smallest);
            index = smallest;
        }
    }

    fn swap(&mut self, left: usize, right: usize) {
        self.heap.swap(left, right);
        self.positions.insert(self.heap[left].key, left);
        self.positions.insert(self.heap[right].key, right);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CircuitId(pub [u8; 16]);
impl CircuitId {
    pub fn random() -> Self {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).expect("OS random source unavailable");
        Self(bytes)
    }
}
fn node_bytes(value: &str) -> [u8; 16] {
    let mut out = [0; 16];
    assert_eq!(value.len(), 32, "node id is 16-byte hex");
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("node id hex");
    }
    out
}
fn node_string(bytes: [u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
#[derive(Debug, Clone)]
pub struct CircuitOpen {
    pub source: String,
    pub destination: String,
    pub path: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OpenRequest {
    pub source: String,
    pub destination: String,
    pub path: Vec<String>,
    /// Opaque, end-to-end circuit identifier used by relays for forwarding.
    pub circuit_id: CircuitId,
    pub ephemeral_public_key: [u8; 32],
    pub public_key: String,
    pub signature: String,
}
impl OpenRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: impl Into<String>,
        source_key: &ed25519_dalek::SigningKey,
        destination: impl Into<String>,
        path: Vec<String>,
        circuit_id: CircuitId,
        ephemeral_public_key: [u8; 32],
    ) -> Self {
        let mut request = Self {
            source: source.into(),
            destination: destination.into(),
            path,
            circuit_id,
            ephemeral_public_key,
            public_key: encode_public(&source_key.verifying_key()),
            signature: String::new(),
        };
        request.signature =
            STANDARD_NO_PAD.encode(source_key.sign(&request.signing_bytes()).to_bytes());
        request
    }
    pub fn signing_bytes(&self) -> Vec<u8> {
        use crate::wire::Writer;
        let mut out = Writer::new();
        // The wire kind is part of the OPEN transcript. Source and
        // destination are derived from the authenticated key and path; local
        // routing policy is intentionally kept out of the signed wire object.
        out.u8(16);
        out.bytes(&self.circuit_id.0);
        out.bytes(&self.ephemeral_public_key);
        out.bytes(
            &STANDARD_NO_PAD
                .decode(&self.public_key)
                .expect("public key"),
        );
        out.u16(u16::try_from(self.path.len()).expect("path fits wire"));
        for node in &self.path {
            out.bytes(&node_bytes(node));
        }
        out.finish()
    }
    pub fn encode_body(&self) -> Result<Vec<u8>, crate::wire::Error> {
        use crate::wire::Writer;
        let mut out = Writer::new();
        out.bytes(&self.signing_bytes());
        out.bytes(
            &STANDARD_NO_PAD
                .decode(&self.signature)
                .map_err(|_| crate::wire::Error::Truncated)?,
        );
        Ok(out.finish())
    }
    pub fn decode_body(bytes: &[u8]) -> Result<Self, crate::wire::Error> {
        use crate::wire::Reader;
        let mut in_ = Reader::new(bytes);
        if in_.u8()? != 16 {
            return Err(crate::wire::Error::Truncated);
        }
        let circuit_id = CircuitId(in_.fixed()?);
        let ephemeral_public_key = in_.fixed()?;
        let public_key_bytes = in_.fixed::<32>()?;
        let public_key = STANDARD_NO_PAD.encode(public_key_bytes);
        let count = usize::from(in_.u16()?);
        if count == 0 || count > MAX_OPEN_PATH_HOPS {
            // Fail closed at wire-parse time. `wire::Error` has no policy
            // variant, so over-long counts report as `Truncated`; the
            // `verify`/`validate_open` bounds report `InvalidPath`.
            return Err(crate::wire::Error::Truncated);
        }
        let mut path = Vec::with_capacity(count);
        for _ in 0..count {
            path.push(node_string(in_.fixed()?));
        }
        let signature = STANDARD_NO_PAD.encode(in_.fixed::<64>()?);
        in_.finish()?;
        let source = crate::identity::decode_public(&public_key)
            .map(|key| node_id(&key))
            .map_err(|_| crate::wire::Error::Truncated)?;
        let destination = path.last().cloned().ok_or(crate::wire::Error::Truncated)?;
        Ok(Self {
            source,
            destination,
            path,
            circuit_id,
            ephemeral_public_key,
            public_key,
            signature,
        })
    }
    pub fn verify(&self) -> Result<(), CircuitError> {
        let key = crate::identity::decode_public(&self.public_key)
            .map_err(|e| CircuitError::Signature(e.to_string()))?;
        let signature = STANDARD_NO_PAD
            .decode(&self.signature)
            .map_err(|e| CircuitError::Signature(e.to_string()))?;
        let signature = ed25519_dalek::Signature::from_slice(&signature)
            .map_err(|e| CircuitError::Signature(e.to_string()))?;
        key.verify(&self.signing_bytes(), &signature)
            .map_err(|e| CircuitError::Signature(e.to_string()))?;
        if self.source != node_id(&key) {
            return Err(CircuitError::Signature(
                "source identity does not match public key".into(),
            ));
        }
        if self.path.len() > MAX_OPEN_PATH_HOPS {
            return Err(CircuitError::InvalidPath);
        }
        if self.path.first() != Some(&self.source) || self.path.last() != Some(&self.destination) {
            return Err(CircuitError::InvalidPath);
        }
        Ok(())
    }
    pub fn as_open(&self) -> CircuitOpen {
        CircuitOpen {
            source: self.source.clone(),
            destination: self.destination.clone(),
            path: self.path.clone(),
        }
    }
    pub fn forwarded(&self) -> Result<Self, CircuitError> {
        // The request is signed end-to-end. The ordered path establishes the
        // next hop at every relay, so forwarding is an idempotent clone.
        Ok(self.clone())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CircuitError {
    #[error("invalid path")]
    InvalidPath,
    #[error("transit denied")]
    Denied,
    #[error("manual path override denied")]
    ManualPathDenied,
    #[error("invalid source signature: {0}")]
    Signature(String),
    #[error("OPEN arrived from a peer that is not its declared previous hop")]
    UnexpectedPreviousHop,
    #[error("replayed OPEN request")]
    Replay,
    #[error("CircuitId is already bound to different OPEN fields")]
    Rebinding,
    #[error("circuit authorization capacity exceeded")]
    Capacity,
    #[error("renewal counter is older than the accepted renewal")]
    StaleRenewal,
}
pub fn validate_open(
    open: &CircuitOpen,
    here: &str,
    transit: &TransitPolicy,
) -> Result<(), CircuitError> {
    if open.path.len() < 2 || open.path.len() > MAX_OPEN_PATH_HOPS {
        return Err(CircuitError::InvalidPath);
    }
    let pos = open
        .path
        .iter()
        .position(|n| n == here)
        .ok_or(CircuitError::InvalidPath)?;
    if open.path.first() != Some(&open.source)
        || open.path.last() != Some(&open.destination)
        || open.path.iter().filter(|n| *n == here).count() != 1
    {
        return Err(CircuitError::InvalidPath);
    }
    if pos > 0 && pos + 1 < open.path.len() && !transit.permits(&open.source) {
        return Err(CircuitError::Denied);
    }
    Ok(())
}

/// Enforces a local manual override for locally originated and transit
/// circuits. A relay compares only the suffix from itself, so `[relay, exit]`
/// also authorizes `source -> relay -> exit`.
pub fn validate_manual_path(
    open: &CircuitOpen,
    here: &str,
    paths: &BTreeMap<String, Vec<Vec<String>>>,
) -> Result<(), CircuitError> {
    let Some(allowed) = paths.get(&open.destination) else {
        return Ok(());
    };
    let position = open
        .path
        .iter()
        .position(|node| node == here)
        .ok_or(CircuitError::InvalidPath)?;
    allowed
        .iter()
        .any(|path| path.as_slice() == &open.path[position..])
        .then_some(())
        .ok_or(CircuitError::ManualPathDenied)
}
#[derive(Default)]
pub struct LabelTable {
    forwards: HashMap<CircuitId, RelayBinding>,
}
pub type RelayLabelTables =
    Arc<std::sync::RwLock<HashMap<u64, Arc<std::sync::RwLock<LabelTable>>>>>;

const MAX_CIRCUIT_AUTHORIZATIONS: usize = 4096;
const MAX_LABEL_BINDINGS: usize = 4096;

/// Authorizations installed only after a signed OPEN reaches its final node.
/// A data frame must arrive on the same authenticated Link instance and carry
/// the same label and source public key.  This prevents a configured peer
/// from injecting a frame directly into an exit without a circuit.
#[derive(Clone, Default)]
pub struct CircuitAuthorizations {
    allowed: Arc<RwLock<HashMap<(u64, CircuitId), String>>>,
}

impl CircuitAuthorizations {
    pub async fn install(
        &self,
        link_instance: u64,
        circuit_id: CircuitId,
        source_key: String,
    ) -> Result<(), CircuitError> {
        let mut allowed = self.allowed.write().await;
        if !allowed.contains_key(&(link_instance, circuit_id))
            && allowed.len() >= MAX_CIRCUIT_AUTHORIZATIONS
        {
            return Err(CircuitError::Capacity);
        }
        allowed.insert((link_instance, circuit_id), source_key);
        Ok(())
    }

    pub async fn permits(
        &self,
        link_instance: u64,
        circuit_id: CircuitId,
        source_key: &str,
    ) -> bool {
        self.allowed
            .read()
            .await
            .get(&(link_instance, circuit_id))
            .is_some_and(|expected| expected == source_key)
    }

    pub async fn remove_link(&self, link_instance: u64) {
        self.allowed
            .write()
            .await
            .retain(|(instance, _), _| *instance != link_instance);
    }
    pub async fn remove(&self, link_instance: u64, circuit_id: CircuitId) {
        self.allowed
            .write()
            .await
            .remove(&(link_instance, circuit_id));
    }
}

struct CircuitBinding {
    source: String,
    destination: String,
    path: Vec<String>,
    public_key: String,
    ephemeral_public_key: [u8; 32],
    outgoing: Option<LinkRef>,
    renewal_counter: u64,
    close_counter: u64,
    lease_deadline: Instant,
    lease_generation: u64,
    last_refresh_millis: AtomicU64,
}

#[derive(Default)]
struct BindingState {
    bindings: HashMap<(u64, CircuitId), CircuitBinding>,
    deadlines: LeaseDeadlines,
}
impl Clone for CircuitBinding {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            destination: self.destination.clone(),
            path: self.path.clone(),
            public_key: self.public_key.clone(),
            ephemeral_public_key: self.ephemeral_public_key,
            outgoing: self.outgoing.clone(),
            renewal_counter: self.renewal_counter,
            close_counter: self.close_counter,
            lease_deadline: self.lease_deadline,
            lease_generation: self.lease_generation,
            last_refresh_millis: AtomicU64::new(self.last_refresh_millis.load(Ordering::Relaxed)),
        }
    }
}
impl CircuitBinding {
    fn matches(&self, request: &OpenRequest) -> bool {
        self.source == request.source
            && self.destination == request.destination
            && self.path == request.path
            && self.public_key == request.public_key
            && self.ephemeral_public_key == request.ephemeral_public_key
    }
}

#[derive(Clone)]
pub struct Router {
    pub local: String,
    transit: TransitPolicy,
    relay_permissions: Arc<RwLock<HashMap<String, bool>>>,
    known_sources: Arc<RwLock<HashSet<String>>>,
    paths: Arc<RwLock<BTreeMap<String, Vec<Vec<String>>>>>,
    links: LinkDirectoryRef,
    authorizations: CircuitAuthorizations,
    relay_labels: RelayLabelTables,
    secure_dataplane: bool,
    binding_state: Arc<std::sync::RwLock<BindingState>>,
    closed: Arc<std::sync::RwLock<HashSet<(u64, CircuitId)>>>,
    lease_notify: Arc<tokio::sync::Notify>,
}
/// Upper bound for OPEN path hops. Wire `count` is a `u16`, but paths are
/// short node lists; bounding decode/verify/validate together prevents a
/// ~4k-hop path from amplifying per-relay clone/forward work.
pub const MAX_OPEN_PATH_HOPS: usize = 16;
/// Upper bound for authenticated-close tombstones per router. `closed` is
/// only pruned on `remove_bindings`, so an unbounded set is a RAM DoS via
/// sequential open/close on one Link.
pub const MAX_CLOSED_BINDINGS: usize = 4096;

/// Records an authenticated teardown so a late duplicate OPEN/CLOSE for the
/// same `(incoming, circuit)` cannot resurrect the binding. The set is
/// bounded: at capacity one tombstone is evicted before insert, so
/// sequential open/close on one Link cannot grow memory without bound.
/// Eviction prefers a tombstone from the same incoming Link, keeping a
/// churning link's pressure off other links' tombstones.
fn insert_closed_tombstone(
    closed: &Arc<std::sync::RwLock<HashSet<(u64, CircuitId)>>>,
    key: (u64, CircuitId),
) {
    let mut guard = closed.write().expect("closed circuit lock");
    if guard.len() >= MAX_CLOSED_BINDINGS
        && !guard.contains(&key)
        && let Some(victim) = guard
            .iter()
            .find(|(incoming, _)| *incoming == key.0)
            .or_else(|| guard.iter().next())
            .copied()
    {
        guard.remove(&victim);
    }
    guard.insert(key);
}
#[derive(Clone)]
pub struct RelayBinding {
    pub circuit_id: CircuitId,
    pub outgoing: LinkRef,
}
/// A binding that was authenticated and removed by `CircuitClose`.  The
/// optional next hop is absent at the exit, but every successful close must
/// still release its local receiver session.
pub struct ClosedBinding {
    pub outgoing: Option<RelayBinding>,
}
#[derive(Debug, Error)]
pub enum RouterError {
    #[error(transparent)]
    Circuit(#[from] CircuitError),
    #[error("next hop {0} is not connected")]
    MissingNextHop(String),
}
impl Router {
    pub fn new<L>(local: impl Into<String>, transit: TransitPolicy, links: L) -> Self
    where
        L: LinkDirectory + 'static,
    {
        Self::with_paths(local, transit, links, BTreeMap::new())
    }

    pub fn with_paths<L>(
        local: impl Into<String>,
        transit: TransitPolicy,
        links: L,
        paths: BTreeMap<String, Vec<Vec<String>>>,
    ) -> Self
    where
        L: LinkDirectory + 'static,
    {
        Self {
            local: local.into(),
            transit,
            relay_permissions: Arc::new(RwLock::new(HashMap::new())),
            known_sources: Arc::new(RwLock::new(HashSet::new())),
            paths: Arc::new(RwLock::new(paths)),
            links: Arc::new(links),
            authorizations: CircuitAuthorizations::default(),
            relay_labels: Arc::new(std::sync::RwLock::new(HashMap::new())),
            secure_dataplane: false,
            binding_state: Arc::new(std::sync::RwLock::new(BindingState::default())),
            closed: Arc::new(std::sync::RwLock::new(HashSet::new())),
            lease_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }
    pub async fn replace_paths(&self, paths: BTreeMap<String, Vec<Vec<String>>>) {
        *self.paths.write().await = paths;
    }
    pub async fn set_relay_permissions(&self, permissions: HashMap<String, bool>) {
        *self.relay_permissions.write().await = permissions;
    }
    pub async fn set_known_sources(&self, sources: HashSet<String>) {
        *self.known_sources.write().await = sources;
    }
    pub fn authorizations(&self) -> CircuitAuthorizations {
        self.authorizations.clone()
    }
    pub fn relay_labels(&self) -> RelayLabelTables {
        self.relay_labels.clone()
    }
    pub fn relay_labels_for(&self, link_instance: u64) -> Arc<std::sync::RwLock<LabelTable>> {
        self.relay_labels
            .write()
            .expect("relay label table lock")
            .entry(link_instance)
            .or_default()
            .clone()
    }
    pub fn remove_relay_labels(&self, link_instance: u64) {
        let mut tables = self.relay_labels.write().expect("relay label table lock");
        tables.remove(&link_instance);
        // A relay table is keyed by the incoming Link, but each binding also
        // owns an outgoing Link.  When the outgoing Link reconnects, remove
        // those bindings too; otherwise an old Circuit can keep forwarding
        // DATAGRAMs into the closed connection and poison the new session.
        for table in tables.values() {
            table
                .write()
                .expect("relay label lock")
                .remove_outgoing(link_instance);
        }
    }

    pub fn remove_relay_labels_for_outgoing(&self, link_instance: u64) {
        let tables = self.relay_labels.write().expect("relay label table lock");
        for table in tables.values() {
            table
                .write()
                .expect("relay label lock")
                .remove_outgoing(link_instance);
        }
    }
    pub fn remove_bindings(&self, link_instance: u64) -> Vec<(u64, CircuitId)> {
        let mut state = self.binding_state.write().expect("binding state lock");
        let keys = state
            .bindings
            .iter()
            .filter_map(|(key, binding)| {
                (key.0 != link_instance
                    && binding
                        .outgoing
                        .as_ref()
                        .is_some_and(|link| link.instance() == link_instance))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        let broken: Vec<(u64, CircuitId)> = keys
            .iter()
            .filter_map(|key| state.bindings.remove(key).map(|_| (key.0, key.1)))
            .collect();
        let removed_incoming = state
            .bindings
            .keys()
            .filter(|(incoming, _)| *incoming == link_instance)
            .copied()
            .collect::<Vec<_>>();
        state
            .bindings
            .retain(|(incoming, _), _| *incoming != link_instance);
        for (incoming_instance, circuit_id) in &broken {
            state.deadlines.remove(LeaseKey {
                incoming_instance: *incoming_instance,
                circuit_id: *circuit_id,
            });
        }
        for (incoming_instance, circuit_id) in removed_incoming {
            state.deadlines.remove(LeaseKey {
                incoming_instance,
                circuit_id,
            });
        }
        drop(state);
        self.closed
            .write()
            .expect("closed circuit lock")
            .retain(|(incoming, _)| *incoming != link_instance);
        broken
    }

    /// Abort a relay OPEN after its binding has been installed but before the
    /// circuit lifecycle has completed. This is deliberately separate from
    /// authenticated CLOSE: the source may not have received an ACK yet, so
    /// there is no source-signed CLOSE that can authenticate this cleanup.
    /// Only relay bindings are removed; an exit authorization is never
    /// mistaken for a transit binding.
    pub async fn abort_relay_binding(
        &self,
        incoming_instance: u64,
        circuit_id: CircuitId,
    ) -> Option<RelayBinding> {
        let outgoing = {
            let mut state = self.binding_state.write().expect("binding state lock");
            let binding = state.bindings.get(&(incoming_instance, circuit_id))?;
            let outgoing = binding.outgoing.clone()?;
            let _binding = state
                .bindings
                .remove(&(incoming_instance, circuit_id))
                .expect("binding checked while holding state lock");
            state.deadlines.remove(LeaseKey {
                incoming_instance,
                circuit_id,
            });
            outgoing
        };
        // Abort is unauthenticated local cleanup (no source-signed CLOSE
        // exists yet), but the tombstone still prevents an immediate
        // re-OPEN of the same CircuitId with different path/key material
        // from resurrecting relay state the failure just removed.
        insert_closed_tombstone(&self.closed, (incoming_instance, circuit_id));
        self.authorizations
            .remove(incoming_instance, circuit_id)
            .await;
        if let Some(table) = self
            .relay_labels
            .read()
            .expect("relay label table lock")
            .get(&incoming_instance)
        {
            table.write().expect("relay label lock").remove(circuit_id);
        }
        if let Some(table) = self
            .relay_labels
            .read()
            .expect("reverse relay label table lock")
            .get(&outgoing.instance())
        {
            table
                .write()
                .expect("reverse relay label lock")
                .remove(circuit_id);
        }
        Some(RelayBinding {
            circuit_id,
            outgoing,
        })
    }

    /// Abort the relay binding whose outgoing Link carried a failed or stale
    /// lifecycle message. The lookup is exact on Link instance and CircuitId,
    /// so a replacement Link cannot remove a newer binding.
    pub async fn abort_relay_binding_from_outgoing(
        &self,
        outgoing_instance: u64,
        circuit_id: CircuitId,
    ) -> Option<RelayBinding> {
        let incoming_instance = self
            .binding_state
            .read()
            .expect("binding state lock")
            .bindings
            .iter()
            .find_map(|((incoming_instance, bound_circuit_id), binding)| {
                (*bound_circuit_id == circuit_id
                    && binding
                        .outgoing
                        .as_ref()
                        .is_some_and(|outgoing| outgoing.instance() == outgoing_instance))
                .then_some(*incoming_instance)
            })?;
        self.abort_relay_binding(incoming_instance, circuit_id)
            .await
    }
    /// Refresh after authenticated DATA or a validated renewal.  Returns
    /// false if the binding has already been removed.
    ///
    /// Most packets arrive much faster than the lease granularity, so the
    /// per-packet caller only takes a read lock and an atomic load; the
    /// writer lock and deadline-heap update run at most once per configured
    /// lease refresh throttle per circuit.
    pub fn refresh_binding(&self, incoming_instance: u64, circuit_id: CircuitId) -> bool {
        let now = monotonic_millis();
        let last_refresh = {
            let state = self.binding_state.read().expect("binding state lock");
            state
                .bindings
                .get(&(incoming_instance, circuit_id))
                .map(|binding| binding.last_refresh_millis.load(Ordering::Relaxed))
        };
        let Some(last_refresh) = last_refresh else {
            return false;
        };
        let throttle = lease_refresh_throttle_millis();
        if now.saturating_sub(last_refresh) < throttle {
            return true;
        }
        {
            let mut state = self.binding_state.write().expect("binding state lock");
            let Some(binding) = state.bindings.get_mut(&(incoming_instance, circuit_id)) else {
                return false;
            };
            if now.saturating_sub(binding.last_refresh_millis.load(Ordering::Relaxed)) < throttle {
                return true;
            }
            binding.last_refresh_millis.store(now, Ordering::Relaxed);
            binding.lease_deadline = Instant::now() + circuit_lease();
            binding.lease_generation = binding.lease_generation.saturating_add(1);
            let deadline = binding.lease_deadline;
            let generation = binding.lease_generation;
            state.deadlines.insert_or_reset(
                LeaseKey {
                    incoming_instance,
                    circuit_id,
                },
                deadline,
                generation,
            );
        }
        self.lease_notify.notify_one();
        true
    }
    pub fn next_lease_deadline(&self) -> Option<Instant> {
        self.binding_state
            .read()
            .expect("binding state lock")
            .deadlines
            .next()
    }
    pub async fn expire_due_bindings(&self, now: Instant) -> Vec<(u64, CircuitId)> {
        let expired_bindings = {
            let mut state = self.binding_state.write().expect("binding state lock");
            let due = state.deadlines.pop_due(now);
            due.into_iter()
                .filter_map(|deadline| {
                    let key = deadline.key;
                    let (lease_deadline, lease_generation) = state
                        .bindings
                        .get(&(key.incoming_instance, key.circuit_id))
                        .map(|binding| (binding.lease_deadline, binding.lease_generation))?;
                    if lease_generation != deadline.generation || lease_deadline > now {
                        state
                            .deadlines
                            .insert_or_reset(key, lease_deadline, lease_generation);
                        return None;
                    }
                    state
                        .bindings
                        .remove(&(key.incoming_instance, key.circuit_id))
                        .map(|binding| (key, binding))
                })
                .collect::<Vec<_>>()
        };
        let mut expired = Vec::with_capacity(expired_bindings.len());
        for (key, binding) in expired_bindings {
            // Expired bindings join the same tombstone set as closes/aborts:
            // without it an expired CircuitId is immediately re-OPENable with
            // different path/key material.
            insert_closed_tombstone(&self.closed, (key.incoming_instance, key.circuit_id));
            self.authorizations
                .remove(key.incoming_instance, key.circuit_id)
                .await;
            if let Some(table) = self
                .relay_labels
                .read()
                .expect("relay label table lock")
                .get(&key.incoming_instance)
            {
                table
                    .write()
                    .expect("relay label lock")
                    .remove(key.circuit_id);
            }
            if let Some(outgoing) = &binding.outgoing
                && let Some(table) = self
                    .relay_labels
                    .read()
                    .expect("relay label table lock")
                    .get(&outgoing.instance())
            {
                table
                    .write()
                    .expect("reverse relay label lock")
                    .remove(key.circuit_id);
            }
            expired.push((key.incoming_instance, key.circuit_id));
        }
        expired
    }
    pub async fn wait_for_lease_change(&self) {
        self.lease_notify.notified().await;
    }
    /// Remove one established binding and every capability derived from it.
    /// Callers must first authenticate the source-signed lifecycle message.
    pub async fn close_binding(
        &self,
        incoming_instance: u64,
        circuit_id: CircuitId,
        source_public_key: &str,
        counter: u64,
    ) -> Option<ClosedBinding> {
        let binding = {
            let mut state = self.binding_state.write().expect("binding state lock");
            let binding = state.bindings.get(&(incoming_instance, circuit_id))?;
            if binding.public_key != source_public_key || counter <= binding.close_counter {
                return None;
            }
            let binding = state
                .bindings
                .remove(&(incoming_instance, circuit_id))
                .expect("binding checked while holding state lock");
            state.deadlines.remove(LeaseKey {
                incoming_instance,
                circuit_id,
            });
            binding
        };
        insert_closed_tombstone(&self.closed, (incoming_instance, circuit_id));
        self.authorizations
            .remove(incoming_instance, circuit_id)
            .await;
        if let Some(table) = self
            .relay_labels
            .read()
            .expect("relay label table lock")
            .get(&incoming_instance)
        {
            table.write().expect("relay label lock").remove(circuit_id);
        }
        if let Some(outgoing) = &binding.outgoing
            && let Some(table) = self
                .relay_labels
                .read()
                .expect("relay label table lock")
                .get(&outgoing.instance())
        {
            table
                .write()
                .expect("reverse relay label lock")
                .remove(circuit_id);
        }
        Some(ClosedBinding {
            outgoing: binding.outgoing.map(|outgoing| RelayBinding {
                circuit_id,
                outgoing,
            }),
        })
    }
    /// Validate and record a strictly monotonic source renewal. The returned
    /// link is the next hop for relays; `None` means this node is the exit.
    pub fn renew_binding(
        &self,
        incoming_instance: u64,
        circuit_id: CircuitId,
        source_public_key: &str,
        counter: u64,
    ) -> Result<Option<LinkRef>, CircuitError> {
        let mut state = self.binding_state.write().expect("binding state lock");
        let binding = state
            .bindings
            .get_mut(&(incoming_instance, circuit_id))
            .ok_or(CircuitError::InvalidPath)?;
        if binding.public_key != source_public_key {
            return Err(CircuitError::Rebinding);
        }
        // RFC-0046: a Renew with an older counter is idempotently ignored. It
        // must not be forwarded, re-ACKed, or rejected: the source's waiter
        // only accepts the exact counter it is waiting for, and a rejection
        // feedback here would wrongly revoke a still-healthy circuit.
        if counter < binding.renewal_counter {
            return Err(CircuitError::StaleRenewal);
        }
        let is_new = counter > binding.renewal_counter;
        binding.renewal_counter = binding.renewal_counter.max(counter);
        let outgoing = binding.outgoing.clone();
        if !is_new {
            return Ok(outgoing);
        }
        let now_millis = monotonic_millis();
        if now_millis.saturating_sub(binding.last_refresh_millis.load(Ordering::Relaxed))
            >= lease_refresh_throttle_millis()
        {
            binding
                .last_refresh_millis
                .store(now_millis, Ordering::Relaxed);
            binding.lease_deadline = Instant::now() + circuit_lease();
            binding.lease_generation = binding.lease_generation.saturating_add(1);
            let deadline = binding.lease_deadline;
            let generation = binding.lease_generation;
            state.deadlines.insert_or_reset(
                LeaseKey {
                    incoming_instance,
                    circuit_id,
                },
                deadline,
                generation,
            );
            self.lease_notify.notify_one();
        }
        Ok(outgoing)
    }
    pub async fn reverse_relay(
        &self,
        outgoing_instance: u64,
        circuit_id: CircuitId,
    ) -> Option<LinkRef> {
        let incoming_instance = self
            .relay_labels
            .read()
            .expect("relay label table lock")
            .iter()
            .find_map(|(incoming_instance, table)| {
                let binding = table
                    .read()
                    .expect("relay label lock")
                    .forward(circuit_id)?;
                (binding.outgoing.instance() == outgoing_instance).then_some(*incoming_instance)
            });
        let incoming_instance = incoming_instance.or_else(|| {
            self.binding_state
                .read()
                .expect("binding state lock")
                .bindings
                .iter()
                .find_map(|((incoming_instance, bound_circuit_id), binding)| {
                    (*bound_circuit_id == circuit_id
                        && binding
                            .outgoing
                            .as_ref()
                            .is_some_and(|link| link.instance() == outgoing_instance))
                    .then_some(*incoming_instance)
                })
        })?;
        self.links.by_instance(incoming_instance)
    }
    pub fn set_secure_dataplane(&mut self, enabled: bool) {
        self.secure_dataplane = enabled;
    }
    pub fn has_secure_dataplane(&self) -> bool {
        self.secure_dataplane
    }
    pub async fn handle_open(
        &self,
        incoming: &dyn LinkHandle,
        request: &OpenRequest,
    ) -> Result<Option<RelayBinding>, RouterError> {
        request.verify()?;
        validate_open(&request.as_open(), &self.local, &self.transit)?;
        let position = request
            .path
            .iter()
            .position(|node| node == &self.local)
            .ok_or(CircuitError::InvalidPath)?;
        if position > 0 && position + 1 < request.path.len() {
            let known_source = self.known_sources.read().await.contains(&request.source);
            if !known_source
                && !self
                    .relay_permissions
                    .read()
                    .await
                    .get(incoming.peer_identity())
                    .copied()
                    .unwrap_or(false)
            {
                return Err(RouterError::Circuit(CircuitError::Denied));
            }
        }
        if position == 0 || request.path[position - 1] != incoming.peer_identity() {
            return Err(RouterError::Circuit(CircuitError::UnexpectedPreviousHop));
        }
        if let Some(binding) = self
            .binding_state
            .read()
            .expect("binding state lock")
            .bindings
            .get(&(incoming.instance(), request.circuit_id))
            .cloned()
        {
            if !binding.matches(request) {
                return Err(RouterError::Circuit(CircuitError::Rebinding));
            }
            return Ok(binding.outgoing.map(|outgoing| RelayBinding {
                circuit_id: request.circuit_id,
                outgoing,
            }));
        }
        if self
            .closed
            .read()
            .expect("closed circuit lock")
            .contains(&(incoming.instance(), request.circuit_id))
        {
            return Err(RouterError::Circuit(CircuitError::Rebinding));
        }
        {
            let paths = self.paths.read().await;
            validate_manual_path(&request.as_open(), &self.local, &paths)?;
        }
        if request.destination == self.local {
            self.authorizations
                .install(
                    incoming.instance(),
                    request.circuit_id,
                    request.public_key.clone(),
                )
                .await?;
            let deadline = Instant::now() + circuit_lease();
            {
                let mut state = self.binding_state.write().expect("binding state lock");
                state.bindings.insert(
                    (incoming.instance(), request.circuit_id),
                    CircuitBinding {
                        source: request.source.clone(),
                        destination: request.destination.clone(),
                        path: request.path.clone(),
                        public_key: request.public_key.clone(),
                        ephemeral_public_key: request.ephemeral_public_key,
                        outgoing: None,
                        renewal_counter: 0,
                        close_counter: 0,
                        lease_deadline: deadline,
                        lease_generation: 1,
                        last_refresh_millis: AtomicU64::new(0),
                    },
                );
                state.deadlines.insert_or_reset(
                    LeaseKey {
                        incoming_instance: incoming.instance(),
                        circuit_id: request.circuit_id,
                    },
                    deadline,
                    1,
                );
            }
            self.lease_notify.notify_one();
            return Ok(None);
        }
        let next = request
            .path
            .get(position + 1)
            .ok_or(CircuitError::InvalidPath)?
            .clone();
        let outgoing: LinkRef = self
            .links
            .by_peer(&next)
            .ok_or(RouterError::MissingNextHop(next))?;
        let deadline = Instant::now() + circuit_lease();
        {
            let mut state = self.binding_state.write().expect("binding state lock");
            state.bindings.insert(
                (incoming.instance(), request.circuit_id),
                CircuitBinding {
                    source: request.source.clone(),
                    destination: request.destination.clone(),
                    path: request.path.clone(),
                    public_key: request.public_key.clone(),
                    ephemeral_public_key: request.ephemeral_public_key,
                    outgoing: Some(outgoing.clone()),
                    renewal_counter: 0,
                    close_counter: 0,
                    lease_deadline: deadline,
                    lease_generation: 1,
                    last_refresh_millis: AtomicU64::new(0),
                },
            );
            state.deadlines.insert_or_reset(
                LeaseKey {
                    incoming_instance: incoming.instance(),
                    circuit_id: request.circuit_id,
                },
                deadline,
                1,
            );
        }
        self.lease_notify.notify_one();
        Ok(Some(RelayBinding {
            circuit_id: request.circuit_id,
            outgoing,
        }))
    }
}
impl LabelTable {
    pub fn install(&mut self, circuit_id: CircuitId, link: LinkRef) -> Result<(), CircuitError> {
        if !self.forwards.contains_key(&circuit_id) && self.forwards.len() >= MAX_LABEL_BINDINGS {
            return Err(CircuitError::Capacity);
        }
        self.forwards.insert(
            circuit_id,
            RelayBinding {
                circuit_id,
                outgoing: link,
            },
        );
        Ok(())
    }
    pub fn forward(&self, circuit_id: CircuitId) -> Option<RelayBinding> {
        self.forwards.get(&circuit_id).cloned()
    }

    fn remove_outgoing(&mut self, link_instance: u64) {
        self.forwards
            .retain(|_, binding| binding.outgoing.instance() != link_instance);
    }
    pub fn remove(&mut self, circuit_id: CircuitId) {
        self.forwards.remove(&circuit_id);
    }
}
#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct TestLink {
        peer: String,
        identity: String,
        instance: u64,
    }

    impl TestLink {
        fn make(peer: impl Into<String>, identity: impl Into<String>, instance: u64) -> LinkRef {
            Arc::new(Self {
                peer: peer.into(),
                identity: identity.into(),
                instance,
            })
        }
    }

    impl LinkHandle for TestLink {
        fn peer_name(&self) -> &str {
            &self.peer
        }

        fn peer_identity(&self) -> &str {
            &self.identity
        }

        fn instance(&self) -> u64 {
            self.instance
        }

        fn is_healthy(&self) -> bool {
            true
        }

        fn set_healthy(&self, _healthy: bool) {}

        fn should_log_dataplane_warning(&self) -> bool {
            true
        }

        fn is_closed(&self) -> bool {
            false
        }

        fn send_forward(&self, _frame: &[u8]) -> Result<(), crate::link::LinkError> {
            Ok(())
        }

        fn send_control<'a>(
            &'a self,
            _message: &'a crate::control::ControlMessage,
        ) -> crate::link::LinkFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    struct TestDirectory {
        links: Vec<LinkRef>,
    }

    impl LinkDirectory for TestDirectory {
        fn by_peer(&self, peer_identity: &str) -> Option<LinkRef> {
            self.links
                .iter()
                .find(|link| link.peer_identity() == peer_identity)
                .cloned()
        }

        fn by_instance(&self, instance: u64) -> Option<LinkRef> {
            self.links
                .iter()
                .find(|link| link.instance() == instance)
                .cloned()
        }
    }

    fn install_test_binding(
        router: &Router,
        incoming_instance: u64,
        circuit_id: CircuitId,
        deadline: Instant,
        generation: u64,
    ) {
        let mut state = router.binding_state.write().expect("binding state lock");
        state.bindings.insert(
            (incoming_instance, circuit_id),
            CircuitBinding {
                source: "source".into(),
                destination: "exit".into(),
                path: vec!["source".into(), "exit".into()],
                public_key: "source-key".into(),
                ephemeral_public_key: [0; 32],
                outgoing: None,
                renewal_counter: 0,
                close_counter: 0,
                lease_deadline: deadline,
                lease_generation: generation,
                last_refresh_millis: AtomicU64::new(0),
            },
        );
        state.deadlines.insert_or_reset(
            LeaseKey {
                incoming_instance,
                circuit_id,
            },
            deadline,
            generation,
        );
    }

    #[test]
    fn lease_deadlines_reset_in_place_and_remove_cleanly() {
        let now = Instant::now();
        let id = CircuitId([1; 16]);
        let mut deadlines = LeaseDeadlines::default();
        let key = LeaseKey {
            incoming_instance: 7,
            circuit_id: id,
        };
        deadlines.insert_or_reset(key, now + Duration::from_secs(20), 1);
        deadlines.insert_or_reset(key, now + Duration::from_secs(10), 2);
        assert_eq!(deadlines.heap.len(), 1);
        assert_eq!(deadlines.next(), Some(now + Duration::from_secs(10)));
        let due = deadlines.pop_due(now + Duration::from_secs(10));
        assert_eq!(
            due,
            vec![LeaseDeadline {
                at: now + Duration::from_secs(10),
                key,
                generation: 2
            }]
        );
        assert!(deadlines.pop_due(now + Duration::from_secs(30)).is_empty());
        deadlines.insert_or_reset(key, now + Duration::from_secs(20), 3);
        assert!(deadlines.remove(key));
        assert!(deadlines.next().is_none());
    }

    #[tokio::test]
    async fn authorization_binds_link_circuit_and_source_and_is_removed_with_link() {
        let id = CircuitId([7; 16]);
        let authorizations = CircuitAuthorizations::default();
        authorizations
            .install(11, id, "source-key".into())
            .await
            .unwrap();
        assert!(authorizations.permits(11, id, "source-key").await);
        assert!(!authorizations.permits(12, id, "source-key").await);
        assert!(
            !authorizations
                .permits(11, CircuitId([8; 16]), "source-key")
                .await
        );
        assert!(!authorizations.permits(11, id, "other-key").await);
        authorizations.remove_link(11).await;
        assert!(!authorizations.permits(11, id, "source-key").await);
    }

    #[tokio::test]
    async fn close_reclaims_binding_and_authorization_and_rejects_replay() {
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        let id = CircuitId([9; 16]);
        install_test_binding(&router, 11, id, Instant::now() + CIRCUIT_LEASE, 1);
        router
            .authorizations()
            .install(11, id, "source-key".into())
            .await
            .unwrap();

        assert!(router.close_binding(11, id, "wrong-key", 1).await.is_none());
        assert_eq!(
            router
                .binding_state
                .read()
                .expect("binding state lock")
                .deadlines
                .heap
                .len(),
            1
        );

        let closed = router
            .close_binding(11, id, "source-key", 1)
            .await
            .expect("first valid close removes the binding");
        assert!(closed.outgoing.is_none());
        assert!(!router.authorizations().permits(11, id, "source-key").await);
        assert!(router.next_lease_deadline().is_none());
        assert!(
            router
                .close_binding(11, id, "source-key", 2)
                .await
                .is_none()
        );
    }

    #[test]
    fn refreshing_a_binding_does_not_accumulate_deadlines() {
        backdate_monotonic_epoch();
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        let id = CircuitId([11; 16]);
        install_test_binding(&router, 13, id, Instant::now() + CIRCUIT_LEASE, 1);
        for _ in 0..10_000 {
            assert!(router.refresh_binding(13, id));
        }
        assert_eq!(
            router
                .binding_state
                .read()
                .expect("binding state lock")
                .deadlines
                .heap
                .len(),
            1
        );
    }

    #[test]
    fn renewal_authentication_is_monotonic_and_preserves_one_deadline() {
        backdate_monotonic_epoch();
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        let id = CircuitId([12; 16]);
        install_test_binding(&router, 14, id, Instant::now() + CIRCUIT_LEASE, 1);

        assert!(matches!(
            router.renew_binding(14, id, "wrong-source-key", 1),
            Err(CircuitError::Rebinding)
        ));
        assert!(
            router
                .renew_binding(14, id, "source-key", 1)
                .expect("first authenticated renewal is accepted")
                .is_none()
        );
        assert!(
            router
                .renew_binding(14, id, "source-key", 1)
                .expect("duplicate renewal is idempotent")
                .is_none()
        );
        assert!(matches!(
            router.renew_binding(14, id, "source-key", 0),
            Err(CircuitError::StaleRenewal)
        ));
        let state = router.binding_state.read().expect("binding state lock");
        assert_eq!(state.bindings[&(14, id)].renewal_counter, 1);
        assert_eq!(state.deadlines.heap.len(), 1);
    }

    #[test]
    fn removing_an_incoming_link_reclaims_bindings_and_deadlines_atomically() {
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        let removed_id = CircuitId([13; 16]);
        let retained_id = CircuitId([14; 16]);
        install_test_binding(&router, 15, removed_id, Instant::now() + CIRCUIT_LEASE, 1);
        install_test_binding(&router, 16, retained_id, Instant::now() + CIRCUIT_LEASE, 1);
        router
            .closed
            .write()
            .expect("closed circuit lock")
            .insert((15, CircuitId([15; 16])));

        assert!(router.remove_bindings(15).is_empty());
        let state = router.binding_state.read().expect("binding state lock");
        assert!(!state.bindings.contains_key(&(15, removed_id)));
        assert!(state.bindings.contains_key(&(16, retained_id)));
        assert_eq!(state.deadlines.heap.len(), 1);
        assert_eq!(state.deadlines.heap[0].key.circuit_id, retained_id);
        drop(state);
        assert!(
            router
                .closed
                .read()
                .expect("closed circuit lock")
                .iter()
                .all(|(incoming, _)| *incoming != 15)
        );
    }

    #[tokio::test]
    async fn exact_lease_expiry_reclaims_only_the_current_generation() {
        backdate_monotonic_epoch();
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        let id = CircuitId([10; 16]);
        let now = Instant::now();
        install_test_binding(&router, 12, id, now - Duration::from_secs(1), 3);
        router
            .authorizations()
            .install(12, id, "source-key".into())
            .await
            .unwrap();

        assert_eq!(router.expire_due_bindings(now).await, vec![(12, id)]);
        assert!(!router.authorizations().permits(12, id, "source-key").await);
        assert!(router.renew_binding(12, id, "source-key", 1).is_err());
    }

    #[tokio::test]
    async fn stale_deadline_generation_cannot_expire_a_renewed_binding() {
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        let id = CircuitId([16; 16]);
        let now = Instant::now();
        let renewed_deadline = now + Duration::from_secs(60);
        install_test_binding(&router, 17, id, renewed_deadline, 2);
        {
            let mut state = router.binding_state.write().expect("binding state lock");
            state.deadlines.insert_or_reset(
                LeaseKey {
                    incoming_instance: 17,
                    circuit_id: id,
                },
                now - Duration::from_secs(1),
                1,
            );
        }

        assert!(router.expire_due_bindings(now).await.is_empty());
        let state = router.binding_state.read().expect("binding state lock");
        assert!(state.bindings.contains_key(&(17, id)));
        assert_eq!(state.deadlines.next(), Some(renewed_deadline));
        assert_eq!(state.deadlines.heap[0].generation, 2);
    }

    #[test]
    fn rejects_loop() {
        let o = CircuitOpen {
            source: "a".into(),
            destination: "c".into(),
            path: vec!["a".into(), "b".into(), "b".into(), "c".into()],
        };
        assert_eq!(
            validate_open(&o, "b", &TransitPolicy::default()),
            Err(CircuitError::InvalidPath)
        );
    }

    #[test]
    fn open_validation_does_not_depend_on_packet_mtu() {
        let open = CircuitOpen {
            source: "a".into(),
            destination: "b".into(),
            path: vec!["a".into(), "b".into()],
        };
        assert!(validate_open(&open, "b", &TransitPolicy::default()).is_ok());
    }

    #[test]
    fn path_length_is_bounded_by_max_open_path_hops() {
        let path = (0..MAX_OPEN_PATH_HOPS)
            .map(|index| format!("node-{index}"))
            .collect::<Vec<_>>();
        let open = CircuitOpen {
            source: path[0].clone(),
            destination: path[MAX_OPEN_PATH_HOPS - 1].clone(),
            path,
        };
        assert!(
            validate_open(
                &open,
                &format!("node-{}", MAX_OPEN_PATH_HOPS - 1),
                &TransitPolicy::default()
            )
            .is_ok()
        );
        let long = (0..=MAX_OPEN_PATH_HOPS + 1)
            .map(|index| format!("node-{index}"))
            .collect::<Vec<_>>();
        let open = CircuitOpen {
            source: long[0].clone(),
            destination: long[long.len() - 1].clone(),
            path: long,
        };
        assert_eq!(
            validate_open(&open, "node-1", &TransitPolicy::default()),
            Err(CircuitError::InvalidPath)
        );
    }
    #[test]
    fn transit_peer_override_takes_precedence_over_node_default() {
        let open = CircuitOpen {
            source: "a".into(),
            destination: "c".into(),
            path: vec!["a".into(), "b".into(), "c".into()],
        };
        let policy = TransitPolicy::new(false, HashMap::from([("a".into(), Some(true))]));
        assert!(validate_open(&open, "b", &policy).is_ok());
        let policy = TransitPolicy::new(true, HashMap::from([("a".into(), Some(false))]));
        assert_eq!(
            validate_open(&open, "b", &policy),
            Err(CircuitError::Denied)
        );
    }

    #[test]
    fn unknown_signed_source_can_transit_when_local_default_allows_it() {
        let key = crate::identity::generate();
        let source = crate::identity::node_id(&key.verifying_key());
        let open = CircuitOpen {
            source: source.clone(),
            destination: "unknown-exit-fingerprint".into(),
            path: vec![
                source,
                "relay-fingerprint".into(),
                "unknown-exit-fingerprint".into(),
            ],
        };
        assert!(validate_open(&open, "relay-fingerprint", &TransitPolicy::default()).is_ok());
    }
    #[test]
    fn signed_open_covers_identity_circuit_and_ephemeral_key() {
        let key = crate::identity::generate();
        let source = crate::identity::node_id(&key.verifying_key());
        let relay = crate::identity::node_id(&crate::identity::generate().verifying_key());
        let exit = crate::identity::node_id(&crate::identity::generate().verifying_key());
        let request = OpenRequest::new(
            source.clone(),
            &key,
            exit.clone(),
            vec![source, relay, exit],
            CircuitId([1; 16]),
            [2; 32],
        );
        assert!(request.verify().is_ok());
        let mut tampered = request.clone();
        tampered.destination =
            crate::identity::node_id(&crate::identity::generate().verifying_key());
        assert!(tampered.verify().is_err());
        let mut tampered = request.clone();
        tampered.circuit_id = CircuitId([3; 16]);
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn signed_open_wire_round_trip_and_malformed_inputs_are_rejected() {
        let key = crate::identity::generate();
        let source = crate::identity::node_id(&key.verifying_key());
        let destination = "11111111111111111111111111111111".to_owned();
        let request = OpenRequest::new(
            source,
            &key,
            destination,
            vec![
                crate::identity::node_id(&key.verifying_key()),
                "11111111111111111111111111111111".into(),
            ],
            CircuitId([4; 16]),
            [5; 32],
        );
        let encoded = request.encode_body().unwrap();
        assert_eq!(encoded.len(), 1 + 16 + 32 + 32 + 2 + 2 * 16 + 64);
        let decoded = OpenRequest::decode_body(&encoded).unwrap();
        assert_eq!(decoded.source, request.source);
        assert_eq!(decoded.destination, request.destination);
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.circuit_id, request.circuit_id);
        assert!(decoded.verify().is_ok());
        let mut bad_domain = encoded.clone();
        bad_domain[0] = 15;
        assert!(OpenRequest::decode_body(&bad_domain).is_err());
        assert!(OpenRequest::decode_body(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(OpenRequest::decode_body(&trailing).is_err());

        let mut bad_signature = request.clone();
        bad_signature.signature = "!".into();
        assert!(bad_signature.encode_body().is_err());
        let mut bad_key = request.clone();
        bad_key.public_key = "!".into();
        assert!(bad_key.verify().is_err());
        assert!(request.forwarded().is_ok());
    }

    #[test]
    fn lease_heap_reheaps_after_non_root_removal_and_due_pop() {
        let now = Instant::now();
        let mut deadlines = LeaseDeadlines::default();
        let keys = [
            LeaseKey {
                incoming_instance: 1,
                circuit_id: CircuitId([1; 16]),
            },
            LeaseKey {
                incoming_instance: 2,
                circuit_id: CircuitId([2; 16]),
            },
            LeaseKey {
                incoming_instance: 3,
                circuit_id: CircuitId([3; 16]),
            },
        ];
        deadlines.insert_or_reset(keys[0], now + Duration::from_secs(30), 1);
        deadlines.insert_or_reset(keys[1], now + Duration::from_secs(10), 1);
        deadlines.insert_or_reset(keys[2], now + Duration::from_secs(20), 1);
        assert!(deadlines.remove(keys[2]));
        assert_eq!(deadlines.next(), Some(now + Duration::from_secs(10)));
        assert_eq!(deadlines.pop_due(now + Duration::from_secs(10)).len(), 1);
        assert!(deadlines.remove(keys[0]));
        assert!(!deadlines.remove(keys[0]));
        assert!(deadlines.next().is_none());
    }

    #[test]
    fn manual_path_applies_to_transit_suffixes() {
        let open = CircuitOpen {
            source: "a".into(),
            destination: "c".into(),
            path: vec!["a".into(), "b".into(), "c".into()],
        };
        let paths = BTreeMap::from([("c".into(), vec![vec!["b".into(), "c".into()]])]);
        assert!(validate_manual_path(&open, "b", &paths).is_ok());

        let denied = CircuitOpen {
            path: vec!["a".into(), "b".into(), "d".into(), "c".into()],
            ..open
        };
        assert_eq!(
            validate_manual_path(&denied, "b", &paths),
            Err(CircuitError::ManualPathDenied)
        );
    }

    #[tokio::test]
    async fn relay_binding_lifecycle_handles_replay_abort_and_link_replacement() {
        backdate_monotonic_epoch();
        let source_key = crate::identity::generate();
        let source = crate::identity::node_id(&source_key.verifying_key());
        let relay_key = crate::identity::generate();
        let relay = crate::identity::node_id(&relay_key.verifying_key());
        let exit_key = crate::identity::generate();
        let exit = crate::identity::node_id(&exit_key.verifying_key());
        let incoming = TestLink::make("source", source.clone(), 1);
        let outgoing = TestLink::make("exit", exit.clone(), 2);
        let router = Router::new(
            relay,
            TransitPolicy::new(true, HashMap::new()),
            TestDirectory {
                links: vec![incoming.clone(), outgoing.clone()],
            },
        );
        router
            .set_known_sources(HashSet::from([source.clone()]))
            .await;

        let request = OpenRequest::new(
            source.clone(),
            &source_key,
            exit.clone(),
            vec![source.clone(), router.local.clone(), exit.clone()],
            CircuitId([21; 16]),
            [22; 32],
        );
        let binding = router
            .handle_open(incoming.as_ref(), &request)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(binding.outgoing.instance(), 2);
        assert!(
            router
                .handle_open(incoming.as_ref(), &request)
                .await
                .unwrap()
                .is_some()
        );

        let mut rebound = request.clone();
        rebound.ephemeral_public_key = [23; 32];
        rebound.signature =
            STANDARD_NO_PAD.encode(source_key.sign(&rebound.signing_bytes()).to_bytes());
        assert!(matches!(
            router.handle_open(incoming.as_ref(), &rebound).await,
            Err(RouterError::Circuit(CircuitError::Rebinding))
        ));

        let incoming_table = router.relay_labels_for(1);
        let outgoing_table = router.relay_labels_for(2);
        incoming_table
            .write()
            .unwrap()
            .install(request.circuit_id, outgoing.clone())
            .unwrap();
        outgoing_table
            .write()
            .unwrap()
            .install(request.circuit_id, incoming.clone())
            .unwrap();
        router.remove_relay_labels_for_outgoing(2);
        assert!(
            incoming_table
                .read()
                .unwrap()
                .forward(request.circuit_id)
                .is_none()
        );

        let closed = router
            .close_binding(1, request.circuit_id, &request.public_key, 1)
            .await
            .unwrap();
        assert_eq!(closed.outgoing.unwrap().outgoing.instance(), 2);

        let aborted_id = CircuitId([24; 16]);
        let mut aborted = request.clone();
        aborted.circuit_id = aborted_id;
        aborted.signature =
            STANDARD_NO_PAD.encode(source_key.sign(&aborted.signing_bytes()).to_bytes());
        router
            .handle_open(incoming.as_ref(), &aborted)
            .await
            .unwrap();
        assert!(router.abort_relay_binding(1, aborted_id).await.is_some());

        let replaced_id = CircuitId([25; 16]);
        let mut replaced = request.clone();
        replaced.circuit_id = replaced_id;
        replaced.signature =
            STANDARD_NO_PAD.encode(source_key.sign(&replaced.signing_bytes()).to_bytes());
        router
            .handle_open(incoming.as_ref(), &replaced)
            .await
            .unwrap();
        assert!(
            router
                .abort_relay_binding_from_outgoing(2, replaced_id)
                .await
                .is_some()
        );

        let removed_id = CircuitId([26; 16]);
        let mut removed = request;
        removed.circuit_id = removed_id;
        removed.signature =
            STANDARD_NO_PAD.encode(source_key.sign(&removed.signing_bytes()).to_bytes());
        router
            .handle_open(incoming.as_ref(), &removed)
            .await
            .unwrap();
        assert_eq!(router.remove_bindings(2), vec![(1, removed_id)]);
        router.remove_relay_labels(1);
    }

    #[test]
    fn open_and_manual_path_validation_rejects_all_boundary_forms() {
        let valid = CircuitOpen {
            source: "a".into(),
            destination: "c".into(),
            path: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(
            validate_open(
                &CircuitOpen {
                    path: vec!["a".into(), "c".into()],
                    ..valid.clone()
                },
                "missing",
                &TransitPolicy::default()
            ),
            Err(CircuitError::InvalidPath)
        );
        assert_eq!(
            validate_open(
                &CircuitOpen {
                    source: "wrong".into(),
                    ..valid.clone()
                },
                "b",
                &TransitPolicy::default()
            ),
            Err(CircuitError::InvalidPath)
        );
        assert_eq!(
            validate_open(
                &CircuitOpen {
                    path: vec!["a".into(), "b".into(), "b".into(), "c".into()],
                    ..valid.clone()
                },
                "b",
                &TransitPolicy::default()
            ),
            Err(CircuitError::InvalidPath)
        );
        assert_eq!(
            validate_open(&valid, "b", &TransitPolicy::new(false, HashMap::new())),
            Err(CircuitError::Denied)
        );
        assert!(validate_manual_path(&valid, "b", &BTreeMap::new()).is_ok());
        assert_eq!(
            validate_manual_path(
                &valid,
                "missing",
                &BTreeMap::from([("c".into(), vec![vec!["b".into(), "c".into()]])])
            ),
            Err(CircuitError::InvalidPath)
        );
    }

    #[tokio::test]
    async fn circuit_state_handles_missing_refreshes_reverse_lookups_and_label_removal() {
        backdate_monotonic_epoch();
        let router = Router::new(
            "relay",
            TransitPolicy::new(true, HashMap::new()),
            TestDirectory { links: Vec::new() },
        );
        let id = CircuitId([31; 16]);
        assert!(!router.refresh_binding(1, id));
        assert!(matches!(
            router.renew_binding(1, id, "source-key", 1),
            Err(CircuitError::InvalidPath)
        ));
        assert!(router.reverse_relay(2, id).await.is_none());

        let relay = "aa".repeat(16);
        let exit = "bb".repeat(16);
        let outgoing = TestLink::make("exit", exit.clone(), 2);
        let incoming = TestLink::make("source", "source", 1);
        let router = Router::new(
            relay.clone(),
            TransitPolicy::new(true, HashMap::from([("source".into(), Some(true))])),
            TestDirectory {
                links: vec![incoming.clone(), outgoing.clone()],
            },
        );
        let source_key = crate::identity::generate();
        let source = crate::identity::node_id(&source_key.verifying_key());
        let request = OpenRequest::new(
            source.clone(),
            &source_key,
            exit.clone(),
            vec![source, relay, exit],
            id,
            [32; 32],
        );
        router
            .set_known_sources(HashSet::from([request.source.clone()]))
            .await;
        let _ = router.handle_open(incoming.as_ref(), &request).await;
        router
            .relay_labels_for(incoming.instance())
            .write()
            .unwrap()
            .install(id, outgoing.clone())
            .unwrap();
        assert_eq!(
            router
                .reverse_relay(outgoing.instance(), id)
                .await
                .unwrap()
                .instance(),
            incoming.instance()
        );
        router.remove_relay_labels_for_outgoing(outgoing.instance());
        assert!(
            router
                .reverse_relay(outgoing.instance(), id)
                .await
                .is_none()
        );
        assert!(
            router
                .abort_relay_binding_from_outgoing(outgoing.instance(), id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn exit_open_replay_and_closed_circuit_states_are_rejected() {
        let source_key = crate::identity::generate();
        let source = crate::identity::node_id(&source_key.verifying_key());
        let exit = "cc".repeat(16);
        let incoming = TestLink::make("source", source.clone(), 41);
        let router = Router::new(
            exit.clone(),
            TransitPolicy::default(),
            TestDirectory {
                links: vec![incoming.clone()],
            },
        );
        let request = OpenRequest::new(
            source.clone(),
            &source_key,
            exit.clone(),
            vec![source, exit],
            CircuitId([42; 16]),
            [43; 32],
        );
        assert!(
            router
                .handle_open(incoming.as_ref(), &request)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            router
                .handle_open(incoming.as_ref(), &request)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            router
                .close_binding(
                    incoming.instance(),
                    request.circuit_id,
                    &request.public_key,
                    1
                )
                .await
                .is_some()
        );
        assert!(matches!(
            router.handle_open(incoming.as_ref(), &request).await,
            Err(RouterError::Circuit(CircuitError::Rebinding))
        ));
    }

    #[tokio::test]
    async fn aborted_relay_binding_rejects_immediate_reopen() {
        let relay = "aa".repeat(16);
        let exit = "bb".repeat(16);
        let source_key = crate::identity::generate();
        let source = crate::identity::node_id(&source_key.verifying_key());
        let incoming = TestLink::make("source-peer", source.clone(), 1);
        let outgoing = TestLink::make("exit-peer", exit.clone(), 2);
        let router = Router::new(
            relay.clone(),
            TransitPolicy::new(true, HashMap::new()),
            TestDirectory {
                links: vec![incoming.clone(), outgoing.clone()],
            },
        );
        router
            .set_known_sources(HashSet::from([source.clone()]))
            .await;
        let id = CircuitId([77; 16]);
        let request = OpenRequest::new(
            source.clone(),
            &source_key,
            exit.clone(),
            vec![source, relay, exit],
            id,
            [32; 32],
        );
        assert!(
            router
                .handle_open(incoming.as_ref(), &request)
                .await
                .is_ok()
        );
        assert!(
            router
                .abort_relay_binding(incoming.instance(), id)
                .await
                .is_some()
        );
        assert!(matches!(
            router.handle_open(incoming.as_ref(), &request).await,
            Err(RouterError::Circuit(CircuitError::Rebinding))
        ));
    }

    #[test]
    fn closed_tombstones_are_bounded() {
        let closed = Arc::new(std::sync::RwLock::new(HashSet::new()));
        for index in 0..(MAX_CLOSED_BINDINGS + 500) {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            insert_closed_tombstone(&closed, (1, CircuitId(id)));
        }
        assert!(closed.read().expect("closed circuit lock").len() <= MAX_CLOSED_BINDINGS);
    }

    #[test]
    fn closed_tombstone_eviction_prefers_the_churning_link() {
        let closed = Arc::new(std::sync::RwLock::new(HashSet::new()));
        let sheltered = (1, CircuitId([0xaa; 16]));
        insert_closed_tombstone(&closed, sheltered);
        for index in 0..(MAX_CLOSED_BINDINGS + 100) {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            insert_closed_tombstone(&closed, (2, CircuitId(id)));
        }
        let guard = closed.read().expect("closed circuit lock");
        assert!(guard.len() <= MAX_CLOSED_BINDINGS);
        // Churn on link 2 must not evict link 1's tombstone.
        assert!(guard.contains(&sheltered));
    }

    #[test]
    fn overlong_open_paths_are_rejected_at_decode_and_verify() {
        let key = crate::identity::generate();
        let source = crate::identity::node_id(&key.verifying_key());
        let node = |byte: u8| format!("{byte:02x}").repeat(16);
        let mut path = vec![source.clone()];
        path.extend((0..15).map(|index| node(index as u8)));
        path.push(node(0xff));
        assert_eq!(path.len(), MAX_OPEN_PATH_HOPS + 1);
        let request = OpenRequest::new(source, &key, node(0xff), path, CircuitId([1; 16]), [2; 32]);
        assert_eq!(request.verify().unwrap_err(), CircuitError::InvalidPath);
        let body = request.encode_body().unwrap();
        assert_eq!(
            OpenRequest::decode_body(&body).unwrap_err(),
            crate::wire::Error::Truncated
        );
    }

    #[test]
    fn open_paths_are_bounded_everywhere() {
        let long: Vec<String> = (0..(MAX_OPEN_PATH_HOPS + 1))
            .map(|i| format!("n{i}"))
            .collect();
        let open = CircuitOpen {
            source: long[0].clone(),
            destination: long[long.len() - 1].clone(),
            path: long,
        };
        let transit = TransitPolicy::default();
        assert_eq!(
            validate_open(&open, &open.path[1], &transit).unwrap_err(),
            CircuitError::InvalidPath
        );
    }

    #[test]
    fn lease_heap_sifts_up_after_non_root_removal_and_down_via_right_child() {
        let now = Instant::now();
        let mut deadlines = LeaseDeadlines::default();
        let at = |seconds: u64| now + Duration::from_secs(seconds);
        let keys: Vec<LeaseKey> = (0..6)
            .map(|index| LeaseKey {
                incoming_instance: 1,
                circuit_id: CircuitId([index as u8; 16]),
            })
            .collect();
        for (key, seconds) in keys.iter().zip([10u64, 50, 20, 60, 70, 30]) {
            deadlines.insert_or_reset(*key, at(seconds), 1);
        }
        // Removing the node at index 3 moves the last entry (30) into a slot
        // whose parent (50) is larger, forcing a sift-up.
        assert!(deadlines.remove(keys[3]));
        assert_eq!(deadlines.heap.len(), 5);
        assert_eq!(deadlines.next(), Some(at(10)));
        // Popping the root sifts the new root down through the right child.
        let due = deadlines.pop_due(at(10));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].key, keys[0]);
        assert_eq!(deadlines.next(), Some(at(20)));
    }

    #[test]
    fn circuit_id_random_produces_distinct_ids() {
        assert_ne!(CircuitId::random(), CircuitId::random());
    }

    #[test]
    fn verify_rejects_source_identity_mismatch() {
        let key = crate::identity::generate();
        let other = crate::identity::generate();
        let wrong_source = crate::identity::node_id(&other.verifying_key());
        let destination = "11111111111111111111111111111111".to_owned();
        let request = OpenRequest::new(
            wrong_source.clone(),
            &key,
            destination.clone(),
            vec![wrong_source, destination],
            CircuitId([6; 16]),
            [7; 32],
        );
        assert!(matches!(request.verify(), Err(CircuitError::Signature(_))));
    }

    #[tokio::test]
    async fn authorization_capacity_is_bounded() {
        let authorizations = CircuitAuthorizations::default();
        for index in 0..MAX_CIRCUIT_AUTHORIZATIONS {
            authorizations
                .install(
                    index as u64,
                    CircuitId([index as u8; 16]),
                    "source-key".into(),
                )
                .await
                .unwrap();
        }
        assert!(matches!(
            authorizations
                .install(
                    MAX_CIRCUIT_AUTHORIZATIONS as u64,
                    CircuitId([255; 16]),
                    "source-key".into(),
                )
                .await,
            Err(CircuitError::Capacity)
        ));
        // Re-installing an existing key does not hit the capacity limit.
        assert!(
            authorizations
                .install(0, CircuitId([0; 16]), "source-key".into())
                .await
                .is_ok()
        );
    }

    #[test]
    fn label_table_capacity_is_bounded() {
        let mut table = LabelTable::default();
        for index in 0..MAX_LABEL_BINDINGS {
            let link = TestLink::make("peer", "identity", index as u64);
            table
                .install(
                    CircuitId([
                        index as u8,
                        (index >> 8) as u8,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ]),
                    link,
                )
                .unwrap();
        }
        assert!(matches!(
            table.install(
                CircuitId::random(),
                TestLink::make("peer", "identity", 9999)
            ),
            Err(CircuitError::Capacity)
        ));
    }

    #[tokio::test]
    async fn wait_for_lease_change_wakes_on_binding_refresh() {
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        backdate_monotonic_epoch();
        let id = CircuitId([22; 16]);
        install_test_binding(&router, 20, id, Instant::now() + CIRCUIT_LEASE, 1);
        let notify = router.lease_notify.clone();
        let wake = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), notify.notified()).await
        });
        // A refresh past the throttle notifies lease waiters.
        let now = monotonic_millis();
        let throttle = lease_refresh_throttle_millis();
        {
            let mut state = router.binding_state.write().expect("binding state lock");
            state
                .bindings
                .get_mut(&(20, id))
                .unwrap()
                .last_refresh_millis
                .store(now.saturating_sub(throttle + 1), Ordering::Relaxed);
        }
        assert!(router.refresh_binding(20, id));
        assert!(wake.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn replace_paths_swaps_the_manual_path_table() {
        let router = Router::new(
            "a",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        router
            .replace_paths(BTreeMap::from([(
                "c".into(),
                vec![vec!["b".into(), "c".into()]],
            )]))
            .await;
        let paths = router.paths.read().await;
        assert_eq!(
            paths.get("c"),
            Some(&vec![vec!["b".to_owned(), "c".to_owned()]])
        );
    }

    #[test]
    fn refresh_binding_renews_when_throttle_elapsed_and_rejects_unknown_circuits() {
        backdate_monotonic_epoch();
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        let id = CircuitId([17; 16]);
        install_test_binding(&router, 18, id, Instant::now() + CIRCUIT_LEASE, 1);
        assert!(!router.refresh_binding(18, CircuitId([99; 16])));

        let now = monotonic_millis();
        let throttle = lease_refresh_throttle_millis();
        {
            let mut state = router.binding_state.write().expect("binding state lock");
            state
                .bindings
                .get_mut(&(18, id))
                .unwrap()
                .last_refresh_millis
                .store(now.saturating_sub(throttle + 1), Ordering::Relaxed);
        }
        assert!(router.refresh_binding(18, id));
        let state = router.binding_state.read().expect("binding state lock");
        assert_eq!(state.bindings[&(18, id)].lease_generation, 2);
        assert_eq!(state.deadlines.heap.len(), 1);
    }

    #[test]
    fn renew_binding_extends_the_lease_after_the_throttle() {
        backdate_monotonic_epoch();
        let router = Router::new(
            "exit",
            TransitPolicy::default(),
            Arc::new(Mutex::new(HashMap::new())),
        );
        let id = CircuitId([18; 16]);
        install_test_binding(&router, 19, id, Instant::now() + CIRCUIT_LEASE, 1);
        let now = monotonic_millis();
        let throttle = lease_refresh_throttle_millis();
        {
            let mut state = router.binding_state.write().expect("binding state lock");
            state
                .bindings
                .get_mut(&(19, id))
                .unwrap()
                .last_refresh_millis
                .store(now.saturating_sub(throttle + 1), Ordering::Relaxed);
        }
        router
            .renew_binding(19, id, "source-key", 1)
            .expect("renewal after throttle extends the lease");
        let state = router.binding_state.read().expect("binding state lock");
        assert_eq!(state.bindings[&(19, id)].lease_generation, 2);
    }

    #[tokio::test]
    async fn expiring_a_relay_binding_cleans_relay_labels_both_ways() {
        let exit = "exit-identity";
        let incoming = TestLink::make("source", "source-identity", 21);
        let outgoing = TestLink::make("exit", exit, 22);
        let router = Router::new(
            "relay",
            TransitPolicy::default(),
            TestDirectory {
                links: vec![incoming.clone(), outgoing.clone()],
            },
        );
        let id = CircuitId([19; 16]);
        install_test_binding(&router, 21, id, Instant::now() - Duration::from_secs(1), 1);
        {
            let mut state = router.binding_state.write().expect("binding state lock");
            state.bindings.get_mut(&(21, id)).unwrap().outgoing = Some(outgoing.clone());
        }
        let incoming_table = router.relay_labels_for(21);
        incoming_table
            .write()
            .unwrap()
            .install(id, outgoing.clone())
            .unwrap();
        let outgoing_table = router.relay_labels_for(22);
        outgoing_table
            .write()
            .unwrap()
            .install(id, incoming.clone())
            .unwrap();

        assert_eq!(
            router.expire_due_bindings(Instant::now()).await,
            vec![(21, id)]
        );
        assert!(incoming_table.read().unwrap().forward(id).is_none());
        assert!(outgoing_table.read().unwrap().forward(id).is_none());
    }

    #[tokio::test]
    async fn reverse_relay_falls_back_to_binding_state_without_labels() {
        let exit = "exit-identity";
        let incoming = TestLink::make("source", "source-identity", 23);
        let outgoing = TestLink::make("exit", exit, 24);
        let router = Router::new(
            "relay",
            TransitPolicy::default(),
            TestDirectory {
                links: vec![incoming.clone(), outgoing.clone()],
            },
        );
        let id = CircuitId([20; 16]);
        install_test_binding(&router, 23, id, Instant::now() + CIRCUIT_LEASE, 1);
        {
            let mut state = router.binding_state.write().expect("binding state lock");
            state.bindings.get_mut(&(23, id)).unwrap().outgoing = Some(outgoing.clone());
        }
        let reversed = router.reverse_relay(24, id).await;
        assert_eq!(reversed.unwrap().instance(), 23);
    }

    #[tokio::test]
    async fn relay_open_without_permission_or_known_source_is_denied() {
        let source_key = crate::identity::generate();
        let source = crate::identity::node_id(&source_key.verifying_key());
        let relay_key = crate::identity::generate();
        let relay = crate::identity::node_id(&relay_key.verifying_key());
        let exit_key = crate::identity::generate();
        let exit = crate::identity::node_id(&exit_key.verifying_key());
        let incoming = TestLink::make("source", source.clone(), 25);
        let router = Router::new(
            relay.clone(),
            TransitPolicy::new(true, HashMap::new()),
            TestDirectory {
                links: vec![incoming.clone()],
            },
        );
        let request = OpenRequest::new(
            source.clone(),
            &source_key,
            exit.clone(),
            vec![source.clone(), relay, exit],
            CircuitId([21; 16]),
            [22; 32],
        );
        assert!(matches!(
            router.handle_open(incoming.as_ref(), &request).await,
            Err(RouterError::Circuit(CircuitError::Denied))
        ));
    }
}
