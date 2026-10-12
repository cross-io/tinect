//! QUIC link establishment. TLS protects the carrier while the signed hello
//! authenticates the Tinect identity, so self-signed transport certificates do
//! not become an authorization mechanism.

mod error;
mod quicp;
mod underlay;

pub use error::CarrierError;

use self::underlay::MixedUdpSocket;
use crate::{
    config::{CarrierProtocol, LinkHealthConfig},
    identity::{decode_public, encode_public, node_id},
    mtu::user_ip_capacity_from_physical_with_fec,
    physical::{PhysicalPayload, PhysicalSession},
    priority::{self, PriorityClass},
    topology::LinkStateAdvertisement,
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{Signer, Verifier};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, crypto::rustls::QuicClientConfig};
use rcgen::generate_simple_self_signed;
use rustls::{
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, Once, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore, broadcast, mpsc};
use tokio_util::sync::CancellationToken;

pub const CAP_RELIABLE_TOPOLOGY_STREAM: u32 = 1;
pub const MAX_PENDING_TOPOLOGY_DELTAS: usize = 4096;
const CONTROL_STREAM_SEND_TIMEOUT: Duration = Duration::from_secs(5);

struct FecLink {
    enabled: bool,
    rate_cap_milli: u16,
    receive_lock: StdMutex<()>,
    send_lock: StdMutex<()>,
    sender: StdMutex<crate::fec::WindowEncoder>,
    decoder: StdMutex<crate::fec::WindowDecoder>,
    estimator: StdMutex<crate::fec::LossEstimator>,
    repair_admission: StdMutex<RepairAdmission>,
    feedback_notify: Arc<Notify>,
    tail_notify: Arc<Notify>,
    recovery_notify: Arc<Notify>,
    feedback_started: AtomicBool,
    tail_started: AtomicBool,
    recovery_started: AtomicBool,
    tail_pending: AtomicBool,
    tail_generation: AtomicU64,
    last_source_millis: AtomicU64,
    last_report_id: AtomicU64,
    health: StdMutex<FecHealthState>,
    data_degraded: AtomicBool,
    #[cfg(test)]
    tail_idle_for_test: AtomicBool,
}

const FEC_FEEDBACK_RETRY_INITIAL: Duration = Duration::from_millis(50);
const FEC_FEEDBACK_RETRY_MAX: Duration = Duration::from_secs(2);
const FEC_TAIL_IDLE_DELAY: Duration = Duration::from_millis(50);
const FEC_TAIL_RETRY_INITIAL: Duration = Duration::from_millis(50);
const FEC_TAIL_RETRY_MAX: Duration = Duration::from_secs(2);
const FEC_RECOVERY_PROBE_INTERVAL: Duration = Duration::from_secs(1);
// One report needs 128 decided samples; leave room for the decoder's reorder
// tolerance so a single batch can produce feedback after a loss burst.
const FEC_RECOVERY_PROBE_BATCH_SIZE: usize = 128 + 8;
const FORWARD_QUEUE_CAPACITY: usize = 1024;
const FEC_READY_CAPACITY: usize = FORWARD_QUEUE_CAPACITY;
const FEC_DEGRADE_AFTER_SATURATED_REPORTS: u8 = 3;
const FEC_RECOVER_AFTER_VALID_REPORTS: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecReportHealth {
    Unchanged,
    Degraded,
    Recovered,
}

#[derive(Debug, Default)]
struct FecHealthState {
    saturated_reports: u8,
    valid_reports_after_degradation: u8,
    degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepairAdmission {
    rate_cap_milli: u16,
    highest_source_exclusive: Option<u32>,
    credit_milli: u64,
}

impl RepairAdmission {
    fn new(rate_cap_milli: u16) -> Self {
        Self {
            rate_cap_milli,
            highest_source_exclusive: None,
            credit_milli: 0,
        }
    }

    fn advance_to(&mut self, source_exclusive: u32) {
        let Some(highest) = self.highest_source_exclusive else {
            self.highest_source_exclusive = Some(source_exclusive);
            self.credit_milli = (u64::from(source_exclusive) * u64::from(self.rate_cap_milli))
                .min(crate::fec::MAX_REPAIR_CREDIT_MILLI);
            return;
        };
        let distance = source_exclusive.wrapping_sub(highest);
        if distance == 0 || distance >= 0x8000_0000 {
            return;
        }
        self.highest_source_exclusive = Some(source_exclusive);
        self.credit_milli = self
            .credit_milli
            .saturating_add(u64::from(distance) * u64::from(self.rate_cap_milli))
            .min(crate::fec::MAX_REPAIR_CREDIT_MILLI);
    }

    fn observe_source(&mut self, esi: u32) {
        self.advance_to(esi.wrapping_add(1));
    }

    fn admit_repair(&mut self, end_esi: u32) -> bool {
        self.advance_to(end_esi.wrapping_add(1));
        if self.credit_milli < 1_000 {
            return false;
        }
        self.credit_milli -= 1_000;
        true
    }
}

#[derive(Debug)]
enum RepairReceive {
    Accepted(crate::fec::Delivery),
    Discarded,
    RateLimited,
}

impl FecLink {
    fn new(rate_milli: u16) -> Self {
        Self {
            enabled: rate_milli != 0,
            rate_cap_milli: rate_milli.min(crate::fec::MAX_RATE_MILLI),
            receive_lock: StdMutex::new(()),
            send_lock: StdMutex::new(()),
            sender: StdMutex::new(crate::fec::WindowEncoder::new(rate_milli)),
            decoder: StdMutex::new(crate::fec::WindowDecoder::new()),
            estimator: StdMutex::new(crate::fec::LossEstimator::default()),
            repair_admission: StdMutex::new(RepairAdmission::new(rate_milli)),
            feedback_notify: Arc::new(Notify::new()),
            tail_notify: Arc::new(Notify::new()),
            recovery_notify: Arc::new(Notify::new()),
            feedback_started: AtomicBool::new(false),
            tail_started: AtomicBool::new(false),
            recovery_started: AtomicBool::new(false),
            tail_pending: AtomicBool::new(false),
            tail_generation: AtomicU64::new(0),
            last_source_millis: AtomicU64::new(monotonic_millis()),
            last_report_id: AtomicU64::new(0),
            health: StdMutex::new(FecHealthState::default()),
            data_degraded: AtomicBool::new(false),
            #[cfg(test)]
            tail_idle_for_test: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    fn force_tail_idle_for_test(&self) {
        self.tail_idle_for_test.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn push_source(
        &self,
        frame: &[u8],
    ) -> Result<(crate::fec::SourceSymbol, Vec<crate::fec::RepairSymbol>), crate::fec::FecError>
    {
        self.sender.lock().expect("FEC sender lock").push(frame)
    }

    fn send_source_batch(
        &self,
        frame: &[u8],
        send_source: impl FnOnce(crate::fec::SourceSymbol) -> Result<(), CarrierError>,
        mut send_repair: impl FnMut(crate::fec::RepairSymbol) -> Result<(), CarrierError>,
    ) -> Result<(), CarrierError> {
        let _send_guard = self.send_lock.lock().expect("FEC send lock");
        let mut sender = self.sender.lock().expect("FEC sender lock");
        let previous = sender.clone();
        let (source, repairs) = sender
            .push(frame)
            .map_err(|error| CarrierError::Protocol(format!("FEC source: {error:?}")))?;
        let source_transmission_sequence = source.transmission_sequence;
        if let Err(error) = send_source(source) {
            *sender = previous;
            return Err(error);
        }
        self.last_source_millis
            .store(monotonic_millis(), Ordering::Release);
        self.tail_generation.fetch_add(1, Ordering::Release);
        self.tail_pending.store(true, Ordering::Release);
        self.tail_notify.notify_one();
        let total_repairs = repairs.len();
        let mut sent_repairs = 0;
        for repair in repairs {
            match send_repair(repair) {
                Ok(()) => sent_repairs += 1,
                Err(error) => {
                    sender.rollback_unsent_repairs(
                        source_transmission_sequence,
                        sent_repairs,
                        total_repairs,
                    );
                    if error.is_local_datagram_rejection() {
                        return Ok(());
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn send_tail_batch(
        &self,
        mut send_repair: impl FnMut(crate::fec::RepairSymbol) -> Result<(), CarrierError>,
    ) -> Result<(), CarrierError> {
        let _send_guard = self.send_lock.lock().expect("FEC send lock");
        if !self.tail_idle() {
            return Ok(());
        }
        let mut sender = self.sender.lock().expect("FEC sender lock");
        let repairs = sender.flush_tail();
        let Some(first_repair_sequence) =
            repairs.first().map(|repair| repair.transmission_sequence)
        else {
            sender.finish_tail();
            self.tail_pending.store(false, Ordering::Release);
            return Ok(());
        };
        let total_repairs = repairs.len();
        let mut sent_repairs = 0;
        for repair in repairs {
            match send_repair(repair) {
                Ok(()) => sent_repairs += 1,
                Err(error) => {
                    let unsent_repairs = total_repairs.saturating_sub(sent_repairs);
                    sender.truncate_transmission_sequence(
                        first_repair_sequence.wrapping_add(sent_repairs as u32),
                    );
                    sender.restore_tail_repairs(unsent_repairs);
                    self.tail_pending.store(true, Ordering::Release);
                    // Local backpressure keeps the burst open; the tail worker
                    // retries the restored budget with bounded backoff.
                    if error.is_local_datagram_rejection() {
                        return Ok(());
                    }
                    return Err(error);
                }
            }
        }
        sender.finish_tail();
        self.tail_pending.store(false, Ordering::Release);
        Ok(())
    }

    fn tail_due(&self) -> bool {
        self.tail_pending.load(Ordering::Acquire) && self.tail_idle()
    }

    fn tail_idle(&self) -> bool {
        #[cfg(test)]
        if self.tail_idle_for_test.load(Ordering::Acquire) {
            return true;
        }
        monotonic_millis().saturating_sub(self.last_source_millis.load(Ordering::Acquire))
            >= FEC_TAIL_IDLE_DELAY.as_millis() as u64
    }

    fn receive_source(
        &self,
        transmission_sequence: u32,
        esi: u32,
        frame: &[u8],
    ) -> Result<crate::fec::Delivery, crate::fec::FecError> {
        let _receive_guard = self.receive_lock.lock().expect("FEC receive lock");
        let delivery = self
            .decoder
            .lock()
            .expect("FEC decoder lock")
            .source(esi, frame)?;
        self.estimator
            .lock()
            .expect("FEC estimator lock")
            .observe(transmission_sequence);
        self.repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .observe_source(esi);
        self.feedback_notify.notify_one();
        Ok(delivery)
    }

    fn receive_repair(
        &self,
        transmission_sequence: u32,
        rid: u32,
        first_esi: u32,
        symbol_count: u16,
        vector: &[u8],
    ) -> Result<RepairReceive, crate::fec::FecError> {
        let count = usize::from(symbol_count);
        if count == 0 || count > crate::fec::MAX_REPAIR_WINDOW {
            return Err(crate::fec::FecError::InvalidRepairCount);
        }
        if vector.is_empty() || vector.len() > crate::fec::MAX_SYMBOL_BYTES {
            return Err(crate::fec::FecError::RepairVectorTooLarge);
        }
        let end_esi = first_esi.wrapping_add(u32::from(symbol_count).saturating_sub(1));
        let _receive_guard = self.receive_lock.lock().expect("FEC receive lock");
        let window_admissible = self
            .decoder
            .lock()
            .expect("FEC decoder lock")
            .repair_window_admissible(first_esi, symbol_count)?;
        if !window_admissible {
            self.estimator
                .lock()
                .expect("FEC estimator lock")
                .observe(transmission_sequence);
            self.feedback_notify.notify_one();
            return Ok(RepairReceive::Discarded);
        }

        let candidate = {
            let admission = self
                .repair_admission
                .lock()
                .expect("FEC repair admission lock");
            let mut candidate = admission.clone();
            if !candidate.admit_repair(end_esi) {
                self.estimator
                    .lock()
                    .expect("FEC estimator lock")
                    .observe(transmission_sequence);
                self.feedback_notify.notify_one();
                return Ok(RepairReceive::RateLimited);
            }
            candidate
        };
        let delivery = self.decoder.lock().expect("FEC decoder lock").repair(
            rid,
            first_esi,
            symbol_count,
            vector,
        )?;
        if !delivery.discarded {
            *self
                .repair_admission
                .lock()
                .expect("FEC repair admission lock") = candidate;
        }
        self.estimator
            .lock()
            .expect("FEC estimator lock")
            .observe(transmission_sequence);
        self.feedback_notify.notify_one();
        Ok(RepairReceive::Accepted(delivery))
    }

    fn reordered(&self) -> u64 {
        self.estimator
            .lock()
            .expect("FEC estimator lock")
            .reordered()
    }

    fn loss_metrics(&self) -> (u64, u64) {
        self.estimator
            .lock()
            .expect("FEC estimator lock")
            .latest_report()
            .map(|report| (u64::from(report.loss_ppm), u64::from(report.samples)))
            .unwrap_or_default()
    }

    fn take_report(&self) -> Option<crate::fec::FecReport> {
        self.estimator
            .lock()
            .expect("FEC estimator lock")
            .take_report()
    }

    fn requeue_report(&self, report: crate::fec::FecReport) {
        self.estimator
            .lock()
            .expect("FEC estimator lock")
            .requeue_report(report);
    }

    fn feedback_notified(&self) -> &Notify {
        &self.feedback_notify
    }

    fn tail_notified(&self) -> &Notify {
        &self.tail_notify
    }

    fn recovery_notified(&self) -> &Notify {
        &self.recovery_notify
    }

    fn apply_report(&self, report: crate::fec::FecReport) -> FecReportHealth {
        if report.report_id <= self.last_report_id.load(Ordering::Acquire) {
            return FecReportHealth::Unchanged;
        }
        self.last_report_id
            .store(report.report_id, Ordering::Release);
        let health = self.observe_report_health(report);
        let Some(target) =
            crate::fec::window_rate_milli(crate::fec::WINDOW_CAPACITY, report, self.rate_cap_milli)
        else {
            return health;
        };
        let mut sender = self.sender.lock().expect("FEC sender lock");
        let rate = crate::fec::slew_rate_milli(sender.rate_milli(), target, self.rate_cap_milli);
        sender.set_rate_milli(rate);
        health
    }

    fn observe_report_health(&self, report: crate::fec::FecReport) -> FecReportHealth {
        let mut state = self.health.lock().expect("FEC health lock");
        let transition = if crate::fec::report_is_saturated_loss(report) {
            state.saturated_reports = state
                .saturated_reports
                .saturating_add(1)
                .min(FEC_DEGRADE_AFTER_SATURATED_REPORTS);
            state.valid_reports_after_degradation = 0;
            if !state.degraded && state.saturated_reports >= FEC_DEGRADE_AFTER_SATURATED_REPORTS {
                state.degraded = true;
                FecReportHealth::Degraded
            } else {
                FecReportHealth::Unchanged
            }
        } else if crate::fec::report_is_valid(report) {
            state.saturated_reports = 0;
            if state.degraded {
                state.valid_reports_after_degradation = state
                    .valid_reports_after_degradation
                    .saturating_add(1)
                    .min(FEC_RECOVER_AFTER_VALID_REPORTS);
                if state.valid_reports_after_degradation >= FEC_RECOVER_AFTER_VALID_REPORTS {
                    state.degraded = false;
                    FecReportHealth::Recovered
                } else {
                    FecReportHealth::Unchanged
                }
            } else {
                state.valid_reports_after_degradation = 0;
                FecReportHealth::Unchanged
            }
        } else {
            FecReportHealth::Unchanged
        };
        if !matches!(transition, FecReportHealth::Unchanged) {
            self.data_degraded.store(state.degraded, Ordering::Release);
            self.recovery_notify.notify_one();
        }
        transition
    }

    fn is_data_degraded(&self) -> bool {
        self.data_degraded.load(Ordering::Acquire)
    }
}

/// A Link-owned background operation.  The runtime owns spawning and joining
/// these futures so carrier workers cannot outlive daemon shutdown.
pub type LinkWorker = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityChangeReason {
    QuicDplpmtud,
    ProbeConfirmed,
    ProbeDecreased,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkCapacityChanged {
    pub link_instance: u64,
    /// Confirmed capacity in complete user IP bytes. Tinect and carrier
    /// headers have already been removed by the Link boundary.
    pub user_ip_capacity: u16,
    pub capacity_generation: u64,
    pub reason: CapacityChangeReason,
}

#[derive(Debug, Default)]
struct TopologyDeltaOutbox {
    /// The newest Delta for every origin that changed after the active
    /// Snapshot was fixed. Keeping this per-Link makes an old epoch unable to
    /// leak pending work into a replacement Link.
    pending: BTreeMap<String, LinkStateAdvertisement>,
}

impl TopologyDeltaOutbox {
    fn enqueue(&mut self, advertisements: Vec<LinkStateAdvertisement>) -> bool {
        let additional = advertisements
            .iter()
            .filter(|advertisement| !self.pending.contains_key(&advertisement.origin))
            .map(|advertisement| advertisement.origin.as_str())
            .collect::<HashSet<_>>()
            .len();
        if self.pending.len().saturating_add(additional) > MAX_PENDING_TOPOLOGY_DELTAS {
            return false;
        }
        for advertisement in advertisements {
            let replace = self
                .pending
                .get(&advertisement.origin)
                .is_none_or(|current| current.sequence <= advertisement.sequence);
            if replace {
                self.pending
                    .insert(advertisement.origin.clone(), advertisement);
            }
        }
        true
    }

    fn take(&mut self) -> Vec<LinkStateAdvertisement> {
        std::mem::take(&mut self.pending).into_values().collect()
    }
}

#[derive(Debug)]
pub(crate) struct BareDatagram {
    pub(crate) source: SocketAddr,
    pub(crate) frame: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BareEndpoint {
    inner: BareEndpointInner,
}
#[derive(Debug, Clone)]
enum BareEndpointInner {
    Udp(Arc<MixedUdpSocket>),
    #[cfg(target_os = "linux")]
    FakeTcp(Arc<quicp::QuicpSocket>),
}
impl BareEndpoint {
    fn register_receive_id(&self, id: u32) -> Result<mpsc::Receiver<BareDatagram>, CarrierError> {
        match &self.inner {
            BareEndpointInner::Udp(socket) => socket.register_receive_id(id),
            #[cfg(target_os = "linux")]
            BareEndpointInner::FakeTcp(socket) => socket.register_receive_id(id),
        }
        .map_err(|error| CarrierError::Protocol(error.to_string()))
    }
    fn unregister_receive_id(&self, id: u32) {
        match &self.inner {
            BareEndpointInner::Udp(socket) => socket.unregister_receive_id(id),
            #[cfg(target_os = "linux")]
            BareEndpointInner::FakeTcp(socket) => socket.unregister_receive_id(id),
        }
    }
    fn send(&self, remote: SocketAddr, frame: &[u8]) -> Result<usize, CarrierError> {
        match &self.inner {
            BareEndpointInner::Udp(socket) => socket.send_bare(remote, frame),
            #[cfg(target_os = "linux")]
            BareEndpointInner::FakeTcp(socket) => socket.send_bare(remote, frame),
        }
        .map_err(|error| match error.raw_os_error() {
            Some(errno) => CarrierError::LocalIo(errno),
            None => CarrierError::Protocol(error.to_string()),
        })
    }
}

/// Process-local monotonic clock used for lock-free link activity metrics.
fn monotonic_millis() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn classify_quic_datagram_error(
    error: quinn::SendDatagramError,
    size: usize,
    limit: Option<usize>,
) -> CarrierError {
    match error {
        quinn::SendDatagramError::TooLarge => CarrierError::DatagramTooLarge {
            size,
            limit: limit.unwrap_or_else(|| size.saturating_sub(1)),
        },
        quinn::SendDatagramError::ConnectionLost(error) => CarrierError::Quinn(error),
        quinn::SendDatagramError::UnsupportedByPeer => {
            CarrierError::Protocol("QUIC DATAGRAM is not supported by the peer".into())
        }
        quinn::SendDatagramError::Disabled => {
            CarrierError::Protocol("QUIC DATAGRAM support is disabled".into())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PmtuFailureReason {
    LocalOversize,
    QueuePressure,
    AckTimeout,
    PeerTeardown,
    Protocol,
}

fn classify_pmtu_failure(error: &CarrierError) -> PmtuFailureReason {
    match error {
        CarrierError::DatagramTooLarge { .. } => PmtuFailureReason::LocalOversize,
        CarrierError::AdmissionRejected => PmtuFailureReason::QueuePressure,
        CarrierError::LocalIo(errno) if is_local_backpressure_errno(*errno) => {
            PmtuFailureReason::QueuePressure
        }
        CarrierError::LocalIo(errno) if is_local_oversize_errno(*errno) => {
            PmtuFailureReason::LocalOversize
        }
        CarrierError::EndpointClosed
        | CarrierError::Quinn(_)
        | CarrierError::Connect(_)
        | CarrierError::Write(_)
        | CarrierError::Read(_) => PmtuFailureReason::PeerTeardown,
        _ => PmtuFailureReason::Protocol,
    }
}

/// A local EMSGSIZE is deterministic for the current socket path, unlike a
/// missing acknowledgement. Retrying the same candidate cannot provide new
/// information and only repeats framing, AEAD work and a failed send.
fn pmtu_should_retry_candidate(reason: Option<PmtuFailureReason>) -> bool {
    !matches!(reason, Some(PmtuFailureReason::LocalOversize))
}

// A recovered first hop must raise its active send budget promptly enough for
// the dynamic-budget contract, while a stable known ceiling must not restart
// the local binary search every few seconds.
fn bare_pmtu_upward_reprobe_interval() -> Duration {
    crate::timing::active().bare_pmtu_upward_reprobe_interval
}

fn pmtu_upward_reprobe_due(next: Option<Instant>, now: Instant) -> bool {
    next.is_some_and(|due| now >= due)
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InboundPacketKind {
    Quic,
    BarePhysical,
    Drop,
}

/// RFC-0014's deterministic first-byte demultiplexer. Quinn never sees a
/// packet with a clear fixed bit, and malformed/non-registered forms are
/// dropped before they can cause a per-link AEAD attempt.
#[allow(dead_code)]
pub(crate) fn classify_inbound_packet(packet: &[u8]) -> InboundPacketKind {
    let Some(&first) = packet.first() else {
        return InboundPacketKind::Drop;
    };
    if first & 0x40 != 0 {
        return InboundPacketKind::Quic;
    }
    if first & 0xC0 != 0
        || !(crate::physical::FORM_FORWARD..=crate::physical::FORM_FEC_REPAIR).contains(&first)
    {
        return InboundPacketKind::Drop;
    }
    if packet.len() < 1 + 4 + 8 + 16 {
        return InboundPacketKind::Drop;
    }
    if packet[1..5] == [0, 0, 0, 0] {
        return InboundPacketKind::Drop;
    }
    InboundPacketKind::BarePhysical
}

#[derive(Default)]
pub(crate) struct ReceiveIdAllocator {
    active: HashSet<u32>,
    next: u32,
}
impl ReceiveIdAllocator {
    pub(crate) fn allocate(&mut self) -> Option<u32> {
        for _ in 0..u32::MAX {
            self.next = self.next.wrapping_add(1).max(1);
            if self.active.insert(self.next) {
                return Some(self.next);
            }
        }
        None
    }
    pub(crate) fn release(&mut self, id: u32) {
        self.active.remove(&id);
    }
}
static RECEIVE_ID_ALLOCATOR: OnceLock<StdMutex<ReceiveIdAllocator>> = OnceLock::new();
#[derive(Debug)]
struct Hello {
    identity: String,
    public_key: String,
    nonce: String,
    sender_receive_id: u32,
    capabilities: u32,
    repair_rate: Option<u16>,
    signature: String,
}
#[derive(Debug)]
struct Ack {
    identity: String,
    public_key: String,
    sender_receive_id: u32,
    capabilities: u32,
    repair_rate: Option<u16>,
    signature: String,
}
fn id_bytes(value: &str) -> Result<[u8; 16], CarrierError> {
    if value.len() != 32 {
        return Err(CarrierError::Identity("node id length".into()));
    }
    let mut out = [0; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|e| CarrierError::Identity(e.to_string()))?;
    }
    Ok(out)
}
fn id_string(bytes: [u8; 16]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}
impl Hello {
    fn encode(&self) -> Result<Vec<u8>, CarrierError> {
        let mut out = crate::wire::Writer::new();
        out.raw(&id_bytes(&self.identity)?);
        out.raw(
            &STANDARD_NO_PAD
                .decode(&self.public_key)
                .map_err(|e| CarrierError::Identity(e.to_string()))?,
        );
        out.raw(
            &STANDARD_NO_PAD
                .decode(&self.nonce)
                .map_err(|e| CarrierError::Protocol(e.to_string()))?,
        );
        if self.sender_receive_id == 0 {
            return Err(CarrierError::Protocol("zero receive id".into()));
        }
        out.u32(self.sender_receive_id);
        out.u32(self.capabilities);
        if let Some(rate) = self.repair_rate {
            if rate == 0 || rate > crate::fec::MAX_RATE_MILLI {
                return Err(CarrierError::Protocol(
                    "FEC repair rate exceeds limit".into(),
                ));
            }
            out.u16(rate);
        }
        out.raw(
            &STANDARD_NO_PAD
                .decode(&self.signature)
                .map_err(|e| CarrierError::Identity(e.to_string()))?,
        );
        crate::wire::encode_message(1, out.finish())
            .map_err(|e| CarrierError::Protocol(e.to_string()))
    }
    fn decode(bytes: &[u8]) -> Result<Self, CarrierError> {
        let (kind, body) = crate::wire::decode_message(bytes)
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        if kind != 1 {
            return Err(CarrierError::Protocol("expected hello".into()));
        }
        let mut input = crate::wire::Reader::new(body);
        let identity = id_string(
            input
                .fixed()
                .map_err(|e| CarrierError::Protocol(e.to_string()))?,
        );
        let public_key = STANDARD_NO_PAD.encode(
            input
                .fixed::<32>()
                .map_err(|e| CarrierError::Protocol(e.to_string()))?,
        );
        let nonce = STANDARD_NO_PAD.encode(
            input
                .fixed::<32>()
                .map_err(|e| CarrierError::Protocol(e.to_string()))?,
        );
        let sender_receive_id = input
            .u32()
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        if sender_receive_id == 0 {
            return Err(CarrierError::Protocol("zero receive id".into()));
        }
        let capabilities = input
            .u32()
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        let repair_rate = match input.remaining().len() {
            64 => None,
            66 => {
                let rate = input
                    .u16()
                    .map_err(|e| CarrierError::Protocol(e.to_string()))?;
                if rate == 0 || rate > crate::fec::MAX_RATE_MILLI {
                    return Err(CarrierError::Protocol(
                        "FEC repair rate exceeds limit".into(),
                    ));
                }
                Some(rate)
            }
            _ => return Err(CarrierError::Protocol("invalid hello FEC extension".into())),
        };
        let signature = STANDARD_NO_PAD.encode(
            input
                .fixed::<64>()
                .map_err(|e| CarrierError::Protocol(e.to_string()))?,
        );
        input
            .finish()
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        Ok(Self {
            identity,
            public_key,
            nonce,
            sender_receive_id,
            capabilities,
            repair_rate,
            signature,
        })
    }
}
impl Ack {
    fn encode(&self) -> Result<Vec<u8>, CarrierError> {
        let mut out = crate::wire::Writer::new();
        out.raw(&id_bytes(&self.identity)?);
        out.raw(
            &STANDARD_NO_PAD
                .decode(&self.public_key)
                .map_err(|e| CarrierError::Identity(e.to_string()))?,
        );
        if self.sender_receive_id == 0 {
            return Err(CarrierError::Protocol("zero receive id".into()));
        }
        out.u32(self.sender_receive_id);
        out.u32(self.capabilities);
        if let Some(rate) = self.repair_rate {
            if rate == 0 || rate > crate::fec::MAX_RATE_MILLI {
                return Err(CarrierError::Protocol(
                    "FEC repair rate exceeds limit".into(),
                ));
            }
            out.u16(rate);
        }
        out.raw(
            &STANDARD_NO_PAD
                .decode(&self.signature)
                .map_err(|e| CarrierError::Identity(e.to_string()))?,
        );
        crate::wire::encode_message(2, out.finish())
            .map_err(|e| CarrierError::Protocol(e.to_string()))
    }
    fn decode(bytes: &[u8]) -> Result<Self, CarrierError> {
        let (kind, body) = crate::wire::decode_message(bytes)
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        if kind != 2 {
            return Err(CarrierError::Protocol(
                "expected hello acknowledgement".into(),
            ));
        }
        let mut input = crate::wire::Reader::new(body);
        let identity = id_string(
            input
                .fixed()
                .map_err(|e| CarrierError::Protocol(e.to_string()))?,
        );
        let public_key = STANDARD_NO_PAD.encode(
            input
                .fixed::<32>()
                .map_err(|e| CarrierError::Protocol(e.to_string()))?,
        );
        let sender_receive_id = input
            .u32()
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        if sender_receive_id == 0 {
            return Err(CarrierError::Protocol("zero receive id".into()));
        }
        let capabilities = input
            .u32()
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        let repair_rate = match input.remaining().len() {
            64 => None,
            66 => {
                let rate = input
                    .u16()
                    .map_err(|e| CarrierError::Protocol(e.to_string()))?;
                if rate == 0 || rate > crate::fec::MAX_RATE_MILLI {
                    return Err(CarrierError::Protocol(
                        "FEC repair rate exceeds limit".into(),
                    ));
                }
                Some(rate)
            }
            _ => {
                return Err(CarrierError::Protocol(
                    "invalid acknowledgement FEC extension".into(),
                ));
            }
        };
        let signature = STANDARD_NO_PAD.encode(
            input
                .fixed::<64>()
                .map_err(|e| CarrierError::Protocol(e.to_string()))?,
        );
        input
            .finish()
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        Ok(Self {
            identity,
            public_key,
            sender_receive_id,
            capabilities,
            repair_rate,
            signature,
        })
    }
}
pub struct Link {
    /// Local configuration name, used only for local status and link lookup.
    pub peer: String,
    /// Hash of the peer Ed25519 public key. This is the only peer identifier
    /// carried in protocol messages after the authenticated handshake.
    pub peer_identity: String,
    /// Authenticated identifier shared by both ends of a QUIC connection.
    /// It is used by the runtime to converge simultaneous dials to one Link.
    link_id: String,
    instance: u64,
    lifecycle_token: crate::link::LinkToken,
    carrier_healthy: AtomicBool,
    healthy: AtomicBool,
    connection: Connection,
    carrier: LinkCarrier,
    receive_id: u32,
    bare_mtu: AtomicU64,
    bare_target_upper: u16,
    pmtu: StdMutex<PmtuState>,
    pmtu_notify: Arc<Notify>,
    pmtu_cancel: CancellationToken,
    pmtu_started: AtomicBool,
    capacity_monitor_started: AtomicBool,
    quic_observed_capacity: AtomicU64,
    quic_capacity_generation: AtomicU64,
    capacity_events: broadcast::Sender<LinkCapacityChanged>,
    tx_datagrams: AtomicU64,
    tx_bytes: AtomicU64,
    tx_queue_drops: AtomicU64,
    datagram_wire_oversize: AtomicU64,
    stream_admission_rejections: AtomicU64,
    datagram_admission_rejections: AtomicU64,
    forward_queue_drops: AtomicU64,
    tx_errors: AtomicU64,
    pmtu_local_oversize: AtomicU64,
    pmtu_queue_pressure: AtomicU64,
    pmtu_ack_timeouts: AtomicU64,
    pmtu_peer_teardowns: AtomicU64,
    pmtu_protocol_errors: AtomicU64,
    rx_datagrams: AtomicU64,
    rx_bytes: AtomicU64,
    fec: FecLink,
    fec_ready: AsyncMutex<VecDeque<Vec<u8>>>,
    fec_tx_repairs: AtomicU64,
    fec_rx_sources: AtomicU64,
    fec_rx_repairs: AtomicU64,
    fec_recovered: AtomicU64,
    fec_lost: AtomicU64,
    fec_discarded: AtomicU64,
    fec_rate_limited: AtomicU64,
    fec_reordered: AtomicU64,
    fec_invalid: AtomicU64,
    fec_feedback_sent: AtomicU64,
    fec_feedback_retries: AtomicU64,
    physical: PhysicalSession,
    priority: priority::Gate,
    s0_stream_writers: Semaphore,
    s1_stream_writers: Semaphore,
    recovery_stream_writers: Semaphore,
    topology_inbound_synced: AtomicBool,
    topology_outbound_acked: AtomicBool,
    topology_delta_outbox: AsyncMutex<TopologyDeltaOutbox>,
    last_tx_millis: AtomicU64,
    last_rx_millis: AtomicU64,
    /// Log at most one high-rate data-plane rejection per link per second.
    /// Counters retain every event for diagnostics without turning a malformed
    /// or stale packet burst into synchronous log I/O.
    last_dataplane_warning_second: AtomicU64,
    /// Bounded single-consumer Forward queue.  A Link has exactly one data
    /// plane owner (legacy bridge, relay, or secure dispatcher), so a fanout
    /// queue would make packet ownership depend on subscriber timing.
    forward_payloads: mpsc::Sender<Vec<u8>>,
    forward_receiver: AsyncMutex<Option<mpsc::Receiver<Vec<u8>>>>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.lifecycle_token.revoke();
        self.pmtu_cancel.cancel();
        if let LinkCarrier::BareUdp {
            socket,
            local_receive_id,
            ..
        } = &self.carrier
        {
            socket.unregister_receive_id(*local_receive_id);
            release_receive_id(*local_receive_id);
        }
        if !matches!(&self.carrier, LinkCarrier::BareUdp { .. }) {
            release_receive_id(self.receive_id);
        }
    }
}

enum LinkCarrier {
    Quic,
    BareUdp {
        socket: Arc<BareEndpoint>,
        remote: SocketAddr,
        destination_receive_id: u32,
        receiver: AsyncMutex<mpsc::Receiver<BareDatagram>>,
        local_receive_id: u32,
    },
}

fn enqueue_bounded_fec_frames(
    queue: &mut VecDeque<Vec<u8>>,
    frames: impl IntoIterator<Item = Vec<u8>>,
) -> usize {
    let mut dropped = 0;
    for frame in frames {
        // Recovery probes are estimator-only traffic.  Filter them before
        // applying the bounded queue policy so a probe burst cannot evict or
        // crowd out a real Forward frame waiting for the single consumer.
        if crate::fec::is_recovery_probe(&frame) {
            continue;
        }
        if queue.len() >= FEC_READY_CAPACITY {
            dropped += 1;
        } else {
            queue.push_back(frame);
        }
    }
    dropped
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod topology_outbox_tests {
    use super::*;

    fn advertisement(origin: &str, sequence: u64) -> LinkStateAdvertisement {
        LinkStateAdvertisement {
            origin: origin.into(),
            sequence,
            expires_at: 1,
            neighbors: Vec::new(),
            public_key: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn topology_delta_outbox_coalesces_per_origin() {
        let mut outbox = TopologyDeltaOutbox::default();
        assert!(outbox.enqueue(vec![advertisement("01", 1), advertisement("02", 4)]));
        assert!(outbox.enqueue(vec![advertisement("01", 3), advertisement("02", 2)]));
        let pending = outbox.take();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].sequence, 3);
        assert_eq!(pending[1].sequence, 4);
        assert!(outbox.take().is_empty());
    }

    #[test]
    fn topology_delta_outbox_rejects_at_capacity_and_keeps_newest_per_origin() {
        let mut outbox = TopologyDeltaOutbox::default();
        for index in 0..MAX_PENDING_TOPOLOGY_DELTAS {
            assert!(outbox.enqueue(vec![advertisement(&format!("{index:032x}"), 1)]));
        }
        // At capacity a brand-new origin must be rejected so the caller can
        // enter SnapshotRequired instead of silently losing the change.
        assert!(!outbox.enqueue(vec![advertisement("ffffffffffffffffffffffffffffffff", 1)]));
        // A known origin is still coalesced to its newest sequence.
        assert!(outbox.enqueue(vec![advertisement("00000000000000000000000000000000", 2)]));
        let pending = outbox.take();
        assert_eq!(pending.len(), MAX_PENDING_TOPOLOGY_DELTAS);
        assert!(pending.iter().any(|advertisement| advertisement.origin
            == "00000000000000000000000000000000"
            && advertisement.sequence == 2));
        assert!(outbox.take().is_empty());
    }

    #[test]
    fn fec_ready_queue_drops_at_a_fixed_bound() {
        let mut queue = VecDeque::new();
        let dropped = enqueue_bounded_fec_frames(
            &mut queue,
            (0..=FEC_READY_CAPACITY).map(|value| vec![value as u8]),
        );
        assert_eq!(queue.len(), FEC_READY_CAPACITY);
        assert_eq!(dropped, 1);
    }

    #[test]
    fn fec_recovery_probes_do_not_consume_forward_queue_capacity() {
        let mut queue = VecDeque::new();
        let mut frames = (0..FEC_READY_CAPACITY)
            .map(|value| vec![value as u8])
            .collect::<Vec<_>>();
        frames.push(crate::fec::recovery_probe_frame());
        frames.push(vec![0xff]);

        let dropped = enqueue_bounded_fec_frames(&mut queue, frames);

        assert_eq!(queue.len(), FEC_READY_CAPACITY);
        assert_eq!(dropped, 1);
        assert!(
            queue
                .iter()
                .all(|frame| !crate::fec::is_recovery_probe(frame))
        );
    }

    #[test]
    fn local_pmtu_oversize_is_not_retried() {
        assert!(!pmtu_should_retry_candidate(Some(
            PmtuFailureReason::LocalOversize,
        )));
        assert!(pmtu_should_retry_candidate(Some(
            PmtuFailureReason::AckTimeout,
        )));
    }

    #[test]
    fn pmtu_failure_classification_preserves_local_and_peer_causes() {
        assert_eq!(
            classify_pmtu_failure(&CarrierError::DatagramTooLarge { size: 2, limit: 1 }),
            PmtuFailureReason::LocalOversize
        );
        assert_eq!(
            classify_pmtu_failure(&CarrierError::AdmissionRejected),
            PmtuFailureReason::QueuePressure
        );
        assert_eq!(
            classify_pmtu_failure(&CarrierError::LocalIo(libc::EAGAIN)),
            PmtuFailureReason::QueuePressure
        );
        assert_eq!(
            classify_pmtu_failure(&CarrierError::LocalIo(libc::EMSGSIZE)),
            PmtuFailureReason::LocalOversize
        );
        assert_eq!(
            classify_pmtu_failure(&CarrierError::EndpointClosed),
            PmtuFailureReason::PeerTeardown
        );
        assert_eq!(
            classify_pmtu_failure(&CarrierError::Protocol("invalid probe".into())),
            PmtuFailureReason::Protocol
        );
    }

    #[test]
    fn quic_too_large_is_a_local_datagram_rejection() {
        let error =
            classify_quic_datagram_error(quinn::SendDatagramError::TooLarge, 1_201, Some(1_200));
        assert!(error.is_local_datagram_rejection());
        assert!(matches!(
            error,
            CarrierError::DatagramTooLarge {
                size: 1_201,
                limit: 1_200
            }
        ));
    }

    #[test]
    fn quic_datagram_disable_is_not_a_local_rejection() {
        let error =
            classify_quic_datagram_error(quinn::SendDatagramError::Disabled, 1_201, Some(1_200));
        assert!(!error.is_local_datagram_rejection());
        assert!(matches!(error, CarrierError::Protocol(_)));
    }

    #[test]
    fn quic_connection_loss_remains_fatal() {
        let error = classify_quic_datagram_error(
            quinn::SendDatagramError::ConnectionLost(quinn::ConnectionError::TimedOut),
            1_201,
            Some(1_200),
        );
        assert!(!error.is_local_datagram_rejection());
        assert!(matches!(error, CarrierError::Quinn(_)));
    }

    #[test]
    fn upward_pmtu_reprobe_waits_for_its_recovery_deadline() {
        let now = Instant::now();
        let due = now + bare_pmtu_upward_reprobe_interval();
        assert!(!pmtu_upward_reprobe_due(Some(due), now));
        assert!(pmtu_upward_reprobe_due(Some(due), due));
        assert!(!pmtu_upward_reprobe_due(None, due));
    }

    fn pmtu_state_for_test() -> PmtuState {
        PmtuState {
            confirmed_capacity: 1_200,
            safe_capacity: 1_000,
            lower_bound: 1_200,
            upper_bound: 1_400,
            active: None,
            consecutive_successes: 0,
            consecutive_failures: 0,
            last_confirmed_at: None,
            next_upward_reprobe_at: None,
            capacity_generation: 1,
            next_attempt_id: 0,
        }
    }

    #[test]
    fn pmtu_state_transitions_cover_tightening_confirmation_and_reprobe() {
        let now = Instant::now();
        let mut state = pmtu_state_for_test();
        assert_eq!(
            tighten_pmtu_after_failure(&mut state, 1_200, now),
            Some((1_136, 2))
        );
        assert_eq!(state.lower_bound, 1_000);
        assert_eq!(state.upper_bound, 1_199);
        assert!(state.next_upward_reprobe_at.is_some());

        let mut state = pmtu_state_for_test();
        assert_eq!(tighten_pmtu_after_failure(&mut state, 1_300, now), None);
        assert_eq!(state.confirmed_capacity, 1_200);
        assert_eq!(state.upper_bound, 1_299);
        assert!(state.next_upward_reprobe_at.is_some());

        let mut state = pmtu_state_for_test();
        assert_eq!(apply_pmtu_success(&mut state, 1_300, 1_448, now), None);
        assert_eq!(state.consecutive_successes, 1);
        assert_eq!(
            apply_pmtu_success(&mut state, 1_300, 1_448, now),
            Some((1_300, 2))
        );
        assert_eq!(state.lower_bound, 1_300);

        let mut state = pmtu_state_for_test();
        state.upper_bound = 1_250;
        state.next_upward_reprobe_at = Some(now - Duration::from_secs(1));
        assert_eq!(apply_pmtu_success(&mut state, 1_200, 1_448, now), None);
        assert_eq!(state.upper_bound, 1_444);
        assert!(state.next_upward_reprobe_at.is_none());

        let mut state = pmtu_state_for_test();
        assert_eq!(apply_pmtu_success(&mut state, 1_100, 1_448, now), None);
        assert_eq!(state.consecutive_successes, 1);
    }

    #[test]
    fn fec_link_recovers_a_dropped_source_and_ignores_stale_feedback() {
        let sender = FecLink::new(1_000);
        let receiver = FecLink::new(1_000);
        let frames = [
            vec![1; crate::crypto::FRAME_OVERHEAD + 3],
            vec![2; crate::crypto::FRAME_OVERHEAD + 7],
            vec![3; crate::crypto::FRAME_OVERHEAD + 5],
        ];
        let mut generated = Vec::new();
        for frame in &frames {
            generated.push(sender.push_source(frame).unwrap());
        }
        let first = receiver
            .receive_source(
                generated[0].0.transmission_sequence,
                generated[0].0.esi,
                &generated[0].0.frame,
            )
            .unwrap();
        assert_eq!(first.frames[0].frame, frames[0]);
        assert_eq!(first.frames[0].origin, crate::fec::DeliveryOrigin::Source);
        let third = receiver
            .receive_source(
                generated[2].0.transmission_sequence,
                generated[2].0.esi,
                &generated[2].0.frame,
            )
            .unwrap();
        assert_eq!(third.frames[0].frame, frames[2]);
        assert_eq!(third.frames[0].origin, crate::fec::DeliveryOrigin::Source);
        let repair = &generated[2].1[0];
        let recovered = match receiver
            .receive_repair(
                repair.transmission_sequence,
                repair.rid,
                repair.first_esi,
                repair.symbol_count,
                &repair.vector,
            )
            .unwrap()
        {
            RepairReceive::Accepted(delivery) => delivery,
            RepairReceive::Discarded => panic!("valid repair was discarded"),
            RepairReceive::RateLimited => panic!("valid repair was rate limited"),
        };
        assert_eq!(recovered.frames.len(), 1);
        assert_eq!(recovered.frames[0].frame, frames[1]);
        assert_eq!(
            recovered.frames[0].origin,
            crate::fec::DeliveryOrigin::Recovered
        );
        assert_eq!(recovered.frames[0].esi, generated[1].0.esi);
        assert!(
            receiver
                .receive_source(
                    generated[1].0.transmission_sequence,
                    generated[1].0.esi,
                    &generated[1].0.frame,
                )
                .unwrap()
                .frames
                .is_empty()
        );
        let report = crate::fec::FecReport {
            report_id: 1,
            samples: 128,
            loss_ppm: 100_000,
            burst_milli: 1_000,
        };
        assert_eq!(sender.apply_report(report), FecReportHealth::Unchanged);
        assert_eq!(sender.apply_report(report), FecReportHealth::Unchanged);
    }

    #[test]
    fn saturated_fec_reports_degrade_after_a_consecutive_threshold() {
        let sender = FecLink::new(1_000);
        let report = |report_id| crate::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm: 1_000_000,
            burst_milli: 1_000,
        };
        assert_eq!(sender.apply_report(report(1)), FecReportHealth::Unchanged);
        assert_eq!(sender.apply_report(report(2)), FecReportHealth::Unchanged);
        assert_eq!(sender.apply_report(report(2)), FecReportHealth::Unchanged);
        assert!(!sender.is_data_degraded());
        assert_eq!(sender.apply_report(report(3)), FecReportHealth::Degraded);
        assert_eq!(sender.sender.lock().unwrap().rate_milli(), 1_000);
        assert!(sender.is_data_degraded());

        let valid = |report_id| crate::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm: 100_000,
            burst_milli: 1_000,
        };
        assert_eq!(sender.apply_report(valid(4)), FecReportHealth::Unchanged);
        assert_eq!(sender.apply_report(valid(5)), FecReportHealth::Recovered);
        assert!(!sender.is_data_degraded());
    }

    #[test]
    fn invalid_fec_reports_do_not_advance_health_hysteresis() {
        let sender = FecLink::new(1_000);
        let saturated = |report_id| crate::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm: 1_000_000,
            burst_milli: 1_000,
        };
        let invalid = |report_id| crate::fec::FecReport {
            report_id,
            samples: 127,
            loss_ppm: 1_000_000,
            burst_milli: 1_000,
        };
        assert_eq!(
            sender.apply_report(saturated(1)),
            FecReportHealth::Unchanged
        );
        assert_eq!(sender.apply_report(invalid(2)), FecReportHealth::Unchanged);
        assert_eq!(
            sender.apply_report(saturated(3)),
            FecReportHealth::Unchanged
        );
        assert!(!sender.is_data_degraded());
        assert_eq!(sender.apply_report(saturated(4)), FecReportHealth::Degraded);
    }

    #[test]
    fn fec_loss_metrics_come_from_the_local_sequence_estimator() {
        let receiver = FecLink::new(1_000);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];
        for sequence in 0..=200 {
            receiver.receive_source(sequence, sequence, &frame).unwrap();
        }

        let (loss_ppm, samples) = receiver.loss_metrics();
        assert_eq!(loss_ppm, 0);
        assert!(samples >= 128);
    }

    #[test]
    fn fec_source_state_rolls_back_when_source_send_fails() {
        let sender = FecLink::new(1_000);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];

        let result = sender.send_source_batch(
            &frame,
            |_source| Err(CarrierError::AdmissionRejected),
            |_repair| Ok(()),
        );
        assert!(matches!(result, Err(CarrierError::AdmissionRejected)));

        let (source, repairs) = sender.push_source(&frame).unwrap();
        assert_eq!(source.esi, 0);
        assert_eq!(source.transmission_sequence, 0);
        assert_eq!(repairs[0].rid, 0);
    }

    #[test]
    fn nonfatal_repair_send_failure_does_not_fail_source_batch() {
        let sender = FecLink::new(1_000);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];

        sender
            .send_source_batch(
                &frame,
                |_source| Ok(()),
                |_repair| Err(CarrierError::WouldBlock),
            )
            .unwrap();

        let (source, _) = sender.push_source(&frame).unwrap();
        assert_eq!(source.esi, 1);
        assert_eq!(source.transmission_sequence, 1);
    }

    #[test]
    fn repeated_repair_capacity_rejection_keeps_sender_credit_bounded() {
        let sender = FecLink::new(crate::fec::MAX_RATE_MILLI);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];
        let pushes_to_cap =
            (crate::fec::MAX_REPAIR_CREDIT_MILLI / u64::from(crate::fec::MAX_RATE_MILLI)) as usize;

        for _ in 0..=pushes_to_cap {
            sender
                .send_source_batch(
                    &frame,
                    |_source| Ok(()),
                    |_repair| {
                        Err(CarrierError::DatagramTooLarge {
                            size: 1_201,
                            limit: 1_200,
                        })
                    },
                )
                .unwrap();
            assert!(
                sender
                    .sender
                    .lock()
                    .expect("FEC sender lock")
                    .credit_milli_for_test()
                    <= crate::fec::MAX_REPAIR_CREDIT_MILLI
            );
        }

        assert_eq!(
            sender
                .sender
                .lock()
                .expect("FEC sender lock")
                .credit_milli_for_test(),
            crate::fec::MAX_REPAIR_CREDIT_MILLI
        );
    }

    #[test]
    fn fatal_repair_send_failure_keeps_source_state_committed() {
        let sender = FecLink::new(1_000);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];

        assert!(matches!(
            sender.send_source_batch(
                &frame,
                |_source| Ok(()),
                |_repair| Err(CarrierError::EndpointClosed),
            ),
            Err(CarrierError::EndpointClosed)
        ));

        let (source, _) = sender.push_source(&frame).unwrap();
        assert_eq!(source.esi, 1);
        assert_eq!(source.transmission_sequence, 1);
    }

    #[tokio::test]
    async fn fec_source_batch_notifies_tail_worker() {
        let sender = FecLink::new(1_500);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];
        let notified = sender.tail_notified().notified();

        sender
            .send_source_batch(
                &frame,
                |_source| Ok(()),
                |_repair| Err(CarrierError::WouldBlock),
            )
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), notified)
            .await
            .expect("FEC tail notification should be delivered");
    }

    #[test]
    fn fec_admission_and_tail_helpers_cover_empty_invalid_and_rate_limited_paths() {
        let mut admission = RepairAdmission::new(1_000);
        admission.advance_to(1);
        let snapshot = admission.clone();
        admission.advance_to(1);
        admission.advance_to(0);
        assert_eq!(admission, snapshot);
        admission.observe_source(0);
        assert!(admission.admit_repair(0));
        assert!(!admission.admit_repair(0));

        let sender = FecLink::new(0);
        assert!(!sender.tail_due());
        sender.force_tail_idle_for_test();
        assert!(!sender.tail_due());
        sender
            .send_tail_batch(|_| Ok(()))
            .expect("an empty tail is a successful no-op");

        assert!(matches!(
            sender.send_source_batch(&[], |_| Ok(()), |_| Ok(())),
            Err(CarrierError::Protocol(_))
        ));
        assert!(matches!(
            sender.receive_repair(1, 1, 0, 0, &[1]),
            Err(crate::fec::FecError::InvalidRepairCount)
        ));
        assert!(matches!(
            sender.receive_repair(1, 1, 0, (crate::fec::MAX_REPAIR_WINDOW + 1) as u16, &[1]),
            Err(crate::fec::FecError::InvalidRepairCount)
        ));
        assert!(matches!(
            sender.receive_repair(1, 1, 0, 1, &[]),
            Err(crate::fec::FecError::RepairVectorTooLarge)
        ));
        assert!(matches!(
            sender.receive_repair(1, 1, 0, 1, &vec![1; crate::fec::MAX_SYMBOL_BYTES + 1]),
            Err(crate::fec::FecError::RepairVectorTooLarge)
        ));
        assert!(matches!(
            sender.receive_repair(1, 1, 0, 1, &[1]),
            Ok(RepairReceive::RateLimited)
        ));
        assert_eq!(sender.reordered(), 0);
        assert!(sender.take_report().is_none());
        sender.requeue_report(crate::fec::FecReport {
            report_id: 1,
            samples: 128,
            loss_ppm: 0,
            burst_milli: 0,
        });
        assert!(sender.take_report().is_some());
        let _ = sender.feedback_notified();
        let _ = sender.recovery_notified();
    }

    #[test]
    fn tail_repairs_are_sent_after_idle_without_sequence_gaps() {
        let sender = FecLink::new(1_500);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];
        sender
            .send_source_batch(
                &frame,
                |_source| Ok(()),
                |_repair| Err(CarrierError::WouldBlock),
            )
            .unwrap();
        sender.force_tail_idle_for_test();

        let mut sequences = Vec::new();
        sender
            .send_tail_batch(|repair| {
                sequences.push(repair.transmission_sequence);
                Ok(())
            })
            .unwrap();
        assert_eq!(sequences, vec![1]);
        assert!(!sender.tail_due());

        let (source, repairs) = sender.push_source(&frame).unwrap();
        assert_eq!(source.transmission_sequence, 2);
        assert_eq!(repairs[0].transmission_sequence, 3);
        assert_eq!(repairs.len(), 2);
    }

    #[test]
    fn tail_repair_send_failure_retries_unsent_repairs_without_sequence_gaps() {
        let sender = FecLink::new(4_500);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];
        for _ in 0..3 {
            sender
                .send_source_batch(
                    &frame,
                    |_source| Ok(()),
                    |_repair| Err(CarrierError::WouldBlock),
                )
                .unwrap();
        }
        sender.force_tail_idle_for_test();

        let mut attempts = 0;
        let mut sent = Vec::new();
        sender
            .send_tail_batch(|repair| {
                attempts += 1;
                if attempts == 1 {
                    sent.push(repair.transmission_sequence);
                    Ok(())
                } else {
                    Err(CarrierError::AdmissionRejected)
                }
            })
            .unwrap();
        assert_eq!(sent, vec![3]);
        assert!(sender.tail_pending.load(Ordering::Acquire));

        let mut retried = Vec::new();
        sender
            .send_tail_batch(|repair| {
                retried.push(repair.transmission_sequence);
                Ok(())
            })
            .unwrap();
        assert_eq!(retried, vec![4, 5, 6]);
        assert!(!sender.tail_pending.load(Ordering::Acquire));

        let (source, _) = sender.push_source(&frame).unwrap();
        assert_eq!(source.transmission_sequence, 7);
    }

    #[test]
    fn repair_admission_respects_fractional_rate_and_burst_cap() {
        let mut admission = RepairAdmission::new(750);
        let mut accepted = 0;
        for esi in 0..10_000 {
            admission.observe_source(esi);
            if admission.admit_repair(esi) {
                accepted += 1;
            }
        }
        assert!(accepted <= 7_501, "accepted {accepted} repairs");

        let mut burst = RepairAdmission::new(750);
        for esi in 0..2_000 {
            burst.observe_source(esi);
        }
        let mut burst_accepted = 0;
        for esi in 0..2_000 {
            if burst.admit_repair(esi) {
                burst_accepted += 1;
            }
        }
        assert_eq!(burst_accepted, crate::fec::DECODER_WIDTH);

        let mut disabled = RepairAdmission::new(0);
        disabled.observe_source(0);
        assert!(!disabled.admit_repair(0));
    }

    #[test]
    fn rate_limited_repair_never_enters_decoder() {
        let receiver = FecLink::new(750);
        let before = receiver
            .repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .clone();
        assert!(matches!(
            receiver
                .receive_repair(0, 1, 0, 1, &[0; crate::crypto::FRAME_OVERHEAD + 2])
                .unwrap(),
            RepairReceive::RateLimited
        ));
        let after = receiver
            .repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .clone();
        assert_eq!(before, after);
        let delivery = receiver
            .receive_source(1, 0, &[1; crate::crypto::FRAME_OVERHEAD + 3])
            .unwrap();
        assert_eq!(delivery.frames.len(), 1);
    }

    #[test]
    fn invalid_repair_window_does_not_consume_admission_credit() {
        let receiver = FecLink::new(1_000);
        receiver
            .receive_source(0, 0, &[1; crate::crypto::FRAME_OVERHEAD + 3])
            .unwrap();
        let before = receiver
            .repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .clone();
        assert!(matches!(
            receiver.receive_repair(
                1,
                1,
                (crate::fec::MAX_REPAIR_WINDOW * 4 + 1) as u32,
                1,
                &[0; crate::crypto::FRAME_OVERHEAD + 2],
            ),
            Ok(RepairReceive::Accepted(crate::fec::Delivery {
                discarded: true,
                ..
            }))
        ));
        let after = receiver
            .repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .clone();
        assert_eq!(before, after);
    }

    #[test]
    fn expired_repair_is_discarded_without_consuming_admission_credit() {
        let receiver = FecLink::new(1_000);
        receiver
            .receive_source(0, 0, &[1; crate::crypto::FRAME_OVERHEAD + 3])
            .unwrap();
        receiver
            .receive_source(
                1,
                (crate::fec::DECODER_WIDTH + 1) as u32,
                &[2; crate::crypto::FRAME_OVERHEAD + 3],
            )
            .unwrap();
        let before = receiver
            .repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .clone();
        assert!(matches!(
            receiver
                .receive_repair(2, 1, 0, 1, &[0; crate::crypto::FRAME_OVERHEAD + 2])
                .unwrap(),
            RepairReceive::Discarded
        ));
        let after = receiver
            .repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .clone();
        assert_eq!(before, after);
    }

    #[test]
    fn discarded_repair_does_not_consume_admission_credit() {
        let sender = FecLink::new(1_000);
        let receiver = FecLink::new(1_000);
        let (source, repairs) = sender
            .push_source(&[1; crate::crypto::FRAME_OVERHEAD + 3])
            .unwrap();
        receiver
            .receive_source(source.transmission_sequence, source.esi, &source.frame)
            .unwrap();
        let before = receiver
            .repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .clone();
        assert!(matches!(
            receiver
                .receive_repair(
                    repairs[0].transmission_sequence,
                    repairs[0].rid,
                    repairs[0].first_esi,
                    repairs[0].symbol_count,
                    &repairs[0].vector,
                )
                .unwrap(),
            RepairReceive::Accepted(crate::fec::Delivery {
                discarded: true,
                ..
            })
        ));
        let after = receiver
            .repair_admission
            .lock()
            .expect("FEC repair admission lock")
            .clone();
        assert_eq!(before, after);
    }

    #[test]
    fn tail_batch_waits_for_idle_and_recovers_from_fatal_errors() {
        let sender = FecLink::new(1_000);
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];
        sender
            .send_source_batch(
                &frame,
                |_source| Ok(()),
                |_repair| Err(CarrierError::WouldBlock),
            )
            .unwrap();

        // The idle delay has not elapsed yet: the tail batch is a no-op and
        // must not touch the pending repairs.
        sender
            .send_tail_batch(|_| -> Result<(), CarrierError> {
                unreachable!("tail must wait for idle")
            })
            .unwrap();
        assert!(sender.tail_pending.load(Ordering::Acquire));

        sender.force_tail_idle_for_test();
        // A fatal (non-local) send failure propagates, but the unsent repairs
        // stay queued so a later flush can still deliver them.
        assert!(matches!(
            sender.send_tail_batch(|_| Err(CarrierError::EndpointClosed)),
            Err(CarrierError::EndpointClosed)
        ));
        assert!(sender.tail_pending.load(Ordering::Acquire));

        let mut retried = Vec::new();
        sender
            .send_tail_batch(|repair| {
                retried.push(repair.transmission_sequence);
                Ok(())
            })
            .unwrap();
        assert_eq!(retried, vec![1]);
        assert!(!sender.tail_pending.load(Ordering::Acquire));
    }

    #[test]
    fn fec_receive_source_rejects_truncated_frames() {
        let receiver = FecLink::new(1_000);
        assert!(matches!(
            receiver.receive_source(0, 0, &[1; crate::crypto::FRAME_OVERHEAD - 1]),
            Err(crate::fec::FecError::FrameTooShort)
        ));
    }

    #[test]
    fn quic_datagram_unsupported_by_peer_is_a_protocol_error() {
        let error = classify_quic_datagram_error(
            quinn::SendDatagramError::UnsupportedByPeer,
            1_201,
            Some(1_200),
        );
        assert!(!error.is_local_datagram_rejection());
        assert!(matches!(error, CarrierError::Protocol(_)));
    }
}

struct ProbeInFlight {
    attempt_id: u64,
    probe_id: u64,
    target: u16,
    deadline: Instant,
    acknowledged: bool,
}

struct PmtuState {
    confirmed_capacity: u16,
    safe_capacity: u16,
    lower_bound: u16,
    upper_bound: u16,
    active: Option<ProbeInFlight>,
    consecutive_successes: u8,
    consecutive_failures: u8,
    last_confirmed_at: Option<Instant>,
    /// After a failed upward probe, retain the learned ceiling until a
    /// deliberately infrequent recovery check. This avoids restarting the
    /// same local binary search after every successful downward check.
    next_upward_reprobe_at: Option<Instant>,
    capacity_generation: u64,
    next_attempt_id: u64,
}

/// Tighten the software PMTU after a probe that did not establish a usable
/// candidate. The returned generation is published by the Link layer only
/// when the confirmed capacity actually changed.
fn tighten_pmtu_after_failure(
    state: &mut PmtuState,
    target: u16,
    now: Instant,
) -> Option<(u16, u64)> {
    if target == state.confirmed_capacity {
        let previous = state.confirmed_capacity;
        state.confirmed_capacity = previous.saturating_sub(64).max(state.safe_capacity);
        state.lower_bound = state.safe_capacity;
        state.upper_bound = previous.saturating_sub(1).max(state.confirmed_capacity);
        state.last_confirmed_at = Some(now);
        state.next_upward_reprobe_at = Some(now + bare_pmtu_upward_reprobe_interval());
        state.capacity_generation = state.capacity_generation.saturating_add(1);
        Some((state.confirmed_capacity, state.capacity_generation))
    } else {
        state.upper_bound = target.saturating_sub(1).max(state.confirmed_capacity);
        state.next_upward_reprobe_at = Some(now + bare_pmtu_upward_reprobe_interval());
        None
    }
}

/// Apply a successful probe to the hysteresis state. A return value denotes a
/// newly confirmed capacity that the Link layer must publish.
fn apply_pmtu_success(
    state: &mut PmtuState,
    target: u16,
    bare_target_upper: u16,
    now: Instant,
) -> Option<(u16, u64)> {
    state.consecutive_successes = state.consecutive_successes.saturating_add(1);
    state.consecutive_failures = 0;
    if state.consecutive_successes >= 2 && target > state.confirmed_capacity {
        state.confirmed_capacity = target;
        state.lower_bound = target;
        state.consecutive_successes = 0;
        state.last_confirmed_at = Some(now);
        state.capacity_generation = state.capacity_generation.saturating_add(1);
        Some((target, state.capacity_generation))
    } else if target == state.confirmed_capacity {
        state.consecutive_successes = 0;
        state.last_confirmed_at = Some(now);
        // A successful re-check proves that the current path remains usable.
        // A prior local EMSGSIZE has already taught us a tighter ceiling, so
        // only re-open that upward search on its recovery cadence instead of
        // repeating known failures on every downward check.
        if pmtu_upward_reprobe_due(state.next_upward_reprobe_at, now) {
            state.lower_bound = state.confirmed_capacity;
            state.upper_bound = state.upper_bound.max(bare_target_upper.saturating_sub(4));
            state.next_upward_reprobe_at = None;
        }
        None
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkMetrics {
    pub tx_datagrams: u64,
    pub tx_bytes: u64,
    pub rx_datagrams: u64,
    pub rx_bytes: u64,
    pub datagram_max_size: u64,
    pub datagram_queue_drops: u64,
    pub datagram_wire_oversize: u64,
    pub stream_admission_rejections: u64,
    pub datagram_admission_rejections: u64,
    pub forward_queue_drops: u64,
    pub datagram_send_errors: u64,
    pub pmtu_local_oversize: u64,
    pub pmtu_queue_pressure: u64,
    pub pmtu_ack_timeouts: u64,
    pub pmtu_peer_teardowns: u64,
    pub pmtu_protocol_errors: u64,
    pub fec_enabled: bool,
    pub fec_repair_rate_milli: u16,
    pub fec_loss_ppm: u64,
    pub fec_loss_samples: u64,
    pub fec_tx_repairs: u64,
    pub fec_rx_sources: u64,
    pub fec_rx_repairs: u64,
    pub fec_recovered: u64,
    pub fec_lost: u64,
    pub fec_discarded: u64,
    pub fec_rate_limited: u64,
    pub fec_reordered: u64,
    pub fec_invalid: u64,
    pub fec_feedback_sent: u64,
    pub fec_feedback_retries: u64,
}
impl Link {
    pub fn link_id(&self) -> &str {
        &self.link_id
    }
    pub fn instance(&self) -> u64 {
        self.instance
    }
    pub fn lifecycle_token(&self) -> crate::link::LinkToken {
        self.lifecycle_token.clone()
    }
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }
    pub fn set_healthy(&self, healthy: bool) {
        self.carrier_healthy.store(healthy, Ordering::Release);
        self.refresh_health();
    }
    fn refresh_health(&self) {
        let healthy = self.carrier_healthy.load(Ordering::Acquire) && !self.fec.is_data_degraded();
        self.healthy.store(healthy, Ordering::Release);
    }
    pub fn fec_enabled(&self) -> bool {
        self.fec.enabled
    }
    pub fn fec_repair_rate_milli(&self) -> u16 {
        self.fec
            .sender
            .lock()
            .expect("FEC sender lock")
            .rate_milli()
    }
    pub fn take_fec_report(&self) -> Option<crate::fec::FecReport> {
        if self.fec.enabled {
            self.fec.take_report()
        } else {
            None
        }
    }
    pub fn requeue_fec_report(&self, report: crate::fec::FecReport) {
        if self.fec.enabled {
            self.fec.requeue_report(report);
        }
    }

    pub fn take_fec_feedback_worker(self: &Arc<Self>) -> Option<LinkWorker> {
        if !self.fec.enabled || self.fec.feedback_started.swap(true, Ordering::AcqRel) {
            return None;
        }
        let weak = Arc::downgrade(self);
        Some(Box::pin(async move {
            let mut retry_delay = FEC_FEEDBACK_RETRY_INITIAL;
            loop {
                let Some(link) = weak.upgrade() else {
                    return;
                };
                if let Some(report) = link.take_fec_report() {
                    let result = tokio::time::timeout(
                        FEC_FEEDBACK_RETRY_MAX,
                        link.send_control(&crate::control::ControlMessage::FecReport(report)),
                    )
                    .await;
                    if matches!(result, Ok(Ok(()))) {
                        link.fec_feedback_sent.fetch_add(1, Ordering::Relaxed);
                        retry_delay = FEC_FEEDBACK_RETRY_INITIAL;
                        continue;
                    }
                    link.fec_feedback_retries.fetch_add(1, Ordering::Relaxed);
                    link.requeue_fec_report(report);
                    let delay = retry_delay;
                    retry_delay = retry_delay
                        .checked_mul(2)
                        .unwrap_or(FEC_FEEDBACK_RETRY_MAX)
                        .min(FEC_FEEDBACK_RETRY_MAX);
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = link.connection.closed() => return,
                    }
                    continue;
                }
                tokio::select! {
                    _ = link.fec.feedback_notified().notified() => {}
                    _ = link.connection.closed() => return,
                }
            }
        }))
    }

    pub fn take_fec_recovery_worker(self: &Arc<Self>) -> Option<LinkWorker> {
        if !self.fec.enabled || self.fec.recovery_started.swap(true, Ordering::AcqRel) {
            return None;
        }
        let weak = Arc::downgrade(self);
        Some(Box::pin(async move {
            loop {
                let Some(link) = weak.upgrade() else {
                    return;
                };
                if !link.fec.is_data_degraded() {
                    tokio::select! {
                        _ = link.fec.recovery_notified().notified() => {}
                        _ = link.connection.closed() => return,
                    }
                    continue;
                }
                if let Err(error) = link.send_fec_recovery_probe_batch() {
                    if matches!(
                        &error,
                        CarrierError::EndpointClosed | CarrierError::Quinn(_)
                    ) {
                        return;
                    }
                    tracing::debug!(
                        peer_name = %link.peer,
                        peer_identity = %link.peer_identity,
                        error = %error,
                        "FEC recovery probe batch was not fully sent"
                    );
                }
                tokio::select! {
                    _ = tokio::time::sleep(FEC_RECOVERY_PROBE_INTERVAL) => {}
                    _ = link.fec.recovery_notified().notified() => {}
                    _ = link.connection.closed() => return,
                }
            }
        }))
    }

    pub fn take_fec_tail_worker(self: &Arc<Self>) -> Option<LinkWorker> {
        if !self.fec.enabled || self.fec.tail_started.swap(true, Ordering::AcqRel) {
            return None;
        }
        let weak = Arc::downgrade(self);
        Some(Box::pin(async move {
            let mut retry_delay = FEC_TAIL_RETRY_INITIAL;
            loop {
                let Some(link) = weak.upgrade() else {
                    return;
                };
                let notified = link.fec.tail_notified().notified();
                if !link.fec.tail_pending.load(Ordering::Acquire) {
                    tokio::select! {
                        _ = notified => {}
                        _ = link.connection.closed() => return,
                    }
                    continue;
                }

                let generation = link.fec.tail_generation.load(Ordering::Acquire);
                let elapsed = Duration::from_millis(
                    monotonic_millis()
                        .saturating_sub(link.fec.last_source_millis.load(Ordering::Acquire)),
                );
                let remaining = FEC_TAIL_IDLE_DELAY.saturating_sub(elapsed);
                let result = tokio::select! {
                    _ = notified => None,
                    _ = tokio::time::sleep(remaining) => {
                        (link.fec.tail_generation.load(Ordering::Acquire) == generation
                            && link.fec.tail_due())
                            .then(|| link.send_fec_tail())
                    }
                    _ = link.connection.closed() => return,
                };
                if let Some(result) = result {
                    match result {
                        Ok(()) => {
                            if link.fec.tail_pending.load(Ordering::Acquire) {
                                let delay = retry_delay;
                                retry_delay = retry_delay
                                    .checked_mul(2)
                                    .unwrap_or(FEC_TAIL_RETRY_MAX)
                                    .min(FEC_TAIL_RETRY_MAX);
                                tokio::select! {
                                    _ = tokio::time::sleep(delay) => {}
                                    _ = link.fec.tail_notified().notified() => {}
                                    _ = link.connection.closed() => return,
                                }
                            } else {
                                retry_delay = FEC_TAIL_RETRY_INITIAL;
                            }
                        }
                        Err(error) => {
                            tracing::debug!(
                                peer_name = %link.peer,
                                peer_identity = %link.peer_identity,
                                error = %error,
                                "FEC tail repair worker stopped"
                            );
                            return;
                        }
                    }
                }
            }
        }))
    }

    fn send_fec_tail(&self) -> Result<(), CarrierError> {
        self.fec.send_tail_batch(|repair| {
            self.send_physical(PhysicalPayload::FecRepair {
                transmission_sequence: repair.transmission_sequence,
                rid: repair.rid,
                first_esi: repair.first_esi,
                symbol_count: repair.symbol_count,
                vector: repair.vector,
            })
        })
    }

    fn send_fec_source_batch(&self, frame: &[u8]) -> Result<(), CarrierError> {
        self.fec.send_source_batch(
            frame,
            |source| {
                self.send_physical(PhysicalPayload::FecSource {
                    transmission_sequence: source.transmission_sequence,
                    esi: source.esi,
                    frame: source.frame,
                })
            },
            |repair| {
                self.send_physical(PhysicalPayload::FecRepair {
                    transmission_sequence: repair.transmission_sequence,
                    rid: repair.rid,
                    first_esi: repair.first_esi,
                    symbol_count: repair.symbol_count,
                    vector: repair.vector,
                })
            },
        )
    }

    fn send_fec_recovery_probe_batch(&self) -> Result<(), CarrierError> {
        let frame = crate::fec::recovery_probe_frame();
        for _ in 0..FEC_RECOVERY_PROBE_BATCH_SIZE {
            self.send_fec_source_batch(&frame)?;
        }
        Ok(())
    }
    pub fn apply_fec_report(&self, report: crate::fec::FecReport) -> FecReportHealth {
        if !self.fec.enabled {
            return FecReportHealth::Unchanged;
        }
        let health = self.fec.apply_report(report);
        if !matches!(health, FecReportHealth::Unchanged) {
            self.refresh_health();
        }
        health
    }
    /// A Link becomes eligible for topology-derived routing only after the
    /// current epoch has completed both directions of RFC-0016's initial
    /// Snapshot exchange.
    pub fn topology_ready(&self) -> bool {
        self.topology_inbound_synced.load(Ordering::Acquire)
            && self.topology_outbound_acked.load(Ordering::Acquire)
    }
    pub fn mark_topology_snapshot_received(&self) -> bool {
        self.topology_inbound_synced.store(true, Ordering::Release);
        self.topology_ready()
    }
    pub fn mark_topology_snapshot_acknowledged(&self) -> bool {
        self.topology_outbound_acked.store(true, Ordering::Release);
        self.topology_ready()
    }
    pub fn mark_topology_inbound_unsynchronized(&self) {
        self.topology_inbound_synced.store(false, Ordering::Release);
    }
    pub fn mark_topology_outbound_unsynchronized(&self) {
        self.topology_outbound_acked.store(false, Ordering::Release);
    }
    pub fn mark_topology_unsynchronized(&self) {
        self.mark_topology_inbound_unsynchronized();
        self.mark_topology_outbound_unsynchronized();
    }
    /// Queue only the newest LSA for each origin while this Link is
    /// synchronizing. The control handler flushes it after TopologyReady, so
    /// a Delta can never overtake the Snapshot that must establish the epoch.
    pub async fn queue_topology_deltas(&self, advertisements: Vec<LinkStateAdvertisement>) -> bool {
        self.topology_delta_outbox
            .lock()
            .await
            .enqueue(advertisements)
    }
    pub async fn take_topology_deltas(&self) -> Vec<LinkStateAdvertisement> {
        self.topology_delta_outbox.lock().await.take()
    }
    pub async fn clear_topology_deltas(&self) {
        self.topology_delta_outbox.lock().await.take();
    }
    fn send_datagram(&self, payload: Vec<u8>) -> Result<(), CarrierError> {
        let bytes = payload.len() as u64;
        let size = payload.len();
        let limit = self.max_datagram_size();
        if let Some(limit) = limit
            && size > limit
        {
            self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
            return Err(CarrierError::DatagramTooLarge { size, limit });
        }
        let result = self
            .connection
            .send_datagram(payload.into())
            .map_err(|error| {
                classify_quic_datagram_error(error, size, self.max_datagram_size().or(limit))
            });
        if matches!(result, Err(CarrierError::DatagramTooLarge { .. })) {
            self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
        }
        if let Err(error) = result {
            self.tx_errors.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        self.tx_datagrams.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }

    /// Returns the carrier-local payload capacity for one sealed Physical
    /// frame. For full QUIC this is Quinn's application DATAGRAM limit (not
    /// its DPLPMTUD path-payload limit); for bare UDP it is the Physical-frame
    /// limit after removing the receive-id header. The caller still adds the
    /// receive-id when checking bare wire length.
    pub fn max_datagram_size(&self) -> Option<usize> {
        match &self.carrier {
            LinkCarrier::Quic => self.connection.max_datagram_size(),
            LinkCarrier::BareUdp { .. } => Some(self.bare_mtu.load(Ordering::Relaxed) as usize),
        }
    }

    pub fn subscribe_capacity_changed(&self) -> broadcast::Receiver<LinkCapacityChanged> {
        self.capacity_events.subscribe()
    }

    fn publish_capacity_changed(
        &self,
        physical_capacity: u16,
        capacity_generation: u64,
        reason: CapacityChangeReason,
    ) {
        let _ = self.capacity_events.send(LinkCapacityChanged {
            link_instance: self.instance,
            user_ip_capacity: u16::try_from(user_ip_capacity_from_physical_with_fec(
                usize::from(physical_capacity),
                self.fec.enabled,
            ))
            .expect("user IP capacity fits in u16"),
            capacity_generation,
            reason,
        });
    }

    fn record_pmtu_failure(&self, reason: PmtuFailureReason) {
        let counter = match reason {
            PmtuFailureReason::LocalOversize => &self.pmtu_local_oversize,
            PmtuFailureReason::QueuePressure => &self.pmtu_queue_pressure,
            PmtuFailureReason::AckTimeout => &self.pmtu_ack_timeouts,
            PmtuFailureReason::PeerTeardown => &self.pmtu_peer_teardowns,
            PmtuFailureReason::Protocol => &self.pmtu_protocol_errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the locally confirmed user IP capacity and semantic version.
    /// Full QUIC carriers delegate path discovery to Quinn and treat its
    /// application DATAGRAM limit as the Physical-frame capacity. Bare
    /// carriers publish the confirmed Physical-frame probe after removing the
    /// receive-id header. Both paths normalize to complete user IP bytes here.
    pub fn confirmed_user_ip_capacity(&self) -> Option<(u16, u64)> {
        match &self.carrier {
            LinkCarrier::Quic => {
                let physical_capacity = self
                    .max_datagram_size()
                    .and_then(|capacity| u16::try_from(capacity).ok())?;
                let previous = self
                    .quic_observed_capacity
                    .swap(u64::from(physical_capacity), Ordering::AcqRel);
                let generation = if previous != 0 && previous != u64::from(physical_capacity) {
                    self.quic_capacity_generation
                        .fetch_add(1, Ordering::AcqRel)
                        .saturating_add(1)
                } else {
                    self.quic_capacity_generation.load(Ordering::Acquire)
                };
                if previous != 0 && previous != u64::from(physical_capacity) {
                    self.publish_capacity_changed(
                        physical_capacity,
                        generation,
                        CapacityChangeReason::QuicDplpmtud,
                    );
                }
                Some((
                    u16::try_from(user_ip_capacity_from_physical_with_fec(
                        usize::from(physical_capacity),
                        self.fec.enabled,
                    ))
                    .expect("user IP capacity fits in u16"),
                    generation,
                ))
            }
            LinkCarrier::BareUdp { .. } => {
                let state = self.pmtu.lock().expect("pmtu lock");
                Some((
                    u16::try_from(user_ip_capacity_from_physical_with_fec(
                        usize::from(state.confirmed_capacity),
                        self.fec.enabled,
                    ))
                    .expect("user IP capacity fits in u16"),
                    state.capacity_generation,
                ))
            }
        }
    }

    /// Quinn exposes DPLPMTUD changes through a polled DATAGRAM limit.  Keep
    /// the local capacity event path independent from topology/route refresh
    /// cadence by polling that limit with a weak Link reference.
    pub fn take_capacity_monitor(self: &Arc<Self>) -> Option<LinkWorker> {
        if !matches!(self.carrier, LinkCarrier::Quic)
            || self.capacity_monitor_started.swap(true, Ordering::AcqRel)
        {
            return None;
        }
        let weak = Arc::downgrade(self);
        let cancellation = self.pmtu_cancel.clone();
        Some(Box::pin(async move {
            loop {
                let Some(link) = weak.upgrade() else { return };
                let _ = link.confirmed_user_ip_capacity();
                drop(link);
                tokio::select! {
                    _ = cancellation.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }))
    }

    /// Start the RFC-0014 authenticated binary-search probe loop. The PMTU
    /// state remains in Physical-frame units internally; Link capacity
    /// publication converts it to complete user IP bytes, while the four-byte
    /// bare receive-id header is only added on the wire.
    pub fn take_bare_pmtu_worker(self: &Arc<Self>) -> Option<LinkWorker> {
        if !matches!(self.carrier, LinkCarrier::BareUdp { .. }) {
            return None;
        }
        if self.pmtu_started.swap(true, Ordering::AcqRel) {
            return None;
        }
        let weak = Arc::downgrade(self);
        let cancellation = self.pmtu_cancel.clone();
        Some(Box::pin(async move {
            loop {
                let Some(link) = weak.upgrade() else { return };
                let target = {
                    let state = link.pmtu.lock().expect("pmtu lock");
                    Some(if state.confirmed_capacity < state.upper_bound {
                        // A downward failure keeps the historical lower
                        // bound for future recovery, but that bound may now
                        // be below the current confirmed capacity.  Never
                        // probe below confirmed: doing so would make the
                        // binary search repeat a smaller, already-known
                        // value forever instead of testing recovery above it.
                        let lower_bound = state.lower_bound.max(state.confirmed_capacity);
                        lower_bound.saturating_add(
                            state
                                .upper_bound
                                .saturating_sub(lower_bound)
                                .saturating_add(1)
                                / 2,
                        )
                    } else if state.confirmed_capacity >= state.safe_capacity {
                        // Downward checks have a short cadence.  They are
                        // intentionally separate from the long upward
                        // hysteresis so a carrier failure tightens the
                        // software budget promptly.  Keep probing at the
                        // safe floor too: once a path recovers, the success
                        // branch below reopens the upward search window.
                        state.confirmed_capacity
                    } else {
                        0
                    })
                };
                let Some(target) = target.filter(|target| *target > 0) else {
                    tokio::select! {
                        _ = cancellation.cancelled() => return,
                        _ = link.connection.closed() => return,
                        _ = tokio::time::sleep(Duration::from_secs(600)) => {}
                    }
                    continue;
                };

                let mut succeeded = false;
                for _ in 0..3 {
                    let mut id = [0; 8];
                    getrandom::fill(&mut id).expect("OS random source unavailable");
                    let probe_id = u64::from_be_bytes(id);
                    let attempt_id = {
                        let mut state = link.pmtu.lock().expect("pmtu lock");
                        state.next_attempt_id = state.next_attempt_id.saturating_add(1).max(1);
                        let attempt_id = state.next_attempt_id;
                        state.active = Some(ProbeInFlight {
                            attempt_id,
                            probe_id,
                            target,
                            deadline: Instant::now() + Duration::from_secs(3),
                            acknowledged: false,
                        });
                        attempt_id
                    };
                    let target_len = target.saturating_add(4);
                    let padding = vec![0; usize::from(target_len).saturating_sub(39)];
                    let send_result = link.send_physical(PhysicalPayload::Probe {
                        probe_id,
                        target_len,
                        padding,
                    });
                    if let Err(error) = &send_result {
                        link.record_pmtu_failure(classify_pmtu_failure(error));
                    }
                    if send_result.is_ok() {
                        tokio::select! {
                            _ = cancellation.cancelled() => return,
                            _ = link.connection.closed() => return,
                            _ = link.pmtu_notify.notified() => {}
                            _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                        }
                    }
                    let mut state = link.pmtu.lock().expect("pmtu lock");
                    succeeded = send_result.is_ok()
                        && state.active.as_ref().is_some_and(|active| {
                            active.attempt_id == attempt_id && active.acknowledged
                        });
                    let failure_reason = if succeeded {
                        None
                    } else if let Err(error) = &send_result {
                        Some(classify_pmtu_failure(error))
                    } else {
                        Some(PmtuFailureReason::AckTimeout)
                    };
                    if let Some(reason) = failure_reason {
                        if matches!(reason, PmtuFailureReason::AckTimeout) && send_result.is_ok() {
                            link.record_pmtu_failure(reason);
                        }
                        if state
                            .active
                            .as_ref()
                            .is_some_and(|active| active.attempt_id == attempt_id)
                        {
                            state.active = None;
                        }
                        if !pmtu_should_retry_candidate(failure_reason) {
                            if let Some((capacity, generation)) =
                                tighten_pmtu_after_failure(&mut state, target, Instant::now())
                            {
                                link.bare_mtu.store(u64::from(capacity), Ordering::Release);
                                link.publish_capacity_changed(
                                    capacity,
                                    generation,
                                    CapacityChangeReason::ProbeDecreased,
                                );
                            }
                            break;
                        }
                        if !matches!(
                            reason,
                            PmtuFailureReason::LocalOversize | PmtuFailureReason::AckTimeout
                        ) {
                            state.consecutive_successes = 0;
                            state.consecutive_failures = 0;
                            if matches!(reason, PmtuFailureReason::PeerTeardown) {
                                // Do not keep the Link alive while a closed
                                // carrier is being retried. Returning drops
                                // the task's temporary strong reference; the
                                // Link destructor then cancels this worker.
                                drop(state);
                                drop(link);
                                return;
                            }
                            continue;
                        }
                    }
                    if state
                        .active
                        .as_ref()
                        .is_some_and(|active| active.attempt_id == attempt_id)
                    {
                        state.active = None;
                    }
                    if succeeded {
                        if let Some((capacity, generation)) = apply_pmtu_success(
                            &mut state,
                            target,
                            link.bare_target_upper,
                            Instant::now(),
                        ) {
                            link.bare_mtu.store(u64::from(capacity), Ordering::Release);
                            link.publish_capacity_changed(
                                capacity,
                                generation,
                                CapacityChangeReason::ProbeConfirmed,
                            );
                        }
                        break;
                    }
                    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                    state.consecutive_successes = 0;
                    if let Some((capacity, generation)) =
                        tighten_pmtu_after_failure(&mut state, target, Instant::now())
                    {
                        link.bare_mtu.store(u64::from(capacity), Ordering::Release);
                        link.publish_capacity_changed(
                            capacity,
                            generation,
                            CapacityChangeReason::ProbeDecreased,
                        );
                    }
                }
                if !succeeded {
                    let mut state = link.pmtu.lock().expect("pmtu lock");
                    state.upper_bound = state.upper_bound.max(state.confirmed_capacity);
                }
                let short_cooldown = {
                    let state = link.pmtu.lock().expect("pmtu lock");
                    target == state.confirmed_capacity
                };
                tokio::select! {
                    _ = cancellation.cancelled() => return,
                    _ = link.connection.closed() => return,
                    _ = tokio::time::sleep(if short_cooldown {
                        Duration::from_secs(5)
                    } else {
                        Duration::from_millis(50)
                    }) => {}
                }
            }
        }))
    }
    pub async fn recv_datagram(&self) -> Result<impl AsRef<[u8]>, CarrierError> {
        // Quinn already returns an owned `Bytes`. Keep that ownership through
        // physical AEAD parsing instead of copying every DATAGRAM into a new
        // Vec before the frame is authenticated.
        let packet = self.connection.read_datagram().await?;
        self.rx_datagrams.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        Ok(packet)
    }
    /// Seal and transmit a versioned physical-link payload. All overlay
    /// DATAGRAM users must use this rather than raw QUIC DATAGRAMs.
    pub fn send_physical(&self, payload: PhysicalPayload) -> Result<(), CarrierError> {
        if let PhysicalPayload::Forward(frame) = &payload {
            return self.send_forward(frame);
        }
        if matches!(
            &payload,
            PhysicalPayload::FecSource { .. } | PhysicalPayload::FecRepair { .. }
        ) && !self.fec.enabled
        {
            return Err(CarrierError::Protocol(
                "FEC payload on a Link without negotiated FEC".into(),
            ));
        }
        // Perform a side-effect-free size check before priority admission,
        // sealing, and PhysicalSession sequence allocation.  The check is
        // intentionally repeated after sealing below: PMTU can change between
        // these two operations, and the final carrier check is authoritative.
        match self.preflight_wire_size(&payload) {
            Ok(()) => {}
            Err(error @ CarrierError::DatagramTooLarge { .. }) => {
                self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        let class = match payload {
            PhysicalPayload::Probe { .. } | PhysicalPayload::ProbeAck { .. } => PriorityClass::D0,
            PhysicalPayload::Keepalive => PriorityClass::D1,
            PhysicalPayload::FecSource { .. }
            | PhysicalPayload::FecRepair { .. }
            | PhysicalPayload::Forward(_) => PriorityClass::D2,
        };
        if !self.priority.try_admit_datagram(class) {
            self.tx_queue_drops.fetch_add(1, Ordering::Relaxed);
            self.datagram_admission_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(CarrierError::AdmissionRejected);
        }
        let frame = self
            .physical
            .seal(&payload)
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        match &self.carrier {
            LinkCarrier::Quic => self.send_datagram(frame)?,
            LinkCarrier::BareUdp {
                socket,
                remote,
                destination_receive_id,
                ..
            } => {
                let mut wire = Vec::with_capacity(frame.len() + 4);
                wire.push(frame[0]);
                wire.extend_from_slice(&destination_receive_id.to_be_bytes());
                wire.extend_from_slice(&frame[1..]);
                let wire_limit = match &payload {
                    PhysicalPayload::Probe { target_len, .. } => {
                        let target_len = usize::from(*target_len);
                        if target_len < 39 || target_len > usize::from(self.bare_target_upper) {
                            return Err(CarrierError::Protocol(
                                "PMTU probe target is outside the link bounds".into(),
                            ));
                        }
                        if wire.len() != target_len {
                            return Err(CarrierError::Protocol(
                                "PMTU probe length does not match target".into(),
                            ));
                        }
                        usize::from(self.bare_target_upper)
                    }
                    _ => self
                        .max_datagram_size()
                        .map(|size| size.saturating_add(4))
                        .unwrap_or(usize::MAX),
                };
                if wire.len() > wire_limit {
                    self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
                    return Err(CarrierError::DatagramTooLarge {
                        size: wire.len(),
                        limit: wire_limit,
                    });
                }
                match socket.send(*remote, &wire) {
                    Ok(_) => {}
                    Err(CarrierError::LocalIo(errno)) if is_local_oversize_errno(errno) => {
                        self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
                        return Err(CarrierError::DatagramTooLarge {
                            size: wire.len(),
                            limit: self
                                .max_datagram_size()
                                .map(|size| size.saturating_add(4))
                                .unwrap_or(usize::MAX),
                        });
                    }
                    Err(CarrierError::Protocol(message)) if is_local_oversize_message(&message) => {
                        self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
                        return Err(CarrierError::DatagramTooLarge {
                            size: wire.len(),
                            limit: self
                                .max_datagram_size()
                                .map(|size| size.saturating_add(4))
                                .unwrap_or(usize::MAX),
                        });
                    }
                    Err(CarrierError::LocalIo(errno)) if is_local_backpressure_errno(errno) => {
                        return Err(CarrierError::AdmissionRejected);
                    }
                    Err(error) => return Err(error),
                }

                self.tx_datagrams.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes
                    .fetch_add(wire.len() as u64, Ordering::Relaxed);
            }
        }
        self.last_tx_millis
            .store(monotonic_millis(), Ordering::Relaxed);
        if matches!(&payload, PhysicalPayload::FecRepair { .. }) {
            self.fec_tx_repairs.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn preflight_wire_size(&self, payload: &PhysicalPayload) -> Result<(), CarrierError> {
        let physical_len = payload
            .wire_len()
            .map_err(|error| CarrierError::Protocol(error.to_string()))?;
        let wire_limit = match (&self.carrier, payload) {
            (LinkCarrier::Quic, _) => self.max_datagram_size().unwrap_or(usize::MAX),
            (LinkCarrier::BareUdp { .. }, PhysicalPayload::Probe { target_len, .. }) => {
                let target_len = usize::from(*target_len);
                if target_len < 39 || target_len > usize::from(self.bare_target_upper) {
                    return Err(CarrierError::Protocol(
                        "PMTU probe target is outside the link bounds".into(),
                    ));
                }
                let wire_len = physical_len.saturating_add(4);
                if wire_len != target_len {
                    return Err(CarrierError::Protocol(
                        "PMTU probe length does not match target".into(),
                    ));
                }
                usize::from(self.bare_target_upper)
            }
            (LinkCarrier::BareUdp { .. }, _) => self
                .max_datagram_size()
                .map(|size| size.saturating_add(4))
                .unwrap_or(usize::MAX),
        };
        let wire_len = if matches!(self.carrier, LinkCarrier::BareUdp { .. }) {
            physical_len.saturating_add(4)
        } else {
            physical_len
        };
        if wire_len > wire_limit {
            return Err(CarrierError::DatagramTooLarge {
                size: wire_len,
                limit: wire_limit,
            });
        }
        Ok(())
    }

    async fn enqueue_fec_frames(&self, frames: impl IntoIterator<Item = Vec<u8>>) {
        let dropped = {
            let mut queue = self.fec_ready.lock().await;
            enqueue_bounded_fec_frames(&mut queue, frames)
        };
        if dropped != 0 {
            self.record_forward_queue_drop(dropped as u64);
        }
    }

    /// Receive and authenticate one physical payload. Invalid frames are
    /// dropped and never refresh link liveness; only a carrier failure is
    /// returned to the caller so a forged frame cannot stop its receiver.
    pub async fn recv_physical(&self) -> Result<PhysicalPayload, CarrierError> {
        loop {
            if let Some(frame) = self.fec_ready.lock().await.pop_front() {
                return Ok(PhysicalPayload::Forward(frame));
            }
            let (opened, bare_wire_len) = match &self.carrier {
                LinkCarrier::Quic => {
                    // Quinn returns an owned Bytes buffer. Authenticate it
                    // directly instead of copying it into a Vec before
                    // PhysicalSession reconstructs the forward frame.
                    let frame = self.recv_datagram().await?;
                    (self.physical.open(frame.as_ref()), None)
                }
                LinkCarrier::BareUdp {
                    remote, receiver, ..
                } => {
                    let mut receiver = receiver.lock().await;
                    let datagram = tokio::select! {
                        _ = self.connection.closed() => return Err(CarrierError::EndpointClosed),
                        datagram = receiver.recv() => {
                            datagram.ok_or(CarrierError::EndpointClosed)?
                        }
                    };
                    if datagram.source != *remote || datagram.frame.len() < 5 {
                        continue;
                    }
                    let wire_len = datagram.frame.len();
                    let mut frame = Vec::with_capacity(datagram.frame.len() - 4);
                    frame.push(datagram.frame[0]);
                    frame.extend_from_slice(&datagram.frame[5..]);
                    self.rx_datagrams.fetch_add(1, Ordering::Relaxed);
                    self.rx_bytes
                        .fetch_add(datagram.frame.len() as u64, Ordering::Relaxed);
                    (self.physical.open(&frame), Some(wire_len))
                }
            };
            match opened {
                Ok(payload) => {
                    // Every authenticated physical payload proves that the
                    // carrier is alive, including PMTU probes and their
                    // acknowledgements.  PMTU probing is periodic and can
                    // legitimately suppress the ordinary Keepalive sender;
                    // excluding these forms here would therefore make two
                    // otherwise healthy links self-expire at the idle
                    // deadline while they are actively probing.
                    self.last_rx_millis
                        .store(monotonic_millis(), Ordering::Relaxed);
                    match &payload {
                        PhysicalPayload::Probe {
                            probe_id,
                            target_len,
                            ..
                        } if bare_wire_len.is_some() => {
                            let valid = *target_len >= 39
                                && *target_len <= self.bare_target_upper
                                && bare_wire_len == Some(usize::from(*target_len));
                            if valid {
                                match self.send_physical(PhysicalPayload::ProbeAck {
                                    probe_id: *probe_id,
                                    target_len: *target_len,
                                }) {
                                    Ok(()) | Err(CarrierError::AdmissionRejected) => {
                                        // A D0 admission miss is local, transient backpressure.
                                        // Dropping this acknowledgement lets the probing peer retry;
                                        // it must not stop the sole physical receiver for this Link.
                                    }
                                    Err(error) => return Err(error),
                                }
                            }
                            continue;
                        }
                        PhysicalPayload::ProbeAck {
                            probe_id,
                            target_len,
                        } if bare_wire_len.is_some() => {
                            let mut state = self.pmtu.lock().expect("pmtu lock");
                            if let Some(active) = &mut state.active
                                && active.probe_id == *probe_id
                                && active.target.saturating_add(4) == *target_len
                                && Instant::now() <= active.deadline
                            {
                                active.acknowledged = true;
                                self.pmtu_notify.notify_one();
                            }
                            continue;
                        }
                        PhysicalPayload::Probe { .. } | PhysicalPayload::ProbeAck { .. } => {
                            continue;
                        }
                        PhysicalPayload::FecSource {
                            transmission_sequence,
                            esi,
                            frame,
                        } => {
                            if !self.fec.enabled {
                                self.fec_invalid.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            match self.fec.receive_source(*transmission_sequence, *esi, frame) {
                                Ok(delivery) => {
                                    self.record_fec_delivery(&delivery);
                                    self.fec_reordered
                                        .store(self.fec.reordered(), Ordering::Relaxed);
                                    self.enqueue_fec_frames(
                                        delivery.frames.into_iter().map(|item| item.frame),
                                    )
                                    .await;
                                }
                                Err(_) => {
                                    self.fec_invalid.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if let Some(frame) = self.fec_ready.lock().await.pop_front() {
                                return Ok(PhysicalPayload::Forward(frame));
                            }
                            continue;
                        }
                        PhysicalPayload::FecRepair {
                            transmission_sequence,
                            rid,
                            first_esi,
                            symbol_count,
                            vector,
                        } => {
                            if !self.fec.enabled {
                                self.fec_invalid.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            self.fec_rx_repairs.fetch_add(1, Ordering::Relaxed);
                            match self.fec.receive_repair(
                                *transmission_sequence,
                                *rid,
                                *first_esi,
                                *symbol_count,
                                vector,
                            ) {
                                Ok(RepairReceive::Accepted(delivery)) => {
                                    self.record_fec_delivery(&delivery);
                                    self.fec_reordered
                                        .store(self.fec.reordered(), Ordering::Relaxed);
                                    self.enqueue_fec_frames(
                                        delivery.frames.into_iter().map(|item| item.frame),
                                    )
                                    .await;
                                }
                                Ok(RepairReceive::Discarded) => {
                                    self.fec_discarded.fetch_add(1, Ordering::Relaxed);
                                    self.fec_reordered
                                        .store(self.fec.reordered(), Ordering::Relaxed);
                                }
                                Ok(RepairReceive::RateLimited) => {
                                    self.fec_rate_limited.fetch_add(1, Ordering::Relaxed);
                                    self.fec_reordered
                                        .store(self.fec.reordered(), Ordering::Relaxed);
                                }
                                Err(_) => {
                                    self.fec_invalid.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if let Some(frame) = self.fec_ready.lock().await.pop_front() {
                                return Ok(PhysicalPayload::Forward(frame));
                            }
                            continue;
                        }
                        _ => {}
                    }
                    return Ok(payload);
                }
                Err(error) => {
                    if self.should_log_dataplane_warning() {
                        tracing::warn!(
                            peer_name = %self.peer,
                            peer_identity = %self.peer_identity,
                            error = %error,
                            "physical payload rejected (further rejections are rate-limited)"
                        );
                    }
                }
            }
        }
    }

    fn record_fec_delivery(&self, delivery: &crate::fec::Delivery) {
        if delivery.discarded {
            self.fec_discarded.fetch_add(1, Ordering::Relaxed);
        }
        self.fec_lost
            .fetch_add(delivery.lost.len() as u64, Ordering::Relaxed);
        for frame in &delivery.frames {
            match frame.origin {
                crate::fec::DeliveryOrigin::Source => {
                    self.fec_rx_sources.fetch_add(1, Ordering::Relaxed);
                }
                crate::fec::DeliveryOrigin::Recovered => {
                    self.fec_recovered.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Seal and transmit an existing end-to-end encrypted forward frame.
    ///
    /// The caller retains ownership, which is important for sender retries and
    /// broadcast subscribers: physical forwarding never needs a separate
    /// owned copy of the input frame.
    pub fn send_forward(&self, frame: &[u8]) -> Result<(), CarrierError> {
        if self.fec.enabled {
            return self.send_fec_source_batch(frame);
        }
        let physical_len = crate::physical::FORWARD_OVERHEAD.saturating_add(frame.len());
        if frame.len() < crate::crypto::FRAME_OVERHEAD {
            return Err(CarrierError::Protocol(
                "physical payload is truncated".into(),
            ));
        }
        let wire_len = if matches!(self.carrier, LinkCarrier::BareUdp { .. }) {
            physical_len.saturating_add(4)
        } else {
            physical_len
        };
        let wire_limit = self
            .max_datagram_size()
            .map(|size| {
                if matches!(self.carrier, LinkCarrier::BareUdp { .. }) {
                    size.saturating_add(4)
                } else {
                    size
                }
            })
            .unwrap_or(usize::MAX);
        if wire_len > wire_limit {
            self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
            return Err(CarrierError::DatagramTooLarge {
                size: wire_len,
                limit: wire_limit,
            });
        }
        if !self.priority.try_admit_datagram(PriorityClass::D2) {
            self.tx_queue_drops.fetch_add(1, Ordering::Relaxed);
            self.datagram_admission_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(CarrierError::AdmissionRejected);
        }
        let frame = self
            .physical
            .seal_forward(frame)
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        let sent = match &self.carrier {
            LinkCarrier::Quic => self.send_datagram(frame),
            LinkCarrier::BareUdp {
                socket,
                remote,
                destination_receive_id,
                ..
            } => {
                let mut wire = Vec::with_capacity(frame.len() + 4);
                wire.push(frame[0]);
                wire.extend_from_slice(&destination_receive_id.to_be_bytes());
                wire.extend_from_slice(&frame[1..]);
                match socket.send(*remote, &wire) {
                    Ok(_) => {
                        self.tx_datagrams.fetch_add(1, Ordering::Relaxed);
                        self.tx_bytes
                            .fetch_add(wire.len() as u64, Ordering::Relaxed);
                        Ok(())
                    }
                    Err(CarrierError::LocalIo(errno)) if is_local_oversize_errno(errno) => {
                        self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
                        Err(CarrierError::DatagramTooLarge {
                            size: wire.len(),
                            limit: wire_limit,
                        })
                    }
                    Err(CarrierError::Protocol(message)) if is_local_oversize_message(&message) => {
                        self.datagram_wire_oversize.fetch_add(1, Ordering::Relaxed);
                        Err(CarrierError::DatagramTooLarge {
                            size: wire.len(),
                            limit: wire_limit,
                        })
                    }
                    Err(CarrierError::LocalIo(errno)) if is_local_backpressure_errno(errno) => {
                        Err(CarrierError::AdmissionRejected)
                    }
                    Err(error) => Err(error),
                }
            }
        };
        if sent.is_ok() {
            self.last_tx_millis
                .store(monotonic_millis(), Ordering::Relaxed);
        }
        sent
    }
    /// Claim the sole Forward consumer for this Link. The physical receiver
    /// starts immediately after authentication, but data-plane ownership is
    /// explicit and cannot accidentally become a broadcast fanout.
    pub async fn take_forward_receiver(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.forward_receiver.lock().await.take()
    }
    pub fn publish_forward(&self, frame: Vec<u8>) {
        if self.forward_payloads.try_send(frame).is_err() {
            self.record_forward_queue_drop(1);
        }
    }
    /// Record payloads skipped by a bounded forward subscriber queue.
    pub fn record_forward_queue_drop(&self, skipped: u64) {
        self.forward_queue_drops
            .fetch_add(skipped, Ordering::Relaxed);
    }
    pub fn tx_idle_for(&self) -> Duration {
        Duration::from_millis(
            monotonic_millis().saturating_sub(self.last_tx_millis.load(Ordering::Relaxed)),
        )
    }
    pub fn rx_idle_for(&self) -> Duration {
        Duration::from_millis(
            monotonic_millis().saturating_sub(self.last_rx_millis.load(Ordering::Relaxed)),
        )
    }

    pub fn should_log_dataplane_warning(&self) -> bool {
        let now = monotonic_millis() / 1_000;
        let mut previous = self.last_dataplane_warning_second.load(Ordering::Relaxed);
        loop {
            if previous == now {
                return false;
            }
            match self.last_dataplane_warning_second.compare_exchange_weak(
                previous,
                now,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => previous = observed,
            }
        }
    }
    pub fn metrics(&self) -> LinkMetrics {
        let (fec_loss_ppm, fec_loss_samples) = self.fec.loss_metrics();
        LinkMetrics {
            tx_datagrams: self.tx_datagrams.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_datagrams: self.rx_datagrams.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            datagram_max_size: self.max_datagram_size().unwrap_or_default() as u64,
            datagram_queue_drops: self.tx_queue_drops.load(Ordering::Relaxed),
            datagram_wire_oversize: self.datagram_wire_oversize.load(Ordering::Relaxed),
            stream_admission_rejections: self.stream_admission_rejections.load(Ordering::Relaxed),
            datagram_admission_rejections: self
                .datagram_admission_rejections
                .load(Ordering::Relaxed),
            forward_queue_drops: self.forward_queue_drops.load(Ordering::Relaxed),
            datagram_send_errors: self.tx_errors.load(Ordering::Relaxed),
            pmtu_local_oversize: self.pmtu_local_oversize.load(Ordering::Relaxed),
            pmtu_queue_pressure: self.pmtu_queue_pressure.load(Ordering::Relaxed),
            pmtu_ack_timeouts: self.pmtu_ack_timeouts.load(Ordering::Relaxed),
            pmtu_peer_teardowns: self.pmtu_peer_teardowns.load(Ordering::Relaxed),
            pmtu_protocol_errors: self.pmtu_protocol_errors.load(Ordering::Relaxed),
            fec_enabled: self.fec.enabled,
            fec_repair_rate_milli: self.fec_repair_rate_milli(),
            fec_loss_ppm,
            fec_loss_samples,
            fec_tx_repairs: self.fec_tx_repairs.load(Ordering::Relaxed),
            fec_rx_sources: self.fec_rx_sources.load(Ordering::Relaxed),
            fec_rx_repairs: self.fec_rx_repairs.load(Ordering::Relaxed),
            fec_recovered: self.fec_recovered.load(Ordering::Relaxed),
            fec_lost: self.fec_lost.load(Ordering::Relaxed),
            fec_discarded: self.fec_discarded.load(Ordering::Relaxed),
            fec_rate_limited: self.fec_rate_limited.load(Ordering::Relaxed),
            fec_reordered: self.fec_reordered.load(Ordering::Relaxed),
            fec_invalid: self.fec_invalid.load(Ordering::Relaxed),
            fec_feedback_sent: self.fec_feedback_sent.load(Ordering::Relaxed),
            fec_feedback_retries: self.fec_feedback_retries.load(Ordering::Relaxed),
        }
    }
    pub async fn send_control(
        &self,
        message: &crate::control::ControlMessage,
    ) -> Result<(), CarrierError> {
        let class = match message {
            crate::control::ControlMessage::TopologySync { .. }
            | crate::control::ControlMessage::TopologySyncAck { .. }
            | crate::control::ControlMessage::TopologySyncRequest { .. } => PriorityClass::S1,
            _ => PriorityClass::S0,
        };
        let encoded = message
            .encode()
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        let admitted = tokio::select! {
            admitted = self.priority.admit_stream(class, encoded.len()) => admitted,
            _ = self.connection.closed() => return Err(CarrierError::EndpointClosed),
        };
        if !admitted {
            self.stream_admission_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(CarrierError::AdmissionRejected);
        }
        let recovery = matches!(
            message,
            crate::control::ControlMessage::TopologySyncAck { .. }
                | crate::control::ControlMessage::TopologySyncRequest { .. }
        );
        let semaphore = if recovery {
            &self.recovery_stream_writers
        } else if matches!(class, PriorityClass::S0) {
            &self.s0_stream_writers
        } else {
            &self.s1_stream_writers
        };
        // The RFC-0017 gate has already handed this message to the selected
        // writer class.  Waiting for that class's bounded writer slot is
        // therefore control-plane backpressure, not a reason to drop S0 or
        // S1.  Cancellation by connection close keeps a Link replacement
        // from leaving a sender parked on a superseded connection forever.
        let _writer = tokio::select! {
            writer = semaphore.acquire() => {
                writer.map_err(|_| CarrierError::EndpointClosed)?
            }
            _ = self.connection.closed() => return Err(CarrierError::EndpointClosed),
        };
        match tokio::time::timeout(CONTROL_STREAM_SEND_TIMEOUT, async {
            tokio::select! {
                result = async {
                    let mut stream = self
                        .connection
                        .open_uni()
                        .await
                        .map_err(|e| CarrierError::Protocol(e.to_string()))?;
                    write_bytes(&mut stream, &encoded).await
                } => result,
                _ = self.connection.closed() => Err(CarrierError::EndpointClosed),
            }
        })
        .await
        {
            Ok(result) => result,
            Err(_) => {
                // A stream writer that cannot complete within the bound is
                // evidence that this Link is no longer a viable control
                // path.  Force the normal Link replacement/re-auth path so
                // callers do not keep retrying the same stuck connection.
                self.close("control stream send timeout");
                Err(CarrierError::ControlStreamTimeout)
            }
        }
    }
    pub async fn recv_control(&self) -> Result<crate::control::ControlMessage, CarrierError> {
        let mut stream = self
            .connection
            .accept_uni()
            .await
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        // The control header is outside its u16 body length. RFC-0016 allows
        // a TopologySync body to fill that field exactly.
        let raw = read_bytes(&mut stream, usize::from(u16::MAX) + 3).await?;
        crate::control::ControlMessage::decode(&raw)
            .map_err(|e| CarrierError::Protocol(e.to_string()))
    }
    pub async fn wait_closed(&self) {
        self.connection.closed().await;
    }
    pub fn close_reason(&self) -> Option<quinn::ConnectionError> {
        self.connection.close_reason()
    }
    pub fn close(&self, reason: &str) {
        self.lifecycle_token.revoke();
        self.connection.close(0u32.into(), reason.as_bytes());
    }
}

impl crate::link::LinkHandle for Link {
    fn peer_name(&self) -> &str {
        &self.peer
    }

    fn peer_identity(&self) -> &str {
        &self.peer_identity
    }

    fn instance(&self) -> u64 {
        self.instance()
    }

    fn is_healthy(&self) -> bool {
        self.is_healthy()
    }

    fn set_healthy(&self, healthy: bool) {
        self.set_healthy(healthy);
    }

    fn should_log_dataplane_warning(&self) -> bool {
        self.should_log_dataplane_warning()
    }

    fn is_closed(&self) -> bool {
        self.close_reason().is_some()
    }

    fn send_forward(&self, frame: &[u8]) -> Result<(), crate::link::LinkError> {
        Link::send_forward(self, frame).map_err(Into::into)
    }

    fn send_control<'a>(
        &'a self,
        message: &'a crate::control::ControlMessage,
    ) -> crate::link::LinkFuture<'a> {
        Box::pin(async move { Link::send_control(self, message).await.map_err(Into::into) })
    }
}

impl From<crate::link::LinkError> for CarrierError {
    fn from(error: crate::link::LinkError) -> Self {
        match error {
            crate::link::LinkError::AdmissionRejected => Self::AdmissionRejected,
            crate::link::LinkError::ControlStreamTimeout => Self::ControlStreamTimeout,
            crate::link::LinkError::WouldBlock => Self::WouldBlock,
            crate::link::LinkError::DatagramTooLarge { size, limit } => {
                Self::DatagramTooLarge { size, limit }
            }
            crate::link::LinkError::EndpointClosed => Self::EndpointClosed,
            crate::link::LinkError::Transport(message) => Self::Protocol(message),
        }
    }
}

impl From<CarrierError> for crate::link::LinkError {
    fn from(error: CarrierError) -> Self {
        match error {
            CarrierError::AdmissionRejected => Self::AdmissionRejected,
            CarrierError::ControlStreamTimeout => Self::ControlStreamTimeout,
            CarrierError::WouldBlock => Self::WouldBlock,
            CarrierError::DatagramTooLarge { size, limit } => {
                Self::DatagramTooLarge { size, limit }
            }
            CarrierError::EndpointClosed => Self::EndpointClosed,
            other => Self::Transport(other.to_string()),
        }
    }
}

fn next_instance() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn is_local_oversize_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("message too long")
        || message.contains("emsgsize")
        || message.contains("os error 90")
}

fn is_local_oversize_errno(errno: i32) -> bool {
    errno == libc::EMSGSIZE
}

fn is_local_backpressure_errno(errno: i32) -> bool {
    errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::ENOBUFS
}

fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
pub fn endpoint(bind: SocketAddr) -> Result<Endpoint, CarrierError> {
    endpoint_with_link_health(bind, &LinkHealthConfig::default())
}
pub fn endpoint_with_link_health(
    bind: SocketAddr,
    health: &LinkHealthConfig,
) -> Result<Endpoint, CarrierError> {
    endpoint_with_options(CarrierProtocol::Quic, bind, health, None, None)
}
pub fn endpoint_with_options(
    protocol: CarrierProtocol,
    bind: SocketAddr,
    health: &LinkHealthConfig,
    fwmark: Option<u32>,
    carrier_interface: Option<&str>,
) -> Result<Endpoint, CarrierError> {
    Ok(endpoint_with_options_and_bare(
        protocol,
        bind,
        health,
        fwmark,
        carrier_interface,
        Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
    )?
    .0)
}

pub fn endpoint_with_options_and_bare(
    protocol: CarrierProtocol,
    bind: SocketAddr,
    health: &LinkHealthConfig,
    fwmark: Option<u32>,
    carrier_interface: Option<&str>,
    fake_tcp_reset_key: Option<&[u8]>,
) -> Result<(Endpoint, Option<Arc<BareEndpoint>>), CarrierError> {
    install_crypto_provider();
    let cert = generate_simple_self_signed(vec!["tinect".into()])
        .map_err(|e| CarrierError::Certificate(e.to_string()))?;
    let chain = vec![cert.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = ServerConfig::with_single_cert(chain, key)
        .map_err(|e| CarrierError::Certificate(e.to_string()))?;
    let transport = transport_config(health, protocol, bind.is_ipv4());
    server.transport_config(Arc::new(transport));
    underlay::open_endpoint_with_bare(
        protocol,
        bind,
        server,
        fwmark,
        carrier_interface,
        fake_tcp_reset_key,
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn bind_socket_interface(
    socket: &std::net::UdpSocket,
    interface: &str,
) -> Result<(), CarrierError> {
    use std::{ffi::CString, num::NonZeroU32, os::fd::AsRawFd};

    unsafe extern "C" {
        fn if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
        fn setsockopt(
            socket: std::ffi::c_int,
            level: std::ffi::c_int,
            option_name: std::ffi::c_int,
            option_value: *const std::ffi::c_void,
            option_len: u32,
        ) -> std::ffi::c_int;
    }
    const IPPROTO_IP: std::ffi::c_int = 0;
    const IP_BOUND_IF: std::ffi::c_int = 25;
    let interface = CString::new(interface).map_err(|_| {
        CarrierError::Protocol("carrier_interface cannot contain a NUL byte".into())
    })?;
    let index =
        NonZeroU32::new(unsafe { if_nametoindex(interface.as_ptr()) }).ok_or_else(|| {
            CarrierError::Protocol(format!(
                "unknown carrier interface {}",
                interface.to_string_lossy()
            ))
        })?;
    let result = unsafe {
        setsockopt(
            socket.as_raw_fd(),
            IPPROTO_IP,
            IP_BOUND_IF,
            (&index.get() as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(CarrierError::Protocol(format!(
            "binding QUIC carrier to interface {} failed: {}",
            interface.to_string_lossy(),
            std::io::Error::last_os_error()
        )))
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn bind_socket_interface(
    _: &std::net::UdpSocket,
    interface: &str,
) -> Result<(), CarrierError> {
    Err(CarrierError::Protocol(format!(
        "carrier_interface ({interface}) is supported only on macOS"
    )))
}

#[cfg(target_os = "linux")]
pub(crate) fn set_socket_mark(socket: &std::net::UdpSocket, mark: u32) -> Result<(), CarrierError> {
    unsafe extern "C" {
        fn setsockopt(
            fd: std::os::fd::RawFd,
            level: std::ffi::c_int,
            option_name: std::ffi::c_int,
            option_value: *const std::ffi::c_void,
            option_len: u32,
        ) -> std::ffi::c_int;
    }
    // Linux's SOL_SOCKET/SO_MARK.  This requires CAP_NET_ADMIN, which `up`
    // already requires to create the TUN device.
    const SOL_SOCKET: std::ffi::c_int = 1;
    const SO_MARK: std::ffi::c_int = 36;
    use std::os::fd::AsRawFd;
    let result = unsafe {
        setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(CarrierError::Protocol(format!(
            "setting Linux SO_MARK {mark:#x} failed: {}",
            std::io::Error::last_os_error()
        )))
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_socket_mark(_: &std::net::UdpSocket, _: u32) -> Result<(), CarrierError> {
    Err(CarrierError::Protocol(
        "fwmark is supported only on Linux".into(),
    ))
}

pub fn client_config() -> ClientConfig {
    client_config_with_link_health(&LinkHealthConfig::default())
}
pub fn client_config_with_link_health(health: &LinkHealthConfig) -> ClientConfig {
    client_config_for(health, CarrierProtocol::Quic, true)
}

fn client_config_for(
    health: &LinkHealthConfig,
    protocol: CarrierProtocol,
    is_ipv4: bool,
) -> ClientConfig {
    install_crypto_provider();
    let verifier = Arc::new(AcceptAnyCertificate);
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).expect("valid QUIC TLS config"),
    ));
    let transport = transport_config(health, protocol, is_ipv4);
    config.transport_config(Arc::new(transport));
    config
}

/// Configure physical-link DPLPMTUD identically for incoming and outgoing
/// QUIC connections. Quinn starts at the QUIC-safe 1200-byte UDP payload and
/// probes up to the conservative Ethernet-safe payload ceiling.
fn transport_config(
    health: &LinkHealthConfig,
    protocol: CarrierProtocol,
    is_ipv4: bool,
) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    // Control messages use one uni stream each. Keep the peer's pre-accept
    // backlog bounded by the combined RFC-0017 writer ceiling (8 S0 + 32
    // normal S1 + one recovery stream) instead of Quinn's larger default.
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(41));
    // DATAGRAM traffic has no stream-level retransmission or flow control;
    // BBR keeps the relay's sending rate from collapsing after transient
    // loss, which is important on long-haul paths.
    let mut bbr = quinn::congestion::BbrConfig::default();
    // Size the initial window for an expected 200 Mbps / 50 ms path:
    // bandwidth-delay-product = 200_000_000 / 8 * 0.050 = 1_250_000 bytes.
    // This avoids spending the short speed-test interval in a tiny-window
    // startup phase; BBR still reduces the window when the path cannot carry
    // this rate.
    bbr.initial_window(1_250_000);
    transport.congestion_controller_factory(std::sync::Arc::new(bbr));
    transport.initial_mtu(crate::mtu::INITIAL_QUIC_PATH_PAYLOAD_SIZE as u16);
    transport.initial_rtt(Duration::from_millis(60));
    transport.send_fairness(false);
    transport.datagram_send_buffer_size(16 * 1024 * 1024);
    transport.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
    let mut discovery = quinn::MtuDiscoveryConfig::default();
    let fake_tcp = matches!(
        protocol,
        CarrierProtocol::QuicFakeTcp | CarrierProtocol::QuicFullFakeTcp
    );
    let upper_bound = crate::mtu::max_quic_path_payload_size(fake_tcp, is_ipv4);
    discovery.upper_bound(upper_bound as u16);
    transport.mtu_discovery_config(Some(discovery));
    transport.keep_alive_interval(Some(Duration::from_secs(health.keepalive_secs)));
    transport.max_idle_timeout(Some(
        quinn::VarInt::from_u32(health.idle_timeout_secs.saturating_mul(1_000) as u32).into(),
    ));
    transport
}

pub async fn connect(
    endpoint: &Endpoint,
    remote: SocketAddr,
    expected_peer: &str,
    expected_key: &str,
    _local_identity: &str,
    local_key: &ed25519_dalek::SigningKey,
) -> Result<Link, CarrierError> {
    connect_with_link_health(
        endpoint,
        remote,
        CarrierProtocol::Quic,
        expected_peer,
        expected_key,
        _local_identity,
        local_key,
        &LinkHealthConfig::default(),
    )
    .await
}
#[allow(clippy::too_many_arguments)]
pub async fn connect_with_link_health(
    endpoint: &Endpoint,
    remote: SocketAddr,
    protocol: CarrierProtocol,
    expected_peer: &str,
    expected_key: &str,
    _local_identity: &str,
    local_key: &ed25519_dalek::SigningKey,
    health: &LinkHealthConfig,
) -> Result<Link, CarrierError> {
    connect_with_link_health_and_bare(
        endpoint,
        None,
        remote,
        protocol,
        expected_peer,
        expected_key,
        _local_identity,
        local_key,
        health,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn connect_with_link_health_and_bare(
    endpoint: &Endpoint,
    bare_socket: Option<&Arc<BareEndpoint>>,
    remote: SocketAddr,
    protocol: CarrierProtocol,
    expected_peer: &str,
    expected_key: &str,
    _local_identity: &str,
    local_key: &ed25519_dalek::SigningKey,
    health: &LinkHealthConfig,
) -> Result<Link, CarrierError> {
    connect_with_link_health_and_bare_and_fec(
        endpoint,
        bare_socket,
        remote,
        protocol,
        expected_peer,
        expected_key,
        _local_identity,
        local_key,
        health,
        0,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn connect_with_link_health_and_bare_and_fec(
    endpoint: &Endpoint,
    bare_socket: Option<&Arc<BareEndpoint>>,
    remote: SocketAddr,
    protocol: CarrierProtocol,
    expected_peer: &str,
    expected_key: &str,
    _local_identity: &str,
    local_key: &ed25519_dalek::SigningKey,
    health: &LinkHealthConfig,
    repair_rate: u16,
) -> Result<Link, CarrierError> {
    let conn = endpoint
        .connect_with(
            client_config_for(health, protocol, remote.is_ipv4()),
            remote,
            "tinect",
        )?
        .await?;
    // The admission domain starts with the identity exchange, not after it:
    // this is the first S0 writer on this connection and the same gate moves
    // into the Link after authentication succeeds.
    let priority = priority::Gate::default();
    if !priority.admit_stream(PriorityClass::S0, 0).await {
        return Err(CarrierError::AdmissionRejected);
    }
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| CarrierError::Protocol(e.to_string()))?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).expect("OS random source unavailable");
    let sender_receive_id = next_receive_id();
    let local_identity = node_id(&local_key.verifying_key());
    let hello = Hello {
        identity: local_identity.clone(),
        public_key: encode_public(&local_key.verifying_key()),
        nonce: STANDARD_NO_PAD.encode(nonce),
        sender_receive_id,
        capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
        repair_rate: (repair_rate != 0).then_some(repair_rate.min(crate::fec::MAX_RATE_MILLI)),
        signature: sign_hello_with_rate(
            local_key,
            &local_identity,
            &encode_public(&local_key.verifying_key()),
            &nonce,
            sender_receive_id,
            CAP_RELIABLE_TOPOLOGY_STREAM,
            (repair_rate != 0).then_some(repair_rate.min(crate::fec::MAX_RATE_MILLI)),
        ),
    };
    write_bytes(&mut send, &hello.encode()?).await?;
    let ack = Ack::decode(&read_bytes(&mut recv, usize::from(u16::MAX)).await?)?;
    verify_ack_with_rate(&ack, expected_peer, expected_key, &nonce)?;
    if ack.capabilities & CAP_RELIABLE_TOPOLOGY_STREAM == 0 {
        return Err(CarrierError::Protocol(
            "peer does not support reliable topology stream".into(),
        ));
    }
    let peer_key =
        decode_public(expected_key).map_err(|e| CarrierError::Identity(e.to_string()))?;
    let physical = PhysicalSession::new(
        local_key,
        &peer_key,
        &STANDARD_NO_PAD
            .decode(&hello.nonce)
            .map_err(|e| CarrierError::Protocol(e.to_string()))?,
    )
    .map_err(|e| CarrierError::Protocol(e.to_string()))?;
    let carrier = if protocol.is_bare_udp() {
        let socket = bare_socket.ok_or_else(|| {
            CarrierError::Protocol("bare UDP endpoint has no shared socket".into())
        })?;
        let receiver = socket.register_receive_id(sender_receive_id)?;
        LinkCarrier::BareUdp {
            socket: socket.clone(),
            remote,
            destination_receive_id: ack.sender_receive_id,
            receiver: AsyncMutex::new(receiver),
            local_receive_id: sender_receive_id,
        }
    } else {
        LinkCarrier::Quic
    };
    let (forward_payloads, forward_receiver) = mpsc::channel(FORWARD_QUEUE_CAPACITY);
    let (capacity_events, _) = broadcast::channel(128);
    Ok(Link {
        peer: expected_peer.into(),
        peer_identity: node_id(&peer_key),
        link_id: hello.nonce,
        instance: next_instance(),
        lifecycle_token: crate::link::LinkToken::default(),
        carrier_healthy: AtomicBool::new(false),
        healthy: AtomicBool::new(false),
        connection: conn,
        carrier,
        receive_id: sender_receive_id,
        bare_mtu: AtomicU64::new(if protocol.is_bare_udp() {
            crate::mtu::INITIAL_BARE_PHYSICAL_SIZE as u64
        } else {
            0
        }),
        bare_target_upper: if protocol.is_bare_udp() {
            if protocol.is_fake_tcp() {
                if remote.is_ipv4() { 1448 } else { 1428 }
            } else if remote.is_ipv4() {
                1472
            } else {
                1452
            }
        } else {
            0
        },
        pmtu: StdMutex::new(PmtuState {
            confirmed_capacity: if protocol.is_bare_udp() {
                crate::mtu::INITIAL_BARE_PHYSICAL_SIZE as u16
            } else {
                0
            },
            safe_capacity: if protocol.is_bare_udp() {
                crate::mtu::INITIAL_BARE_PHYSICAL_SIZE as u16
            } else {
                0
            },
            lower_bound: if protocol.is_bare_udp() {
                crate::mtu::INITIAL_BARE_PHYSICAL_SIZE as u16
            } else {
                0
            },
            upper_bound: if protocol.is_bare_udp() {
                if protocol.is_fake_tcp() {
                    if remote.is_ipv4() { 1444 } else { 1424 }
                } else if remote.is_ipv4() {
                    1468
                } else {
                    1448
                }
            } else {
                0
            },
            active: None,
            consecutive_successes: 0,
            consecutive_failures: 0,
            last_confirmed_at: None,
            next_upward_reprobe_at: None,
            capacity_generation: 1,
            next_attempt_id: 0,
        }),
        pmtu_notify: Arc::new(Notify::new()),
        pmtu_cancel: CancellationToken::new(),
        pmtu_started: AtomicBool::new(false),
        capacity_monitor_started: AtomicBool::new(false),
        quic_observed_capacity: AtomicU64::new(0),
        quic_capacity_generation: AtomicU64::new(1),
        capacity_events,
        tx_datagrams: AtomicU64::new(0),
        tx_bytes: AtomicU64::new(0),
        tx_queue_drops: AtomicU64::new(0),
        datagram_wire_oversize: AtomicU64::new(0),
        stream_admission_rejections: AtomicU64::new(0),
        datagram_admission_rejections: AtomicU64::new(0),
        forward_queue_drops: AtomicU64::new(0),
        tx_errors: AtomicU64::new(0),
        pmtu_local_oversize: AtomicU64::new(0),
        pmtu_queue_pressure: AtomicU64::new(0),
        pmtu_ack_timeouts: AtomicU64::new(0),
        pmtu_peer_teardowns: AtomicU64::new(0),
        pmtu_protocol_errors: AtomicU64::new(0),
        rx_datagrams: AtomicU64::new(0),
        rx_bytes: AtomicU64::new(0),
        fec: FecLink::new(
            repair_rate
                .min(ack.repair_rate.unwrap_or(0))
                .min(crate::fec::MAX_RATE_MILLI),
        ),
        fec_ready: AsyncMutex::new(VecDeque::new()),
        fec_tx_repairs: AtomicU64::new(0),
        fec_rx_sources: AtomicU64::new(0),
        fec_rx_repairs: AtomicU64::new(0),
        fec_recovered: AtomicU64::new(0),
        fec_lost: AtomicU64::new(0),
        fec_discarded: AtomicU64::new(0),
        fec_rate_limited: AtomicU64::new(0),
        fec_reordered: AtomicU64::new(0),
        fec_invalid: AtomicU64::new(0),
        fec_feedback_sent: AtomicU64::new(0),
        fec_feedback_retries: AtomicU64::new(0),
        physical,
        priority,
        s0_stream_writers: Semaphore::new(8),
        s1_stream_writers: Semaphore::new(32),
        recovery_stream_writers: Semaphore::new(1),
        topology_inbound_synced: AtomicBool::new(false),
        topology_outbound_acked: AtomicBool::new(false),
        topology_delta_outbox: AsyncMutex::new(TopologyDeltaOutbox::default()),
        last_tx_millis: AtomicU64::new(monotonic_millis()),
        last_rx_millis: AtomicU64::new(monotonic_millis()),
        last_dataplane_warning_second: AtomicU64::new(u64::MAX),
        forward_payloads,
        forward_receiver: AsyncMutex::new(Some(forward_receiver)),
    })
}
pub async fn accept(
    endpoint: &Endpoint,
    peers: &BTreeMap<String, crate::config::Peer>,
    accept_connections: bool,
    _local_identity: &str,
    local_key: &ed25519_dalek::SigningKey,
) -> Result<Link, CarrierError> {
    accept_with_bare(
        endpoint,
        None,
        CarrierProtocol::Quic,
        peers,
        accept_connections,
        _local_identity,
        local_key,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn accept_with_bare(
    endpoint: &Endpoint,
    bare_socket: Option<&Arc<BareEndpoint>>,
    protocol: CarrierProtocol,
    peers: &BTreeMap<String, crate::config::Peer>,
    accept_connections: bool,
    _local_identity: &str,
    local_key: &ed25519_dalek::SigningKey,
) -> Result<Link, CarrierError> {
    accept_with_bare_and_fec(
        endpoint,
        bare_socket,
        protocol,
        peers,
        accept_connections,
        _local_identity,
        local_key,
        0,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn accept_with_bare_and_fec(
    endpoint: &Endpoint,
    bare_socket: Option<&Arc<BareEndpoint>>,
    protocol: CarrierProtocol,
    peers: &BTreeMap<String, crate::config::Peer>,
    accept_connections: bool,
    _local_identity: &str,
    local_key: &ed25519_dalek::SigningKey,
    repair_rate: u16,
) -> Result<Link, CarrierError> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or(CarrierError::EndpointClosed)?;
    let remote = incoming.remote_address();
    let conn = incoming
        .await
        .map_err(|error| CarrierError::InboundHandshake {
            remote,
            stage: "QUIC transport handshake",
            reason: error.to_string(),
        })?;
    // Keep the handshake acknowledgement in the same per-connection S0
    // admission domain that will later serve this Link.
    let priority = priority::Gate::default();
    let (mut send, mut recv) =
        conn.accept_bi()
            .await
            .map_err(|error| CarrierError::InboundHandshake {
                remote,
                stage: "opening identity stream",
                reason: error.to_string(),
            })?;
    let hello: Hello = Hello::decode(&read_bytes(&mut recv, usize::from(u16::MAX)).await?)
        .map_err(|error| CarrierError::InboundHandshake {
            remote,
            stage: "reading identity hello",
            reason: error.to_string(),
        })?;
    let peer_name = peers
        .iter()
        .find_map(|(name, peer)| (peer.public_key == hello.public_key).then_some(name.clone()));
    let Some(peer_name) = peer_name else {
        return Err(CarrierError::Identity(
            "unknown peer cannot establish a link".into(),
        ));
    };
    if !peers[&peer_name].accepts_connections(accept_connections) {
        return Err(CarrierError::Identity(
            "peer is not allowed to connect".into(),
        ));
    }
    let nonce = STANDARD_NO_PAD
        .decode(&hello.nonce)
        .map_err(|e| CarrierError::Protocol(e.to_string()))?;
    let pk = decode_public(&hello.public_key).map_err(|e| CarrierError::Identity(e.to_string()))?;
    if hello.identity != node_id(&pk) {
        return Err(CarrierError::Identity(
            "peer identity does not match public key".into(),
        ));
    }
    verify_signed_receive_id_with_rate(
        &pk,
        &hello.identity,
        &hello.public_key,
        &nonce,
        hello.sender_receive_id,
        hello.capabilities,
        hello.repair_rate,
        &hello.signature,
    )?;
    if hello.capabilities & CAP_RELIABLE_TOPOLOGY_STREAM == 0 {
        return Err(CarrierError::Protocol(
            "peer does not support reliable topology stream".into(),
        ));
    }
    let local_identity = node_id(&local_key.verifying_key());
    let sender_receive_id = next_receive_id();
    let ack = Ack {
        identity: local_identity.clone(),
        public_key: encode_public(&local_key.verifying_key()),
        sender_receive_id,
        capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
        repair_rate: (repair_rate != 0 && hello.repair_rate.is_some_and(|rate| rate != 0))
            .then_some(repair_rate.min(crate::fec::MAX_RATE_MILLI)),
        signature: sign_ack_with_rate(
            local_key,
            &local_identity,
            &encode_public(&local_key.verifying_key()),
            &nonce,
            sender_receive_id,
            CAP_RELIABLE_TOPOLOGY_STREAM,
            (repair_rate != 0 && hello.repair_rate.is_some_and(|rate| rate != 0))
                .then_some(repair_rate.min(crate::fec::MAX_RATE_MILLI)),
        ),
    };
    if !priority.admit_stream(PriorityClass::S0, 0).await {
        return Err(CarrierError::AdmissionRejected);
    }
    write_bytes(&mut send, &ack.encode()?)
        .await
        .map_err(|error| CarrierError::InboundHandshake {
            remote,
            stage: "sending identity acknowledgement",
            reason: error.to_string(),
        })?;
    let physical = PhysicalSession::new(local_key, &pk, &nonce)
        .map_err(|e| CarrierError::Protocol(e.to_string()))?;
    let carrier = if protocol.is_bare_udp() {
        let socket = bare_socket.ok_or_else(|| {
            CarrierError::Protocol("bare UDP endpoint has no shared socket".into())
        })?;
        let local_receive_id = sender_receive_id;
        let receiver = socket.register_receive_id(local_receive_id)?;
        LinkCarrier::BareUdp {
            socket: socket.clone(),
            remote,
            destination_receive_id: hello.sender_receive_id,
            receiver: AsyncMutex::new(receiver),
            local_receive_id,
        }
    } else {
        LinkCarrier::Quic
    };
    let (forward_payloads, forward_receiver) = mpsc::channel(FORWARD_QUEUE_CAPACITY);
    let (capacity_events, _) = broadcast::channel(128);
    Ok(Link {
        peer: peer_name.clone(),
        peer_identity: hello.identity,
        link_id: hello.nonce,
        instance: next_instance(),
        lifecycle_token: crate::link::LinkToken::default(),
        carrier_healthy: AtomicBool::new(false),
        healthy: AtomicBool::new(false),
        connection: conn,
        carrier,
        receive_id: sender_receive_id,
        bare_mtu: AtomicU64::new(if protocol.is_bare_udp() {
            crate::mtu::INITIAL_BARE_PHYSICAL_SIZE as u64
        } else {
            0
        }),
        bare_target_upper: if protocol.is_bare_udp() {
            if protocol.is_fake_tcp() {
                if remote.is_ipv4() { 1448 } else { 1428 }
            } else if remote.is_ipv4() {
                1472
            } else {
                1452
            }
        } else {
            0
        },
        pmtu: StdMutex::new(PmtuState {
            confirmed_capacity: if protocol.is_bare_udp() {
                crate::mtu::INITIAL_BARE_PHYSICAL_SIZE as u16
            } else {
                0
            },
            safe_capacity: if protocol.is_bare_udp() {
                crate::mtu::INITIAL_BARE_PHYSICAL_SIZE as u16
            } else {
                0
            },
            lower_bound: if protocol.is_bare_udp() {
                crate::mtu::INITIAL_BARE_PHYSICAL_SIZE as u16
            } else {
                0
            },
            upper_bound: if protocol.is_bare_udp() {
                if protocol.is_fake_tcp() {
                    if remote.is_ipv4() { 1444 } else { 1424 }
                } else if remote.is_ipv4() {
                    1468
                } else {
                    1448
                }
            } else {
                0
            },
            active: None,
            consecutive_successes: 0,
            consecutive_failures: 0,
            last_confirmed_at: None,
            next_upward_reprobe_at: None,
            capacity_generation: 1,
            next_attempt_id: 0,
        }),
        pmtu_notify: Arc::new(Notify::new()),
        pmtu_cancel: CancellationToken::new(),
        pmtu_started: AtomicBool::new(false),
        capacity_monitor_started: AtomicBool::new(false),
        quic_observed_capacity: AtomicU64::new(0),
        quic_capacity_generation: AtomicU64::new(1),
        capacity_events,
        tx_datagrams: AtomicU64::new(0),
        tx_bytes: AtomicU64::new(0),
        tx_queue_drops: AtomicU64::new(0),
        datagram_wire_oversize: AtomicU64::new(0),
        stream_admission_rejections: AtomicU64::new(0),
        datagram_admission_rejections: AtomicU64::new(0),
        forward_queue_drops: AtomicU64::new(0),
        tx_errors: AtomicU64::new(0),
        pmtu_local_oversize: AtomicU64::new(0),
        pmtu_queue_pressure: AtomicU64::new(0),
        pmtu_ack_timeouts: AtomicU64::new(0),
        pmtu_peer_teardowns: AtomicU64::new(0),
        pmtu_protocol_errors: AtomicU64::new(0),
        rx_datagrams: AtomicU64::new(0),
        rx_bytes: AtomicU64::new(0),
        fec: FecLink::new(
            repair_rate
                .min(hello.repair_rate.unwrap_or(0))
                .min(crate::fec::MAX_RATE_MILLI),
        ),
        fec_ready: AsyncMutex::new(VecDeque::new()),
        fec_tx_repairs: AtomicU64::new(0),
        fec_rx_sources: AtomicU64::new(0),
        fec_rx_repairs: AtomicU64::new(0),
        fec_recovered: AtomicU64::new(0),
        fec_lost: AtomicU64::new(0),
        fec_discarded: AtomicU64::new(0),
        fec_rate_limited: AtomicU64::new(0),
        fec_reordered: AtomicU64::new(0),
        fec_invalid: AtomicU64::new(0),
        fec_feedback_sent: AtomicU64::new(0),
        fec_feedback_retries: AtomicU64::new(0),
        physical,
        priority,
        s0_stream_writers: Semaphore::new(8),
        s1_stream_writers: Semaphore::new(32),
        recovery_stream_writers: Semaphore::new(1),
        topology_inbound_synced: AtomicBool::new(false),
        topology_outbound_acked: AtomicBool::new(false),
        topology_delta_outbox: AsyncMutex::new(TopologyDeltaOutbox::default()),
        last_tx_millis: AtomicU64::new(monotonic_millis()),
        last_rx_millis: AtomicU64::new(monotonic_millis()),
        last_dataplane_warning_second: AtomicU64::new(u64::MAX),
        forward_payloads,
        forward_receiver: AsyncMutex::new(Some(forward_receiver)),
    })
}

/// Returns whether a newly authenticated connection should replace the
/// currently registered connection for the same peer. Both endpoints receive
/// the same authenticated IDs, so this makes simultaneous dials converge
/// without relying on a node-name ordering.
pub fn should_replace_link(current_id: &str, candidate_id: &str) -> bool {
    candidate_id < current_id
}
fn signed(id: &str, public_key: &str, nonce: &[u8]) -> Vec<u8> {
    [
        id_bytes(id).expect("identity").as_slice(),
        STANDARD_NO_PAD
            .decode(public_key)
            .expect("public key")
            .as_slice(),
        nonce,
    ]
    .concat()
}
fn signed_with_receive_id_and_rate(
    id: &str,
    public_key: &str,
    nonce: &[u8],
    receive_id: u32,
    capabilities: u32,
    repair_rate: Option<u16>,
) -> Vec<u8> {
    let mut out = [
        signed(id, public_key, nonce).as_slice(),
        &receive_id.to_be_bytes(),
        &capabilities.to_be_bytes(),
    ]
    .concat();
    if let Some(rate) = repair_rate {
        out.extend_from_slice(&rate.to_be_bytes());
    }
    out
}
fn sign_hello_with_rate(
    k: &ed25519_dalek::SigningKey,
    id: &str,
    public_key: &str,
    nonce: &[u8],
    receive_id: u32,
    capabilities: u32,
    repair_rate: Option<u16>,
) -> String {
    STANDARD_NO_PAD.encode(
        k.sign(&signed_with_receive_id_and_rate(
            id,
            public_key,
            nonce,
            receive_id,
            capabilities,
            repair_rate,
        ))
        .to_bytes(),
    )
}
fn sign_ack_with_rate(
    k: &ed25519_dalek::SigningKey,
    id: &str,
    public_key: &str,
    hello_nonce: &[u8],
    receive_id: u32,
    capabilities: u32,
    repair_rate: Option<u16>,
) -> String {
    sign_hello_with_rate(
        k,
        id,
        public_key,
        hello_nonce,
        receive_id,
        capabilities,
        repair_rate,
    )
}
#[cfg(test)]
fn sign_hello(
    k: &ed25519_dalek::SigningKey,
    id: &str,
    public_key: &str,
    nonce: &[u8],
    receive_id: u32,
    capabilities: u32,
) -> String {
    sign_hello_with_rate(k, id, public_key, nonce, receive_id, capabilities, None)
}
#[cfg(test)]
fn sign_ack(
    k: &ed25519_dalek::SigningKey,
    id: &str,
    public_key: &str,
    hello_nonce: &[u8],
    receive_id: u32,
    capabilities: u32,
) -> String {
    sign_ack_with_rate(
        k,
        id,
        public_key,
        hello_nonce,
        receive_id,
        capabilities,
        None,
    )
}
fn verify_ack_with_rate(
    ack: &Ack,
    _peer: &str,
    key: &str,
    nonce: &[u8],
) -> Result<(), CarrierError> {
    let pk = decode_public(key).map_err(|e| CarrierError::Identity(e.to_string()))?;
    if ack.identity != node_id(&pk) || ack.public_key != key {
        return Err(CarrierError::Identity("unexpected peer identity".into()));
    }
    let raw = STANDARD_NO_PAD
        .decode(&ack.signature)
        .map_err(|e| CarrierError::Identity(e.to_string()))?;
    let signature = ed25519_dalek::Signature::from_slice(&raw)
        .map_err(|e| CarrierError::Identity(e.to_string()))?;
    pk.verify(
        &signed_with_receive_id_and_rate(
            &ack.identity,
            &ack.public_key,
            nonce,
            ack.sender_receive_id,
            ack.capabilities,
            ack.repair_rate,
        ),
        &signature,
    )
    .map_err(|e| CarrierError::Identity(e.to_string()))
}
fn next_receive_id() -> u32 {
    RECEIVE_ID_ALLOCATOR
        .get_or_init(|| std::sync::Mutex::new(ReceiveIdAllocator::default()))
        .lock()
        .expect("receive id allocator")
        .allocate()
        .unwrap_or(1)
}
fn release_receive_id(id: u32) {
    if let Ok(mut allocator) = RECEIVE_ID_ALLOCATOR
        .get_or_init(|| std::sync::Mutex::new(ReceiveIdAllocator::default()))
        .lock()
    {
        allocator.release(id);
    }
}
#[cfg(test)]
fn verify_signed_receive_id(
    k: &ed25519_dalek::VerifyingKey,
    id: &str,
    public_key: &str,
    nonce: &[u8],
    receive_id: u32,
    capabilities: u32,
    sig: &str,
) -> Result<(), CarrierError> {
    verify_signed_receive_id_with_rate(
        k,
        id,
        public_key,
        nonce,
        receive_id,
        capabilities,
        None,
        sig,
    )
}
#[allow(clippy::too_many_arguments)]
fn verify_signed_receive_id_with_rate(
    k: &ed25519_dalek::VerifyingKey,
    id: &str,
    public_key: &str,
    nonce: &[u8],
    receive_id: u32,
    capabilities: u32,
    repair_rate: Option<u16>,
    sig: &str,
) -> Result<(), CarrierError> {
    if receive_id == 0 {
        return Err(CarrierError::Identity("zero receive id".into()));
    }
    let raw = STANDARD_NO_PAD
        .decode(sig)
        .map_err(|e| CarrierError::Identity(e.to_string()))?;
    let signature = ed25519_dalek::Signature::from_slice(&raw)
        .map_err(|e| CarrierError::Identity(e.to_string()))?;
    k.verify(
        &signed_with_receive_id_and_rate(
            id,
            public_key,
            nonce,
            receive_id,
            capabilities,
            repair_rate,
        ),
        &signature,
    )
    .map_err(|e| CarrierError::Identity(e.to_string()))
}
async fn write_bytes(send: &mut quinn::SendStream, data: &[u8]) -> Result<(), CarrierError> {
    send.write_all(data).await?;
    send.finish()
        .map_err(|e| CarrierError::Protocol(e.to_string()))?;
    Ok(())
}
async fn read_bytes(recv: &mut quinn::RecvStream, limit: usize) -> Result<Vec<u8>, CarrierError> {
    Ok(recv.read_to_end(limit).await?)
}
#[derive(Debug)]
struct AcceptAnyCertificate;
impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let _ = (message, cert, dss);
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let _ = (message, cert, dss);
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::{CircuitId, OpenRequest},
        identity::generate,
    };

    async fn join_task<T>(mut task: tokio::task::JoinHandle<T>, label: &str) -> Result<(), String> {
        match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(format!("{label} panicked: {error}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(format!("{label} timed out and was aborted"))
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fwmark_is_applied_to_the_carrier_socket() {
        // Local developer test runs are commonly unprivileged.  The remote
        // network suite runs this test as root and verifies the actual value.
        if unsafe { libc_geteuid() } != 0 {
            return;
        }
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        set_socket_mark(&socket, 0x42).unwrap();
        let mut mark = 0_u32;
        let mut length = std::mem::size_of::<u32>() as u32;
        let result = unsafe {
            getsockopt(
                socket.as_raw_fd(),
                SOL_SOCKET,
                SO_MARK,
                (&mut mark as *mut u32).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(mark, 0x42);
    }

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        fn getsockopt(
            fd: std::os::fd::RawFd,
            level: std::ffi::c_int,
            option_name: std::ffi::c_int,
            option_value: *mut std::ffi::c_void,
            option_len: *mut u32,
        ) -> std::ffi::c_int;
    }

    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;

    #[cfg(target_os = "linux")]
    const SOL_SOCKET: std::ffi::c_int = 1;
    #[cfg(target_os = "linux")]
    const SO_MARK: std::ffi::c_int = 36;

    #[cfg(target_os = "linux")]
    unsafe fn libc_geteuid() -> u32 {
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() }
    }

    #[tokio::test]
    async fn authenticated_quic_link_transports_datagrams() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = BTreeMap::from([(
            "client".to_owned(),
            crate::config::Peer {
                public_key: encode_public(&client_key.verifying_key()),
                endpoints: vec![],
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: vec![],
                routes: vec![],
                paths: vec![],
            },
        )]);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                server_bare.as_ref(),
                CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
                1_000,
            )
            .await
            .unwrap()
        });
        let (client, client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = Arc::new(
            connect_with_link_health_and_bare_and_fec(
                &client,
                client_bare.as_ref(),
                addr,
                CarrierProtocol::Quic,
                "server",
                &server_public,
                "client",
                &client_key,
                &LinkHealthConfig::default(),
                1_000,
            )
            .await
            .unwrap(),
        );
        assert!(!link.link_id().is_empty());
        assert!(link.instance() > 0);
        assert!(link.lifecycle_token().is_active());
        link.set_healthy(true);
        assert!(link.is_healthy());
        assert!(link.fec_enabled());
        assert_eq!(link.fec_repair_rate_milli(), 1_000);
        assert!(link.take_capacity_monitor().is_none());
        let pmtu_worker = link.take_bare_pmtu_worker().unwrap();
        assert!(link.take_bare_pmtu_worker().is_none());
        let feedback_worker = link.take_fec_feedback_worker().unwrap();
        let recovery_worker = link.take_fec_recovery_worker().unwrap();
        let tail_worker = link.take_fec_tail_worker().unwrap();
        assert!(link.take_fec_feedback_worker().is_none());
        assert!(link.take_fec_recovery_worker().is_none());
        assert!(link.take_fec_tail_worker().is_none());
        assert!(link.take_fec_report().is_none());
        assert!(link.max_datagram_size().is_some());
        assert!(link.confirmed_user_ip_capacity().is_some());
        assert!(!link.topology_ready());
        assert!(!link.mark_topology_snapshot_acknowledged());
        assert!(link.mark_topology_snapshot_received());
        assert!(link.topology_ready());
        link.mark_topology_unsynchronized();
        assert!(!link.topology_ready());
        assert!(!link.mark_topology_snapshot_received());
        let advertisement = LinkStateAdvertisement {
            origin: "01".repeat(16),
            sequence: 1,
            expires_at: 1,
            neighbors: Vec::new(),
            public_key: String::new(),
            signature: String::new(),
        };
        assert!(link.queue_topology_deltas(vec![advertisement]).await);
        assert_eq!(link.take_topology_deltas().await.len(), 1);
        link.clear_topology_deltas().await;
        link.last_dataplane_warning_second
            .store(u64::MAX, Ordering::Relaxed);
        assert!(link.should_log_dataplane_warning());
        assert!(!link.should_log_dataplane_warning());
        let saturated_report = |report_id| crate::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm: 1_000_000,
            burst_milli: 1_000,
        };
        assert_eq!(
            link.apply_fec_report(saturated_report(1)),
            FecReportHealth::Unchanged
        );
        assert_eq!(
            link.apply_fec_report(saturated_report(2)),
            FecReportHealth::Unchanged
        );
        assert_eq!(
            link.apply_fec_report(saturated_report(3)),
            FecReportHealth::Degraded
        );
        assert!(!link.is_healthy());
        link.set_healthy(true);
        assert!(!link.is_healthy());
        let valid_report = |report_id| crate::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm: 100_000,
            burst_milli: 1_000,
        };
        assert_eq!(
            link.apply_fec_report(valid_report(4)),
            FecReportHealth::Unchanged
        );
        assert_eq!(
            link.apply_fec_report(valid_report(5)),
            FecReportHealth::Recovered
        );
        assert!(link.is_healthy());
        let payload = vec![0x5a; crate::crypto::FRAME_OVERHEAD + 3];
        link.send_physical(PhysicalPayload::Keepalive).unwrap();
        link.send_physical(PhysicalPayload::Forward(payload.clone()))
            .unwrap();
        let accepted = Arc::new(server_task.await.unwrap());
        let queued_fec = vec![0x4c; crate::crypto::FRAME_OVERHEAD + 2];
        accepted
            .fec_ready
            .lock()
            .await
            .push_back(queued_fec.clone());
        assert_eq!(
            accepted.recv_physical().await.unwrap(),
            PhysicalPayload::Forward(queued_fec)
        );
        assert_eq!(
            accepted.recv_physical().await.unwrap(),
            PhysicalPayload::Keepalive
        );
        assert_eq!(
            accepted.recv_physical().await.unwrap(),
            PhysicalPayload::Forward(payload)
        );

        // A malformed bare-carrier frame is ignored by the physical receiver;
        // the following valid keepalive proves forged input cannot terminate
        // the sole receiver task.
        if let LinkCarrier::BareUdp {
            socket,
            remote,
            destination_receive_id,
            ..
        } = &link.carrier
        {
            let mut malformed = vec![0xff];
            malformed.extend_from_slice(&destination_receive_id.to_be_bytes());
            malformed.extend_from_slice(&[0; 8]);
            socket.send(*remote, &malformed).unwrap();
            link.send_physical(PhysicalPayload::Keepalive).unwrap();
            assert_eq!(
                accepted.recv_physical().await.unwrap(),
                PhysicalPayload::Keepalive
            );
        }

        // Exercise the physical FEC receive path with a source followed by
        // its authenticated repair.  The source is delivered immediately;
        // the repair is then consumed by the decoder before the following
        // keepalive gives the receiver a non-FEC payload to return.
        let fec_frame = vec![0x6b; crate::crypto::FRAME_OVERHEAD + 3];
        let (source, repairs) = link.fec.push_source(&fec_frame).unwrap();
        let repair_count = repairs.len();
        let duplicate_repair = repairs.first().cloned();
        link.send_physical(PhysicalPayload::FecSource {
            transmission_sequence: source.transmission_sequence,
            esi: source.esi,
            frame: source.frame,
        })
        .unwrap();
        assert_eq!(
            accepted.recv_physical().await.unwrap(),
            PhysicalPayload::Forward(fec_frame)
        );
        for repair in repairs {
            link.send_physical(PhysicalPayload::FecRepair {
                transmission_sequence: repair.transmission_sequence,
                rid: repair.rid,
                first_esi: repair.first_esi,
                symbol_count: repair.symbol_count,
                vector: repair.vector,
            })
            .unwrap();
        }
        if let Some(repair) = duplicate_repair {
            let discarded_before = accepted.metrics().fec_discarded;
            link.send_physical(PhysicalPayload::FecRepair {
                transmission_sequence: repair.transmission_sequence,
                rid: repair.rid,
                first_esi: repair.first_esi,
                symbol_count: repair.symbol_count,
                vector: repair.vector,
            })
            .unwrap();
            link.send_physical(PhysicalPayload::Keepalive).unwrap();
            assert_eq!(
                accepted.recv_physical().await.unwrap(),
                PhysicalPayload::Keepalive
            );
            assert!(accepted.metrics().fec_discarded > discarded_before);
        }
        link.send_physical(PhysicalPayload::Keepalive).unwrap();
        assert_eq!(
            accepted.recv_physical().await.unwrap(),
            PhysicalPayload::Keepalive
        );
        assert!(accepted.metrics().fec_rx_repairs >= repair_count as u64);

        let client_feedback_task = tokio::spawn(feedback_worker);
        let server_feedback_task =
            tokio::spawn(accepted.clone().take_fec_feedback_worker().unwrap());
        for index in 0..128 {
            let payload = vec![index as u8; crate::crypto::FRAME_OVERHEAD + 3];
            link.send_forward(&payload).unwrap();
            loop {
                if matches!(
                    accepted.recv_physical().await.unwrap(),
                    PhysicalPayload::Forward(_)
                ) {
                    break;
                }
            }
        }
        let report = tokio::time::timeout(Duration::from_secs(2), link.recv_control())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            report,
            crate::control::ControlMessage::FecReport(_)
        ));

        let client_recovery_task = tokio::spawn(recovery_worker);
        let client_tail_task = tokio::spawn(tail_worker);
        tokio::time::sleep(Duration::from_millis(100)).await;
        link.send_control(&crate::control::ControlMessage::Ping)
            .await
            .unwrap();
        assert!(matches!(
            accepted.recv_control().await.unwrap(),
            crate::control::ControlMessage::Ping
        ));
        accepted
            .send_control(&crate::control::ControlMessage::Pong)
            .await
            .unwrap();
        assert!(matches!(
            link.recv_control().await.unwrap(),
            crate::control::ControlMessage::Pong
        ));

        // Run the bare PMTU worker against the authenticated Probe/ProbeAck
        // path.  Both physical receivers remain active so the worker can
        // complete a probe instead of merely being constructed.
        let server_physical_link = accepted.clone();
        let server_physical_task =
            tokio::spawn(
                async move { while server_physical_link.recv_physical().await.is_ok() {} },
            );
        let client_physical_link = link.clone();
        let client_physical_task =
            tokio::spawn(
                async move { while client_physical_link.recv_physical().await.is_ok() {} },
            );
        let pmtu_task = tokio::spawn(pmtu_worker);
        tokio::time::sleep(Duration::from_millis(100)).await;
        pmtu_task.abort();
        let _ = pmtu_task.await;
        link.close("FEC worker test complete");
        accepted.close("FEC worker test complete");
        join_task(server_physical_task, "server physical receiver")
            .await
            .unwrap();
        join_task(client_physical_task, "client physical receiver")
            .await
            .unwrap();
        link.record_forward_queue_drop(2);
        assert!(link.metrics().forward_queue_drops >= 2);
        let task_results = [
            join_task(client_feedback_task, "client FEC feedback worker").await,
            join_task(server_feedback_task, "server FEC feedback worker").await,
            join_task(client_recovery_task, "client FEC recovery worker").await,
            join_task(client_tail_task, "client FEC tail worker").await,
        ];
        for result in task_results {
            assert!(result.is_ok(), "{result:?}");
        }
    }

    #[tokio::test]
    async fn full_quic_link_transports_datagrams_and_control_streams() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, _server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = BTreeMap::from([(
            "client".to_owned(),
            crate::config::Peer {
                public_key: encode_public(&client_key.verifying_key()),
                endpoints: vec![],
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: vec![],
                routes: vec![],
                paths: vec![],
            },
        )]);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                None,
                CarrierProtocol::QuicFull,
                &peers,
                false,
                "server",
                &server_key,
                0,
            )
            .await
            .unwrap()
        });
        let (client, _client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = Arc::new(
            connect_with_link_health_and_bare_and_fec(
                &client,
                None,
                addr,
                CarrierProtocol::QuicFull,
                "server",
                &server_public,
                "client",
                &client_key,
                &LinkHealthConfig::default(),
                0,
            )
            .await
            .unwrap(),
        );
        assert!(link.lifecycle_token().is_active());
        assert!(!link.fec_enabled());
        assert_eq!(link.fec_repair_rate_milli(), 0);
        assert!(link.take_capacity_monitor().is_some());
        assert!(link.take_capacity_monitor().is_none());
        assert!(link.take_bare_pmtu_worker().is_none());
        assert!(link.take_fec_feedback_worker().is_none());
        assert!(link.take_fec_recovery_worker().is_none());
        assert!(link.take_fec_tail_worker().is_none());
        assert!(link.take_fec_report().is_none());
        assert!(link.max_datagram_size().is_some());
        assert!(link.confirmed_user_ip_capacity().is_some());

        link.send_physical(PhysicalPayload::Keepalive).unwrap();
        let payload = vec![0x3c; crate::crypto::FRAME_OVERHEAD + 7];
        link.send_forward(&payload).unwrap();
        let accepted = server_task.await.unwrap();
        assert_eq!(
            accepted.recv_physical().await.unwrap(),
            PhysicalPayload::Keepalive
        );
        assert_eq!(
            accepted.recv_physical().await.unwrap(),
            PhysicalPayload::Forward(payload)
        );

        link.send_control(&crate::control::ControlMessage::Ping)
            .await
            .unwrap();
        assert!(matches!(
            accepted.recv_control().await.unwrap(),
            crate::control::ControlMessage::Ping
        ));
        accepted
            .send_control(&crate::control::ControlMessage::Pong)
            .await
            .unwrap();
        assert!(matches!(
            link.recv_control().await.unwrap(),
            crate::control::ControlMessage::Pong
        ));
    }

    #[tokio::test]
    async fn rejects_a_peer_that_disallows_inbound_connections() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let peers = BTreeMap::from([(
            "client".to_owned(),
            crate::config::Peer {
                public_key: encode_public(&client_key.verifying_key()),
                endpoints: vec![],
                upstream_dns: None,
                accept_connections: Some(false),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: vec![],
                routes: vec![],
                paths: vec![],
            },
        )]);
        let server_task =
            tokio::spawn(async move { accept(&server, &peers, true, "server", &server_key).await });
        let client = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();

        assert!(
            connect(
                &client,
                addr,
                "server",
                &server_public,
                "client",
                &client_key,
            )
            .await
            .is_err()
        );
        assert!(matches!(
            server_task.await.unwrap(),
            Err(CarrierError::Identity(message)) if message == "peer is not allowed to connect"
        ));
    }

    #[tokio::test]
    async fn closed_endpoint_is_reported_as_a_terminal_error() {
        let server_key = generate();
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        server.close(0u32.into(), b"test shutdown");

        assert!(matches!(
            accept(&server, &BTreeMap::new(), true, "server", &server_key).await,
            Err(CarrierError::EndpointClosed)
        ));
    }

    #[test]
    fn duplicate_link_selection_is_symmetric_and_stable() {
        assert!(should_replace_link("z-link", "a-link"));
        assert!(!should_replace_link("a-link", "z-link"));
        assert!(!should_replace_link("same", "same"));
    }

    #[tokio::test]
    async fn three_node_signed_circuit_forwards_opaque_payload() {
        let source_key = generate();
        let destination_key = generate();
        let source_id = node_id(&source_key.verifying_key());
        let destination_id = node_id(&destination_key.verifying_key());
        let relay_id = "11".repeat(16);
        let request = OpenRequest::new(
            source_id.clone(),
            &source_key,
            destination_id.clone(),
            vec![source_id, relay_id, destination_id],
            CircuitId([4; 16]),
            [5; 32],
        );
        assert!(request.verify().is_ok());
        let encoded = request.encode_body().unwrap();
        let decoded = OpenRequest::decode_body(&encoded).unwrap();
        assert_eq!(decoded.encode_body().unwrap(), encoded);
        let forwarded = decoded.forwarded().unwrap();
        assert_eq!(forwarded.path, request.path);
        assert!(forwarded.verify().is_ok());
    }

    fn accepting_peers(
        name: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> BTreeMap<String, crate::config::Peer> {
        BTreeMap::from([(
            name.to_owned(),
            crate::config::Peer {
                public_key: encode_public(&key.verifying_key()),
                endpoints: vec![],
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: vec![],
                routes: vec![],
                paths: vec![],
            },
        )])
    }

    #[test]
    fn client_config_wrappers_build() {
        let _ = client_config();
        let _ = client_config_with_link_health(&LinkHealthConfig::default());
    }

    #[test]
    fn accept_any_certificate_answers_all_verifier_callbacks() {
        // DigitallySignedStruct has no public constructor, so only the
        // certificate and scheme-list callbacks are exercised directly here;
        // the TLS 1.3 signature callback runs during every test handshake.
        let verifier = AcceptAnyCertificate;
        let cert = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
        let name = ServerName::try_from("example.com").expect("valid server name");
        assert!(
            verifier
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
        assert!(
            verifier
                .supported_verify_schemes()
                .contains(&SignatureScheme::ED25519)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bind_socket_interface_rejects_invalid_interfaces() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(matches!(
            bind_socket_interface(&socket, "lo\0invalid"),
            Err(CarrierError::Protocol(message)) if message.contains("NUL")
        ));
        assert!(matches!(
            bind_socket_interface(&socket, "tinect-no-such-interface0"),
            Err(CarrierError::Protocol(message)) if message.contains("unknown carrier interface")
        ));
        bind_socket_interface(&socket, "lo0").unwrap();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn bind_socket_interface_is_rejected_off_macos() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(matches!(
            bind_socket_interface(&socket, "lo"),
            Err(CarrierError::Protocol(message)) if message.contains("supported only on macOS")
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_socket_mark_result_matches_caller_privileges() {
        // Unprivileged callers must see the SO_MARK failure instead of a
        // silently unmarked carrier socket; root (CI) exercises the Ok path.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let result = set_socket_mark(&socket, 0x17);
        if unsafe { libc_geteuid() } == 0 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(CarrierError::Protocol(_))));
        }
    }

    #[tokio::test]
    async fn bare_endpoint_register_send_and_unregister_paths() {
        let (_endpoint, bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let bare = bare.expect("QUIC endpoints expose the shared bare socket");
        let _receiver = bare.register_receive_id(77).unwrap();
        // A duplicate registration fails without replacing the active route.
        assert!(matches!(
            bare.register_receive_id(77),
            Err(CarrierError::Protocol(message)) if message.contains("already registered")
        ));
        assert!(matches!(
            bare.register_receive_id(0),
            Err(CarrierError::Protocol(message)) if message.contains("zero receive id")
        ));
        bare.unregister_receive_id(77);
        let _receiver = bare.register_receive_id(77).unwrap();

        // The shared socket is nonblocking: a send can transiently report
        // WouldBlock (without an OS errno) before it is writable. Retry
        // briefly and also exercise that errno-less mapping.
        let mut sent = None;
        for _ in 0..100 {
            match bare.send("127.0.0.1:9".parse().unwrap(), &[1, 2, 3, 4, 5]) {
                Ok(bytes) => {
                    sent = Some(bytes);
                    break;
                }
                Err(CarrierError::Protocol(message)) if message.contains("would block") => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("unexpected bare send error: {error}"),
            }
        }
        assert_eq!(sent, Some(5));
        // An IPv6 destination on an IPv4 socket fails with the raw errno.
        assert!(matches!(
            bare.send("[::1]:9".parse().unwrap(), &[1, 2, 3, 4, 5]),
            Err(CarrierError::LocalIo(_))
        ));
    }

    #[tokio::test]
    async fn link_helper_methods_cover_error_and_accounting_paths() {
        use crate::link::LinkHandle;

        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                server_bare.as_ref(),
                CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
                1_000,
            )
            .await
            .unwrap()
        });
        let (client, client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = Arc::new(
            connect_with_link_health_and_bare_and_fec(
                &client,
                client_bare.as_ref(),
                addr,
                CarrierProtocol::Quic,
                "server",
                &server_public,
                "client",
                &client_key,
                &LinkHealthConfig::default(),
                1_000,
            )
            .await
            .unwrap(),
        );
        let accepted = Arc::new(server_task.await.unwrap());
        // Authenticate probe acknowledgements on the accept side so the
        // ProbeAck path runs while the client drives its own assertions.
        let server_receiver = {
            let accepted = accepted.clone();
            tokio::spawn(async move { while accepted.recv_physical().await.is_ok() {} })
        };

        // FEC report queueing is only live on FEC-enabled links.
        let report = crate::fec::FecReport {
            report_id: 1,
            samples: 128,
            loss_ppm: 0,
            burst_milli: 0,
        };
        link.requeue_fec_report(report);
        assert!(link.take_fec_report().is_some());
        assert!(link.take_fec_report().is_none());

        let _subscription = link.subscribe_capacity_changed();

        for reason in [
            PmtuFailureReason::LocalOversize,
            PmtuFailureReason::QueuePressure,
            PmtuFailureReason::AckTimeout,
            PmtuFailureReason::PeerTeardown,
            PmtuFailureReason::Protocol,
        ] {
            link.record_pmtu_failure(reason);
        }
        let metrics = link.metrics();
        assert_eq!(metrics.pmtu_local_oversize, 1);
        assert_eq!(metrics.pmtu_queue_pressure, 1);
        assert_eq!(metrics.pmtu_ack_timeouts, 1);
        assert_eq!(metrics.pmtu_peer_teardowns, 1);
        assert_eq!(metrics.pmtu_protocol_errors, 1);

        assert!(link.tx_idle_for() < Duration::from_secs(60));
        assert!(link.rx_idle_for() < Duration::from_secs(60));

        // The single Forward consumer is explicit; a published frame reaches
        // it, and publishing after it is gone records a queue drop.
        let mut receiver = link
            .take_forward_receiver()
            .await
            .expect("the first consumer claims the forward queue");
        assert!(link.take_forward_receiver().await.is_none());
        link.publish_forward(vec![1, 2, 3]);
        assert_eq!(receiver.recv().await, Some(vec![1, 2, 3]));
        drop(receiver);
        link.publish_forward(vec![4]);
        assert!(link.metrics().forward_queue_drops >= 1);

        // The recovered-frames queue is bounded and reports its drops.
        link.enqueue_fec_frames((0..FEC_READY_CAPACITY + 10).map(|value| vec![value as u8; 4]))
            .await;
        assert!(link.metrics().forward_queue_drops >= 11);

        // Direct datagram sends enforce the wire budget before hitting QUIC.
        let limit = link.max_datagram_size().unwrap();
        assert!(matches!(
            link.send_datagram(vec![0; limit + 1]),
            Err(CarrierError::DatagramTooLarge { .. })
        ));
        assert!(link.metrics().datagram_wire_oversize >= 1);

        // A well-formed bare PMTU probe is D0 traffic and is answered.
        link.send_physical(PhysicalPayload::Probe {
            probe_id: 1,
            target_len: 100,
            padding: vec![0; 100 - 39],
        })
        .unwrap();
        // Probe targets outside the link bounds or inconsistent with the
        // sealed length are rejected before any carrier write.
        for (target_len, padding) in [(30_u16, vec![]), (u16::MAX, vec![]), (100, vec![])] {
            assert!(matches!(
                link.send_physical(PhysicalPayload::Probe {
                    probe_id: 2,
                    target_len,
                    padding,
                }),
                Err(CarrierError::Protocol(_))
            ));
        }
        // Oversize and truncated payloads are rejected before sealing.
        assert!(matches!(
            link.send_physical(PhysicalPayload::FecSource {
                transmission_sequence: 0,
                esi: 0,
                frame: vec![0; 4_096],
            }),
            Err(CarrierError::DatagramTooLarge { .. })
        ));
        // On a FEC-enabled link, send_forward enters the FEC source batch and
        // a truncated frame is rejected by the encoder.
        assert!(matches!(
            link.send_forward(&[1, 2, 3]),
            Err(CarrierError::Protocol(message)) if message.contains("FEC source")
        ));
        assert!(matches!(
            link.send_forward(&vec![0; 4_096]),
            Err(CarrierError::DatagramTooLarge { .. })
        ));

        // Recovery-class control messages use their own writer semaphore and
        // the S1 admission class.
        link.send_control(&crate::control::ControlMessage::TopologySyncRequest { reason: 1 })
            .await
            .unwrap();
        link.send_control(&crate::control::ControlMessage::TopologySync {
            mode: crate::control::TopologySyncMode::Snapshot,
            sync_id: 1,
            chunk_index: 0,
            chunk_count: 1,
            advertisements: vec![],
        })
        .await
        .unwrap();
        assert!(matches!(
            accepted.recv_control().await.unwrap(),
            crate::control::ControlMessage::TopologySyncRequest { reason: 1 }
        ));
        assert!(matches!(
            accepted.recv_control().await.unwrap(),
            crate::control::ControlMessage::TopologySync { sync_id: 1, .. }
        ));

        // The LinkHandle trait surface forwards to the same implementation.
        assert_eq!(LinkHandle::peer_name(link.as_ref()), "server");
        assert_eq!(LinkHandle::peer_identity(link.as_ref()), link.peer_identity);
        assert_eq!(LinkHandle::instance(link.as_ref()), link.instance());
        assert!(!LinkHandle::is_healthy(link.as_ref()));
        LinkHandle::send_forward(link.as_ref(), &[7; crate::crypto::FRAME_OVERHEAD + 1]).unwrap();
        LinkHandle::send_control(link.as_ref(), &crate::control::ControlMessage::Ping)
            .await
            .unwrap();
        assert!(matches!(
            accepted.recv_control().await.unwrap(),
            crate::control::ControlMessage::Ping
        ));

        // A queued report plus a dead connection exercises the feedback
        // worker's retry-and-abandon path.
        link.requeue_fec_report(crate::fec::FecReport {
            report_id: 2,
            samples: 128,
            loss_ppm: 0,
            burst_milli: 0,
        });
        let feedback_worker = link.take_fec_feedback_worker().unwrap();
        link.close("test shutdown");
        accepted.close("test shutdown");
        let feedback_task = tokio::spawn(feedback_worker);
        join_task(feedback_task, "FEC feedback worker")
            .await
            .expect("feedback worker should stop after link close");
        assert!(link.metrics().fec_feedback_retries >= 1);

        assert!(link.close_reason().is_some());
        tokio::time::timeout(Duration::from_secs(2), link.wait_closed())
            .await
            .unwrap();
        // Sends after close surface the carrier error and are accounted.
        assert!(matches!(
            link.send_datagram(vec![1]),
            Err(CarrierError::Quinn(_))
        ));
        assert!(link.metrics().datagram_send_errors >= 1);

        server_receiver.abort();
        let server_receiver_result = server_receiver.await;
        assert!(
            server_receiver_result.is_ok()
                || server_receiver_result
                    .as_ref()
                    .is_err_and(tokio::task::JoinError::is_cancelled)
        );
    }

    #[tokio::test]
    async fn full_quic_link_rejects_fec_payloads_and_reports() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, _server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                None,
                CarrierProtocol::QuicFull,
                &peers,
                false,
                "server",
                &server_key,
                0,
            )
            .await
            .unwrap()
        });
        let (client, _client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = connect_with_link_health_and_bare_and_fec(
            &client,
            None,
            addr,
            CarrierProtocol::QuicFull,
            "server",
            &server_public,
            "client",
            &client_key,
            &LinkHealthConfig::default(),
            0,
        )
        .await
        .unwrap();
        let accepted = server_task.await.unwrap();
        assert!(!link.fec_enabled());

        assert!(matches!(
            link.send_physical(PhysicalPayload::FecSource {
                transmission_sequence: 0,
                esi: 0,
                frame: vec![1; crate::crypto::FRAME_OVERHEAD + 3],
            }),
            Err(CarrierError::Protocol(message)) if message.contains("without negotiated FEC")
        ));
        assert!(matches!(
            link.send_physical(PhysicalPayload::FecRepair {
                transmission_sequence: 0,
                rid: 0,
                first_esi: 0,
                symbol_count: 1,
                vector: vec![1],
            }),
            Err(CarrierError::Protocol(message)) if message.contains("without negotiated FEC")
        ));

        assert!(matches!(
            link.send_forward(&[1, 2, 3]),
            Err(CarrierError::Protocol(message)) if message.contains("physical payload is truncated")
        ));
        let limit = link.max_datagram_size().unwrap();
        assert!(matches!(
            link.send_forward(&vec![0; limit]),
            Err(CarrierError::DatagramTooLarge { .. })
        ));

        // Build valid authenticated FEC forms directly, then deliver them to
        // a link that negotiated no FEC. The receiver must account and drop
        // both forms while remaining available for ordinary traffic.
        for payload in [
            PhysicalPayload::FecSource {
                transmission_sequence: 1,
                esi: 0,
                frame: vec![0; crate::crypto::FRAME_OVERHEAD + 3],
            },
            PhysicalPayload::FecRepair {
                transmission_sequence: 1,
                rid: 0,
                first_esi: 0,
                symbol_count: 1,
                vector: vec![0; 1],
            },
        ] {
            let frame = link.physical.seal(&payload).unwrap();
            link.send_datagram(frame).unwrap();
        }
        link.send_physical(PhysicalPayload::Keepalive).unwrap();
        assert_eq!(
            accepted.recv_physical().await.unwrap(),
            PhysicalPayload::Keepalive
        );
        assert_eq!(accepted.metrics().fec_invalid, 2);
        let report = crate::fec::FecReport {
            report_id: 1,
            samples: 128,
            loss_ppm: 1_000_000,
            burst_milli: 1_000,
        };
        assert_eq!(link.apply_fec_report(report), FecReportHealth::Unchanged);
        assert!(link.take_fec_report().is_none());
        link.requeue_fec_report(report);
        assert!(link.take_fec_report().is_none());
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn accept_rejects_an_unknown_peer_identity() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            accept(&server, &BTreeMap::new(), true, "server", &server_key).await
        });
        let client = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(
            connect(
                &client,
                addr,
                "server",
                &server_public,
                "client",
                &client_key,
            )
            .await
            .is_err()
        );
        assert!(matches!(
            server_task.await.unwrap(),
            Err(CarrierError::Identity(message)) if message == "unknown peer cannot establish a link"
        ));
    }

    #[tokio::test]
    async fn accept_reports_identity_stream_failures() {
        // A client that finishes the identity stream without a hello fails
        // the accept at the hello decode stage.
        let server_key = generate();
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = {
            let server_key = server_key.clone();
            tokio::spawn(async move {
                accept(&server, &BTreeMap::new(), true, "server", &server_key).await
            })
        };
        let client = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = client
            .connect_with(client_config(), addr, "tinect")
            .unwrap()
            .await
            .unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send.finish().unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(CarrierError::InboundHandshake {
                stage: "reading identity hello",
                ..
            })
        ));
        connection.close(0u32.into(), b"test shutdown");

        // A client that closes without opening the identity stream fails the
        // accept at the stream stage (or earlier during hello reads).
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            accept(&server, &BTreeMap::new(), true, "server", &server_key).await
        });
        let client = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = client
            .connect_with(client_config(), addr, "tinect")
            .unwrap()
            .await
            .unwrap();
        connection.close(0u32.into(), b"test shutdown");
        assert!(matches!(
            server_task.await.unwrap(),
            Err(CarrierError::InboundHandshake { .. })
        ));
    }

    #[tokio::test]
    async fn bare_udp_connect_requires_the_shared_socket() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                server_bare.as_ref(),
                CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
                0,
            )
            .await
            .unwrap()
        });
        let (client, _client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        // The bare carrier cannot operate without the endpoint's shared socket.
        assert!(matches!(
            connect_with_link_health_and_bare(
                &client,
                None,
                addr,
                CarrierProtocol::Quic,
                "server",
                &server_public,
                "client",
                &client_key,
                &LinkHealthConfig::default(),
            )
            .await,
            Err(CarrierError::Protocol(message)) if message == "bare UDP endpoint has no shared socket"
        ));
        let accepted = server_task.await.unwrap();
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn bare_udp_ipv6_links_use_ipv6_capacity_bounds() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "[::1]:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                server_bare.as_ref(),
                CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
                0,
            )
            .await
            .unwrap()
        });
        let (client, client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "[::1]:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = connect_with_link_health_and_bare(
            &client,
            client_bare.as_ref(),
            addr,
            CarrierProtocol::Quic,
            "server",
            &server_public,
            "client",
            &client_key,
            &LinkHealthConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(link.bare_target_upper, 1_452);
        assert_eq!(link.pmtu.lock().expect("pmtu lock").upper_bound, 1_448);
        let accepted = server_task.await.unwrap();
        assert_eq!(accepted.bare_target_upper, 1_452);
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    /// Authenticated bare-UDP link pair used by the PMTU and tail-worker
    /// tests. Returns the client link, the accepted server link, the client
    /// bare socket (for raw crafted frames), and the server address.
    async fn bare_quic_link_pair(
        repair_rate: u16,
    ) -> (Arc<Link>, Arc<Link>, Arc<BareEndpoint>, SocketAddr) {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                server_bare.as_ref(),
                CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
                repair_rate,
            )
            .await
            .unwrap()
        });
        let (client, client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = Arc::new(
            connect_with_link_health_and_bare_and_fec(
                &client,
                client_bare.as_ref(),
                addr,
                CarrierProtocol::Quic,
                "server",
                &server_public,
                "client",
                &client_key,
                &LinkHealthConfig::default(),
                repair_rate,
            )
            .await
            .unwrap(),
        );
        let accepted = Arc::new(server_task.await.unwrap());
        (
            link,
            accepted,
            client_bare.expect("QUIC endpoints expose the shared bare socket"),
            addr,
        )
    }

    /// Authenticated full-QUIC link pair (no bare carrier) used by the FEC
    /// worker and capacity-monitor tests.
    async fn full_quic_link_pair(repair_rate: u16) -> (Arc<Link>, Arc<Link>) {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, _server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                None,
                CarrierProtocol::QuicFull,
                &peers,
                false,
                "server",
                &server_key,
                repair_rate,
            )
            .await
            .unwrap()
        });
        let (client, _client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::QuicFull,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let link = Arc::new(
            connect_with_link_health_and_bare_and_fec(
                &client,
                None,
                addr,
                CarrierProtocol::QuicFull,
                "server",
                &server_public,
                "client",
                &client_key,
                &LinkHealthConfig::default(),
                repair_rate,
            )
            .await
            .unwrap(),
        );
        let accepted = Arc::new(server_task.await.unwrap());
        (link, accepted)
    }

    fn saturated_fec_report(report_id: u64) -> crate::fec::FecReport {
        crate::fec::FecReport {
            report_id,
            samples: 128,
            loss_ppm: 1_000_000,
            burst_milli: 1_000,
        }
    }

    /// The shared bare socket is nonblocking: a fresh socket can transiently
    /// report WouldBlock before it is writable. Retry briefly, as the other
    /// bare-socket tests do.
    async fn bare_send_when_writable(socket: &BareEndpoint, remote: SocketAddr, frame: &[u8]) {
        for _ in 0..100 {
            match socket.send(remote, frame) {
                Ok(_) => return,
                Err(CarrierError::Protocol(message)) if message.contains("would block") => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("unexpected bare send error: {error}"),
            }
        }
        panic!("bare socket stayed congested");
    }

    #[tokio::test]
    async fn fec_workers_exit_when_the_link_is_dropped() {
        let (link, accepted) = full_quic_link_pair(1_000).await;
        let feedback = link.take_fec_feedback_worker().unwrap();
        let recovery = link.take_fec_recovery_worker().unwrap();
        let tail = link.take_fec_tail_worker().unwrap();
        // Once the last strong Link reference is gone, every worker's weak
        // upgrade fails and the worker must return instead of leaking.
        drop(accepted);
        drop(link);
        for (worker, label) in [
            (feedback, "feedback"),
            (recovery, "recovery"),
            (tail, "tail"),
        ] {
            tokio::time::timeout(Duration::from_secs(2), worker)
                .await
                .unwrap_or_else(|_| panic!("{label} worker should exit after the Link is dropped"));
        }
    }

    #[tokio::test]
    async fn fec_feedback_worker_retries_when_control_sends_stall() {
        let (link, accepted) = full_quic_link_pair(1_000).await;
        // Hold every S0 writer slot so the report send parks inside the
        // worker's bounded timeout while the connection itself stays up.
        let permits = link
            .s0_stream_writers
            .acquire_many(8)
            .await
            .expect("S0 writer permits");
        link.requeue_fec_report(crate::fec::FecReport {
            report_id: 1,
            samples: 128,
            loss_ppm: 0,
            burst_milli: 0,
        });
        let worker = tokio::spawn(link.take_fec_feedback_worker().unwrap());
        tokio::time::sleep(Duration::from_millis(2_300)).await;
        // The timed-out send is requeued and retried with backoff; the worker
        // keeps running because the connection is still alive.
        assert!(link.metrics().fec_feedback_retries >= 1);
        assert!(!worker.is_finished());
        drop(permits);
        link.close("test shutdown");
        accepted.close("test shutdown");
        join_task(worker, "FEC feedback worker").await.unwrap();
    }

    #[tokio::test]
    async fn fec_recovery_worker_stops_when_the_carrier_is_torn_down() {
        let (link, accepted) = full_quic_link_pair(1_000).await;
        for report_id in 1..=3 {
            link.apply_fec_report(saturated_fec_report(report_id));
        }
        assert!(link.fec.is_data_degraded());
        let worker = link.take_fec_recovery_worker().unwrap();
        link.close("test shutdown");
        accepted.close("test shutdown");
        // A Quinn teardown error from the recovery probe batch is terminal:
        // the worker must return instead of retrying a dead connection.
        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .expect("recovery worker should stop after carrier teardown");
    }

    #[tokio::test]
    async fn fec_recovery_worker_tolerates_local_send_rejections_until_close() {
        let (link, accepted, ..) = bare_quic_link_pair(1_000).await;
        for report_id in 1..=3 {
            link.apply_fec_report(saturated_fec_report(report_id));
        }
        assert!(link.fec.is_data_degraded());
        // Shrink the confirmed budget so every recovery probe batch is
        // rejected locally with DatagramTooLarge before it reaches the socket.
        link.bare_mtu.store(1, Ordering::Relaxed);
        let rejected_before = link.metrics().datagram_wire_oversize;
        let worker = tokio::spawn(link.take_fec_recovery_worker().unwrap());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(link.metrics().datagram_wire_oversize > rejected_before);
        // Local rejections are not terminal: the worker is parked in its
        // probe interval until the Link is closed.
        assert!(!worker.is_finished());
        link.close("test shutdown");
        accepted.close("test shutdown");
        join_task(worker, "FEC recovery worker").await.unwrap();
    }

    #[tokio::test]
    async fn fec_tail_worker_backs_off_while_tail_repairs_stay_pending() {
        let (link, accepted, ..) = bare_quic_link_pair(1_000).await;
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];
        link.fec
            .send_source_batch(
                &frame,
                |_source| Ok(()),
                |_repair| Err(CarrierError::WouldBlock),
            )
            .unwrap();
        assert!(link.fec.tail_pending.load(Ordering::Acquire));
        link.fec.force_tail_idle_for_test();
        // Every tail flush attempt is rejected locally as oversize, so the
        // repairs stay pending and the worker retries with bounded backoff.
        link.bare_mtu.store(1, Ordering::Relaxed);
        let rejected_before = link.metrics().datagram_wire_oversize;
        let worker = tokio::spawn(link.take_fec_tail_worker().unwrap());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(link.metrics().datagram_wire_oversize > rejected_before);
        assert!(link.fec.tail_pending.load(Ordering::Acquire));
        assert!(!worker.is_finished());
        link.close("test shutdown");
        accepted.close("test shutdown");
        join_task(worker, "FEC tail worker").await.unwrap();
    }

    #[tokio::test]
    async fn fec_tail_worker_stops_after_a_fatal_send_error() {
        let (link, accepted) = full_quic_link_pair(1_000).await;
        let frame = vec![1; crate::crypto::FRAME_OVERHEAD + 3];
        link.fec
            .send_source_batch(
                &frame,
                |_source| Ok(()),
                |_repair| Err(CarrierError::WouldBlock),
            )
            .unwrap();
        assert!(link.fec.tail_pending.load(Ordering::Acquire));
        link.fec.force_tail_idle_for_test();
        // Exhaust the physical session sequence space: sealing the tail
        // repair then fails with a fatal (non-local) protocol error even
        // though the connection itself stays healthy.
        link.physical.exhaust_send_sequence_for_test();
        let worker = link.take_fec_tail_worker().unwrap();
        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .expect("tail worker should stop after a fatal send error");
        // The unsent repairs stay queued; only the worker stops.
        assert!(link.fec.tail_pending.load(Ordering::Acquire));
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn bare_pmtu_worker_tightens_capacity_after_unanswered_probes() {
        let (link, accepted, ..) = bare_quic_link_pair(0).await;
        // Nobody runs the server physical receiver, so probes go unanswered.
        // Pin the probe target at the confirmed capacity so the timeout
        // tightens the confirmed budget and publishes a decrease.
        {
            let mut state = link.pmtu.lock().expect("pmtu lock");
            state.upper_bound = state.confirmed_capacity;
        }
        let mut capacity_events = link.subscribe_capacity_changed();
        tokio::time::pause();
        let worker = tokio::spawn(link.take_bare_pmtu_worker().unwrap());
        for _ in 0..20 {
            if link.metrics().pmtu_ack_timeouts >= 1 {
                break;
            }
            tokio::time::advance(Duration::from_millis(200)).await;
            tokio::task::yield_now().await;
        }
        assert!(link.metrics().pmtu_ack_timeouts >= 1);
        let event = capacity_events
            .try_recv()
            .expect("an unanswered probe at the confirmed capacity publishes a decrease");
        assert_eq!(event.reason, CapacityChangeReason::ProbeDecreased);
        assert_eq!(event.capacity_generation, 2);
        link.pmtu_cancel.cancel();
        tokio::time::resume();
        join_task(worker, "bare PMTU worker").await.unwrap();
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn bare_pmtu_worker_confirms_capacity_after_acknowledged_probes() {
        let (link, accepted, ..) = bare_quic_link_pair(0).await;
        let server_receiver = {
            let accepted = accepted.clone();
            tokio::spawn(async move { while accepted.recv_physical().await.is_ok() {} })
        };
        let client_receiver = {
            let link = link.clone();
            tokio::spawn(async move { while link.recv_physical().await.is_ok() {} })
        };
        let (_, initial_generation) = link.confirmed_user_ip_capacity().unwrap();
        let worker = tokio::spawn(link.take_bare_pmtu_worker().unwrap());
        tokio::time::sleep(Duration::from_millis(400)).await;
        let (_, generation) = link.confirmed_user_ip_capacity().unwrap();
        assert!(
            generation > initial_generation,
            "acknowledged probes raise the confirmed capacity"
        );
        link.pmtu_cancel.cancel();
        join_task(worker, "bare PMTU worker").await.unwrap();
        link.close("test shutdown");
        accepted.close("test shutdown");
        server_receiver.abort();
        client_receiver.abort();
        let _ = server_receiver.await;
        let _ = client_receiver.await;
    }

    #[tokio::test]
    async fn bare_pmtu_worker_idles_when_confirmed_capacity_is_below_the_safe_floor() {
        let (link, accepted, ..) = bare_quic_link_pair(0).await;
        // confirmed >= upper_bound selects the downward-check branch, but
        // confirmed < safe_capacity leaves no useful target: the worker must
        // idle instead of probing below the safe floor.
        {
            let mut state = link.pmtu.lock().expect("pmtu lock");
            state.confirmed_capacity = 1_468;
            state.upper_bound = 1_468;
            state.safe_capacity = 1_472;
        }
        let sent_before = link.metrics().tx_datagrams;
        let worker = tokio::spawn(link.take_bare_pmtu_worker().unwrap());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(link.metrics().tx_datagrams, sent_before);
        assert!(!worker.is_finished());
        link.pmtu_cancel.cancel();
        join_task(worker, "bare PMTU worker").await.unwrap();
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn bare_pmtu_worker_retries_protocol_failures_without_stopping() {
        let (link, accepted, ..) = bare_quic_link_pair(0).await;
        // An upper bound beyond the link's probe ceiling makes every probe
        // fail its bounds check: a local protocol failure that must be
        // retried, never mistaken for a peer teardown.
        link.pmtu.lock().expect("pmtu lock").upper_bound = 2_000;
        let worker = tokio::spawn(link.take_bare_pmtu_worker().unwrap());
        tokio::time::sleep(Duration::from_millis(250)).await;
        let metrics = link.metrics();
        assert!(metrics.pmtu_protocol_errors >= 3);
        assert_eq!(metrics.pmtu_peer_teardowns, 0);
        assert!(!worker.is_finished());
        link.pmtu_cancel.cancel();
        join_task(worker, "bare PMTU worker").await.unwrap();
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn quic_capacity_changes_publish_events_and_the_monitor_observes_the_limit() {
        let (link, accepted) = full_quic_link_pair(0).await;
        let mut events = link.subscribe_capacity_changed();
        let (capacity, generation) = link.confirmed_user_ip_capacity().unwrap();
        assert_eq!(generation, 1);
        // Simulate Quinn's DPLPMTUD reporting a different DATAGRAM limit: the
        // previously observed value no longer matches the current limit.
        link.quic_observed_capacity.store(1, Ordering::Relaxed);
        let (same_capacity, bumped) = link.confirmed_user_ip_capacity().unwrap();
        assert_eq!(same_capacity, capacity);
        assert_eq!(bumped, 2);
        let event = events
            .try_recv()
            .expect("a capacity change is published to subscribers");
        assert_eq!(event.link_instance, link.instance());
        assert_eq!(event.user_ip_capacity, capacity);
        assert_eq!(event.capacity_generation, 2);
        assert_eq!(event.reason, CapacityChangeReason::QuicDplpmtud);

        let monitor = tokio::spawn(link.take_capacity_monitor().unwrap());
        tokio::time::sleep(Duration::from_millis(250)).await;
        // The monitor keeps polling the stable limit without republishing.
        assert!(!monitor.is_finished());
        assert!(events.try_recv().is_err());
        link.pmtu_cancel.cancel();
        join_task(monitor, "capacity monitor").await.unwrap();
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn bare_send_forward_maps_local_oversize_errno_to_a_budget_error() {
        let (link, accepted, ..) = bare_quic_link_pair(0).await;
        // Inflate the confirmed budget so the frame passes the local size
        // checks and the kernel is the one to reject the oversize datagram.
        link.bare_mtu.store(100_000, Ordering::Relaxed);
        let rejected_before = link.metrics().datagram_wire_oversize;
        let frame = vec![0x55; 70_000];
        assert!(matches!(
            link.send_forward(&frame),
            Err(CarrierError::DatagramTooLarge { size, .. }) if size > 65_507
        ));
        assert_eq!(link.metrics().datagram_wire_oversize, rejected_before + 1);
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn bare_fec_source_send_maps_local_oversize_errno_to_a_budget_error() {
        let (link, accepted, ..) = bare_quic_link_pair(1_000).await;
        link.bare_mtu.store(100_000, Ordering::Relaxed);
        let rejected_before = link.metrics().datagram_wire_oversize;
        assert!(matches!(
            link.send_physical(PhysicalPayload::FecSource {
                transmission_sequence: 0,
                esi: 0,
                frame: vec![0x55; 70_000],
            }),
            Err(CarrierError::DatagramTooLarge { size, .. }) if size > 65_507
        ));
        assert_eq!(link.metrics().datagram_wire_oversize, rejected_before + 1);
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn bare_recv_physical_skips_wrong_source_forged_and_malformed_frames() {
        let (link, accepted, client_bare, addr) = bare_quic_link_pair(0).await;
        let (_third, third_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let third_bare = third_bare.expect("QUIC endpoints expose the shared bare socket");
        let receive_id = accepted.receive_id;

        // A datagram routed to this link's receive id but sent by a stranger
        // is skipped before authentication and never counted.
        let mut junk = vec![crate::physical::FORM_FORWARD];
        junk.extend_from_slice(&receive_id.to_be_bytes());
        junk.extend_from_slice(&[7; 8 + 16]);
        bare_send_when_writable(&third_bare, addr, &junk).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // An authenticated probe whose wire length contradicts its target is
        // dropped without an acknowledgement.
        let forged = link
            .physical
            .seal(&PhysicalPayload::Probe {
                probe_id: 9,
                target_len: 100,
                padding: vec![0; 10],
            })
            .unwrap();
        let mut wire = Vec::with_capacity(forged.len() + 4);
        wire.push(forged[0]);
        wire.extend_from_slice(&receive_id.to_be_bytes());
        wire.extend_from_slice(&forged[1..]);
        bare_send_when_writable(&client_bare, addr, &wire).await;

        // A frame that fails authentication is dropped (and its rejection
        // logged) without stopping the sole physical receiver.
        let mut malformed = vec![crate::physical::FORM_FORWARD];
        malformed.extend_from_slice(&receive_id.to_be_bytes());
        malformed.extend_from_slice(&[9; 8 + 16]);
        bare_send_when_writable(&client_bare, addr, &malformed).await;

        link.send_physical(PhysicalPayload::Keepalive).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), accepted.recv_physical())
                .await
                .expect("receiver should survive forged input")
                .unwrap(),
            PhysicalPayload::Keepalive
        );
        // Only source-matched frames (probe, malformed, keepalive) count.
        assert_eq!(accepted.metrics().rx_datagrams, 3);
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn full_quic_link_drops_probe_payloads_without_a_bare_carrier() {
        let (link, accepted) = full_quic_link_pair(0).await;
        link.send_physical(PhysicalPayload::Probe {
            probe_id: 1,
            target_len: 39,
            padding: vec![],
        })
        .unwrap();
        link.send_physical(PhysicalPayload::ProbeAck {
            probe_id: 1,
            target_len: 39,
        })
        .unwrap();
        link.send_physical(PhysicalPayload::Keepalive).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), accepted.recv_physical())
                .await
                .expect("probes are consumed, not delivered")
                .unwrap(),
            PhysicalPayload::Keepalive
        );
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn queued_fec_frames_are_delivered_before_carrier_reads() {
        let (link, accepted) = full_quic_link_pair(0).await;
        link.enqueue_fec_frames(vec![vec![1, 2, 3], vec![4, 5, 6]])
            .await;
        for expected in [vec![1, 2, 3], vec![4, 5, 6]] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), link.recv_physical())
                    .await
                    .unwrap()
                    .unwrap(),
                PhysicalPayload::Forward(expected)
            );
        }
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn recovered_fec_frames_are_delivered_after_a_repair() {
        let (link, accepted, ..) = bare_quic_link_pair(1_000).await;
        let frames: Vec<Vec<u8>> = (0..3_u8)
            .map(|index| vec![0x10 + index; crate::crypto::FRAME_OVERHEAD + 3])
            .collect();
        let mut generated = Vec::new();
        for frame in &frames {
            generated.push(link.fec.push_source(frame).unwrap());
        }
        // Deliver sources 0 and 2, skipping 1; the decoder delivers both
        // immediately. The repair then recovers frame 1 out of the gap.
        for index in [0_usize, 2] {
            let (source, _) = &generated[index];
            link.send_physical(PhysicalPayload::FecSource {
                transmission_sequence: source.transmission_sequence,
                esi: source.esi,
                frame: source.frame.clone(),
            })
            .unwrap();
        }
        // A duplicated source yields no delivery; the receiver drops it and
        // keeps reading instead of returning an empty batch.
        let (duplicate, _) = &generated[0];
        link.send_physical(PhysicalPayload::FecSource {
            transmission_sequence: duplicate.transmission_sequence,
            esi: duplicate.esi,
            frame: duplicate.frame.clone(),
        })
        .unwrap();
        let repair = &generated[2].1[0];
        link.send_physical(PhysicalPayload::FecRepair {
            transmission_sequence: repair.transmission_sequence,
            rid: repair.rid,
            first_esi: repair.first_esi,
            symbol_count: repair.symbol_count,
            vector: repair.vector.clone(),
        })
        .unwrap();
        for expected in [&frames[0], &frames[2], &frames[1]] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), accepted.recv_physical())
                    .await
                    .unwrap()
                    .unwrap(),
                PhysicalPayload::Forward(expected.clone())
            );
        }
        let metrics = accepted.metrics();
        assert_eq!(metrics.fec_rx_sources, 2);
        assert_eq!(metrics.fec_rx_repairs, 1);
        assert_eq!(metrics.fec_recovered, 1);
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn recv_physical_accounts_for_rate_limited_and_discarded_repairs() {
        // A negotiated rate of 1 milli credits less than one repair, so the
        // very first repairs are already over the admission budget.
        let (link, accepted, ..) = bare_quic_link_pair(1).await;
        let vector = vec![9; 32];
        for rid in 7..=8 {
            link.send_physical(PhysicalPayload::FecRepair {
                transmission_sequence: rid,
                rid,
                first_esi: 0,
                symbol_count: 1,
                vector: vector.clone(),
            })
            .unwrap();
        }
        // Move the decoder window far forward so a repair for the old window
        // is discarded before any credit is charged.
        link.send_physical(PhysicalPayload::FecSource {
            transmission_sequence: 100,
            esi: 10_000,
            frame: vec![3; crate::crypto::FRAME_OVERHEAD + 3],
        })
        .unwrap();
        link.send_physical(PhysicalPayload::FecRepair {
            transmission_sequence: 101,
            rid: 9,
            first_esi: 0,
            symbol_count: 1,
            vector,
        })
        .unwrap();
        link.send_physical(PhysicalPayload::Keepalive).unwrap();
        // Drain recovered/forwarded frames until the keepalive proves every
        // repair above was processed in order.
        loop {
            if matches!(
                tokio::time::timeout(Duration::from_secs(2), accepted.recv_physical())
                    .await
                    .expect("repairs should not stop the receiver")
                    .unwrap(),
                PhysicalPayload::Keepalive
            ) {
                break;
            }
        }
        let metrics = accepted.metrics();
        assert_eq!(metrics.fec_rate_limited, 2);
        assert!(metrics.fec_discarded >= 1);
        link.close("test shutdown");
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn control_send_times_out_when_uni_stream_budget_is_exhausted() {
        let (link, accepted) = full_quic_link_pair(0).await;
        // Exhaust the negotiated uni-stream budget so the control writer
        // cannot open its stream; the peer never accepts them.
        let mut held = Vec::new();
        for _ in 0..41 {
            held.push(link.connection.open_uni().await.unwrap());
        }
        tokio::time::pause();
        let send = tokio::spawn({
            let link = link.clone();
            async move {
                link.send_control(&crate::control::ControlMessage::Ping)
                    .await
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(CONTROL_STREAM_SEND_TIMEOUT + Duration::from_secs(1)).await;
        let result = send.await.unwrap();
        assert!(matches!(result, Err(CarrierError::ControlStreamTimeout)));
        // A stuck control path closes the Link to force replacement.
        assert!(!link.lifecycle_token().is_active());
        tokio::time::resume();
        drop(held);
        accepted.close("test shutdown");
    }

    #[tokio::test]
    async fn bare_udp_accept_requires_the_shared_socket() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let (server, _server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task = tokio::spawn(async move {
            accept_with_bare_and_fec(
                &server,
                None,
                CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
                0,
            )
            .await
        });
        let (client, client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        // The client may or may not observe the completed handshake: the
        // accept side drops the connection as soon as the missing shared
        // socket turns the authenticated Link into an error.
        let result = connect_with_link_health_and_bare(
            &client,
            client_bare.as_ref(),
            addr,
            CarrierProtocol::Quic,
            "server",
            &server_public,
            "client",
            &client_key,
            &LinkHealthConfig::default(),
        )
        .await;
        if let Ok(link) = result {
            link.close("test shutdown");
        }
        assert!(matches!(
            server_task.await.unwrap(),
            Err(CarrierError::Protocol(message)) if message == "bare UDP endpoint has no shared socket"
        ));
    }

    /// Drive the identity exchange from a raw QUIC client so the accept side
    /// can be fed crafted hellos.
    async fn write_raw_hello(addr: SocketAddr, hello: &Hello) -> (Endpoint, Connection) {
        let client = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = client
            .connect_with(client_config(), addr, "tinect")
            .unwrap()
            .await
            .unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        write_bytes(&mut send, &hello.encode().unwrap())
            .await
            .unwrap();
        (client, connection)
    }

    #[tokio::test]
    async fn accept_rejects_a_hello_with_mismatched_identity() {
        let client_key = generate();
        let server_key = generate();
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task =
            tokio::spawn(async move { accept(&server, &peers, true, "server", &server_key).await });
        let public = encode_public(&client_key.verifying_key());
        let wrong_identity = node_id(&generate().verifying_key());
        let nonce = [5; 32];
        let hello = Hello {
            identity: wrong_identity.clone(),
            public_key: public.clone(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            sender_receive_id: 7,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature: sign_hello_with_rate(
                &client_key,
                &wrong_identity,
                &public,
                &nonce,
                7,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                None,
            ),
        };
        let (_endpoint, connection) = write_raw_hello(addr, &hello).await;
        assert!(matches!(
            server_task.await.unwrap(),
            Err(CarrierError::Identity(message)) if message == "peer identity does not match public key"
        ));
        connection.close(0u32.into(), b"test shutdown");
    }

    #[tokio::test]
    async fn accept_rejects_a_hello_with_an_invalid_signature() {
        let client_key = generate();
        let server_key = generate();
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task =
            tokio::spawn(async move { accept(&server, &peers, true, "server", &server_key).await });
        let identity = node_id(&client_key.verifying_key());
        let public = encode_public(&client_key.verifying_key());
        let nonce = [6; 32];
        let hello = Hello {
            identity: identity.clone(),
            public_key: public.clone(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            sender_receive_id: 7,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            // The signature covers a different nonce than the hello carries.
            signature: sign_hello_with_rate(
                &client_key,
                &identity,
                &public,
                &[9; 32],
                7,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                None,
            ),
        };
        let (_endpoint, connection) = write_raw_hello(addr, &hello).await;
        assert!(matches!(
            server_task.await.unwrap(),
            Err(CarrierError::Identity(_))
        ));
        connection.close(0u32.into(), b"test shutdown");
    }

    #[tokio::test]
    async fn accept_rejects_a_hello_without_reliable_topology_support() {
        let client_key = generate();
        let server_key = generate();
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let peers = accepting_peers("client", &client_key);
        let server_task =
            tokio::spawn(async move { accept(&server, &peers, true, "server", &server_key).await });
        let identity = node_id(&client_key.verifying_key());
        let public = encode_public(&client_key.verifying_key());
        let nonce = [7; 32];
        let hello = Hello {
            identity: identity.clone(),
            public_key: public.clone(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            sender_receive_id: 7,
            capabilities: 0,
            repair_rate: None,
            // The signature is valid for the (capability-free) hello, so the
            // rejection comes from the capability check itself.
            signature: sign_hello_with_rate(&client_key, &identity, &public, &nonce, 7, 0, None),
        };
        let (_endpoint, connection) = write_raw_hello(addr, &hello).await;
        assert!(matches!(
            server_task.await.unwrap(),
            Err(CarrierError::Protocol(message)) if message == "peer does not support reliable topology stream"
        ));
        connection.close(0u32.into(), b"test shutdown");
    }

    #[tokio::test]
    async fn connect_rejects_an_ack_without_reliable_topology_support() {
        let client_key = generate();
        let server_key = generate();
        let server_public = encode_public(&server_key.verifying_key());
        let server = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = {
            let server_key = server_key.clone();
            tokio::spawn(async move {
                let connection = server.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let hello_bytes = read_bytes(&mut recv, usize::from(u16::MAX)).await.unwrap();
                let hello = Hello::decode(&hello_bytes).unwrap();
                let nonce = STANDARD_NO_PAD.decode(&hello.nonce).unwrap();
                let identity = node_id(&server_key.verifying_key());
                let public = encode_public(&server_key.verifying_key());
                let ack = Ack {
                    identity: identity.clone(),
                    public_key: public.clone(),
                    sender_receive_id: 9,
                    capabilities: 0,
                    repair_rate: None,
                    signature: sign_ack_with_rate(
                        &server_key,
                        &identity,
                        &public,
                        &nonce,
                        9,
                        0,
                        None,
                    ),
                };
                write_bytes(&mut send, &ack.encode().unwrap())
                    .await
                    .unwrap();
                // Keep the connection alive until the client has read the
                // ack and rejected it; an immediate drop would race the ack
                // delivery with the connection close.
                let _ = tokio::time::timeout(Duration::from_secs(2), connection.closed()).await;
            })
        };
        let client = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(matches!(
            connect(&client, addr, "server", &server_public, "client", &client_key).await,
            Err(CarrierError::Protocol(message)) if message == "peer does not support reliable topology stream"
        ));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_reports_connection_failures() {
        let client_key = generate();
        let client = endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        // Connecting from a closed endpoint fails instead of producing a
        // half-initialized Link.
        client.close(0u32.into(), b"test shutdown");
        let result = connect(
            &client,
            "127.0.0.1:9".parse().unwrap(),
            "server",
            &encode_public(&generate().verifying_key()),
            "client",
            &client_key,
        )
        .await;
        assert!(result.is_err());
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod rfc14_tests {
    use super::*;
    use crate::physical::{FORM_FORWARD, FORM_KEEPALIVE};
    use std::collections::BTreeMap;

    #[test]
    fn demux_requires_fixed_bit_or_registered_bare_form() {
        assert_eq!(classify_inbound_packet(&[]), InboundPacketKind::Drop);
        assert_eq!(classify_inbound_packet(&[0x40]), InboundPacketKind::Quic);
        assert_eq!(
            classify_inbound_packet(&[
                FORM_FORWARD,
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
                0
            ]),
            InboundPacketKind::Drop
        );
        let mut bare = vec![FORM_FORWARD, 0, 0, 0, 1];
        bare.extend_from_slice(&[0; 8 + 16]);
        assert_eq!(
            classify_inbound_packet(&bare),
            InboundPacketKind::BarePhysical
        );
        // RFC-0016's authenticated Physical keepalive keeps bare Links alive
        // while topology itself moves to reliable control streams.
        bare[0] = FORM_KEEPALIVE;
        assert_eq!(
            classify_inbound_packet(&bare),
            InboundPacketKind::BarePhysical
        );
        bare[0] = 0x07;
        assert_eq!(classify_inbound_packet(&bare), InboundPacketKind::Drop);
        bare[0] = FORM_FORWARD;
        bare[1..5].fill(0);
        assert_eq!(classify_inbound_packet(&bare), InboundPacketKind::Drop);
        bare[1..5].copy_from_slice(&1_u32.to_be_bytes());
        bare.truncate(5);
        assert_eq!(classify_inbound_packet(&bare), InboundPacketKind::Drop);
    }

    #[test]
    fn receive_ids_are_nonzero_unique_and_reusable() {
        let mut ids = ReceiveIdAllocator::default();
        let first = ids.allocate().unwrap();
        let second = ids.allocate().unwrap();
        assert_ne!(first, 0);
        assert_ne!(first, second);
        ids.release(first);
        let reused = ids.allocate().unwrap();
        assert_ne!(reused, second);
    }

    #[test]
    fn receive_id_is_bound_by_hello_signature() {
        let key = crate::identity::generate();
        let id = crate::identity::node_id(&key.verifying_key());
        let public = crate::identity::encode_public(&key.verifying_key());
        let nonce = [3; 32];
        let signature = sign_hello(&key, &id, &public, &nonce, 7, CAP_RELIABLE_TOPOLOGY_STREAM);
        assert!(
            verify_signed_receive_id(
                &key.verifying_key(),
                &id,
                &public,
                &nonce,
                7,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                &signature,
            )
            .is_ok()
        );
        assert!(
            verify_signed_receive_id(
                &key.verifying_key(),
                &id,
                &public,
                &nonce,
                8,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                &signature,
            )
            .is_err()
        );
    }

    #[test]
    fn hello_and_ack_use_fixed_width_rfc14_bodies() {
        let key = crate::identity::generate();
        let identity = crate::identity::node_id(&key.verifying_key());
        let public_key = crate::identity::encode_public(&key.verifying_key());
        let nonce = [9; 32];
        let hello = Hello {
            identity: identity.clone(),
            public_key: public_key.clone(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            sender_receive_id: 11,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature: sign_hello(
                &key,
                &identity,
                &public_key,
                &nonce,
                11,
                CAP_RELIABLE_TOPOLOGY_STREAM,
            ),
        };
        let encoded = hello.encode().unwrap();
        let (_, body) = crate::wire::decode_message(&encoded).unwrap();
        assert_eq!(body.len(), 16 + 32 + 32 + 4 + 4 + 64);

        let ack = Ack {
            identity: identity.clone(),
            public_key: public_key.clone(),
            sender_receive_id: 12,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature: sign_ack(
                &key,
                &identity,
                &public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
            ),
        };
        let encoded = ack.encode().unwrap();
        let (_, body) = crate::wire::decode_message(&encoded).unwrap();
        assert_eq!(body.len(), 16 + 32 + 4 + 4 + 64);

        let enabled = Hello {
            identity: identity.clone(),
            public_key: public_key.clone(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            sender_receive_id: 13,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: Some(750),
            signature: sign_hello_with_rate(
                &key,
                &identity,
                &public_key,
                &nonce,
                13,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                Some(750),
            ),
        };
        let decoded = Hello::decode(&enabled.encode().unwrap()).unwrap();
        assert_eq!(decoded.repair_rate, Some(750));

        let zero = Hello {
            repair_rate: Some(0),
            signature: sign_hello_with_rate(
                &key,
                &identity,
                &public_key,
                &nonce,
                14,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                Some(0),
            ),
            sender_receive_id: 14,
            ..enabled
        };
        assert!(zero.encode().is_err());

        let zero_ack = Ack {
            repair_rate: Some(0),
            signature: sign_ack_with_rate(
                &key,
                &identity,
                &public_key,
                &nonce,
                15,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                Some(0),
            ),
            sender_receive_id: 15,
            ..ack
        };
        assert!(zero_ack.encode().is_err());
    }

    #[test]
    fn hello_and_ack_codecs_reject_invalid_identity_extensions_and_trailing_data() {
        let key = crate::identity::generate();
        let identity = crate::identity::node_id(&key.verifying_key());
        let public_key = crate::identity::encode_public(&key.verifying_key());
        let nonce = [9; 32];
        let hello = Hello {
            identity: identity.clone(),
            public_key: public_key.clone(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            sender_receive_id: 11,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature: sign_hello(
                &key,
                &identity,
                &public_key,
                &nonce,
                11,
                CAP_RELIABLE_TOPOLOGY_STREAM,
            ),
        };
        let encoded = hello.encode().unwrap();
        assert!(Hello::decode(&[]).is_err());
        assert!(Hello::decode(&crate::wire::encode_message(2, vec![]).unwrap()).is_err());

        let mut truncated = encoded.clone();
        truncated.truncate(truncated.len() - 1);
        assert!(Hello::decode(&truncated).is_err());

        let mut zero_id = encoded.clone();
        let id_offset = 3 + 16 + 32 + 32;
        zero_id[id_offset..id_offset + 4].fill(0);
        assert!(Hello::decode(&zero_id).is_err());

        let mut bad_extension = encoded.clone();
        bad_extension.insert(bad_extension.len() - 64, 1);
        assert!(Hello::decode(&bad_extension).is_err());

        let invalid_rate = Hello {
            identity: hello.identity.clone(),
            public_key: hello.public_key.clone(),
            nonce: hello.nonce.clone(),
            sender_receive_id: hello.sender_receive_id,
            capabilities: hello.capabilities,
            repair_rate: Some(crate::fec::MAX_RATE_MILLI + 1),
            signature: hello.signature.clone(),
        };
        assert!(invalid_rate.encode().is_err());

        let ack = Ack {
            identity,
            public_key,
            sender_receive_id: 12,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature: sign_ack(
                &key,
                &hello.identity,
                &hello.public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
            ),
        };
        let encoded_ack = ack.encode().unwrap();
        assert!(Ack::decode(&[]).is_err());
        assert!(Ack::decode(&crate::wire::encode_message(1, vec![]).unwrap()).is_err());
        let mut truncated_ack = encoded_ack.clone();
        truncated_ack.truncate(truncated_ack.len() - 1);
        assert!(Ack::decode(&truncated_ack).is_err());
        let mut zero_ack_id = encoded_ack.clone();
        zero_ack_id[3 + 16 + 32..3 + 16 + 32 + 4].fill(0);
        assert!(Ack::decode(&zero_ack_id).is_err());
        let mut bad_ack_extension = encoded_ack;
        bad_ack_extension.insert(bad_ack_extension.len() - 64, 1);
        assert!(Ack::decode(&bad_ack_extension).is_err());
        let invalid_ack = Ack {
            repair_rate: Some(crate::fec::MAX_RATE_MILLI + 1),
            ..ack
        };
        assert!(invalid_ack.encode().is_err());

        assert!(id_bytes("short").is_err());
        assert!(id_bytes(&"gg".repeat(16)).is_err());
        assert_eq!(id_string([0xab; 16]), "ab".repeat(16));
    }

    #[test]
    fn hello_ack_verifiers_and_pmtu_helpers_cover_rejection_boundaries() {
        let key = crate::identity::generate();
        let identity = crate::identity::node_id(&key.verifying_key());
        let public_key = crate::identity::encode_public(&key.verifying_key());
        let nonce = [7; 32];
        let hello = Hello {
            identity: identity.clone(),
            public_key: public_key.clone(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            sender_receive_id: 11,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: Some(750),
            signature: sign_hello_with_rate(
                &key,
                &identity,
                &public_key,
                &nonce,
                11,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                Some(750),
            ),
        };
        let encoded = hello.encode().unwrap();
        let rate_offset = 3 + 16 + 32 + 32 + 4 + 4;
        for rate in [0_u16, crate::fec::MAX_RATE_MILLI + 1] {
            let mut invalid = encoded.clone();
            invalid[rate_offset..rate_offset + 2].copy_from_slice(&rate.to_be_bytes());
            assert!(Hello::decode(&invalid).is_err());
        }

        let ack = Ack {
            identity: identity.clone(),
            public_key: public_key.clone(),
            sender_receive_id: 12,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: Some(750),
            signature: sign_ack_with_rate(
                &key,
                &identity,
                &public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                Some(750),
            ),
        };
        let encoded_ack = ack.encode().unwrap();
        let ack_rate_offset = 3 + 16 + 32 + 4 + 4;
        for rate in [0_u16, crate::fec::MAX_RATE_MILLI + 1] {
            let mut invalid = encoded_ack.clone();
            invalid[ack_rate_offset..ack_rate_offset + 2].copy_from_slice(&rate.to_be_bytes());
            assert!(Ack::decode(&invalid).is_err());
        }
        assert!(verify_ack_with_rate(&ack, "ignored", &public_key, &nonce).is_ok());
        let mut invalid_ack = ack;
        invalid_ack.identity = "00".repeat(16);
        assert!(verify_ack_with_rate(&invalid_ack, "ignored", &public_key, &nonce).is_err());
        assert!(
            verify_signed_receive_id_with_rate(
                &key.verifying_key(),
                &identity,
                &public_key,
                &nonce,
                0,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                None,
                "",
            )
            .is_err()
        );

        assert!(pmtu_should_retry_candidate(None));
        assert!(pmtu_should_retry_candidate(Some(
            PmtuFailureReason::AckTimeout
        )));
        assert!(!pmtu_should_retry_candidate(Some(
            PmtuFailureReason::LocalOversize
        )));
        let now = Instant::now();
        assert!(!pmtu_upward_reprobe_due(None, now));
        assert!(!pmtu_upward_reprobe_due(
            Some(now + Duration::from_secs(1)),
            now
        ));
        assert!(pmtu_upward_reprobe_due(Some(now), now));
    }

    #[test]
    fn bare_udp_send_errno_classification_keeps_pmtu_errors_distinct() {
        assert!(is_local_oversize_errno(libc::EMSGSIZE));
        assert!(is_local_backpressure_errno(libc::EAGAIN));
        assert!(is_local_backpressure_errno(libc::ENOBUFS));
        assert!(!is_local_oversize_errno(libc::EIO));
    }

    #[test]
    fn carrier_and_link_errors_preserve_local_admission_boundaries() {
        for error in [
            crate::link::LinkError::AdmissionRejected,
            crate::link::LinkError::ControlStreamTimeout,
            crate::link::LinkError::WouldBlock,
            crate::link::LinkError::EndpointClosed,
        ] {
            let carrier: CarrierError = error.clone().into();
            let round_trip: crate::link::LinkError = carrier.into();
            assert_eq!(round_trip, error);
        }
        let error = crate::link::LinkError::DatagramTooLarge {
            size: 1400,
            limit: 1200,
        };
        let carrier: CarrierError = error.clone().into();
        assert!(matches!(
            carrier,
            CarrierError::DatagramTooLarge {
                size: 1400,
                limit: 1200
            }
        ));
        let error = crate::link::LinkError::Transport("transport failed".into());
        assert!(matches!(
            CarrierError::from(error),
            CarrierError::Protocol(message) if message == "transport failed"
        ));

        assert!(is_local_oversize_message("MESSAGE TOO LONG"));
        assert!(is_local_oversize_message("send failed: EMSGSIZE"));
        assert!(is_local_oversize_message("os error 90"));
        assert!(!is_local_oversize_message("connection reset"));
        assert!(matches!(
            classify_quic_datagram_error(quinn::SendDatagramError::TooLarge, 1400, None,),
            CarrierError::DatagramTooLarge {
                size: 1400,
                limit: 1399
            }
        ));
    }

    #[tokio::test]
    async fn bare_udp_physical_uses_the_same_socket_as_quic_handshake() {
        let server_key = crate::identity::generate();
        let client_key = crate::identity::generate();
        let server_public = crate::identity::encode_public(&server_key.verifying_key());
        let (server, server_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let peers = BTreeMap::from([(
            "client".to_owned(),
            crate::config::Peer {
                public_key: crate::identity::encode_public(&client_key.verifying_key()),
                endpoints: vec![],
                upstream_dns: None,
                accept_connections: Some(true),
                allow_transit: None,
                allow_relay: None,
                bind_addresses: vec![],
                routes: vec![],
                paths: vec![],
            },
        )]);
        let server_bare_for_task = server_bare.clone();
        let server_task = tokio::spawn(async move {
            accept_with_bare(
                &server,
                server_bare_for_task.as_ref(),
                CarrierProtocol::Quic,
                &peers,
                false,
                "server",
                &server_key,
            )
            .await
            .unwrap()
        });
        let (client, client_bare) = endpoint_with_options_and_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            &LinkHealthConfig::default(),
            None,
            None,
            Some(crate::config::DEFAULT_FAKE_TCP_RESET_KEY.as_bytes()),
        )
        .unwrap();
        let client_link = connect_with_link_health_and_bare(
            &client,
            client_bare.as_ref(),
            address,
            CarrierProtocol::Quic,
            "server",
            &server_public,
            "client",
            &client_key,
            &LinkHealthConfig::default(),
        )
        .await
        .unwrap();
        client_link
            .send_physical(PhysicalPayload::Probe {
                probe_id: 7,
                target_len: 1201,
                padding: vec![0; 1201 - 39],
            })
            .unwrap();
        let server_link = Arc::new(server_task.await.unwrap());
        let receiver_link = server_link.clone();
        let receiver = tokio::spawn(async move { receiver_link.recv_physical().await.unwrap() });
        // A PMTU probe is itself authenticated carrier activity.  It must
        // keep the link alive even though recv_physical consumes it rather
        // than returning it to the caller.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(server_link.rx_idle_for() < Duration::from_secs(1));
        let mut frame = vec![1; 24];
        frame.extend_from_slice(&[2; 8]);
        frame.extend_from_slice(&[3; 16]);
        client_link
            .send_physical(PhysicalPayload::Forward(frame.clone()))
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), receiver)
                .await
                .expect("bare packet should be routed")
                .unwrap(),
            PhysicalPayload::Forward(frame)
        );

        let forwarded = vec![4; crate::crypto::FRAME_OVERHEAD + 3];
        client_link.send_forward(&forwarded).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server_link.recv_physical())
                .await
                .expect("bare send_forward packet should be routed")
                .unwrap(),
            PhysicalPayload::Forward(forwarded)
        );

        let receiver_link = server_link.clone();
        let closed_receiver = tokio::spawn(async move { receiver_link.recv_physical().await });
        // A bare-UDP receiver must follow the QUIC control connection's
        // lifetime.  Otherwise a reconnect leaves the old PMTU/physical
        // workers holding the Link alive and sending frames encrypted with
        // the superseded session key.
        client_link.close("test shutdown");
        let result = tokio::time::timeout(Duration::from_secs(2), closed_receiver)
            .await
            .expect("closed QUIC link should stop bare receiver")
            .expect("receiver task should join");
        assert!(matches!(result, Err(CarrierError::EndpointClosed)));
    }

    #[test]
    fn hello_and_ack_encode_reject_zero_receive_ids_and_invalid_base64() {
        let key = crate::identity::generate();
        let identity = crate::identity::node_id(&key.verifying_key());
        let public_key = crate::identity::encode_public(&key.verifying_key());
        let nonce = [4; 32];
        let signature = |receive_id: u32| {
            sign_hello(
                &key,
                &identity,
                &public_key,
                &nonce,
                receive_id,
                CAP_RELIABLE_TOPOLOGY_STREAM,
            )
        };
        let hello = |receive_id: u32, public_key: String, nonce: String, signature: String| Hello {
            identity: identity.clone(),
            public_key,
            nonce,
            sender_receive_id: receive_id,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature,
        };
        let valid_nonce = || STANDARD_NO_PAD.encode(nonce);
        assert!(matches!(
            hello(0, public_key.clone(), valid_nonce(), signature(11)).encode(),
            Err(CarrierError::Protocol(message)) if message == "zero receive id"
        ));
        assert!(matches!(
            hello(11, "not base64!!".into(), valid_nonce(), signature(11)).encode(),
            Err(CarrierError::Identity(_))
        ));
        assert!(matches!(
            hello(11, public_key.clone(), "not base64!!".into(), signature(11)).encode(),
            Err(CarrierError::Protocol(_))
        ));
        assert!(matches!(
            hello(11, public_key.clone(), valid_nonce(), "not base64!!".into()).encode(),
            Err(CarrierError::Identity(_))
        ));

        let ack = |receive_id: u32, public_key: String, signature: String| Ack {
            identity: identity.clone(),
            public_key,
            sender_receive_id: receive_id,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature,
        };
        assert!(matches!(
            ack(0, public_key.clone(), signature(12)).encode(),
            Err(CarrierError::Protocol(message)) if message == "zero receive id"
        ));
        assert!(matches!(
            ack(12, "not base64!!".into(), signature(12)).encode(),
            Err(CarrierError::Identity(_))
        ));
        assert!(matches!(
            ack(12, public_key.clone(), "not base64!!".into()).encode(),
            Err(CarrierError::Identity(_))
        ));
    }

    #[test]
    fn hello_and_ack_decode_reject_unknown_extension_lengths() {
        let key = crate::identity::generate();
        let identity = crate::identity::node_id(&key.verifying_key());
        let public_key = crate::identity::encode_public(&key.verifying_key());
        let nonce = [6; 32];
        let hello = Hello {
            identity: identity.clone(),
            public_key: public_key.clone(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            sender_receive_id: 11,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature: sign_hello(
                &key,
                &identity,
                &public_key,
                &nonce,
                11,
                CAP_RELIABLE_TOPOLOGY_STREAM,
            ),
        };
        let encoded = hello.encode().unwrap();
        let (kind, body) = crate::wire::decode_message(&encoded).unwrap();
        assert_eq!(kind, 1);
        // Insert one byte between the fixed header and the signature so the
        // remaining length (65) matches neither the plain (64) nor the FEC
        // (66) extension form.  Re-framing keeps the wire length prefix
        // consistent, unlike a raw byte insertion into the encoded message.
        let mut extended = body.to_vec();
        extended.insert(extended.len() - 64, 0);
        let reframed = crate::wire::encode_message(1, extended).unwrap();
        assert!(matches!(
            Hello::decode(&reframed),
            Err(CarrierError::Protocol(message)) if message == "invalid hello FEC extension"
        ));
        let mut extended = body.to_vec();
        for _ in 0..3 {
            extended.insert(extended.len() - 64, 0);
        }
        let reframed = crate::wire::encode_message(1, extended).unwrap();
        assert!(matches!(
            Hello::decode(&reframed),
            Err(CarrierError::Protocol(message)) if message == "invalid hello FEC extension"
        ));

        let ack = Ack {
            identity: identity.clone(),
            public_key: public_key.clone(),
            sender_receive_id: 12,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature: sign_ack(
                &key,
                &identity,
                &public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
            ),
        };
        let encoded = ack.encode().unwrap();
        let (kind, body) = crate::wire::decode_message(&encoded).unwrap();
        assert_eq!(kind, 2);
        let mut extended = body.to_vec();
        extended.insert(extended.len() - 64, 0);
        let reframed = crate::wire::encode_message(2, extended).unwrap();
        assert!(matches!(
            Ack::decode(&reframed),
            Err(CarrierError::Protocol(message)) if message == "invalid acknowledgement FEC extension"
        ));
    }

    #[test]
    fn ack_and_receive_id_verification_reject_malformed_inputs() {
        let key = crate::identity::generate();
        let other = crate::identity::generate();
        let identity = crate::identity::node_id(&key.verifying_key());
        let public_key = crate::identity::encode_public(&key.verifying_key());
        let nonce = [8; 32];
        let ack = |signature: String| Ack {
            identity: identity.clone(),
            public_key: public_key.clone(),
            sender_receive_id: 12,
            capabilities: CAP_RELIABLE_TOPOLOGY_STREAM,
            repair_rate: None,
            signature,
        };
        let valid = || {
            ack(sign_ack(
                &key,
                &identity,
                &public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
            ))
        };
        // An undecodable expected key is an identity error, not a crash.
        assert!(matches!(
            verify_ack_with_rate(&valid(), "ignored", "not base64!!", &nonce),
            Err(CarrierError::Identity(_))
        ));
        // A well-formed but unexpected key rejects the ack identity.
        let wrong_public = crate::identity::encode_public(&other.verifying_key());
        assert!(matches!(
            verify_ack_with_rate(&valid(), "ignored", &wrong_public, &nonce),
            Err(CarrierError::Identity(message)) if message == "unexpected peer identity"
        ));
        // Malformed signature encodings and foreign signatures are rejected.
        assert!(matches!(
            verify_ack_with_rate(&ack("not base64!!".into()), "ignored", &public_key, &nonce),
            Err(CarrierError::Identity(_))
        ));
        assert!(matches!(
            verify_ack_with_rate(
                &ack(STANDARD_NO_PAD.encode([0; 32])),
                "ignored",
                &public_key,
                &nonce,
            ),
            Err(CarrierError::Identity(_))
        ));
        let foreign = ack(sign_ack(
            &other,
            &identity,
            &public_key,
            &nonce,
            12,
            CAP_RELIABLE_TOPOLOGY_STREAM,
        ));
        assert!(matches!(
            verify_ack_with_rate(&foreign, "ignored", &public_key, &nonce),
            Err(CarrierError::Identity(_))
        ));

        let verifying = key.verifying_key();
        assert!(
            verify_signed_receive_id_with_rate(
                &verifying,
                &identity,
                &public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                Some(750),
                &sign_hello_with_rate(
                    &key,
                    &identity,
                    &public_key,
                    &nonce,
                    12,
                    CAP_RELIABLE_TOPOLOGY_STREAM,
                    Some(750),
                ),
            )
            .is_ok()
        );
        // A signature that omits the negotiated repair rate must not verify.
        assert!(
            verify_signed_receive_id_with_rate(
                &verifying,
                &identity,
                &public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                Some(750),
                &sign_hello(
                    &key,
                    &identity,
                    &public_key,
                    &nonce,
                    12,
                    CAP_RELIABLE_TOPOLOGY_STREAM
                ),
            )
            .is_err()
        );
        assert!(
            verify_signed_receive_id_with_rate(
                &verifying,
                &identity,
                &public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                None,
                "not base64!!",
            )
            .is_err()
        );
        assert!(
            verify_signed_receive_id_with_rate(
                &verifying,
                &identity,
                &public_key,
                &nonce,
                12,
                CAP_RELIABLE_TOPOLOGY_STREAM,
                None,
                &STANDARD_NO_PAD.encode([0; 32]),
            )
            .is_err()
        );
    }

    #[test]
    fn carrier_error_conversion_maps_oversize_and_transport_fallback() {
        let link: crate::link::LinkError = CarrierError::DatagramTooLarge {
            size: 1_400,
            limit: 1_200,
        }
        .into();
        assert_eq!(
            link,
            crate::link::LinkError::DatagramTooLarge {
                size: 1_400,
                limit: 1_200
            }
        );
        let link: crate::link::LinkError = CarrierError::Protocol("boom".into()).into();
        assert_eq!(
            link,
            crate::link::LinkError::Transport("protocol error: boom".into())
        );
    }
}
