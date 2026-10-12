use crate::{
    carrier::LinkMetrics,
    observability::{Observability, TrafficCounters},
    wire::{self, Reader, Writer},
};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::BTreeMap, fmt::Write as _, io, path::Path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Notify, RwLock, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

const MAX_METRICS_CONNECTIONS: usize = 64;
const METRICS_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const METRICS_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

mod management;

pub use management::{serve, serve_until_cancelled};
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_identity: Option<String>,
    pub links: Vec<LinkStatus>,
    pub circuits: Vec<CircuitStatus>,
    pub flow_count: usize,
    pub topology_nodes: usize,
    pub topology_generation: u64,
    pub supervised_tasks: usize,
    pub shutting_down: bool,
    pub last_shutdown_error: Option<String>,
    pub circuit_traffic: BTreeMap<String, TrafficCounters>,
    pub acl_rejections: BTreeMap<String, u64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct LinkStatus {
    pub peer: String,
    pub peer_identity: String,
    pub healthy: bool,
    pub last_error: Option<String>,
    pub metrics: Option<LinkMetrics>,
}
#[derive(Debug, Clone, Serialize)]
pub struct CircuitStatus {
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_identity: Option<String>,
    pub active_path: Vec<String>,
    /// Names aligned with `active_path`; unknown topology nodes are `null`.
    pub active_path_names: Vec<Option<String>>,
    pub healthy: bool,
    pub migration_state: MigrationState,
    pub preferred_path: Vec<String>,
    pub preferred_path_names: Vec<Option<String>>,
    pub migration_started_at: Option<u64>,
    pub migration_last_error: Option<String>,
}

/// Local lifecycle state exposed by the management status API. This is not a
/// circuit wire-frame state: peers remain compatible while a source retries a
/// preferred-path migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum MigrationState {
    #[default]
    Stable,
    MigrationPending,
    MigrationOverdue,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteStatus {
    pub selector: String,
    pub entries: usize,
    pub candidates: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DaemonState {
    pub status: Status,
    pub routes: Vec<RouteStatus>,
    #[serde(skip)]
    pub observability: Arc<Observability>,
    #[serde(skip)]
    pub topology_dot: String,
    /// Management and metrics requests wake the status refresher on demand
    /// instead of a fixed polling task.
    #[serde(skip)]
    pub status_refresh_requested: Arc<Notify>,
    #[serde(skip)]
    pub status_refresh_done: Arc<Notify>,
    /// Set by requesters before notifying so a wake-up that lands while the
    /// refresher is already busy (or not yet registered) cannot be lost.
    #[serde(skip)]
    pub status_refresh_pending: Arc<AtomicBool>,
}

/// Ask the daemon's status refresher to pull a fresh snapshot and wait
/// (bounded) for it.  The refresh is best-effort: if the refresher is busy
/// or the request races a completed refresh, the caller proceeds with the
/// current snapshot rather than blocking the management socket.
pub(crate) async fn request_status_refresh(state: &Arc<RwLock<DaemonState>>) {
    let done = {
        let daemon = state.read().await;
        daemon.status_refresh_done.clone()
    };
    let notified = done.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    state
        .read()
        .await
        .status_refresh_pending
        .store(true, Ordering::Release);
    state.read().await.status_refresh_requested.notify_waiters();
    // The refresher coalesces bursts to at most once per second; a caller
    // that loses this race (or arrives during the quiet period) must not
    // block the management socket for a full refresh interval.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(50), notified).await;
}

/// Binary local management opcode. Request: opcode:u8|body_length:u16|body.
/// Response chunks: opcode:u8|status:u8|body_length:u16|body, terminated by EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ManagementOpcode {
    Status = 1,
    Routes = 2,
    Topology = 3,
    Pcap = 4,
}
impl TryFrom<u8> for ManagementOpcode {
    type Error = io::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Status),
            2 => Ok(Self::Routes),
            3 => Ok(Self::Topology),
            4 => Ok(Self::Pcap),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown management opcode",
            )),
        }
    }
}
pub enum ManagementRequest {
    Opcode(ManagementOpcode),
}
impl From<ManagementOpcode> for ManagementRequest {
    fn from(value: ManagementOpcode) -> Self {
        Self::Opcode(value)
    }
}
impl From<&str> for ManagementRequest {
    fn from(value: &str) -> Self {
        let opcode = match value.trim() {
            "status" => ManagementOpcode::Status,
            "routes" => ManagementOpcode::Routes,
            "topology" => ManagementOpcode::Topology,
            "pcap" => ManagementOpcode::Pcap,
            _ => ManagementOpcode::Status,
        };
        Self::Opcode(opcode)
    }
}

fn count(value: usize) -> Result<u16, wire::Error> {
    value.try_into().map_err(|_| wire::Error::Length)
}

fn encode_metrics(out: &mut Writer, metrics: &LinkMetrics) {
    for value in [
        metrics.tx_datagrams,
        metrics.tx_bytes,
        metrics.rx_datagrams,
        metrics.rx_bytes,
        metrics.datagram_max_size,
        metrics.datagram_queue_drops,
        metrics.datagram_wire_oversize,
        metrics.stream_admission_rejections,
        metrics.datagram_admission_rejections,
        metrics.forward_queue_drops,
        metrics.datagram_send_errors,
        metrics.pmtu_local_oversize,
        metrics.pmtu_queue_pressure,
        metrics.pmtu_ack_timeouts,
        metrics.pmtu_peer_teardowns,
        metrics.pmtu_protocol_errors,
    ] {
        out.u64(value);
    }
    out.u8(metrics.fec_enabled as u8);
    out.u16(metrics.fec_repair_rate_milli);
    for value in [
        metrics.fec_loss_ppm,
        metrics.fec_loss_samples,
        metrics.fec_tx_repairs,
        metrics.fec_rx_sources,
        metrics.fec_rx_repairs,
        metrics.fec_recovered,
        metrics.fec_lost,
        metrics.fec_discarded,
        metrics.fec_rate_limited,
        metrics.fec_reordered,
        metrics.fec_invalid,
        metrics.fec_feedback_sent,
        metrics.fec_feedback_retries,
    ] {
        out.u64(value);
    }
}

fn decode_metrics(input: &mut Reader<'_>) -> Result<LinkMetrics, wire::Error> {
    Ok(LinkMetrics {
        tx_datagrams: input.u64()?,
        tx_bytes: input.u64()?,
        rx_datagrams: input.u64()?,
        rx_bytes: input.u64()?,
        datagram_max_size: input.u64()?,
        datagram_queue_drops: input.u64()?,
        datagram_wire_oversize: input.u64()?,
        stream_admission_rejections: input.u64()?,
        datagram_admission_rejections: input.u64()?,
        forward_queue_drops: input.u64()?,
        datagram_send_errors: input.u64()?,
        pmtu_local_oversize: input.u64()?,
        pmtu_queue_pressure: input.u64()?,
        pmtu_ack_timeouts: input.u64()?,
        pmtu_peer_teardowns: input.u64()?,
        pmtu_protocol_errors: input.u64()?,
        fec_enabled: input.bool()?,
        fec_repair_rate_milli: input.u16()?,
        fec_loss_ppm: input.u64()?,
        fec_loss_samples: input.u64()?,
        fec_tx_repairs: input.u64()?,
        fec_rx_sources: input.u64()?,
        fec_rx_repairs: input.u64()?,
        fec_recovered: input.u64()?,
        fec_lost: input.u64()?,
        fec_discarded: input.u64()?,
        fec_rate_limited: input.u64()?,
        fec_reordered: input.u64()?,
        fec_invalid: input.u64()?,
        fec_feedback_sent: input.u64()?,
        fec_feedback_retries: input.u64()?,
    })
}

pub fn encode_status(value: &Status) -> Result<Vec<u8>, wire::Error> {
    let mut out = Writer::new();
    out.string(&value.node)?;
    out.optional_string(value.node_identity.as_deref())?;
    out.u16(count(value.links.len())?);
    for link in &value.links {
        out.string(&link.peer)?;
        out.string(&link.peer_identity)?;
        out.u8(link.healthy as u8);
        out.optional_string(link.last_error.as_deref())?;
        out.u8(link.metrics.is_some() as u8);
        if let Some(metrics) = &link.metrics {
            encode_metrics(&mut out, metrics);
        }
    }
    out.u16(count(value.circuits.len())?);
    for circuit in &value.circuits {
        out.string(&circuit.destination)?;
        out.optional_string(circuit.destination_identity.as_deref())?;
        out.u16(count(circuit.active_path.len())?);
        for node in &circuit.active_path {
            out.string(node)?;
        }
        out.u16(count(circuit.active_path_names.len())?);
        for name in &circuit.active_path_names {
            out.optional_string(name.as_deref())?;
        }
        out.u8(circuit.healthy as u8);
        out.u8(match circuit.migration_state {
            MigrationState::Stable => 0,
            MigrationState::MigrationPending => 1,
            MigrationState::MigrationOverdue => 2,
        });
        out.u16(count(circuit.preferred_path.len())?);
        for node in &circuit.preferred_path {
            out.string(node)?;
        }
        out.u16(count(circuit.preferred_path_names.len())?);
        for name in &circuit.preferred_path_names {
            out.optional_string(name.as_deref())?;
        }
        out.u8(circuit.migration_started_at.is_some() as u8);
        if let Some(started_at) = circuit.migration_started_at {
            out.u64(started_at);
        }
        out.optional_string(circuit.migration_last_error.as_deref())?;
    }
    out.u64(value.flow_count as u64);
    out.u64(value.topology_nodes as u64);
    out.u64(value.topology_generation);
    out.u64(value.supervised_tasks as u64);
    out.u8(value.shutting_down as u8);
    out.optional_string(value.last_shutdown_error.as_deref())?;
    out.u16(count(value.circuit_traffic.len())?);
    for (name, traffic) in &value.circuit_traffic {
        out.string(name)?;
        out.u64(traffic.tx_packets);
        out.u64(traffic.tx_bytes);
        out.u64(traffic.rx_packets);
        out.u64(traffic.rx_bytes);
    }
    out.u16(count(value.acl_rejections.len())?);
    for (reason, value) in &value.acl_rejections {
        out.string(reason)?;
        out.u64(*value);
    }
    Ok(out.finish())
}

pub fn decode_status(bytes: &[u8]) -> Result<Status, wire::Error> {
    let mut input = Reader::new(bytes);
    let node = input.string()?;
    let node_identity = input.optional_string()?;
    let mut links = Vec::new();
    for _ in 0..input.u16()? {
        let peer = input.string()?;
        let peer_identity = input.string()?;
        let healthy = input.bool()?;
        let last_error = input.optional_string()?;
        let metrics = if input.bool()? {
            Some(decode_metrics(&mut input)?)
        } else {
            None
        };
        links.push(LinkStatus {
            peer,
            peer_identity,
            healthy,
            last_error,
            metrics,
        });
    }
    let mut circuits = Vec::new();
    for _ in 0..input.u16()? {
        let destination = input.string()?;
        let destination_identity = input.optional_string()?;
        let mut active_path = Vec::new();
        for _ in 0..input.u16()? {
            active_path.push(input.string()?);
        }
        let mut active_path_names = Vec::new();
        for _ in 0..input.u16()? {
            active_path_names.push(input.optional_string()?);
        }
        let healthy = input.bool()?;
        let migration_state = match input.u8()? {
            0 => MigrationState::Stable,
            1 => MigrationState::MigrationPending,
            2 => MigrationState::MigrationOverdue,
            _ => return Err(wire::Error::Bool),
        };
        let mut preferred_path = Vec::new();
        for _ in 0..input.u16()? {
            preferred_path.push(input.string()?);
        }
        let mut preferred_path_names = Vec::new();
        for _ in 0..input.u16()? {
            preferred_path_names.push(input.optional_string()?);
        }
        let migration_started_at = if input.bool()? {
            Some(input.u64()?)
        } else {
            None
        };
        let migration_last_error = input.optional_string()?;
        circuits.push(CircuitStatus {
            destination,
            destination_identity,
            active_path,
            active_path_names,
            healthy,
            migration_state,
            preferred_path,
            preferred_path_names,
            migration_started_at,
            migration_last_error,
        });
    }
    let flow_count = input.u64()? as usize;
    let topology_nodes = input.u64()? as usize;
    let topology_generation = input.u64()?;
    let supervised_tasks = input.u64()? as usize;
    let shutting_down = input.bool()?;
    let last_shutdown_error = input.optional_string()?;
    let mut circuit_traffic = BTreeMap::new();
    for _ in 0..input.u16()? {
        let name = input.string()?;
        circuit_traffic.insert(
            name,
            TrafficCounters {
                tx_packets: input.u64()?,
                tx_bytes: input.u64()?,
                rx_packets: input.u64()?,
                rx_bytes: input.u64()?,
            },
        );
    }
    let mut acl_rejections = BTreeMap::new();
    for _ in 0..input.u16()? {
        acl_rejections.insert(input.string()?, input.u64()?);
    }
    input.finish()?;
    Ok(Status {
        node,
        node_identity,
        links,
        circuits,
        flow_count,
        topology_nodes,
        topology_generation,
        supervised_tasks,
        shutting_down,
        last_shutdown_error,
        circuit_traffic,
        acl_rejections,
    })
}

pub fn encode_routes(routes: &[RouteStatus]) -> Result<Vec<u8>, wire::Error> {
    let mut out = Writer::new();
    out.u16(count(routes.len())?);
    for route in routes {
        out.string(&route.selector)?;
        out.u32(u32::try_from(route.entries).map_err(|_| wire::Error::Length)?);
        out.u16(count(route.candidates.len())?);
        for candidate in &route.candidates {
            out.string(candidate)?;
        }
    }
    Ok(out.finish())
}
pub fn decode_routes(bytes: &[u8]) -> Result<Vec<RouteStatus>, wire::Error> {
    let mut input = Reader::new(bytes);
    let mut routes = Vec::new();
    for _ in 0..input.u16()? {
        let selector = input.string()?;
        let entries = input.u32()? as usize;
        let mut candidates = Vec::new();
        for _ in 0..input.u16()? {
            candidates.push(input.string()?);
        }
        routes.push(RouteStatus {
            selector,
            entries,
            candidates,
        });
    }
    input.finish()?;
    Ok(routes)
}

pub async fn request(
    path: impl AsRef<Path>,
    request: impl Into<ManagementRequest>,
) -> io::Result<Vec<u8>> {
    let ManagementRequest::Opcode(opcode) = request.into();
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    stream.write_all(&[opcode as u8, 0, 0]).await?;
    stream.shutdown().await?;
    let mut reply = Vec::new();
    loop {
        let mut header = [0; 4];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        }
        if header[0] != opcode as u8 || header[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "management response rejected",
            ));
        }
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let start = reply.len();
        reply.resize(start + length, 0);
        stream.read_exact(&mut reply[start..]).await?;
    }
    Ok(reply)
}

pub fn prometheus(state: &DaemonState) -> String {
    let dataplane = state.observability.snapshot().dataplane;
    let healthy_links = state
        .status
        .links
        .iter()
        .filter(|link| link.healthy)
        .count();
    let healthy_circuits = state
        .status
        .circuits
        .iter()
        .filter(|circuit| circuit.healthy)
        .count();
    let mut output = format!(
        "# TYPE tinect_links_healthy gauge\n\
tinect_links_healthy {healthy_links}\n\
# TYPE tinect_circuits_healthy gauge\n\
tinect_circuits_healthy {healthy_circuits}\n\
# TYPE tinect_flows gauge\n\
tinect_flows {}\n\
# TYPE tinect_topology_nodes gauge\n\
tinect_topology_nodes {}\n\
# TYPE tinect_topology_generation gauge\n\
tinect_topology_generation {}\n",
        state.status.flow_count, state.status.topology_nodes, state.status.topology_generation
    );
    writeln!(
        output,
        "# TYPE tinect_tun_rx_packets counter\ntinect_tun_rx_packets {}\n# TYPE tinect_tun_rx_bytes counter\ntinect_tun_rx_bytes {}\n# TYPE tinect_tun_tx_packets counter\ntinect_tun_tx_packets {}\n# TYPE tinect_tun_tx_bytes counter\ntinect_tun_tx_bytes {}\n# TYPE tinect_route_lookups counter\ntinect_route_lookups {}\n# TYPE tinect_route_lookup_seconds_total counter\ntinect_route_lookup_seconds_total {}\n# TYPE tinect_fake_ip_dns_queries counter\ntinect_fake_ip_dns_queries {}\n# TYPE tinect_fake_ip_dns_matches counter\ntinect_fake_ip_dns_matches {}\n# TYPE tinect_fake_ip_dns_failures counter\ntinect_fake_ip_dns_failures {}\n# TYPE tinect_fake_ip_mappings gauge\ntinect_fake_ip_mappings {}\n# TYPE tinect_fake_ip_flows gauge\ntinect_fake_ip_flows {}",
        dataplane.tun_rx_packets,
        dataplane.tun_rx_bytes,
        dataplane.tun_tx_packets,
        dataplane.tun_tx_bytes,
        dataplane.route_lookups,
        dataplane.route_lookup_nanos as f64 / 1_000_000_000.0,
        dataplane.fake_ip_dns_queries,
        dataplane.fake_ip_dns_matches,
        dataplane.fake_ip_dns_failures,
        dataplane.fake_ip_mappings,
        dataplane.fake_ip_flows,
    )
    .expect("writing to String");
    output.push_str(
        "# TYPE tinect_circuit_tx_bytes counter\n# TYPE tinect_circuit_rx_bytes counter\n",
    );
    output.push_str(
        "# TYPE tinect_link_datagram_max_size gauge\n# TYPE tinect_link_datagram_queue_drops counter\n# TYPE tinect_link_datagram_wire_oversize counter\n# TYPE tinect_link_stream_admission_rejections counter\n# TYPE tinect_link_datagram_admission_rejections counter\n# TYPE tinect_link_forward_queue_drops counter\n# TYPE tinect_link_datagram_send_errors counter\n# TYPE tinect_link_pmtu_local_oversize counter\n# TYPE tinect_link_pmtu_queue_pressure counter\n# TYPE tinect_link_pmtu_ack_timeouts counter\n# TYPE tinect_link_pmtu_peer_teardowns counter\n# TYPE tinect_link_pmtu_protocol_errors counter\n# TYPE tinect_link_fec_enabled gauge\n# TYPE tinect_link_fec_repair_rate_milli gauge\n# TYPE tinect_link_fec_loss_ppm gauge\n# TYPE tinect_link_fec_loss_samples gauge\n# TYPE tinect_link_fec_tx_repairs counter\n# TYPE tinect_link_fec_rx_sources counter\n# TYPE tinect_link_fec_rx_repairs counter\n# TYPE tinect_link_fec_recovered counter\n# TYPE tinect_link_fec_lost counter\n# TYPE tinect_link_fec_discarded counter\n# TYPE tinect_link_fec_rate_limited counter\n# TYPE tinect_link_fec_reordered counter\n# TYPE tinect_link_fec_invalid counter\n# TYPE tinect_link_fec_feedback_sent counter\n# TYPE tinect_link_fec_feedback_retries counter\n",
    );
    for link in &state.status.links {
        let peer = prometheus_label_value(&link.peer);
        if let Some(metrics) = &link.metrics {
            writeln!(
                output,
                "tinect_link_datagram_max_size{{peer=\"{peer}\"}} {}",
                metrics.datagram_max_size
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_datagram_queue_drops{{peer=\"{peer}\"}} {}",
                metrics.datagram_queue_drops
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_datagram_wire_oversize{{peer=\"{peer}\"}} {}",
                metrics.datagram_wire_oversize
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_stream_admission_rejections{{peer=\"{peer}\"}} {}",
                metrics.stream_admission_rejections
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_datagram_admission_rejections{{peer=\"{peer}\"}} {}",
                metrics.datagram_admission_rejections
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_forward_queue_drops{{peer=\"{peer}\"}} {}",
                metrics.forward_queue_drops
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_datagram_send_errors{{peer=\"{peer}\"}} {}",
                metrics.datagram_send_errors
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_pmtu_local_oversize{{peer=\"{peer}\"}} {}",
                metrics.pmtu_local_oversize
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_pmtu_queue_pressure{{peer=\"{peer}\"}} {}",
                metrics.pmtu_queue_pressure
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_pmtu_ack_timeouts{{peer=\"{peer}\"}} {}",
                metrics.pmtu_ack_timeouts
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_pmtu_peer_teardowns{{peer=\"{peer}\"}} {}",
                metrics.pmtu_peer_teardowns
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_pmtu_protocol_errors{{peer=\"{peer}\"}} {}",
                metrics.pmtu_protocol_errors
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_enabled{{peer=\"{peer}\"}} {}",
                metrics.fec_enabled as u8
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_repair_rate_milli{{peer=\"{peer}\"}} {}",
                metrics.fec_repair_rate_milli
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_loss_ppm{{peer=\"{peer}\"}} {}",
                metrics.fec_loss_ppm
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_loss_samples{{peer=\"{peer}\"}} {}",
                metrics.fec_loss_samples
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_tx_repairs{{peer=\"{peer}\"}} {}",
                metrics.fec_tx_repairs
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_rx_sources{{peer=\"{peer}\"}} {}",
                metrics.fec_rx_sources
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_rx_repairs{{peer=\"{peer}\"}} {}",
                metrics.fec_rx_repairs
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_recovered{{peer=\"{peer}\"}} {}",
                metrics.fec_recovered
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_lost{{peer=\"{peer}\"}} {}",
                metrics.fec_lost
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_discarded{{peer=\"{peer}\"}} {}",
                metrics.fec_discarded
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_rate_limited{{peer=\"{peer}\"}} {}",
                metrics.fec_rate_limited
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_reordered{{peer=\"{peer}\"}} {}",
                metrics.fec_reordered
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_invalid{{peer=\"{peer}\"}} {}",
                metrics.fec_invalid
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_feedback_sent{{peer=\"{peer}\"}} {}",
                metrics.fec_feedback_sent
            )
            .expect("writing to String");
            writeln!(
                output,
                "tinect_link_fec_feedback_retries{{peer=\"{peer}\"}} {}",
                metrics.fec_feedback_retries
            )
            .expect("writing to String");
        }
    }
    for (name, traffic) in &state.status.circuit_traffic {
        let name = prometheus_label_value(name);
        // Writing into a String cannot fail.
        writeln!(
            output,
            "tinect_circuit_tx_bytes{{circuit=\"{name}\"}} {}",
            traffic.tx_bytes
        )
        .expect("writing to String");
        writeln!(
            output,
            "tinect_circuit_rx_bytes{{circuit=\"{name}\"}} {}",
            traffic.rx_bytes
        )
        .expect("writing to String");
    }
    output.push_str("# TYPE tinect_acl_rejections_total counter\n");
    for (reason, count) in &state.status.acl_rejections {
        let reason = prometheus_label_value(reason);
        writeln!(
            output,
            "tinect_acl_rejections_total{{reason=\"{reason}\"}} {count}"
        )
        .expect("writing to String");
    }
    output
}

/// Escapes a value embedded in a Prometheus label. Configuration values and
/// policy errors can contain arbitrary text, so they must never be inserted
/// into the exposition format verbatim.
fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

/// Minimal dependency-free Prometheus text endpoint. It intentionally serves
/// only GET /metrics and should normally be bound to loopback.
pub async fn serve_metrics(
    bind: std::net::SocketAddr,
    state: Arc<RwLock<DaemonState>>,
) -> io::Result<()> {
    serve_metrics_until_cancelled(bind, state, CancellationToken::new()).await
}

/// Serves the local Prometheus endpoint until `cancellation` is triggered.
///
/// Metric requests are bounded in both concurrency and total processing time.
/// The listener waits for every accepted request task to observe cancellation
/// before returning, so callers can safely release the daemon's runtime state.
pub async fn serve_metrics_until_cancelled(
    bind: std::net::SocketAddr,
    state: Arc<RwLock<DaemonState>>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    serve_metrics_listener_until_cancelled(listener, state, cancellation).await
}

async fn serve_metrics_listener_until_cancelled(
    listener: TcpListener,
    state: Arc<RwLock<DaemonState>>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_METRICS_CONNECTIONS));
    let mut clients = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            completed = clients.join_next(), if !clients.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "metrics client task failed");
                }
                continue;
            }
            accepted = listener.accept() => accepted?,
        };
        let (mut stream, _) = accepted;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let cancellation = cancellation.clone();
        clients.spawn(async move {
            let _permit = permit;
            let mut request = [0_u8; 1024];
            tokio::select! {
                _ = cancellation.cancelled() => {}
                _ = tokio::time::timeout(METRICS_REQUEST_TIMEOUT, async {
                    let read = tokio::time::timeout(METRICS_READ_TIMEOUT, stream.read(&mut request))
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or_default();
                    let first_line = std::str::from_utf8(&request[..read])
                        .unwrap_or("")
                        .lines()
                        .next()
                        .unwrap_or("");
                    let (code, body) = if first_line.starts_with("GET /metrics ") {
                        request_status_refresh(&state).await;
                        let daemon = state.read().await;
                        ("200 OK", prometheus(&daemon))
                    } else {
                        ("404 Not Found", "not found\n".to_owned())
                    };
                    let reply = format!(
                        "HTTP/1.1 {code}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                }) => {}
            }
        });
    }
    while clients.join_next().await.is_some() {}
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Arc<RwLock<DaemonState>> {
        Arc::new(RwLock::new(DaemonState {
            status: Status {
                node: "test".into(),
                node_identity: None,
                links: Vec::new(),
                circuits: Vec::new(),
                flow_count: 0,
                topology_nodes: 0,
                topology_generation: 0,
                supervised_tasks: 0,
                shutting_down: false,
                last_shutdown_error: None,
                circuit_traffic: BTreeMap::new(),
                acl_rejections: BTreeMap::new(),
            },
            routes: Vec::new(),
            observability: Arc::new(Observability::new(0)),
            topology_dot: "digraph tinect {}\n".into(),
            status_refresh_requested: Arc::new(Notify::new()),
            status_refresh_done: Arc::new(Notify::new()),
            status_refresh_pending: Arc::new(AtomicBool::new(false)),
        }))
    }

    #[test]
    fn migration_state_binary_round_trips_all_states() {
        let circuit = |state: MigrationState| CircuitStatus {
            destination: "exit".into(),
            destination_identity: None,
            active_path: vec!["source".into(), "exit".into()],
            active_path_names: vec![Some("source".into()), None],
            healthy: true,
            migration_state: state,
            preferred_path: vec!["source".into(), "exit".into()],
            preferred_path_names: vec![None, None],
            migration_started_at: None,
            migration_last_error: None,
        };
        let status = Status {
            node: "node".into(),
            node_identity: None,
            links: vec![LinkStatus {
                peer: "peer".into(),
                peer_identity: "4567".into(),
                healthy: true,
                last_error: None,
                metrics: None,
            }],
            circuits: vec![
                circuit(MigrationState::Stable),
                circuit(MigrationState::MigrationPending),
                circuit(MigrationState::MigrationOverdue),
            ],
            flow_count: 0,
            topology_nodes: 0,
            topology_generation: 0,
            supervised_tasks: 0,
            shutting_down: false,
            last_shutdown_error: None,
            circuit_traffic: BTreeMap::new(),
            acl_rejections: BTreeMap::new(),
        };
        let decoded = decode_status(&encode_status(&status).unwrap()).unwrap();
        assert_eq!(decoded.circuits[0].migration_state, MigrationState::Stable);
        assert_eq!(
            decoded.circuits[1].migration_state,
            MigrationState::MigrationPending
        );
        assert_eq!(
            decoded.circuits[2].migration_state,
            MigrationState::MigrationOverdue
        );
        assert!(decoded.links[0].metrics.is_none());
        assert!(decoded.circuits[0].migration_started_at.is_none());
        // An invalid migration byte is rejected. Derive its offset by
        // comparing otherwise-identical single-circuit encodings, rather than
        // matching an arbitrary byte pattern in the length fields.
        let mut stable = status.clone();
        stable.circuits.truncate(1);
        let mut overdue = stable.clone();
        overdue.circuits[0].migration_state = MigrationState::MigrationOverdue;
        let stable_wire = encode_status(&stable).unwrap();
        let overdue_wire = encode_status(&overdue).unwrap();
        assert_eq!(stable_wire.len(), overdue_wire.len());
        let migration_offset = stable_wire
            .iter()
            .zip(&overdue_wire)
            .position(|(stable, overdue)| stable != overdue)
            .expect("migration state byte");
        let mut wire = stable_wire;
        wire[migration_offset] = 7;
        assert!(decode_status(&wire).is_err());
    }

    #[test]
    fn management_request_from_opcode_constructs_opcode_requests() {
        let request: ManagementRequest = ManagementOpcode::Status.into();
        assert!(matches!(
            request,
            ManagementRequest::Opcode(ManagementOpcode::Status)
        ));
    }

    #[tokio::test]
    async fn management_request_reads_multi_frame_replies_and_rejects_bad_opcodes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0; 3];
            stream.read_exact(&mut header).await.unwrap();
            let frame_header =
                |length: usize| [header[0], 0, (length >> 8) as u8, (length & 0xff) as u8];
            let first = b"hello";
            stream.write_all(&frame_header(first.len())).await.unwrap();
            stream.write_all(first).await.unwrap();
            let second = b"world!";
            stream.write_all(&frame_header(second.len())).await.unwrap();
            stream.write_all(second).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let reply = request(&path, ManagementOpcode::Status).await.unwrap();
        assert_eq!(reply, b"helloworld!");
        server.await.unwrap();

        let path = dir.path().join("bad.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0; 3];
            stream.read_exact(&mut header).await.unwrap();
            stream.write_all(&[0xff, 0, 0, 0]).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        assert!(request(&path, ManagementOpcode::Status).await.is_err());
        server.await.unwrap();

        let path = dir.path().join("empty.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0; 3];
            stream.read_exact(&mut header).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let reply = request(&path, ManagementOpcode::Status).await.unwrap();
        assert!(reply.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn metrics_listener_cancellation_joins_an_idle_client() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let listener_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            serve_metrics_listener_until_cancelled(listener, state(), listener_cancellation).await
        });
        let _client = tokio::net::TcpStream::connect(address).await.unwrap();
        // Let the listener accept the connection and start its pending read.
        tokio::task::yield_now().await;
        cancellation.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("cancellation stops listener and its accepted clients")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn metrics_listener_serves_metrics_and_not_found_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let listener_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            serve_metrics_listener_until_cancelled(listener, state(), listener_cancellation).await
        });

        for (request, expected) in [
            (
                b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n" as &[u8],
                "200 OK",
            ),
            (
                b"GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "404 Not Found",
            ),
        ] {
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client.write_all(request).await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {expected}")));
        }

        cancellation.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("metrics listener stops")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn management_status_and_routes_use_fielded_binary_bodies() {
        let value = Status {
            node: "node".into(),
            node_identity: Some("0123".into()),
            links: vec![LinkStatus {
                peer: "peer".into(),
                peer_identity: "4567".into(),
                healthy: true,
                last_error: Some("none".into()),
                metrics: Some(LinkMetrics {
                    tx_datagrams: 1,
                    tx_bytes: 2,
                    rx_datagrams: 3,
                    rx_bytes: 4,
                    datagram_max_size: 14,
                    datagram_queue_drops: 15,
                    datagram_wire_oversize: 16,
                    stream_admission_rejections: 16,
                    datagram_admission_rejections: 17,
                    forward_queue_drops: 18,
                    datagram_send_errors: 19,
                    pmtu_local_oversize: 20,
                    pmtu_queue_pressure: 21,
                    pmtu_ack_timeouts: 22,
                    pmtu_peer_teardowns: 23,
                    pmtu_protocol_errors: 24,
                    fec_enabled: false,
                    fec_repair_rate_milli: 0,
                    fec_loss_ppm: 0,
                    fec_loss_samples: 0,
                    fec_tx_repairs: 0,
                    fec_rx_sources: 0,
                    fec_rx_repairs: 0,
                    fec_recovered: 0,
                    fec_lost: 0,
                    fec_discarded: 0,
                    fec_rate_limited: 0,
                    fec_reordered: 0,
                    fec_invalid: 0,
                    fec_feedback_sent: 0,
                    fec_feedback_retries: 0,
                }),
            }],
            circuits: vec![CircuitStatus {
                destination: "exit".into(),
                destination_identity: None,
                active_path: vec!["source".into(), "exit".into()],
                active_path_names: vec![Some("source".into()), None],
                healthy: true,
                migration_state: MigrationState::MigrationPending,
                preferred_path: vec!["source".into(), "relay".into(), "exit".into()],
                preferred_path_names: vec![Some("source".into()), Some("relay".into()), None],
                migration_started_at: Some(1_700_000_000),
                migration_last_error: Some("OpenAck timeout".into()),
            }],
            flow_count: 18,
            topology_nodes: 19,
            topology_generation: 20,
            supervised_tasks: 21,
            shutting_down: false,
            last_shutdown_error: None,
            circuit_traffic: BTreeMap::from([(
                "exit".into(),
                TrafficCounters {
                    tx_packets: 22,
                    tx_bytes: 23,
                    rx_packets: 24,
                    rx_bytes: 25,
                },
            )]),
            acl_rejections: BTreeMap::from([("deny".into(), 26)]),
        };
        let encoded = encode_status(&value).unwrap();
        assert_ne!(encoded.first(), Some(&b'{'));
        assert_eq!(
            serde_json::to_value(decode_status(&encoded).unwrap()).unwrap(),
            serde_json::to_value(value).unwrap()
        );
        let routes = vec![RouteStatus {
            selector: "ip_cidr:10.0.0.0/8".into(),
            entries: 1,
            candidates: vec!["exit".into()],
        }];
        assert_eq!(
            serde_json::to_value(decode_routes(&encode_routes(&routes).unwrap()).unwrap()).unwrap(),
            serde_json::to_value(routes).unwrap()
        );
    }

    #[test]
    fn reload_management_opcode_is_not_exposed() {
        assert!(ManagementOpcode::try_from(5).is_err());
    }

    #[test]
    fn management_binary_rejects_invalid_boolean() {
        let mut bytes = Writer::new();
        bytes.string("node").unwrap();
        bytes.u8(2);
        assert!(matches!(
            decode_status(&bytes.finish()),
            Err(wire::Error::Bool)
        ));
    }

    #[test]
    fn prometheus_exposes_operational_gauges() {
        let state = DaemonState {
            status: Status {
                node: "a".into(),
                node_identity: Some("fingerprint-a".into()),
                links: vec![LinkStatus {
                    peer: "b".into(),
                    peer_identity: "fingerprint-b".into(),
                    healthy: true,
                    last_error: None,
                    metrics: Some(LinkMetrics {
                        tx_datagrams: 0,
                        tx_bytes: 0,
                        rx_datagrams: 0,
                        rx_bytes: 0,
                        datagram_max_size: 0,
                        datagram_queue_drops: 0,
                        datagram_wire_oversize: 0,
                        stream_admission_rejections: 2,
                        datagram_admission_rejections: 3,
                        forward_queue_drops: 0,
                        datagram_send_errors: 0,
                        pmtu_local_oversize: 0,
                        pmtu_queue_pressure: 0,
                        pmtu_ack_timeouts: 0,
                        pmtu_peer_teardowns: 0,
                        pmtu_protocol_errors: 0,
                        fec_enabled: false,
                        fec_repair_rate_milli: 0,
                        fec_loss_ppm: 0,
                        fec_loss_samples: 0,
                        fec_tx_repairs: 0,
                        fec_rx_sources: 0,
                        fec_rx_repairs: 0,
                        fec_recovered: 0,
                        fec_lost: 0,
                        fec_discarded: 0,
                        fec_rate_limited: 0,
                        fec_reordered: 0,
                        fec_invalid: 0,
                        fec_feedback_sent: 0,
                        fec_feedback_retries: 0,
                    }),
                }],
                circuits: vec![CircuitStatus {
                    destination: "c".into(),
                    destination_identity: Some("fingerprint-c".into()),
                    active_path: vec!["a".into(), "b".into(), "c".into()],
                    active_path_names: vec![Some("a".into()), Some("b".into()), Some("c".into())],
                    healthy: true,
                    migration_state: MigrationState::Stable,
                    preferred_path: Vec::new(),
                    preferred_path_names: Vec::new(),
                    migration_started_at: None,
                    migration_last_error: None,
                }],
                flow_count: 7,
                topology_nodes: 3,
                topology_generation: 9,
                supervised_tasks: 0,
                shutting_down: false,
                last_shutdown_error: None,
                circuit_traffic: BTreeMap::new(),
                acl_rejections: BTreeMap::new(),
            },
            routes: Vec::new(),
            observability: Arc::new(Observability::new(0)),
            topology_dot: "digraph tinect {}\n".into(),
            status_refresh_requested: Arc::new(Notify::new()),
            status_refresh_done: Arc::new(Notify::new()),
            status_refresh_pending: Arc::new(AtomicBool::new(false)),
        };
        let metrics = prometheus(&state);
        assert!(metrics.contains("tinect_links_healthy 1"));
        assert!(metrics.contains("tinect_flows 7"));
        assert!(metrics.contains("tinect_topology_generation 9"));
        assert!(metrics.contains("tinect_tun_rx_packets 0"));
        assert!(metrics.contains("tinect_route_lookups 0"));
        assert!(metrics.contains("tinect_link_stream_admission_rejections{peer=\"b\"} 2"));
        assert!(metrics.contains("tinect_link_datagram_admission_rejections{peer=\"b\"} 3"));
        assert!(metrics.contains("tinect_link_fec_loss_ppm{peer=\"b\"} 0"));
        assert!(metrics.contains("tinect_link_fec_loss_samples{peer=\"b\"} 0"));
        assert!(metrics.contains("tinect_link_fec_recovered{peer=\"b\"} 0"));
        assert!(metrics.contains("tinect_link_fec_feedback_retries{peer=\"b\"} 0"));
        assert!(!metrics.contains("tinect_link_cwnd_bytes"));
        assert!(!metrics.contains("tinect_link_congestion_events"));
        assert!(!metrics.contains("tinect_link_datagram_send_buffer_space"));
    }

    #[test]
    fn prometheus_escapes_dynamic_label_values() {
        let mut state = DaemonState {
            status: Status {
                node: "a".into(),
                node_identity: None,
                links: Vec::new(),
                circuits: Vec::new(),
                flow_count: 0,
                topology_nodes: 0,
                topology_generation: 0,
                supervised_tasks: 0,
                shutting_down: false,
                last_shutdown_error: None,
                circuit_traffic: BTreeMap::from([(
                    "exit\\\"one".into(),
                    TrafficCounters::default(),
                )]),
                acl_rejections: BTreeMap::new(),
            },
            routes: Vec::new(),
            observability: Arc::new(Observability::new(0)),
            topology_dot: String::new(),
            status_refresh_requested: Arc::new(Notify::new()),
            status_refresh_done: Arc::new(Notify::new()),
            status_refresh_pending: Arc::new(AtomicBool::new(false)),
        };
        state.status.acl_rejections.insert("bad\nreason".into(), 2);

        let metrics = prometheus(&state);
        assert!(metrics.contains("circuit=\"exit\\\\\\\"one\""));
        assert!(metrics.contains("reason=\"bad\\nreason\"} 2"));
    }

    #[test]
    fn management_requests_map_every_supported_name_and_default_unknowns() {
        for (name, opcode) in [
            ("status", ManagementOpcode::Status),
            ("routes", ManagementOpcode::Routes),
            ("topology", ManagementOpcode::Topology),
            ("pcap", ManagementOpcode::Pcap),
            ("unknown", ManagementOpcode::Status),
            ("", ManagementOpcode::Status),
        ] {
            assert!(matches!(
                ManagementRequest::from(name),
                ManagementRequest::Opcode(value) if value == opcode
            ));
        }
        for (value, opcode) in [
            (1, ManagementOpcode::Status),
            (2, ManagementOpcode::Routes),
            (3, ManagementOpcode::Topology),
            (4, ManagementOpcode::Pcap),
        ] {
            assert_eq!(ManagementOpcode::try_from(value).unwrap(), opcode);
        }
    }

    #[test]
    fn binary_status_and_route_decoders_reject_invalid_state_and_trailing_wire() {
        let mut status = Writer::new();
        status.string("node").unwrap();
        status.optional_string(None).unwrap();
        status.u16(0); // links
        status.u16(1); // circuits
        status.string("exit").unwrap();
        status.optional_string(None).unwrap();
        status.u16(0); // active path
        status.u16(0); // active path names
        status.u8(1); // healthy
        status.u8(3); // invalid migration state
        assert!(matches!(
            decode_status(&status.finish()),
            Err(wire::Error::Bool)
        ));

        let mut routes = encode_routes(&[]).unwrap();
        routes.push(0);
        assert!(matches!(decode_routes(&routes), Err(wire::Error::Trailing)));
    }

    #[test]
    fn prometheus_omits_missing_link_metrics_and_escapes_all_label_controls() {
        let mut value = state().blocking_read().clone();
        value.status.links.push(LinkStatus {
            peer: "peer\\\"\n\r".into(),
            peer_identity: "identity".into(),
            healthy: false,
            last_error: None,
            metrics: None,
        });
        value.status.circuits.push(CircuitStatus {
            destination: "exit".into(),
            destination_identity: None,
            active_path: Vec::new(),
            active_path_names: Vec::new(),
            healthy: false,
            migration_state: MigrationState::MigrationOverdue,
            preferred_path: Vec::new(),
            preferred_path_names: Vec::new(),
            migration_started_at: None,
            migration_last_error: None,
        });
        let metrics = prometheus(&value);
        assert!(metrics.contains("tinect_links_healthy 0"));
        assert!(metrics.contains("tinect_circuits_healthy 0"));
        assert!(!metrics.contains("tinect_link_datagram_max_size{peer=\"peer"));
    }
}
