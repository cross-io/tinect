//! Bounded, local-only observability primitives for the data plane.
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    hash::{Hash, Hasher},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Traffic and rejection counters are written on the data-plane hot path
/// while status snapshots are infrequent.  Sharding the maps keeps a single
/// global mutex from serializing every packet across all circuits.
const COUNTER_SHARDS: usize = 16;

fn shard_for(key: &str) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % COUNTER_SHARDS
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct TrafficCounters {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Snapshot {
    pub circuits: BTreeMap<String, TrafficCounters>,
    pub acl_rejections: BTreeMap<String, u64>,
    pub dataplane: DataplaneCounters,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct DataplaneCounters {
    pub tun_rx_packets: u64,
    pub tun_rx_bytes: u64,
    pub tun_tx_packets: u64,
    pub tun_tx_bytes: u64,
    pub route_lookups: u64,
    pub route_lookup_nanos: u64,
    pub fake_ip_dns_queries: u64,
    pub fake_ip_dns_matches: u64,
    pub fake_ip_dns_failures: u64,
    pub fake_ip_mappings: u64,
    pub fake_ip_flows: u64,
}

#[derive(Debug)]
struct Packet {
    seconds: u32,
    micros: u32,
    bytes: Vec<u8>,
}

/// Captures decrypted inner IP frames in a bounded ring. It is deliberately
/// disabled by default: packet capture contains user traffic and must only be
/// exposed through the owner-only management socket.
#[derive(Debug)]
pub struct Observability {
    circuits: Vec<Mutex<BTreeMap<String, TrafficCounters>>>,
    acl_rejections: Vec<Mutex<BTreeMap<String, u64>>>,
    packets: Mutex<VecDeque<Packet>>,
    packet_limit: usize,
    tun_rx_packets: AtomicU64,
    tun_rx_bytes: AtomicU64,
    tun_tx_packets: AtomicU64,
    tun_tx_bytes: AtomicU64,
    route_lookups: AtomicU64,
    route_lookup_nanos: AtomicU64,
    fake_ip_dns_queries: AtomicU64,
    fake_ip_dns_matches: AtomicU64,
    fake_ip_dns_failures: AtomicU64,
    fake_ip_mappings: AtomicU64,
    fake_ip_flows: AtomicU64,
}

impl Observability {
    pub fn new(packet_limit: usize) -> Self {
        Self {
            circuits: (0..COUNTER_SHARDS)
                .map(|_| Mutex::new(BTreeMap::new()))
                .collect(),
            acl_rejections: (0..COUNTER_SHARDS)
                .map(|_| Mutex::new(BTreeMap::new()))
                .collect(),
            packets: Mutex::new(VecDeque::with_capacity(packet_limit)),
            packet_limit,
            tun_rx_packets: AtomicU64::new(0),
            tun_rx_bytes: AtomicU64::new(0),
            tun_tx_packets: AtomicU64::new(0),
            tun_tx_bytes: AtomicU64::new(0),
            route_lookups: AtomicU64::new(0),
            route_lookup_nanos: AtomicU64::new(0),
            fake_ip_dns_queries: AtomicU64::new(0),
            fake_ip_dns_matches: AtomicU64::new(0),
            fake_ip_dns_failures: AtomicU64::new(0),
            fake_ip_mappings: AtomicU64::new(0),
            fake_ip_flows: AtomicU64::new(0),
        }
    }
    pub fn fake_ip_dns_query(&self, matched: bool) {
        self.fake_ip_dns_queries.fetch_add(1, Ordering::Relaxed);
        if matched {
            self.fake_ip_dns_matches.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn fake_ip_dns_failure(&self) {
        self.fake_ip_dns_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn fake_ip_pool_usage(&self, mappings: usize, flows: usize) {
        self.fake_ip_mappings
            .store(mappings as u64, Ordering::Relaxed);
        self.fake_ip_flows.store(flows as u64, Ordering::Relaxed);
    }
    pub fn tun_rx(&self, bytes: usize) {
        self.tun_rx_packets.fetch_add(1, Ordering::Relaxed);
        self.tun_rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn tun_tx(&self, bytes: usize) {
        self.tun_tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tun_tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn route_lookup(&self, elapsed: std::time::Duration) {
        self.route_lookups.fetch_add(1, Ordering::Relaxed);
        self.route_lookup_nanos.fetch_add(
            elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }
    pub fn circuit_tx(&self, circuit: &str, bytes: usize) {
        let mut all = self.circuits[shard_for(circuit)]
            .lock()
            .expect("circuit metrics lock");
        update_traffic_counter(&mut all, circuit, |counter| {
            counter.tx_packets += 1;
            counter.tx_bytes += bytes as u64;
        });
    }
    pub fn circuit_rx(&self, circuit: &str, bytes: usize) {
        let mut all = self.circuits[shard_for(circuit)]
            .lock()
            .expect("circuit metrics lock");
        update_traffic_counter(&mut all, circuit, |counter| {
            counter.rx_packets += 1;
            counter.rx_bytes += bytes as u64;
        });
    }
    pub fn reject(&self, reason: impl AsRef<str>) {
        let reason = reason.as_ref();
        let mut all = self.acl_rejections[shard_for(reason)]
            .lock()
            .expect("ACL metrics lock");
        if let Some(count) = all.get_mut(reason) {
            *count += 1;
        } else {
            all.insert(reason.to_owned(), 1);
        }
    }
    pub fn capture(&self, packet: &[u8]) {
        if self.packet_limit == 0 {
            return;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut packets = self.packets.lock().expect("pcap lock");
        if packets.len() == self.packet_limit {
            packets.pop_front();
        }
        packets.push_back(Packet {
            seconds: now.as_secs().min(u64::from(u32::MAX)) as u32,
            micros: now.subsec_micros(),
            bytes: packet.to_vec(),
        });
    }
    pub fn snapshot(&self) -> Snapshot {
        let mut circuits = BTreeMap::new();
        for shard in &self.circuits {
            for (circuit, counter) in shard.lock().expect("circuit metrics lock").iter() {
                let merged: &mut TrafficCounters = circuits.entry(circuit.clone()).or_default();
                merged.tx_packets += counter.tx_packets;
                merged.tx_bytes += counter.tx_bytes;
                merged.rx_packets += counter.rx_packets;
                merged.rx_bytes += counter.rx_bytes;
            }
        }
        let mut acl_rejections = BTreeMap::new();
        for shard in &self.acl_rejections {
            for (reason, count) in shard.lock().expect("ACL metrics lock").iter() {
                let merged: &mut u64 = acl_rejections.entry(reason.clone()).or_default();
                *merged += *count;
            }
        }
        Snapshot {
            circuits,
            acl_rejections,
            dataplane: DataplaneCounters {
                tun_rx_packets: self.tun_rx_packets.load(Ordering::Relaxed),
                tun_rx_bytes: self.tun_rx_bytes.load(Ordering::Relaxed),
                tun_tx_packets: self.tun_tx_packets.load(Ordering::Relaxed),
                tun_tx_bytes: self.tun_tx_bytes.load(Ordering::Relaxed),
                route_lookups: self.route_lookups.load(Ordering::Relaxed),
                route_lookup_nanos: self.route_lookup_nanos.load(Ordering::Relaxed),
                fake_ip_dns_queries: self.fake_ip_dns_queries.load(Ordering::Relaxed),
                fake_ip_dns_matches: self.fake_ip_dns_matches.load(Ordering::Relaxed),
                fake_ip_dns_failures: self.fake_ip_dns_failures.load(Ordering::Relaxed),
                fake_ip_mappings: self.fake_ip_mappings.load(Ordering::Relaxed),
                fake_ip_flows: self.fake_ip_flows.load(Ordering::Relaxed),
            },
        }
    }
    /// PCAP v2.4, little endian, DLT_RAW (101): each record begins with an IP
    /// header and can be opened directly by Wireshark or tcpdump.
    pub fn pcap(&self) -> Vec<u8> {
        let packets = self.packets.lock().expect("pcap lock");
        let mut output =
            Vec::with_capacity(24 + packets.iter().map(|p| 16 + p.bytes.len()).sum::<usize>());
        output.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        output.extend_from_slice(&2u16.to_le_bytes());
        output.extend_from_slice(&4u16.to_le_bytes());
        output.extend_from_slice(&0i32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&65535u32.to_le_bytes());
        output.extend_from_slice(&101u32.to_le_bytes());
        for packet in packets.iter() {
            let length = packet.bytes.len().min(u32::MAX as usize) as u32;
            output.extend_from_slice(&packet.seconds.to_le_bytes());
            output.extend_from_slice(&packet.micros.to_le_bytes());
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(&packet.bytes[..length as usize]);
        }
        output
    }
}

fn update_traffic_counter(
    counters: &mut BTreeMap<String, TrafficCounters>,
    circuit: &str,
    update: impl FnOnce(&mut TrafficCounters),
) {
    if let Some(counter) = counters.get_mut(circuit) {
        update(counter);
        return;
    }
    counters.insert(circuit.to_owned(), TrafficCounters::default());
    let counter = counters
        .get_mut(circuit)
        .expect("traffic counter was inserted immediately before lookup");
    update(counter);
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pcap_is_bounded_and_has_raw_ip_header() {
        let metrics = Observability::new(1);
        metrics.capture(&[0x45, 1]);
        metrics.capture(&[0x60, 2, 3]);
        let pcap = metrics.pcap();
        assert_eq!(&pcap[..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(pcap[20..24].try_into().unwrap()), 101);
        assert_eq!(pcap.len(), 24 + 16 + 3);
    }

    #[test]
    fn dataplane_counters_are_snapshot_safe() {
        let metrics = Observability::new(0);
        metrics.tun_rx(10);
        metrics.tun_tx(7);
        metrics.route_lookup(std::time::Duration::from_micros(3));
        metrics.circuit_tx("exit", 11);
        metrics.circuit_tx("exit", 13);
        metrics.circuit_rx("exit", 17);
        metrics.reject("packet:malformed");
        metrics.reject("packet:malformed");
        let snapshot = metrics.snapshot().dataplane;
        assert_eq!(snapshot.tun_rx_packets, 1);
        assert_eq!(snapshot.tun_rx_bytes, 10);
        assert_eq!(snapshot.tun_tx_packets, 1);
        assert_eq!(snapshot.tun_tx_bytes, 7);
        assert_eq!(snapshot.route_lookups, 1);
        assert_eq!(snapshot.route_lookup_nanos, 3_000);

        let circuit = metrics.snapshot().circuits["exit"].clone();
        assert_eq!(circuit.tx_packets, 2);
        assert_eq!(circuit.tx_bytes, 24);
        assert_eq!(circuit.rx_packets, 1);
        assert_eq!(circuit.rx_bytes, 17);
        assert_eq!(metrics.snapshot().acl_rejections["packet:malformed"], 2);
    }

    #[test]
    fn fake_ip_dns_failure_counter_increments() {
        let metrics = Observability::new(0);
        metrics.fake_ip_dns_query(true);
        metrics.fake_ip_dns_failure();
        assert_eq!(metrics.snapshot().dataplane.fake_ip_dns_queries, 1);
        assert_eq!(metrics.snapshot().dataplane.fake_ip_dns_failures, 1);
    }
}
