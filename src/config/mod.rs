use crate::{
    identity,
    policy::Protocol,
    route_sets::{RouteSetLoader, RouteSetRegistry, SetId},
};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, fs,
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use thiserror::Error;

mod direct;
mod endpoint;
mod fake_ip;

pub use direct::DirectConfig;
pub use endpoint::{CarrierEndpoint, CarrierProtocol};
pub use fake_ip::{DnsServer, FakeIpConfig};

/// Local topology LSAs are renewed by the link-health scheduler before this
/// lifetime elapses. Keep this shared with validation so a configuration
/// cannot make a healthy topology disappear between renewals.
pub const TOPOLOGY_ADVERTISEMENT_TTL_SECS: u64 = 50;
/// Default shared key for fake-TCP RST authentication. Operators should set a
/// distinct private value when fake-TCP RST teardown is enabled across an
/// untrusted path.
pub const DEFAULT_FAKE_TCP_RESET_KEY: &str = "ihciah/tinect";
/// Environment variable containing a Base64 Ed25519 private key.
pub const IDENTITY_KEY_ENV: &str = "IDENTITY_KEY";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub id: String,
    /// Default inbound-link and transit permissions for configured peers.
    #[serde(default = "default_accept_connections")]
    pub accept_connections: bool,
    #[serde(default)]
    pub allow_transit: bool,
    /// Optional Base64 Ed25519 secret embedded in the configuration. The
    /// `IDENTITY_KEY` environment variable takes precedence when present.
    #[serde(default)]
    pub identity_key: Option<String>,
    /// Path to a file containing the Base64 Ed25519 secret.
    #[serde(default)]
    pub identity_key_path: Option<String>,
    /// Protocol-qualified listener endpoint. `quic://` uses the bare-UDP
    /// physical carrier; `quicfull://` keeps physical traffic in QUIC
    /// DATAGRAMs. The `*-faketcp` forms are Linux-only.
    #[serde(default)]
    pub listen: String,
    /// fake-TCP RST authentication: omit for the compatibility default key,
    /// set `false` to ignore all RST, or set a non-empty string as the shared
    /// per-deployment key. This applies only to `*-faketcp` carriers.
    #[serde(default)]
    pub fake_tcp_reset_key: FakeTcpResetKey,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default = "default_managed_routes")]
    pub managed_routes: bool,
    #[serde(default)]
    pub carrier_interface: Option<String>,
    /// Literal upstream DNS servers used for configured hostnames. An omitted
    /// port defaults to 53; an empty list uses the system resolver directly.
    #[serde(default)]
    pub dns_servers: Vec<DnsServer>,
    /// Optional source-side FakeIP DNS and address-translation service.
    #[serde(default)]
    pub fake_ip: Option<FakeIpConfig>,
    /// Loaded once by [`Config::load`]; route entries retain only SetIds.
    #[serde(skip, default)]
    pub route_sets: Arc<RouteSetRegistry>,
    /// Linux-only healthy-route nft set configuration and cleanup policy.
    #[serde(default)]
    pub nft_healthy_set: Option<NftHealthySetConfig>,
    /// Optional local TUN reinjection fallback. Linux is required because the
    /// reinjected packet is normally classified by the local nft policy.
    #[serde(default)]
    pub direct: Option<DirectConfig>,
    /// Optional trusted shell commands executed after TUN and Tinect-managed
    /// networking have been configured. `TINECT_TUN` contains the TUN name.
    #[serde(default)]
    pub post_up: Option<LifecycleCommands>,
    /// Optional trusted shell commands executed before TUN and Tinect-managed
    /// networking are removed.
    #[serde(default)]
    pub pre_down: Option<LifecycleCommands>,
    pub tun: TunConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// QUIC Link liveness and persistent reconnection behaviour.
    #[serde(default)]
    pub link_health: LinkHealthConfig,
    /// Bounded migration back to the first ready configured/topology path.
    #[serde(default)]
    pub path_migration: PathMigrationConfig,
    #[serde(default)]
    pub peers: BTreeMap<String, Peer>,
    /// Peers this node should proactively dial. Peer endpoint addresses remain
    /// address metadata; they do not themselves opt a peer into dialing.
    #[serde(default)]
    pub connect_to: Vec<ConnectTarget>,
    /// Maximum number of repair datagrams per source datagram accepted from a
    /// peer. The active side's per-target value is negotiated independently.
    #[serde(default = "default_repair_rate")]
    pub repair_rate: f64,
    /// Optional constraints for automatic paths. Every destination without an
    /// explicit `paths` entry is automatically searched, even when it has no
    /// constraint here.
    #[serde(default)]
    pub path_policies: BTreeMap<String, crate::topology::PathConstraint>,
    #[serde(default)]
    pub allowed_routes: Vec<AllowedRoute>,
    #[serde(default)]
    pub allowed_local_ports: Vec<AllowedLocalPort>,
}

// Manual `Debug`: `identity_key` is a private Ed25519 secret and
// `fake_tcp_reset_key` is a shared authenticator. Neither may ever appear in
// logs, panic messages, or `{:?}` snapshots of the config.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("id", &self.id)
            .field("accept_connections", &self.accept_connections)
            .field("allow_transit", &self.allow_transit)
            .field(
                "identity_key",
                &self.identity_key.as_ref().map(|_| "[redacted]"),
            )
            .field("identity_key_path", &self.identity_key_path)
            .field("listen", &self.listen)
            .field("fake_tcp_reset_key", &self.fake_tcp_reset_key)
            .field("fwmark", &self.fwmark)
            .field("managed_routes", &self.managed_routes)
            .field("carrier_interface", &self.carrier_interface)
            .field("dns_servers", &self.dns_servers)
            .field("fake_ip", &self.fake_ip)
            .field("nft_healthy_set", &self.nft_healthy_set)
            .field("direct", &self.direct)
            .field("post_up", &self.post_up)
            .field("pre_down", &self.pre_down)
            .field("tun", &self.tun)
            .field("runtime", &self.runtime)
            .field("link_health", &self.link_health)
            .field("path_migration", &self.path_migration)
            .field("peers", &self.peers)
            .field("connect_to", &self.connect_to)
            .field("repair_rate", &self.repair_rate)
            .field("path_policies", &self.path_policies)
            .field("allowed_routes", &self.allowed_routes)
            .field("allowed_local_ports", &self.allowed_local_ports)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConnectTarget {
    Peer(String),
    Configured(ConnectTargetConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTargetConfig {
    pub peer: String,
    #[serde(default = "default_repair_rate")]
    pub repair_rate: f64,
}

impl ConnectTarget {
    pub fn peer_name(&self) -> &str {
        match self {
            Self::Peer(peer) => peer,
            Self::Configured(config) => &config.peer,
        }
    }

    pub fn repair_rate(&self) -> f64 {
        match self {
            Self::Peer(_) => 0.0,
            Self::Configured(config) => config.repair_rate,
        }
    }

    pub fn repair_rate_milli(&self) -> u16 {
        repair_rate_milli(self.repair_rate())
    }
}

impl From<String> for ConnectTarget {
    fn from(peer: String) -> Self {
        Self::Peer(peer)
    }
}

impl From<&str> for ConnectTarget {
    fn from(peer: &str) -> Self {
        Self::Peer(peer.into())
    }
}

fn default_repair_rate() -> f64 {
    0.0
}

pub fn repair_rate_milli(rate: f64) -> u16 {
    (rate.clamp(0.0, crate::fec::MAX_RATE) * 1_000.0).round() as u16
}

fn validate_repair_rate(rate: f64, field: &str) -> Result<(), ConfigError> {
    if !rate.is_finite() || !(0.0..=crate::fec::MAX_RATE).contains(&rate) {
        return Err(ConfigError::Invalid(format!(
            "{field} must be a finite value between 0 and {}",
            crate::fec::MAX_RATE
        )));
    }
    if rate > 0.0 && rate < 0.001 {
        return Err(ConfigError::Invalid(format!(
            "{field} must be 0 or at least 0.001"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftHealthySetTarget {
    pub table: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NftHealthySetConfig {
    /// Base name used to derive the per-family set names.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Explicit IPv4 healthy-route set, in `<inet-table>:<set>` form.
    #[serde(default)]
    pub v4: Option<String>,
    /// Explicit IPv6 healthy-route set, in `<inet-table>:<set>` form.
    #[serde(default)]
    pub v6: Option<String>,
    /// Delete configured sets when the daemon exits.
    #[serde(default)]
    pub destroy_set: bool,
    /// Delete configured tables when the daemon exits.
    #[serde(default)]
    pub destroy_table: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NftHealthySetTargets {
    pub v4: Option<NftHealthySetTarget>,
    pub v6: Option<NftHealthySetTarget>,
    pub destroy_set: bool,
    pub destroy_table: bool,
}

fn parse_nft_target(value: &str, field: &str) -> Result<NftHealthySetTarget, ConfigError> {
    if value.is_empty() || value.bytes().filter(|byte| *byte == b':').count() != 1 {
        return Err(ConfigError::Invalid(format!(
            "{field} must use exactly one non-empty <table>:<set> value"
        )));
    }
    let (table, name) = value.split_once(':').expect("validated separator count");
    for (label, identifier) in [("table", table), ("set", name)] {
        if identifier.len() > 255
            || identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || !identifier
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        {
            return Err(ConfigError::Invalid(format!(
                "{field} {label} is not a valid nft identifier"
            )));
        }
    }
    Ok(NftHealthySetTarget {
        table: table.into(),
        name: name.into(),
    })
}

impl Config {
    pub fn nft_healthy_set_targets(&self) -> Result<NftHealthySetTargets, ConfigError> {
        let configured = self.nft_healthy_set.as_ref();
        let prefix = configured
            .and_then(|config| config.prefix.as_deref())
            .map(|value| parse_nft_target(value, "nft_healthy_set.prefix"))
            .transpose()?;
        let explicit_v4 = configured
            .and_then(|config| config.v4.as_deref())
            .map(|value| parse_nft_target(value, "nft_healthy_set.v4"))
            .transpose()?;
        let explicit_v6 = configured
            .and_then(|config| config.v6.as_deref())
            .map(|value| parse_nft_target(value, "nft_healthy_set.v6"))
            .transpose()?;
        let v4 = explicit_v4.or_else(|| {
            prefix.as_ref().map(|target| NftHealthySetTarget {
                table: target.table.clone(),
                name: format!("{}_v4", target.name),
            })
        });
        let v6 = explicit_v6.or_else(|| {
            prefix.as_ref().map(|target| NftHealthySetTarget {
                table: target.table.clone(),
                name: format!("{}_v6", target.name),
            })
        });
        for (family, target) in [("v4", v4.as_ref()), ("v6", v6.as_ref())] {
            if let Some(target) = target {
                let value = format!("{}:{}", target.table, target.name);
                parse_nft_target(&value, &format!("derived {family} nft set"))?;
            }
        }
        if v4.as_ref() == v6.as_ref() && v4.is_some() {
            return Err(ConfigError::Invalid(
                "nft healthy IPv4 and IPv6 sets must have different table:name identities".into(),
            ));
        }
        Ok(NftHealthySetTargets {
            v4,
            v6,
            destroy_set: configured.is_some_and(|config| config.destroy_set),
            destroy_table: configured.is_some_and(|config| config.destroy_table),
        })
    }
}

/// Configuration for fake-TCP RST authentication.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum FakeTcpResetKey {
    Disabled(bool),
    Key(String),
}

impl std::fmt::Debug for FakeTcpResetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled(value) => f.debug_tuple("Disabled").field(value).finish(),
            Self::Key(_) => f.debug_tuple("Key").field(&"[redacted]").finish(),
        }
    }
}

impl Default for FakeTcpResetKey {
    fn default() -> Self {
        Self::Key(DEFAULT_FAKE_TCP_RESET_KEY.into())
    }
}

impl FakeTcpResetKey {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Disabled(_) => None,
            Self::Key(key) => Some(key.as_bytes()),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Disabled(false) => Ok(()),
            Self::Disabled(true) => Err(ConfigError::Invalid(
                "fake_tcp_reset_key must be false or a non-empty string".into(),
            )),
            Self::Key(key) if key.is_empty() => Err(ConfigError::Invalid(
                "fake_tcp_reset_key must be false or a non-empty string".into(),
            )),
            Self::Key(_) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct LifecycleCommands(pub Vec<String>);

impl LifecycleCommands {
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

impl From<Vec<String>> for LifecycleCommands {
    fn from(commands: Vec<String>) -> Self {
        Self(commands)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Unix-domain status socket. Defaults to /run/tinect/<node id>.sock.
    pub status_socket: Option<String>,
    /// Optional local HTTP listener exposing Prometheus text metrics.
    pub metrics_listen: Option<SocketAddr>,
    /// Number of decrypted inner IP packets retained for `tinect pcap`.
    /// Disabled by default because capture contains sensitive traffic.
    #[serde(default)]
    pub pcap_buffer_packets: usize,
    /// Maximum time spent waiting for managed daemon tasks during shutdown.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
}
fn default_shutdown_timeout() -> u64 {
    10
}
impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            status_socket: None,
            metrics_listen: None,
            pcap_buffer_packets: 0,
            shutdown_timeout_secs: default_shutdown_timeout(),
        }
    }
}
/// Transport-level liveness values shared by inbound and outbound QUIC Links.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinkHealthConfig {
    /// Emit QUIC keepalive traffic at this interval.
    #[serde(default = "default_link_keepalive")]
    pub keepalive_secs: u64,
    /// Reclaim a QUIC session that receives no peer traffic for this period.
    #[serde(default = "default_link_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Delay before the deterministic connector retries a failed peer.
    #[serde(default = "default_link_reconnect")]
    pub reconnect_interval_secs: u64,
}
impl Default for LinkHealthConfig {
    fn default() -> Self {
        Self {
            keepalive_secs: default_link_keepalive(),
            idle_timeout_secs: default_link_idle_timeout(),
            reconnect_interval_secs: default_link_reconnect(),
        }
    }
}
fn default_link_keepalive() -> u64 {
    10
}
fn default_link_idle_timeout() -> u64 {
    35
}
fn default_link_reconnect() -> u64 {
    2
}

/// Lifecycle bounds for preferred-path migration. These values deliberately
/// apply locally; they do not alter the circuit wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PathMigrationConfig {
    #[serde(default = "default_path_migration_stability")]
    pub readiness_stability_secs: u64,
    #[serde(default = "default_path_migration_deadline")]
    pub deadline_secs: u64,
    #[serde(default = "default_path_migration_drain")]
    pub drain_timeout_secs: u64,
}

fn default_path_migration_stability() -> u64 {
    1
}
fn default_path_migration_deadline() -> u64 {
    5
}
fn default_path_migration_drain() -> u64 {
    1
}

impl Default for PathMigrationConfig {
    fn default() -> Self {
        Self {
            readiness_stability_secs: default_path_migration_stability(),
            deadline_secs: default_path_migration_deadline(),
            drain_timeout_secs: default_path_migration_drain(),
        }
    }
}
fn default_accept_connections() -> bool {
    true
}
fn default_managed_routes() -> bool {
    true
}
impl Config {
    pub fn fec_possible(&self) -> bool {
        repair_rate_milli(self.repair_rate) != 0
            || self
                .connect_to
                .iter()
                .any(|target| target.repair_rate_milli() != 0)
    }

    pub fn has_bare_carrier(&self) -> bool {
        self.listen_endpoint()
            .map(|(protocol, _)| protocol.is_bare_udp())
            .unwrap_or(false)
            || self
                .peers
                .values()
                .flat_map(|peer| peer.endpoints.iter())
                .any(|endpoint| {
                    CarrierEndpoint::parse(endpoint, "peer endpoint")
                        .map(|endpoint| endpoint.protocol.is_bare_udp())
                        .unwrap_or(false)
                })
    }
    pub fn has_full_quic_carrier(&self) -> bool {
        self.listen_endpoint()
            .map(|(protocol, _)| !protocol.is_bare_udp())
            .unwrap_or(false)
            || self
                .peers
                .values()
                .flat_map(|peer| peer.endpoints.iter())
                .any(|endpoint| {
                    CarrierEndpoint::parse(endpoint, "peer endpoint")
                        .map(|endpoint| !endpoint.protocol.is_bare_udp())
                        .unwrap_or(false)
                })
    }
    pub fn load_identity(&self) -> Result<ed25519_dalek::SigningKey, identity::IdentityError> {
        let env_key = match env::var_os(IDENTITY_KEY_ENV) {
            Some(value) => Some(value.into_string().map_err(|_| {
                identity::IdentityError::InvalidKey(format!(
                    "{IDENTITY_KEY_ENV} must contain valid UTF-8"
                ))
            })?),
            None => None,
        };
        self.load_identity_with_env(env_key.as_deref())
    }

    fn load_identity_with_env(
        &self,
        env_key: Option<&str>,
    ) -> Result<ed25519_dalek::SigningKey, identity::IdentityError> {
        if let Some(key) = env_key {
            return identity::decode_secret(key);
        }
        match (&self.identity_key, &self.identity_key_path) {
            (Some(key), None) => identity::decode_secret(key),
            (None, Some(path)) => identity::load_secret(path),
            _ => Err(identity::IdentityError::InvalidKey(format!(
                "configure identity_key, identity_key_path, or {IDENTITY_KEY_ENV}"
            ))),
        }
    }

    pub fn listen_endpoint(&self) -> Result<(CarrierProtocol, SocketAddr), ConfigError> {
        let endpoint = if self.listen.is_empty() {
            let endpoint = self
                .connect_to
                .iter()
                .filter_map(|target| self.peers.get(target.peer_name()))
                .flat_map(|peer| peer.endpoints.iter())
                .next()
                .ok_or_else(|| {
                    ConfigError::Invalid(
                        "listen may be omitted only for a node with a connect_to endpoint".into(),
                    )
                })?;
            let endpoint = CarrierEndpoint::parse(endpoint, "connect_to endpoint")?;
            let peer_uses_ipv6 = endpoint
                .address
                .parse::<SocketAddr>()
                .ok()
                .is_some_and(|address| address.is_ipv6());
            let local_address = if peer_uses_ipv6 {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            CarrierEndpoint {
                protocol: endpoint.protocol,
                address: local_address.into(),
            }
        } else {
            CarrierEndpoint::parse(&self.listen, "listen")?
        };
        #[cfg(not(target_os = "linux"))]
        if matches!(
            endpoint.protocol,
            CarrierProtocol::QuicFakeTcp | CarrierProtocol::QuicFullFakeTcp
        ) {
            return Err(ConfigError::Invalid(
                "quicp is supported only on Linux".into(),
            ));
        }
        endpoint
            .address
            .parse()
            .map(|address| (endpoint.protocol, address))
            .map_err(|error| {
                ConfigError::Invalid(format!("listen has an invalid QUIC address: {error}"))
            })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    /// Whether this node owns a local Layer-3 TUN device.  Relays that only
    /// forward encrypted circuits can disable it explicitly.
    #[serde(default = "default_tun_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub addresses: Vec<IpNet>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Whether outbound TCP SYN packets have their MSS limited to the active
    /// overlay path MTU. This avoids depending on ICMP PTB delivery.
    #[serde(default = "default_clamp_mss")]
    pub clamp_mss: bool,
}
fn default_tun_enabled() -> bool {
    true
}
fn default_mtu() -> u16 {
    1280
}
fn default_clamp_mss() -> bool {
    true
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub public_key: String,
    pub endpoints: Vec<String>,
    /// Optional FakeIP DNS upstreams used when this peer is the resolving
    /// exit. Omission inherits `fake_ip.upstream_dns`.
    #[serde(default)]
    pub upstream_dns: Option<Vec<DnsServer>>,
    /// Whether this peer may establish an inbound QUIC Link to this node.
    /// When omitted, top-level `accept_connections` applies.
    #[serde(default)]
    pub accept_connections: Option<bool>,
    /// Whether circuits sourced by this peer may transit this node.
    /// When omitted, top-level `allow_transit` applies.
    #[serde(default)]
    pub allow_transit: Option<bool>,
    /// Whether arbitrary traffic arriving from this peer may be relayed.
    /// This is deliberately separate from `allow_transit`, which authorizes
    /// the signed circuit OPEN request. Unknown peers never receive this
    /// permission.
    #[serde(default)]
    pub allow_relay: Option<bool>,
    /// Inner source ranges that this peer is allowed to originate when a
    /// receiver has source-address binding enabled for those ranges.
    #[serde(default)]
    pub bind_addresses: Vec<IpNet>,
    #[serde(default)]
    pub routes: Vec<PeerRoute>,
    /// Ordered manual paths to this peer. The first path has the highest
    /// priority. Path-local route overrides remain local to this node.
    #[serde(default)]
    pub paths: Vec<ConfiguredPath>,
}
impl Peer {
    pub fn accepts_connections(&self, node_default: bool) -> bool {
        self.accept_connections.unwrap_or(node_default)
    }

    pub fn allows_transit(&self, node_default: bool) -> bool {
        self.allow_transit.unwrap_or(node_default)
    }

    pub fn allows_relay(&self) -> bool {
        self.allow_relay.unwrap_or(false)
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct PeerRoute {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_cidr: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_set: Option<String>,
    pub priority: u32,
    /// When true, the route's IP CIDR is also bound to this peer identity for
    /// conditional source-address authorization.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bind: bool,
    #[serde(skip)]
    pub site_id: Option<SetId>,
    #[serde(skip)]
    pub(crate) shared_selector: Option<Arc<SharedRouteSelector>>,
    #[serde(skip)]
    pub(crate) shared_spec: Option<Arc<SharedRouteSpec>>,
}

impl PeerRoute {
    fn site_id_resolved(&self) -> Option<SetId> {
        self.shared_spec
            .as_ref()
            .map(|spec| spec.selector.site_id)
            .or(self.site_id)
    }

    fn priority_resolved(&self) -> u32 {
        self.shared_spec
            .as_ref()
            .map_or(self.priority, |spec| spec.priority)
    }

    pub fn selector_eq_override(&self, other: &RouteOverride) -> bool {
        if let (Some(left), Some(right)) = (self.site_id_resolved(), other.site_id_resolved()) {
            return left == right;
        }
        self.ip_cidr == other.ip_cidr
            && self.domain == other.domain
            && self.site_set == other.site_set
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SharedRouteSelector {
    pub site_id: SetId,
    pub has_domains: bool,
    pub has_prefixes: bool,
    pub entries: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct SharedRouteSpec {
    pub selector: Arc<SharedRouteSelector>,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredPath {
    pub path: Vec<String>,
    #[serde(default)]
    pub override_routes: Vec<RouteOverride>,
    /// Optional path-local FakeIP DNS upstream override. Omission inherits
    /// the destination peer value and then the global FakeIP value.
    #[serde(default)]
    pub override_upstream_dns: Option<Vec<DnsServer>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RouteOverride {
    #[serde(default)]
    pub ip_cidr: Option<IpNet>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub site_set: Option<String>,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub priority_delta: Option<i64>,
    #[serde(skip)]
    pub site_id: Option<SetId>,
    #[serde(skip)]
    pub(crate) shared_selector: Option<Arc<SharedRouteSelector>>,
    #[serde(skip)]
    pub(crate) shared_spec: Option<Arc<SharedOverrideSpec>>,
}

impl RouteOverride {
    fn site_id_resolved(&self) -> Option<SetId> {
        self.shared_spec
            .as_ref()
            .and_then(|spec| spec.selector.as_ref().map(|selector| selector.site_id))
            .or(self.site_id)
    }

    pub fn priority_for(&self, base: u32) -> Option<u32> {
        let priority = self
            .shared_spec
            .as_ref()
            .and_then(|spec| spec.priority)
            .or(self.priority);
        let priority_delta = self
            .shared_spec
            .as_ref()
            .and_then(|spec| spec.priority_delta)
            .or(self.priority_delta);
        if let Some(priority) = priority {
            return (priority > 0).then_some(priority);
        }
        priority_delta.and_then(|delta| {
            let adjusted = i128::from(base) + i128::from(delta);
            (adjusted > 0).then_some(adjusted.min(i128::from(u32::MAX)) as u32)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SharedOverrideSpec {
    pub selector: Option<Arc<SharedRouteSelector>>,
    pub priority: Option<u32>,
    pub priority_delta: Option<i64>,
}

type OverrideSpecKey = (Option<SetId>, Option<u32>, Option<i64>);

fn default_peer_route_priority() -> u32 {
    100
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRouteFields {
    #[serde(default)]
    ip_cidr: Option<IpNet>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    site_set: Option<String>,
    #[serde(default = "default_peer_route_priority")]
    priority: u32,
    #[serde(default)]
    bind: bool,
}

impl<'de> Deserialize<'de> for PeerRoute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = PeerRouteFields::deserialize(deserializer)?;
        let selectors = usize::from(fields.ip_cidr.is_some())
            + usize::from(fields.domain.is_some())
            + usize::from(fields.site_set.is_some());
        if selectors != 1 {
            return Err(serde::de::Error::custom(
                "route must specify exactly one of ip_cidr, domain, or site_set",
            ));
        }
        if fields.bind && fields.ip_cidr.is_none() {
            return Err(serde::de::Error::custom(
                "route bind requires an ip_cidr selector",
            ));
        }
        Ok(Self {
            ip_cidr: fields.ip_cidr,
            domain: fields.domain,
            site_set: fields.site_set,
            priority: fields.priority,
            bind: fields.bind,
            site_id: None,
            shared_selector: None,
            shared_spec: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedRoute {
    pub allow: Vec<IpNet>,
    #[serde(default)]
    pub deny: Vec<IpNet>,
    #[serde(default)]
    pub r#for: RouteSourceSelector,
}

/// Destination transport policy for traffic delivered to this node.  Address
/// authorization remains in `allowed_routes`; this type intentionally only
/// describes the locally exposed protocol/port surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedLocalPort {
    pub allow: Vec<PortSelector>,
    #[serde(default)]
    pub deny: Vec<PortSelector>,
    #[serde(default = "default_port_source_selector")]
    pub r#for: RouteSourceSelector,
}

fn default_port_source_selector() -> RouteSourceSelector {
    RouteSourceSelector::Keyword("any_known".into())
}

impl AllowedLocalPort {
    pub fn permits(&self, source: &str, protocol: Protocol, port: u16, known: bool) -> bool {
        self.r#for.matches(source, known)
            && self
                .allow
                .iter()
                .any(|selector| selector.matches(protocol, port))
            && !self
                .deny
                .iter()
                .any(|selector| selector.matches(protocol, port))
    }

    pub fn denies(&self, source: &str, protocol: Protocol, port: u16, known: bool) -> bool {
        self.r#for.matches(source, known)
            && self
                .deny
                .iter()
                .any(|selector| selector.matches(protocol, port))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSelector {
    All,
    Protocol(Protocol),
    PortRange {
        protocol: Protocol,
        first: u16,
        last: u16,
    },
}

impl PortSelector {
    fn matches(&self, protocol: Protocol, port: u16) -> bool {
        match self {
            Self::All => true,
            Self::Protocol(expected) => *expected == protocol,
            Self::PortRange {
                protocol: expected,
                first,
                last,
            } => *expected == protocol && (*first..=*last).contains(&port),
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        if value == "all" {
            return Ok(Self::All);
        }
        match value {
            "tcp" => return Ok(Self::Protocol(Protocol::Tcp)),
            "udp" => return Ok(Self::Protocol(Protocol::Udp)),
            "icmp" => return Ok(Self::Protocol(Protocol::Icmp)),
            "icmpv6" => return Ok(Self::Protocol(Protocol::Icmpv6)),
            _ => {}
        };
        let Some((protocol, range)) = value.split_once('(') else {
            return Err("must be all, tcp, udp, icmp, icmpv6, tcp(PORT), or udp(PORT)".into());
        };
        let range = range
            .strip_suffix(')')
            .ok_or_else(|| "has an unclosed port range".to_owned())?;
        let protocol = match protocol {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => return Err("port ranges are supported only for tcp and udp".into()),
        };
        let (first, last) = match range.split_once(':') {
            Some((first, last)) => (first, last),
            None => (range, range),
        };
        let first = first
            .parse::<u16>()
            .map_err(|_| "has an invalid first port")?;
        let last = last
            .parse::<u16>()
            .map_err(|_| "has an invalid last port")?;
        if first == 0 || last == 0 || first > last {
            return Err("port range must be within 1..=65535 and ordered".into());
        }
        Ok(Self::PortRange {
            protocol,
            first,
            last,
        })
    }
}

impl std::str::FromStr for PortSelector {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for PortSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for PortSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = match self {
            Self::All => "all".to_owned(),
            Self::Protocol(Protocol::Tcp) => "tcp".to_owned(),
            Self::Protocol(Protocol::Udp) => "udp".to_owned(),
            Self::Protocol(Protocol::Icmp) => "icmp".to_owned(),
            Self::Protocol(Protocol::Icmpv6) => "icmpv6".to_owned(),
            Self::PortRange {
                protocol,
                first,
                last,
            } => {
                let protocol = match protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    Protocol::Icmp => "icmp",
                    Protocol::Icmpv6 => "icmpv6",
                };
                if first == last {
                    format!("{protocol}({first})")
                } else {
                    format!("{protocol}({first}:{last})")
                }
            }
        };
        serializer.serialize_str(&value)
    }
}
impl AllowedRoute {
    pub fn permits(&self, source: &str, destination: std::net::IpAddr, known: bool) -> bool {
        let source_allowed = self.r#for.matches(source, known);
        source_allowed
            && self
                .allow
                .iter()
                .any(|prefix| prefix.contains(&destination))
            && !self.deny.iter().any(|prefix| prefix.contains(&destination))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RouteSourceSelector {
    Nodes(Vec<String>),
    Keyword(String),
}

impl Default for RouteSourceSelector {
    fn default() -> Self {
        Self::Nodes(Vec::new())
    }
}

impl RouteSourceSelector {
    pub fn matches(&self, source: &str, known: bool) -> bool {
        match self {
            // An empty node list matches nothing. Validation rejects empty
            // `for`, but programmatic construction must not fail open via
            // `all()` on an empty iterator.
            Self::Nodes(nodes) if nodes.is_empty() => false,
            Self::Nodes(nodes) if nodes.iter().all(|node| node.starts_with('!')) => {
                !nodes.iter().any(|node| &node[1..] == source)
            }
            Self::Nodes(nodes) => nodes.iter().any(|node| node == source),
            Self::Keyword(value) => match value.as_str() {
                "any_known" => known,
                "any_inc_unknown" => true,
                _ => false,
            },
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteImport {
    pub prefix: IpNet,
    pub candidates: Vec<RouteCandidate>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainRouteImport {
    pub set_id: SetId,
    pub candidates: Vec<RouteCandidate>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCandidate {
    pub node: String,
    pub priority: u32,
}
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error("configuration error: {0}")]
    Invalid(String),
}

fn validate_source_selector(
    selector: &RouteSourceSelector,
    field: &str,
) -> Result<(), ConfigError> {
    match selector {
        RouteSourceSelector::Nodes(nodes) if nodes.is_empty() => Err(ConfigError::Invalid(
            format!("{field}.for must not be empty"),
        )),
        RouteSourceSelector::Nodes(nodes) => {
            let negated = nodes.iter().filter(|node| node.starts_with('!')).count();
            if negated != 0 && negated != nodes.len() {
                return Err(ConfigError::Invalid(format!(
                    "{field}.for cannot mix allowed and denied node selectors"
                )));
            }
            if nodes
                .iter()
                .any(|node| node == "!" || (node.starts_with('!') && node[1..].is_empty()))
            {
                return Err(ConfigError::Invalid(format!(
                    "{field}.for contains an invalid negated node"
                )));
            }
            Ok(())
        }
        RouteSourceSelector::Keyword(value)
            if value == "any_known" || value == "any_inc_unknown" =>
        {
            Ok(())
        }
        RouteSourceSelector::Keyword(_) => Err(ConfigError::Invalid(format!(
            "{field}.for must be any_known or any_inc_unknown"
        ))),
    }
}

fn load_route_selector(
    loader: &mut RouteSetLoader,
    route: &mut PeerRoute,
) -> Result<(), ConfigError> {
    route.site_id = load_site_id(
        loader,
        route.ip_cidr,
        route.domain.as_deref(),
        route.site_set.as_deref(),
    )?;
    Ok(())
}

fn load_override_selector(
    loader: &mut RouteSetLoader,
    route: &mut RouteOverride,
) -> Result<(), ConfigError> {
    route.site_id = load_site_id(
        loader,
        route.ip_cidr,
        route.domain.as_deref(),
        route.site_set.as_deref(),
    )?;
    Ok(())
}

fn load_site_id(
    loader: &mut RouteSetLoader,
    ip_cidr: Option<IpNet>,
    domain: Option<&str>,
    site_set: Option<&str>,
) -> Result<Option<SetId>, ConfigError> {
    let result = site_set
        .map(|path| loader.load(path))
        .or_else(|| domain.map(|domain| loader.load_inline(domain)))
        .or_else(|| ip_cidr.map(|prefix| loader.load_inline(&format!("ip-cidr:{prefix}"))));
    result
        .map(|result| result.map_err(|error| ConfigError::Invalid(error.to_string())))
        .transpose()
}

#[derive(Default)]
struct RouteInterner {
    selectors: HashMap<SetId, Arc<SharedRouteSelector>>,
    route_specs: HashMap<(SetId, u32), Arc<SharedRouteSpec>>,
    override_specs: HashMap<OverrideSpecKey, Arc<SharedOverrideSpec>>,
}

impl RouteInterner {
    fn selector(
        &mut self,
        site_id: SetId,
        registry: &RouteSetRegistry,
    ) -> Option<Arc<SharedRouteSelector>> {
        if let Some(selector) = self.selectors.get(&site_id) {
            return Some(selector.clone());
        }
        let site = registry.site(site_id)?;
        let selector = Arc::new(SharedRouteSelector {
            site_id,
            has_domains: site.has_domains(),
            has_prefixes: !site.prefixes().is_empty(),
            entries: site.len(),
        });
        self.selectors.insert(site_id, selector.clone());
        Some(selector)
    }

    fn intern_peer_route(&mut self, route: &mut PeerRoute, registry: &RouteSetRegistry) {
        let Some(site_id) = route.site_id else {
            return;
        };
        let Some(selector) = self.selector(site_id, registry) else {
            return;
        };
        let spec = self
            .route_specs
            .entry((site_id, route.priority))
            .or_insert_with(|| {
                Arc::new(SharedRouteSpec {
                    selector: selector.clone(),
                    priority: route.priority,
                })
            })
            .clone();
        route.shared_selector = Some(selector);
        route.shared_spec = Some(spec);
    }

    fn intern_override(&mut self, route: &mut RouteOverride, registry: &RouteSetRegistry) {
        let selector = route
            .site_id
            .and_then(|site_id| self.selector(site_id, registry));
        let key = (route.site_id, route.priority, route.priority_delta);
        let spec = self
            .override_specs
            .entry(key)
            .or_insert_with(|| {
                Arc::new(SharedOverrideSpec {
                    selector: selector.clone(),
                    priority: route.priority,
                    priority_delta: route.priority_delta,
                })
            })
            .clone();
        route.shared_selector = selector;
        route.shared_spec = Some(spec);
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let mut c: Self = serde_yaml::from_str(&fs::read_to_string(path)?)?;
        c.load_route_sets(path.parent().unwrap_or_else(|| Path::new(".")))?;
        c.validate()?;
        c.warn_identity_key_permissions();
        Ok(c)
    }

    /// Warns when the identity key file is readable beyond its owner.
    /// `save_secret` writes `0600`, but a copied-in key may be world-readable;
    /// loading still succeeds so existing setups keep working.
    fn warn_identity_key_permissions(&self) {
        #[cfg(unix)]
        if let Some(path) = self.identity_key_path.as_ref()
            && let Ok(metadata) = std::fs::metadata(path)
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 {
                tracing::warn!(
                    path = %path,
                    "identity key file is readable by group or others; run `chmod 600` on it"
                );
            }
        }
    }

    fn load_route_sets(&mut self, base: &Path) -> Result<(), ConfigError> {
        let mut loader = RouteSetLoader::new(base);
        for peer in self.peers.values_mut() {
            for route in &mut peer.routes {
                load_route_selector(&mut loader, route)?;
            }
            for path in &mut peer.paths {
                for route in &mut path.override_routes {
                    load_override_selector(&mut loader, route)?;
                }
            }
        }
        if let Some(direct) = &mut self.direct {
            for route in &mut direct.routes {
                load_route_selector(&mut loader, route)?;
            }
        }
        self.route_sets = Arc::new(loader.finish());
        self.intern_route_specs();
        Ok(())
    }

    fn intern_route_specs(&mut self) {
        let mut interner = RouteInterner::default();
        for peer in self.peers.values_mut() {
            for route in &mut peer.routes {
                interner.intern_peer_route(route, &self.route_sets);
            }
            for path in &mut peer.paths {
                for route in &mut path.override_routes {
                    interner.intern_override(route, &self.route_sets);
                }
            }
        }
        if let Some(direct) = &mut self.direct {
            for route in &mut direct.routes {
                interner.intern_peer_route(route, &self.route_sets);
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.id.is_empty() {
            return Err(ConfigError::Invalid("id is required".into()));
        }
        if self.id.contains('/') || self.id.contains('\0') {
            return Err(ConfigError::Invalid(
                "id must not contain path separators or NUL".into(),
            ));
        }
        self.fake_tcp_reset_key.validate()?;
        if let Some(fake) = &self.fake_ip {
            if fake.listen.port() == 0 {
                return Err(ConfigError::Invalid(
                    "fake_ip.listen port must not be zero".into(),
                ));
            }
            if fake.upstream_dns.is_empty() {
                return Err(ConfigError::Invalid(
                    "fake_ip.upstream_dns must not be empty".into(),
                ));
            }
            if fake.min_cache_ttl_secs == 0
                || fake.min_cache_ttl_secs > fake.max_cache_ttl_secs
                || fake.max_entries == 0
            {
                return Err(ConfigError::Invalid(
                    "fake_ip requires 0 < min_cache_ttl_secs <= max_cache_ttl_secs and max_entries > 0"
                        .into(),
                ));
            }
            if !fake.ipv4_pool.addr().is_ipv4() || !fake.ipv6_pool.addr().is_ipv6() {
                return Err(ConfigError::Invalid(
                    "fake_ip IPv4/IPv6 pools must use their declared address family".into(),
                ));
            }
            let pools = [fake.ipv4_pool, fake.ipv6_pool];
            for (index, left) in pools.iter().enumerate() {
                if self
                    .tun
                    .addresses
                    .iter()
                    .any(|right| prefixes_overlap(*left, *right))
                    || pools[index + 1..]
                        .iter()
                        .any(|right| prefixes_overlap(*left, *right))
                {
                    return Err(ConfigError::Invalid(format!(
                        "fake_ip pool {left} overlaps another FakeIP or TUN prefix"
                    )));
                }
            }
        }
        let has_domain_routes = self.peers.values().any(|peer| {
            peer.routes.iter().any(|route| {
                route
                    .site_id
                    .and_then(|id| self.route_sets.site(id))
                    .is_some_and(|site| site.has_domains())
                    || route.domain.is_some()
            }) || peer.paths.iter().any(|path| {
                path.override_routes.iter().any(|route| {
                    route
                        .site_id
                        .and_then(|id| self.route_sets.site(id))
                        .is_some_and(|site| site.has_domains())
                        || route.domain.is_some()
                })
            })
        }) || self.direct.as_ref().is_some_and(|direct| {
            direct.routes.iter().any(|route| {
                route
                    .site_id
                    .and_then(|id| self.route_sets.site(id))
                    .is_some_and(|site| site.has_domains())
                    || route.domain.is_some()
            })
        });
        if has_domain_routes && self.fake_ip.is_none() {
            return Err(ConfigError::Invalid(
                "domain routes and site sets containing domains require fake_ip to be configured"
                    .into(),
            ));
        }
        let has_upstream_overrides = self.peers.values().any(|peer| {
            peer.upstream_dns.is_some()
                || peer
                    .paths
                    .iter()
                    .any(|path| path.override_upstream_dns.is_some())
        });
        if has_upstream_overrides && self.fake_ip.is_none() {
            return Err(ConfigError::Invalid(
                "peer/path upstream_dns overrides require fake_ip to be configured".into(),
            ));
        }
        let _nft_targets = self.nft_healthy_set_targets()?;
        #[cfg(not(target_os = "linux"))]
        if self.nft_healthy_set.is_some() {
            return Err(ConfigError::Invalid(
                "nft healthy route sets are supported only on Linux".into(),
            ));
        }
        if self.fwmark == Some(0) {
            return Err(ConfigError::Invalid(
                "fwmark must be non-zero when configured".into(),
            ));
        }
        if let Some(direct) = &self.direct {
            if direct.dscp > 63 {
                return Err(ConfigError::Invalid(
                    "direct.dscp must be within 0..=63".into(),
                ));
            }
            if direct.conntrack_zone == 0 {
                return Err(ConfigError::Invalid(
                    "direct.conntrack_zone must be non-zero".into(),
                ));
            }
            if direct.fwmark == Some(0) {
                return Err(ConfigError::Invalid(
                    "direct.fwmark must be non-zero when configured".into(),
                ));
            }
            if let (Some(top), Some(direct_mark)) = (self.fwmark, direct.fwmark)
                && top == direct_mark
            {
                return Err(ConfigError::Invalid(
                    "fwmark and direct.fwmark must differ: the carrier SO_MARK and the reinjected-packet mark are distinct mark spaces".into(),
                ));
            }
            #[cfg(not(target_os = "linux"))]
            return Err(ConfigError::Invalid(
                "direct is supported only on Linux".into(),
            ));
        }
        for (field, commands) in [("post_up", &self.post_up), ("pre_down", &self.pre_down)] {
            if let Some(commands) = commands
                && (commands.0.is_empty()
                    || commands
                        .0
                        .iter()
                        .any(|command| command.trim().is_empty() || command.contains('\0')))
            {
                return Err(ConfigError::Invalid(format!(
                    "{field} must be a non-empty command list without blank commands or NUL bytes"
                )));
            }
        }
        let (listen_protocol, _) = self.listen_endpoint()?;
        if let Some(interface) = &self.carrier_interface {
            if interface.contains('\0') {
                return Err(ConfigError::Invalid(
                    "carrier_interface must not contain NUL bytes".into(),
                ));
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = interface;
                return Err(ConfigError::Invalid(
                    "carrier_interface is supported only on macOS".into(),
                ));
            }
        }
        if matches!(
            listen_protocol,
            CarrierProtocol::QuicFakeTcp | CarrierProtocol::QuicFullFakeTcp
        ) && self.carrier_interface.is_some()
        {
            return Err(ConfigError::Invalid(
                "carrier_interface is not supported with fake-TCP carriers".into(),
            ));
        }
        for (peer_name, peer) in &self.peers {
            for (index, endpoint) in peer.endpoints.iter().enumerate() {
                let parsed = CarrierEndpoint::parse(
                    endpoint,
                    &format!("peers.{peer_name}.endpoints[{index}]"),
                )?;
                crate::dns::validate_socket_target(&parsed.address).map_err(|error| {
                    ConfigError::Invalid(format!(
                        "peers.{peer_name}.endpoints[{index}] has an invalid address: {error}"
                    ))
                })?;
                if matches!(
                    parsed.protocol,
                    CarrierProtocol::QuicFakeTcp | CarrierProtocol::QuicFullFakeTcp
                ) {
                    #[cfg(not(target_os = "linux"))]
                    {
                        return Err(ConfigError::Invalid(
                            "quicp is supported only on Linux".into(),
                        ));
                    }
                    #[cfg(target_os = "linux")]
                    {
                        if self.carrier_interface.is_some() {
                            return Err(ConfigError::Invalid(
                                "carrier_interface is not supported with fake-TCP carriers".into(),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(metrics) = self.runtime.metrics_listen
            && !metrics.ip().is_loopback()
        {
            return Err(ConfigError::Invalid(
                "runtime.metrics_listen must bind a loopback address".into(),
            ));
        }
        if !(1..=60).contains(&self.runtime.shutdown_timeout_secs) {
            return Err(ConfigError::Invalid(
                "runtime.shutdown_timeout_secs must be 1..=60".into(),
            ));
        }
        if self.runtime.pcap_buffer_packets > 65_536 {
            return Err(ConfigError::Invalid(
                "runtime.pcap_buffer_packets must be 0..=65536".into(),
            ));
        }
        if self.identity_key.is_some() && self.identity_key_path.is_some() {
            return Err(ConfigError::Invalid(
                "configure at most one of identity_key or identity_key_path".into(),
            ));
        }
        if self.identity_key.is_none()
            && self.identity_key_path.is_none()
            && env::var_os(IDENTITY_KEY_ENV).is_none()
        {
            return Err(ConfigError::Invalid(format!(
                "configure identity_key, identity_key_path, or {IDENTITY_KEY_ENV}"
            )));
        }
        if self.tun.enabled {
            if self.tun.addresses.is_empty() {
                return Err(ConfigError::Invalid(
                    "at least one TUN address is required when tun.enabled is true".into(),
                ));
            }
            if !(576..=9000).contains(&self.tun.mtu) {
                return Err(ConfigError::Invalid("TUN MTU must be 576..=9000".into()));
            }
        } else {
            if self.post_up.is_some() || self.pre_down.is_some() {
                return Err(ConfigError::Invalid(
                    "post_up and pre_down require tun.enabled to be true".into(),
                ));
            }
            if !self.allowed_routes.is_empty()
                || !self.allowed_local_ports.is_empty()
                || !self.route_imports().is_empty()
                || !self.domain_route_imports().is_empty()
                || !self.override_route_prefixes().is_empty()
            {
                return Err(ConfigError::Invalid(
                    "allowed_routes, allowed_local_ports, peer routes, and path overrides require tun.enabled to be true"
                        .into(),
                ));
            }
            if self.direct.is_some() {
                return Err(ConfigError::Invalid(
                    "direct requires tun.enabled to be true".into(),
                ));
            }
        }
        let link = &self.link_health;
        if link.keepalive_secs == 0 || link.idle_timeout_secs <= link.keepalive_secs {
            return Err(ConfigError::Invalid(
                "link_health.idle_timeout_secs must be greater than non-zero keepalive_secs".into(),
            ));
        }
        let topology_ttl = crate::timing::active().topology_advertisement_ttl_secs;
        if link.keepalive_secs >= topology_ttl {
            return Err(ConfigError::Invalid(format!(
                "link_health.keepalive_secs must be less than topology LSA TTL ({topology_ttl} seconds)"
            )));
        }
        if link.reconnect_interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "link_health.reconnect_interval_secs must be non-zero".into(),
            ));
        }
        let migration = &self.path_migration;
        if migration.readiness_stability_secs == 0
            || migration.deadline_secs == 0
            || migration.readiness_stability_secs > migration.deadline_secs
            || migration.drain_timeout_secs > migration.deadline_secs
        {
            return Err(ConfigError::Invalid(
                "path_migration requires non-zero stability/deadline values with stability and drain <= deadline".into(),
            ));
        }
        if self.peers.len() > crate::topology::MAX_NEIGHBORS_PER_LSA {
            return Err(ConfigError::Invalid(format!(
                "at most {} peers are supported by one local topology advertisement",
                crate::topology::MAX_NEIGHBORS_PER_LSA
            )));
        }
        let mut peer_keys = HashSet::new();
        for (name, peer) in &self.peers {
            let key = identity::decode_public(&peer.public_key).map_err(|error| {
                ConfigError::Invalid(format!("peers.{name}.public_key: {error}"))
            })?;
            let canonical = identity::encode_public(&key);
            if peer.public_key != canonical {
                return Err(ConfigError::Invalid(format!(
                    "peers.{name}.public_key must use canonical base64-no-pad encoding"
                )));
            }
            if !peer_keys.insert(canonical) {
                return Err(ConfigError::Invalid(format!(
                    "peers.{name}.public_key duplicates another configured peer identity"
                )));
            }
        }
        for route in &self.allowed_routes {
            if route.allow.is_empty() {
                return Err(ConfigError::Invalid(
                    "allowed_route.allow must not be empty".into(),
                ));
            }
            validate_source_selector(&route.r#for, "allowed_route")?;
        }
        for rule in &self.allowed_local_ports {
            if rule.allow.is_empty() {
                return Err(ConfigError::Invalid(
                    "allowed_port.allow must not be empty".into(),
                ));
            }
            validate_source_selector(&rule.r#for, "allowed_port")?;
        }
        validate_repair_rate(self.repair_rate, "repair_rate")?;
        let mut dial_targets = HashSet::new();
        for target in &self.connect_to {
            let peer_name = target.peer_name();
            validate_repair_rate(
                target.repair_rate(),
                &format!("connect_to.{peer_name}.repair_rate"),
            )?;
            if !dial_targets.insert(peer_name) {
                return Err(ConfigError::Invalid(format!(
                    "connect_to repeats peer {peer_name}"
                )));
            }
            let Some(peer) = self.peers.get(peer_name) else {
                return Err(ConfigError::Invalid(format!(
                    "connect_to peer {peer_name} is not configured"
                )));
            };
            if peer.endpoints.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "connect_to peer {peer_name} has no endpoint"
                )));
            }
        }
        for (dest, peer) in &self.peers {
            if peer.upstream_dns.as_ref().is_some_and(Vec::is_empty) {
                return Err(ConfigError::Invalid(format!(
                    "peers.{dest}.upstream_dns must not be empty when configured"
                )));
            }
            for (index, route) in peer.routes.iter().enumerate() {
                if route.bind && route.ip_cidr.is_none() {
                    return Err(ConfigError::Invalid(format!(
                        "peers.{dest}.routes[{index}].bind requires an ip_cidr selector"
                    )));
                }
            }
            for configured in &peer.paths {
                validate_path(&self.id, dest, &configured.path, &self.peers)?;
                validate_route_overrides(dest, configured)?;
                if configured
                    .override_upstream_dns
                    .as_ref()
                    .is_some_and(Vec::is_empty)
                {
                    return Err(ConfigError::Invalid(format!(
                        "path to {dest} override_upstream_dns must not be empty when configured"
                    )));
                }
            }
        }
        if let Some(direct) = &self.direct {
            for (index, route) in direct.routes.iter().enumerate() {
                if route.bind {
                    return Err(ConfigError::Invalid(format!(
                        "direct.routes[{index}].bind is not supported"
                    )));
                }
            }
        }
        for destination in self.path_policies.keys() {
            if !self.peers.contains_key(destination) {
                return Err(ConfigError::Invalid(format!(
                    "path policy destination {destination} is not a configured peer"
                )));
            }
        }
        for route in self.route_imports() {
            if route.candidates.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "route {} has no candidates",
                    route.prefix
                )));
            }
            let mut nodes = HashSet::new();
            for c in &route.candidates {
                if !nodes.insert(&c.node) {
                    return Err(ConfigError::Invalid(format!(
                        "route {} repeats candidate {}",
                        route.prefix, c.node
                    )));
                }
                if !self.peers.contains_key(&c.node) {
                    return Err(ConfigError::Invalid(format!(
                        "route {} candidate {} is not a configured peer",
                        route.prefix, c.node
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn status_socket(&self) -> String {
        self.runtime
            .status_socket
            .clone()
            .unwrap_or_else(|| Self::default_status_socket(&self.id))
    }

    pub fn default_status_socket(node_id: &str) -> String {
        format!("{}/{node_id}.sock", Self::default_status_socket_dir())
    }

    pub fn default_status_socket_dir() -> &'static str {
        if cfg!(target_os = "linux") {
            "/run/tinect"
        } else {
            "/var/run/tinect"
        }
    }

    /// Groups route entries declared under peers into the routing engine's
    /// prefix/candidate representation.
    pub fn route_imports(&self) -> Vec<RouteImport> {
        let mut grouped = BTreeMap::<IpNet, Vec<RouteCandidate>>::new();
        for (node, peer) in &self.peers {
            for route in &peer.routes {
                for prefix in self.peer_route_prefixes(route) {
                    upsert_candidate(&mut grouped, prefix, node, route.priority_resolved());
                }
            }
        }
        grouped
            .into_iter()
            .map(|(prefix, candidates)| RouteImport { prefix, candidates })
            .collect()
    }

    /// Returns the source CIDRs explicitly bound to each configured peer.
    /// Route priority and route overrides intentionally do not participate in
    /// this identity authorization relation.
    pub fn source_bindings(&self) -> Vec<(IpNet, String)> {
        self.peers
            .values()
            .flat_map(|peer| {
                peer.bind_addresses
                    .iter()
                    .copied()
                    .chain(
                        peer.routes
                            .iter()
                            .filter_map(|route| route.bind.then_some(route.ip_cidr).flatten()),
                    )
                    .map(|prefix| (prefix, peer.public_key.clone()))
            })
            .collect()
    }

    pub fn domain_route_imports(&self) -> Vec<DomainRouteImport> {
        let mut grouped = BTreeMap::<SetId, Vec<RouteCandidate>>::new();
        for (node, peer) in &self.peers {
            for route in &peer.routes {
                if let Some(set_id) = route.site_id_resolved().filter(|set_id| {
                    self.route_sets
                        .site(*set_id)
                        .is_some_and(|site| site.has_domains())
                }) {
                    upsert_candidate(&mut grouped, set_id, node, route.priority_resolved());
                }
            }
        }
        grouped
            .into_iter()
            .map(|(set_id, candidates)| DomainRouteImport { set_id, candidates })
            .collect()
    }

    pub fn domain_site_ids(&self) -> Vec<SetId> {
        let mut ids = self
            .peers
            .values()
            .flat_map(|peer| {
                peer.routes
                    .iter()
                    .filter_map(|route| {
                        route.site_id_resolved().filter(|id| {
                            self.route_sets
                                .site(*id)
                                .is_some_and(|site| site.has_domains())
                        })
                    })
                    .chain(peer.paths.iter().flat_map(|path| {
                        path.override_routes.iter().filter_map(|route| {
                            route.site_id_resolved().filter(|id| {
                                self.route_sets
                                    .site(*id)
                                    .is_some_and(|site| site.has_domains())
                            })
                        })
                    }))
            })
            .chain(self.direct.iter().flat_map(|direct| {
                direct.routes.iter().filter_map(|route| {
                    route.site_id_resolved().filter(|id| {
                        self.route_sets
                            .site(*id)
                            .is_some_and(|site| site.has_domains())
                    })
                })
            }))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    pub fn direct_prefix_routes(&self) -> Vec<(IpNet, u32)> {
        self.direct
            .iter()
            .flat_map(|direct| &direct.routes)
            .flat_map(|route| {
                self.peer_route_prefixes(route)
                    .into_iter()
                    .map(|prefix| (prefix, route.priority_resolved()))
            })
            .collect()
    }

    pub fn direct_domain_routes(&self) -> Vec<(SetId, u32)> {
        self.direct
            .iter()
            .flat_map(|direct| &direct.routes)
            .filter_map(|route| {
                route
                    .site_id_resolved()
                    .filter(|set_id| {
                        self.route_sets
                            .site(*set_id)
                            .is_some_and(|site| site.has_domains())
                    })
                    .map(|set_id| (set_id, route.priority_resolved()))
            })
            .collect()
    }

    /// Builds routes from overrides captured in active circuit leases.  The
    /// input is immutable lease metadata, so route selection does not need
    /// to rediscover a path or retain a mutable "previous path" cache.
    pub fn effective_route_imports_for_active_leases(
        &self,
        active_overrides: &HashMap<String, Vec<RouteOverride>>,
    ) -> Vec<RouteImport> {
        let mut grouped = BTreeMap::<IpNet, Vec<RouteCandidate>>::new();
        for (node, peer) in &self.peers {
            let overrides = active_overrides.get(node).map(Vec::as_slice);
            for route in &peer.routes {
                let priority = overrides
                    .and_then(|overrides| {
                        overrides.iter().find(|override_route| {
                            override_is_wildcard(override_route)
                                || route.selector_eq_override(override_route)
                        })
                    })
                    .map_or(Some(route.priority_resolved()), |override_route| {
                        override_route.priority_for(route.priority_resolved())
                    });
                if let Some(priority) = priority {
                    for prefix in self.peer_route_prefixes(route) {
                        upsert_candidate(&mut grouped, prefix, node, priority);
                    }
                }
            }
            let Some(overrides) = overrides else {
                continue;
            };
            for override_route in overrides {
                if override_is_wildcard(override_route) {
                    continue;
                }
                if peer
                    .routes
                    .iter()
                    .any(|route| route.selector_eq_override(override_route))
                {
                    continue;
                }
                let Some(priority) = override_route.priority else {
                    continue;
                };
                if priority > 0 {
                    for prefix in self.override_prefixes(override_route) {
                        upsert_candidate(&mut grouped, prefix, node, priority);
                    }
                }
            }
        }
        grouped
            .into_iter()
            .map(|(prefix, candidates)| RouteImport { prefix, candidates })
            .filter(|route| !route.candidates.is_empty())
            .collect()
    }

    pub fn effective_domain_route_imports_for_active_leases(
        &self,
        active_overrides: &HashMap<String, Vec<RouteOverride>>,
    ) -> Vec<DomainRouteImport> {
        let mut grouped = BTreeMap::<SetId, Vec<RouteCandidate>>::new();
        for (node, peer) in &self.peers {
            let overrides = active_overrides.get(node).map(Vec::as_slice);
            for route in &peer.routes {
                let Some(set_id) = route.site_id_resolved().filter(|set_id| {
                    self.route_sets
                        .site(*set_id)
                        .is_some_and(|site| site.has_domains())
                }) else {
                    continue;
                };
                let priority = overrides
                    .and_then(|items| {
                        items.iter().find(|item| {
                            override_is_wildcard(item) || route.selector_eq_override(item)
                        })
                    })
                    .map_or(Some(route.priority_resolved()), |item| {
                        item.priority_for(route.priority_resolved())
                    });
                if let Some(priority) = priority {
                    upsert_candidate(&mut grouped, set_id, node, priority);
                }
            }
            if let Some(overrides) = overrides {
                for item in overrides {
                    let Some(set_id) = item.site_id_resolved().filter(|set_id| {
                        self.route_sets
                            .site(*set_id)
                            .is_some_and(|site| site.has_domains())
                    }) else {
                        continue;
                    };
                    if peer
                        .routes
                        .iter()
                        .any(|route| route.selector_eq_override(item))
                    {
                        continue;
                    }
                    if let Some(priority) = item.priority.filter(|value| *value > 0) {
                        upsert_candidate(&mut grouped, set_id, node, priority);
                    }
                }
            }
        }
        grouped
            .into_iter()
            .map(|(set_id, candidates)| DomainRouteImport { set_id, candidates })
            .collect()
    }

    /// Returns the overrides for the configured manual path corresponding to
    /// a wire path. Callers that create a circuit lease capture this value so
    /// later route refreshes do not need to infer the path again.
    pub fn route_overrides_for_wire(
        &self,
        destination: &str,
        wire_path: &[String],
    ) -> Vec<RouteOverride> {
        let Some(peer) = self.peers.get(destination) else {
            return Vec::new();
        };
        peer.paths
            .iter()
            .find(|configured| {
                configured.path.len() == wire_path.len()
                    && configured
                        .path
                        .iter()
                        .zip(wire_path)
                        .all(|(name, identity)| {
                            self.wire_identity(name).as_deref() == Some(identity)
                        })
            })
            .map(|configured| configured.override_routes.clone())
            .unwrap_or_default()
    }

    /// Resolves the DNS upstream precedence for one Circuit lease:
    /// path override, destination peer override, then the global FakeIP list.
    pub fn upstream_dns_for_wire(&self, destination: &str, wire_path: &[String]) -> Vec<DnsServer> {
        let Some(peer) = self.peers.get(destination) else {
            return Vec::new();
        };
        peer.paths
            .iter()
            .find(|configured| {
                configured.path.len() == wire_path.len()
                    && configured
                        .path
                        .iter()
                        .zip(wire_path)
                        .all(|(name, identity)| {
                            self.wire_identity(name).as_deref() == Some(identity)
                        })
            })
            .and_then(|configured| configured.override_upstream_dns.clone())
            .or_else(|| peer.upstream_dns.clone())
            .or_else(|| self.fake_ip.as_ref().map(|fake| fake.upstream_dns.clone()))
            .unwrap_or_default()
    }

    fn wire_identity(&self, name: &str) -> Option<String> {
        if name == self.id {
            self.local_identity().ok()
        } else {
            self.peer_identity(name)
        }
    }

    /// Returns all prefixes that may be introduced by a path override. These
    /// prefixes are needed by the host routing plan even before a circuit is
    /// active.
    pub fn override_route_prefixes(&self) -> Vec<IpNet> {
        let mut prefixes = self
            .peers
            .values()
            .flat_map(|peer| peer.paths.iter())
            .flat_map(|path| path.override_routes.iter())
            .filter(|route| route.priority_for(0).is_some())
            .flat_map(|route| self.override_prefixes(route))
            .collect::<Vec<_>>();
        prefixes.sort_unstable();
        prefixes.dedup();
        prefixes
    }

    fn peer_route_prefixes(&self, route: &PeerRoute) -> Vec<IpNet> {
        route
            .site_id_resolved()
            .and_then(|id| self.route_sets.site(id))
            .map_or_else(
                || route.ip_cidr.into_iter().collect(),
                |site| site.prefixes().to_vec(),
            )
    }

    fn override_prefixes(&self, route: &RouteOverride) -> Vec<IpNet> {
        route
            .site_id_resolved()
            .and_then(|id| self.route_sets.site(id))
            .map_or_else(
                || route.ip_cidr.into_iter().collect(),
                |site| site.prefixes().to_vec(),
            )
    }

    /// Returns only declared prefixes that need a host routing-table entry.
    ///
    /// A TUN address with a subnet mask already installs its connected route
    /// in the host.  More-specific peer routes inside that subnet must still
    /// participate in Tinect's encrypted route selection, but installing
    /// them again would override the connected route and needlessly alter
    /// local host routing.
    pub fn managed_route_imports(&self) -> Vec<RouteImport> {
        let mut routes = self.route_imports();
        let existing = routes
            .iter()
            .map(|route| route.prefix)
            .collect::<HashSet<_>>();
        for prefix in self.override_route_prefixes() {
            if !existing.contains(&prefix) {
                routes.push(RouteImport {
                    prefix,
                    candidates: Vec::new(),
                });
            }
        }
        for (prefix, _) in self.direct_prefix_routes() {
            if !routes.iter().any(|route| route.prefix == prefix) {
                routes.push(RouteImport {
                    prefix,
                    candidates: Vec::new(),
                });
            }
        }
        if let Some(fake) = &self.fake_ip {
            for prefix in [
                Some(fake.ipv4_pool),
                (!fake.disable_ipv6).then_some(fake.ipv6_pool),
            ]
            .into_iter()
            .flatten()
            {
                if !routes.iter().any(|route| route.prefix == prefix) {
                    routes.push(RouteImport {
                        prefix,
                        candidates: Vec::new(),
                    });
                }
            }
        }
        routes
            .into_iter()
            .filter(|route| {
                !self.tun.addresses.iter().any(|local_prefix| {
                    local_prefix.prefix_len() <= route.prefix.prefix_len()
                        && local_prefix.contains(&route.prefix.network())
                })
            })
            .collect()
    }

    /// Resolves a local operator-facing node name to its wire identity.
    /// Node names never cross the network boundary; wire protocols use the
    /// stable hash of the configured Ed25519 public key instead.
    pub fn peer_identity(&self, name: &str) -> Option<String> {
        self.peers.get(name).and_then(|peer| {
            identity::decode_public(&peer.public_key)
                .ok()
                .map(|key| identity::node_id(&key))
        })
    }

    /// Looks up a configured peer by its wire identity. Paths use identities
    /// rather than local configuration names.
    pub fn peer_by_identity(&self, identity: &str) -> Option<&Peer> {
        self.peers.iter().find_map(|(name, peer)| {
            (self.peer_identity(name).as_deref() == Some(identity)).then_some(peer)
        })
    }

    /// Returns the local operator-facing name for a configured wire identity.
    /// This is intentionally only a presentation lookup: authorization and
    /// all wire protocols continue to use the public-key fingerprint.
    pub fn peer_name_by_identity(&self, identity: &str) -> Option<&str> {
        self.peers.iter().find_map(|(name, _)| {
            (self.peer_identity(name).as_deref() == Some(identity)).then_some(name.as_str())
        })
    }

    pub fn local_identity(&self) -> Result<String, identity::IdentityError> {
        Ok(identity::node_id(&self.load_identity()?.verifying_key()))
    }
}
fn validate_path(
    local: &str,
    dest: &str,
    path: &[String],
    peers: &BTreeMap<String, Peer>,
) -> Result<(), ConfigError> {
    if path.len() < 2
        || path.first().map(String::as_str) != Some(local)
        || path.last().map(String::as_str) != Some(dest)
    {
        return Err(ConfigError::Invalid(format!(
            "path to {dest} must start at {local} and end at {dest}"
        )));
    }
    let mut seen = HashSet::new();
    for n in path {
        if !seen.insert(n) {
            return Err(ConfigError::Invalid(format!(
                "path to {dest} has a loop at {n}"
            )));
        }
        if n != local && n != dest && !peers.contains_key(n) {
            return Err(ConfigError::Invalid(format!(
                "path relay {n} is not a configured peer"
            )));
        }
    }
    Ok(())
}

fn validate_route_overrides(
    destination: &str,
    configured: &ConfiguredPath,
) -> Result<(), ConfigError> {
    if configured.override_routes.is_empty() {
        return Ok(());
    }
    let mut selectors = HashSet::new();
    let mut has_wildcard = false;
    for route in &configured.override_routes {
        if route.priority.is_some() == route.priority_delta.is_some() {
            return Err(ConfigError::Invalid(format!(
                "path to {destination} override route must specify exactly one of priority or priority_delta"
            )));
        }
        let selector_count = usize::from(route.ip_cidr.is_some())
            + usize::from(route.domain.is_some())
            + usize::from(route.site_set.is_some());
        if selector_count > 1 {
            return Err(ConfigError::Invalid(format!(
                "path to {destination} override route must use at most one selector"
            )));
        }
        if selector_count == 1 && route.priority.is_none() {
            return Err(ConfigError::Invalid(format!(
                "path to {destination} override route with a selector must use priority"
            )));
        }
        if selector_count == 1 {
            let selector = if let Some(prefix) = route.ip_cidr {
                format!("ip_cidr:{prefix}")
            } else if let Some(domain) = &route.domain {
                format!("domain:{domain}")
            } else {
                format!("site_set:{}", route.site_set.as_deref().unwrap_or_default())
            };
            if !selectors.insert(selector.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "path to {destination} repeats override selector {selector}"
                )));
            }
            if has_wildcard {
                return Err(ConfigError::Invalid(format!(
                    "path to {destination} cannot combine wildcard and prefix override routes"
                )));
            }
        } else {
            if has_wildcard || !selectors.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "path to {destination} cannot combine wildcard and prefix override routes"
                )));
            }
            has_wildcard = true;
        }
    }
    Ok(())
}

fn override_is_wildcard(route: &RouteOverride) -> bool {
    route.ip_cidr.is_none() && route.domain.is_none() && route.site_set.is_none()
}

fn upsert_candidate<K: Ord>(
    grouped: &mut BTreeMap<K, Vec<RouteCandidate>>,
    key: K,
    node: &str,
    priority: u32,
) {
    let candidates = grouped.entry(key).or_default();
    match candidates
        .iter_mut()
        .find(|candidate| candidate.node == node)
    {
        Some(candidate) => candidate.priority = candidate.priority.max(priority),
        None => candidates.push(RouteCandidate {
            node: node.to_owned(),
            priority,
        }),
    }
}

fn prefixes_overlap(left: IpNet, right: IpNet) -> bool {
    left.addr().is_ipv4() == right.addr().is_ipv4()
        && (left.contains(&right.network()) || right.contains(&left.network()))
}
#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            r#"
id: a
identity_key_path: /tmp/a.key
listen: quic://127.0.0.1:4433
tun: {{name: tinea, addresses: [10.64.0.1/32]}}
peers:
  b:
    public_key: {key}
    endpoints: [quic://127.0.0.1:4434]
    routes: [{{ip_cidr: 10.64.0.2/32, priority: 100}}]
    paths:
      - path: [a, b]
connect_to: [b]
"#
        );
        let config: Config = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();
        config
    }

    #[test]
    fn peer_route_priority_defaults_to_100() {
        let route: PeerRoute = serde_yaml::from_str("ip_cidr: 192.168.191.10/32\n").unwrap();
        assert_eq!(route.priority, 100);
        assert!(!route.bind);
    }

    #[test]
    fn source_bindings_combine_explicit_addresses_and_bound_ip_routes() {
        let b_key = identity::encode_public(&identity::generate().verifying_key());
        let c_key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: /tmp/a.key\nlisten: quic://127.0.0.1:4433\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  b:\n    public_key: {b_key}\n    endpoints: []\n    bind_addresses: [10.0.0.1/32]\n    routes: [{{ip_cidr: 10.0.0.2/32, bind: true}}]\n  c:\n    public_key: {c_key}\n    endpoints: []\n    bind_addresses: [10.0.0.1/32]\n"
        );
        let config: Config = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();

        let bindings = config.source_bindings();
        assert!(bindings.contains(&("10.0.0.1/32".parse().unwrap(), b_key.clone())));
        assert!(bindings.contains(&("10.0.0.1/32".parse().unwrap(), c_key.clone())));
        assert!(bindings.contains(&("10.0.0.2/32".parse().unwrap(), b_key)));
    }

    #[test]
    fn peer_route_bind_requires_an_ip_cidr() {
        let error =
            serde_yaml::from_str::<PeerRoute>("domain: example.test\nbind: true\n").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("bind requires an ip_cidr selector")
        );
    }

    #[test]
    fn direct_routes_cannot_create_source_bindings() {
        let mut configured = config();
        configured.direct = Some(DirectConfig {
            fallback: false,
            dscp: 46,
            fwmark: None,
            conntrack_zone: 32123,
            routes: vec![serde_yaml::from_str("ip_cidr: 10.0.0.1/32\nbind: true\n").unwrap()],
        });
        assert!(configured.validate().is_err());
    }

    #[test]
    fn peer_route_rejects_cidr_shorthand() {
        assert!(serde_yaml::from_str::<PeerRoute>("192.168.191.10/32\n").is_err());
    }

    #[test]
    fn pure_ip_site_sets_load_relative_to_config_without_fake_ip() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("cidrs.txt"),
            "ip-cidr:192.0.2.0/24\nip-cidr:2001:db8::/32\n",
        )
        .unwrap();
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n    routes: [{{site_set: ./cidrs.txt, priority: 90}}]\n"
        );
        fs::write(dir.path().join("node.yaml"), yaml).unwrap();
        let configured = Config::load(dir.path().join("node.yaml")).unwrap();
        assert!(configured.fake_ip.is_none());
        assert_eq!(configured.route_imports().len(), 2);
    }

    #[test]
    fn domain_routes_and_mixed_site_sets_require_fake_ip() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("mixed.txt"),
            "example.test\nip-cidr:192.0.2.0/24\n",
        )
        .unwrap();
        let key = identity::encode_public(&identity::generate().verifying_key());
        for selector in ["domain: example.test", "site_set: ./mixed.txt"] {
            let yaml = format!(
                "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n    routes: [{{{selector}, priority: 90}}]\n"
            );
            fs::write(dir.path().join("node.yaml"), yaml).unwrap();
            let error = Config::load(dir.path().join("node.yaml")).unwrap_err();
            assert!(error.to_string().contains("require fake_ip"));
        }
    }

    #[test]
    fn identical_site_sets_share_one_set_id_and_route_spec() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "example.test\n").unwrap();
        fs::write(dir.path().join("b.txt"), " example.test # duplicate\n").unwrap();
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\nfake_ip:\n  listen: 127.0.0.1:5354\n  upstream_dns: [1.1.1.1]\n  disable_ipv6: true\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n    routes:\n      - {{site_set: ./a.txt, priority: 100}}\n      - {{site_set: ./b.txt, priority: 80}}\n"
        );
        fs::write(dir.path().join("node.yaml"), yaml).unwrap();
        let configured = Config::load(dir.path().join("node.yaml")).unwrap();
        let routes = &configured.peers["b"].routes;
        assert_eq!(routes[0].site_id, routes[1].site_id);
        assert!(Arc::ptr_eq(
            routes[0].shared_selector.as_ref().unwrap(),
            routes[1].shared_selector.as_ref().unwrap()
        ));
        assert!(!Arc::ptr_eq(
            routes[0].shared_spec.as_ref().unwrap(),
            routes[1].shared_spec.as_ref().unwrap()
        ));
        assert_eq!(
            configured.domain_route_imports()[0].candidates[0].priority,
            100
        );
    }

    #[test]
    fn direct_routes_reuse_peer_sets_without_copying_contents() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("peer.txt"), "example.test\n").unwrap();
        fs::write(
            dir.path().join("direct.txt"),
            " example.test # same normalized contents\n",
        )
        .unwrap();
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\nfake_ip:\n  listen: 127.0.0.1:5354\n  upstream_dns: [1.1.1.1]\n  disable_ipv6: true\ndirect:\n  fallback: false\n  dscp: 46\n  conntrack_zone: 32123\n  routes:\n    - {{site_set: ./direct.txt, priority: 100}}\n    - {{ip_cidr: 192.0.2.0/24, priority: 80}}\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n    routes: [{{site_set: ./peer.txt, priority: 100}}]\n    paths:\n      - path: [a, b]\n        override_routes: [{{site_set: ./peer.txt, priority: 100}}]\n"
        );
        let mut configured: Config = serde_yaml::from_str(&yaml).unwrap();
        configured.load_route_sets(dir.path()).unwrap();

        let peer_id = configured.peers["b"].routes[0].site_id.unwrap();
        let direct = configured.direct.as_ref().unwrap();
        assert_eq!(direct.routes[0].site_id, Some(peer_id));
        assert!(Arc::ptr_eq(
            configured.peers["b"].routes[0]
                .shared_selector
                .as_ref()
                .unwrap(),
            direct.routes[0].shared_selector.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            configured.peers["b"].routes[0]
                .shared_spec
                .as_ref()
                .unwrap(),
            direct.routes[0].shared_spec.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            configured.peers["b"].routes[0]
                .shared_selector
                .as_ref()
                .unwrap(),
            configured.peers["b"].paths[0].override_routes[0]
                .shared_selector
                .as_ref()
                .unwrap()
        ));
        assert!(!direct.fallback);
        assert_eq!(configured.route_sets.entry_count(peer_id), 1);
        assert_eq!(configured.direct_domain_routes(), vec![(peer_id, 100)]);
        assert_eq!(
            configured.direct_prefix_routes(),
            vec![("192.0.2.0/24".parse().unwrap(), 80)]
        );
    }

    #[test]
    fn peer_public_keys_must_be_canonical_and_unique() {
        let mut non_canonical = config();
        let key = non_canonical.peers["b"].public_key.clone();
        non_canonical.peers.get_mut("b").unwrap().public_key = format!(" {key} ");
        assert!(non_canonical.validate().is_err());

        let mut duplicate = config();
        let peer = duplicate.peers["b"].clone();
        duplicate.peers.insert("c".into(), peer);
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn effective_routes_apply_exact_disable_and_add_new_prefix() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![
            RouteOverride {
                ip_cidr: Some("10.64.0.2/32".parse().unwrap()),
                priority: Some(0),
                priority_delta: None,
                ..Default::default()
            },
            RouteOverride {
                ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
                priority: Some(80),
                priority_delta: None,
                ..Default::default()
            },
        ];
        configured.validate().unwrap();
        let imports = configured.effective_route_imports_for_active_leases(&HashMap::from([(
            "b".into(),
            configured.peers["b"].paths[0].override_routes.clone(),
        )]));
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].prefix, "192.0.2.0/24".parse().unwrap());
        assert_eq!(imports[0].candidates[0].priority, 80);
    }

    #[test]
    fn effective_routes_apply_wildcard_delta_and_disable_at_zero() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            ip_cidr: None,
            priority: None,
            priority_delta: Some(-100),
            ..Default::default()
        }];
        configured.validate().unwrap();
        assert!(
            configured
                .effective_route_imports_for_active_leases(&HashMap::from([(
                    "b".into(),
                    configured.peers["b"].paths[0].override_routes.clone(),
                )]))
                .is_empty()
        );

        configured.peers.get_mut("b").unwrap().paths[0].override_routes[0].priority_delta =
            Some(-40);
        let imports = configured.effective_route_imports_for_active_leases(&HashMap::from([(
            "b".into(),
            configured.peers["b"].paths[0].override_routes.clone(),
        )]));
        assert_eq!(imports[0].candidates[0].priority, 60);
    }

    #[test]
    fn effective_routes_use_overrides_captured_in_the_active_lease() {
        let configured = config();
        let active_leases = HashMap::from([(
            "b".into(),
            vec![RouteOverride {
                ip_cidr: Some("10.64.0.2/32".parse().unwrap()),
                priority: Some(0),
                priority_delta: None,
                ..Default::default()
            }],
        )]);
        assert!(
            configured
                .effective_route_imports_for_active_leases(&active_leases)
                .is_empty()
        );
    }

    #[test]
    fn captures_manual_path_overrides_for_a_wire_path() {
        let mut configured = config();
        let overrides = vec![RouteOverride {
            ip_cidr: Some("10.64.0.2/32".parse().unwrap()),
            priority: Some(75),
            priority_delta: None,
            ..Default::default()
        }];
        let peer = configured.peers.get_mut("b").unwrap();
        peer.paths[0].path = vec!["b".into()];
        peer.paths[0].override_routes = overrides.clone();
        let wire_path = vec![configured.peer_identity("b").unwrap()];

        assert_eq!(
            configured.route_overrides_for_wire("b", &wire_path),
            overrides
        );
        assert!(
            configured
                .route_overrides_for_wire("unknown", &wire_path)
                .is_empty()
        );
    }

    #[test]
    fn dns_upstreams_follow_path_peer_global_precedence() {
        let mut configured = config();
        configured.identity_key_path = None;
        configured.identity_key = Some(identity::encode_secret(&identity::generate()));
        configured.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
            )
            .unwrap(),
        );
        let peer: Vec<DnsServer> = serde_yaml::from_str("[8.8.8.8]\n").unwrap();
        let path: Vec<DnsServer> = serde_yaml::from_str("[9.9.9.9:5353]\n").unwrap();
        let wire_path = vec![
            configured.local_identity().unwrap(),
            configured.peer_identity("b").unwrap(),
        ];

        assert_eq!(
            configured.upstream_dns_for_wire("b", &wire_path)[0].socket_addr(),
            "1.1.1.1:53".parse().unwrap()
        );
        configured.peers.get_mut("b").unwrap().upstream_dns = Some(peer);
        assert_eq!(
            configured.upstream_dns_for_wire("b", &wire_path)[0].socket_addr(),
            "8.8.8.8:53".parse().unwrap()
        );
        configured.peers.get_mut("b").unwrap().paths[0].override_upstream_dns = Some(path);
        assert_eq!(
            configured.upstream_dns_for_wire("b", &wire_path)[0].socket_addr(),
            "9.9.9.9:5353".parse().unwrap()
        );
    }

    #[test]
    fn dns_upstream_overrides_require_fake_ip_and_cannot_be_empty() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().upstream_dns = Some(Vec::new());
        assert!(configured.validate().is_err());

        configured.peers.get_mut("b").unwrap().upstream_dns =
            Some(serde_yaml::from_str("[8.8.8.8]\n").unwrap());
        assert!(configured.validate().is_err());

        configured.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
            )
            .unwrap(),
        );
        configured.peers.get_mut("b").unwrap().paths[0].override_upstream_dns = Some(Vec::new());
        assert!(configured.validate().is_err());
    }

    #[test]
    fn active_lease_overrides_do_not_depend_on_current_configured_path() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            ip_cidr: Some("10.64.0.2/32".parse().unwrap()),
            priority: Some(0),
            priority_delta: None,
            ..Default::default()
        }];

        let imports = configured.effective_route_imports_for_active_leases(&HashMap::from([(
            "b".into(),
            vec![RouteOverride {
                ip_cidr: Some("10.64.0.2/32".parse().unwrap()),
                priority: Some(55),
                priority_delta: None,
                ..Default::default()
            }],
        )]));

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].prefix, "10.64.0.2/32".parse().unwrap());
        assert_eq!(imports[0].candidates[0].priority, 55);
    }

    #[test]
    fn route_override_validation_rejects_ambiguous_forms() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
            priority: None,
            priority_delta: Some(1),
            ..Default::default()
        }];
        assert!(configured.validate().is_err());

        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![
            RouteOverride {
                ip_cidr: None,
                priority: Some(1),
                priority_delta: None,
                ..Default::default()
            },
            RouteOverride {
                ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
                priority: Some(1),
                priority_delta: None,
                ..Default::default()
            },
        ];
        assert!(configured.validate().is_err());
    }

    #[test]
    fn old_top_level_paths_are_rejected() {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            r#"
id: a
identity_key_path: /tmp/a.key
listen: quic://127.0.0.1:4433
tun: {{name: tinea, addresses: [10.64.0.1/32]}}
peers:
  b:
    public_key: {key}
paths:
  b: [[a, b]]
"#
        );
        assert!(serde_yaml::from_str::<Config>(&yaml).is_err());
    }

    #[test]
    fn dns_servers_accept_literal_addresses_and_default_port() {
        let ipv4: DnsServer = serde_yaml::from_str("10.0.0.53\n").unwrap();
        assert_eq!(ipv4.socket_addr(), "10.0.0.53:53".parse().unwrap());
        let ipv6: DnsServer = serde_yaml::from_str("'[2001:db8::53]:5353'\n").unwrap();
        assert_eq!(ipv6.socket_addr(), "[2001:db8::53]:5353".parse().unwrap());
        let ipv6_default: DnsServer = serde_yaml::from_str("'[2001:db8::53]'\n").unwrap();
        assert_eq!(
            ipv6_default.socket_addr(),
            "[2001:db8::53]:53".parse().unwrap()
        );
        assert!(serde_yaml::from_str::<DnsServer>("dns.example\n").is_err());
        assert!(serde_yaml::from_str::<DnsServer>("10.0.0.53:0\n").is_err());
    }

    #[test]
    fn removed_health_checks_are_rejected() {
        let yaml = serde_yaml::to_string(&config()).unwrap();
        let legacy = format!(
            "{yaml}health_checks:\n  b:\n    targets: [127.0.0.1:443]\n    interval_secs: 1\n    fail_after: 1\n    recover_after: 1\n    hold_down_secs: 0\n"
        );
        let error = serde_yaml::from_str::<Config>(&legacy).unwrap_err();
        assert!(error.to_string().contains("unknown field `health_checks`"));
    }

    #[test]
    fn peer_endpoints_reject_zero_or_malformed_ports() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().endpoints = vec!["quic://127.0.0.1:0".into()];
        assert!(configured.validate().is_err());
        configured.peers.get_mut("b").unwrap().endpoints = vec!["quic://[2001:db8::1]:443".into()];
        assert!(configured.validate().is_ok());
        configured.peers.get_mut("b").unwrap().endpoints = vec!["quic://2001:db8::1:443".into()];
        assert!(configured.validate().is_err());
    }

    #[test]
    fn fake_tcp_reset_key_defaults_allows_custom_key_and_can_be_disabled() {
        let default = config();
        assert_eq!(
            default.fake_tcp_reset_key.as_bytes(),
            Some(DEFAULT_FAKE_TCP_RESET_KEY.as_bytes())
        );

        let key = identity::encode_public(&identity::generate().verifying_key());
        let disabled: Config = serde_yaml::from_str(&format!(
            "id: a\nidentity_key_path: /tmp/a.key\nlisten: quic://127.0.0.1:4433\nfake_tcp_reset_key: false\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  b:\n    public_key: {key}\n    endpoints: [quic://127.0.0.1:4434]\n"
        ))
        .unwrap();
        disabled.validate().unwrap();
        assert_eq!(disabled.fake_tcp_reset_key.as_bytes(), None);

        let mut custom = default;
        custom.fake_tcp_reset_key = FakeTcpResetKey::Key("private-reset-key".into());
        custom.validate().unwrap();
        assert_eq!(
            custom.fake_tcp_reset_key.as_bytes(),
            Some(b"private-reset-key".as_slice())
        );

        custom.fake_tcp_reset_key = FakeTcpResetKey::Disabled(true);
        assert!(custom.validate().is_err());
        custom.fake_tcp_reset_key = FakeTcpResetKey::Key(String::new());
        assert!(custom.validate().is_err());
    }

    #[test]
    fn nft_healthy_set_targets_validate_and_derive_names() {
        let configured = config();
        let mut configured = configured;
        configured.nft_healthy_set = Some(NftHealthySetConfig {
            prefix: Some("router_policy:tinect_healthy".into()),
            v6: Some("other:tinect_route_v6".into()),
            destroy_set: true,
            destroy_table: false,
            ..Default::default()
        });
        let targets = configured.nft_healthy_set_targets().unwrap();
        assert_eq!(targets.v4.unwrap().name, "tinect_healthy_v4");
        assert_eq!(targets.v6.unwrap().table, "other");
        assert!(targets.destroy_set);
        assert!(!targets.destroy_table);
    }

    #[test]
    fn nft_healthy_set_rejects_invalid_identity_and_collision() {
        let mut configured = config();
        for value in ["missing-separator", "a:", ":b", "a:b:c", "a:bad-name"] {
            configured.nft_healthy_set = Some(NftHealthySetConfig {
                prefix: Some(value.into()),
                ..Default::default()
            });
            assert!(configured.nft_healthy_set_targets().is_err(), "{value}");
        }
        configured.nft_healthy_set = Some(NftHealthySetConfig {
            v4: Some("router:tinect".into()),
            v6: Some("router:tinect".into()),
            ..Default::default()
        });
        assert!(configured.nft_healthy_set_targets().is_err());
    }

    #[test]
    fn nft_healthy_set_cleanup_defaults_to_disabled() {
        let configured = config();
        let targets = configured.nft_healthy_set_targets().unwrap();
        assert!(!targets.destroy_set);
        assert!(!targets.destroy_table);
    }

    #[test]
    fn nft_healthy_set_supports_explicit_family_targets_without_prefix() {
        let mut configured = config();
        configured.nft_healthy_set = Some(NftHealthySetConfig {
            v4: Some("v4_table:healthy".into()),
            v6: Some("v6_table:healthy".into()),
            destroy_set: true,
            destroy_table: true,
            ..Default::default()
        });

        let targets = configured.nft_healthy_set_targets().unwrap();
        assert_eq!(targets.v4.as_ref().unwrap().table, "v4_table");
        assert_eq!(targets.v4.as_ref().unwrap().name, "healthy");
        assert_eq!(targets.v6.as_ref().unwrap().table, "v6_table");
        assert_eq!(targets.v6.as_ref().unwrap().name, "healthy");
        assert!(targets.destroy_set);
        assert!(targets.destroy_table);
    }

    #[test]
    fn legacy_local_fallback_is_rejected_as_an_unknown_field() {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let error = serde_yaml::from_str::<Config>(&format!(
            "id: a\nidentity_key_path: /tmp/a\nlisten: quic://127.0.0.1:4433\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\nlocal_route_fallback: [10.0.0.0/8]\npeers:\n  b:\n    public_key: {key}\n"
        ))
        .unwrap_err();
        assert!(error.to_string().contains("local_route_fallback"));
    }
    #[test]
    fn route_candidate_uses_automatic_path_by_default() {
        let mut automatic = config();
        automatic.peers.get_mut("b").unwrap().paths.clear();
        assert!(automatic.validate().is_ok());
    }

    #[test]
    fn paths_and_path_policies_require_a_configured_destination() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths = vec![ConfiguredPath {
            path: vec!["a".into(), "missing".into()],
            override_routes: Vec::new(),
            override_upstream_dns: None,
        }];
        assert!(configured.validate().is_err());

        configured.peers.get_mut("b").unwrap().paths.clear();
        configured
            .path_policies
            .insert("missing".into(), crate::topology::PathConstraint::default());
        assert!(configured.validate().is_err());

        configured.path_policies.remove("missing");
        configured
            .path_policies
            .insert("b".into(), crate::topology::PathConstraint::default());
        assert!(configured.validate().is_ok());
    }

    #[test]
    fn looks_up_peer_by_wire_identity() {
        let configured = config();
        let identity = configured.peer_identity("b").unwrap();
        assert!(configured.peer_by_identity(&identity).is_some());
        assert_eq!(configured.peer_name_by_identity(&identity), Some("b"));
        assert!(configured.peer_by_identity("not-a-peer").is_none());
        assert_eq!(configured.peer_name_by_identity("not-a-peer"), None);
    }

    #[test]
    fn rejects_removed_peer_pmtu_field() {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: /tmp/a.key\nlisten: quic://127.0.0.1:4433\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n    pmtu: 1500\n"
        );
        assert!(serde_yaml::from_str::<Config>(&yaml).is_err());
    }

    #[test]
    fn clamp_mss_defaults_to_true_and_can_be_disabled() {
        assert!(config().tun.clamp_mss);
        let mut configured = config();
        configured.tun.clamp_mss = false;
        assert!(!configured.tun.clamp_mss);
    }

    #[test]
    fn direct_validates_dscp_and_fwmark() {
        let mut configured = config();
        configured.direct = Some(DirectConfig {
            fallback: true,
            dscp: 63,
            fwmark: Some(0x100),
            conntrack_zone: 32123,
            routes: Vec::new(),
        });
        #[cfg(target_os = "linux")]
        assert!(configured.validate().is_ok());
        #[cfg(not(target_os = "linux"))]
        assert!(configured.validate().is_err());

        configured.direct.as_mut().unwrap().fwmark = None;
        #[cfg(target_os = "linux")]
        assert!(configured.validate().is_ok());

        configured.direct.as_mut().unwrap().dscp = 64;
        assert!(configured.validate().is_err());

        configured.direct.as_mut().unwrap().dscp = 46;
        configured.direct.as_mut().unwrap().conntrack_zone = 0;
        assert!(configured.validate().is_err());
    }

    #[test]
    fn direct_parses_zone_and_nonzero_fwmark() {
        let yaml = "dscp: 46\nfwmark: 0x100\nconntrack_zone: 32123\n";
        let fallback: DirectConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!fallback.fallback);
        assert_eq!(fallback.fwmark, Some(0x100));
        assert_eq!(fallback.conntrack_zone, 32123);

        let zero: DirectConfig =
            serde_yaml::from_str("dscp: 46\nfwmark: 0\nconntrack_zone: 32123\n").unwrap();
        let mut configured = config();
        configured.direct = Some(zero);
        assert!(configured.validate().is_err());

        let maximum: DirectConfig =
            serde_yaml::from_str("dscp: 46\nfwmark: 0xffffffff\nconntrack_zone: 65535\n").unwrap();
        assert_eq!(maximum.fwmark, Some(u32::MAX));
        assert_eq!(maximum.conntrack_zone, u16::MAX);
    }

    #[test]
    fn direct_rejects_invalid_fwmark_yaml() {
        assert!(
            serde_yaml::from_str::<DirectConfig>(
                "dscp: 46\nfwmark: 0x100000000\nconntrack_zone: 32123\n"
            )
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<DirectConfig>("dscp: 46\nfwmark: -1\nconntrack_zone: 32123\n")
                .is_err()
        );
        assert!(
            serde_yaml::from_str::<DirectConfig>("dscp: 46\nconntrack_zone: 32123\nunknown: 1\n")
                .is_err()
        );
        assert!(serde_yaml::from_str::<DirectConfig>("dscp: 46\n").is_err());
    }

    #[test]
    fn debug_redacts_identity_and_reset_keys() {
        let mut configured = config();
        configured.identity_key = Some("SECRET-IDENTITY".into());
        configured.fake_tcp_reset_key = FakeTcpResetKey::Key("shared-secret".into());
        let rendered = format!("{configured:?}");
        assert!(!rendered.contains("SECRET-IDENTITY"));
        assert!(!rendered.contains("shared-secret"));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn top_level_fwmark_must_be_nonzero_and_differ_from_direct() {
        let mut configured = config();
        configured.fwmark = Some(0);
        assert!(configured.validate().is_err());

        configured.fwmark = Some(0x100);
        configured.direct = Some(DirectConfig {
            fallback: false,
            dscp: 46,
            fwmark: Some(0x100),
            conntrack_zone: 32123,
            routes: Vec::new(),
        });
        assert!(configured.validate().is_err());

        configured.direct.as_mut().unwrap().fwmark = Some(0x200);
        #[cfg(target_os = "linux")]
        assert!(configured.validate().is_ok());
        #[cfg(not(target_os = "linux"))]
        assert!(configured.validate().is_err());
    }

    #[test]
    fn pcap_buffer_is_bounded() {
        let mut configured = config();
        configured.runtime.pcap_buffer_packets = 65_536;
        assert!(configured.validate().is_ok());
        configured.runtime.pcap_buffer_packets = 65_537;
        assert!(configured.validate().is_err());
    }

    #[test]
    fn empty_node_selector_matches_nothing() {
        let empty = RouteSourceSelector::Nodes(Vec::new());
        assert!(!empty.matches("anyone", true));
        assert!(!empty.matches("anyone", false));
    }

    #[test]
    fn removed_direct_fallback_key_is_rejected() {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: /tmp/a.key\nlisten: quic://127.0.0.1:4433\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\ndirect_fallback:\n  dscp: 46\n  conntrack_zone: 32123\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n"
        );
        assert!(serde_yaml::from_str::<Config>(&yaml).is_err());
    }

    #[test]
    fn link_health_has_safe_defaults_and_rejects_invalid_timeout() {
        let mut configured = config();
        assert_eq!(configured.link_health.keepalive_secs, 10);
        assert_eq!(configured.link_health.idle_timeout_secs, 35);
        assert_eq!(configured.link_health.reconnect_interval_secs, 2);

        configured.link_health.idle_timeout_secs = 10;
        assert!(configured.validate().is_err());
        configured.link_health.idle_timeout_secs = 60;
        configured.link_health.keepalive_secs = TOPOLOGY_ADVERTISEMENT_TTL_SECS;
        assert!(configured.validate().is_err());
        configured.link_health.keepalive_secs = 10;
        configured.link_health.reconnect_interval_secs = 0;
        assert!(configured.validate().is_err());
    }

    #[test]
    fn path_migration_has_bounded_safe_defaults() {
        let mut configured = config();
        assert_eq!(configured.path_migration.readiness_stability_secs, 1);
        assert_eq!(configured.path_migration.deadline_secs, 5);
        assert_eq!(configured.path_migration.drain_timeout_secs, 1);
        configured.path_migration.readiness_stability_secs = 0;
        assert!(configured.validate().is_err());
        configured.path_migration = crate::config::PathMigrationConfig {
            readiness_stability_secs: 3,
            deadline_secs: 2,
            drain_timeout_secs: 1,
        };
        assert!(configured.validate().is_err());
        configured.path_migration = crate::config::PathMigrationConfig {
            readiness_stability_secs: 1,
            deadline_secs: 2,
            drain_timeout_secs: 0,
        };
        assert!(configured.validate().is_ok());
    }

    #[test]
    fn rejects_more_peers_than_one_lsa_can_advertise() {
        let mut configured = config();
        let peer = configured.peers["b"].clone();
        for index in 0..crate::topology::MAX_NEIGHBORS_PER_LSA {
            configured
                .peers
                .insert(format!("extra-{index}"), peer.clone());
        }
        assert!(configured.validate().is_err());
    }

    #[test]
    fn peer_permissions_default_connects_but_transit_requires_enablement() {
        let configured = config();
        assert!(configured.accept_connections);
        assert!(!configured.allow_transit);
        assert_eq!(configured.peers["b"].accept_connections, None);
        assert_eq!(configured.peers["b"].allow_transit, None);
        assert_eq!(configured.peers["b"].allow_relay, None);
        assert!(configured.peers["b"].accepts_connections(configured.accept_connections));
        assert!(!configured.peers["b"].allows_transit(configured.allow_transit));

        let mut denied = configured;
        denied.accept_connections = true;
        denied.allow_transit = true;
        assert!(denied.peers["b"].accepts_connections(denied.accept_connections));
        assert!(denied.peers["b"].allows_transit(denied.allow_transit));
        denied.peers.get_mut("b").unwrap().accept_connections = Some(true);
        denied.peers.get_mut("b").unwrap().allow_transit = Some(true);
        denied.peers.get_mut("b").unwrap().allow_relay = Some(true);
        assert!(denied.peers["b"].accepts_connections(denied.accept_connections));
        assert!(denied.peers["b"].allows_transit(denied.allow_transit));
        assert!(denied.peers["b"].allows_relay());
        denied.peers.get_mut("b").unwrap().accept_connections = Some(false);
        denied.peers.get_mut("b").unwrap().allow_transit = Some(false);
        assert_eq!(denied.peers["b"].accept_connections, Some(false));
        assert_eq!(denied.peers["b"].allow_transit, Some(false));
    }

    #[test]
    fn rejects_unknown_fields_and_non_loopback_metrics() {
        let yaml = r#"
id: a
identity_key_path: /tmp/a.key
listen: quic://127.0.0.1:4433
tun: {name: tinea, addresses: [10.64.0.1/32]}
allow_transitt: true
"#;
        assert!(serde_yaml::from_str::<Config>(yaml).is_err());

        let mut configured = config();
        configured.runtime.metrics_listen = Some("0.0.0.0:9900".parse().unwrap());
        assert!(configured.validate().is_err());
        configured.runtime.metrics_listen = Some("127.0.0.1:9900".parse().unwrap());
        assert!(configured.validate().is_ok());
    }

    #[test]
    fn shutdown_timeout_has_safe_default_and_range() {
        let configured = config();
        assert_eq!(configured.runtime.shutdown_timeout_secs, 10);
        let mut invalid = configured;
        invalid.runtime.shutdown_timeout_secs = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn lifecycle_hooks_are_optional_but_must_be_nonempty_and_nul_free() {
        assert!(serde_yaml::from_str::<LifecycleCommands>("echo ready").is_err());

        let mut configured = config();
        configured.post_up = Some(vec!["echo ready".into()].into());
        configured.pre_down = Some(vec!["echo stopping".into()].into());
        assert!(configured.validate().is_ok());

        configured.post_up = Some(vec!["  \n".into()].into());
        assert!(configured.validate().is_err());
        configured.post_up = Some(vec!["echo bad\0command".into()].into());
        assert!(configured.validate().is_err());
    }

    #[test]
    fn connect_to_must_name_a_unique_peer_with_an_endpoint() {
        let mut configured = config();
        configured.connect_to = vec!["missing".into()];
        assert!(configured.validate().is_err());

        configured.connect_to = vec!["b".into(), "b".into()];
        assert!(configured.validate().is_err());

        configured.connect_to = vec!["b".into()];
        configured.peers.get_mut("b").unwrap().endpoints.clear();
        assert!(configured.validate().is_err());
    }

    #[test]
    fn connect_to_supports_per_peer_repair_rate_without_changing_string_shorthand() {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            r#"
id: a
identity_key_path: /tmp/a.key
listen: quic://127.0.0.1:4433
tun: {{name: tinea, addresses: [10.64.0.1/32]}}
repair_rate: 0.25
peers:
  b:
    public_key: {key}
    endpoints: [quic://127.0.0.1:4434]
connect_to:
  - peer: b
    repair_rate: 0.75
"#
        );
        let configured: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(configured.repair_rate, 0.25);
        assert_eq!(configured.connect_to[0].peer_name(), "b");
        assert_eq!(configured.connect_to[0].repair_rate_milli(), 750);
        configured.validate().unwrap();

        let shorthand: Vec<ConnectTarget> = serde_yaml::from_str("[b]").unwrap();
        assert_eq!(shorthand[0].repair_rate_milli(), 0);
    }

    #[test]
    fn repair_rate_rejects_non_finite_or_excessive_values() {
        let mut configured = config();
        configured.repair_rate = 8.1;
        assert!(configured.validate().is_err());
        configured.repair_rate = f64::NAN;
        assert!(configured.validate().is_err());
        configured.repair_rate = 0.0009;
        assert!(configured.validate().is_err());
        configured.repair_rate = 0.0;
        configured.connect_to = vec![ConnectTarget::Configured(ConnectTargetConfig {
            peer: "b".into(),
            repair_rate: -0.1,
        })];
        assert!(configured.validate().is_err());
    }

    #[test]
    fn fec_possible_uses_the_wire_rate_precision() {
        let mut configured = config();
        configured.repair_rate = 0.0001;
        assert!(!configured.fec_possible());
        configured.repair_rate = 0.001;
        assert!(configured.fec_possible());

        configured.repair_rate = 0.0;
        configured.connect_to = vec![ConnectTarget::Configured(ConnectTargetConfig {
            peer: "b".into(),
            repair_rate: 0.0001,
        })];
        assert!(!configured.fec_possible());
    }

    #[test]
    fn allowed_route_requires_one_source_selector_and_an_allow_prefix() {
        let mut configured = config();
        configured.allowed_routes.push(AllowedRoute {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: vec!["10.0.0.0/8".parse().unwrap()],
            r#for: RouteSourceSelector::Nodes(vec!["a".into()]),
        });
        assert!(configured.validate().is_ok());

        configured.allowed_routes[0].r#for = RouteSourceSelector::Nodes(vec!["!b".into()]);
        let result = configured.validate();
        assert!(result.is_ok(), "{result:?}");
        configured.allowed_routes[0].r#for =
            RouteSourceSelector::Nodes(vec!["a".into(), "!b".into()]);
        assert!(configured.validate().is_err());
        configured.allowed_routes[0].allow.clear();
        assert!(configured.validate().is_err());
    }

    #[test]
    fn allowed_route_for_supports_known_unknown_and_rejects_mixed_lists() {
        let mut configured = config();
        configured.allowed_routes.push(AllowedRoute {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: vec![],
            r#for: RouteSourceSelector::Keyword("any_inc_unknown".into()),
        });
        assert!(configured.validate().is_ok());
        configured.allowed_routes[0].r#for =
            RouteSourceSelector::Nodes(vec!["A".into(), "!B".into()]);
        assert!(configured.validate().is_err());
    }

    #[test]
    fn allowed_local_ports_parse_ranges_default_to_known_and_deny_wins() {
        let mut configured = config();
        configured.allowed_local_ports = vec![AllowedLocalPort {
            allow: vec!["tcp(80:82)".parse().unwrap(), "icmp".parse().unwrap()],
            deny: vec!["tcp(81)".parse().unwrap()],
            r#for: default_port_source_selector(),
        }];
        assert!(configured.validate().is_ok());
        let rule = &configured.allowed_local_ports[0];
        assert!(rule.permits("b", Protocol::Tcp, 80, true));
        assert!(!rule.permits("b", Protocol::Tcp, 81, true));
        assert!(!rule.permits("unknown", Protocol::Icmp, 0, false));
        assert!("all".parse::<PortSelector>().is_ok());
        assert!("udp(53)".parse::<PortSelector>().is_ok());
        assert!("tcp(82:80)".parse::<PortSelector>().is_err());
        assert!("icmp(8)".parse::<PortSelector>().is_err());
    }

    #[test]
    fn policy_helpers_cover_all_selector_and_protocol_variants() {
        let from_string: ConnectTarget = String::from("b").into();
        let from_str: ConnectTarget = "b".into();
        assert_eq!(from_string.peer_name(), "b");
        assert_eq!(from_str.repair_rate(), 0.0);
        assert_eq!(repair_rate_milli(-1.0), 0);
        assert_eq!(repair_rate_milli(0.0006), 1);
        assert_eq!(
            repair_rate_milli(crate::fec::MAX_RATE + 1.0),
            (crate::fec::MAX_RATE * 1_000.0) as u16
        );

        let selectors = [
            ("all", PortSelector::All),
            ("tcp", PortSelector::Protocol(Protocol::Tcp)),
            ("udp", PortSelector::Protocol(Protocol::Udp)),
            ("icmp", PortSelector::Protocol(Protocol::Icmp)),
            ("icmpv6", PortSelector::Protocol(Protocol::Icmpv6)),
            (
                "tcp(80)",
                PortSelector::PortRange {
                    protocol: Protocol::Tcp,
                    first: 80,
                    last: 80,
                },
            ),
            (
                "udp(100:200)",
                PortSelector::PortRange {
                    protocol: Protocol::Udp,
                    first: 100,
                    last: 200,
                },
            ),
        ];
        for (wire, selector) in selectors {
            assert_eq!(
                wire,
                serde_yaml::from_str::<PortSelector>(&format!("{wire}\n"))
                    .ok()
                    .and_then(|value| serde_yaml::to_string(&value).ok())
                    .map(|value| value.trim().to_owned())
                    .unwrap()
            );
            assert_eq!(selector, wire.parse().unwrap());
        }
        for invalid in [
            "",
            "sctp",
            "tcp(",
            "tcp(x)",
            "tcp(0)",
            "tcp(2:1)",
            "icmp(8)",
            "tcp(1:2:3)",
        ] {
            assert!(invalid.parse::<PortSelector>().is_err(), "{invalid}");
        }
        assert!(PortSelector::All.matches(Protocol::Icmpv6, 0));
        assert!(PortSelector::Protocol(Protocol::Icmp).matches(Protocol::Icmp, 0));
        assert!(!PortSelector::Protocol(Protocol::Icmp).matches(Protocol::Icmpv6, 0));
        assert!(
            PortSelector::PortRange {
                protocol: Protocol::Udp,
                first: 100,
                last: 200,
            }
            .matches(Protocol::Udp, 150)
        );
        assert!(
            !PortSelector::PortRange {
                protocol: Protocol::Udp,
                first: 100,
                last: 200,
            }
            .matches(Protocol::Udp, 201)
        );

        let allowed = AllowedRoute {
            allow: vec!["192.0.2.0/24".parse().unwrap()],
            deny: vec!["192.0.2.128/25".parse().unwrap()],
            r#for: RouteSourceSelector::Nodes(vec!["peer".into()]),
        };
        assert!(allowed.permits("peer", "192.0.2.1".parse().unwrap(), true));
        assert!(!allowed.permits("other", "192.0.2.1".parse().unwrap(), true));
        assert!(!allowed.permits("peer", "192.0.2.200".parse().unwrap(), true));
        let ports = AllowedLocalPort {
            allow: vec![PortSelector::Protocol(Protocol::Tcp)],
            deny: vec![PortSelector::PortRange {
                protocol: Protocol::Tcp,
                first: 80,
                last: 80,
            }],
            r#for: RouteSourceSelector::Keyword("any_inc_unknown".into()),
        };
        assert!(ports.permits("unknown", Protocol::Tcp, 81, false));
        assert!(!ports.permits("unknown", Protocol::Tcp, 80, false));
        assert!(ports.denies("unknown", Protocol::Tcp, 80, false));
        assert!(!ports.denies("unknown", Protocol::Udp, 80, false));

        assert!(RouteSourceSelector::Nodes(vec!["peer".into()]).matches("peer", false));
        assert!(!RouteSourceSelector::Nodes(vec!["peer".into()]).matches("other", true));
        assert!(!RouteSourceSelector::Nodes(vec!["!peer".into()]).matches("peer", true));
        assert!(RouteSourceSelector::Nodes(vec!["!peer".into()]).matches("other", false));
        assert!(!RouteSourceSelector::Keyword("unknown".into()).matches("peer", true));
    }

    #[test]
    fn omitted_listen_derives_both_address_families_and_rejects_bad_addresses() {
        let mut configured = config();
        configured.listen.clear();
        assert_eq!(
            configured.listen_endpoint().unwrap(),
            (CarrierProtocol::Quic, "0.0.0.0:0".parse().unwrap())
        );
        configured.peers.get_mut("b").unwrap().endpoints = vec!["quic://[2001:db8::2]:4434".into()];
        assert_eq!(
            configured.listen_endpoint().unwrap(),
            (CarrierProtocol::Quic, "[::]:0".parse().unwrap())
        );
        configured.listen = "quic://not-an-address".into();
        assert!(configured.listen_endpoint().is_err());
        configured.listen = "not-a-carrier".into();
        assert!(configured.listen_endpoint().is_err());
    }

    #[test]
    fn validation_covers_remaining_basic_rejection_edges() {
        let mut invalid = config();
        invalid.id.clear();
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.tun.addresses.clear();
        assert!(invalid.validate().is_err());
        let mut invalid = config();
        invalid.tun.mtu = 575;
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.fake_ip =
            Some(serde_yaml::from_str("listen: 127.0.0.1:0\nupstream_dns: [1.1.1.1]\n").unwrap());
        assert!(invalid.validate().is_err());
        let mut invalid = config();
        let mut fake: FakeIpConfig =
            serde_yaml::from_str("listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\n").unwrap();
        fake.upstream_dns.clear();
        invalid.fake_ip = Some(fake);
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.peers.get_mut("b").unwrap().upstream_dns = Some(Vec::new());
        assert!(invalid.validate().is_err());
        let mut invalid = config();
        invalid.peers.get_mut("b").unwrap().paths[0].override_upstream_dns = Some(Vec::new());
        invalid.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
            )
            .unwrap(),
        );
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.allowed_routes.push(AllowedRoute {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Nodes(Vec::new()),
        });
        assert!(invalid.validate().is_err());
        let mut invalid = config();
        invalid.allowed_local_ports.push(AllowedLocalPort {
            allow: vec!["tcp".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Keyword("bad".into()),
        });
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.peers.get_mut("b").unwrap().paths[0].path =
            vec!["a".into(), "b".into(), "b".into()];
        assert!(invalid.validate().is_err());
        let mut invalid = config();
        invalid.peers.get_mut("b").unwrap().paths[0].path =
            vec!["a".into(), "missing".into(), "b".into()];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn any_inc_unknown_matches_both_source_classes() {
        let selector = RouteSourceSelector::Keyword("any_inc_unknown".into());
        assert!(selector.matches("known", true));
        assert!(selector.matches("unknown", false));
    }

    #[test]
    fn identity_accepts_inline_key_or_path_but_not_both() {
        let key = identity::encode_secret(&identity::generate());
        let mut configured = config();
        configured.identity_key_path = None;
        configured.identity_key = Some(key);
        assert!(configured.validate().is_ok());
        assert!(configured.load_identity().is_ok());

        configured.identity_key_path = Some("/tmp/a.key".into());
        assert!(configured.validate().is_err());
    }

    #[test]
    fn identity_can_be_loaded_from_environment_with_priority_over_config() {
        let env_key = identity::generate();
        let env_secret = identity::encode_secret(&env_key);
        let mut configured = config();
        configured.identity_key_path = None;
        configured.identity_key = Some(identity::encode_secret(&identity::generate()));

        assert_eq!(
            configured
                .load_identity_with_env(Some(&env_secret))
                .unwrap()
                .verifying_key(),
            env_key.verifying_key()
        );
    }

    #[test]
    fn identity_environment_source_is_required_when_config_has_no_key() {
        let mut configured = config();
        configured.identity_key = None;
        configured.identity_key_path = None;
        assert!(configured.load_identity_with_env(None).is_err());
    }

    #[test]
    fn listener_requires_a_supported_protocol() {
        let mut configured = config();
        configured.listen = "127.0.0.1:4433".into();
        assert!(configured.validate().is_err());
        configured.listen = "tcp://127.0.0.1:4433".into();
        assert!(configured.validate().is_err());
        configured.listen = "quic://127.0.0.1:4433".into();
        assert!(configured.validate().is_ok());
    }

    #[test]
    fn outbound_only_node_derives_its_carrier_from_connect_to() {
        let mut configured = config();
        configured.listen.clear();
        configured.connect_to = vec!["b".into()];
        assert!(configured.validate().is_ok());
        assert_eq!(
            configured.listen_endpoint().unwrap().1,
            "0.0.0.0:0".parse().unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn outbound_only_fake_tcp_node_uses_an_ipv6_bind_for_an_ipv6_peer() {
        let mut configured = config();
        configured.listen.clear();
        configured.connect_to = vec!["b".into()];
        configured.peers.get_mut("b").unwrap().endpoints =
            vec!["quic-faketcp://[2001:db8::2]:4434".into()];
        assert_eq!(
            configured.listen_endpoint().unwrap().1,
            "[::]:0".parse().unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fake_tcp_allows_mixed_carriers_but_rejects_unsupported_settings() {
        let mut configured = config();
        configured.listen = "quic-faketcp://127.0.0.1:4433".into();
        configured.peers.get_mut("b").unwrap().endpoints = vec!["quicfull://127.0.0.1:4434".into()];
        assert!(configured.validate().is_ok());

        configured.fwmark = Some(1);
        assert!(configured.validate().is_ok());
        configured.carrier_interface = Some("eth0".into());
        assert!(configured.validate().is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn quicp_is_rejected_outside_linux() {
        let mut configured = config();
        configured.listen = "quicp://127.0.0.1:4433".into();
        assert!(configured.validate().is_err());
    }

    #[test]
    fn node_id_cannot_escape_the_default_socket_directory() {
        let mut configured = config();
        configured.id = "../other".into();
        assert!(configured.validate().is_err());
    }

    #[test]
    fn fwmark_is_an_optional_node_setting() {
        let mut configured = config();
        assert!(configured.managed_routes);
        configured.fwmark = Some(0x42);
        assert!(configured.validate().is_ok());
    }

    #[test]
    fn managed_routes_can_be_disabled_for_external_policy_routing() {
        let yaml = r#"
id: a
identity_key_path: /tmp/a.key
listen: quic://127.0.0.1:4433
managed_routes: false
tun: {name: tinea, addresses: [10.64.0.1/32]}
"#;
        let configured: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!configured.managed_routes);
        assert!(configured.validate().is_ok());
    }

    #[test]
    fn tun_can_be_explicitly_disabled_for_a_relay() {
        let yaml = r#"
id: relay
identity_key_path: /tmp/relay.key
listen: quic://127.0.0.1:4433
tun: {enabled: false}
"#;
        let configured: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!configured.tun.enabled);
        assert!(configured.tun.addresses.is_empty());
        assert!(configured.validate().is_ok());

        let mut invalid = configured.clone();
        invalid.allowed_routes.push(AllowedRoute {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Keyword("any_known".into()),
        });
        assert!(invalid.validate().is_err());

        let mut invalid_hook = configured;
        invalid_hook.post_up = Some(vec!["true".into()].into());
        assert!(invalid_hook.validate().is_err());
    }

    #[test]
    fn local_tun_routes_remain_internal_but_are_not_host_routes() {
        let mut configured = config();
        configured.tun.addresses = vec!["10.64.0.1/24".parse().unwrap()];
        configured.peers.get_mut("b").unwrap().routes = vec![
            PeerRoute {
                ip_cidr: Some("10.64.0.2/32".parse().unwrap()),
                priority: 100,
                bind: false,
                domain: None,
                site_set: None,
                site_id: None,
                shared_selector: None,
                shared_spec: None,
            },
            PeerRoute {
                ip_cidr: Some("8.8.8.8/32".parse().unwrap()),
                priority: 100,
                bind: false,
                domain: None,
                site_set: None,
                site_id: None,
                shared_selector: None,
                shared_spec: None,
            },
            PeerRoute {
                ip_cidr: Some("10.64.0.0/16".parse().unwrap()),
                priority: 100,
                bind: false,
                domain: None,
                site_set: None,
                site_id: None,
                shared_selector: None,
                shared_spec: None,
            },
        ];

        assert_eq!(configured.route_imports().len(), 3);
        let managed = configured.managed_route_imports();
        assert_eq!(managed.len(), 2);
        assert!(
            managed
                .iter()
                .any(|route| route.prefix == "8.8.8.8/32".parse::<IpNet>().unwrap())
        );
        assert!(
            managed
                .iter()
                .any(|route| route.prefix == "10.64.0.0/16".parse::<IpNet>().unwrap())
        );
    }

    #[test]
    fn parses_all_rfc14_carriers_and_allows_mixed_peer_endpoints() {
        let schemes = [
            ("quic://127.0.0.1:1", CarrierProtocol::Quic),
            ("quicfull://127.0.0.1:1", CarrierProtocol::QuicFull),
            ("quic-faketcp://127.0.0.1:1", CarrierProtocol::QuicFakeTcp),
            (
                "quicfull-faketcp://127.0.0.1:1",
                CarrierProtocol::QuicFullFakeTcp,
            ),
        ];
        for (value, protocol) in schemes {
            let parsed = CarrierEndpoint::parse(value, "endpoint").unwrap();
            assert_eq!(parsed.protocol, protocol);
            assert_eq!(
                parsed.protocol.is_bare_udp(),
                matches!(
                    protocol,
                    CarrierProtocol::Quic | CarrierProtocol::QuicFakeTcp
                )
            );
            assert_eq!(
                parsed.protocol.is_fake_tcp(),
                matches!(
                    protocol,
                    CarrierProtocol::QuicFakeTcp | CarrierProtocol::QuicFullFakeTcp
                )
            );
        }
        assert!(CarrierEndpoint::parse("quicp://127.0.0.1:1", "endpoint").is_err());
        let mut configured = config();
        configured.listen = "quicfull://127.0.0.1:4433".into();
        configured.peers.get_mut("b").unwrap().endpoints = vec!["quic://127.0.0.1:4434".into()];
        #[cfg(target_os = "linux")]
        configured
            .peers
            .get_mut("b")
            .unwrap()
            .endpoints
            .push("quicfull-faketcp://127.0.0.1:4435".into());
        assert!(configured.has_bare_carrier());
        assert!(configured.has_full_quic_carrier());
        assert!(configured.validate().is_ok());
    }

    #[test]
    fn carrier_detection_covers_bare_only_and_full_only_configs() {
        let mut bare = config();
        bare.listen = "quic://127.0.0.1:4433".into();
        bare.peers.get_mut("b").unwrap().endpoints = vec!["quic://127.0.0.1:4434".into()];
        assert!(bare.has_bare_carrier());
        assert!(!bare.has_full_quic_carrier());

        let mut full = config();
        full.listen = "quicfull://127.0.0.1:4433".into();
        full.peers.get_mut("b").unwrap().endpoints = vec!["quicfull://127.0.0.1:4434".into()];
        assert!(!full.has_bare_carrier());
        assert!(full.has_full_quic_carrier());
    }

    #[test]
    fn omitted_listen_without_connect_to_endpoint_is_rejected() {
        let mut configured = config();
        configured.listen.clear();
        configured.connect_to.clear();
        assert!(configured.listen_endpoint().is_err());
        assert!(configured.validate().is_err());
    }

    #[test]
    fn route_selector_equality_uses_resolved_site_ids() {
        let route = PeerRoute {
            ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
            domain: None,
            site_set: None,
            priority: 100,
            bind: false,
            site_id: Some(42),
            shared_selector: None,
            shared_spec: None,
        };
        let override_route = RouteOverride {
            ip_cidr: Some("10.0.0.0/8".parse().unwrap()),
            domain: None,
            site_set: None,
            priority: Some(50),
            priority_delta: None,
            site_id: Some(42),
            ..Default::default()
        };
        assert!(route.selector_eq_override(&override_route));
        assert!(!route.selector_eq_override(&RouteOverride {
            site_id: Some(43),
            ..Default::default()
        }));
    }

    #[test]
    fn peer_route_rejects_multiple_selectors_at_deserialize() {
        let error =
            serde_yaml::from_str::<PeerRoute>("ip_cidr: 192.0.2.0/24\ndomain: example.test\n")
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exactly one of ip_cidr, domain, or site_set")
        );
    }

    #[test]
    fn port_selector_serializes_icmp_protocol_ranges() {
        let icmp = PortSelector::PortRange {
            protocol: Protocol::Icmp,
            first: 1,
            last: 1,
        };
        assert_eq!(serde_yaml::to_string(&icmp).unwrap().trim(), "icmp(1)");
        let icmp6 = PortSelector::PortRange {
            protocol: Protocol::Icmpv6,
            first: 8,
            last: 9,
        };
        assert_eq!(serde_yaml::to_string(&icmp6).unwrap().trim(), "icmpv6(8:9)");
    }

    #[test]
    fn route_source_selector_defaults_to_empty_nodes() {
        assert_eq!(
            RouteSourceSelector::default(),
            RouteSourceSelector::Nodes(Vec::new())
        );
    }

    #[test]
    fn source_selector_rejects_bare_negation_nodes() {
        let mut configured = config();
        configured.allowed_routes.push(AllowedRoute {
            allow: vec!["192.0.2.0/24".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Nodes(vec!["!".into()]),
        });
        assert!(configured.validate().is_err());

        let mut configured = config();
        configured.allowed_routes.push(AllowedRoute {
            allow: vec!["192.0.2.0/24".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Nodes(vec!["!peer".into(), "!".into()]),
        });
        assert!(configured.validate().is_err());
    }

    #[test]
    fn fake_ip_validation_rejects_bad_ttl_pools_and_overlaps() {
        let base = "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n";

        let mut configured = config();
        let mut fake: FakeIpConfig = serde_yaml::from_str(base).unwrap();
        fake.min_cache_ttl_secs = 0;
        configured.fake_ip = Some(fake);
        assert!(configured.validate().is_err());

        let mut configured = config();
        let mut fake: FakeIpConfig = serde_yaml::from_str(base).unwrap();
        fake.min_cache_ttl_secs = 100;
        fake.max_cache_ttl_secs = 50;
        configured.fake_ip = Some(fake);
        assert!(configured.validate().is_err());

        let mut configured = config();
        let mut fake: FakeIpConfig = serde_yaml::from_str(base).unwrap();
        fake.ipv4_pool = "2001:db8::/32".parse().unwrap();
        configured.fake_ip = Some(fake);
        assert!(configured.validate().is_err());

        let mut configured = config();
        let mut fake: FakeIpConfig = serde_yaml::from_str(base).unwrap();
        fake.ipv4_pool = "10.0.0.0/8".parse().unwrap();
        configured.fake_ip = Some(fake);
        assert!(configured.validate().is_err());
    }

    #[test]
    fn peer_fake_tcp_endpoint_rejects_carrier_interface() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().endpoints =
            vec!["quic-faketcp://127.0.0.1:4434".into()];
        configured.carrier_interface = Some("eth0".into());
        assert!(configured.validate().is_err());
    }

    #[test]
    fn missing_identity_sources_are_rejected() {
        let mut configured = config();
        configured.identity_key = None;
        configured.identity_key_path = None;
        assert!(configured.validate().is_err());
    }

    #[test]
    fn direct_requires_tun_enabled() {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: /tmp/a.key\nlisten: quic://127.0.0.1:4433\ntun: {{name: tinea, enabled: false}}\ndirect:\n  fallback: false\n  dscp: 46\n  conntrack_zone: 32123\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n"
        );
        let configured: Config = serde_yaml::from_str(&yaml).unwrap();
        assert!(configured.validate().is_err());
    }

    #[test]
    fn invalid_peer_public_key_is_rejected() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().public_key = "not-a-canonical-key".into();
        assert!(configured.validate().is_err());
    }

    #[test]
    fn allowed_port_requires_nonempty_allow_list() {
        let mut configured = config();
        configured.allowed_local_ports.push(AllowedLocalPort {
            allow: Vec::new(),
            deny: Vec::new(),
            r#for: RouteSourceSelector::Nodes(Vec::new()),
        });
        assert!(configured.validate().is_err());
    }

    #[test]
    fn upstream_dns_empty_with_fake_ip_enabled_is_rejected() {
        let mut configured = config();
        configured.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
            )
            .unwrap(),
        );
        configured.peers.get_mut("b").unwrap().upstream_dns = Some(Vec::new());
        assert!(configured.validate().is_err());
    }

    #[test]
    fn peer_route_bind_without_cidr_is_rejected_by_validate() {
        let mut configured = config();
        let route = configured
            .peers
            .get_mut("b")
            .unwrap()
            .routes
            .get_mut(0)
            .unwrap();
        route.bind = true;
        route.ip_cidr = None;
        assert!(configured.validate().is_err());
    }

    #[test]
    fn upstream_dns_for_unknown_destination_is_empty() {
        let configured = config();
        assert!(configured.upstream_dns_for_wire("unknown", &[]).is_empty());
    }

    #[test]
    fn managed_route_imports_include_override_and_direct_prefixes() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
            priority: Some(80),
            priority_delta: None,
            ..Default::default()
        }];
        configured.validate().unwrap();
        let prefixes: Vec<IpNet> = configured
            .managed_route_imports()
            .iter()
            .map(|route| route.prefix)
            .collect();
        assert!(prefixes.contains(&"192.0.2.0/24".parse().unwrap()));

        // Direct routes are Linux-only, so the direct-prefix contribution is
        // asserted on Linux and skipped elsewhere.
        #[cfg(target_os = "linux")]
        {
            let mut configured = config();
            configured.direct = Some(DirectConfig {
                fallback: false,
                dscp: 46,
                fwmark: None,
                conntrack_zone: 32123,
                routes: vec![
                    serde_yaml::from_str("ip_cidr: 198.51.100.0/24\npriority: 70\n").unwrap(),
                ],
            });
            configured.validate().unwrap();
            let prefixes: Vec<IpNet> = configured
                .managed_route_imports()
                .iter()
                .map(|route| route.prefix)
                .collect();
            assert!(prefixes.contains(&"198.51.100.0/24".parse().unwrap()));
        }
    }

    #[test]
    fn override_prefixes_expand_ip_cidr_site_sets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("cidrs.txt"),
            "ip-cidr:192.0.2.0/24\nip-cidr:198.51.100.0/24\n",
        )
        .unwrap();
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            site_set: Some("./cidrs.txt".into()),
            priority: Some(80),
            priority_delta: None,
            ..Default::default()
        }];
        configured.load_route_sets(dir.path()).unwrap();
        let prefixes = configured.override_route_prefixes();
        assert!(prefixes.contains(&"192.0.2.0/24".parse().unwrap()));
        assert!(prefixes.contains(&"198.51.100.0/24".parse().unwrap()));
    }

    #[test]
    fn domain_site_ids_include_path_overrides_and_direct_routes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("domains.txt"),
            "example.test\nexample.org\n",
        )
        .unwrap();
        let mut configured = config();
        configured.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
            )
            .unwrap(),
        );
        configured.peers.get_mut("b").unwrap().routes.clear();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            site_set: Some("./domains.txt".into()),
            priority: Some(80),
            priority_delta: None,
            ..Default::default()
        }];
        configured.load_route_sets(dir.path()).unwrap();
        configured.validate().unwrap();
        assert_eq!(configured.domain_site_ids().len(), 1);

        // Direct domain routes are Linux-only; assert them there and keep the
        // test portable elsewhere.
        #[cfg(target_os = "linux")]
        {
            let mut configured = config();
            configured.fake_ip = Some(
                serde_yaml::from_str(
                    "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
                )
                .unwrap(),
            );
            configured.direct = Some(DirectConfig {
                fallback: false,
                dscp: 46,
                fwmark: None,
                conntrack_zone: 32123,
                routes: vec![
                    serde_yaml::from_str("site_set: ./domains.txt\npriority: 60\n").unwrap(),
                ],
            });
            configured.load_route_sets(dir.path()).unwrap();
            configured.validate().unwrap();
            assert_eq!(configured.direct_domain_routes().len(), 1);
            assert_eq!(configured.domain_site_ids().len(), 1);
        }
    }

    #[test]
    fn effective_domain_imports_apply_active_lease_overrides() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("domains.txt"), "example.test\n").unwrap();
        let mut configured = config();
        configured.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
            )
            .unwrap(),
        );
        configured.peers.get_mut("b").unwrap().routes.clear();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            site_set: Some("./domains.txt".into()),
            priority: Some(80),
            priority_delta: None,
            ..Default::default()
        }];
        configured.load_route_sets(dir.path()).unwrap();
        configured.validate().unwrap();
        let site_id = configured.peers["b"].paths[0].override_routes[0]
            .site_id_resolved()
            .unwrap();

        // The override is not in the peer route table, so it becomes a
        // candidate only through the override branch.
        let imports =
            configured.effective_domain_route_imports_for_active_leases(&HashMap::from([(
                "b".into(),
                configured.peers["b"].paths[0].override_routes.clone(),
            )]));
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].set_id, site_id);
        assert_eq!(imports[0].candidates[0].priority, 80);

        // An override that mirrors an existing peer route applies its
        // priority to the peer-route candidate and is skipped in the
        // override-only branch.
        configured.peers.get_mut("b").unwrap().routes = vec![PeerRoute {
            site_set: Some("./domains.txt".into()),
            priority: 90,
            bind: false,
            ip_cidr: None,
            domain: None,
            site_id: None,
            shared_selector: None,
            shared_spec: None,
        }];
        configured.load_route_sets(dir.path()).unwrap();
        let imports =
            configured.effective_domain_route_imports_for_active_leases(&HashMap::from([(
                "b".into(),
                vec![RouteOverride {
                    site_set: Some("./domains.txt".into()),
                    priority: Some(80),
                    priority_delta: None,
                    ..Default::default()
                }],
            )]));
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].candidates[0].priority, 80);
    }

    #[test]
    fn route_override_validation_rejects_more_ambiguous_forms() {
        let mut configured = config();

        // Both priority and priority_delta.
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
            priority: Some(1),
            priority_delta: Some(1),
            ..Default::default()
        }];
        assert!(configured.validate().is_err());

        // More than one selector.
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
            domain: Some("example.test".into()),
            priority: Some(1),
            priority_delta: None,
            ..Default::default()
        }];
        assert!(configured.validate().is_err());

        // Selector without priority.
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
            priority: None,
            priority_delta: None,
            ..Default::default()
        }];
        assert!(configured.validate().is_err());

        // Duplicate domain selector.
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![
            RouteOverride {
                domain: Some("example.test".into()),
                priority: Some(1),
                priority_delta: None,
                ..Default::default()
            },
            RouteOverride {
                domain: Some("example.test".into()),
                priority: Some(2),
                priority_delta: None,
                ..Default::default()
            },
        ];
        assert!(configured.validate().is_err());

        // Duplicate site_set selector.
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![
            RouteOverride {
                site_set: Some("./s.txt".into()),
                priority: Some(1),
                priority_delta: None,
                ..Default::default()
            },
            RouteOverride {
                site_set: Some("./s.txt".into()),
                priority: Some(2),
                priority_delta: None,
                ..Default::default()
            },
        ];
        assert!(configured.validate().is_err());

        // Wildcard mixed with a prefixed override.
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![
            RouteOverride {
                priority: Some(1),
                priority_delta: None,
                ..Default::default()
            },
            RouteOverride {
                ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
                priority: Some(2),
                priority_delta: None,
                ..Default::default()
            },
        ];
        assert!(configured.validate().is_err());
    }

    #[test]
    fn peer_route_site_set_load_failure_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n    routes: [{{site_set: ./missing.txt, priority: 90}}]\n"
        );
        fs::write(dir.path().join("node.yaml"), yaml).unwrap();
        let error = Config::load(dir.path().join("node.yaml")).unwrap_err();
        assert!(error.to_string().contains("missing.txt"));
    }

    #[test]
    fn invalid_peer_endpoint_scheme_is_rejected() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().endpoints = vec!["garbage://127.0.0.1:4434".into()];
        assert!(configured.validate().is_err());
    }

    #[test]
    fn config_load_reports_io_and_yaml_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = Config::load(dir.path().join("missing.yaml")).unwrap_err();
        assert!(matches!(missing, ConfigError::Io(_)));

        fs::write(dir.path().join("bad.yaml"), "id: [unclosed\n").unwrap();
        let invalid = Config::load(dir.path().join("bad.yaml")).unwrap_err();
        assert!(matches!(invalid, ConfigError::Yaml(_)));
    }

    #[test]
    fn status_socket_defaults_to_the_platform_dir_and_honors_overrides() {
        let mut configured = config();
        if cfg!(target_os = "linux") {
            assert_eq!(Config::default_status_socket_dir(), "/run/tinect");
        } else {
            assert_eq!(Config::default_status_socket_dir(), "/var/run/tinect");
        }
        assert_eq!(
            Config::default_status_socket("node"),
            format!("{}/node.sock", Config::default_status_socket_dir())
        );
        assert_eq!(
            configured.status_socket(),
            Config::default_status_socket("a")
        );
        configured.runtime.status_socket = Some("/tmp/custom.sock".into());
        assert_eq!(configured.status_socket(), "/tmp/custom.sock");
    }

    #[test]
    fn nft_target_rejects_identifier_edge_cases() {
        let mut configured = config();
        for prefix in [
            String::new(),
            "table:1starts-with-digit".into(),
            format!("table:{}", "a".repeat(256)),
        ] {
            configured.nft_healthy_set = Some(NftHealthySetConfig {
                prefix: Some(prefix.clone()),
                ..Default::default()
            });
            assert!(configured.nft_healthy_set_targets().is_err(), "{prefix}");
        }
    }

    #[test]
    fn nft_derived_family_names_are_revalidated() {
        // A 255-byte prefix name is valid on its own, but the derived `_v4`
        // name exceeds the nft identifier limit.
        let mut configured = config();
        configured.nft_healthy_set = Some(NftHealthySetConfig {
            prefix: Some(format!("table:{}", "a".repeat(255))),
            ..Default::default()
        });
        let error = configured.nft_healthy_set_targets().unwrap_err();
        assert!(error.to_string().contains("derived v4 nft set"));
    }

    #[test]
    fn validation_rejects_additional_boundary_values() {
        let mut invalid = config();
        invalid.id = "a\0b".into();
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.tun.mtu = 9001;
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.link_health.keepalive_secs = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.runtime.shutdown_timeout_secs = 61;
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.post_up = Some(LifecycleCommands::from(Vec::new()));
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.allowed_local_ports.push(AllowedLocalPort {
            allow: vec!["tcp".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Nodes(Vec::new()),
        });
        assert!(invalid.validate().is_err());

        assert!(!config().peers["b"].allows_relay());
        let commands = LifecycleCommands::from(vec!["echo ready".to_string()]);
        assert_eq!(commands.as_slice(), ["echo ready".to_string()].as_slice());
    }

    #[test]
    fn fake_ip_pools_must_match_their_family_and_mixed_family_tun_is_allowed() {
        let base = "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\n";

        let mut configured = config();
        let mut fake: FakeIpConfig = serde_yaml::from_str(base).unwrap();
        fake.ipv6_pool = "10.99.0.0/16".parse().unwrap();
        configured.fake_ip = Some(fake);
        assert!(configured.validate().is_err());

        // A v6 TUN address never overlaps the v4 FakeIP pool.
        let mut configured = config();
        configured.tun.addresses = vec![
            "10.64.0.1/32".parse().unwrap(),
            "fd00::1/128".parse().unwrap(),
        ];
        configured.fake_ip = Some(serde_yaml::from_str(base).unwrap());
        configured.validate().unwrap();
    }

    #[test]
    fn path_override_and_direct_domain_routes_require_fake_ip() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            domain: Some("example.test".into()),
            priority: Some(80),
            priority_delta: None,
            ..Default::default()
        }];
        let error = configured.validate().unwrap_err();
        assert!(error.to_string().contains("require fake_ip"));

        let mut configured = config();
        configured.direct = Some(DirectConfig {
            fallback: false,
            dscp: 46,
            fwmark: None,
            conntrack_zone: 32123,
            routes: vec![serde_yaml::from_str("domain: example.test\npriority: 60\n").unwrap()],
        });
        let error = configured.validate().unwrap_err();
        assert!(error.to_string().contains("require fake_ip"));
    }

    #[test]
    fn path_upstream_dns_override_requires_fake_ip() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_upstream_dns =
            Some(serde_yaml::from_str("[8.8.8.8]\n").unwrap());
        let error = configured.validate().unwrap_err();
        assert!(error.to_string().contains("require fake_ip"));
    }

    #[test]
    fn disabled_tun_rejects_local_ports_and_peer_routes() {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: /tmp/a.key\nlisten: quic://127.0.0.1:4433\ntun: {{enabled: false}}\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n"
        );
        let mut configured: Config = serde_yaml::from_str(&yaml).unwrap();
        assert!(configured.validate().is_ok());

        configured.allowed_local_ports.push(AllowedLocalPort {
            allow: vec!["tcp".parse().unwrap()],
            deny: Vec::new(),
            r#for: RouteSourceSelector::Keyword("any_known".into()),
        });
        assert!(configured.validate().is_err());
        configured.allowed_local_ports.clear();

        configured.peers.get_mut("b").unwrap().routes =
            vec![serde_yaml::from_str("ip_cidr: 10.0.0.0/8\n").unwrap()];
        assert!(configured.validate().is_err());
    }

    #[test]
    fn route_imports_group_candidates_and_merge_duplicate_priorities() {
        let mut configured = config();
        let c_key = identity::encode_public(&identity::generate().verifying_key());
        let peer_c: Peer = serde_yaml::from_str(&format!(
            "public_key: {c_key}\nendpoints: []\nroutes: [{{ip_cidr: 10.64.0.2/32, priority: 70}}]\n"
        ))
        .unwrap();
        configured.peers.insert("c".into(), peer_c);
        // A second route for the same prefix from the same node keeps the
        // best (numerically highest) priority.
        configured
            .peers
            .get_mut("b")
            .unwrap()
            .routes
            .push(serde_yaml::from_str("ip_cidr: 10.64.0.2/32\npriority: 50\n").unwrap());

        let imports = configured.route_imports();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].candidates.len(), 2);
        let candidate_b = imports[0]
            .candidates
            .iter()
            .find(|candidate| candidate.node == "b")
            .unwrap();
        assert_eq!(candidate_b.priority, 100);

        // IP-only configurations have no domain or direct route views.
        assert!(configured.domain_route_imports().is_empty());
        assert!(configured.direct_prefix_routes().is_empty());
        assert!(configured.direct_domain_routes().is_empty());
    }

    #[test]
    fn managed_route_imports_include_fake_ip_pools_exactly_once() {
        let mut configured = config();
        configured.fake_ip = Some(
            serde_yaml::from_str("listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\n").unwrap(),
        );
        configured.validate().unwrap();
        let fake = configured.fake_ip.clone().unwrap();

        let prefixes: Vec<IpNet> = configured
            .managed_route_imports()
            .iter()
            .map(|route| route.prefix)
            .collect();
        assert!(prefixes.contains(&fake.ipv4_pool));
        assert!(prefixes.contains(&fake.ipv6_pool));

        // disable_ipv6 drops the v6 pool from the host routing plan.
        configured.fake_ip.as_mut().unwrap().disable_ipv6 = true;
        let prefixes: Vec<IpNet> = configured
            .managed_route_imports()
            .iter()
            .map(|route| route.prefix)
            .collect();
        assert!(!prefixes.contains(&fake.ipv6_pool));

        // A pool already contributed by a peer route is not duplicated.
        configured.peers.get_mut("b").unwrap().routes.push(
            serde_yaml::from_str(&format!("ip_cidr: {}\npriority: 90\n", fake.ipv4_pool)).unwrap(),
        );
        let matching: Vec<_> = configured
            .managed_route_imports()
            .into_iter()
            .filter(|route| route.prefix == fake.ipv4_pool)
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].candidates.len(), 1);
    }

    #[test]
    fn override_route_prefixes_skip_priority_zero_overrides() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![
            RouteOverride {
                ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
                priority: Some(0),
                priority_delta: None,
                ..Default::default()
            },
            RouteOverride {
                ip_cidr: Some("198.51.100.0/24".parse().unwrap()),
                priority: Some(80),
                priority_delta: None,
                ..Default::default()
            },
        ];
        configured.validate().unwrap();
        assert_eq!(
            configured.override_route_prefixes(),
            vec!["198.51.100.0/24".parse::<IpNet>().unwrap()]
        );
    }

    #[test]
    fn effective_routes_ignore_delta_only_overrides_for_new_prefixes() {
        let configured = config();
        let imports = configured.effective_route_imports_for_active_leases(&HashMap::from([(
            "b".into(),
            vec![RouteOverride {
                ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
                priority: None,
                priority_delta: Some(10),
                ..Default::default()
            }],
        )]));
        // The override does not match the peer route and has no absolute
        // priority, so it cannot introduce a new prefix; the peer route
        // keeps its configured priority.
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].prefix, "10.64.0.2/32".parse().unwrap());
        assert_eq!(imports[0].candidates[0].priority, 100);
    }

    #[test]
    fn effective_domain_imports_skip_non_domain_and_delta_only_overrides() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("domains.txt"), "example.test\n").unwrap();
        fs::write(dir.path().join("more-domains.txt"), "example.org\n").unwrap();
        fs::write(dir.path().join("cidrs.txt"), "ip-cidr:192.0.2.0/24\n").unwrap();
        let mut configured = config();
        configured.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
            )
            .unwrap(),
        );
        configured.peers.get_mut("b").unwrap().routes =
            vec![serde_yaml::from_str("site_set: ./domains.txt\npriority: 90\n").unwrap()];
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![
            RouteOverride {
                site_set: Some("./cidrs.txt".into()),
                priority: Some(20),
                priority_delta: None,
                ..Default::default()
            },
            RouteOverride {
                site_set: Some("./more-domains.txt".into()),
                priority: None,
                priority_delta: Some(5),
                ..Default::default()
            },
        ];
        configured.load_route_sets(dir.path()).unwrap();

        let mut active = configured.peers["b"].paths[0].override_routes.clone();
        // An override that never went through the loader has no resolved
        // site id and is ignored.
        active.push(RouteOverride {
            ip_cidr: Some("203.0.113.0/24".parse().unwrap()),
            priority: Some(10),
            priority_delta: None,
            ..Default::default()
        });
        let imports = configured.effective_domain_route_imports_for_active_leases(&HashMap::from(
            [("b".into(), active)],
        ));
        // Only the peer route's domain set remains, at its base priority.
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].candidates[0].priority, 90);
    }

    #[test]
    fn wire_lookups_require_an_exact_identity_path_match() {
        let mut configured = config();
        configured.identity_key_path = None;
        configured.identity_key = Some(identity::encode_secret(&identity::generate()));
        configured.fake_ip = Some(
            serde_yaml::from_str(
                "listen: 127.0.0.1:5354\nupstream_dns: [1.1.1.1]\ndisable_ipv6: true\n",
            )
            .unwrap(),
        );
        configured.peers.get_mut("b").unwrap().paths[0].override_routes = vec![RouteOverride {
            ip_cidr: Some("10.64.0.2/32".parse().unwrap()),
            priority: Some(75),
            priority_delta: None,
            ..Default::default()
        }];
        let local = configured.local_identity().unwrap();
        let peer = configured.peer_identity("b").unwrap();

        // Length mismatch and first-hop identity mismatch both miss.
        assert!(
            configured
                .route_overrides_for_wire("b", std::slice::from_ref(&peer))
                .is_empty()
        );
        assert!(
            configured
                .route_overrides_for_wire("b", &["deadbeef".into(), peer.clone()])
                .is_empty()
        );
        assert_eq!(
            configured
                .route_overrides_for_wire("b", &[local, peer.clone()])
                .len(),
            1
        );

        // upstream_dns falls back to the global FakeIP list when the wire
        // path matches no configured manual path.
        let upstream = configured.upstream_dns_for_wire("b", &[peer]);
        assert_eq!(upstream[0].socket_addr(), "1.1.1.1:53".parse().unwrap());
    }

    #[test]
    fn selector_eq_compares_fields_when_site_ids_are_incomplete() {
        let route = PeerRoute {
            ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
            domain: None,
            site_set: None,
            priority: 100,
            bind: false,
            site_id: Some(42),
            shared_selector: None,
            shared_spec: None,
        };
        let same_fields = RouteOverride {
            ip_cidr: Some("192.0.2.0/24".parse().unwrap()),
            priority: Some(50),
            ..Default::default()
        };
        assert!(route.selector_eq_override(&same_fields));
        let different_fields = RouteOverride {
            domain: Some("example.test".into()),
            priority: Some(50),
            ..Default::default()
        };
        assert!(!route.selector_eq_override(&different_fields));
    }

    #[test]
    fn peer_identity_ignores_undecodable_public_keys() {
        let mut configured = config();
        configured.peers.get_mut("b").unwrap().public_key = "not-base64".into();
        assert_eq!(configured.peer_identity("b"), None);
        assert!(configured.peer_by_identity("anything").is_none());
        assert_eq!(configured.peer_name_by_identity("anything"), None);
    }

    #[test]
    fn carrier_detection_tolerates_unparseable_endpoints() {
        let mut configured = config();
        configured.listen = "not-a-carrier".into();
        configured.peers.get_mut("b").unwrap().endpoints = vec!["also-not-a-carrier".into()];
        assert!(!configured.has_bare_carrier());
        assert!(!configured.has_full_quic_carrier());
    }

    #[test]
    fn omitted_listen_with_hostname_peer_binds_the_ipv4_wildcard() {
        let mut configured = config();
        configured.listen.clear();
        configured.peers.get_mut("b").unwrap().endpoints = vec!["quic://peer.example:4434".into()];
        assert_eq!(
            configured.listen_endpoint().unwrap(),
            (CarrierProtocol::Quic, "0.0.0.0:0".parse().unwrap())
        );
        configured.validate().unwrap();
    }

    #[test]
    fn direct_and_override_site_set_load_failures_propagate() {
        let key = identity::encode_public(&identity::generate().verifying_key());
        let yamls = [
            format!(
                "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\ndirect:\n  fallback: false\n  dscp: 46\n  conntrack_zone: 32123\n  routes: [{{site_set: ./missing.txt, priority: 60}}]\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n"
            ),
            format!(
                "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  b:\n    public_key: {key}\n    endpoints: []\n    paths:\n      - path: [a, b]\n        override_routes: [{{site_set: ./missing.txt, priority: 60}}]\n"
            ),
        ];
        for yaml in yamls {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("node.yaml"), yaml).unwrap();
            let error = Config::load(dir.path().join("node.yaml")).unwrap_err();
            assert!(error.to_string().contains("missing.txt"));
        }
    }

    #[test]
    fn identical_path_overrides_share_interned_specs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("cidrs.txt"),
            "ip-cidr:192.0.2.0/24\nip-cidr:198.51.100.0/24\n",
        )
        .unwrap();
        let key_b = identity::encode_public(&identity::generate().verifying_key());
        let key_c = identity::encode_public(&identity::generate().verifying_key());
        let key_d = identity::encode_public(&identity::generate().verifying_key());
        let yaml = format!(
            "id: a\nidentity_key_path: node.key\nlisten: quic://127.0.0.1:1\ntun: {{name: tinea, addresses: [10.64.0.1/32]}}\npeers:\n  b:\n    public_key: {key_b}\n    endpoints: []\n    paths:\n      - path: [a, b]\n        override_routes: [{{site_set: ./cidrs.txt, priority: 80}}]\n  c:\n    public_key: {key_c}\n    endpoints: []\n    paths:\n      - path: [a, c]\n        override_routes: [{{site_set: ./cidrs.txt, priority: 80}}]\n  d:\n    public_key: {key_d}\n    endpoints: []\n    paths:\n      - path: [a, d]\n        override_routes: [{{priority_delta: -10}}]\n"
        );
        fs::write(dir.path().join("node.yaml"), yaml).unwrap();
        let configured = Config::load(dir.path().join("node.yaml")).unwrap();

        let override_b = &configured.peers["b"].paths[0].override_routes[0];
        let override_c = &configured.peers["c"].paths[0].override_routes[0];
        assert_eq!(override_b.site_id, override_c.site_id);
        assert!(Arc::ptr_eq(
            override_b.shared_selector.as_ref().unwrap(),
            override_c.shared_selector.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            override_b.shared_spec.as_ref().unwrap(),
            override_c.shared_spec.as_ref().unwrap()
        ));
        assert_eq!(override_b.priority_for(100), Some(80));

        // A wildcard override has no selector but still gets an interned
        // spec carrying the shared priority_delta.
        let override_d = &configured.peers["d"].paths[0].override_routes[0];
        assert!(override_d.site_id_resolved().is_none());
        assert!(override_d.shared_selector.is_none());
        assert!(override_d.shared_spec.is_some());
        assert_eq!(override_d.priority_for(100), Some(90));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn fake_tcp_listen_is_rejected_outside_linux() {
        let mut configured = config();
        configured.listen = "quic-faketcp://127.0.0.1:4433".into();
        let error = configured.listen_endpoint().unwrap_err();
        assert!(error.to_string().contains("Linux"));
    }
}
