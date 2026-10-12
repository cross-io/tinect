use super::PeerRoute;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConfig {
    /// Use local direct as the final candidate when all matching peer routes
    /// are unavailable.
    #[serde(default)]
    pub fallback: bool,
    /// DSCP marker written to packets before they are reinjected into TUN.
    pub dscp: u8,
    /// Optional packet mark assigned by the TUN prerouting nft chain.
    #[serde(default)]
    pub fwmark: Option<u32>,
    /// Conntrack zone reserved for the original direction of reinjected flows.
    pub conntrack_zone: u16,
    /// Local-direct candidates ranked alongside peer routes.
    #[serde(default)]
    pub routes: Vec<PeerRoute>,
}
