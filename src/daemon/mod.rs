//! Runtime-only daemon subsystems.
//!
//! The binary remains responsible for CLI dispatch and top-level lifecycle;
//! long-lived workers live here so their dependencies and tests do not accrete
//! in the entry point.

pub(crate) mod application;
pub(crate) mod circuit_reconciler;
pub(crate) mod circuit_resolution;
pub(crate) mod cli_support;
pub(crate) mod control_handler;
pub(crate) mod link_helpers;
pub(crate) mod link_lifecycle;
pub(crate) mod network_lifecycle;
pub(crate) mod path_resolution;
pub(crate) mod physical_dispatch;
pub(crate) mod route_snapshot;
mod status_refresh;
pub(crate) mod support;
mod topology_advertisements;
pub(crate) mod topology_sync;

pub(super) use status_refresh::start_status_refresh;
pub(super) use topology_advertisements::start_topology_advertisements;

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
pub(crate) mod test_support {
    use tinect::config::Config;

    pub(crate) fn backdate_monotonic_epoch() {
        #[cfg(debug_assertions)]
        tinect::circuit::backdate_monotonic_epoch();
    }

    pub(crate) fn minimal_config() -> Config {
        Config {
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
            tun: tinect::config::TunConfig {
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
        }
    }
}
