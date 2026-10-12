//! Daemon-owned host-network resource lifecycle.
//!
//! Keeping ownership and rollback here makes the composition root responsible
//! for wiring components, not for reproducing platform cleanup sequencing.

use std::{collections::HashSet, sync::Arc};
use tinect::{config::Config, platform, runtime::DaemonSupervisor};

/// Owns host-network resources created during daemon startup.
///
/// The ownership ledger records only resources that were actually installed.
/// Cleanup therefore does not have to reconstruct state from configuration,
/// which is especially important when startup fails part way through or when
/// the effective TUN name was allocated by the platform.
pub(crate) struct NetworkResources {
    pub(crate) exit_network: Option<platform::ExitNetworkState>,
    pub(crate) tun_input_firewall: Option<platform::TunInputFirewallState>,
    pub(crate) direct_firewall: Option<platform::DirectFirewallState>,
    pub(crate) direct_nat: Option<platform::DirectNatState>,
    pub(crate) tun_name: Option<String>,
    pub(crate) lifecycle_hooks_active: bool,
    pub(crate) underlay_routes: Option<platform::UnderlayRouteOwnership>,
    managed_overlay_routes: Arc<tokio::sync::RwLock<HashSet<ipnet::IpNet>>>,
}

impl Default for NetworkResources {
    fn default() -> Self {
        Self {
            exit_network: None,
            tun_input_firewall: None,
            direct_firewall: None,
            direct_nat: None,
            tun_name: None,
            lifecycle_hooks_active: false,
            underlay_routes: None,
            managed_overlay_routes: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
        }
    }
}

impl NetworkResources {
    pub(crate) fn managed_overlay_routes(&self) -> Arc<tokio::sync::RwLock<HashSet<ipnet::IpNet>>> {
        self.managed_overlay_routes.clone()
    }

    pub(crate) async fn cleanup(&mut self) {
        if let Some(exit_network) = self.exit_network.take() {
            let _ = platform::cleanup_exit_network(&exit_network);
        }
        if let Some(tun_input_firewall) = self.tun_input_firewall.take() {
            let _ = platform::cleanup_tun_input_firewall(&tun_input_firewall);
        }
        if let Some(direct_firewall) = self.direct_firewall.take() {
            let _ = platform::cleanup_direct_firewall(&direct_firewall);
        }
        if let Some(direct_nat) = self.direct_nat.take() {
            let _ = platform::cleanup_direct_nat(&direct_nat);
        }
        let tun_name = self.tun_name.clone();
        let prefixes = {
            let mut owned = self.managed_overlay_routes.write().await;
            let prefixes = owned.iter().copied().collect::<Vec<_>>();
            owned.clear();
            prefixes
        };
        if let Some(tun_name) = tun_name
            && !prefixes.is_empty()
            && let Err(error) = platform::cleanup_overlay_routes(&tun_name, &prefixes).await
        {
            tracing::warn!(%error, "failed to clean up managed overlay routes");
        }
        if let Some(underlay_routes) = self.underlay_routes.take()
            && let Err(error) = platform::cleanup_underlay_routes(&underlay_routes).await
        {
            tracing::warn!(%error, "failed to clean up owned underlay routes");
        }
    }

    pub(crate) async fn rollback(&mut self, supervisor: &DaemonSupervisor, config: &Config) {
        let _ = supervisor
            .shutdown(std::time::Duration::from_secs(
                config.runtime.shutdown_timeout_secs,
            ))
            .await;
        self.cleanup().await;
    }
}

pub(crate) fn managed_overlay_prefixes(config: &Config) -> Vec<ipnet::IpNet> {
    let mut prefixes = config
        .managed_route_imports()
        .into_iter()
        .map(|route| route.prefix)
        .collect::<Vec<_>>();
    prefixes.sort_unstable();
    prefixes.dedup();
    prefixes
}

pub(crate) async fn sync_managed_overlay_routes(
    tun_name: &str,
    active: &mut HashSet<ipnet::IpNet>,
    desired: HashSet<ipnet::IpNet>,
) -> Result<(), platform::PlatformError> {
    let to_add = desired.difference(active).copied().collect::<Vec<_>>();
    if !to_add.is_empty() {
        let _ownership = platform::install_overlay_routes(tun_name, &to_add, &[]).await?;
    }
    let to_remove = active.difference(&desired).copied().collect::<Vec<_>>();
    if !to_remove.is_empty()
        && let Err(error) = platform::cleanup_overlay_routes(tun_name, &to_remove).await
    {
        // Preserve the previous logical snapshot when removal fails. Undo
        // this attempt's additions so the next reconciliation does not
        // silently treat a partially applied route set as committed.
        if !to_add.is_empty() {
            let _ = platform::cleanup_overlay_routes(tun_name, &to_add).await;
        }
        return Err(error);
    }
    *active = desired;
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_overlay_prefixes_are_sorted_and_deduplicated() {
        let mut config = crate::daemon::test_support::minimal_config();
        config.fake_ip = Some(tinect::config::FakeIpConfig {
            listen: "127.0.0.1:5354".parse().unwrap(),
            upstream_dns: vec![serde_yaml::from_str("1.1.1.1").unwrap()],
            disable_ipv6: false,
            ipv4_pool: "198.18.0.0/15".parse().unwrap(),
            ipv6_pool: "fd74:696e:6563:7400::/64".parse().unwrap(),
            min_cache_ttl_secs: 60,
            max_cache_ttl_secs: 86_400,
            max_entries: 1024,
        });
        assert_eq!(
            managed_overlay_prefixes(&config),
            vec![
                "198.18.0.0/15".parse().unwrap(),
                "fd74:696e:6563:7400::/64".parse().unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn cleanup_and_rollback_without_owned_resources_are_safe() {
        let config = crate::daemon::test_support::minimal_config();
        let mut resources = NetworkResources::default();
        resources.cleanup().await;

        let supervisor = DaemonSupervisor::default();
        resources.rollback(&supervisor, &config).await;
        assert!(supervisor.is_shutting_down());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn managed_overlay_route_sync_commits_additions_and_removals() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let device = platform::create_tun(&tinect::config::TunConfig {
            enabled: true,
            name: "tinectcvnet".into(),
            addresses: vec!["10.64.0.1/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        })
        .unwrap();
        let name = device.name().unwrap();
        let prefix = "192.0.2.0/24".parse().unwrap();
        let desired = HashSet::from([prefix]);
        let mut active = HashSet::new();

        sync_managed_overlay_routes(&name, &mut active, desired.clone())
            .await
            .unwrap();
        assert_eq!(active, desired);

        sync_managed_overlay_routes(&name, &mut active, HashSet::new())
            .await
            .unwrap();
        assert!(active.is_empty());
    }
}
