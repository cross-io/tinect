//! Overlay route ownership at the platform boundary.
//!
//! Linux uses rtnetlink in the parent implementation; macOS retains its
//! platform route invocation here. Callers only depend on this small route
//! lifecycle surface.

use super::PlatformError;
#[cfg(target_os = "macos")]
use super::run_checked;
use ipnet::IpNet;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UnderlayRoute {
    pub(super) endpoint: IpAddr,
    pub(super) gateway: IpAddr,
    pub(super) output_interface: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OwnedUnderlayRoute {
    pub(super) endpoint: IpAddr,
    pub(super) gateway: String,
    pub(super) output_interface: u32,
}

/// Exact underlay host routes installed by one successful startup.
///
/// The fields stay private so callers can only return the ownership token to
/// [`cleanup_underlay_routes`]. Existing administrator-owned host routes are
/// never included in this token.
#[derive(Debug, Default)]
pub struct UnderlayRouteOwnership {
    pub(super) routes: Vec<OwnedUnderlayRoute>,
}

/// Selects only underlay endpoints for which the host has a matching default
/// gateway.  Keeping this decision separate from rtnetlink construction makes
/// route ownership testable without changing the host routing table.
#[cfg(target_os = "linux")]
pub(super) fn underlay_routes(
    underlay: &[IpAddr],
    ipv4_default: Option<(Ipv4Addr, u32)>,
    ipv6_default: Option<(Ipv6Addr, u32)>,
) -> Vec<UnderlayRoute> {
    underlay
        .iter()
        .filter(|endpoint| !endpoint.is_loopback())
        .filter_map(|endpoint| match (endpoint, ipv4_default, ipv6_default) {
            (IpAddr::V4(endpoint), Some((gateway, output_interface)), _) => Some(UnderlayRoute {
                endpoint: IpAddr::V4(*endpoint),
                gateway: IpAddr::V4(gateway),
                output_interface,
            }),
            (IpAddr::V6(endpoint), _, Some((gateway, output_interface))) => Some(UnderlayRoute {
                endpoint: IpAddr::V6(*endpoint),
                gateway: IpAddr::V6(gateway),
                output_interface,
            }),
            _ => None,
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn route_network(prefix: &IpNet) -> String {
    if prefix.prefix_len() == 0 {
        "default".to_owned()
    } else {
        prefix.to_string()
    }
}

#[cfg(target_os = "macos")]
fn macos_route_args(action: &str, tun_name: &str, prefix: &IpNet) -> Vec<String> {
    let mut args = vec!["-n".into(), action.into()];
    if prefix.addr().is_ipv6() {
        args.push("-inet6".into());
    }
    args.extend([
        "-net".into(),
        route_network(prefix),
        "-interface".into(),
        tun_name.into(),
    ]);
    args
}

#[cfg(target_os = "macos")]
fn macos_route_output_has_exact_host(output: &[u8], endpoint: IpAddr) -> bool {
    let output = String::from_utf8_lossy(output);
    let destination_matches = output.lines().any(|line| {
        line.trim()
            .strip_prefix("destination: ")
            .is_some_and(|destination| destination == endpoint.to_string())
    });
    let is_host = output.lines().any(|line| {
        line.trim().strip_prefix("flags: ").is_some_and(|flags| {
            flags
                .trim_matches(['<', '>'])
                .split(',')
                .any(|flag| flag == "HOST")
        })
    });
    destination_matches && is_host
}

#[cfg(target_os = "macos")]
fn macos_has_exact_host_route(endpoint: IpAddr) -> Result<bool, PlatformError> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", &endpoint.to_string()])
        .output()
        .map_err(|error| PlatformError::Command(error.to_string()))?;
    Ok(output.status.success() && macos_route_output_has_exact_host(&output.stdout, endpoint))
}

/// Installs imported routes and pins peer underlay endpoints to the existing
/// default gateway before an overlay default route can take effect.
pub async fn install_overlay_routes(
    tun_name: &str,
    prefixes: &[IpNet],
    underlay: &[IpAddr],
) -> Result<UnderlayRouteOwnership, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        super::linux_install_overlay_routes(tun_name, prefixes, underlay).await
    }
    #[cfg(target_os = "macos")]
    {
        install_macos_overlay_routes(tun_name, prefixes, underlay)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (tun_name, prefixes, underlay);
        Err(PlatformError::Unsupported(std::env::consts::OS.into()))
    }
}

#[cfg(target_os = "macos")]
fn install_macos_overlay_routes(
    tun_name: &str,
    prefixes: &[IpNet],
    underlay: &[IpAddr],
) -> Result<UnderlayRouteOwnership, PlatformError> {
    let default = String::from_utf8_lossy(
        &std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|error| PlatformError::Command(error.to_string()))?
            .stdout,
    )
    .into_owned();
    let gateway = default
        .lines()
        .find_map(|line| line.trim().strip_prefix("gateway: "))
        .unwrap_or("");
    let mut ownership = UnderlayRouteOwnership::default();
    for endpoint in underlay.iter().filter(|endpoint| !endpoint.is_loopback()) {
        if !gateway.is_empty() {
            if macos_has_exact_host_route(*endpoint)? {
                continue;
            }
            if let Err(error) = run_checked(
                "route",
                &["-n", "add", "-host", &endpoint.to_string(), gateway],
            ) {
                cleanup_macos_underlay_routes(&ownership);
                return Err(error);
            }
            ownership.routes.push(OwnedUnderlayRoute {
                endpoint: *endpoint,
                gateway: gateway.to_owned(),
                output_interface: 0,
            });
        }
    }
    for (index, prefix) in prefixes.iter().enumerate() {
        let args = macos_route_args("add", tun_name, prefix);
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        if let Err(error) = run_checked("route", &args) {
            for installed in prefixes[..index].iter().rev() {
                let args = macos_route_args("delete", tun_name, installed);
                let args = args.iter().map(String::as_str).collect::<Vec<_>>();
                let _ = run_checked("route", &args);
            }
            cleanup_macos_underlay_routes(&ownership);
            return Err(error);
        }
    }
    Ok(ownership)
}

/// Removes only the underlay host routes represented by a successful install
/// token. Overlay prefixes are cleaned independently because they can change
/// while the daemon is running.
pub async fn cleanup_underlay_routes(
    ownership: &UnderlayRouteOwnership,
) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        super::linux_cleanup_underlay_routes(&ownership.routes).await
    }
    #[cfg(target_os = "macos")]
    {
        cleanup_macos_underlay_routes(ownership);
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = ownership;
        Err(PlatformError::Unsupported(std::env::consts::OS.into()))
    }
}

#[cfg(target_os = "macos")]
fn cleanup_macos_underlay_routes(ownership: &UnderlayRouteOwnership) {
    for route in ownership.routes.iter().rev() {
        let _ = run_checked(
            "route",
            &[
                "-n",
                "delete",
                "-host",
                &route.endpoint.to_string(),
                &route.gateway,
            ],
        );
    }
}

pub async fn cleanup_overlay_routes(
    tun_name: &str,
    prefixes: &[IpNet],
) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        super::linux_cleanup_overlay_routes(tun_name, prefixes).await
    }
    #[cfg(target_os = "macos")]
    {
        for prefix in prefixes {
            let args = macos_route_args("delete", tun_name, prefix);
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            let _ = run_checked("route", &args);
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (tun_name, prefixes);
        Err(PlatformError::Unsupported(std::env::consts::OS.into()))
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn route_network_uses_default_for_zero_length_prefixes() {
        assert_eq!(route_network(&"0.0.0.0/0".parse().unwrap()), "default");
        assert_eq!(
            route_network(&"2001:db8::/32".parse().unwrap()),
            "2001:db8::/32"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_route_arguments_preserve_family_and_interface() {
        assert_eq!(
            macos_route_args("add", "tinect0", &"192.0.2.0/24".parse().unwrap()),
            vec!["-n", "add", "-net", "192.0.2.0/24", "-interface", "tinect0"]
        );
        assert_eq!(
            macos_route_args("delete", "tinect0", &"2001:db8::/32".parse().unwrap()),
            vec![
                "-n",
                "delete",
                "-inet6",
                "-net",
                "2001:db8::/32",
                "-interface",
                "tinect0"
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_route_output_distinguishes_exact_host_from_default_lookup() {
        let endpoint = "192.0.2.10".parse().unwrap();
        assert!(macos_route_output_has_exact_host(
            b"route to: 192.0.2.10\ndestination: 192.0.2.10\ngateway: 192.0.2.1\nflags: <UP,GATEWAY,HOST,STATIC>\n",
            endpoint,
        ));
        assert!(!macos_route_output_has_exact_host(
            b"route to: 192.0.2.10\ndestination: default\ngateway: 192.0.2.1\nflags: <UP,GATEWAY,STATIC>\n",
            endpoint,
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn underlay_routes_match_gateway_family_and_skip_loopback() {
        let underlay = vec![
            "127.0.0.1".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ];
        assert_eq!(
            underlay_routes(
                &underlay,
                Some(("192.0.2.1".parse().unwrap(), 7)),
                Some(("2001:db8::1".parse().unwrap(), 8)),
            ),
            vec![
                UnderlayRoute {
                    endpoint: "192.0.2.10".parse().unwrap(),
                    gateway: "192.0.2.1".parse().unwrap(),
                    output_interface: 7,
                },
                UnderlayRoute {
                    endpoint: "2001:db8::10".parse().unwrap(),
                    gateway: "2001:db8::1".parse().unwrap(),
                    output_interface: 8,
                },
            ]
        );
        assert!(
            underlay_routes(&underlay, None, Some(("2001:db8::1".parse().unwrap(), 8)))
                .iter()
                .all(|route| route.endpoint.is_ipv6())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn underlay_routes_without_matching_default_are_ignored() {
        let underlay = [
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ];
        assert!(underlay_routes(&underlay, None, None).is_empty());
        assert!(
            underlay_routes(&underlay, Some(("192.0.2.1".parse().unwrap(), 7)), None)
                .iter()
                .all(|route| route.endpoint.is_ipv4())
        );
    }
}
