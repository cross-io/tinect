//! Declarative network-plan rendering and operator-configured hooks.

use super::PlatformError;
use crate::config::TunConfig;
use std::process::Command;

/// A reviewable network-change plan. Applying it requires root privileges.
pub fn network_plan(
    tun: &TunConfig,
    managed_routes: bool,
    forwarded_exit: bool,
    direct: Option<(Option<u32>, u16)>,
    post_up: Option<&[String]>,
    require_root: bool,
) -> Result<Vec<Vec<String>>, PlatformError> {
    if !tun.enabled {
        return Ok(Vec::new());
    }
    if require_root && unsafe { geteuid() } != 0 {
        return Err(PlatformError::Permission);
    }
    let mut plan = Vec::new();
    match std::env::consts::OS {
        "linux" => {
            plan.push(vec![
                "tun".into(),
                "create".into(),
                "device".into(),
                // An empty name means the kernel allocates one at `up` time;
                // never render a blank device in a reviewable dry-run plan.
                if tun.name.is_empty() {
                    "<allocated>".into()
                } else {
                    tun.name.clone()
                },
            ]);
            if managed_routes {
                plan.push(vec![
                    "rtnetlink".into(),
                    "install".into(),
                    "overlay-routes".into(),
                ]);
            }
            plan.push(vec![
                "libnftnl/libmnl".into(),
                "install".into(),
                "tun-input-accept".into(),
            ]);
            if forwarded_exit {
                plan.push(vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "exit-nat".into(),
                ]);
            }
            if direct.is_some_and(|(fwmark, _)| fwmark.is_some()) {
                plan.push(vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "direct-fallback-prerouting-mark".into(),
                ]);
            }
            if let Some((_, zone)) = direct {
                plan.push(vec![
                    "ctnetlink".into(),
                    "flush".into(),
                    format!("direct-fallback-zone={zone}"),
                ]);
                plan.push(vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "direct-fallback-conntrack-zone".into(),
                ]);
            }
            if managed_routes && direct.is_some() {
                plan.push(vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "direct-fallback-masquerade".into(),
                ]);
            }
        }
        #[cfg(target_os = "macos")]
        "macos" => {
            plan.push(vec!["ifconfig".into(), "utun".into(), "create".into()]);
            if forwarded_exit {
                plan.push(vec![
                    "pfctl-rs".into(),
                    "install".into(),
                    "nat-anchor".into(),
                    super::PF_ANCHOR.into(),
                ]);
            }
        }
        other => return Err(PlatformError::Unsupported(other.into())),
    }
    if let Some(commands) = post_up {
        for command in commands {
            plan.push(vec!["/bin/sh".into(), "-ec".into(), command.clone()]);
        }
    }
    Ok(plan)
}

pub fn run_plan(plan: &[Vec<String>]) -> Result<(), PlatformError> {
    for args in plan {
        let Some((bin, rest)) = args.split_first() else {
            return Err(PlatformError::Command(
                "network plan contains an empty command".into(),
            ));
        };
        let status = Command::new(bin)
            .args(rest)
            .status()
            .map_err(|error| PlatformError::Command(error.to_string()))?;
        if !status.success() {
            return Err(PlatformError::Command(args.join(" ")));
        }
    }
    Ok(())
}

/// Runs configured lifecycle hooks in order. Their side effects remain owned
/// by the operator; failures are collected so cleanup commands all run.
pub fn run_lifecycle_hooks(
    commands: &[String],
    tun_name: &str,
    phase: &str,
) -> Result<(), PlatformError> {
    let mut failures = Vec::new();
    for command in commands {
        match Command::new("/bin/sh")
            .args(["-ec", command])
            .env("TINECT_TUN", tun_name)
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => failures.push(format!("{command:?} exited with {status}")),
            Err(error) => failures.push(format!("{command:?}: {error}")),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(PlatformError::Command(format!(
            "{phase}: {}",
            failures.join("; ")
        )))
    }
}

#[cfg(unix)]
unsafe fn geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(not(unix))]
unsafe fn geteuid() -> u32 {
    1
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_hooks_run_in_order_and_report_failures() {
        run_lifecycle_hooks(
            &["test \"$TINECT_TUN\" = \"tinect0\"".into(), "true".into()],
            "tinect0",
            "post-up",
        )
        .unwrap();
        let error = run_lifecycle_hooks(
            &["false".into(), "echo later".into()],
            "tinect0",
            "pre-down",
        )
        .unwrap_err();
        assert!(error.to_string().contains("pre-down"));
        assert!(error.to_string().contains("false"));
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        fn tun() -> TunConfig {
            TunConfig {
                enabled: true,
                name: "tinect0".into(),
                addresses: vec!["100.64.0.10/32".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            }
        }

        #[test]
        fn linux_network_plan_lists_all_owned_steps_in_order() {
            let plan = network_plan(
                &tun(),
                true,
                true,
                Some((Some(0x100), 32123)),
                Some(&["echo up".into()]),
                false,
            )
            .unwrap();
            let expected: Vec<Vec<String>> = vec![
                vec![
                    "tun".into(),
                    "create".into(),
                    "device".into(),
                    "tinect0".into(),
                ],
                vec![
                    "rtnetlink".into(),
                    "install".into(),
                    "overlay-routes".into(),
                ],
                vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "tun-input-accept".into(),
                ],
                vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "exit-nat".into(),
                ],
                vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "direct-fallback-prerouting-mark".into(),
                ],
                vec![
                    "ctnetlink".into(),
                    "flush".into(),
                    "direct-fallback-zone=32123".into(),
                ],
                vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "direct-fallback-conntrack-zone".into(),
                ],
                vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "direct-fallback-masquerade".into(),
                ],
                vec!["/bin/sh".into(), "-ec".into(), "echo up".into()],
            ];
            assert_eq!(plan, expected);
        }

        #[test]
        fn linux_network_plan_without_managed_routes_skips_route_ownership_steps() {
            let plan = network_plan(&tun(), false, false, None, None, false).unwrap();
            let expected: Vec<Vec<String>> = vec![
                vec![
                    "tun".into(),
                    "create".into(),
                    "device".into(),
                    "tinect0".into(),
                ],
                vec![
                    "libnftnl/libmnl".into(),
                    "install".into(),
                    "tun-input-accept".into(),
                ],
            ];
            assert_eq!(plan, expected);
        }
    }
}
