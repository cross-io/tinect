use super::*;

#[cfg(target_os = "linux")]
#[test]
fn tun_offload_disable_rejects_bad_interfaces_without_privileges() {
    // Too-long names fail before any ioctl; missing interfaces fail at the
    // ioctl. Neither path needs root, so they run in ordinary CI quality jobs
    // and pin the best-effort error plumbing.
    assert!(disable_tun_offloads("definitely-too-long-tun-name-exceeding-15").is_err());
    assert!(disable_tun_offloads("tincovnone0").is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_tun_address_and_mtu_operations_use_rtnetlink_successfully() {
    if unsafe { libc::geteuid() } != 0 || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none() {
        return;
    }
    let _network_namespace = crate::test_support::NetworkNamespace::enter();
    let device = create_tun(&TunConfig {
        enabled: true,
        name: "tinectcvplat".into(),
        addresses: vec!["10.64.0.1/32".parse().unwrap()],
        mtu: 1280,
        clamp_mss: true,
    })
    .unwrap();
    let name = device.name().unwrap();
    let addresses = vec![
        "10.64.0.1/32".parse().unwrap(),
        "192.0.2.1/24".parse().unwrap(),
        "198.51.100.1/32".parse().unwrap(),
    ];
    configure_tun_addresses(&name, &addresses).await.unwrap();
    set_tun_mtu(&name, 1400).await.unwrap();

    let prefixes = vec![
        "192.0.2.0/24".parse().unwrap(),
        "2001:db8::/32".parse().unwrap(),
    ];
    install_overlay_routes(&name, &prefixes, &[]).await.unwrap();
    cleanup_overlay_routes(&name, &prefixes).await.unwrap();
}
